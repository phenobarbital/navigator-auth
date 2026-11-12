-- Session Vault: schema changes for envelope v2 (FEAT-099)
-- Idempotent and safe to run on every startup: each change is applied only when
-- the current schema differs, so repeated runs take no table locks.
--
-- 1. auth.user_vault_audit.session_id holds HMAC-SHA256(session id) as 64 hex
--    characters (or "run:<run_id>" for migration audit rows) — widen VARCHAR(36).
-- 2. auth.user_vault_audit.operation also accepts 'quarantine' (offline migrator)
--    and 'integrity_fail' (SessionVault load).
-- 3. Key version columns become INTEGER: KeyRing accepts key ids up to 65535,
--    beyond SMALLINT's 32767.
--
-- Must be applied before running `navigator-vault migrate --run`.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'auth' AND table_name = 'user_vault_audit'
          AND column_name = 'session_id'
          AND (character_maximum_length IS NULL OR character_maximum_length < 64)
          AND data_type = 'character varying'
    ) THEN
        ALTER TABLE auth.user_vault_audit ALTER COLUMN session_id TYPE VARCHAR(64);
    END IF;
END $$;

DO $$
DECLARE
    current_def TEXT;
BEGIN
    SELECT pg_get_constraintdef(c.oid) INTO current_def
    FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = 'auth' AND t.relname = 'user_vault_audit'
      AND c.conname = 'user_vault_audit_operation_check';

    IF to_regclass('auth.user_vault_audit') IS NOT NULL
       AND (current_def IS NULL OR current_def NOT LIKE '%integrity_fail%') THEN
        ALTER TABLE auth.user_vault_audit
            DROP CONSTRAINT IF EXISTS user_vault_audit_operation_check;
        ALTER TABLE auth.user_vault_audit
            ADD CONSTRAINT user_vault_audit_operation_check CHECK (
                operation IN ('set', 'get', 'delete', 'rotate', 'quarantine', 'integrity_fail')
            );
    END IF;
END $$;

DO $$
DECLARE
    target RECORD;
BEGIN
    FOR target IN
        SELECT table_name, column_name
        FROM information_schema.columns
        WHERE table_schema = 'auth'
          AND data_type = 'smallint'
          AND (table_name, column_name) IN (
              ('user_vault_secrets', 'key_version'),
              ('user_vault_audit', 'key_version'),
              ('vault_key_registry', 'key_id')
          )
    LOOP
        EXECUTE format(
            'ALTER TABLE auth.%I ALTER COLUMN %I TYPE INTEGER',
            target.table_name, target.column_name
        );
    END LOOP;
END $$;

DO $$
BEGIN
    IF to_regclass('auth.user_vault_audit') IS NOT NULL THEN
        COMMENT ON COLUMN auth.user_vault_audit.session_id IS
            'HMAC-SHA256 of the session id (64 hex chars, vault naming key) or run:<run_id> for migration rows; never the raw session id';
    END IF;
END $$;
