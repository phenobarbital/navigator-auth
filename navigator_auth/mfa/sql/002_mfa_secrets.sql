-- FEAT-106 review fix #2 (spec M7): TOTP seeds get their own table.
-- {schema} / {users_table} are substituted by mfa/migrations.py.
-- Identity columns (user_id, provider, key) == the AAD fields of mfa_seed_context, so the
-- MfaSecretTarget (navigator_auth/mfa/targets.py) rebuilds the right context on rotation and moved
-- ciphertext stays valid without re-sealing (the AAD carries no table name).
-- key_version is INTEGER (not SMALLINT) to match auth.user_vault_secrets after FEAT-099.
-- Additive and idempotent: safe to run on every startup.
CREATE TABLE IF NOT EXISTS {schema}.user_mfa_secrets (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       bigint       NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    provider      VARCHAR(32)  NOT NULL,
    key           VARCHAR(255) NOT NULL,
    ciphertext_db BYTEA        NOT NULL,
    key_version   INTEGER      NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at    TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS user_mfa_secrets_active_unique
    ON {schema}.user_mfa_secrets (user_id, provider, key) WHERE deleted_at IS NULL;

-- Move every MFA seed out of the user vault (UserVaultTarget scans soft-deleted rows too, so the
-- vault rows are HARD-deleted). One DO block = one statement = atomic. No-op once moved, and a
-- no-op when the vault table does not exist.
DO $$
BEGIN
    IF to_regclass('auth.user_vault_secrets') IS NOT NULL THEN
        INSERT INTO {schema}.user_mfa_secrets
            (id, user_id, provider, key, ciphertext_db, key_version, created_at, updated_at, deleted_at)
        SELECT id, user_id, 'totp', key, ciphertext_db, key_version, created_at, updated_at, deleted_at
          FROM auth.user_vault_secrets
         WHERE key LIKE 'mfa:%'
        ON CONFLICT DO NOTHING;
        DELETE FROM auth.user_vault_secrets WHERE key LIKE 'mfa:%';
    END IF;
END $$;
