-- Identity Vault: INTEGER key_version on auth.user_identities (FEAT-099)
-- The vault KeyRing accepts key ids up to 65535, beyond SMALLINT's 32767.
-- Idempotent: only alters the column while it is still SMALLINT.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'auth' AND table_name = 'user_identities'
          AND column_name = 'key_version' AND data_type = 'smallint'
    ) THEN
        ALTER TABLE auth.user_identities ALTER COLUMN key_version TYPE INTEGER;
    END IF;
END $$;
