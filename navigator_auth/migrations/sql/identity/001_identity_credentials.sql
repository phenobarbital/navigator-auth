-- Identity Vault: credential columns on auth.user_identities
-- Additive and idempotent — safe to run on every startup.

CREATE SCHEMA IF NOT EXISTS auth;

ALTER TABLE IF EXISTS auth.user_identities
    ADD COLUMN IF NOT EXISTS provider_user_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS scopes           JSONB DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS access_token     BYTEA,        -- ciphered (vault master keys)
    ADD COLUMN IF NOT EXISTS refresh_token    BYTEA,        -- ciphered (vault master keys)
    ADD COLUMN IF NOT EXISTS token_type       VARCHAR(50),
    ADD COLUMN IF NOT EXISTS expires_at       TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS refreshed_at     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS enabled          BOOLEAN DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS key_version      SMALLINT;

-- One linked account per (user, provider, external account)
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_identities_provider_account
    ON auth.user_identities (user_id, auth_provider, provider_user_id)
    WHERE provider_user_id IS NOT NULL;
