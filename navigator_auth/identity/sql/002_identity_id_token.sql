-- Identity Vault: id_token column on auth.user_identities (FEAT-096, D7)
-- Additive and idempotent — safe to run on every startup.

ALTER TABLE IF EXISTS auth.user_identities
    ADD COLUMN IF NOT EXISTS id_token BYTEA;   -- ciphered (vault master keys)
