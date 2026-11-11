-- FEAT-106 review fixes (spec M4): durable credential-change state, required regardless of MFA.
-- {schema} / {users_table} are substituted by security_state/migrations.py.
-- Additive and idempotent: safe to run on every startup.
CREATE SCHEMA IF NOT EXISTS {schema};

-- One row per consumed recovery confirmation: SHA-256 hex digest only, never the raw token.
-- Written on the recovery transaction's connection; the committed row makes the confirmation single-use.
CREATE TABLE IF NOT EXISTS {schema}.recovery_confirm_consumptions (
    digest      CHAR(64)    PRIMARY KEY,
    user_id     bigint      NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS recovery_confirm_consumptions_expires_idx
    ON {schema}.recovery_confirm_consumptions (expires_at);

-- OAuth credential generation per user. Absent row == generation 0. Incremented by password_reset and
-- recovery in the same transaction as the password write; every user OAuth artifact carries the
-- generation it was minted under and is rejected once it differs.
CREATE TABLE IF NOT EXISTS {schema}.oauth_user_generation (
    user_id     bigint      PRIMARY KEY REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    generation  bigint      NOT NULL DEFAULT 0 CHECK (generation >= 0),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
