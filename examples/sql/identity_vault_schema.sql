-- ---------------------------------------------------------------------------
-- Minimal `auth` schema for examples/identity_vault_server.py
--
-- navigator-auth expects the Navigator `auth` schema to exist already (it is
-- created by the Navigator platform, not by this library). This file creates
-- the smallest subset the Identity Vault example needs:
--
--   auth.users            -> navigator_auth.models.User   (login + user_id)
--   auth.user_identities  -> navigator_auth.models.UserIdentity (the vault)
--
-- The *credential* columns of auth.user_identities (access_token,
-- refresh_token, expires_at, ...) are NOT created here on purpose: they are
-- added at startup by the idempotent migration shipped with the library
-- (navigator_auth/identity/sql/001_identity_credentials.sql), which
-- AuthHandler runs on every boot. The same is true for the Session Vault
-- tables (auth.user_vault_secrets).
--
-- Apply with:
--   psql "$DSN" -f examples/sql/identity_vault_schema.sql
-- or let the example do it for you (EXAMPLE_BOOTSTRAP_DB=true, the default).
-- ---------------------------------------------------------------------------

CREATE SCHEMA IF NOT EXISTS auth;

-- gen_random_uuid() is built in since PostgreSQL 13. On older servers run
-- `CREATE EXTENSION IF NOT EXISTS pgcrypto;` once as a superuser first (it is
-- not done here so the example can bootstrap with an unprivileged role).

CREATE TABLE IF NOT EXISTS auth.users (
    user_id       SERIAL       PRIMARY KEY,
    userid        UUID         NOT NULL DEFAULT gen_random_uuid(),
    first_name    VARCHAR(254),
    last_name     VARCHAR(254),
    display_name  VARCHAR(254),
    email         VARCHAR(254),
    alt_email     VARCHAR(254),
    password      VARCHAR(255),          -- pbkdf2_sha256$<iterations>$<salt>$<hash>
    username      VARCHAR(254) NOT NULL,
    user_role     SMALLINT,
    is_superuser  BOOLEAN      NOT NULL DEFAULT FALSE,
    is_staff      BOOLEAN      NOT NULL DEFAULT TRUE,
    title         VARCHAR(120),
    avatar        TEXT,
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
    is_new        BOOLEAN      NOT NULL DEFAULT TRUE,
    timezone      VARCHAR(75)  NOT NULL DEFAULT 'UTC',
    attributes    JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_login    TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_users_username ON auth.users (username);

-- The identity vault itself. auth_data keeps the (non-secret) provider
-- profile shown on the management page; every token column is added by the
-- library migration as BYTEA and stored ciphered.
CREATE TABLE IF NOT EXISTS auth.user_identities (
    identity_id   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name  VARCHAR(254),
    title         VARCHAR(120),
    nickname      VARCHAR(120),
    email         VARCHAR(254),
    phone         VARCHAR(50),
    short_bio     TEXT,
    avatar        TEXT,
    user_id       INTEGER      NOT NULL REFERENCES auth.users (user_id) ON DELETE CASCADE,
    auth_provider VARCHAR(60),
    auth_data     JSONB        NOT NULL DEFAULT '{}'::jsonb,
    attributes    JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_identities_user
    ON auth.user_identities (user_id, auth_provider);
