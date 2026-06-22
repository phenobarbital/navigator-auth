-- =====================================================================
-- auth.clients — soporte para OAuth2 (public & confidential clients)
-- Base asumida: client_id (bigserial PK), created_at, updated_at, is_active
-- =====================================================================

-- Identidad del cliente
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client          VARCHAR(255);          -- slug (slugify del client_name)
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client_name     VARCHAR(255) NOT NULL; -- requerido en el modelo
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client_type     VARCHAR(50)  NOT NULL DEFAULT 'public';

-- Secreto: NULLABLE — los public clients NO tienen client_secret (RFC 6749 §2.1)
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client_secret   VARCHAR(255);
ALTER TABLE auth.clients ALTER COLUMN client_secret DROP NOT NULL;   -- por si la columna ya existía como NOT NULL

-- Redirect URIs (JSONB): obligatorias para public clients (auth_code + PKCE, match exacto)
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS redirect_uris   JSONB DEFAULT '[]'::jsonb;

-- Metadatos opcionales
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS policy_uri      VARCHAR(255);
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client_logo_uri VARCHAR(255);

-- Dueño del cliente (FK a auth.users) — usado por client_credentials (client.user.user_id)
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS user_id         INTEGER REFERENCES auth.users(user_id) ON DELETE CASCADE;

-- Scopes y grants permitidos (JSONB)
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS default_scopes      JSONB DEFAULT '["default"]'::jsonb;
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS allowed_grant_types JSONB DEFAULT '[]'::jsonb;

-- Estado / vigencia
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS is_active       BOOLEAN   DEFAULT TRUE;
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS expiration_date TIMESTAMP WITHOUT TIME ZONE;
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS created_at      TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW();
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS updated_at      TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW();

-- =====================================================================
-- Backfill de registros existentes
-- =====================================================================

-- Sincronizar client <-> client_name en filas previas
UPDATE auth.clients SET client_name = client WHERE client_name IS NULL;
UPDATE auth.clients SET client = client_name WHERE client IS NULL;

-- Valores por defecto para el client de prueba (o entradas incompletas)
UPDATE auth.clients
SET
    client_secret       = 'test_client_secret',
    redirect_uris       = '["http://localhost:5000/static/callback.html"]'::jsonb,
    allowed_grant_types = '["authorization_code", "client_credentials"]'::jsonb,
    default_scopes      = '["default"]'::jsonb,
    expiration_date     = NOW() + INTERVAL '1 year'
WHERE client_secret IS NULL;
-- client_uid: opaque public identifier (FEAT-093 — TASK-023)
-- The integer PK (auth.clients.client_id) stays internal and is the FK
-- target for all new token/grant tables.  The string client_uid is what
-- clients present on the wire; it is never an integer.
-- =====================================================================

ALTER TABLE auth.clients
    ADD COLUMN IF NOT EXISTS client_uid VARCHAR(255);

-- Backfill existing rows with an opaque value. Idempotent (WHERE NULL).
UPDATE auth.clients
    SET client_uid = 'client_' || client_id::text || '_' || substr(md5(random()::text), 1, 12)
WHERE client_uid IS NULL;

-- Enforce NOT NULL + UNIQUE after backfill.
ALTER TABLE auth.clients
    ALTER COLUMN client_uid SET NOT NULL;

ALTER TABLE auth.clients
    DROP CONSTRAINT IF EXISTS clients_client_uid_key;

ALTER TABLE auth.clients
    ADD CONSTRAINT clients_client_uid_key UNIQUE (client_uid);

-- Ensure these columns (that likely exist) are correct or present just in case
-- ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW();
-- ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW();
-- ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;

-- Update existing records to correct data
UPDATE auth.clients SET client_name = client WHERE client_name IS NULL;
UPDATE auth.clients SET client = client_name WHERE client IS NULL;

-- Set Default Values for Test Client (or null entries)
UPDATE auth.clients
SET
    client_secret = 'test_client_secret',
    redirect_uris = '["http://localhost:5000/static/callback.html"]'::jsonb,
    allowed_grant_types = '["authorization_code", "client_credentials"]'::jsonb,
    default_scopes = '["default", "offline_access"]'::jsonb,
    expiration_date = NOW() + INTERVAL '1 year'
WHERE client_secret IS NULL;

-- =====================================================================
-- oauth_refresh_tokens — durable refresh token store (FEAT-093 — TASK-026)
-- FK client_id references the INTEGER PK of auth.clients.
-- =====================================================================

CREATE TABLE IF NOT EXISTS auth.oauth_refresh_tokens (
    id                  BIGSERIAL PRIMARY KEY,
    refresh_token       VARCHAR(512) NOT NULL UNIQUE,
    client_id           INTEGER NOT NULL REFERENCES auth.clients(client_id) ON DELETE CASCADE,
    user_id             INTEGER NOT NULL REFERENCES auth.users(user_id) ON DELETE CASCADE,
    scope               TEXT NOT NULL DEFAULT '',
    parent_token        VARCHAR(512),
    issued_at           TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    absolute_expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    revoked             BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at          TIMESTAMP WITHOUT TIME ZONE,
    revoked_reason      VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_user
    ON auth.oauth_refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_client
    ON auth.oauth_refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_parent
    ON auth.oauth_refresh_tokens(parent_token);

-- =====================================================================
-- oauth_grants — durable consent records (FEAT-093 — TASK-027)
-- client_id here is the public client_uid string (not the int PK).
-- =====================================================================

CREATE TABLE IF NOT EXISTS auth.oauth_grants (
    grant_id    UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES auth.users(user_id) ON DELETE CASCADE,
    client_id   VARCHAR(255) NOT NULL,   -- public client_uid
    scopes      JSONB NOT NULL DEFAULT '[]'::jsonb,
    granted_at  TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at  TIMESTAMP WITHOUT TIME ZONE,
    UNIQUE (user_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_grants_user
    ON auth.oauth_grants(user_id);

-- =====================================================================
-- oauth_access_tokens — jti tracking (FEAT-093 — TASK-027)
-- FK client_id references auth.clients(client_id) integer PK.
-- user_id is NULLABLE: client_credentials (2LO / machine-to-machine) tokens
-- have no associated end user.
-- =====================================================================

CREATE TABLE IF NOT EXISTS auth.oauth_access_tokens (
    id          BIGSERIAL PRIMARY KEY,
    jti         UUID NOT NULL UNIQUE,
    user_id     INTEGER REFERENCES auth.users(user_id) ON DELETE CASCADE,
    client_id   INTEGER NOT NULL REFERENCES auth.clients(client_id) ON DELETE CASCADE,
    scope       TEXT NOT NULL DEFAULT '',
    issued_at   TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_jti
    ON auth.oauth_access_tokens(jti);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_user
    ON auth.oauth_access_tokens(user_id);

-- =====================================================================
-- auth.policies.scopes — scope AND-condition (FEAT-093 — TASK-030)
-- =====================================================================

ALTER TABLE auth.policies
    ADD COLUMN IF NOT EXISTS scopes JSONB DEFAULT '[]'::jsonb;
