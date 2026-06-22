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
