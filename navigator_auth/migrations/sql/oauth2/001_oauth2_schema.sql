-- FEAT-110 — OAuth2 schema (FEAT-093/094/095), converted from the hand-applied
-- navigator_auth/backends/oauth2/ddl.sql into a managed migration.
-- Applied by `navauth self upgrade`; {schema} / {users_table} are rendered by
-- navigator_auth/migrations/catalog.py::render_sql. Idempotent and guarded.
-- No seed or test data: public clients must not receive fabricated credentials.
-- Completion (NOT NULL, unique client_uid, foreign keys, indexes) is verified by
-- the runner after this file; unmet conditions roll the file back for repair.

-- 1. {schema}.clients columns (ddl.sql 7-33, 223-239)
ALTER TABLE IF EXISTS {schema}.clients
    ADD COLUMN IF NOT EXISTS client VARCHAR(255),
    ADD COLUMN IF NOT EXISTS client_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS client_type VARCHAR(50) NOT NULL DEFAULT 'public',
    ADD COLUMN IF NOT EXISTS client_secret VARCHAR(255),
    ADD COLUMN IF NOT EXISTS redirect_uris JSONB DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS policy_uri VARCHAR(255),
    ADD COLUMN IF NOT EXISTS client_logo_uri VARCHAR(255),
    ADD COLUMN IF NOT EXISTS user_id INTEGER,
    ADD COLUMN IF NOT EXISTS default_scopes JSONB DEFAULT '["default"]'::jsonb,
    ADD COLUMN IF NOT EXISTS allowed_grant_types JSONB DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS expiration_date TIMESTAMP WITHOUT TIME ZONE,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS client_uid VARCHAR(255),
    ADD COLUMN IF NOT EXISTS token_endpoint_auth_method VARCHAR(64),
    ADD COLUMN IF NOT EXISTS registration_source VARCHAR(32) NOT NULL DEFAULT 'static',
    ADD COLUMN IF NOT EXISTS enforce_access_gate BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE IF EXISTS {schema}.clients
    ALTER COLUMN client_secret DROP NOT NULL,
    ALTER COLUMN user_id DROP NOT NULL;

-- 2. Backfills that only fill NULLs (rule 4)
DO $$
BEGIN
    IF to_regclass('{schema}.clients') IS NULL THEN
        RETURN;
    END IF;

    UPDATE {schema}.clients
       SET client_name = client
     WHERE client_name IS NULL AND client IS NOT NULL;

    UPDATE {schema}.clients
       SET client = client_name
     WHERE client IS NULL AND client_name IS NOT NULL;

    UPDATE {schema}.clients
       SET client_uid = 'client_' || client_id::text || '_' || substr(md5(random()::text), 1, 12)
     WHERE client_uid IS NULL;

    UPDATE {schema}.clients
       SET registration_source = 'static'
     WHERE registration_source IS NULL;
END
$$;

-- 3. NOT NULL and unique client_uid, guarded (rules 2-3)
DO $$
BEGIN
    IF to_regclass('{schema}.clients') IS NULL THEN
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM {schema}.clients WHERE client_name IS NULL) THEN
        ALTER TABLE {schema}.clients ALTER COLUMN client_name SET NOT NULL;
    ELSE
        RAISE WARNING 'OAuth2 migration cannot set clients.client_name NOT NULL: NULL values remain';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM {schema}.clients WHERE client_uid IS NULL) THEN
        ALTER TABLE {schema}.clients ALTER COLUMN client_uid SET NOT NULL;
    ELSE
        RAISE WARNING 'OAuth2 migration cannot set clients.client_uid NOT NULL: NULL values remain';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = to_regclass('{schema}.clients')
           AND conname = 'clients_client_uid_key'
           AND contype = 'u'
    ) THEN
        ALTER TABLE {schema}.clients
            ADD CONSTRAINT clients_client_uid_key UNIQUE (client_uid);
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint c
          JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
         WHERE c.conrelid = to_regclass('{schema}.clients')
           AND c.contype = 'f'
           AND a.attname = 'user_id'
    ) THEN
        ALTER TABLE {schema}.clients
            ADD CONSTRAINT clients_user_id_fkey
            FOREIGN KEY (user_id) REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE;
    END IF;
END
$$;

-- 4. policies.scopes (ddl.sql 168-169)
ALTER TABLE IF EXISTS {schema}.policies
    ADD COLUMN IF NOT EXISTS scopes JSONB DEFAULT '[]'::jsonb;

-- 5. New tables and indexes. The base clients/users tables are platform-owned;
--    without both, the runner's prerequisite check reports the missing base.
DO $$
BEGIN
    IF to_regclass('{schema}.clients') IS NULL
       OR to_regclass('{schema}.{users_table}') IS NULL THEN
        RETURN;
    END IF;

    CREATE TABLE IF NOT EXISTS {schema}.oauth_refresh_tokens (
        id BIGSERIAL PRIMARY KEY,
        refresh_token VARCHAR(512) NOT NULL UNIQUE,
        client_id INTEGER NOT NULL REFERENCES {schema}.clients(client_id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
        scope TEXT NOT NULL DEFAULT '',
        parent_token VARCHAR(512),
        issued_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
        absolute_expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
        revoked BOOLEAN NOT NULL DEFAULT FALSE,
        revoked_at TIMESTAMP WITHOUT TIME ZONE,
        revoked_reason VARCHAR(64)
    );

    CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_user
        ON {schema}.oauth_refresh_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_client
        ON {schema}.oauth_refresh_tokens(client_id);
    CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_parent
        ON {schema}.oauth_refresh_tokens(parent_token);

    CREATE TABLE IF NOT EXISTS {schema}.oauth_grants (
        grant_id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
        client_id VARCHAR(255) NOT NULL,
        scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
        granted_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
        revoked BOOLEAN NOT NULL DEFAULT FALSE,
        revoked_at TIMESTAMP WITHOUT TIME ZONE,
        UNIQUE (user_id, client_id)
    );

    CREATE INDEX IF NOT EXISTS idx_oauth_grants_user
        ON {schema}.oauth_grants(user_id);

    CREATE TABLE IF NOT EXISTS {schema}.oauth_access_tokens (
        id BIGSERIAL PRIMARY KEY,
        jti UUID NOT NULL UNIQUE,
        user_id INTEGER REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
        client_id INTEGER NOT NULL REFERENCES {schema}.clients(client_id) ON DELETE CASCADE,
        scope TEXT NOT NULL DEFAULT '',
        issued_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
        revoked BOOLEAN NOT NULL DEFAULT FALSE
    );

    CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_jti
        ON {schema}.oauth_access_tokens(jti);
    CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_user
        ON {schema}.oauth_access_tokens(user_id);

    CREATE TABLE IF NOT EXISTS {schema}.oauth_device_codes (
        id BIGSERIAL PRIMARY KEY,
        device_code VARCHAR(512) NOT NULL UNIQUE,
        user_code VARCHAR(64) NOT NULL UNIQUE,
        client_id INTEGER NOT NULL REFERENCES {schema}.clients(client_id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES {schema}.{users_table}(user_id) ON DELETE SET NULL,
        scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
        status VARCHAR(16) NOT NULL DEFAULT 'pending'
            CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
        code_challenge VARCHAR(512),
        code_challenge_method VARCHAR(16),
        auth_code VARCHAR(512),
        interval SMALLINT NOT NULL DEFAULT 5,
        last_polled_at TIMESTAMP WITHOUT TIME ZONE,
        issued_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_oauth_device_codes_device_code
        ON {schema}.oauth_device_codes(device_code);
    CREATE INDEX IF NOT EXISTS idx_oauth_device_codes_user_code
        ON {schema}.oauth_device_codes(user_code);
    CREATE INDEX IF NOT EXISTS idx_oauth_device_codes_client
        ON {schema}.oauth_device_codes(client_id);
    CREATE INDEX IF NOT EXISTS idx_oauth_device_codes_status_expires
        ON {schema}.oauth_device_codes(status, expires_at);

    CREATE TABLE IF NOT EXISTS {schema}.client_access (
        access_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id INTEGER NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
        client_id INTEGER REFERENCES {schema}.clients(client_id) ON DELETE CASCADE,
        client_uid VARCHAR(255) NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'active',
        granted_by INTEGER REFERENCES {schema}.{users_table}(user_id) ON DELETE SET NULL,
        granted_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
        revoked_at TIMESTAMP WITHOUT TIME ZONE
    );

    CREATE UNIQUE INDEX IF NOT EXISTS uq_client_access_user_client
        ON {schema}.client_access(user_id, client_id);
    CREATE UNIQUE INDEX IF NOT EXISTS uq_client_access_user_client_uid
        ON {schema}.client_access(user_id, client_uid);
    CREATE INDEX IF NOT EXISTS idx_client_access_client_uid
        ON {schema}.client_access(client_uid);
    CREATE INDEX IF NOT EXISTS idx_client_access_client_status
        ON {schema}.client_access(client_uid, status);

    CREATE INDEX IF NOT EXISTS idx_clients_registration_source
        ON {schema}.clients(registration_source);
END
$$;
