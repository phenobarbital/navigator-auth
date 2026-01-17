-- ALTER TABLE statements for auth.clients
-- Assumes auth.clients exists with client_id (bigserial), created_at, updated_at, is_active

ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client VARCHAR(255);
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client_name VARCHAR(255);
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client_secret VARCHAR(255);
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client_type VARCHAR(50) DEFAULT 'public';
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS redirect_uris JSONB;
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS policy_uri VARCHAR(255);
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client_logo_uri VARCHAR(255);
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES auth.users(user_id) ON DELETE CASCADE;
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS default_scopes JSONB;
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS allowed_grant_types JSONB;
ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS expiration_date TIMESTAMP WITHOUT TIME ZONE;

-- Ensure these columns (that likely exist) are correct or present just in case
-- ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW();
-- ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW();
-- ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;

-- Update existing records to correct data
update auth.clients set client_name = client where client_name is null;
update auth.clients set client = client_name where client is null;

-- Set Default Values for Test Client (or null entries)
UPDATE auth.clients 
SET 
    client_secret = 'test_client_secret',
    redirect_uris = '["http://localhost:5000/static/callback.html"]'::jsonb,
    allowed_grant_types = '["authorization_code", "client_credentials"]'::jsonb,
    default_scopes = '["default"]'::jsonb,
    expiration_date = NOW() + INTERVAL '1 year'
WHERE client_secret IS NULL;