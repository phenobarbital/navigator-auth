-- Passkey (WebAuthn) credentials — FEAT-101.
-- {schema} / {users_table} are substituted by passkey/migrations.py.
-- Additive and idempotent: safe to run on every startup.
CREATE SCHEMA IF NOT EXISTS {schema};

CREATE TABLE IF NOT EXISTS {schema}.user_passkey_handles (
    user_id      integer NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    rp_id        varchar(253) NOT NULL,
    user_handle  bytea NOT NULL UNIQUE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, rp_id)
);

CREATE TABLE IF NOT EXISTS {schema}.user_credentials (
    credential_id  bytea PRIMARY KEY,
    user_id        integer NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    rp_id          varchar(253) NOT NULL,
    public_key     bytea NOT NULL,
    sign_count     bigint NOT NULL DEFAULT 0,
    transports     text[],
    aaguid         uuid,
    device_type    varchar(32),
    backed_up      boolean NOT NULL DEFAULT false,
    label          varchar(128),
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_used_at   timestamptz
);
CREATE INDEX IF NOT EXISTS user_credentials_user_rp_idx
    ON {schema}.user_credentials (user_id, rp_id);
