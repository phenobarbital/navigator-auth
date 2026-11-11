-- FEAT-106 second factor for BasicAuth — MFA tables.
-- {schema} / {users_table} are substituted by mfa/migrations.py.
-- Additive and idempotent: safe to run on every startup.
-- The TOTP seed is NOT here: it lives sealed in {schema}.user_mfa_secrets
-- (002_mfa_secrets.sql; rotated by navigator_auth.mfa.targets.MfaSecretTarget).
CREATE SCHEMA IF NOT EXISTS {schema};

-- Per-tenant policy: DATA, not configuration. Absent row == mode 'off'.
CREATE TABLE IF NOT EXISTS {schema}.tenant_mfa_policy (
    org_id         bigint PRIMARY KEY,
    mode           varchar(16) NOT NULL DEFAULT 'off'
                   CHECK (mode IN ('off', 'optional', 'enforced')),
    remember_days  integer NOT NULL DEFAULT 0 CHECK (remember_days >= 0),
    enforced_at    timestamptz,
    enforced_by    varchar(254),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- Per-user factor enrolment (TOTP today). E-mail is implicit (User.email).
CREATE TABLE IF NOT EXISTS {schema}.user_mfa (
    user_id       bigint NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    provider      varchar(16) NOT NULL,
    enabled       boolean NOT NULL DEFAULT false,
    confirmed_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    PRIMARY KEY (user_id, provider)
);

-- Single-use backup codes, stored only as a keyed hash (D16).
CREATE TABLE IF NOT EXISTS {schema}.user_mfa_backup_codes (
    id          bigserial PRIMARY KEY,
    user_id     bigint NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    code_hash   varchar(64) NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS user_mfa_backup_codes_user_idx
    ON {schema}.user_mfa_backup_codes (user_id) WHERE used_at IS NULL;

-- Remember-me: rotating bearer second factor; superseded rows are kept
-- (rotated_at) so a replay is detectable and revokes the family (D15).
CREATE TABLE IF NOT EXISTS {schema}.user_trusted_devices (
    id             bigserial PRIMARY KEY,
    user_id        bigint NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    token_hash     varchar(64) NOT NULL UNIQUE,
    family_id      uuid NOT NULL,
    label          varchar(128) NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    last_used_at   timestamptz,
    rotated_at     timestamptz,
    revoked_at     timestamptz,
    revoke_reason  varchar(64)
);
CREATE INDEX IF NOT EXISTS user_trusted_devices_user_idx
    ON {schema}.user_trusted_devices (user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS user_trusted_devices_family_idx
    ON {schema}.user_trusted_devices (family_id);

-- Durable, action-specific record of every factor-state transition.
-- NOT abac/audit.py AuditLog (best-effort, records authorization decisions).
-- No foreign keys: the audit trail must outlive the users it mentions.
CREATE TABLE IF NOT EXISTS {schema}.user_mfa_audit (
    id              bigserial PRIMARY KEY,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    actor_user_id   bigint,
    target_user_id  bigint,
    org_id          bigint,
    action          varchar(64) NOT NULL,
    old_state       varchar(16),
    new_state       varchar(16),
    method          varchar(32),
    request_id      varchar(128),
    outcome         varchar(16) NOT NULL,
    detail          jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS user_mfa_audit_target_idx
    ON {schema}.user_mfa_audit (target_user_id, occurred_at DESC);

-- Durable monotonic challenge-invalidation version (spec security contracts).
CREATE TABLE IF NOT EXISTS {schema}.user_mfa_security (
    user_id     bigint PRIMARY KEY REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    version     bigint NOT NULL DEFAULT 0,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
