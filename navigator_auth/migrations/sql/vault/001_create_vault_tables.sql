-- Session Vault: Database Tables
-- Feature: FEAT-001 (Session Vault System)
-- All tables are additive — no changes to existing schema.

-- Ensure auth schema exists
CREATE SCHEMA IF NOT EXISTS auth;

-- ==========================================================================
-- Primary vault table: encrypted user secrets
-- ==========================================================================
CREATE TABLE IF NOT EXISTS auth.user_vault_secrets (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       INTEGER      NOT NULL REFERENCES auth.users(user_id) ON DELETE CASCADE,
    key           VARCHAR(255) NOT NULL,
    ciphertext_db BYTEA        NOT NULL,
    key_version   SMALLINT     NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at    TIMESTAMPTZ
);

-- Partial unique index: only one active (non-deleted) secret per user+key
CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_active_unique
    ON auth.user_vault_secrets (user_id, key)
    WHERE deleted_at IS NULL;

-- Query index: fast lookup of all active secrets for a user
CREATE INDEX IF NOT EXISTS idx_vault_user_active
    ON auth.user_vault_secrets (user_id)
    WHERE deleted_at IS NULL;

-- Index for key rotation batch queries
CREATE INDEX IF NOT EXISTS idx_vault_key_version
    ON auth.user_vault_secrets (key_version)
    WHERE deleted_at IS NULL;

-- ==========================================================================
-- Audit table: records vault operations
-- ==========================================================================
CREATE TABLE IF NOT EXISTS auth.user_vault_audit (
    id          BIGSERIAL    PRIMARY KEY,
    user_id     INTEGER      NOT NULL,
    key         VARCHAR(255) NOT NULL,
    operation   VARCHAR(16)  NOT NULL CHECK (operation IN ('set', 'get', 'delete', 'rotate')),
    key_version SMALLINT,
    ip_address  INET,
    session_id  VARCHAR(36),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vault_audit_user
    ON auth.user_vault_audit (user_id, created_at DESC);

-- ==========================================================================
-- Key registry: master key version metadata (never stores actual keys)
-- ==========================================================================
CREATE TABLE IF NOT EXISTS auth.vault_key_registry (
    key_id      SMALLINT     PRIMARY KEY,
    description VARCHAR(255),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    retired_at  TIMESTAMPTZ,
    env_var     VARCHAR(100) NOT NULL
);
