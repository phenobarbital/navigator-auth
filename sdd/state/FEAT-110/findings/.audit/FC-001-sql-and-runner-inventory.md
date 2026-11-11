---
id: FC-001
query_id: Q010
type: glob
intent: "Inventory every SQL migration file and every migrations.py runner."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 0
---

# FC-001 — Inventory of SQL migration files and migration runners

## Summary

Three subsystem runners exist, each with its own `sql/` folder: identity (6 files), vault (2 files), passkey (1 file). One further SQL file, `navigator_auth/backends/oauth2/ddl.sql`, sits outside any runner. There is no shared/central migrations folder and no `docs/migrations/`.

## Citations

- path: `navigator_auth/identity/migrations.py`
  lines: 1-107
  symbol: `ensure_identity_columns`
- path: `navigator_auth/identity/sql/001_identity_credentials.sql`
- path: `navigator_auth/identity/sql/002_identity_id_token.sql`
- path: `navigator_auth/identity/sql/003_identity_key_version_integer.sql`
- path: `navigator_auth/identity/sql/004_identity_base_columns.sql`
- path: `navigator_auth/identity/sql/005_identity_legacy_uid_default.sql`
- path: `navigator_auth/identity/sql/006_identity_drop_legacy_uid.sql`
- path: `navigator_auth/vault/migrations.py`
  lines: 1-57
  symbol: `ensure_vault_tables`
- path: `navigator_auth/vault/sql/001_create_vault_tables.sql`
- path: `navigator_auth/vault/sql/002_vault_crypto_hardening.sql`
- path: `navigator_auth/passkey/migrations.py`
  lines: 1-60
  symbol: `ensure_passkey_tables`
- path: `navigator_auth/passkey/sql/001_passkey_credentials.sql`
- path: `navigator_auth/backends/oauth2/ddl.sql`

## Notes

No SQL files exist for the base tables (`auth.users`, `auth.groups`, …) under `navigator_auth/`.
