---
id: FW-003
query_id: Q003
type: wiki_query
intent: "Orient: find what defines the auth.user_identities columns."
executed_at: 2026-11-11T13:42:30Z
duration_ms: 0
parent_id: null
depth: 0
---

# FW-003 — auth.user_identities is shaped by six ordered SQL files plus the UserIdentity model

## Summary

`auth.user_identities` columns come from numbered SQL files under `navigator_auth/identity/sql/` (001–006 per the runner, see FW-004), applied by `ensure_identity_columns`. `IdentityTarget` declares the token columns for the vault. This is the table the source says is behind on the local database.

## Citations

- path: `navigator_auth/identity/targets.py`
  symbol: `IdentityTarget`
  wiki_page_id: `sym:navigator_auth/identity/targets.py#IdentityTarget` (score 1.00)
- path: `navigator_auth/identity/sql/001_identity_credentials.sql`
  wiki_page_id: same (score 0.43)
- path: `navigator_auth/identity/sql/003_identity_key_version_integer.sql`
  wiki_page_id: same (score 0.75)
- path: `navigator_auth/identity/sql/004_identity_base_columns.sql`
  wiki_page_id: same (score 0.51)
- path: `navigator_auth/identity/sql/005_identity_legacy_uid_default.sql`
  wiki_page_id: same (score 0.26)
- path: `navigator_auth/identity/sql/006_identity_drop_legacy_uid.sql`
  wiki_page_id: same (score 0.44)
- path: `navigator_auth/identity/migrations.py`
  symbol: `ensure_identity_columns`
  wiki_page_id: `sym:navigator_auth/identity/migrations.py#ensure_identity_columns` (score 0.09)
- path: `tests/unit/identity/test_identity_migrations.py`
  symbol: `TestSQLFile.test_base_columns_sql_is_additive_and_guarded`
  wiki_page_id: same (score 0.15)
- path: `documentation/identity-vault.md`
  wiki_page_id: same (score 0.00)

## Notes

`002_identity_id_token.sql` is not in the query result but is listed in the runner (FW-004).
