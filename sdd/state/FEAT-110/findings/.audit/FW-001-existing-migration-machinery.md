---
id: FW-001
query_id: Q001
type: wiki_query
intent: "Orient: find existing migration machinery for auth tables."
executed_at: 2026-11-11T13:42:30Z
duration_ms: 0
parent_id: null
depth: 0
---

# FW-001 — Existing migration machinery: three per-subsystem runners, no central one

## Summary

The wiki surfaces three independent migration runners, each with its own `sql/` folder: vault, passkey and identity. A fourth (MFA, TASK-130) is specified but not yet implemented. No page describes a central migration runner, a version ledger, or a `docs/migrations/` folder.

## Citations

- path: `navigator_auth/vault/migrations.py`
  symbol: `ensure_vault_tables`
  wiki_page_id: `file:navigator_auth/vault/migrations.py` (score 1.00)
- path: `navigator_auth/passkey/migrations.py`
  wiki_page_id: `file:navigator_auth/passkey/migrations.py` (score 0.33)
- path: `navigator_auth/vault/sql`
  wiki_page_id: `dir:navigator_auth/vault/sql` (score 0.16, 2 entries)
- path: `navigator_auth/identity/sql/005_identity_legacy_uid_default.sql`
  wiki_page_id: same (score 0.04)
- path: `sdd/tasks/active/TASK-130-mfa-migrations.md`
  wiki_page_id: same (score 0.36)
- path: `sdd/tasks/completed/TASK-102-identity-base-columns-migration.md`
  wiki_page_id: same (score 0.11)
- path: `tests/test_passkey_migrations.py`
  symbol: `test_ensure_passkey_tables_uses_pool`
  wiki_page_id: same (score 0.30)
- path: `tests/unit/vault/test_migrations.py`
  wiki_page_id: same (score 0.00)
- path: `.agent/skills/database-schema-validator/SKILL.md`
  wiki_page_id: same (score 0.03)

## Notes

The `database-schema-validator` skill page (read as follow-up) is a generic demo skill (forbids table drops, requires snake_case and an `id` PK) that refers to a `scripts/validate_schema.py`; it is not wired to this repo's migrations and its "every table has an `id` PK" rule does not match the auth tables.
