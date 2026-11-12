---
id: F013
query_id: Q023
type: git_log
intent: "Recent history of identity migrations: which changes a stale local auth.user_identities is likely missing."
executed_at: 2026-11-11T13:44:31Z
duration_ms: 400
parent_id: null
depth: 0
merged_from: [FG-001]
---

# F013 — Identity migration history (navigator_auth/identity/, last 120 days)

## Summary

20 commits (cap reached), nearly all by Jesus Lara, 2026-08-21 → 2026-10-23. Migrations on `auth.user_identities` grew from 002 to 006 in under two months: 002 (id_token, 2026-09-04), 003 (integer key_version, 2026-09-16), 004 (base columns, 2026-10-23), 005 (legacy uid default) and 006 (drop legacy uid), both 2026-10-23. Each new SQL file also required a matching edit to `navigator_auth/identity/migrations.py` (the `_MIGRATION_FILES` registry) — commit 95d98e0 exists only because 006 was added but not registered, leaving it inert. Commit 569383d shows migrations run at app startup via `setup_identity_columns`, which never raises, so a failed file left a half-migrated schema silently.

## Citations

- path: `navigator_auth/identity/migrations.py`
  commit: `569383d` — 2026-10-23 — Jesus Lara — "fix(identity): isolate migration failures so later files still run"
  files: `navigator_auth/identity/migrations.py`, `tests/unit/identity/test_identity_migrations.py`
  excerpt: |
    `ensure_identity_columns` looped `_MIGRATION_FILES` with no error handling,
    so the first failure aborted the loop and `setup_identity_columns` swallowed
    it behind one vague log line. A `003` that hit a lock timeout therefore kept
    `004`, `005` and `006` from ever running, and startup carried on against a
    half-migrated schema
    ...
    `_run_sql` acquires a fresh connection per file ... every file
    guards its own effect on a catalog lookup

- path: `navigator_auth/identity/migrations.py`
  commit: `95d98e0` — 2026-10-23 — Jesus Lara — "fix(identity): run 006 at startup so legacy uid is actually dropped"
  files: `navigator_auth/identity/migrations.py`, `tests/test_identity_id_token.py`, `tests/unit/identity/test_identity_migrations.py`
  excerpt: |
    Registers `006_identity_drop_legacy_uid.sql` in `_MIGRATION_FILES`, after
    `005` ... Without this the migration file is inert

- path: `navigator_auth/identity/sql/006_identity_drop_legacy_uid.sql`
  commit: `64d18bd` — 2026-10-23 — Jesus Lara — "fix(identity): drop the legacy uid column from auth.user_identities"
  files: `navigator_auth/identity/sql/005_identity_legacy_uid_default.sql`, `navigator_auth/identity/sql/006_identity_drop_legacy_uid.sql`

- path: `navigator_auth/identity/sql/005_identity_legacy_uid_default.sql`
  commit: `ccce461` — 2026-10-23 — Jesus Lara — "fix(identity): migration 005 so the legacy uid column cannot block the vault write"
  files: `navigator_auth/identity/migrations.py`, `navigator_auth/identity/sql/005_identity_legacy_uid_default.sql`

- path: `navigator_auth/identity/sql/004_identity_base_columns.sql`
  commit: `81b6663` — 2026-10-23 — Jesus Lara — "feat(external-provider-token-capture): TASK-102 — identity base columns migration 004"
  files: `navigator_auth/identity/migrations.py`, `navigator_auth/identity/sql/004_identity_base_columns.sql`

- path: `navigator_auth/identity/sql/003_identity_key_version_integer.sql`
  commit: `d9906ac` — 2026-09-16 — Jesus Lara — "feat(vault-crypto-hardening): TASK-078 — Session Vault HTTP API v2 — metadata only, typed errors, audit migration"
  files: `navigator_auth/identity/migrations.py`, `navigator_auth/identity/sql/003_identity_key_version_integer.sql`

- path: `navigator_auth/identity/sql/002_identity_id_token.sql`
  commit: `b2c7c32` — 2026-09-04 — Jesus Lara — "feat(external-token-exchange): TASK-047 — Vault id_token column + find_user_by_provider_account"
  files: `navigator_auth/identity/migrations.py`, `navigator_auth/identity/sql/002_identity_id_token.sql`, `navigator_auth/identity/store.py`, `navigator_auth/identity/types.py`

- path: `navigator_auth/identity/migrations.py`
  commits (style only): `0155604`, `4e19fda` — 2026-10-23 — Jesus Lara — f-string logging / black formatting

- path: `navigator_auth/identity/store.py`
  commits (non-migration, same window): `29ace8c`, `a7be28a`, `19d6c43`, `a444b71` (2026-10-23), `5af071b`, `d7dbc8f` (2026-09-16), `76efc60` (2026-08-21, author Claude)

## Notes

- Log was capped at 20; 001_identity_credentials.sql predates the window/cap and its commit was not retrieved.
- 569383d body says 95d98e0's fix was "Verified on the dev database (`navigator`)" — migrations were applied to a shared dev DB by app startup, which fits the source's complaint that a local DB lags.
- [cross-lane: type=read, intent=confirm in navigator_auth/identity/migrations.py that setup_identity_columns is a startup hook that never raises and that _MIGRATION_FILES is a hand-maintained list]
