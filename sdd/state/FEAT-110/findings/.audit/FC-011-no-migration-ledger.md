---
id: FC-011
query_id: Q021
type: grep
intent: "Prove presence/absence of an applied-migrations tracking table."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 0
---

# FC-011 — No applied-migrations ledger exists

## Summary

No matches found for `schema_migrations|schema_version|applied_migrations|migration_history` (case-insensitive) in `navigator_auth/`, `docs/`, `documentation/`. Nothing records which migration files a database has received; state is inferred only by re-running idempotent SQL.

## Citations

- path: `navigator_auth/identity/migrations.py`
  lines: 21-23
  symbol: `_MIGRATION_FILES`
  excerpt: |
    # Applied in order, at every startup. Idempotent: each file uses
    # `ADD COLUMN IF NOT EXISTS` / `CREATE ... IF NOT EXISTS`, or guards its
    # effect on a catalog lookup (003, 005, 006).

## Notes

"Check the existing migrations and compare with existing tables" (source) therefore needs a design decision: introduce a ledger table, or rely on idempotent re-run + catalog introspection.
