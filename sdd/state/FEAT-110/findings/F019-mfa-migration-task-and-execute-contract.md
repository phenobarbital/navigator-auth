---
id: F019
query_id: Q009
type: wiki_page
intent: "In-flight MFA migration task: a fourth migration set that the new command must also cover."
executed_at: 2026-11-11T13:50:00Z
duration_ms: 0
parent_id: null
depth: 0
merged_from: [FW-009]
---

# F019 — MFA migration (TASK-130, pending) adds a fourth runner and documents that execute() hides failures

## Summary

TASK-130 (FEAT-106, status pending) will create `navigator_auth/mfa/migrations.py` and `navigator_auth/mfa/sql/001_mfa_tables.sql` (six tables, `{schema}`/`{users_table}` placeholders), mirroring the passkey runner. The task records a verified fact: asyncdb's `conn.execute()` never raises and returns `[None, <error>]`, so the existing runners, which ignore that return value, can report success without applying anything. The MFA runner therefore inspects the result and confirms with a `to_regclass` probe via `fetchval`.

## Citations

- path: `sdd/tasks/active/TASK-130-mfa-migrations.md`
  wiki_page_id: same
  excerpt: |
    1. **asyncdb's `conn.execute()` NEVER raises (contract D25).** ...
       `await conn.execute("SELECT * FROM auth.no_such_table")`
       returns `[None, UndefinedTableError(...)]` ... The passkey migration
       ignores that return value, so it can "succeed" without creating anything.
- path: `sdd/tasks/active/TASK-130-mfa-migrations.md`
  excerpt: |
    - Create `navigator_auth/mfa/sql/001_mfa_tables.sql` with the six tables + indexes.
    - Create `navigator_auth/mfa/migrations.py`: `render_sql`, `ensure_mfa_tables`,
      `mfa_tables_present`, `setup_mfa_tables`.
- path: `sdd/tasks/active/TASK-130-mfa-migrations.md`
  excerpt: |
    from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE   # conf.py:33-34 ("auth", "users")
    from navigator_auth.conf import REDIS_AUTH_URL, default_dsn       # conf.py:297, :45
- path: `sdd/tasks/active/TASK-130-mfa-migrations.md`
  excerpt: |
    `pyproject.toml` sets `filterwarnings = ["error", …]`; constructing `asyncdb.AsyncPool("pg", …)`
    imports `google.api_core`, which emits a `FutureWarning` → ... the existing
    `tests/test_passkey_store.py` **skips all 4 tests** today for this reason

## Notes

`navigator_auth/mfa/` does not exist yet (the task lists both files as CREATE); do not cite it as present.
Implications for a migration command: (1) it must check `execute()`'s return value or use a raising call, otherwise "applied" is unreliable; (2) live-Postgres tests need the `FutureWarning` filter or they silently skip; (3) `default_dsn` in `navigator_auth/conf.py` is the current DSN source (line numbers quoted from the task, not re-verified here).
[cross-lane: type=read, intent=verify conf.py:33-34 and :45 for AUTH_DB_SCHEMA / AUTH_USERS_TABLE / default_dsn (plan Q017)]
