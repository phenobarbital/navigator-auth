---
id: FC-003
query_id: Q012
type: read
intent: "Read the identity migration runner: ordering, idempotency, schema templating, failure handling."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 0
---

# FC-003 — Identity runner: ordered tuple, re-run every startup, collect-then-raise

## Summary

`ensure_identity_columns` runs a hard-coded ordered tuple `_MIGRATION_FILES` (001–006) on every startup; each file runs in its own connection via `_run_sql` (`conn.execute(sql)` of the whole file). Failures are collected, remaining files still run, then one `RuntimeError` names all failed files. SQL is NOT templated: `auth.user_identities` is hard-coded (no `{schema}` substitution). `setup_identity_columns` is the log-only wrapper.

## Citations

- path: `navigator_auth/identity/migrations.py`
  lines: 18-31
  symbol: `_MIGRATION_FILES`
  excerpt: |
    SQL_DIR = Path(__file__).parent / "sql"
    _MIGRATION_FILES = (
        "001_identity_credentials.sql",
        ...
        "006_identity_drop_legacy_uid.sql",
    )
- path: `navigator_auth/identity/migrations.py`
  lines: 34-49
  symbol: `_run_sql`
  excerpt: |
    async def _run_sql(db_pool: Any, sql: str) -> None:
        ctx = db_pool.acquire()
        if hasattr(ctx, "__aenter__"):
            async with ctx as conn:
                await conn.execute(sql)
- path: `navigator_auth/identity/migrations.py`
  lines: 52-94
  symbol: `ensure_identity_columns`
  excerpt: |
    for filename in _MIGRATION_FILES:
        try:
            sql = (SQL_DIR / filename).read_text()
            await _run_sql(db_pool, sql)
        except Exception as err:
            failures.append(filename)
    if failures:
        raise RuntimeError(f"{len(failures)} of {len(_MIGRATION_FILES)} identity migrations failed: ...") from first_error
- path: `navigator_auth/identity/migrations.py`
  lines: 97-107
  symbol: `setup_identity_columns`

## Notes

No record is kept of which files were applied; idempotency of each SQL file is the only safety. Session memory (not re-verified in this lane) says asyncdb's pg `conn.execute()` swallows DB errors — if so, the failure collection here may never trigger and a new command should use a fail-closed execution path.
