---
id: FW-004
query_id: Q004
type: wiki_page
intent: "API outline of the identity migration runner (the table the source says is behind locally)."
executed_at: 2026-11-11T13:50:00Z
duration_ms: 0
parent_id: null
depth: 0
---

# FW-004 — Identity runner: hard-coded ordered file tuple, re-run at every startup, no ledger

## Summary

`navigator_auth/identity/migrations.py` holds a hard-coded tuple `_MIGRATION_FILES` (001–006) read from `SQL_DIR = Path(__file__).parent / "sql"`. `ensure_identity_columns(db_pool)` runs every file on every call, each in its own connection, continues past a failing file and raises one `RuntimeError` naming all failures. `setup_identity_columns(db_pool)` is the startup wrapper that logs and never raises. Idempotency lives in the SQL (`IF NOT EXISTS` / catalog guards), not in any applied-migrations record. The SQL is not templated: schema `auth` is literal (contrast FW-006).

## Citations

- path: `navigator_auth/identity/migrations.py`
  symbol: `_MIGRATION_FILES`
  wiki_page_id: `file:navigator_auth/identity/migrations.py`
  excerpt: |
    _MIGRATION_FILES = (
        "001_identity_credentials.sql",
        "002_identity_id_token.sql",
        "003_identity_key_version_integer.sql",
        "004_identity_base_columns.sql",
        "005_identity_legacy_uid_default.sql",
        "006_identity_drop_legacy_uid.sql",
    )
- path: `navigator_auth/identity/migrations.py`
  symbol: `_run_sql`
  excerpt: |
    async def _run_sql(db_pool: Any, sql: str) -> None:
        ctx = db_pool.acquire()
        if hasattr(ctx, "__aenter__"):
            async with ctx as conn:
                await conn.execute(sql)
- path: `navigator_auth/identity/migrations.py`
  symbol: `ensure_identity_columns`
  excerpt: |
    if failures:
        raise RuntimeError(
            f"{len(failures)} of {len(_MIGRATION_FILES)} identity migrations failed: {', '.join(failures)}"
        ) from first_error
- path: `navigator_auth/identity/migrations.py`
  symbol: `setup_identity_columns`
  excerpt: |
    try:
        await ensure_identity_columns(db_pool)
    except Exception as err:  # pylint: disable=W0703
        logger.error(f"Failed to ensure identity credential columns: {err}")

## Notes

Module docstring: every file is additive except `006`, which removes the legacy `uid` column (guarded no-op on a canonical database).
The wiki page gives no line numbers. [cross-lane: type=read, intent=line ranges for navigator_auth/identity/migrations.py symbols (plan Q012)]
`_run_sql` ignores the return value of `conn.execute()`; see FW-009 for why that can hide a failed migration.
