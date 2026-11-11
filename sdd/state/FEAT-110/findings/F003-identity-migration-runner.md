---
id: F003
query_id: Q012
type: read
intent: "Read the identity migration runner: ordering, idempotency, schema templating, failure handling."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 0
merged_from: [FC-003, FC-011, FW-004, FW-003]
---

# F003 — Identity runner: ordered tuple, re-run every startup, collect-then-raise

## Summary

[FC-003] `ensure_identity_columns` runs a hard-coded ordered tuple `_MIGRATION_FILES` (001–006) on every startup; each file runs in its own connection via `_run_sql` (`conn.execute(sql)` of the whole file). Failures are collected, remaining files still run, then one `RuntimeError` names all failed files. SQL is NOT templated: `auth.user_identities` is hard-coded (no `{schema}` substitution). `setup_identity_columns` is the log-only wrapper.

[FC-011] No matches found for `schema_migrations|schema_version|applied_migrations|migration_history` (case-insensitive) in `navigator_auth/`, `docs/`, `documentation/`. Nothing records which migration files a database has received; state is inferred only by re-running idempotent SQL.

[FW-004] `navigator_auth/identity/migrations.py` holds a hard-coded tuple `_MIGRATION_FILES` (001–006) read from `SQL_DIR = Path(__file__).parent / "sql"`. `ensure_identity_columns(db_pool)` runs every file on every call, each in its own connection, continues past a failing file and raises one `RuntimeError` naming all failures. `setup_identity_columns(db_pool)` is the startup wrapper that logs and never raises. Idempotency lives in the SQL (`IF NOT EXISTS` / catalog guards), not in any applied-migrations record. The SQL is not templated: schema `auth` is literal (contrast FW-006).

[FW-003] `auth.user_identities` columns come from numbered SQL files under `navigator_auth/identity/sql/` (001–006 per the runner, see FW-004), applied by `ensure_identity_columns`. `IdentityTarget` declares the token columns for the vault. This is the table the source says is behind on the local database.

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

- path: `navigator_auth/identity/migrations.py`
  lines: 21-23
  symbol: `_MIGRATION_FILES`
  excerpt: |
    # Applied in order, at every startup. Idempotent: each file uses
    # `ADD COLUMN IF NOT EXISTS` / `CREATE ... IF NOT EXISTS`, or guards its
    # effect on a catalog lookup (003, 005, 006).

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

[FC-003] No record is kept of which files were applied; idempotency of each SQL file is the only safety. Session memory (not re-verified in this lane) says asyncdb's pg `conn.execute()` swallows DB errors — if so, the failure collection here may never trigger and a new command should use a fail-closed execution path.

[FC-011] "Check the existing migrations and compare with existing tables" (source) therefore needs a design decision: introduce a ledger table, or rely on idempotent re-run + catalog introspection.

[FW-004] Module docstring: every file is additive except `006`, which removes the legacy `uid` column (guarded no-op on a canonical database).
The wiki page gives no line numbers. [cross-lane: type=read, intent=line ranges for navigator_auth/identity/migrations.py symbols (plan Q012)]
`_run_sql` ignores the return value of `conn.execute()`; see FW-009 for why that can hide a failed migration.

[FW-003] `002_identity_id_token.sql` is not in the query result but is listed in the runner (FW-004).
