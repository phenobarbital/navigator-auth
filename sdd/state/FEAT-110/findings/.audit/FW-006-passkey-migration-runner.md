---
id: FW-006
query_id: Q006
type: wiki_page
intent: "API outline of the passkey startup migration."
executed_at: 2026-11-11T13:50:00Z
duration_ms: 0
parent_id: null
depth: 0
---

# FW-006 — Passkey runner: templated SQL ({schema}, {users_table}), run only when the backend is enabled

## Summary

`navigator_auth/passkey/migrations.py` adds `render_sql`, which substitutes `{schema}` and `{users_table}` from `AUTH_DB_SCHEMA` / `AUTH_USERS_TABLE` in `navigator_auth/conf.py`. `ensure_passkey_tables` is called from `PasskeyAuth.on_startup`, so the tables exist only where that backend is configured. It is a third copy of `_run_sql`. A single upgrade command would have to decide whether optional-feature tables are applied unconditionally.

## Citations

- path: `navigator_auth/passkey/migrations.py`
  symbol: `render_sql`
  wiki_page_id: `file:navigator_auth/passkey/migrations.py`
  excerpt: |
    def render_sql(sql: str) -> str:
        return sql.replace("{schema}", AUTH_DB_SCHEMA).replace("{users_table}", AUTH_USERS_TABLE)
- path: `navigator_auth/passkey/migrations.py`
  symbol: `_MIGRATION_FILES`
  excerpt: |
    _MIGRATION_FILES = ("001_passkey_credentials.sql",)
- path: `navigator_auth/passkey/migrations.py`
  symbol: `ensure_passkey_tables`
- path: `navigator_auth/passkey/migrations.py`
  symbol: `setup_passkey_tables`
- path: `navigator_auth/passkey/sql/001_passkey_credentials.sql`
  wiki_page_id: same (score 0.73 in follow-up query)
- path: `navigator_auth/backends/passkey.py`
  lines: 93-106
  symbol: `PasskeyAuth.on_startup`
  wiki_page_id: `sym:navigator_auth/backends/passkey.py#PasskeyAuth.on_startup`
  excerpt: |
    try:
        await ensure_passkey_tables(app["authdb"])
    except Exception as err:  # pylint: disable=W0703
        raise ConfigError(f"PasskeyAuth: could not create passkey tables: {err}") from err
- path: `navigator_auth/conf.py`
  symbol: `AUTH_DB_SCHEMA`
- path: `navigator_auth/conf.py`
  symbol: `AUTH_USERS_TABLE`

## Notes

Identity and vault SQL hard-code the `auth` schema; passkey (and the planned MFA file) use placeholders. Two conventions coexist.
