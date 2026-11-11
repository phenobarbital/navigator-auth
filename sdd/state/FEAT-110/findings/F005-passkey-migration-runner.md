---
id: F005
query_id: Q014
type: read
intent: "Read the passkey migration runner for the same contract."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 0
merged_from: [FC-005, FW-006]
---

# F005 — Passkey runner: the only one that templates schema/table names

## Summary

[FC-005] `ensure_passkey_tables` runs `_MIGRATION_FILES` (1 file) after `render_sql`, which substitutes `{schema}` and `{users_table}` from `AUTH_DB_SCHEMA` / `AUTH_USERS_TABLE`. It is gated on the passkey backend being enabled (run from `PasskeyAuth.on_startup`). `setup_passkey_tables` is a log-only wrapper.

[FW-006] `navigator_auth/passkey/migrations.py` adds `render_sql`, which substitutes `{schema}` and `{users_table}` from `AUTH_DB_SCHEMA` / `AUTH_USERS_TABLE` in `navigator_auth/conf.py`. `ensure_passkey_tables` is called from `PasskeyAuth.on_startup`, so the tables exist only where that backend is configured. It is a third copy of `_run_sql`. A single upgrade command would have to decide whether optional-feature tables are applied unconditionally.

## Citations

- path: `navigator_auth/passkey/migrations.py`
  lines: 11-22
  symbol: `render_sql`
  excerpt: |
    from ..conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE
    _MIGRATION_FILES = ("001_passkey_credentials.sql",)
    def render_sql(sql: str) -> str:
        """Substitute ``{schema}`` and ``{users_table}`` in a migration file."""
        return sql.replace("{schema}", AUTH_DB_SCHEMA).replace("{users_table}", AUTH_USERS_TABLE)
- path: `navigator_auth/passkey/migrations.py`
  lines: 43-52
  symbol: `ensure_passkey_tables`
- path: `navigator_auth/passkey/migrations.py`
  lines: 55-60
  symbol: `setup_passkey_tables`

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
- path: `navigator_auth/conf.py`
  symbol: `AUTH_USERS_TABLE`

## Notes

[FC-005] Inconsistency a unified command must settle: passkey SQL is schema-templated, identity/vault SQL hard-codes `auth.`. Feature-gated sets (passkey) need an opt-in/selection rule in a global "upgrade".

[FW-006] Identity and vault SQL hard-code the `auth` schema; passkey (and the planned MFA file) use placeholders. Two conventions coexist.
