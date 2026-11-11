---
id: FC-005
query_id: Q014
type: read
intent: "Read the passkey migration runner for the same contract."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 0
---

# FC-005 — Passkey runner: the only one that templates schema/table names

## Summary

`ensure_passkey_tables` runs `_MIGRATION_FILES` (1 file) after `render_sql`, which substitutes `{schema}` and `{users_table}` from `AUTH_DB_SCHEMA` / `AUTH_USERS_TABLE`. It is gated on the passkey backend being enabled (run from `PasskeyAuth.on_startup`). `setup_passkey_tables` is a log-only wrapper.

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

## Notes

Inconsistency a unified command must settle: passkey SQL is schema-templated, identity/vault SQL hard-codes `auth.`. Feature-gated sets (passkey) need an opt-in/selection rule in a global "upgrade".
