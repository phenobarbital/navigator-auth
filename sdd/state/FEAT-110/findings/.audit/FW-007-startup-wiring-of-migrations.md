---
id: FW-007
query_id: Q008
type: wiki_related
intent: "Who references the identity migration runner (startup hook vs manual)."
executed_at: 2026-11-11T13:50:00Z
duration_ms: 0
parent_id: null
depth: 1
---

# FW-007 — Migrations already run automatically at app startup with the application's own DB pool

## Summary

`wiki_related` shows only the unit test referencing the identity runner module, but a follow-up query locates the real caller: `AuthHandler.auth_startup` runs `setup_vault_tables(app["authdb"])` and `setup_identity_columns(app["authdb"])` on every boot when `authdb` is in the app. So vault and identity changes are not manual today; they run with the runtime pool's credentials and failures are only logged. This matters for the source's "admin-based credentials" request: the current path assumes the application role may run DDL.

## Citations

- path: `navigator_auth/auth.py`
  lines: 178-203
  symbol: `AuthHandler.auth_startup`
  wiki_page_id: `sym:navigator_auth/auth.py#AuthHandler.auth_startup` (score 1.00)
  excerpt: |
    # Create vault tables if they don't exist (non-blocking)
    setup_vault_keyring(app)
    if "authdb" in app:
        await setup_vault_tables(app["authdb"])
        await setup_identity_columns(app["authdb"])
- path: `tests/unit/identity/test_identity_migrations.py`
  symbol: `TestSetupIdentityColumns.test_applies_the_rest_when_one_migration_fails`
  wiki_page_id: same (edge: references)
- path: `examples/sql/identity_vault_schema.sql`
  wiki_page_id: same (score 1.00 in follow-up query)
  excerpt: |
    -- navigator-auth expects the Navigator `auth` schema to exist already (it is
    -- created by the Navigator platform, not by this library).

## Notes

`examples/sql/identity_vault_schema.sql` states that base tables (`auth.users`, `auth.user_identities`) are created by the Navigator platform, not by this library; the library only ships additive migrations on top. A `self upgrade` command inherits that boundary unless the spec widens it.
`wikitoolkit symbols lookup/blast` crashed with a traceback, so the caller set was not verified structurally.
[cross-lane: type=grep, intent=all call sites of setup_vault_tables / setup_identity_columns / ensure_* (plan Q011)]
