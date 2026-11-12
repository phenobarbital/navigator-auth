---
id: F002
query_id: Q011
type: grep
intent: "Find where the ensure_* migration functions are invoked (startup, CLI, tests)."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 1
merged_from: [FC-002, FW-007]
---

# F002 — Migrations run only from application startup hooks

## Summary

[FC-002] Every migration runner is invoked from aiohttp startup, never from a CLI. `AuthHandler.auth_startup` calls the non-raising wrappers `setup_vault_tables` and `setup_identity_columns` when `"authdb"` is in the app; `PasskeyAuth.on_startup` calls `ensure_passkey_tables` and raises `ConfigError` on failure. All use the application pool `app["authdb"]`, i.e. the runtime DB user.

[FW-007] `wiki_related` shows only the unit test referencing the identity runner module, but a follow-up query locates the real caller: `AuthHandler.auth_startup` runs `setup_vault_tables(app["authdb"])` and `setup_identity_columns(app["authdb"])` on every boot when `authdb` is in the app. So vault and identity changes are not manual today; they run with the runtime pool's credentials and failures are only logged. This matters for the source's "admin-based credentials" request: the current path assumes the application role may run DDL.

## Citations

- path: `navigator_auth/auth.py`
  lines: 178-192
  symbol: `auth_startup`
  excerpt: |
    # Create vault tables if they don't exist (non-blocking)
    setup_vault_keyring(app)
    if "authdb" in app:
        await setup_vault_tables(app["authdb"])
        await setup_identity_columns(app["authdb"])
- path: `navigator_auth/auth.py`
  lines: 34-38
  symbol: `setup_identity_columns`
  excerpt: |
    from .identity.migrations import setup_identity_columns
- path: `navigator_auth/vault/integration.py`
  lines: 102-113
  symbol: `setup_vault_tables`
  excerpt: |
    async def setup_vault_tables(db_pool: Any) -> None:
        """... Non-blocking: logs errors but does not raise. Called during app startup."""
        try:
            await ensure_vault_tables(db_pool)
        except Exception as err:
            logger.error("Failed to create vault tables: %s", err)
- path: `navigator_auth/backends/passkey.py`
  lines: 103-106
  symbol: `on_startup`
  excerpt: |
    try:
        await ensure_passkey_tables(app["authdb"])
    except Exception as err:  # pylint: disable=W0703
        raise ConfigError(f"PasskeyAuth: could not create passkey tables: {err}") from err

- path: `navigator_auth/auth.py`
  lines: 178-203
  symbol: `auth_startup`
  wiki_page_id: `sym:navigator_auth/auth.py#auth_startup` (score 1.00)
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

[FC-002] Startup wrappers swallow failures (log only), so a DB whose runtime user lacks DDL rights stays behind silently — consistent with the source's "my local auth.user_identities lacks changes".

[FW-007] `examples/sql/identity_vault_schema.sql` states that base tables (`auth.users`, `auth.user_identities`) are created by the Navigator platform, not by this library; the library only ships additive migrations on top. A `self upgrade` command inherits that boundary unless the spec widens it.
`wikitoolkit symbols lookup/blast` crashed with a traceback, so the caller set was not verified structurally.
[cross-lane: type=grep, intent=all call sites of setup_vault_tables / setup_identity_columns / ensure_* (plan Q011)]
