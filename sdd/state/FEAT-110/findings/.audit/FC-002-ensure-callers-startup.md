---
id: FC-002
query_id: Q011
type: grep
intent: "Find where the ensure_* migration functions are invoked (startup, CLI, tests)."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 0
---

# FC-002 — Migrations run only from application startup hooks

## Summary

Every migration runner is invoked from aiohttp startup, never from a CLI. `AuthHandler.auth_startup` calls the non-raising wrappers `setup_vault_tables` and `setup_identity_columns` when `"authdb"` is in the app; `PasskeyAuth.on_startup` calls `ensure_passkey_tables` and raises `ConfigError` on failure. All use the application pool `app["authdb"]`, i.e. the runtime DB user.

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

## Notes

Startup wrappers swallow failures (log only), so a DB whose runtime user lacks DDL rights stays behind silently — consistent with the source's "my local auth.user_identities lacks changes".
