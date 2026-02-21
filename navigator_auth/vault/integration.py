"""
Vault Integration — Hooks for wiring SessionVault into navigator-auth.

Provides:
- ``load_vault_for_session()`` — load vault after login (non-blocking on failure)
- ``setup_vault_tables()`` — ensure vault DB tables exist on startup
- ``_attach_vault_to_request()`` — attach vault to request from session

Security Note:
    Vault failures MUST NOT block authentication. All integration functions
    catch exceptions and log errors rather than propagating them.
"""
import logging
from typing import Any, Optional

from navigator_session.vault.session_vault import SessionVault
from .migrations import ensure_vault_tables

logger = logging.getLogger("navigator.vault")

# Session key for storing the vault instance
VAULT_SESSION_KEY = "_vault"


async def load_vault_for_session(
    session: Any,
    user_id: int,
    db_pool: Any,
    redis: Any = None,
    session_ttl: int = 3600,
) -> Optional[SessionVault]:
    """Load vault for a user session after successful authentication.

    This wraps ``SessionVault.load_for_session()`` with error handling.
    Vault failure MUST NOT block login — errors are logged and None is returned.

    Args:
        session: Navigator session object (must have ``session_id`` attribute).
        user_id: Authenticated user's ID.
        db_pool: asyncpg-compatible connection pool.
        redis: Optional Redis client for session caching.
        session_ttl: TTL for Redis cache entries (seconds).

    Returns:
        SessionVault instance, or None if loading fails.
    """
    try:
        session_uuid = str(session.session_id)
        vault = await SessionVault.load_for_session(
            session_uuid=session_uuid,
            user_id=user_id,
            db_pool=db_pool,
            redis=redis,
            session_ttl=session_ttl,
        )
        logger.info("Vault loaded for user %s", user_id)
        return vault
    except Exception as err:
        logger.error("Failed to load vault for user %s: %s", user_id, err)
        return None


async def setup_vault_tables(db_pool: Any) -> None:
    """Create vault tables if they don't exist.

    Non-blocking: logs errors but does not raise. Called during app startup.

    Args:
        db_pool: asyncpg-compatible connection pool.
    """
    try:
        await ensure_vault_tables(db_pool)
    except Exception as err:
        logger.error("Failed to create vault tables: %s", err)


def _attach_vault_to_request(request: Any, session: Any) -> None:
    """Attach vault instance from session to the request object.

    Called by the ``@user_session`` decorator. Non-blocking on failure.

    Args:
        request: aiohttp web.Request object.
        session: Navigator session object.
    """
    try:
        vault = session.get(VAULT_SESSION_KEY)
        if vault is not None:
            request.vault = vault
    except Exception:
        pass
