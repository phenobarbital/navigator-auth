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
    # The vault stores rows keyed by an integer ``user_id``. Some auth
    # backends populate ``user_id`` with the username (a str) instead of the
    # numeric PK. Coerce here and skip vault loading when it is not an
    # integer — the vault is optional and must never raise on these users.
    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        logger.debug(
            "Skipping vault load: non-integer user_id %r", user_id
        )
        return None
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


async def get_session_vault(
    request: Any, session: Any, user_id: Any
) -> Optional[SessionVault]:
    """Get the session's vault, loading it on demand.

    Returns the vault stored in the session when present; otherwise
    tries to load it from ``request.app`` resources and caches it in
    the session. Returns None when the vault cannot be loaded — vault
    availability must never break the calling endpoint.
    """
    try:
        vault = session.get(VAULT_SESSION_KEY)
        if vault is not None:
            return vault
    except Exception:  # pylint: disable=W0703
        return None
    db_pool = request.app.get("authdb")
    redis = request.app.get("redis")
    if not db_pool or not user_id:
        return None
    vault = await load_vault_for_session(
        session, user_id=user_id, db_pool=db_pool, redis=redis
    )
    if vault is not None:
        try:
            session[VAULT_SESSION_KEY] = vault
        except Exception:  # pylint: disable=W0703
            pass
    return vault


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
