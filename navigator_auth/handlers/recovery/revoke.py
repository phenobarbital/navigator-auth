"""SessionRevoker — kills a user's live Redis session and outstanding JWTs
(FEAT-098, Module 5).

This is what makes step 3 of the recovery flow ("revoke sessions and
outstanding JWTs") real rather than cosmetic. Two independent halves, both
best-effort so one failing deletion never aborts the rest:

  - the Redis session: ``session:{session_id}`` plus the ``user:{identity}``
    index key ``navigator_session`` writes on login (for Basic auth,
    ``identity`` is the **username**, not the user_id);
  - every outstanding JWT ``jti`` tracked under
    ``auth:user:jti:{user_id}`` (written by ``BasicAuth.open_session``,
    TASK-066), revoked via each backend's own ``access_token_storage``
    (found the same way ``AuthHandler._token_is_revoked`` finds it — by
    walking ``request.app['auth'].backends``).
"""
import logging
from typing import Optional

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

# Mirrors navigator_auth.backends.basic.JTI_INDEX_PREFIX. Duplicated (not
# imported) to avoid a recovery/ -> backends/ import for a single constant.
JTI_INDEX_PREFIX = "auth:user:jti:"


def _username_of(user) -> Optional[str]:
    if isinstance(user, dict):
        return user.get("username")
    return getattr(user, "username", None)


def _user_id_of(user):
    if isinstance(user, dict):
        return user.get("user_id")
    return getattr(user, "user_id", None)


class SessionRevoker:
    """Kills live sessions + JWTs for a user. Best-effort per record."""

    def __init__(self, session_pool: aioredis.ConnectionPool):
        self._session_pool = session_pool

    async def revoke_user(self, request, user) -> int:
        """Returns the count of records actually revoked."""
        count = 0
        count += await self._revoke_session(user)
        count += await self._revoke_jtis(request, user)
        return count

    async def _revoke_session(self, user) -> int:
        username = _username_of(user)
        if not username:
            return 0
        revoked = 0
        try:
            async with aioredis.Redis(connection_pool=self._session_pool) as redis:
                session_id = await redis.get(f"user:{username}")
                if session_id:
                    try:
                        if await redis.delete(f"session:{session_id}"):
                            revoked += 1
                    except Exception as exc:  # pylint: disable=W0703
                        logger.warning(
                            "SessionRevoker: failed to delete session:%s: %s",
                            session_id, exc,
                        )
                try:
                    if await redis.delete(f"user:{username}"):
                        revoked += 1
                except Exception as exc:  # pylint: disable=W0703
                    logger.warning(
                        "SessionRevoker: failed to delete user:%s index: %s",
                        username, exc,
                    )
        except Exception as exc:  # pylint: disable=W0703
            logger.warning(
                "SessionRevoker: unable to reach session Redis for user %s: %s",
                username, exc,
            )
        return revoked

    async def _revoke_jtis(self, request, user) -> int:
        user_id = _user_id_of(user)
        if user_id is None or request is None:
            return 0
        auth_handler = getattr(request, "app", {}).get("auth")
        if auth_handler is None:
            return 0
        revoked = 0
        key = f"{JTI_INDEX_PREFIX}{user_id}"
        for backend in getattr(auth_handler, "backends", {}).values():
            storage = getattr(backend, "access_token_storage", None)
            if storage is None:
                continue
            try:
                jtis = await storage.redis.smembers(key)
            except Exception as exc:  # pylint: disable=W0703
                logger.warning(
                    "SessionRevoker: unable to read jti index for user %s: %s",
                    user_id, exc,
                )
                continue
            for jti in jtis:
                try:
                    await storage.revoke(jti)
                    revoked += 1
                except Exception as exc:  # pylint: disable=W0703
                    logger.warning(
                        "SessionRevoker: failed to revoke jti=%s: %s", jti, exc,
                    )
                    continue
                try:
                    await storage.redis.srem(key, jti)
                except Exception as exc:  # pylint: disable=W0703
                    logger.warning(
                        "SessionRevoker: failed to prune jti=%s from index: %s",
                        jti, exc,
                    )
        return revoked
