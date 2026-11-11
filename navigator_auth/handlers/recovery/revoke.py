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


class RevocationError(Exception):
    """Strict revocation could not prove that every session and token of a user was revoked.

    Raised only by ``SessionRevoker.revoke_user(..., strict=True)``; the message is secret-free.
    """


class SessionRevoker:
    """Kills live sessions + JWTs for a user. Best-effort per record (strict mode opt-in)."""

    def __init__(self, session_pool: aioredis.ConnectionPool):
        self._session_pool = session_pool

    async def revoke_user(self, request, user, *, strict: bool = False) -> int:
        """Revoke a user's live session and every indexed JWT ``jti``.

        Args:
            request: Current request (its ``app["auth"].backends`` expose ``access_token_storage``).
            user: Mapping or object with ``username`` and ``user_id``.
            strict: ``False`` (default, FEAT-098) - best-effort, failures are logged and not counted.
                ``True`` (FEAT-106 review fixes: password reset / recovery) - attempt every record, then
                raise when any session, index or token revocation failed or a required backend is missing.

        Returns:
            The count of records actually revoked.

        Raises:
            RevocationError: Only in strict mode.
        """
        failures: Optional[list[str]] = [] if strict else None
        count = 0
        count += await self._revoke_session(user, failures)
        count += await self._revoke_jtis(request, user, failures)
        if failures:
            logger.error(
                "SessionRevoker: strict revocation incomplete for user_id=%s (%d failure(s), %d revoked)",
                _user_id_of(user),
                len(failures),
                count,
            )
            raise RevocationError(f"revocation incomplete: {', '.join(sorted(set(failures)))}")
        return count

    async def _revoke_session(self, user, failures: Optional[list[str]] = None) -> int:
        username = _username_of(user)
        if not username:
            if failures is not None:
                failures.append("username_missing")
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
                        if failures is not None:
                            failures.append("session_delete")
                        logger.warning(
                            "SessionRevoker: failed to delete session:%s: %s",
                            session_id,
                            exc,
                        )
                try:
                    if await redis.delete(f"user:{username}"):
                        revoked += 1
                except Exception as exc:  # pylint: disable=W0703
                    if failures is not None:
                        failures.append("session_index_delete")
                    logger.warning(
                        "SessionRevoker: failed to delete user:%s index: %s",
                        username,
                        exc,
                    )
        except Exception as exc:  # pylint: disable=W0703
            if failures is not None:
                failures.append("session_store_unreachable")
            logger.warning(
                "SessionRevoker: unable to reach session Redis for user %s: %s",
                username,
                exc,
            )
        return revoked

    async def _revoke_jtis(self, request, user, failures: Optional[list[str]] = None) -> int:
        user_id = _user_id_of(user)
        if user_id is None:
            if failures is not None:
                failures.append("user_id_missing")
            return 0
        if request is None:
            if failures is not None:
                failures.append("jti_backend_missing")
            return 0
        auth_handler = getattr(request, "app", {}).get("auth")
        if auth_handler is None:
            if failures is not None:
                failures.append("jti_backend_missing")
            return 0
        revoked = 0
        seen_storage = False
        key = f"{JTI_INDEX_PREFIX}{user_id}"
        for backend in getattr(auth_handler, "backends", {}).values():
            storage = getattr(backend, "access_token_storage", None)
            if storage is None:
                continue
            seen_storage = True
            try:
                jtis = await storage.redis.smembers(key)
            except Exception as exc:  # pylint: disable=W0703
                if failures is not None:
                    failures.append("jti_index_unreadable")
                logger.warning(
                    "SessionRevoker: unable to read jti index for user %s: %s",
                    user_id,
                    exc,
                )
                continue
            for jti in jtis:
                try:
                    await storage.revoke(jti)
                    revoked += 1
                except Exception as exc:  # pylint: disable=W0703
                    if failures is not None:
                        failures.append("jti_revoke")
                    logger.warning(
                        "SessionRevoker: failed to revoke jti=%s: %s",
                        jti,
                        exc,
                    )
                    continue
                try:
                    await storage.redis.srem(key, jti)
                except Exception as exc:  # pylint: disable=W0703
                    logger.warning(
                        "SessionRevoker: failed to prune jti=%s from index: %s",
                        jti,
                        exc,
                    )
        if not seen_storage and failures is not None:
            failures.append("jti_backend_missing")
        return revoked
