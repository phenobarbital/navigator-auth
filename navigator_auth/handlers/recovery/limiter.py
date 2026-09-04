"""RateLimiter — fixed-window Redis counter for the recovery request
endpoint (FEAT-098, Module 4).

Step 1 of the recovery flow is public and unauthenticated. Without a
throttle it is an inbox-spam tool (repeat one address) and an
enumeration oracle (sweep many addresses). This is the counter only;
TASK-067 wires it into the handler. Not a generic app-wide rate-limit
middleware (explicit non-goal of the spec) — scoped to this feature's
endpoints.
"""
import hashlib
import logging

import redis.asyncio as aioredis

from navigator_auth.backends.oauth2.dcr import parse_rate_limit

logger = logging.getLogger(__name__)

RATE_KEY_PREFIX = "auth:recovery:rate:"


def _hash_key(value: str) -> str:
    """Never place a raw address (or any raw key material) in Redis."""
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


class RateLimiter:
    """Fixed-window Redis counter (INCR + EXPIRE on first hit).

    ``EXPIRE`` is only issued when ``INCR`` returns 1 (the first hit of a
    new window) — setting it on every call would turn this into a sliding
    window that never expires under sustained load.

    Fail-open by design: a Redis error returns ``True`` (allowed) rather
    than locking every user out of recovery when the cache is down. The
    outage is logged at WARNING so it stays visible.
    """

    def __init__(self, pool: aioredis.ConnectionPool, spec: str, prefix: str):
        self._pool = pool
        self._count, self._window = parse_rate_limit(spec)
        self._prefix = prefix

    async def check(self, key: str) -> bool:
        """True when the call is allowed."""
        if self._count <= 0:
            # parse_rate_limit() already normalizes an unset/malformed spec
            # to (0, 0) — that means "limiting disabled", never "blocked".
            return True

        redis_key = f"{RATE_KEY_PREFIX}{self._prefix}:{_hash_key(key)}"
        try:
            async with aioredis.Redis(connection_pool=self._pool) as redis:
                current = await redis.incr(redis_key)
                if current == 1:
                    await redis.expire(redis_key, self._window)
        except Exception as exc:  # noqa: BLE001 - fail-open by design
            logger.warning(
                "RateLimiter: Redis error, failing open for key=%r: %s",
                self._prefix,
                exc,
            )
            return True

        return current <= self._count
