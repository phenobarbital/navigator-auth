"""Fail-closed fixed-window MFA rate limiter."""

import hashlib
import logging

import redis.asyncio as aioredis
from redis.exceptions import RedisError

from navigator_auth.backends.oauth2.dcr import parse_rate_limit

logger = logging.getLogger("navigator.mfa")
RATE_KEY_PREFIX = "auth:mfa:rate:"
_INCR_WINDOW_LUA = """
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return n
"""


def _hash_key(value: str) -> str:
    """Hash a user or address before storing it."""
    return hashlib.sha256(str(value).strip().lower().encode()).hexdigest()


class StrictRateLimiter:
    """Fixed-window limiter that refuses requests when Redis fails."""

    def __init__(self, pool: aioredis.ConnectionPool, spec: str, prefix: str):
        self._pool, self._prefix = pool, prefix
        self._count, self._window = parse_rate_limit(spec)
        if spec and (self._count, self._window) == (0, 0):
            logger.warning("StrictRateLimiter %r: unparseable spec %r — limiting disabled", prefix, spec)

    async def check(self, key: str) -> bool:
        """Return whether the request is allowed; refuse on storage errors."""
        if self._count <= 0:
            return True
        redis_key = f"{RATE_KEY_PREFIX}{self._prefix}:{_hash_key(key)}"
        try:
            async with aioredis.Redis(connection_pool=self._pool) as redis:
                current = int(await redis.eval(_INCR_WINDOW_LUA, 1, redis_key, self._window))
            return current <= self._count
        except RedisError as exc:
            logger.warning("StrictRateLimiter %r: storage error, refusing: %s", self._prefix, type(exc).__name__)
            return False
