"""Redis-backed, single-use storage for per-request OAuth2 flow state.

Backends are process-lifetime singletons, so per-login/per-link state
(state, nonce, redirect data, provider flow dicts) must never live on the
backend instance. This store keeps each flow payload in Redis under a
random ``state`` key with a short TTL, consumed exactly once by the
callback (GETDEL), which also provides CSRF protection.
"""
from typing import Any, Optional

import redis.asyncio as aioredis

from ..libs.json import json_encoder, json_decoder

LINK_KEY_PREFIX = "idlink:"


class IdentityFlowStore:
    """Small wrapper over an aioredis connection pool."""

    def __init__(self, pool: aioredis.ConnectionPool):
        self._pool = pool

    async def set(self, key: str, payload: dict, ttl: int) -> None:
        async with aioredis.Redis(connection_pool=self._pool) as redis:
            await redis.setex(key, ttl, json_encoder(payload))

    async def get(self, key: str) -> Optional[dict]:
        async with aioredis.Redis(connection_pool=self._pool) as redis:
            result = await redis.get(key)
        return json_decoder(result) if result else None

    async def getdel(self, key: str) -> Optional[dict]:
        """Fetch and atomically delete (single-use consumption)."""
        async with aioredis.Redis(connection_pool=self._pool) as redis:
            result = await redis.getdel(key)
        return json_decoder(result) if result else None

    async def delete(self, key: str) -> None:
        async with aioredis.Redis(connection_pool=self._pool) as redis:
            await redis.delete(key)

    # --- identity-link flow helpers -----------------------------------
    async def start_link(self, state: str, payload: dict, ttl: int) -> None:
        await self.set(f"{LINK_KEY_PREFIX}{state}", payload, ttl)

    async def consume_link(self, state: str) -> Optional[dict]:
        return await self.getdel(f"{LINK_KEY_PREFIX}{state}")
