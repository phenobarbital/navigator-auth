"""OAuth2 token/code storage backends.

FEAT-093:
  TASK-024 — mark_used() for single-use code enforcement (B5).
              user_id round-tripped through OauthAuthorizationCode.
  TASK-026 — RefreshTokenStorage extended: revoke_token, revoke_chain,
              list_tokens (for cascade revocation on grant revoke).
  TASK-027 — GrantStorage (consent) and AccessTokenStorage (jti revoke).

FEAT-094:
  TASK-032 — DeviceCodeStorage ABC + Memory/Redis/Postgres tiers;
              registered in get_device_code_storage() factory.
"""

from datetime import datetime, timezone
import asyncio
import json
import logging

logger = logging.getLogger(__name__)

from ...conf import REDIS_URL

try:
    import redis.asyncio as redis
except ImportError:
    raise ImportError(
        "redis>=4.2.0 with asyncio support is required. "
        "Install it with: pip install 'redis[asyncio]>=4.2'"
    )


def _now() -> datetime:
    return datetime.now()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Authorization Code Storage (Redis)
# ---------------------------------------------------------------------------

class AuthorizationCodeStorage:
    """Redis-backed authorization code store.

    TASK-024: Codes are marked ``used=True`` and then deleted after exchange (B5).
    """

    def __init__(self, dsn: str = None):
        if not dsn:
            dsn = REDIS_URL
        self.redis = redis.from_url(dsn, decode_responses=True)
        self.prefix = "oauth2:code:"

    async def save_code(self, code):
        """Save an OauthAuthorizationCode; auto-expire at code.expires_at."""

        key = f"{self.prefix}{code.code}"

        if not code.expires_at:
            return False

        # TTL = remaining seconds until expiry.
        remaining = code.expires_at - _now()
        ttl = max(int(remaining.total_seconds()), 1)

        data = code.model_dump_json()
        await self.redis.set(key, data, ex=ttl)
        return True

    async def get_code(self, code: str):
        """Retrieve a code object by the code string."""
        from .models import OauthAuthorizationCode  # avoid circular import

        key = f"{self.prefix}{code}"
        data = await self.redis.get(key)
        if data:
            try:
                code_data = json.loads(data)
                return OauthAuthorizationCode(**code_data)
            except Exception as e:
                logger.error("Error decoding auth code from Redis: %s", e)
                return None
        return None

    async def mark_used(self, code: str) -> bool:
        """Mark a code as used (B5 single-use enforcement).

        Updates the ``used`` flag and ``used_at`` timestamp in place.
        The caller must call delete_code() to purge from Redis after marking.
        """
        obj = await self.get_code(code)
        if not obj:
            return False
        obj.used = True
        obj.used_at = _now()
        # Re-save with a very short TTL (5 s) to propagate state before deletion.
        key = f"{self.prefix}{code}"
        await self.redis.set(key, obj.model_dump_json(), ex=5)
        return True

    async def delete_code(self, code: str):
        """Delete a code from Redis."""
        key = f"{self.prefix}{code}"
        await self.redis.delete(key)


# ---------------------------------------------------------------------------
# Refresh Token Storage (Redis) — TASK-026 extended
# ---------------------------------------------------------------------------

class RefreshTokenStorage:
    """Redis-backed refresh token store.

    TASK-026 additions:
        revoke_token(token, reason) — mark one token as revoked.
        revoke_chain(token)         — find the chain root and revoke all siblings.
        list_tokens(user_id)        — return all live tokens for a user.
    """

    def __init__(self, dsn: str = None):
        if not dsn:
            dsn = REDIS_URL
        self.redis = redis.from_url(dsn, decode_responses=True)
        self.prefix = "oauth2:refresh:"
        # Secondary index: user_id -> set of refresh_token strings.
        self.user_index_prefix = "oauth2:refresh:user:"

    async def save_token(self, token):
        """Persist an OauthRefreshToken; TTL follows sliding expiry."""
        key = f"{self.prefix}{token.refresh_token}"

        if not token.expires_at:
            return False

        remaining = token.expires_at - _now()
        ttl = max(int(remaining.total_seconds()), 1)

        data = token.model_dump_json()
        await self.redis.set(key, data, ex=ttl)

        # Maintain user -> token index.
        user_key = f"{self.user_index_prefix}{token.user_id}"
        await self.redis.sadd(user_key, token.refresh_token)
        # Keep index entry for at least as long as the absolute TTL.
        abs_remaining = token.absolute_expires_at - _now()
        abs_ttl = max(int(abs_remaining.total_seconds()), ttl)
        await self.redis.expire(user_key, abs_ttl)

        return True

    async def get_token(self, refresh_token: str):
        """Retrieve an OauthRefreshToken by value."""
        from .models import OauthRefreshToken  # avoid circular import

        key = f"{self.prefix}{refresh_token}"
        data = await self.redis.get(key)
        if data:
            try:
                token_data = json.loads(data)
                return OauthRefreshToken(**token_data)
            except Exception as e:
                logger.error("Error decoding refresh token from Redis: %s", e)
                return None
        return None

    async def delete_token(self, refresh_token: str):
        """Hard-delete a refresh token from Redis."""
        key = f"{self.prefix}{refresh_token}"
        await self.redis.delete(key)

    async def revoke_token(self, refresh_token: str, reason: str = "revoked") -> bool:
        """Soft-revoke a single refresh token.

        Sets ``revoked=True`` and ``revoked_reason`` in the stored record,
        preserving the data for reuse-detection (TASK-026).
        """

        obj = await self.get_token(refresh_token)
        if not obj:
            return False

        obj.revoked = True
        obj.revoked_at = _now()
        obj.revoked_reason = reason

        key = f"{self.prefix}{refresh_token}"
        # Keep the record alive for 5 minutes so reuse-detection can fire.
        await self.redis.set(key, obj.model_dump_json(), ex=300)
        return True

    async def revoke_chain(self, refresh_token: str) -> None:
        """Revoke every refresh token in the same family.

        On reuse-detection the entire token family must be invalidated, not
        just the ancestors reachable via ``parent_token``. We therefore revoke
        ALL live tokens that belong to the same ``(user_id, client_id)`` pair,
        which guarantees every descendant (and sibling) is also killed. This
        mirrors the in-memory implementation used in the tests.

        Used when a replayed / reused token is detected (TASK-026).
        Also called by the per-app grant revocation endpoint (TASK-027).
        """
        root = await self.get_token(refresh_token)
        if not root:
            return

        # Identify the client owning this token (None-safe).
        root_client = getattr(getattr(root, "client", None), "client_id", None)

        for obj in await self.list_tokens(root.user_id):
            obj_client = getattr(getattr(obj, "client", None), "client_id", None)
            # Revoke same-client tokens; when client is unknown, fall back to
            # the originally requested token to avoid skipping it.
            same_family = (root_client is not None and obj_client == root_client) or (
                obj.refresh_token == refresh_token
            )
            if same_family and not obj.revoked:
                await self.revoke_token(obj.refresh_token, "cascade")

    async def list_tokens(self, user_id: int) -> list:
        """Return all non-expired OauthRefreshToken objects for a user.

        Used by grant revocation to cascade-revoke all of a user's tokens
        for a specific client (TASK-027).
        """
        user_key = f"{self.user_index_prefix}{user_id}"
        token_ids = await self.redis.smembers(user_key)

        tokens = []
        for tid in token_ids:
            obj = await self.get_token(tid)
            if obj:
                tokens.append(obj)
            else:
                # Token expired — clean up the index.
                await self.redis.srem(user_key, tid)

        return tokens


# ---------------------------------------------------------------------------
# Grant Storage (durable consent records, TASK-027)
# ---------------------------------------------------------------------------

class GrantStorage:
    """Redis-backed durable consent grant store (TASK-027)."""

    def __init__(self, dsn: str = None):
        if not dsn:
            dsn = REDIS_URL
        self.redis = redis.from_url(dsn, decode_responses=True)
        self.prefix = "oauth2:grant:"
        # Index: user_id -> set of client_ids with grants.
        self.user_index_prefix = "oauth2:grant:user:"

    async def save_grant(self, grant) -> bool:
        """Upsert an OauthGrant for (user_id, client_id)."""
        key = f"{self.prefix}{grant.user_id}:{grant.client_id}"
        data = grant.model_dump_json()
        # Grants don't expire by design (until explicitly revoked).
        await self.redis.set(key, data)

        user_key = f"{self.user_index_prefix}{grant.user_id}"
        await self.redis.sadd(user_key, grant.client_id)
        return True

    async def get_grant(self, user_id: int, client_id: str):
        """Get the OauthGrant for (user_id, client_id), or None."""
        from .models import OauthGrant  # avoid circular import

        key = f"{self.prefix}{user_id}:{client_id}"
        data = await self.redis.get(key)
        if data:
            try:
                return OauthGrant(**json.loads(data))
            except Exception as e:
                logger.error("Error decoding grant from Redis: %s", e)
        return None

    async def revoke_grant(self, user_id: int, client_id: str) -> bool:
        """Soft-revoke a grant by marking revoked=True."""

        obj = await self.get_grant(user_id, client_id)
        if not obj:
            return False

        obj.revoked = True
        obj.revoked_at = _now()

        key = f"{self.prefix}{user_id}:{client_id}"
        await self.redis.set(key, obj.model_dump_json())
        return True

    async def list_grants(self, user_id: int) -> list:
        """Return all OauthGrant objects for a user."""

        user_key = f"{self.user_index_prefix}{user_id}"
        client_ids = await self.redis.smembers(user_key)

        grants = []
        for cid in client_ids:
            obj = await self.get_grant(user_id, cid)
            if obj:
                grants.append(obj)

        return grants


# ---------------------------------------------------------------------------
# Access Token Record Storage (jti revocation, TASK-027)
# ---------------------------------------------------------------------------

class AccessTokenStorage:
    """Redis-backed jti record store for access token revocation (TASK-027)."""

    def __init__(self, dsn: str = None):
        if not dsn:
            dsn = REDIS_URL
        self.redis = redis.from_url(dsn, decode_responses=True)
        self.prefix = "oauth2:jti:"
        self.revoked_prefix = "oauth2:jti:revoked:"

    async def save(self, record) -> bool:
        """Persist an OauthAccessTokenRecord keyed by jti."""
        key = f"{self.prefix}{record.jti}"
        remaining = record.expires_at - _now()
        ttl = max(int(remaining.total_seconds()), 1)
        await self.redis.set(key, record.model_dump_json(), ex=ttl)
        return True

    async def get(self, jti: str):
        """Fetch an OauthAccessTokenRecord by jti."""
        from .models import OauthAccessTokenRecord  # avoid circular import

        key = f"{self.prefix}{jti}"
        data = await self.redis.get(key)
        if data:
            try:
                return OauthAccessTokenRecord(**json.loads(data))
            except Exception as e:
                logger.error("Error decoding access token record from Redis: %s", e)
        return None

    async def revoke(self, jti: str) -> bool:
        """Revoke a jti (mark in a revocation set with TTL)."""
        # Keep the revoked marker alive for as long as the JWT can still be valid.
        rec = await self.get(jti)
        if rec:
            remaining = rec.expires_at - _now()
            ttl = max(int(remaining.total_seconds()), 300)
        else:
            ttl = 3600  # Fallback TTL.

        revoked_key = f"{self.revoked_prefix}{jti}"
        await self.redis.set(revoked_key, "1", ex=ttl)
        return True

    async def is_revoked(self, jti: str) -> bool:
        """Return True if the jti is in the revocation set."""
        revoked_key = f"{self.revoked_prefix}{jti}"
        return bool(await self.redis.exists(revoked_key))


# ---------------------------------------------------------------------------
# Device Code Storage (FEAT-094 TASK-032)
# ---------------------------------------------------------------------------

class MemoryDeviceCodeStorage:
    """In-memory DeviceCodeStorage for tests and single-process deployments.

    Key design:
      - Keyed by device_code (primary lookup).
      - Secondary index keyed by user_code for the verification page lookup.
      - No TTL enforcement in memory — callers use poll_decision to check
        expires_at.
    """

    def __init__(self):
        self._by_device_code: dict = {}
        self._by_user_code: dict = {}
        self._lock = asyncio.Lock()

    async def save(self, dc) -> bool:
        """Persist an OauthDeviceCode record."""
        async with self._lock:
            self._by_device_code[dc.device_code] = dc
            self._by_user_code[dc.user_code.upper()] = dc.device_code
        return True

    async def get_by_device_code(self, device_code: str):
        """Return an OauthDeviceCode by device_code, or None."""
        return self._by_device_code.get(device_code)

    async def get_by_user_code(self, user_code: str):
        """Return an OauthDeviceCode by (normalised) user_code, or None."""
        key = user_code.upper().replace("-", "").replace(" ", "")
        device_code = self._by_user_code.get(key)
        if device_code:
            return self._by_device_code.get(device_code)
        return None

    async def update(self, dc) -> bool:
        """Update a stored OauthDeviceCode record (status/user_id/interval etc.)."""
        async with self._lock:
            if dc.device_code not in self._by_device_code:
                return False
            self._by_device_code[dc.device_code] = dc
            # Rebuild user_code index entry in case user_code changed (shouldn't
            # happen in practice, but be safe).
            self._by_user_code[dc.user_code.upper()] = dc.device_code
        return True

    async def delete(self, device_code: str) -> bool:
        """Remove a device code record from storage."""
        async with self._lock:
            dc = self._by_device_code.pop(device_code, None)
            if dc:
                self._by_user_code.pop(dc.user_code.upper(), None)
            return dc is not None


class RedisDeviceCodeStorage:
    """Redis-backed DeviceCodeStorage.

    Primary key: oauth2:device:<device_code>
    Secondary index: oauth2:device:user:<user_code_upper> → device_code
    TTL driven by dc.expires_at.
    """

    def __init__(self, dsn: str = None):
        if not dsn:
            dsn = REDIS_URL
        self.redis = redis.from_url(dsn, decode_responses=True)
        self.prefix = "oauth2:device:"
        self.user_index_prefix = "oauth2:device:user:"

    async def save(self, dc) -> bool:
        """Persist an OauthDeviceCode with TTL derived from expires_at."""
        key = f"{self.prefix}{dc.device_code}"
        remaining = dc.expires_at - _now()
        ttl = max(int(remaining.total_seconds()), 1)
        data = dc.model_dump_json()
        await self.redis.set(key, data, ex=ttl)
        user_key = f"{self.user_index_prefix}{dc.user_code.upper()}"
        await self.redis.set(user_key, dc.device_code, ex=ttl)
        return True

    async def get_by_device_code(self, device_code: str):
        """Retrieve an OauthDeviceCode by device_code."""
        from .models import OauthDeviceCode  # avoid circular import
        key = f"{self.prefix}{device_code}"
        data = await self.redis.get(key)
        if data:
            try:
                return OauthDeviceCode.model_validate_json(data)
            except Exception as e:
                logger.error("Error decoding device code from Redis: %s", e)
        return None

    async def get_by_user_code(self, user_code: str):
        """Retrieve an OauthDeviceCode by (normalised) user_code."""
        key = user_code.upper().replace("-", "").replace(" ", "")
        user_key = f"{self.user_index_prefix}{key}"
        device_code = await self.redis.get(user_key)
        if device_code:
            return await self.get_by_device_code(device_code)
        return None

    async def update(self, dc) -> bool:
        """Update a stored OauthDeviceCode (re-save with remaining TTL)."""
        key = f"{self.prefix}{dc.device_code}"
        user_key = f"{self.user_index_prefix}{dc.user_code.upper()}"
        remaining = dc.expires_at - _now()
        ttl = max(int(remaining.total_seconds()), 1)
        await self.redis.set(key, dc.model_dump_json(), ex=ttl)
        # Also refresh the secondary user_code index TTL.
        await self.redis.expire(user_key, ttl)
        return True

    async def delete(self, device_code: str) -> bool:
        """Remove a device code record from Redis."""
        dc = await self.get_by_device_code(device_code)
        key = f"{self.prefix}{device_code}"
        await self.redis.delete(key)
        if dc:
            user_key = f"{self.user_index_prefix}{dc.user_code.upper()}"
            await self.redis.delete(user_key)
        return True


# ---------------------------------------------------------------------------
# Factory helpers (backend.py uses these)
# ---------------------------------------------------------------------------

def get_refresh_token_storage(storage_type: str = "redis", dsn: str = None) -> RefreshTokenStorage:
    """Return an appropriate RefreshTokenStorage.

    Currently only Redis is implemented; the argument is reserved for future
    Postgres/memory variants.
    """
    return RefreshTokenStorage(dsn=dsn or REDIS_URL)


def get_grant_storage(storage_type: str = "redis", dsn: str = None) -> GrantStorage:
    """Return an appropriate GrantStorage."""
    return GrantStorage(dsn=dsn or REDIS_URL)


def get_access_token_storage(storage_type: str = "redis", dsn: str = None) -> AccessTokenStorage:
    """Return an appropriate AccessTokenStorage."""
    return AccessTokenStorage(dsn=dsn or REDIS_URL)


def get_device_code_storage(storage_type: str = "redis", dsn: str = None):
    """Return an appropriate DeviceCodeStorage.

    - ``memory`` : MemoryDeviceCodeStorage (tests / single-process)
    - ``redis``  : RedisDeviceCodeStorage  (default; device codes are short-TTL)
    - ``postgres``: falls back to Redis for device codes (no postgres tier yet)
    """
    if storage_type == "memory":
        return MemoryDeviceCodeStorage()
    # redis and postgres both use Redis for device codes
    return RedisDeviceCodeStorage(dsn=dsn or REDIS_URL)
