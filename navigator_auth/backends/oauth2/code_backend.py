"""OAuth2 token/code storage backends.

FEAT-093:
  TASK-024 — mark_used() for single-use code enforcement (B5).
              user_id round-tripped through OauthAuthorizationCode.
  TASK-026 — RefreshTokenStorage extended: revoke_token, revoke_chain,
              list_tokens (for cascade revocation on grant revoke).
  TASK-027 — GrantStorage (consent) and AccessTokenStorage (jti revoke).
"""

from datetime import datetime, timezone
import json
import logging

from ...conf import REDIS_URL

try:
    import redis.asyncio as redis
except ImportError:
    import redis


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
                logging.error(f"Error decoding auth code from Redis: {e}")
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
                logging.error(f"Error decoding refresh token from Redis: {e}")
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
        """Walk the parent_token chain and revoke every token.

        Used when a replayed / reused token is detected (TASK-026).
        Also called by the per-app grant revocation endpoint (TASK-027).
        """
        visited = set()
        current = refresh_token

        while current and current not in visited:
            visited.add(current)
            obj = await self.get_token(current)
            if not obj:
                break
            if not obj.revoked:
                await self.revoke_token(current, "cascade")
            # Walk up the chain.
            current = obj.parent_token

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
                logging.error(f"Error decoding grant from Redis: {e}")
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
                logging.error(f"Error decoding access token record from Redis: {e}")
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
