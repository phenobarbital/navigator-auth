"""Persistence for linked identities (auth.user_identities).

DB is the source of truth; the Session Vault is used as a per-session
cache of the decrypted credential to avoid database round-trips.
"""
from typing import Any, Optional
from datetime import datetime, timezone

from asyncdb.exceptions import NoDataFound
from navconfig.logging import logging

from ..models import UserIdentity
from .crypto import IdentityCipher
from .types import TokenResponse

logger = logging.getLogger("navigator.identity")

# Session Vault key for the cached credential of a provider:
IDENTITY_VAULT_KEY = "identity:{provider}"


class IdentityStore:
    """CRUD for ciphered identity credentials on auth.user_identities."""

    def __init__(self, db_pool: Any, cipher: Optional[IdentityCipher] = None):
        self._pool = db_pool
        self._cipher = cipher if cipher is not None else IdentityCipher()

    async def save_linked_identity(
        self,
        user_id: Any,
        provider: str,
        token: TokenResponse,
        userinfo: Optional[dict] = None,
    ) -> UserIdentity:
        """Upsert the linked identity for (user, provider, external account)."""
        userinfo = userinfo or {}
        now = datetime.now(timezone.utc)
        values = {
            "provider_user_id": token.provider_user_id,
            "scopes": list(token.scopes or []),
            "access_token": self._cipher.encrypt(token.access_token),
            "refresh_token": (
                self._cipher.encrypt(token.refresh_token)
                if token.refresh_token
                else None
            ),
            "token_type": token.token_type,
            "expires_at": token.expires_at,
            "refreshed_at": now,
            "enabled": True,
            "key_version": self._cipher.key_id,
            "auth_data": self._identity_profile(userinfo),
        }
        async with await self._pool.acquire() as conn:
            UserIdentity.Meta.connection = conn
            existing = None
            try:
                existing = await UserIdentity.get(
                    user_id=user_id,
                    auth_provider=provider,
                    provider_user_id=token.provider_user_id,
                )
            except NoDataFound:
                existing = None
            if existing:
                for key, value in values.items():
                    setattr(existing, key, value)
                return await existing.update()
            identity = UserIdentity(
                user_id=user_id,
                auth_provider=provider,
                **values,
            )
            return await identity.insert()

    def _identity_profile(self, userinfo: dict) -> dict:
        """Displayable (non-secret) provider profile attributes."""
        profile = {}
        for key in (
            "name",
            "email",
            "login",
            "sub",
            "id",
            "picture",
            "avatar_url",
            "preferred_username",
            "userPrincipalName",
            "displayName",
        ):
            value = userinfo.get(key)
            if value is not None:
                profile[key] = value
        return profile

    async def list_for_user(self, user_id: Any) -> list[dict]:
        """All linked identities for a user, with secrets masked out."""
        async with await self._pool.acquire() as conn:
            UserIdentity.Meta.connection = conn
            try:
                rows = await UserIdentity.filter(user_id=user_id)
            except NoDataFound:
                return []
        return [self.masked(row) for row in rows or []]

    async def get_one(
        self, user_id: Any, identity_id: Any
    ) -> Optional[UserIdentity]:
        """One identity by PK, restricted to its owner."""
        async with await self._pool.acquire() as conn:
            UserIdentity.Meta.connection = conn
            try:
                return await UserIdentity.get(
                    identity_id=identity_id, user_id=user_id
                )
            except NoDataFound:
                return None

    async def get_by_provider(
        self, user_id: Any, provider: str
    ) -> Optional[UserIdentity]:
        """The newest enabled credential-bearing identity for a provider."""
        async with await self._pool.acquire() as conn:
            UserIdentity.Meta.connection = conn
            try:
                rows = await UserIdentity.filter(
                    user_id=user_id, auth_provider=provider
                )
            except NoDataFound:
                return None
        rows = [
            row
            for row in rows or []
            if getattr(row, "access_token", None) and getattr(row, "enabled", True)
        ]
        if not rows:
            return None
        rows.sort(
            key=lambda r: getattr(r, "refreshed_at", None)
            or getattr(r, "created_at", None)
            or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
        return rows[0]

    async def delete(self, user_id: Any, identity_id: Any) -> bool:
        async with await self._pool.acquire() as conn:
            UserIdentity.Meta.connection = conn
            try:
                row = await UserIdentity.get(
                    identity_id=identity_id, user_id=user_id
                )
            except NoDataFound:
                return False
            await row.delete()
            return True

    async def update_tokens(
        self, identity: UserIdentity, token: TokenResponse
    ) -> UserIdentity:
        """Persist refreshed tokens on an existing identity row."""
        identity.access_token = self._cipher.encrypt(token.access_token)
        if token.refresh_token:
            identity.refresh_token = self._cipher.encrypt(token.refresh_token)
        identity.token_type = token.token_type
        identity.expires_at = token.expires_at
        identity.refreshed_at = datetime.now(timezone.utc)
        identity.key_version = self._cipher.key_id
        if token.scopes:
            identity.scopes = list(token.scopes)
        async with await self._pool.acquire() as conn:
            UserIdentity.Meta.connection = conn
            return await identity.update()

    def decrypt_credential(self, identity: UserIdentity) -> TokenResponse:
        """Decrypt a stored identity row into a TokenResponse."""
        access_token = self._cipher.decrypt(identity.access_token)
        refresh_token = (
            self._cipher.decrypt(identity.refresh_token)
            if identity.refresh_token
            else None
        )
        return TokenResponse(
            access_token=access_token,
            token_type=identity.token_type or "Bearer",
            refresh_token=refresh_token,
            expires_at=identity.expires_at,
            scopes=list(identity.scopes or []),
            provider_user_id=identity.provider_user_id,
        )

    def masked(self, identity: UserIdentity) -> dict:
        """API-safe representation: never includes token material."""
        return {
            "identity_id": str(identity.identity_id),
            "auth_provider": identity.auth_provider,
            "provider_user_id": identity.provider_user_id,
            "scopes": list(identity.scopes or []),
            "token_type": identity.token_type,
            "expires_at": (
                identity.expires_at.isoformat() if identity.expires_at else None
            ),
            "refreshed_at": (
                identity.refreshed_at.isoformat()
                if identity.refreshed_at
                else None
            ),
            "created_at": (
                identity.created_at.isoformat() if identity.created_at else None
            ),
            "enabled": identity.enabled,
            "has_refresh_token": identity.refresh_token is not None,
            "profile": identity.auth_data or {},
        }


# --- Session Vault caching helpers (best-effort; DB is source of truth) ---

async def cache_credential(session: Any, provider: str, credential: dict) -> None:
    """Cache a decrypted credential in the user's Session Vault."""
    try:
        from ..vault.integration import VAULT_SESSION_KEY

        vault = session.get(VAULT_SESSION_KEY)
        if vault is not None:
            await vault.set(
                IDENTITY_VAULT_KEY.format(provider=provider), credential
            )
    except Exception as err:  # pylint: disable=W0703
        logger.warning(f"Identity: cannot cache credential in vault: {err}")


async def cached_credential(session: Any, provider: str) -> Optional[dict]:
    """Fetch a cached credential from the Session Vault, if present."""
    try:
        from ..vault.integration import VAULT_SESSION_KEY

        vault = session.get(VAULT_SESSION_KEY)
        if vault is None:
            return None
        key = IDENTITY_VAULT_KEY.format(provider=provider)
        if not await vault.exists(key):
            return None
        return await vault.get(key)
    except Exception as err:  # pylint: disable=W0703
        logger.warning(f"Identity: cannot read credential from vault: {err}")
        return None


async def invalidate_cached(session: Any, provider: str) -> None:
    """Remove a cached credential from the Session Vault."""
    try:
        from ..vault.integration import VAULT_SESSION_KEY

        vault = session.get(VAULT_SESSION_KEY)
        if vault is not None:
            key = IDENTITY_VAULT_KEY.format(provider=provider)
            if await vault.exists(key):
                await vault.delete(key)
    except Exception as err:  # pylint: disable=W0703
        logger.warning(f"Identity: cannot invalidate vault credential: {err}")
