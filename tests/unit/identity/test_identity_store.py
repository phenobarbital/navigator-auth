"""Unit tests for IdentityStore and the vault-cache helpers."""
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from navigator_auth.identity.crypto import IdentityCipher
from navigator_auth.identity.store import (
    IDENTITY_VAULT_KEY,
    IdentityStore,
    cache_credential,
    cached_credential,
    invalidate_cached,
)
from navigator_auth.identity.types import TokenResponse


MASTER_KEYS = {1: b"\x00" * 32}


def _make_pool():
    conn = AsyncMock()
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=conn)
    ctx.__aexit__ = AsyncMock(return_value=False)

    async def _acquire():
        return ctx

    pool = MagicMock()
    pool.acquire = MagicMock(side_effect=lambda: _acquire())
    return pool, conn


def _store():
    pool, _ = _make_pool()
    return IdentityStore(pool, cipher=IdentityCipher(master_keys=MASTER_KEYS))


class TestCipherRoundtripThroughStore:
    def test_decrypt_credential(self):
        store = _store()
        cipher = store._cipher
        identity = MagicMock()
        identity.access_token = cipher.encrypt("the-at")
        identity.refresh_token = cipher.encrypt("the-rt")
        identity.token_type = "Bearer"
        identity.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        identity.scopes = ["read:user"]
        identity.provider_user_id = "99"
        token = store.decrypt_credential(identity)
        assert token.access_token == "the-at"
        assert token.refresh_token == "the-rt"
        assert token.scopes == ["read:user"]

    def test_decrypt_without_refresh_token(self):
        store = _store()
        identity = MagicMock()
        identity.access_token = store._cipher.encrypt("at")
        identity.refresh_token = None
        identity.token_type = None
        identity.expires_at = None
        identity.scopes = None
        identity.provider_user_id = None
        token = store.decrypt_credential(identity)
        assert token.access_token == "at"
        assert token.refresh_token is None
        assert token.token_type == "Bearer"


class TestMasked:
    def test_masked_has_no_token_material(self):
        store = _store()
        identity = MagicMock()
        identity.identity_id = "11111111-1111-1111-1111-111111111111"
        identity.auth_provider = "github"
        identity.provider_user_id = "99"
        identity.scopes = ["read:user"]
        identity.token_type = "Bearer"
        identity.expires_at = None
        identity.refreshed_at = None
        identity.created_at = None
        identity.enabled = True
        identity.refresh_token = b"ciphered"
        identity.auth_data = {"login": "octo"}
        masked = store.masked(identity)
        assert "access_token" not in masked
        assert masked["has_refresh_token"] is True
        assert masked["auth_provider"] == "github"
        assert masked["profile"] == {"login": "octo"}


class TestVaultCacheHelpers:
    def _session_with_vault(self, vault):
        session = MagicMock()
        session.get = MagicMock(return_value=vault)
        return session

    @pytest.mark.asyncio
    async def test_cache_credential_sets_key(self):
        vault = AsyncMock()
        session = self._session_with_vault(vault)
        await cache_credential(session, "github", {"access_token": "at"})
        vault.set.assert_awaited_once_with(
            IDENTITY_VAULT_KEY.format(provider="github"),
            {"access_token": "at"},
        )

    @pytest.mark.asyncio
    async def test_cached_credential_roundtrip(self):
        vault = AsyncMock()
        vault.exists = AsyncMock(return_value=True)
        vault.get = AsyncMock(return_value={"access_token": "at"})
        session = self._session_with_vault(vault)
        assert await cached_credential(session, "github") == {
            "access_token": "at"
        }

    @pytest.mark.asyncio
    async def test_cached_credential_none_without_vault(self):
        session = self._session_with_vault(None)
        assert await cached_credential(session, "github") is None

    @pytest.mark.asyncio
    async def test_invalidate_deletes_key(self):
        vault = AsyncMock()
        vault.exists = AsyncMock(return_value=True)
        session = self._session_with_vault(vault)
        await invalidate_cached(session, "github")
        vault.delete.assert_awaited_once_with(
            IDENTITY_VAULT_KEY.format(provider="github")
        )

    @pytest.mark.asyncio
    async def test_helpers_swallow_vault_errors(self):
        vault = AsyncMock()
        vault.set = AsyncMock(side_effect=RuntimeError("redis down"))
        session = self._session_with_vault(vault)
        # must not raise
        await cache_credential(session, "github", {"a": 1})
