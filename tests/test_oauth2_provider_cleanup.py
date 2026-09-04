"""TASK-069: Oauth2Provider.on_cleanup() must close its Redis-backed storages.

``on_startup`` opens up to seven separate Redis connections (one per
storage, when ``OAUTH2_CLIENT_STORAGE``/backing config selects a
Redis-backed implementation). Before this fix, ``on_cleanup`` was a no-op
and leaked every one of those connections on app shutdown/reload, which is
also what caused test-teardown hangs whenever an ``Oauth2Provider`` instance
was spun up in a test fixture.
"""
from unittest.mock import AsyncMock, MagicMock

import pytest

from navigator_auth.backends.oauth2.backend import Oauth2Provider


#: The storage attributes on_cleanup() must consider — mirrors on_startup().
STORAGE_ATTRS = (
    "client_storage",
    "code_storage",
    "refresh_token_storage",
    "grant_storage",
    "access_token_storage",
    "device_code_storage",
    "client_access_storage",
)


def _make_provider() -> Oauth2Provider:
    """A bare Oauth2Provider, same construction pattern used elsewhere in
    the oauth2 test suite (e.g. tests/test_oauth2_metadata.py)."""
    return Oauth2Provider(user_model=MagicMock(), identity=MagicMock())


def _redis_backed_storage() -> MagicMock:
    """A storage stub exposing an async-closable ``.redis`` client."""
    storage = MagicMock()
    storage.redis = AsyncMock()
    storage.redis.aclose = AsyncMock()
    return storage


class TestOauth2ProviderCleanup:
    """Acceptance criteria for TASK-069."""

    @pytest.mark.asyncio
    async def test_on_cleanup_closes_all_redis_backed_storages(self):
        """Every storage attribute with a `.redis` client gets `aclose()`d."""
        provider = _make_provider()
        storages = {attr: _redis_backed_storage() for attr in STORAGE_ATTRS}
        for attr, storage in storages.items():
            setattr(provider, attr, storage)

        await provider.on_cleanup(app=MagicMock())

        for attr, storage in storages.items():
            storage.redis.aclose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_cleanup_skips_non_redis_storages(self):
        """Memory/Postgres-backed storages (no `.redis` attr) are skipped
        without error."""
        provider = _make_provider()

        # A storage with no `.redis` attribute at all (e.g. MemoryClientStorage,
        # PostgresClientStorage) must be silently skipped.
        class _NoRedisStorage:
            pass

        no_redis = _NoRedisStorage()
        assert not hasattr(no_redis, "redis")
        provider.client_storage = no_redis

        # Mix in a couple of real Redis-backed storages to prove the loop still
        # does its job for the ones that do have a connection.
        redis_storage = _redis_backed_storage()
        provider.code_storage = redis_storage

        # Everything else stays at its default (None from __init__).
        await provider.on_cleanup(app=MagicMock())

        redis_storage.redis.aclose.assert_awaited_once()
        # No exception raised, and the non-redis storage was left untouched.
        assert not hasattr(no_redis, "redis")

    @pytest.mark.asyncio
    async def test_on_cleanup_tolerates_individual_close_failure(self):
        """One storage's `aclose()` raising does not stop the others from
        closing."""
        provider = _make_provider()

        failing_storage = _redis_backed_storage()
        failing_storage.redis.aclose.side_effect = RuntimeError("boom")

        ok_storage = _redis_backed_storage()

        provider.client_storage = failing_storage
        provider.access_token_storage = ok_storage

        # Must not raise despite the failure above.
        await provider.on_cleanup(app=MagicMock())

        failing_storage.redis.aclose.assert_awaited_once()
        ok_storage.redis.aclose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_cleanup_safe_without_prior_startup(self):
        """Calling on_cleanup() when storages are still None (no on_startup)
        doesn't raise."""
        provider = _make_provider()

        for attr in STORAGE_ATTRS:
            assert getattr(provider, attr, "MISSING") is None

        # Must not raise.
        await provider.on_cleanup(app=MagicMock())
