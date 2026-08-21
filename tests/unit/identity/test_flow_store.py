"""Unit tests for navigator_auth.identity.flow_store.IdentityFlowStore."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from navigator_auth.identity.flow_store import (
    IdentityFlowStore,
    LINK_KEY_PREFIX,
)
from navigator_auth.libs.json import json_encoder


def _make_store(storage: dict):
    """FlowStore over a fake redis client backed by a plain dict."""
    redis = AsyncMock()

    async def _setex(key, ttl, value):
        storage[key] = (value, ttl)

    async def _get(key):
        entry = storage.get(key)
        return entry[0] if entry else None

    async def _getdel(key):
        entry = storage.pop(key, None)
        return entry[0] if entry else None

    async def _delete(key):
        storage.pop(key, None)

    redis.setex = AsyncMock(side_effect=_setex)
    redis.get = AsyncMock(side_effect=_get)
    redis.getdel = AsyncMock(side_effect=_getdel)
    redis.delete = AsyncMock(side_effect=_delete)
    redis.__aenter__ = AsyncMock(return_value=redis)
    redis.__aexit__ = AsyncMock(return_value=False)

    store = IdentityFlowStore(pool=MagicMock())
    patcher = patch(
        "navigator_auth.identity.flow_store.aioredis.Redis",
        return_value=redis,
    )
    return store, redis, patcher


@pytest.mark.asyncio
async def test_set_get_roundtrip():
    storage = {}
    store, redis, patcher = _make_store(storage)
    with patcher:
        await store.set("k1", {"a": 1}, ttl=600)
        assert await store.get("k1") == {"a": 1}
    redis.setex.assert_awaited_once()
    _, ttl, _ = redis.setex.await_args.args
    assert ttl == 600


@pytest.mark.asyncio
async def test_getdel_is_single_use():
    storage = {}
    store, _, patcher = _make_store(storage)
    with patcher:
        await store.set("k1", {"a": 1}, ttl=10)
        assert await store.getdel("k1") == {"a": 1}
        assert await store.getdel("k1") is None


@pytest.mark.asyncio
async def test_get_missing_returns_none():
    store, _, patcher = _make_store({})
    with patcher:
        assert await store.get("nope") is None


@pytest.mark.asyncio
async def test_link_helpers_use_prefixed_key():
    storage = {}
    store, _, patcher = _make_store(storage)
    with patcher:
        await store.start_link("st4te", {"user_id": 5}, ttl=300)
        assert f"{LINK_KEY_PREFIX}st4te" in storage
        # consumed once
        assert await store.consume_link("st4te") == {"user_id": 5}
        assert await store.consume_link("st4te") is None


@pytest.mark.asyncio
async def test_payload_stored_as_json():
    storage = {}
    store, _, patcher = _make_store(storage)
    with patcher:
        await store.set("k", {"user_id": 7, "flow": "identity_link"}, ttl=1)
    raw, _ = storage["k"]
    assert raw == json_encoder({"user_id": 7, "flow": "identity_link"})
