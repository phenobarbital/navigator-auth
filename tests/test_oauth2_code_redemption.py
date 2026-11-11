"""FEAT-108 follow-ups — authorization-code redemption (TASK-224, TASK-225).

TASK-224 (issue:cf77c0161ff6): ``AuthorizationCodeStorage.mark_used`` is atomic and
the claim TTL comes from ``OAUTH_CODE_CLAIM_TTL``.
"""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from navigator_auth.backends.oauth2 import code_backend
from navigator_auth.backends.oauth2.code_backend import AuthorizationCodeStorage
from navigator_auth.backends.oauth2.models import OAuthClient, OauthAuthorizationCode

CODE = "code-redemption-1"


class _InterleavingRedis:
    """Minimal async Redis double that yields to the loop before every command.

    Each command is atomic (as in Redis) but two coroutines interleave between
    commands, which is exactly the window a get-then-set ``mark_used`` loses.
    """

    def __init__(self):
        self.data: dict = {}
        self.set_calls: list = []

    async def get(self, key):
        await asyncio.sleep(0)
        return self.data.get(key)

    async def set(self, key, value, nx=False, ex=None):
        await asyncio.sleep(0)
        self.set_calls.append((key, nx, ex))
        if nx and key in self.data:
            return None
        self.data[key] = value
        return True

    async def delete(self, key):
        await asyncio.sleep(0)
        self.data.pop(key, None)


def _storage(redis=None) -> AuthorizationCodeStorage:
    storage = AuthorizationCodeStorage.__new__(AuthorizationCodeStorage)
    storage.prefix = "oauth2:code:"
    storage.redis = redis or _InterleavingRedis()
    return storage


def _code() -> OauthAuthorizationCode:
    client = OAuthClient(
        client_id="public_app",
        client_name="Public App",
        client_type="public",
        redirect_uris=["https://example.com/callback"],
    )
    return OauthAuthorizationCode(
        client=client,
        user_id=42,
        code=CODE,
        redirect_uri="https://example.com/callback",
        scope="default",
        state="s",
        response_type="code",
        expires_at=datetime.now() + timedelta(seconds=120),
        used=False,
    )


class TestAtomicMarkUsed:
    @pytest.mark.asyncio
    async def test_only_the_first_of_concurrent_callers_wins(self):
        storage = _storage()
        await storage.save_code(_code())

        results = await asyncio.gather(*(storage.mark_used(CODE) for _ in range(5)))

        assert sorted(results) == [False, False, False, False, True]

    @pytest.mark.asyncio
    async def test_a_second_sequential_call_loses(self):
        storage = _storage()
        await storage.save_code(_code())

        assert await storage.mark_used(CODE) is True
        assert await storage.mark_used(CODE) is False

    @pytest.mark.asyncio
    async def test_the_record_is_still_flagged_used(self):
        storage = _storage()
        await storage.save_code(_code())

        await storage.mark_used(CODE)

        assert (await storage.get_code(CODE)).used is True

    @pytest.mark.asyncio
    async def test_the_marker_lives_as_long_as_a_code_can(self):
        redis = _InterleavingRedis()
        storage = _storage(redis)
        await storage.save_code(_code())

        await storage.mark_used(CODE)

        assert (f"oauth2:code:used:{CODE}", True, code_backend.OAUTH_CODE_TTL) in redis.set_calls

    @pytest.mark.asyncio
    async def test_a_missing_code_is_not_consumed(self):
        storage = _storage()

        assert await storage.mark_used("never-issued") is False


class TestClaimTtl:
    @pytest.mark.asyncio
    async def test_default_ttl_comes_from_configuration(self):
        redis = _InterleavingRedis()
        storage = _storage(redis)

        with patch.object(code_backend, "OAUTH_CODE_CLAIM_TTL", 90):
            assert await storage.claim_code(CODE) is True

        assert redis.set_calls == [(f"oauth2:code:claim:{CODE}", True, 90)]

    @pytest.mark.asyncio
    async def test_an_explicit_ttl_wins(self):
        redis = _InterleavingRedis()
        storage = _storage(redis)

        assert await storage.claim_code(CODE, ttl=5) is True

        assert redis.set_calls == [(f"oauth2:code:claim:{CODE}", True, 5)]

    @pytest.mark.asyncio
    async def test_a_held_claim_cannot_be_taken_twice(self):
        storage = _storage()

        assert await storage.claim_code(CODE) is True
        assert await storage.claim_code(CODE) is False
