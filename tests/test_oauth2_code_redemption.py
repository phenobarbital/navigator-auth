"""FEAT-108 follow-ups — authorization-code redemption (TASK-224, TASK-225).

TASK-224 (issue:cf77c0161ff6): ``AuthorizationCodeStorage.mark_used`` is atomic and
the claim TTL comes from ``OAUTH_CODE_CLAIM_TTL``.

TASK-225 (issue:42d67472eccd): the code grant binds the (per-identity, shared)
session only after it consumed the code, so a losing redeemer never touches it.
"""

import asyncio
import contextlib
import json
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from navigator_auth.backends.oauth2 import code_backend
from navigator_auth.backends.oauth2.backend import Oauth2Provider
from navigator_auth.backends.oauth2.client_backend import MemoryClientStorage
from navigator_auth.backends.oauth2.code_backend import AuthorizationCodeStorage
from navigator_auth.backends.oauth2.models import OAuthClient, OauthAuthorizationCode
from navigator_auth.backends.oauth2.pkce import generate_challenge

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


# --- TASK-225: session binding after the code is consumed ------------------------------------
CLIENT_UID = "cli_redemption"
REDIRECT_URI = "https://app.example.com/cb"
VERIFIER = "v" * 50


def _grant_code():
    code = MagicMock()
    code.used = False
    code.expires_at = datetime.now() + timedelta(minutes=5)
    code.client = MagicMock()
    code.client.client_id = CLIENT_UID
    code.redirect_uri = REDIRECT_URI
    code.code_challenge = generate_challenge(VERIFIER)
    code.code_challenge_method = "S256"
    code.user_id = 35
    code.generation = 0
    code.scope = "default"
    code.mfa = False
    code.amr = None
    code.resource = None
    return code


class _OrderedCodes:
    """Code storage double that records calls into a shared, ordered log."""

    def __init__(self, log, *, wins=True):
        self.log = log
        self.wins = wins

    async def get_code(self, code):
        return _grant_code()

    async def claim_code(self, code):
        self.log.append("claim")
        return True

    async def release_claim(self, code):
        self.log.append("release")

    async def mark_used(self, code):
        self.log.append("mark_used")
        return self.wins

    async def delete_code(self, code):
        self.log.append("delete")


async def _redeeming_provider(log, *, wins=True):
    provider = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    provider.logger = MagicMock()
    storage = MemoryClientStorage()
    await storage.save_client(
        OAuthClient(
            client_id=CLIENT_UID,
            client_name="App",
            client_type="public",
            redirect_uris=[REDIRECT_URI],
            enforce_access_gate=False,
        )
    )
    provider.client_storage = storage
    provider.code_storage = _OrderedCodes(log, wins=wins)

    @contextlib.asynccontextmanager
    async def _generation(request, user_id):
        yield MagicMock(), 0

    owner = MagicMock(name="owner")

    async def _resolve(user_id):
        log.append("resolve")
        return owner

    async def _create_session(request, user, *args, **kwargs):
        log.append("session")
        assert user is owner  # bound to the owner resolved before consumption
        return None

    provider._user_generation = _generation
    provider._resolve_resource_owner = AsyncMock(side_effect=_resolve)
    provider._create_user_session = AsyncMock(side_effect=_create_session)
    provider._idp.create_token = MagicMock(return_value=("tok", None, time.time() + 60, "Bearer"))
    provider.access_token_storage = None
    return provider


def _payload():
    return {"code": "code-1", "client_id": CLIENT_UID, "redirect_uri": REDIRECT_URI, "code_verifier": VERIFIER}


class TestSessionAfterConsume:
    @pytest.mark.asyncio
    async def test_the_session_is_bound_after_the_code_is_consumed(self):
        log = []
        provider = await _redeeming_provider(log)

        response = await provider._handle_authorization_code(_payload(), MagicMock())

        assert response.status == 200
        assert log == ["claim", "resolve", "mark_used", "delete", "session"]
        provider._resolve_resource_owner.assert_awaited_once()  # no second lookup

    @pytest.mark.asyncio
    async def test_a_redeemer_that_loses_mark_used_never_touches_the_session(self):
        log = []
        provider = await _redeeming_provider(log, wins=False)

        response = await provider._handle_authorization_code(_payload(), MagicMock())

        assert response.status == 400
        assert json.loads(response.body)["error_description"] == "Authorization code already used."
        assert log == ["claim", "resolve", "mark_used"]
        provider._create_user_session.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_token_session_claims_skips_the_lookup_for_a_resolved_owner(self):
        provider = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
        provider._resolve_resource_owner = AsyncMock()
        provider._create_user_session = AsyncMock(return_value=None)
        owner = MagicMock()

        assert await provider._token_session_claims(MagicMock(), 35, user=owner) == {}

        provider._resolve_resource_owner.assert_not_awaited()
        provider._create_user_session.assert_awaited_once()
        assert provider._create_user_session.await_args.args[1] is owner
