"""FEAT-108 TASK-226 (issue:3ae0de8a2704) — owner re-check on userinfo and introspection.

A bearer minted before its owner was deleted or disabled must stop working on
``/oauth2/userinfo`` (401, or 503 on an identity-store outage) and must introspect
as ``{"active": false}``.
"""

import json
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from navigator_auth.backends.oauth2.backend import Oauth2Provider
from navigator_auth.backends.oauth2.models import OAuthClient, OauthRefreshToken
from navigator_auth.exceptions import UserNotFound

OWNER_ID = 42
ACTIVE = SimpleNamespace(user_id=OWNER_ID, username="owner", first_name="O", last_name="W", email="o@example.com")
DISABLED = SimpleNamespace(user_id=OWNER_ID, username="owner", is_active=False)

# Each owner state as the IdP reports it: (user_from_id kwargs, userinfo status).
_GONE = [
    pytest.param({"side_effect": UserNotFound("gone")}, id="unknown"),
    pytest.param({"return_value": None}, id="none"),
    pytest.param({"return_value": DISABLED}, id="disabled"),
]
_OUTAGE = {"side_effect": RuntimeError("db down")}


# --- userinfo ---------------------------------------------------------------------------------
def _userinfo_provider(payload: dict, owner: dict) -> Oauth2Provider:
    provider = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    provider.logger = MagicMock()
    provider.access_token_storage = None
    provider._generation_ok = AsyncMock(return_value=True)
    provider._idp.decode_token = MagicMock(return_value=("Bearer", dict(payload)))
    provider._idp.user_from_id = AsyncMock(**owner)
    return provider


def _bearer_request() -> MagicMock:
    request = MagicMock()
    request.headers = {"Authorization": "Bearer tok"}
    return request


OAUTH_USER_TOKEN = {"user_id": OWNER_ID, "client_id": "app", "jti": "j-1", "scope": "default profile email"}


class TestUserinfoOwner:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("owner", _GONE)
    async def test_a_missing_or_disabled_owner_is_401(self, owner):
        provider = _userinfo_provider(OAUTH_USER_TOKEN, owner)

        response = await provider.userinfo(_bearer_request())

        assert response.status == 401
        assert json.loads(response.body)["error"] == "invalid_token"

    @pytest.mark.asyncio
    async def test_an_identity_store_outage_is_503(self):
        provider = _userinfo_provider(OAUTH_USER_TOKEN, _OUTAGE)

        response = await provider.userinfo(_bearer_request())

        assert response.status == 503
        assert json.loads(response.body)["error"] == "temporarily_unavailable"

    @pytest.mark.asyncio
    async def test_an_active_owner_answers_from_one_lookup(self):
        provider = _userinfo_provider(OAUTH_USER_TOKEN, {"return_value": ACTIVE})

        response = await provider.userinfo(_bearer_request())

        assert response.status == 200
        body = json.loads(response.body)
        assert body["sub"] == str(OWNER_ID)
        assert body["username"] == "owner"
        assert body["email"] == "o@example.com"
        provider._idp.user_from_id.assert_awaited_once_with(OWNER_ID)

    @pytest.mark.asyncio
    async def test_the_owner_is_checked_even_without_profile_scopes(self):
        token = {**OAUTH_USER_TOKEN, "scope": "default"}
        provider = _userinfo_provider(token, {"side_effect": UserNotFound("gone")})

        response = await provider.userinfo(_bearer_request())

        assert response.status == 401

    @pytest.mark.asyncio
    async def test_a_token_that_is_not_an_oauth_user_token_keeps_the_tolerant_lookup(self):
        # No client_id: not an OAuth user token (e.g. a BasicAuth JWT) — unchanged.
        token = {"user_id": OWNER_ID, "jti": "j-1", "scope": "default profile"}
        provider = _userinfo_provider(token, {"side_effect": UserNotFound("gone")})

        response = await provider.userinfo(_bearer_request())

        assert response.status == 200
        assert json.loads(response.body) == {"sub": str(OWNER_ID)}


# --- introspection ----------------------------------------------------------------------------
CALLER = OAuthClient(
    client_id="rs_client",
    client_pk=10,
    client_name="Resource Server",
    client_secret="s3cr3t",
    client_type="confidential",
    redirect_uris=[],
    default_scopes=["default"],
    allowed_grant_types=["client_credentials"],
)


class _NeverRevoked:
    async def is_revoked(self, jti):
        return False


class _OneRefresh:
    def __init__(self, token):
        self.token = token

    async def get_token(self, value):
        return self.token if value == self.token.refresh_token else None


def _introspect_provider(owner: dict, *, refresh=None) -> Oauth2Provider:
    provider = Oauth2Provider.__new__(Oauth2Provider)
    provider.logger = MagicMock()
    provider.client_storage = MagicMock()
    provider.client_storage.get_client = AsyncMock(return_value=CALLER)
    provider.access_token_storage = _NeverRevoked()
    provider.refresh_token_storage = refresh or MagicMock()

    @asynccontextmanager
    async def _no_generation(request, user_id):
        yield None, 0

    provider._user_generation = _no_generation
    provider._generation_ok = AsyncMock(return_value=True)
    provider._idp = MagicMock()
    provider._idp.user_from_id = AsyncMock(**owner)
    return provider


def _access_payload(client_id: str = CALLER.client_id) -> dict:
    now = datetime.now(timezone.utc).timestamp()
    return {
        "jti": "jti-1",
        "client_id": client_id,
        "user_id": OWNER_ID,
        "scope": "default",
        "exp": now + 3600,
        "iat": now,
        "token_type": "Bearer",
        "aud": "user",
    }


def _form(token: str, **extra) -> MagicMock:
    request = MagicMock()
    request.method = "POST"
    request.content_type = "application/x-www-form-urlencoded"
    request.post = AsyncMock(
        return_value={"client_id": CALLER.client_id, "client_secret": "s3cr3t", "token": token, **extra}
    )
    request.headers = {}
    return request


class TestIntrospectOwner:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("owner", [*_GONE, pytest.param(_OUTAGE, id="outage")])
    async def test_an_unresolvable_owner_makes_an_access_token_inactive(self, owner):
        provider = _introspect_provider(owner)
        provider._idp.decode_token = MagicMock(return_value=(None, _access_payload()))

        response = await provider.introspect(_form("access"))

        assert response.status == 200
        assert json.loads(response.body) == {"active": False}

    @pytest.mark.asyncio
    async def test_an_active_owner_keeps_the_token_active_with_its_username(self):
        provider = _introspect_provider({"return_value": ACTIVE})
        provider._idp.decode_token = MagicMock(return_value=(None, _access_payload()))

        response = await provider.introspect(_form("access"))

        body = json.loads(response.body)
        assert body["active"] is True
        assert body["username"] == "owner"
        provider._idp.user_from_id.assert_awaited_once_with(OWNER_ID)

    @pytest.mark.asyncio
    async def test_a_foreign_client_never_triggers_an_owner_lookup(self):
        provider = _introspect_provider({"return_value": ACTIVE})
        provider._idp.decode_token = MagicMock(return_value=(None, _access_payload(client_id="someone_else")))

        response = await provider.introspect(_form("access"))

        assert json.loads(response.body) == {"active": False}
        provider._idp.user_from_id.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("owner", [*_GONE, pytest.param(_OUTAGE, id="outage")])
    async def test_an_unresolvable_owner_makes_a_refresh_token_inactive(self, owner):
        now = datetime.now()
        rt = OauthRefreshToken(
            client=CALLER,
            user_id=OWNER_ID,
            refresh_token=secrets.token_urlsafe(40),
            scope="default offline_access",
            issued_at=now,
            expires_at=now + timedelta(days=30),
            absolute_expires_at=now + timedelta(days=90),
        )
        provider = _introspect_provider(owner, refresh=_OneRefresh(rt))
        provider._idp.decode_token = MagicMock(side_effect=ValueError("opaque"))

        response = await provider.introspect(_form(rt.refresh_token, token_type_hint="refresh_token"))

        assert json.loads(response.body) == {"active": False}
