"""FEAT-108 M6 — unknown or disabled resource owners fail closed; store outages answer 503.

TASK-200 adds the IdentityProvider.user_from_id tests; TASK-203/204 append provider tests.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web
from asyncdb.exceptions import NoDataFound
from datamodel.exceptions import ValidationError

from navigator_auth.backends.idp import IdentityProvider
from navigator_auth.backends.oauth2.backend import Oauth2Provider
from navigator_auth.backends.oauth2.client_backend import MemoryClientStorage
from navigator_auth.backends.oauth2.models import OAuthClient
from navigator_auth.backends.oauth2.pkce import generate_challenge
from navigator_auth.exceptions import FailedAuth, IdentityStoreUnavailable, UserNotFound


def _idp(*, get=None, acquire_error=None) -> IdentityProvider:
    """IdentityProvider over a fake pool: `async with await db.acquire() as conn`."""
    idp = IdentityProvider()
    conn_ctx = MagicMock()
    conn_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    conn_ctx.__aexit__ = AsyncMock(return_value=False)
    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=conn_ctx, side_effect=acquire_error)
    idp.app = {"authdb": pool}
    idp.user_search = MagicMock()
    idp.user_search.get = get or AsyncMock(return_value=None)
    return idp


class TestUserFromId:
    @pytest.mark.asyncio
    async def test_found(self):
        user = MagicMock()
        assert await _idp(get=AsyncMock(return_value=user)).user_from_id(1) is user

    @pytest.mark.asyncio
    async def test_no_data_found_is_user_not_found(self):
        with pytest.raises(UserNotFound):
            await _idp(get=AsyncMock(side_effect=NoDataFound("none"))).user_from_id(1)

    @pytest.mark.asyncio
    async def test_empty_result_is_user_not_found(self):
        with pytest.raises(UserNotFound):
            await _idp(get=AsyncMock(return_value=None)).user_from_id(1)

    @pytest.mark.asyncio
    async def test_validation_error_is_reraised(self):
        err = ValidationError("bad row", payload={"a": 1})
        with pytest.raises(ValidationError) as info:
            await _idp(get=AsyncMock(side_effect=err)).user_from_id(1)
        assert info.value is err

    @pytest.mark.asyncio
    @pytest.mark.parametrize("where", ["acquire", "query", "no_pool"])
    async def test_store_outage_is_identity_store_unavailable(self, where):
        secret = "db-secret-detail"
        if where == "acquire":
            cause = ConnectionError(secret)
            idp = _idp(acquire_error=cause)
        elif where == "query":
            cause = RuntimeError(secret)
            idp = _idp(get=AsyncMock(side_effect=cause))
        else:
            cause = None
            idp = _idp()
            idp.app = {}
        with pytest.raises(IdentityStoreUnavailable) as info:
            await idp.user_from_id(1)
        exc = info.value
        assert exc.status == 503
        assert secret not in str(exc)
        if cause is not None:
            assert exc.__cause__ is cause
        else:
            assert isinstance(exc.__cause__, KeyError)


# --- TASK-203: resolver, authorize, consent ---------------------------------------------------
OWNER_ID = 35
CLIENT_UID = "cli_owner_test"
REDIRECT_URI = "https://app.example.com/cb"


async def _noop(request):  # pragma: no cover
    return web.Response()


@pytest.fixture
def provider():
    prov = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    prov.logger = MagicMock()
    return prov


def _owner_user(is_active=True):
    user = MagicMock()
    user.user_id = OWNER_ID
    user.is_active = is_active
    return user


def _params():
    return {
        "response_type": "code",
        "client_id": CLIENT_UID,
        "redirect_uri": REDIRECT_URI,
        "scope": "default",
        "state": "st123",
        "code_challenge": generate_challenge("v" * 50),
        "code_challenge_method": "S256",
    }


class _Codes:
    def __init__(self):
        self.codes = {}

    async def save_code(self, code_obj):
        self.codes[code_obj.code] = code_obj
        return True


async def _wired(provider, user_from_id, params=None, action=None):
    """Provider wired for authorize/consent with a session owner id 35."""
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
    provider.code_storage = _Codes()
    provider.grant_storage = None
    session_user = MagicMock()
    session_user.user_id = OWNER_ID
    provider.check_session = AsyncMock(return_value={"user_id": OWNER_ID})
    provider._decode_session_user = MagicMock(return_value=session_user)
    provider._session_auth_context = AsyncMock(return_value=None)
    provider._idp.user_from_id = user_from_id
    payload = dict(params or _params())
    if action:
        payload["action"] = action
    provider.get_payload = AsyncMock(return_value=payload)
    app = web.Application()
    app.router.add_route("*", "/oauth2/login", _noop, name="nav_oauth2_login")
    request = MagicMock()
    request.app = app
    request.method = "POST" if action else "GET"
    return request


class TestResolveResourceOwner:
    @pytest.mark.asyncio
    async def test_found_and_active(self, provider):
        user = _owner_user()
        provider._idp.user_from_id = AsyncMock(return_value=user)
        assert await provider._resolve_resource_owner(OWNER_ID) is user

    @pytest.mark.asyncio
    async def test_user_not_found(self, provider):
        provider._idp.user_from_id = AsyncMock(side_effect=UserNotFound("x"))
        with pytest.raises(UserNotFound):
            await provider._resolve_resource_owner(OWNER_ID)

    @pytest.mark.asyncio
    async def test_validation_error_is_user_not_found(self, provider):
        provider._idp.user_from_id = AsyncMock(side_effect=ValidationError("bad"))
        with pytest.raises(UserNotFound):
            await provider._resolve_resource_owner(OWNER_ID)

    @pytest.mark.asyncio
    async def test_inactive_is_failed_auth(self, provider):
        provider._idp.user_from_id = AsyncMock(return_value=_owner_user(is_active=False))
        with pytest.raises(FailedAuth):
            await provider._resolve_resource_owner(OWNER_ID)

    @pytest.mark.asyncio
    async def test_inactive_dict_record_is_failed_auth(self, provider):
        provider._idp.user_from_id = AsyncMock(return_value={"user_id": 1, "is_active": False})
        with pytest.raises(FailedAuth):
            await provider._resolve_resource_owner(OWNER_ID)

    @pytest.mark.asyncio
    async def test_store_unavailable_passes_through(self, provider):
        provider._idp.user_from_id = AsyncMock(side_effect=IdentityStoreUnavailable())
        with pytest.raises(IdentityStoreUnavailable):
            await provider._resolve_resource_owner(OWNER_ID)

    @pytest.mark.asyncio
    async def test_unknown_exception_is_outage(self, provider):
        provider._idp.user_from_id = AsyncMock(side_effect=RuntimeError("db down"))
        with pytest.raises(IdentityStoreUnavailable):
            await provider._resolve_resource_owner(OWNER_ID)


class TestAuthorizeUnknownOwner:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "lookup",
        [
            AsyncMock(side_effect=UserNotFound("x")),
            AsyncMock(side_effect=ValidationError("bad")),
            AsyncMock(return_value=_owner_user(is_active=False)),
        ],
        ids=["unknown", "validation_error", "disabled"],
    )
    async def test_redirects_to_login(self, provider, lookup):
        request = await _wired(provider, lookup)
        with pytest.raises(web.HTTPFound) as exc:
            await provider.authorize(request)
        location = str(exc.value.location)
        assert location.startswith("/oauth2/login")
        for key in ("client_id", "redirect_uri", "state", "scope", "code_challenge", "code_challenge_method"):
            assert f"{key}=" in location
        assert provider.code_storage.codes == {}

    @pytest.mark.asyncio
    async def test_outage_is_503(self, provider):
        request = await _wired(provider, AsyncMock(side_effect=RuntimeError("db down")))
        response = await provider.authorize(request)
        assert response.status == 503
        assert json.loads(response.body)["error"] == "server_error"
        assert "db down" not in response.body.decode()
        assert provider.code_storage.codes == {}


class TestConsentUnknownOwner:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "lookup",
        [
            AsyncMock(side_effect=UserNotFound("x")),
            AsyncMock(return_value=_owner_user(is_active=False)),
        ],
        ids=["unknown", "disabled"],
    )
    async def test_consent_unknown_owner_401(self, provider, lookup):
        request = await _wired(provider, lookup, action="approve")
        response = await provider.consent(request)
        assert response.status == 401
        body = json.loads(response.body)
        assert body["error"] == "access_denied"
        assert body["error_description"] == "Unknown or disabled resource owner."
        assert provider.code_storage.codes == {}

    @pytest.mark.asyncio
    async def test_consent_outage_is_503(self, provider):
        request = await _wired(provider, AsyncMock(side_effect=RuntimeError("db down")), action="approve")
        response = await provider.consent(request)
        assert response.status == 503
        assert json.loads(response.body)["error"] == "server_error"
        assert provider.code_storage.codes == {}
