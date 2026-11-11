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
from navigator_auth.backends.oauth2.code_backend import AuthorizationCodeStorage
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


# --- TASK-204: authorization-code claim storage ----------------------------------------------
class TestCodeStorageClaim:
    @pytest.mark.asyncio
    async def test_claim_code_uses_atomic_set_nx_with_ttl(self):
        storage = AuthorizationCodeStorage.__new__(AuthorizationCodeStorage)
        storage.prefix = "oauth2:code:"
        storage.redis = MagicMock()
        storage.redis.set = AsyncMock(return_value=True)

        assert await storage.claim_code("code-1") is True
        storage.redis.set.assert_awaited_once_with("oauth2:code:claim:code-1", "1", nx=True, ex=30)

    @pytest.mark.asyncio
    async def test_release_claim_deletes_claim_key(self):
        storage = AuthorizationCodeStorage.__new__(AuthorizationCodeStorage)
        storage.prefix = "oauth2:code:"
        storage.redis = MagicMock()
        storage.redis.delete = AsyncMock()

        await storage.release_claim("code-1")
        storage.redis.delete.assert_awaited_once_with("oauth2:code:claim:code-1")


# --- FEAT-108 review follow-up: grant-level owner checks (D6) ---------------------------------
import contextlib  # noqa: E402
import time  # noqa: E402
from datetime import datetime, timedelta  # noqa: E402
from unittest.mock import patch  # noqa: E402

VERIFIER = "v" * 50
_UNRESOLVED = "The resource owner of this grant cannot be resolved."


def _auth_code():
    code = MagicMock()
    code.used = False
    code.expires_at = datetime.now() + timedelta(minutes=5)
    code.client = MagicMock()
    code.client.client_id = CLIENT_UID
    code.redirect_uri = REDIRECT_URI
    code.code_challenge = generate_challenge(VERIFIER)
    code.code_challenge_method = "S256"
    code.user_id = OWNER_ID
    code.generation = 0
    code.scope = "default"
    code.mfa = False
    code.amr = None
    code.resource = None
    return code


class _GrantCodes:
    """Records the order of claim / consume / release calls."""

    def __init__(self, auth_code, claimable=True):
        self.auth_code = auth_code
        self.claimable = claimable
        self.calls = []

    async def get_code(self, code):
        return self.auth_code

    async def delete_code(self, code):
        self.calls.append("delete")

    async def mark_used(self, code):
        self.calls.append("mark_used")
        return True

    async def claim_code(self, code):
        self.calls.append("claim")
        return self.claimable

    async def release_claim(self, code):
        self.calls.append("release")


class _GrantRefresh:
    def __init__(self, token):
        self.token = token
        self.calls = []

    async def get_token(self, token):
        return self.token

    async def revoke_chain(self, token):
        self.calls.append(("revoke_chain", token))

    async def revoke_token(self, token, reason):
        self.calls.append(("revoke_token", reason))

    async def save_token(self, token):
        self.calls.append(("save_token", None))


async def _grant_provider(provider, claims_effect):
    """Provider wired for the token endpoint; ``claims_effect`` drives the owner lookup."""
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

    @contextlib.asynccontextmanager
    async def _generation(request, user_id):
        yield MagicMock(), 0

    provider._user_generation = _generation
    provider._token_session_claims = AsyncMock(**claims_effect)
    provider._gate_permits = AsyncMock(return_value=True)
    provider._idp.create_token = MagicMock(return_value=("tok", None, time.time() + 60, "Bearer"))
    provider.access_token_storage = None
    return provider


_OWNER_GONE = [
    pytest.param(UserNotFound("x"), id="unknown"),
    pytest.param(FailedAuth("disabled"), id="disabled"),
]


def _code_payload():
    return {
        "code": "code-1",
        "client_id": CLIENT_UID,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": VERIFIER,
    }


class TestCodeGrantOwnerCheck:
    @pytest.mark.asyncio
    async def test_found_consumes_the_code(self, provider):
        await _grant_provider(provider, {"return_value": {}})
        provider.code_storage = _GrantCodes(_auth_code())
        response = await provider._handle_authorization_code(_code_payload(), MagicMock())
        assert response.status == 200
        assert provider.code_storage.calls == ["claim", "mark_used", "delete"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("error", _OWNER_GONE)
    async def test_missing_or_disabled_owner_is_invalid_grant_and_consumes(self, provider, error):
        await _grant_provider(provider, {"side_effect": error})
        provider.code_storage = _GrantCodes(_auth_code())
        response = await provider._handle_authorization_code(_code_payload(), MagicMock())
        assert response.status == 400
        body = json.loads(response.body)
        assert body["error"] == "invalid_grant"
        assert body["error_description"] == _UNRESOLVED
        assert provider.code_storage.calls == ["claim", "mark_used", "delete"]

    @pytest.mark.asyncio
    async def test_outage_is_503_and_keeps_the_code_retryable(self, provider):
        await _grant_provider(provider, {"side_effect": IdentityStoreUnavailable()})
        provider.code_storage = _GrantCodes(_auth_code())
        response = await provider._handle_authorization_code(_code_payload(), MagicMock())
        assert response.status == 503
        assert json.loads(response.body)["error"] == "server_error"
        assert provider.code_storage.calls == ["claim", "release"]

    @pytest.mark.asyncio
    async def test_unexpected_failure_releases_the_claim(self, provider):
        await _grant_provider(provider, {"side_effect": RuntimeError("session store down")})
        provider.code_storage = _GrantCodes(_auth_code())
        with pytest.raises(RuntimeError):
            await provider._handle_authorization_code(_code_payload(), MagicMock())
        assert provider.code_storage.calls == ["claim", "release"]

    @pytest.mark.asyncio
    async def test_a_held_claim_is_rejected_before_the_owner_lookup(self, provider):
        await _grant_provider(provider, {"return_value": {}})
        provider.code_storage = _GrantCodes(_auth_code(), claimable=False)
        response = await provider._handle_authorization_code(_code_payload(), MagicMock())
        assert response.status == 400
        assert json.loads(response.body)["error_description"] == "Authorization code already used."
        assert provider.code_storage.calls == ["claim"]
        provider._token_session_claims.assert_not_awaited()


def _refresh_token(client):
    rt = MagicMock()
    rt.refresh_token = "rt-1"
    rt.revoked = False
    rt.revoked_reason = None
    rt.user_id = OWNER_ID
    rt.generation = 0
    rt.client = client
    rt.scope = "default"
    rt.mfa = False
    rt.amr = None
    rt.expires_at = datetime.now() + timedelta(days=1)
    rt.absolute_expires_at = datetime.now() + timedelta(days=30)
    return rt


async def _refresh_provider(provider, claims_effect):
    await _grant_provider(provider, claims_effect)
    client = await provider.client_storage.get_client(CLIENT_UID)
    provider.refresh_token_storage = _GrantRefresh(_refresh_token(client))
    return provider


def _refresh_payload():
    return {"refresh_token": "rt-1", "client_id": CLIENT_UID}


class TestRefreshGrantOwnerCheck:
    @pytest.mark.asyncio
    async def test_found_rotates_without_revoking_the_chain(self, provider):
        await _refresh_provider(provider, {"return_value": {}})
        response = await provider._handle_refresh_token(_refresh_payload(), MagicMock())
        assert response.status == 200
        calls = provider.refresh_token_storage.calls
        assert ("revoke_token", "rotated") in calls
        assert not [c for c in calls if c[0] == "revoke_chain"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("error", _OWNER_GONE)
    async def test_missing_or_disabled_owner_revokes_the_chain_and_does_not_rotate(self, provider, error):
        await _refresh_provider(provider, {"side_effect": error})
        response = await provider._handle_refresh_token(_refresh_payload(), MagicMock())
        assert response.status == 400
        body = json.loads(response.body)
        assert body["error"] == "invalid_grant"
        assert body["error_description"] == _UNRESOLVED
        assert provider.refresh_token_storage.calls == [("revoke_chain", "rt-1")]

    @pytest.mark.asyncio
    async def test_outage_is_503_and_neither_revokes_nor_rotates(self, provider):
        await _refresh_provider(provider, {"side_effect": IdentityStoreUnavailable()})
        response = await provider._handle_refresh_token(_refresh_payload(), MagicMock())
        assert response.status == 503
        assert json.loads(response.body)["error"] == "server_error"
        assert provider.refresh_token_storage.calls == []


class TestDeviceGrantOwnerCheck:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("error", _OWNER_GONE)
    async def test_device_poll_for_a_missing_or_disabled_owner_is_invalid_grant(self, provider, error):
        await _grant_provider(provider, {"side_effect": error})
        provider.code_storage = _GrantCodes(_auth_code())
        device = MagicMock()
        device.client_id = CLIENT_UID
        device.auth_code = "code-dev"
        device.code_challenge = None
        provider.device_code_storage = MagicMock()
        provider.device_code_storage.get_by_device_code = AsyncMock(return_value=device)
        provider.device_code_storage.update = AsyncMock()
        payload = {"device_code": "dc-1", "client_id": CLIENT_UID, "code_verifier": VERIFIER}
        with patch("navigator_auth.backends.oauth2.backend._poll_decision", return_value="approved"):
            response = await provider._handle_device_code(payload, MagicMock())
        assert response.status == 400
        body = json.loads(response.body)
        assert body["error"] == "invalid_grant"
        assert body["error_description"] == _UNRESOLVED
        assert provider.code_storage.calls == ["claim", "mark_used", "delete"]


class TestResolverFailsClosedOnNone:
    @pytest.mark.asyncio
    async def test_idp_returning_none_is_user_not_found(self, provider):
        """A custom IdP may return None; user_is_active(None) is True, so it must not pass."""
        provider._idp.user_from_id = AsyncMock(return_value=None)
        with pytest.raises(UserNotFound):
            await provider._resolve_resource_owner(OWNER_ID)

    @pytest.mark.asyncio
    async def test_outage_log_carries_no_exception_text(self, provider):
        provider._idp.user_from_id = AsyncMock(side_effect=RuntimeError("dsn=postgres://u:secret@db"))
        with pytest.raises(IdentityStoreUnavailable):
            await provider._resolve_resource_owner(OWNER_ID)
        logged = str(provider.logger.error.call_args)
        assert "secret" not in logged
        assert "RuntimeError" in logged


class TestTokenSessionClaimsResolvesOwner:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "lookup, expected",
        [
            (AsyncMock(side_effect=UserNotFound("x")), UserNotFound),
            (AsyncMock(return_value=None), UserNotFound),
            (AsyncMock(return_value=_owner_user(is_active=False)), FailedAuth),
            (AsyncMock(side_effect=IdentityStoreUnavailable()), IdentityStoreUnavailable),
        ],
        ids=["unknown", "none", "disabled", "outage"],
    )
    async def test_unresolvable_owner_raises_before_any_session_is_created(self, provider, lookup, expected):
        provider._idp.user_from_id = lookup
        provider._create_user_session = AsyncMock()
        with pytest.raises(expected):
            await provider._token_session_claims(MagicMock(), OWNER_ID)
        provider._create_user_session.assert_not_awaited()
