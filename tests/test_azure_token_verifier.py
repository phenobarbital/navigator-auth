"""Unit tests for FEAT-096 TASK-049: AzureAuth.verify_external_token +
audience-bound check_credentials.

Reuses the rsa_keypair/JWKS-mocking pattern from
tests/test_external_verify_helpers.py. Mocks `AzureAuth.get` (Graph `/me`)
with a canned profile — no real network calls.
"""
import base64
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
from aiohttp.test_utils import make_mocked_request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from navigator_auth.backends import jwksutils
from navigator_auth.backends.azure import AzureAuth
from navigator_auth.conf import (
    AZURE_ADFS_CLIENT_ID,
    AZURE_ADFS_TENANT_ID,
    AZURE_IDENTITY_SCOPES,
)
from navigator_auth.identity.types import TokenResponse
from navigator_auth.exceptions import InvalidAuth

# Pre-existing, out-of-scope quirk: BaseAuthBackend.auth_error() passes a
# `body=` kwarg into aiohttp's web.HTTPUnauthorized(...), which aiohttp now
# deprecates; this project's pytest config turns warnings into errors.
pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

KID = "azure-test-kid"
ISSUER = f"https://login.microsoftonline.com/{AZURE_ADFS_TENANT_ID}/v2.0"
GRAPH_PROFILE = {
    "id": "graph-oid-123",
    "userPrincipalName": "user@example.com",
    "displayName": "Test User",
    "mail": "user@example.com",
}


@pytest.fixture(autouse=True)
def _clear_jwks_cache():
    jwksutils.get_jwks.cache_clear()
    yield
    jwksutils.get_jwks.cache_clear()


def _b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.fixture
def rsa_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": KID,
        "use": "sig",
        "alg": "RS256",
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }
    return key, jwk


def _pem(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _make_token(private_key, kid: str, claims: dict) -> str:
    return pyjwt.encode(claims, _pem(private_key), algorithm="RS256", headers={"kid": kid})


def _id_token_claims(**overrides) -> dict:
    now = int(time.time())
    claims = {
        "aud": AZURE_ADFS_CLIENT_ID,
        "iss": ISSUER,
        "oid": "azure-oid-1",
        "sub": "azure-sub-1",
        "iat": now,
        "exp": now + 3600,
    }
    claims.update(overrides)
    return claims


_FAKE_JWKS_URI = "https://login.microsoftonline.com/fake-tenant/discovery/v2.0/keys"


def _mock_jwks(monkeypatch, jwk: dict):
    """Azure/ADFS verification goes through OIDC discovery first (to learn
    `jwks_uri`), then fetches the JWKS itself — both via `requests.get`.
    Mock both steps by URL.
    """

    class _FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    def _fake_get(url, *a, **kw):
        if "openid-configuration" in url:
            return _FakeResponse({"jwks_uri": _FAKE_JWKS_URI})
        return _FakeResponse({"keys": [jwk]})

    monkeypatch.setattr(jwksutils.requests, "get", _fake_get)


@pytest.fixture
def backend():
    be = AzureAuth(user_model=object)
    be.userinfo_uri = "https://graph.microsoft.com/v1.0/me"
    be.get = AsyncMock(return_value=dict(GRAPH_PROFILE))
    return be


# ---------------------------------------------------------------------------
# id_token path
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_verify_id_token_ok(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    id_token = _make_token(key, KID, _id_token_claims())
    userinfo, normalized = await backend.verify_external_token(
        "graph-access-token", token_type="Bearer", id_token=id_token
    )
    assert userinfo == GRAPH_PROFILE
    assert normalized.provider_user_id == "azure-oid-1"
    assert normalized.id_token == id_token
    assert normalized.expires_at is not None
    backend.get.assert_awaited_once()


@pytest.mark.asyncio
async def test_verify_id_token_wrong_aud(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    id_token = _make_token(key, KID, _id_token_claims(aud="some-other-app"))
    with pytest.raises(InvalidAuth) as exc:
        await backend.verify_external_token("token", id_token=id_token)
    assert "wrong_audience" in str(exc.value)
    backend.get.assert_not_awaited()


# ---------------------------------------------------------------------------
# access-token-only path
# ---------------------------------------------------------------------------
def _access_token_claims(**overrides) -> dict:
    now = int(time.time())
    claims = {
        "aud": "https://graph.microsoft.com",
        "appid": AZURE_ADFS_CLIENT_ID,
        "iss": ISSUER,
        "oid": "azure-oid-2",
        "iat": now,
        "exp": now + 3600,
    }
    claims.update(overrides)
    return claims


@pytest.mark.asyncio
async def test_verify_access_token_requires_appid(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    # appid belongs to a DIFFERENT application than ours.
    token = _make_token(key, KID, _access_token_claims(appid="some-other-app-id"))
    with pytest.raises(InvalidAuth) as exc:
        await backend.verify_external_token(token)
    assert "wrong_audience" in str(exc.value)
    backend.get.assert_not_awaited()


@pytest.mark.asyncio
async def test_verify_access_token_ok_with_matching_appid(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    token = _make_token(key, KID, _access_token_claims())
    userinfo, normalized = await backend.verify_external_token(token)
    assert userinfo == GRAPH_PROFILE
    assert normalized.provider_user_id == "azure-oid-2"
    backend.get.assert_awaited_once()


@pytest.mark.asyncio
async def test_verify_access_token_ok_with_trusted_appid(backend, rsa_keypair, monkeypatch):
    """A token minted for a trusted third-party app (AZURE_TRUSTED_APPIDS)
    is accepted; anything outside that allow-list is still rejected."""
    from navigator_auth.backends import azure as azure_module

    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    teams_bridge = "93c34821-c15f-4226-affd-995b488e8c11"
    monkeypatch.setattr(
        azure_module,
        "_AZURE_TRUSTED_APPIDS",
        frozenset({AZURE_ADFS_CLIENT_ID, teams_bridge}),
    )
    token = _make_token(key, KID, _access_token_claims(appid=teams_bridge))
    userinfo, normalized = await backend.verify_external_token(token)
    assert userinfo == GRAPH_PROFILE
    assert normalized.provider_user_id == "azure-oid-2"
    backend.get.assert_awaited_once()

    backend.get.reset_mock()
    other = _make_token(key, KID, _access_token_claims(appid="some-other-app-id"))
    with pytest.raises(InvalidAuth) as exc:
        await backend.verify_external_token(other)
    assert "wrong_audience" in str(exc.value)
    backend.get.assert_not_awaited()


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_verify_expired(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    now = int(time.time())
    id_token = _make_token(key, KID, _id_token_claims(iat=now - 7200, exp=now - 3600))
    with pytest.raises(InvalidAuth) as exc:
        await backend.verify_external_token("token", id_token=id_token)
    assert "expired" in str(exc.value)


# ---------------------------------------------------------------------------
# check_credentials regression: audience-bound now, not any Graph token.
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_check_credentials_audience_bound_regression(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    # A Graph token minted for a DIFFERENT application (appid mismatch) —
    # this used to be accepted unconditionally before TASK-049.
    foreign_token = _make_token(
        key, KID, _access_token_claims(appid="some-other-app-id")
    )
    request = make_mocked_request(
        "GET", "/auth/azure/check_credentials",
        headers={"Authorization": f"Bearer {foreign_token}"},
    )
    response = await backend.check_credentials(request)
    assert response.status == 401
    backend.get.assert_not_awaited()


# --- FEAT-103: provider-credential capture -------------------------------

@pytest.fixture
def msal_result_full():
    """An MSAL authorization_code result shaped like msal 1.38.0 returns it."""
    return {
        "token_type": "Bearer",
        "access_token": "AT.graph",
        "id_token": "ID.jwt",
        "refresh_token": "RT.secret",      # present on the auth-code grant
        "expires_in": 419,                 # measured lifetime
        "scope": "User.Read Mail.Read",
        "id_token_claims": {"oid": "4e2aa0ea-0000", "tid": "af176793-0000"},
    }


def _fake_cache(secret=None):
    """A SerializableTokenCache double (only ``.find`` is used)."""
    cache = MagicMock()
    cache.find.return_value = [{"secret": secret}] if secret else []
    return cache


class TestMsalNormalizer:
    def test_msal_normalizer_captures_id_and_prefers_result_refresh(
        self, msal_result_full
    ):
        token = AzureAuth._token_from_msal_result(
            msal_result_full, _fake_cache("RT.from-cache")
        )
        assert token.refresh_token == "RT.secret"  # result wins over cache
        assert token.id_token == "ID.jwt"
        assert token.scopes == ["User.Read", "Mail.Read"]
        assert "refresh_token" not in token.raw
        assert token.expires_at is not None

    def test_normalizer_falls_back_to_cache_when_result_omits_refresh(
        self, msal_result_full
    ):
        msal_result_full.pop("refresh_token")
        token = AzureAuth._token_from_msal_result(
            msal_result_full, _fake_cache("RT.from-cache")
        )
        assert token.refresh_token == "RT.from-cache"


def _wire_callback(backend, monkeypatch, msal_result):
    """Wire auth_callback with a stubbed MSAL app, redis flow record and
    downstream methods; returns the spies."""
    import json
    from navigator_auth.backends import azure as azure_mod

    app = MagicMock()
    app.acquire_token_by_auth_code_flow = MagicMock(return_value=msal_result)
    backend.get_msal_app = MagicMock(return_value=app)
    redis = MagicMock()
    redis.get = AsyncMock(return_value=json.dumps({"state": "st1"}))
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=redis)
    cm.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(azure_mod.aioredis, "Redis", MagicMock(return_value=cm))
    backend._pool = MagicMock()
    spies = MagicMock()
    spies.build = MagicMock(wraps=backend.build_user_info)
    backend.build_user_info = spies.build
    backend.validate_user_info = AsyncMock(return_value={"token": "NAV"})
    backend.capture_login_credential = AsyncMock()
    backend.home_redirect = MagicMock(return_value="HOME")
    return spies


class TestAuthCallbackCapture:
    @pytest.mark.asyncio
    async def test_auth_callback_captures_refresh_and_id_token(
        self, backend, msal_result_full, monkeypatch
    ):
        backend.user_mapping = {"id": "id", "userPrincipalName": "username"}
        backend.username_attribute = "username"
        spies = _wire_callback(backend, monkeypatch, msal_result_full)
        request = make_mocked_request("GET", "/auth/azure/callback/?state=st1&code=c")
        result = await backend.auth_callback(request)
        assert result == "HOME"
        kwargs = spies.build.call_args.kwargs
        assert kwargs["id_token"] == "ID.jwt"
        assert kwargs["refresh_token"] == "RT.secret"
        assert kwargs["expires_at"] is not None
        assert kwargs["provider_user_id"] == "graph-oid-123"  # verified Graph id
        backend.capture_login_credential.assert_awaited_once()
        grant = backend.capture_login_credential.await_args.args[1]
        assert isinstance(grant, TokenResponse)
        assert grant.refresh_token == "RT.secret"
        assert grant.provider_user_id == "graph-oid-123"
        # the callback requested the .default selector, result carried scope
        assert grant.scopes == ["User.Read", "Mail.Read"]

    @pytest.mark.asyncio
    async def test_auth_callback_refresh_token_from_cache_fallback(
        self, backend, msal_result_full, monkeypatch
    ):
        msal_result_full.pop("refresh_token")
        backend.user_mapping = {"id": "id", "userPrincipalName": "username"}
        backend.username_attribute = "username"
        spies = _wire_callback(backend, monkeypatch, msal_result_full)
        monkeypatch.setattr(
            AzureAuth, "_refresh_token_from_cache",
            staticmethod(lambda cache: "RT.from-cache"),
        )
        request = make_mocked_request("GET", "/auth/azure/callback/?state=st1&code=c")
        await backend.auth_callback(request)
        grant = backend.capture_login_credential.await_args.args[1]
        assert grant.refresh_token == "RT.from-cache"
        assert spies.build.call_args.kwargs["refresh_token"] == "RT.from-cache"

    @pytest.mark.asyncio
    async def test_auth_callback_profile_without_account_id_creates_no_binding(
        self, backend, msal_result_full, monkeypatch
    ):
        """A Graph profile with neither id nor userPrincipalName yields
        provider_user_id None (so the vault write is skipped downstream)."""
        backend.get = AsyncMock(return_value={"displayName": "x", "username": "u"})
        backend.user_mapping = {"username": "username"}
        backend.username_attribute = "username"
        backend.userid_attribute = "username"
        spies = _wire_callback(backend, monkeypatch, msal_result_full)
        request = make_mocked_request("GET", "/auth/azure/callback/?state=st1&code=c")
        await backend.auth_callback(request)
        assert spies.build.call_args.kwargs["provider_user_id"] is None


class TestAuthCallbackFreshness:
    """issue:3fd80396c685 — Entra answers a silent re-login with the access
    token it already issued; the callback must not publish it as-is."""

    @pytest.mark.asyncio
    async def test_cached_entra_token_is_refreshed_before_the_session(
        self, backend, msal_result_full, monkeypatch
    ):
        # what Entra returns on the second login: the same token, with only
        # the remainder of its lifetime in expires_in
        msal_result_full["expires_in"] = 45
        backend.user_mapping = {"id": "id", "userPrincipalName": "username"}
        backend.username_attribute = "username"
        rotated = TokenResponse(
            access_token="AT.fresh", refresh_token="RT.rotated",
            expires_in=5457, scopes=["User.Read", "Mail.Read"],
        )
        backend.refresh_provider_tokens = AsyncMock(return_value=rotated)
        spies = _wire_callback(backend, monkeypatch, msal_result_full)
        request = make_mocked_request("GET", "/auth/azure/callback/?state=st1&code=c")
        assert await backend.auth_callback(request) == "HOME"
        backend.refresh_provider_tokens.assert_awaited_once()
        # Graph, the session and the vault all see the rotated credential
        backend.get.assert_awaited_once()
        assert backend.get.await_args.kwargs["token"] == "AT.fresh"
        assert spies.build.call_args.kwargs["token"] == "AT.fresh"
        assert spies.build.call_args.kwargs["expires_at"] == rotated.expires_at
        assert backend.capture_login_credential.await_args.args[1] is rotated
        # the account binding survives the rotation
        assert rotated.provider_user_id == "graph-oid-123"

    @pytest.mark.asyncio
    async def test_a_freshly_issued_token_is_not_refreshed(
        self, backend, msal_result_full, monkeypatch
    ):
        backend.user_mapping = {"id": "id", "userPrincipalName": "username"}
        backend.username_attribute = "username"
        backend.refresh_provider_tokens = AsyncMock()
        spies = _wire_callback(backend, monkeypatch, msal_result_full)
        request = make_mocked_request("GET", "/auth/azure/callback/?state=st1&code=c")
        await backend.auth_callback(request)
        backend.refresh_provider_tokens.assert_not_awaited()
        assert spies.build.call_args.kwargs["token"] == "AT.graph"


class TestAzureRefreshScopes:
    @pytest.mark.asyncio
    async def test_azure_login_refresh_preserves_grant_scopes(self, backend):
        app = MagicMock()
        app.acquire_token_by_refresh_token = MagicMock(
            return_value={
                "access_token": "AT.new", "expires_in": 419,
                "scope": "User.Read Mail.Read",
            }
        )
        backend.get_msal_app = MagicMock(return_value=app)
        stored = TokenResponse(
            access_token="AT.old",
            refresh_token="RT.secret",
            scopes=["User.Read", "Mail.Read", "offline_access"],
        )
        refreshed = await backend.refresh_provider_tokens(stored)
        sent = app.acquire_token_by_refresh_token.call_args.kwargs["scopes"]
        assert sent == ["User.Read", "Mail.Read"]  # offline_access excluded
        assert sent != AZURE_IDENTITY_SCOPES
        assert refreshed.access_token == "AT.new"
        assert refreshed.refresh_token == "RT.secret"  # not rotated: kept

    def test_azure_missing_scope_fallback(self, msal_result_full):
        result = dict(msal_result_full)
        result.pop("scope")
        cache = _fake_cache()
        # (a) callback: the .default selector is the requested value
        cb = AzureAuth._token_from_msal_result(
            result, cache,
            requested_scopes=["https://graph.microsoft.com/.default"],
        )
        assert cb.scopes == ["https://graph.microsoft.com/.default"]
        # (b) ROPC
        ropc = AzureAuth._token_from_msal_result(
            result, cache, requested_scopes=["User.ReadBasic.All"]
        )
        assert ropc.scopes == ["User.ReadBasic.All"]
        # reserved scopes are dropped
        res = AzureAuth._token_from_msal_result(
            result, cache, requested_scopes=["openid", "User.Read", "offline_access"]
        )
        assert res.scopes == ["User.Read"]

    @pytest.mark.asyncio
    async def test_azure_missing_scope_fallback_on_refresh(self, backend):
        """A refresh response omitting `scope` still retains the requested
        scopes rather than an empty list."""
        app = MagicMock()
        app.acquire_token_by_refresh_token = MagicMock(
            return_value={"access_token": "AT.new", "expires_in": 419}
        )
        backend.get_msal_app = MagicMock(return_value=app)
        stored = TokenResponse(
            access_token="AT.old", refresh_token="RT.secret",
            scopes=["User.Read", "Mail.Read"],
        )
        refreshed = await backend.refresh_provider_tokens(stored)
        assert refreshed.scopes == ["User.Read", "Mail.Read"]

    @pytest.mark.asyncio
    async def test_azure_refresh_reduced_grant_is_not_published(self, backend):
        app = MagicMock()
        app.acquire_token_by_refresh_token = MagicMock(
            return_value={
                "access_token": "AT.reduced", "expires_in": 419,
                "scope": "User.Read",  # Mail.Read explicitly dropped
            }
        )
        backend.get_msal_app = MagicMock(return_value=app)
        stored = TokenResponse(
            access_token="AT.old",
            refresh_token="RT.secret",
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
            scopes=["User.Read", "Mail.Read"],
            provider_user_id="graph-oid-123",
        )
        assert await backend.refresh_provider_tokens(stored) is None

        # drive the full helper: the session credential must be untouched
        backend._service_name = "azure"
        session = {
            "user_id": 35, "auth_method": "azure", "auth_token": "AT.old",
            "external_provider_user_id": "graph-oid-123",
        }
        store = MagicMock()
        store.get_for_provider_account = AsyncMock(return_value=MagicMock())
        store.decrypt_credential = MagicMock(return_value=stored)
        store.update_tokens = AsyncMock()
        request = make_mocked_request("GET", "/x")
        request.app["authdb"] = MagicMock()
        with patch(
            "navigator_session.get_session", AsyncMock(return_value=session)
        ), patch(
            "navigator_auth.identity.store.IdentityStore",
            MagicMock(return_value=store),
        ):
            result = await backend.get_live_provider_token(request, 35)
        assert result is None  # expired + reduced refresh => nothing to publish
        assert session["auth_token"] == "AT.old"
        store.update_tokens.assert_not_awaited()
