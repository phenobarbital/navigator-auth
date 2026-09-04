"""Unit tests for FEAT-096 TASK-049: AzureAuth.verify_external_token +
audience-bound check_credentials.

Reuses the rsa_keypair/JWKS-mocking pattern from
tests/test_external_verify_helpers.py. Mocks `AzureAuth.get` (Graph `/me`)
with a canned profile — no real network calls.
"""
import base64
import time
from unittest.mock import AsyncMock

import jwt as pyjwt
import pytest
from aiohttp.test_utils import make_mocked_request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from navigator_auth.backends import jwksutils
from navigator_auth.backends.azure import AzureAuth
from navigator_auth.conf import AZURE_ADFS_CLIENT_ID, AZURE_ADFS_TENANT_ID
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
