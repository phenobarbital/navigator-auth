"""Unit tests for FEAT-096 TASK-050: GoogleAuth.verify_external_token +
real check_credentials.

Reuses the rsa_keypair/JWKS-mocking pattern from
tests/test_external_verify_helpers.py. Mocks `GoogleAuth.get` (tokeninfo /
userinfo) — no real network calls.
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
from navigator_auth.backends.google import GOOGLE_TOKENINFO_URI, GoogleAuth
from navigator_auth.conf import GOOGLE_CLIENT_ID
from navigator_auth.exceptions import InvalidAuth

KID = "google-test-kid"
ISSUER = "https://accounts.google.com"

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


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
        "aud": GOOGLE_CLIENT_ID,
        "iss": ISSUER,
        "sub": "google-sub-1",
        "email": "user@example.com",
        "email_verified": True,
        "given_name": "Test",
        "family_name": "User",
        "name": "Test User",
        "iat": now,
        "exp": now + 3600,
    }
    claims.update(overrides)
    return claims


def _mock_jwks(monkeypatch, jwk: dict):
    class _FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"keys": [jwk]}

    monkeypatch.setattr(jwksutils.requests, "get", lambda *a, **kw: _FakeResponse())


@pytest.fixture
def backend():
    be = GoogleAuth(user_model=object)
    be.userinfo_uri = "https://openidconnect.googleapis.com/v1/userinfo"
    return be


def _mock_get(backend, *, tokeninfo=None, userinfo=None, tokeninfo_error=None, userinfo_error=None):
    async def _fake_get(url, **kwargs):
        if url.startswith(GOOGLE_TOKENINFO_URI):
            if tokeninfo_error:
                raise tokeninfo_error
            return tokeninfo
        if userinfo_error:
            raise userinfo_error
        return userinfo

    backend.get = AsyncMock(side_effect=_fake_get)


# ---------------------------------------------------------------------------
# id_token path
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_verify_id_token_ok(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    id_token = _make_token(key, KID, _id_token_claims())
    userinfo, normalized = await backend.verify_external_token(
        "access-token-value", id_token=id_token
    )
    assert userinfo["email"] == "user@example.com"
    assert normalized.provider_user_id == "google-sub-1"
    assert normalized.id_token == id_token


@pytest.mark.asyncio
async def test_verify_id_token_email_unverified(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    id_token = _make_token(key, KID, _id_token_claims(email_verified=False))
    with pytest.raises(InvalidAuth) as exc:
        await backend.verify_external_token("token", id_token=id_token)
    assert "email_unverified" in str(exc.value)


@pytest.mark.asyncio
async def test_verify_id_token_wrong_aud(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    id_token = _make_token(key, KID, _id_token_claims(aud="someone-else"))
    with pytest.raises(InvalidAuth) as exc:
        await backend.verify_external_token("token", id_token=id_token)
    assert "wrong_audience" in str(exc.value)


@pytest.mark.asyncio
async def test_verify_expired(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    now = int(time.time())
    id_token = _make_token(key, KID, _id_token_claims(iat=now - 7200, exp=now - 3600))
    with pytest.raises(InvalidAuth) as exc:
        await backend.verify_external_token("token", id_token=id_token)
    assert "expired" in str(exc.value)


@pytest.mark.asyncio
async def test_token_only_jwt_shape_treated_as_id_token(backend, rsa_keypair, monkeypatch):
    """A single `token` that itself is a JWT (no separate id_token) is
    treated as the id_token (id-token-only clients)."""
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    id_token = _make_token(key, KID, _id_token_claims())
    userinfo, normalized = await backend.verify_external_token(id_token)
    assert normalized.provider_user_id == "google-sub-1"
    assert normalized.access_token == id_token


# ---------------------------------------------------------------------------
# opaque access-token path (tokeninfo + userinfo)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_verify_access_token_tokeninfo_azp_ok(backend):
    _mock_get(
        backend,
        tokeninfo={"aud": "another-client", "azp": GOOGLE_CLIENT_ID, "scope": "email profile", "expires_in": "3599"},
        userinfo={"sub": "google-sub-2", "email": "user2@example.com", "email_verified": True},
    )
    userinfo, normalized = await backend.verify_external_token("opaque-access-token")
    assert userinfo["email"] == "user2@example.com"
    assert normalized.provider_user_id == "google-sub-2"
    assert normalized.scopes == ["email", "profile"]
    assert normalized.expires_at is not None


@pytest.mark.asyncio
async def test_verify_access_token_tokeninfo_azp_mismatch(backend):
    _mock_get(
        backend,
        tokeninfo={"aud": "another-client", "azp": "yet-another-client"},
        userinfo={"sub": "x", "email": "x@example.com", "email_verified": True},
    )
    with pytest.raises(InvalidAuth) as exc:
        await backend.verify_external_token("opaque-access-token")
    assert "wrong_audience" in str(exc.value)


@pytest.mark.asyncio
async def test_verify_access_token_userinfo_email_unverified(backend):
    _mock_get(
        backend,
        tokeninfo={"aud": GOOGLE_CLIENT_ID, "scope": "email"},
        userinfo={"sub": "x", "email": "x@example.com", "email_verified": False},
    )
    with pytest.raises(InvalidAuth) as exc:
        await backend.verify_external_token("opaque-access-token")
    assert "email_unverified" in str(exc.value)


@pytest.mark.asyncio
async def test_verify_access_token_tokeninfo_400_is_expired(backend):
    from navigator_auth.exceptions import AuthException

    _mock_get(backend, tokeninfo_error=AuthException("Invalid Value", status=400))
    with pytest.raises(InvalidAuth) as exc:
        await backend.verify_external_token("opaque-access-token")
    assert "expired" in str(exc.value)


# ---------------------------------------------------------------------------
# check_credentials no longer returns True unconditionally
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_check_credentials_rejects_wrong_audience(backend):
    _mock_get(
        backend,
        tokeninfo={"aud": "another-client", "azp": "yet-another-client"},
    )
    request = make_mocked_request(
        "GET", "/auth/google/check_credentials",
        headers={"Authorization": "Bearer some-foreign-token"},
    )
    response = await backend.check_credentials(request)
    assert response is not True
    assert response.status == 401


@pytest.mark.asyncio
async def test_check_credentials_no_longer_stub_true(backend):
    _mock_get(backend, tokeninfo_error=RuntimeError("network down"))
    request = make_mocked_request(
        "GET", "/auth/google/check_credentials",
        headers={"Authorization": "Bearer some-token"},
    )
    response = await backend.check_credentials(request)
    assert response is not True
