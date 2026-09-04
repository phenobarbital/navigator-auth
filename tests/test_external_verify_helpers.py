"""Unit tests for FEAT-096 TASK-048:

- ExternalAuth.verify_external_token default (NotImplementedError).
- ExternalAuth._verify_jwt (JWKS-based JWT verification).
- ExternalAuth._require_verified_email.
- jwksutils.get_jwks with an explicit `jwks_url`.

Uses a throwaway 2048-bit RSA keypair (PyJWT emits InsecureKeyLengthWarning
below that) and a monkeypatched `jwksutils.requests.get` — no real network
calls.
"""
import base64
import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from navigator_auth.backends import jwksutils
from navigator_auth.backends.external import EXCHANGE_REASONS, ExternalAuth
from navigator_auth.exceptions import InvalidAuth

AUDIENCE = "test-client-id"
ISSUER = "https://issuer.example.com"
KID = "test-kid-1"


class _FakeExternalAuth(ExternalAuth):
    """Minimal concrete ExternalAuth for exercising the shared helpers."""

    _service_name = "fake"

    async def check_credentials(self, request):  # pragma: no cover - unused
        return None

    async def authenticate(self, request):  # pragma: no cover - unused
        return None

    async def auth_callback(self, request):  # pragma: no cover - unused
        return None

    async def logout(self, request):  # pragma: no cover - unused
        return None

    async def finish_logout(self, request):  # pragma: no cover - unused
        return None


@pytest.fixture
def backend():
    return _FakeExternalAuth(user_model=object)


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


def _base_claims(**overrides) -> dict:
    now = int(time.time())
    claims = {
        "aud": AUDIENCE,
        "iss": ISSUER,
        "sub": "user-123",
        "iat": now,
        "exp": now + 3600,
    }
    claims.update(overrides)
    return claims


def _mock_jwks(monkeypatch, jwk: dict):
    class _FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"keys": [jwk]}

    monkeypatch.setattr(jwksutils.requests, "get", lambda *a, **kw: _FakeResponse())


JWKS_URL = "https://test.example.com/.well-known/jwks.json"


# ---------------------------------------------------------------------------
# verify_external_token default
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_default_verify_external_token_not_implemented(backend):
    with pytest.raises(NotImplementedError):
        await backend.verify_external_token("some-token")


# ---------------------------------------------------------------------------
# _verify_jwt
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_verify_jwt_ok(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    token = _make_token(key, KID, _base_claims())
    claims = await backend._verify_jwt(
        token, audience=AUDIENCE, issuer=ISSUER, jwks_url=JWKS_URL
    )
    assert claims["sub"] == "user-123"
    assert claims["aud"] == AUDIENCE


@pytest.mark.asyncio
async def test_verify_jwt_bad_signature(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _mock_jwks(monkeypatch, jwk)
    # Signed with a DIFFERENT key than the one published in the JWKS.
    token = _make_token(other_key, KID, _base_claims())
    with pytest.raises(InvalidAuth) as exc:
        await backend._verify_jwt(
            token, audience=AUDIENCE, issuer=ISSUER, jwks_url=JWKS_URL
        )
    assert "bad_signature" in str(exc.value)


@pytest.mark.asyncio
async def test_verify_jwt_wrong_audience(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    token = _make_token(key, KID, _base_claims(aud="someone-else"))
    with pytest.raises(InvalidAuth) as exc:
        await backend._verify_jwt(
            token, audience=AUDIENCE, issuer=ISSUER, jwks_url=JWKS_URL
        )
    assert "wrong_audience" in str(exc.value)


@pytest.mark.asyncio
async def test_verify_jwt_wrong_issuer(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    token = _make_token(key, KID, _base_claims(iss="https://not-the-issuer.example.com"))
    with pytest.raises(InvalidAuth) as exc:
        await backend._verify_jwt(
            token, audience=AUDIENCE, issuer=ISSUER, jwks_url=JWKS_URL
        )
    assert "wrong_issuer" in str(exc.value)


@pytest.mark.asyncio
async def test_verify_jwt_expired(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    now = int(time.time())
    token = _make_token(key, KID, _base_claims(iat=now - 7200, exp=now - 3600))
    with pytest.raises(InvalidAuth) as exc:
        await backend._verify_jwt(
            token, audience=AUDIENCE, issuer=ISSUER, jwks_url=JWKS_URL
        )
    assert "expired" in str(exc.value)


@pytest.mark.asyncio
async def test_verify_jwt_accepts_audience_list(backend, rsa_keypair, monkeypatch):
    key, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    token = _make_token(key, KID, _base_claims(aud=AUDIENCE))
    claims = await backend._verify_jwt(
        token,
        audience=["other-client", AUDIENCE],
        issuer=[ISSUER, "https://alt-issuer.example.com"],
        jwks_url=JWKS_URL,
    )
    assert claims["aud"] == AUDIENCE


# ---------------------------------------------------------------------------
# _require_verified_email
# ---------------------------------------------------------------------------
def test_require_verified_email_missing(backend):
    with pytest.raises(InvalidAuth) as exc:
        backend._require_verified_email({})
    assert "email_unverified" in str(exc.value)


def test_require_verified_email_false(backend):
    with pytest.raises(InvalidAuth):
        backend._require_verified_email({"email": "a@b.com", "email_verified": False})
    with pytest.raises(InvalidAuth):
        backend._require_verified_email({"email": "a@b.com", "email_verified": "false"})


def test_require_verified_email_ok(backend):
    email = backend._require_verified_email({"email": "a@b.com", "email_verified": True})
    assert email == "a@b.com"
    email = backend._require_verified_email({"email": "a@b.com", "email_verified": "true"})
    assert email == "a@b.com"


# ---------------------------------------------------------------------------
# jwksutils explicit jwks_url + reason codes constant
# ---------------------------------------------------------------------------
def test_jwksutils_get_jwks_with_explicit_url(rsa_keypair, monkeypatch):
    _, jwk = rsa_keypair
    _mock_jwks(monkeypatch, jwk)
    doc = jwksutils.get_jwks(jwks_url=JWKS_URL)
    assert doc["keys"][0]["kid"] == KID


def test_exchange_reasons_constant_has_expected_codes():
    for code in ("bad_signature", "wrong_audience", "wrong_issuer", "expired", "email_unverified"):
        assert code in EXCHANGE_REASONS
