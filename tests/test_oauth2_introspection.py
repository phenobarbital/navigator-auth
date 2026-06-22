"""Unit tests for FEAT-094 TASK-033 — POST /oauth2/introspect (RFC 7662).

Tests:
  test_introspect_active_access_token      — valid access token (own client) → active:true
  test_introspect_revoked_jti_inactive     — revoked jti → {"active": false}
  test_introspect_refresh_token            — active refresh → active; rotated → inactive
  test_introspect_foreign_client_inactive  — token issued to B, introspected by A → inactive
  test_introspect_requires_client_auth     — unauthenticated/bad secret → 401; missing token → 400
"""

import asyncio
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from navigator_auth.backends.oauth2.models import (
    OAuthClient,
    OauthUser,
    OauthAccessTokenRecord,
    OauthRefreshToken,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _confidential_client(client_id: str = "rs_client", secret: str = "s3cr3t") -> OAuthClient:
    return OAuthClient(
        client_id=client_id,
        client_pk=10,
        client_name="Resource Server",
        client_secret=secret,
        client_type="confidential",
        redirect_uris=[],
        default_scopes=["default", "read"],
        allowed_grant_types=["client_credentials"],
    )


def _public_client(client_id: str = "app_client") -> OAuthClient:
    return OAuthClient(
        client_id=client_id,
        client_pk=20,
        client_name="App",
        client_secret=None,
        client_type="public",
        redirect_uris=["https://app.example.com/cb"],
        default_scopes=["default"],
        allowed_grant_types=["authorization_code"],
    )


def _make_provider(
    caller_client: OAuthClient,
    access_token_storage=None,
    refresh_token_storage=None,
    user=None,
):
    """Build a minimal Oauth2Provider with mocked storage and IDP."""
    from navigator_auth.backends.oauth2.backend import Oauth2Provider

    provider = Oauth2Provider.__new__(Oauth2Provider)
    provider.logger = MagicMock()

    # Storage mocks
    provider.client_storage = MagicMock()
    provider.client_storage.get_client = AsyncMock(return_value=caller_client)
    provider.access_token_storage = access_token_storage or MagicMock()
    provider.refresh_token_storage = refresh_token_storage or MagicMock()
    provider.device_code_storage = MagicMock()
    provider.grant_storage = MagicMock()
    provider.code_storage = MagicMock()

    # IDP mock
    provider._idp = MagicMock()
    if user:
        provider._idp.user_from_id = AsyncMock(return_value=user)
    else:
        provider._idp.user_from_id = AsyncMock(return_value=None)

    return provider


def _make_request(form_data: dict) -> MagicMock:
    """Minimal aiohttp request mock with form data payload."""
    request = MagicMock()
    request.method = "POST"
    request.content_type = "application/x-www-form-urlencoded"
    request.post = AsyncMock(return_value=form_data)
    request.headers = {}
    return request


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _now() -> datetime:
    return datetime.now()


# ---------------------------------------------------------------------------
# In-memory storage stubs
# ---------------------------------------------------------------------------

class _MemAccessStorage:
    def __init__(self):
        self._records = {}
        self._revoked = set()

    async def save(self, rec) -> bool:
        self._records[str(rec.jti)] = rec
        return True

    async def get(self, jti: str):
        return self._records.get(str(jti))

    async def revoke(self, jti: str) -> bool:
        self._revoked.add(str(jti))
        return True

    async def is_revoked(self, jti: str) -> bool:
        return str(jti) in self._revoked


class _MemRefreshStorage:
    def __init__(self):
        self._tokens = {}

    async def save_token(self, token) -> bool:
        self._tokens[token.refresh_token] = token
        return True

    async def get_token(self, token_str: str):
        return self._tokens.get(token_str)

    async def revoke_token(self, token_str: str, reason: str = "revoked") -> bool:
        t = self._tokens.get(token_str)
        if t:
            t.revoked = True
            t.revoked_reason = reason
            return True
        return False


# ---------------------------------------------------------------------------
# Fixtures for RFC 7662 claims (payload builder helper)
# ---------------------------------------------------------------------------

def _jwt_payload(
    jti: str,
    client_id: str,
    scope: str = "default read",
    exp_offset: int = 3600,
    user_id: int = None,
    iat_offset: int = 0,
    token_type: str = "Bearer",
) -> dict:
    now_ts = _now_utc().timestamp()
    payload = {
        "jti": jti,
        "client_id": client_id,
        "scope": scope,
        "exp": now_ts + exp_offset,
        "iat": now_ts - iat_offset,
        "token_type": token_type,
        "aud": "user",
    }
    if user_id is not None:
        payload["user_id"] = user_id
    return payload


# ---------------------------------------------------------------------------
# test_introspect_requires_client_auth
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_introspect_missing_token_returns_400():
    """Missing token parameter → 400 invalid_request."""
    client = _confidential_client()
    provider = _make_provider(client)
    request = _make_request({"client_id": "rs_client", "client_secret": "s3cr3t"})
    # No 'token' key.
    resp = await provider.introspect(request)
    assert resp.status == 400
    import json
    body = json.loads(resp.body)
    assert body["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_introspect_bad_secret_returns_401():
    """Bad client_secret → 401 invalid_client with WWW-Authenticate."""
    client = _confidential_client(secret="correct")
    provider = _make_provider(client)
    request = _make_request({
        "client_id": "rs_client",
        "client_secret": "wrong",
        "token": "sometoken",
    })
    resp = await provider.introspect(request)
    assert resp.status == 401
    assert "WWW-Authenticate" in resp.headers


@pytest.mark.asyncio
async def test_introspect_public_client_returns_401():
    """Public client (no secret) as caller → 401 invalid_client."""
    pub = _public_client()
    provider = _make_provider(pub)
    request = _make_request({
        "client_id": "app_client",
        "client_secret": "",
        "token": "sometoken",
    })
    resp = await provider.introspect(request)
    assert resp.status == 401


# ---------------------------------------------------------------------------
# test_introspect_active_access_token
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_introspect_active_access_token():
    """Valid access token (own client) → active:true + RFC 7662 claims."""
    jti = str(uuid4())
    client = _confidential_client()
    access_store = _MemAccessStorage()
    rec = OauthAccessTokenRecord(
        jti=jti,
        user_id=42,
        client_id=client.client_id,
        scope="default read",
        issued_at=_now(),
        expires_at=_now() + timedelta(hours=1),
    )
    await access_store.save(rec)

    jwt_payload = _jwt_payload(jti, client.client_id, user_id=42)
    provider = _make_provider(client, access_token_storage=access_store)
    provider._idp.decode_token = MagicMock(return_value=(None, jwt_payload))

    request = _make_request({
        "client_id": client.client_id,
        "client_secret": "s3cr3t",
        "token": "dummy_access_token",
    })
    resp = await provider.introspect(request)
    assert resp.status == 200
    import json
    body = json.loads(resp.body)
    assert body["active"] is True
    assert body["client_id"] == client.client_id
    assert "scope" in body
    assert "exp" in body
    assert "iat" in body


# ---------------------------------------------------------------------------
# test_introspect_revoked_jti_inactive
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_introspect_revoked_jti_inactive():
    """Revoked jti → {"active": false} (real-time, no cache)."""
    jti = str(uuid4())
    client = _confidential_client()
    access_store = _MemAccessStorage()
    rec = OauthAccessTokenRecord(
        jti=jti,
        user_id=42,
        client_id=client.client_id,
        scope="default",
        issued_at=_now(),
        expires_at=_now() + timedelta(hours=1),
    )
    await access_store.save(rec)
    # Revoke immediately.
    await access_store.revoke(jti)

    jwt_payload = _jwt_payload(jti, client.client_id)
    provider = _make_provider(client, access_token_storage=access_store)
    provider._idp.decode_token = MagicMock(return_value=(None, jwt_payload))

    request = _make_request({
        "client_id": client.client_id,
        "client_secret": "s3cr3t",
        "token": "dummy_access_token",
    })
    resp = await provider.introspect(request)
    assert resp.status == 200
    import json
    body = json.loads(resp.body)
    assert body == {"active": False}


# ---------------------------------------------------------------------------
# test_introspect_refresh_token
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_introspect_active_refresh_token():
    """Active refresh token (own client) → active:true."""
    client = _confidential_client()
    rt_value = secrets.token_urlsafe(40)
    refresh_store = _MemRefreshStorage()
    rt = OauthRefreshToken(
        client=client,
        user_id=42,
        refresh_token=rt_value,
        scope="default offline_access",
        issued_at=_now(),
        expires_at=_now() + timedelta(days=30),
        absolute_expires_at=_now() + timedelta(days=90),
    )
    await refresh_store.save_token(rt)

    # decode_token returns token_type=refresh_token so the branch picks refresh.
    jwt_payload = _jwt_payload("jti-irrelevant", client.client_id, token_type="refresh_token")
    provider = _make_provider(client, refresh_token_storage=refresh_store)
    provider._idp.decode_token = MagicMock(return_value=(None, jwt_payload))

    request = _make_request({
        "client_id": client.client_id,
        "client_secret": "s3cr3t",
        "token": rt_value,
        "token_type_hint": "refresh_token",
    })
    resp = await provider.introspect(request)
    assert resp.status == 200
    import json
    body = json.loads(resp.body)
    assert body["active"] is True


@pytest.mark.asyncio
async def test_introspect_revoked_refresh_token_inactive():
    """Rotated/revoked refresh token → {"active": false}."""
    client = _confidential_client()
    rt_value = secrets.token_urlsafe(40)
    refresh_store = _MemRefreshStorage()
    rt = OauthRefreshToken(
        client=client,
        user_id=42,
        refresh_token=rt_value,
        scope="default offline_access",
        issued_at=_now(),
        expires_at=_now() + timedelta(days=30),
        absolute_expires_at=_now() + timedelta(days=90),
    )
    await refresh_store.save_token(rt)
    await refresh_store.revoke_token(rt_value, "rotated")

    jwt_payload = _jwt_payload("jti-irrelevant", client.client_id, token_type="refresh_token")
    provider = _make_provider(client, refresh_token_storage=refresh_store)
    provider._idp.decode_token = MagicMock(return_value=(None, jwt_payload))

    request = _make_request({
        "client_id": client.client_id,
        "client_secret": "s3cr3t",
        "token": rt_value,
        "token_type_hint": "refresh_token",
    })
    resp = await provider.introspect(request)
    assert resp.status == 200
    import json
    body = json.loads(resp.body)
    assert body == {"active": False}


# ---------------------------------------------------------------------------
# test_introspect_foreign_client_inactive
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_introspect_foreign_client_inactive():
    """Token issued to client B, introspected by client A → {"active": false}."""
    client_a = _confidential_client(client_id="client_a", secret="secret_a")
    access_store = _MemAccessStorage()
    jti = str(uuid4())
    rec = OauthAccessTokenRecord(
        jti=jti,
        user_id=42,
        client_id="client_b",     # token belongs to client_b
        scope="default",
        issued_at=_now(),
        expires_at=_now() + timedelta(hours=1),
    )
    await access_store.save(rec)

    # JWT payload says client_id = client_b.
    jwt_payload = _jwt_payload(jti, "client_b")
    provider = _make_provider(client_a, access_token_storage=access_store)
    provider._idp.decode_token = MagicMock(return_value=(None, jwt_payload))

    request = _make_request({
        "client_id": "client_a",
        "client_secret": "secret_a",
        "token": "dummy_token",
    })
    resp = await provider.introspect(request)
    assert resp.status == 200
    import json
    body = json.loads(resp.body)
    assert body == {"active": False}


# ---------------------------------------------------------------------------
# test_introspect_expired_token_inactive
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_introspect_expired_token_inactive():
    """Expired access token (exp in the past) → {"active": false}."""
    jti = str(uuid4())
    client = _confidential_client()
    access_store = _MemAccessStorage()
    rec = OauthAccessTokenRecord(
        jti=jti,
        user_id=42,
        client_id=client.client_id,
        scope="default",
        issued_at=_now() - timedelta(hours=2),
        expires_at=_now() - timedelta(hours=1),  # expired
    )
    await access_store.save(rec)

    # exp in the past
    jwt_payload = _jwt_payload(jti, client.client_id, exp_offset=-1)
    provider = _make_provider(client, access_token_storage=access_store)
    provider._idp.decode_token = MagicMock(return_value=(None, jwt_payload))

    request = _make_request({
        "client_id": client.client_id,
        "client_secret": "s3cr3t",
        "token": "expired_token",
    })
    resp = await provider.introspect(request)
    assert resp.status == 200
    import json
    body = json.loads(resp.body)
    assert body == {"active": False}


# ---------------------------------------------------------------------------
# test_introspect_unknown_token_inactive
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_introspect_unknown_token_inactive():
    """Unparseable / unknown token → {"active": false} — no info leakage."""
    client = _confidential_client()
    provider = _make_provider(client)
    # decode_token raises (bad JWT signature etc.)
    provider._idp.decode_token = MagicMock(side_effect=Exception("bad token"))

    request = _make_request({
        "client_id": client.client_id,
        "client_secret": "s3cr3t",
        "token": "garbage",
    })
    resp = await provider.introspect(request)
    assert resp.status == 200
    import json
    body = json.loads(resp.body)
    assert body == {"active": False}
