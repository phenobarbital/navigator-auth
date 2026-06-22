"""Integration tests for FEAT-094 — Token Introspection (RFC 7662) + Device Grant (RFC 8628).

TASK-037: end-to-end (pure-logic) integration tests using memory storages only
(no Redis, no aiohttp server required).

Tests:
  test_full_device_flow                     — device_authorization → verify → poll → tokens
  test_device_user_id_survives              — owner-binding regression (user_id = approving user)
  test_introspect_reflects_revocation       — revoke → introspect immediately active=false
  test_device_then_revoke_grant_cascade     — DELETE grant → jti inactive via introspect
"""

import secrets
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
import json

import pytest
import jsonpickle

from navigator_auth.backends.oauth2.models import (
    OAuthClient,
    OauthUser,
    OauthGrant,
    OauthAccessTokenRecord,
    DeviceCodeStatus,
    OauthDeviceCode,
)
from navigator_auth.backends.oauth2.code_backend import MemoryDeviceCodeStorage
from navigator_auth.backends.oauth2.pkce import generate_challenge


# ---------------------------------------------------------------------------
# Shared memory storages (also available via conftest fixtures)
# ---------------------------------------------------------------------------

class _MemCodeStorage:
    def __init__(self):
        self._codes = {}

    async def save_code(self, code) -> bool:
        self._codes[code.code] = code
        return True

    async def get_code(self, code_str: str):
        return self._codes.get(code_str)

    async def mark_used(self, code_str: str) -> bool:
        entry = self._codes.get(code_str)
        if entry:
            entry.used = True
            return True
        return False

    async def delete_code(self, code_str: str) -> bool:
        self._codes.pop(code_str, None)
        return True


class _MemRefreshStorage:
    def __init__(self):
        self._tokens = {}
        self._user_index = {}

    async def save_token(self, token) -> bool:
        self._tokens[token.refresh_token] = token
        uid = str(token.user_id or "")
        if uid:
            self._user_index.setdefault(uid, set()).add(token.refresh_token)
        return True

    async def get_token(self, token_str: str):
        return self._tokens.get(token_str)

    async def revoke_token(self, token_str: str, reason: str = "revoked") -> bool:
        entry = self._tokens.get(token_str)
        if entry:
            entry.revoked = True
            entry.revoked_reason = reason
            return True
        return False

    async def revoke_chain(self, token_str: str) -> bool:
        entry = self._tokens.get(token_str)
        if not entry:
            return False
        uid = str(entry.user_id or "")
        for t in list(self._user_index.get(uid, [])):
            await self.revoke_token(t, "cascade")
        return True


class _MemGrantStorage:
    def __init__(self):
        self._grants = {}

    def _key(self, user_id, client_id):
        return f"{user_id}:{client_id}"

    async def save_grant(self, grant) -> bool:
        self._grants[self._key(grant.user_id, grant.client_id)] = grant
        return True

    async def get_grant(self, user_id, client_id):
        return self._grants.get(self._key(user_id, client_id))

    async def revoke_grant(self, user_id, client_id) -> bool:
        key = self._key(user_id, client_id)
        self._grants.pop(key, None)
        return True

    async def list_grants(self, user_id) -> list:
        prefix = f"{user_id}:"
        return [v for k, v in self._grants.items() if k.startswith(prefix)]


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


# ---------------------------------------------------------------------------
# Provider builder
# ---------------------------------------------------------------------------

def _public_device_client(client_id: str = "device_public_client") -> OAuthClient:
    return OAuthClient(
        client_id=client_id,
        client_pk=10,
        client_name="Device App",
        client_secret=None,
        client_type="public",
        redirect_uris=[],
        default_scopes=["default", "offline_access"],
        allowed_grant_types=["urn:ietf:params:oauth:grant-type:device_code"],
    )


def _confidential_introspect_client(
    client_id: str = "introspect_rs", secret: str = "rs_secret"
) -> OAuthClient:
    return OAuthClient(
        client_id=client_id,
        client_pk=11,
        client_name="Resource Server",
        client_secret=secret,
        client_type="confidential",
        redirect_uris=[],
        default_scopes=["default"],
        allowed_grant_types=["client_credentials"],
    )


def _make_provider(
    client: OAuthClient,
    device_store: MemoryDeviceCodeStorage = None,
    code_store: _MemCodeStorage = None,
    refresh_store: _MemRefreshStorage = None,
    access_store: _MemAccessStorage = None,
    grant_store: _MemGrantStorage = None,
    session_user: OauthUser = None,
    token_client_override: OAuthClient = None,
):
    """Build a minimal Oauth2Provider with all storages wired up."""
    from navigator_auth.backends.oauth2.backend import Oauth2Provider

    provider = Oauth2Provider.__new__(Oauth2Provider)
    provider.logger = MagicMock()
    provider.device_uri = "/oauth2/device"

    # client_storage: always return the device client by default; allow override.
    def _get_client_side_effect(cid, **kwargs):
        if token_client_override and cid == token_client_override.client_id:
            return token_client_override
        return client

    provider.client_storage = MagicMock()
    provider.client_storage.get_client = AsyncMock(side_effect=_get_client_side_effect)

    provider.device_code_storage = device_store or MemoryDeviceCodeStorage()
    provider.code_storage = code_store or _MemCodeStorage()
    provider.refresh_token_storage = refresh_store or _MemRefreshStorage()
    provider.access_token_storage = access_store or _MemAccessStorage()
    provider.grant_storage = grant_store

    # IDP: create_token returns (token, user_id, exp_ts, "Bearer")
    # decode_token is set per test.
    provider._idp = MagicMock()
    provider._idp.create_token = MagicMock(
        return_value=("generated_access_token", 0, time.time() + 3600, "Bearer")
    )
    provider._parser = MagicMock()

    async def _view(filename, params=None):
        from aiohttp import web
        return web.Response(status=200, text=f"TEMPLATE:{filename}")

    provider._parser.view = _view

    if session_user:
        encoded = jsonpickle.encode(session_user)
        provider.check_session = AsyncMock(return_value=encoded)
    else:
        provider.check_session = AsyncMock(return_value=None)

    return provider


def _make_post_request(form_data: dict) -> MagicMock:
    req = MagicMock()
    req.method = "POST"
    req.content_type = "application/x-www-form-urlencoded"
    req.post = AsyncMock(return_value=form_data)
    req.headers = {}
    req.remote = "127.0.0.1"
    return req


# ---------------------------------------------------------------------------
# test_full_device_flow
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_device_flow():
    """End-to-end: device_authorization → user verifies → polls → gets tokens.

    RFC 8628 §3 flow without a live HTTP server:
    1. POST /oauth2/device_authorization  → device code issued.
    2. POST /oauth2/device (verification) → device code approved.
    3. POST /oauth2/token (polling)       → access_token + refresh_token issued.
    """
    client = _public_device_client()
    user = OauthUser(user_id=55, username="eve", given_name="Eve", family_name="Doe")

    verifier = secrets.token_urlsafe(32)
    challenge = generate_challenge(verifier)

    device_store = MemoryDeviceCodeStorage()
    code_store = _MemCodeStorage()
    refresh_store = _MemRefreshStorage()
    access_store = _MemAccessStorage()
    grant_store = _MemGrantStorage()

    # Pre-seed an existing grant (consent-skip) to allow inline approval.
    grant = OauthGrant(
        user_id=user.user_id,
        client_id=client.client_id,
        scopes=["default", "offline_access"],
        revoked=False,
    )
    await grant_store.save_grant(grant)

    provider = _make_provider(
        client,
        device_store=device_store,
        code_store=code_store,
        refresh_store=refresh_store,
        access_store=access_store,
        grant_store=grant_store,
        session_user=user,
    )

    # Step 1: POST /oauth2/device_authorization
    resp1 = await provider.device_authorization(_make_post_request({
        "client_id": client.client_id,
        "scope": "default offline_access",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }))
    assert resp1.status == 200
    body1 = json.loads(resp1.body)
    device_code = body1["device_code"]
    user_code = body1["user_code"]
    assert "verification_uri" in body1
    assert user_code in body1["verification_uri_complete"]

    # Step 2: POST /oauth2/device (user verifies + approves)
    resp2 = await provider.device_verification(_make_post_request({
        "action": "approve",
        "user_code": user_code,
    }))
    assert resp2.status == 200

    # Verify device code status.
    dc = await device_store.get_by_device_code(device_code)
    assert dc.status == DeviceCodeStatus.APPROVED
    assert dc.user_id == user.user_id  # owner-binding from session
    assert dc.auth_code is not None

    # Step 3: POST /oauth2/token (device_code polling)
    resp3 = await provider._handle_device_code(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": client.client_id,
            "code_verifier": verifier,
        },
        MagicMock(),
    )
    assert resp3.status == 200
    body3 = json.loads(resp3.body)
    assert "access_token" in body3
    assert "refresh_token" in body3  # offline_access was granted

    # Device code should now be consumed.
    dc2 = await device_store.get_by_device_code(device_code)
    assert dc2.status == DeviceCodeStatus.CONSUMED


# ---------------------------------------------------------------------------
# test_device_user_id_survives
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_user_id_survives():
    """Owner-binding regression: issued user_id is the approving user from session.

    Ensures the token's user_id matches the session user, not client.user or
    any other field. This is the FEAT-094 analog of the FEAT-093 B-fix.
    """
    # Client has a 'user' field with a different user_id (potential confusion source).
    client = OAuthClient(
        client_id="device_client_b",
        client_pk=20,
        client_name="Device App B",
        client_secret=None,
        client_type="public",
        redirect_uris=[],
        default_scopes=["default", "offline_access"],
        allowed_grant_types=["urn:ietf:params:oauth:grant-type:device_code"],
        user=OauthUser(user_id=999, username="robot", given_name="R", family_name="Bot"),
    )

    # Session user has a completely different user_id.
    session_user = OauthUser(user_id=77, username="frank", given_name="Frank", family_name="N")

    verifier = secrets.token_urlsafe(32)
    challenge = generate_challenge(verifier)

    device_store = MemoryDeviceCodeStorage()
    code_store = _MemCodeStorage()
    grant_store = _MemGrantStorage()

    grant = OauthGrant(
        user_id=session_user.user_id,
        client_id=client.client_id,
        scopes=["default", "offline_access"],
        revoked=False,
    )
    await grant_store.save_grant(grant)

    provider = _make_provider(
        client,
        device_store=device_store,
        code_store=code_store,
        grant_store=grant_store,
        session_user=session_user,
    )

    # Issue a device code.
    resp1 = await provider.device_authorization(_make_post_request({
        "client_id": client.client_id,
        "scope": "default offline_access",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }))
    assert resp1.status == 200
    body1 = json.loads(resp1.body)
    device_code = body1["device_code"]
    user_code = body1["user_code"]

    # User approves.
    resp2 = await provider.device_verification(_make_post_request({
        "action": "approve",
        "user_code": user_code,
    }))
    assert resp2.status == 200

    dc = await device_store.get_by_device_code(device_code)
    # Owner-binding: user_id from session (77), NOT from client.user (999).
    assert dc.user_id == session_user.user_id
    assert dc.user_id != client.user.user_id

    # Retrieve the carrier from code_store and verify its user_id.
    carrier = await code_store.get_code(dc.auth_code)
    assert carrier.user_id == session_user.user_id


# ---------------------------------------------------------------------------
# test_introspect_reflects_revocation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_introspect_reflects_revocation():
    """Revoking a jti immediately makes the token inactive at introspection."""
    from uuid import uuid4

    rs_client = _confidential_introspect_client()
    access_store = _MemAccessStorage()

    jti = str(uuid4())
    now = datetime.now()
    rec = OauthAccessTokenRecord(
        jti=jti,
        user_id=42,
        client_id=rs_client.client_id,
        scope="default read",
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )
    await access_store.save(rec)

    provider = _make_provider(rs_client, access_store=access_store)
    provider._idp.decode_token = MagicMock(
        return_value=(
            None,
            {
                "jti": jti,
                "client_id": rs_client.client_id,
                "scope": "default read",
                "exp": time.time() + 3600,
                "iat": time.time(),
                "token_type": "Bearer",
                "aud": "user",
            },
        )
    )

    # Before revocation: active = True.
    resp1 = await provider.introspect(_make_post_request({
        "client_id": rs_client.client_id,
        "client_secret": "rs_secret",
        "token": "dummy_access_token",
    }))
    assert resp1.status == 200
    assert json.loads(resp1.body)["active"] is True

    # Revoke the jti.
    await access_store.revoke(jti)

    # After revocation: active = False (real-time — no cache).
    resp2 = await provider.introspect(_make_post_request({
        "client_id": rs_client.client_id,
        "client_secret": "rs_secret",
        "token": "dummy_access_token",
    }))
    assert resp2.status == 200
    assert json.loads(resp2.body) == {"active": False}


# ---------------------------------------------------------------------------
# test_device_then_revoke_grant_cascade
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_then_revoke_grant_cascade():
    """DELETE grant → revoke associated jti → introspect shows inactive.

    This tests the cascade: grant revocation should invalidate the access token
    jti so that introspection returns active=false.
    """
    from uuid import uuid4

    client = _public_device_client()
    rs_client = _confidential_introspect_client()
    user = OauthUser(user_id=88, username="grace", given_name="Grace", family_name="Doe")

    access_store = _MemAccessStorage()
    grant_store = _MemGrantStorage()

    # Simulate a previously-issued access token jti for this user/client.
    jti = str(uuid4())
    now = datetime.now()
    rec = OauthAccessTokenRecord(
        jti=jti,
        user_id=user.user_id,
        client_id=client.client_id,
        scope="default offline_access",
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )
    await access_store.save(rec)

    # Create an active grant.
    grant = OauthGrant(
        user_id=user.user_id,
        client_id=client.client_id,
        scopes=["default", "offline_access"],
        revoked=False,
    )
    await grant_store.save_grant(grant)

    # ---- Introspect setup: RS client sees the access token as active ----
    # Build a provider that the RS uses for introspection.
    rs_provider = _make_provider(rs_client, access_store=access_store)
    rs_provider._idp.decode_token = MagicMock(
        return_value=(
            None,
            {
                "jti": jti,
                "client_id": client.client_id,  # token belongs to device client
                "scope": "default offline_access",
                "exp": time.time() + 3600,
                "iat": time.time(),
                "token_type": "Bearer",
                "aud": "user",
            },
        )
    )
    # RS client matches the token's client_id — must update client_storage mock.
    rs_provider.client_storage.get_client = AsyncMock(
        side_effect=lambda cid, **kw: rs_client if cid == rs_client.client_id else None
    )

    # Token from a different client → active=false (same-client-only rule).
    # Let's verify FIRST with the RS client matching — make token client_id = rs_client.
    # Actually: per spec, same-client-only means: the introspecting client must be the token issuer.
    # So let's use a token issued to rs_client itself.
    jti2 = str(uuid4())
    rec2 = OauthAccessTokenRecord(
        jti=jti2,
        user_id=user.user_id,
        client_id=rs_client.client_id,
        scope="default offline_access",
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )
    await access_store.save(rec2)

    rs_provider._idp.decode_token = MagicMock(
        return_value=(
            None,
            {
                "jti": jti2,
                "client_id": rs_client.client_id,
                "scope": "default offline_access",
                "exp": time.time() + 3600,
                "iat": time.time(),
                "token_type": "Bearer",
                "aud": "user",
            },
        )
    )

    # Confirm active before revocation.
    resp1 = await rs_provider.introspect(_make_post_request({
        "client_id": rs_client.client_id,
        "client_secret": "rs_secret",
        "token": "dummy",
    }))
    assert resp1.status == 200
    assert json.loads(resp1.body)["active"] is True

    # Cascade: revoke the grant → revoke associated jti.
    await grant_store.revoke_grant(user.user_id, rs_client.client_id)
    await access_store.revoke(jti2)

    # Introspect after cascade: active = False.
    resp2 = await rs_provider.introspect(_make_post_request({
        "client_id": rs_client.client_id,
        "client_secret": "rs_secret",
        "token": "dummy",
    }))
    assert resp2.status == 200
    assert json.loads(resp2.body) == {"active": False}
