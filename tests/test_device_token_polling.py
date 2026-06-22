"""Unit tests for FEAT-094 TASK-036 — device_code grant polling (RFC 8628 §3.4-3.5).

Tests:
  test_device_poll_slow_down            — polling too fast → slow_down + interval bump
  test_device_poll_pending              — PENDING state → authorization_pending
  test_device_poll_denied               — DENIED state → access_denied
  test_device_poll_expired              — expired device code → expired_token
  test_device_poll_success_single_use   — approved + valid PKCE → token; second poll → expired
  test_device_no_offline_access_no_refresh — approved without offline_access → no refresh_token
  test_device_pkce_verify_fails         — bad code_verifier → invalid_grant
  test_device_poll_missing_device_code  — missing device_code → 400 invalid_request
  test_device_poll_unknown_device_code  — unknown device_code → 400 expired_token
"""

import secrets
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
import json

import pytest

from navigator_auth.backends.oauth2.models import (
    OAuthClient,
    OauthAuthorizationCode,
    OauthUser,
    DeviceCodeStatus,
    OauthDeviceCode,
)
from navigator_auth.backends.oauth2.code_backend import MemoryDeviceCodeStorage
from navigator_auth.backends.oauth2.pkce import generate_challenge


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _public_client(client_id: str = "device_client") -> OAuthClient:
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


def _make_dc(
    client_id: str = "device_client",
    status: DeviceCodeStatus = DeviceCodeStatus.PENDING,
    interval: int = 5,
    last_polled_at: datetime = None,
    expires_offset: int = 600,
    code_challenge: str = None,
    code_challenge_method: str = None,
    auth_code: str = None,
) -> OauthDeviceCode:
    now = datetime.now()
    return OauthDeviceCode(
        device_code=secrets.token_urlsafe(32),
        user_code="BCDFBCDF",
        client_id=client_id,
        scopes=["default", "offline_access"],
        status=status,
        interval=interval,
        last_polled_at=last_polled_at,
        issued_at=now,
        expires_at=now + timedelta(seconds=expires_offset),
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        auth_code=auth_code,
    )


def _make_auth_code_carrier(
    client: OAuthClient,
    user_id: int,
    auth_code_str: str,
    scope: str = "default offline_access",
    code_challenge: str = None,
    code_challenge_method: str = None,
) -> OauthAuthorizationCode:
    now = datetime.now()
    return OauthAuthorizationCode(
        client=client,
        user_id=user_id,
        code=auth_code_str,
        redirect_uri="",
        response_type="device_code",
        scope=scope,
        state="",
        expires_at=now + timedelta(minutes=5),
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )


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

    async def save_token(self, token) -> bool:
        self._tokens[token.refresh_token] = token
        return True

    async def get_token(self, token_str: str):
        return self._tokens.get(token_str)


class _MemAccessStorage:
    def __init__(self):
        self._records = {}

    async def save(self, rec) -> bool:
        self._records[str(rec.jti)] = rec
        return True


def _make_provider(
    client: OAuthClient,
    device_store: MemoryDeviceCodeStorage = None,
    code_store: _MemCodeStorage = None,
    refresh_store: _MemRefreshStorage = None,
    access_store: _MemAccessStorage = None,
):
    """Build a minimal Oauth2Provider with mocked dependencies."""
    from navigator_auth.backends.oauth2.backend import Oauth2Provider

    provider = Oauth2Provider.__new__(Oauth2Provider)
    provider.logger = MagicMock()

    provider.client_storage = MagicMock()
    provider.client_storage.get_client = AsyncMock(return_value=client)

    provider.device_code_storage = device_store or MemoryDeviceCodeStorage()
    provider.code_storage = code_store or _MemCodeStorage()
    provider.refresh_token_storage = refresh_store or _MemRefreshStorage()
    provider.access_token_storage = access_store or _MemAccessStorage()
    provider.grant_storage = None

    # Mock IDP: create_token returns (access_token_str, user_id, exp_ts, "Bearer")
    import time
    provider._idp = MagicMock()
    provider._idp.create_token = MagicMock(
        return_value=("mock_access_token", 42, time.time() + 3600, "Bearer")
    )

    return provider


def _make_post_request(form_data: dict) -> MagicMock:
    request = MagicMock()
    request.method = "POST"
    request.content_type = "application/x-www-form-urlencoded"
    request.post = AsyncMock(return_value=form_data)
    request.headers = {}
    return request


# ---------------------------------------------------------------------------
# test_device_poll_slow_down
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_poll_slow_down():
    """Polling faster than interval → slow_down + server-side interval bump."""
    client = _public_client()
    dc = _make_dc(
        status=DeviceCodeStatus.PENDING,
        interval=5,
        # last_polled_at = 2 seconds ago → too soon for interval=5
        last_polled_at=datetime.now() - timedelta(seconds=2),
    )
    store = MemoryDeviceCodeStorage()
    await store.save(dc)

    provider = _make_provider(client, device_store=store)
    request = _make_post_request({
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": dc.device_code,
        "client_id": client.client_id,
    })
    resp = await provider._handle_device_code(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": dc.device_code,
            "client_id": client.client_id,
        },
        request,
    )
    assert resp.status == 400
    body = json.loads(resp.body)
    assert body["error"] == "slow_down"
    assert "interval" in body
    assert body["interval"] > 5  # bumped

    # Verify the device record was updated.
    updated_dc = await store.get_by_device_code(dc.device_code)
    assert updated_dc.interval > 5


# ---------------------------------------------------------------------------
# test_device_poll_pending
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_poll_pending():
    """PENDING + sufficient interval elapsed → authorization_pending."""
    client = _public_client()
    dc = _make_dc(
        status=DeviceCodeStatus.PENDING,
        interval=5,
        # No last_polled_at → first poll
    )
    store = MemoryDeviceCodeStorage()
    await store.save(dc)

    provider = _make_provider(client, device_store=store)
    resp = await provider._handle_device_code(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": dc.device_code,
            "client_id": client.client_id,
        },
        MagicMock(),
    )
    assert resp.status == 400
    body = json.loads(resp.body)
    assert body["error"] == "authorization_pending"


# ---------------------------------------------------------------------------
# test_device_poll_denied
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_poll_denied():
    """DENIED state → access_denied."""
    client = _public_client()
    dc = _make_dc(status=DeviceCodeStatus.DENIED)
    store = MemoryDeviceCodeStorage()
    await store.save(dc)

    provider = _make_provider(client, device_store=store)
    resp = await provider._handle_device_code(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": dc.device_code,
            "client_id": client.client_id,
        },
        MagicMock(),
    )
    assert resp.status == 400
    body = json.loads(resp.body)
    assert body["error"] == "access_denied"


# ---------------------------------------------------------------------------
# test_device_poll_expired
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_poll_expired():
    """Expired device code → expired_token."""
    client = _public_client()
    dc = _make_dc(status=DeviceCodeStatus.PENDING, expires_offset=-100)  # already expired
    store = MemoryDeviceCodeStorage()
    await store.save(dc)

    provider = _make_provider(client, device_store=store)
    resp = await provider._handle_device_code(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": dc.device_code,
            "client_id": client.client_id,
        },
        MagicMock(),
    )
    assert resp.status == 400
    body = json.loads(resp.body)
    assert body["error"] == "expired_token"


# ---------------------------------------------------------------------------
# test_device_poll_success_single_use
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_poll_success_single_use():
    """Approved + valid PKCE → access token; second poll → consumed/expired."""
    client = _public_client()
    verifier = secrets.token_urlsafe(32)
    challenge = generate_challenge(verifier)

    auth_code_str = secrets.token_urlsafe(32)
    carrier = _make_auth_code_carrier(
        client=client,
        user_id=42,
        auth_code_str=auth_code_str,
        scope="default offline_access",
        code_challenge=challenge,
        code_challenge_method="S256",
    )

    dc = _make_dc(
        status=DeviceCodeStatus.APPROVED,
        code_challenge=challenge,
        code_challenge_method="S256",
        auth_code=auth_code_str,
    )
    device_store = MemoryDeviceCodeStorage()
    await device_store.save(dc)

    code_store = _MemCodeStorage()
    await code_store.save_code(carrier)

    refresh_store = _MemRefreshStorage()
    access_store = _MemAccessStorage()

    provider = _make_provider(
        client,
        device_store=device_store,
        code_store=code_store,
        refresh_store=refresh_store,
        access_store=access_store,
    )

    resp = await provider._handle_device_code(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": dc.device_code,
            "client_id": client.client_id,
            "code_verifier": verifier,
        },
        MagicMock(),
    )
    assert resp.status == 200
    body = json.loads(resp.body)
    assert "access_token" in body
    assert body["access_token"] == "mock_access_token"
    # offline_access present → refresh_token issued
    assert "refresh_token" in body

    # Device code should now be CONSUMED.
    updated_dc = await device_store.get_by_device_code(dc.device_code)
    assert updated_dc.status == DeviceCodeStatus.CONSUMED

    # Second poll: device code is CONSUMED → expired_token.
    resp2 = await provider._handle_device_code(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": dc.device_code,
            "client_id": client.client_id,
            "code_verifier": verifier,
        },
        MagicMock(),
    )
    assert resp2.status == 400
    body2 = json.loads(resp2.body)
    assert body2["error"] == "expired_token"


# ---------------------------------------------------------------------------
# test_device_no_offline_access_no_refresh
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_no_offline_access_no_refresh():
    """Approved without offline_access → no refresh_token in response."""
    client = _public_client()
    verifier = secrets.token_urlsafe(32)
    challenge = generate_challenge(verifier)

    auth_code_str = secrets.token_urlsafe(32)
    carrier = _make_auth_code_carrier(
        client=client,
        user_id=42,
        auth_code_str=auth_code_str,
        scope="default",  # no offline_access
        code_challenge=challenge,
        code_challenge_method="S256",
    )

    dc = _make_dc(
        status=DeviceCodeStatus.APPROVED,
        code_challenge=challenge,
        code_challenge_method="S256",
        auth_code=auth_code_str,
    )
    device_store = MemoryDeviceCodeStorage()
    await device_store.save(dc)

    code_store = _MemCodeStorage()
    await code_store.save_code(carrier)

    provider = _make_provider(client, device_store=device_store, code_store=code_store)
    resp = await provider._handle_device_code(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": dc.device_code,
            "client_id": client.client_id,
            "code_verifier": verifier,
        },
        MagicMock(),
    )
    assert resp.status == 200
    body = json.loads(resp.body)
    assert "access_token" in body
    assert "refresh_token" not in body


# ---------------------------------------------------------------------------
# test_device_pkce_verify_fails
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_pkce_verify_fails():
    """Bad code_verifier → invalid_grant."""
    client = _public_client()
    verifier = secrets.token_urlsafe(32)
    challenge = generate_challenge(verifier)

    auth_code_str = secrets.token_urlsafe(32)
    dc = _make_dc(
        status=DeviceCodeStatus.APPROVED,
        code_challenge=challenge,
        code_challenge_method="S256",
        auth_code=auth_code_str,
    )
    device_store = MemoryDeviceCodeStorage()
    await device_store.save(dc)

    provider = _make_provider(client, device_store=device_store)
    resp = await provider._handle_device_code(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": dc.device_code,
            "client_id": client.client_id,
            "code_verifier": "wrong_verifier_xxxxxxxxxxxx",
        },
        MagicMock(),
    )
    assert resp.status == 400
    body = json.loads(resp.body)
    assert body["error"] == "invalid_grant"


# ---------------------------------------------------------------------------
# test_device_poll_missing_device_code
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_poll_missing_device_code():
    """Missing device_code parameter → 400 invalid_request."""
    client = _public_client()
    provider = _make_provider(client)

    resp = await provider._handle_device_code(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client.client_id,
        },
        MagicMock(),
    )
    assert resp.status == 400
    body = json.loads(resp.body)
    assert body["error"] == "invalid_request"


# ---------------------------------------------------------------------------
# test_device_poll_unknown_device_code
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_poll_unknown_device_code():
    """Unknown device_code → 400 expired_token."""
    client = _public_client()
    store = MemoryDeviceCodeStorage()  # empty
    provider = _make_provider(client, device_store=store)

    resp = await provider._handle_device_code(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": "nonexistent_device_code",
            "client_id": client.client_id,
        },
        MagicMock(),
    )
    assert resp.status == 400
    body = json.loads(resp.body)
    assert body["error"] == "expired_token"
