"""Unit tests for FEAT-094 TASK-034 — POST /oauth2/device_authorization.

Tests:
  test_device_authorization_response    — returns all RFC 8628 fields
  test_device_invalid_scope             — scope outside allow-list → invalid_scope
  test_device_public_requires_pkce      — D4 — public client without code_challenge rejected
"""

import asyncio
import secrets
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
import json

import pytest

from navigator_auth.backends.oauth2.models import OAuthClient, OauthUser
from navigator_auth.backends.oauth2.code_backend import MemoryDeviceCodeStorage


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
        default_scopes=["default", "profile", "offline_access"],
        allowed_grant_types=["urn:ietf:params:oauth:grant-type:device_code"],
    )


def _confidential_client(client_id: str = "device_conf_client") -> OAuthClient:
    return OAuthClient(
        client_id=client_id,
        client_pk=11,
        client_name="Device Confidential App",
        client_secret="conf_secret",
        client_type="confidential",
        redirect_uris=[],
        default_scopes=["default", "offline_access"],
        allowed_grant_types=["urn:ietf:params:oauth:grant-type:device_code"],
    )


def _make_provider(client: OAuthClient, device_store=None):
    """Build a minimal Oauth2Provider with mocked storage."""
    from navigator_auth.backends.oauth2.backend import Oauth2Provider

    provider = Oauth2Provider.__new__(Oauth2Provider)
    provider.logger = MagicMock()
    provider.device_uri = "/oauth2/device"

    provider.client_storage = MagicMock()
    provider.client_storage.get_client = AsyncMock(return_value=client)

    provider.device_code_storage = device_store or MemoryDeviceCodeStorage()

    provider._idp = MagicMock()
    return provider


def _make_post_request(form_data: dict) -> MagicMock:
    request = MagicMock()
    request.method = "POST"
    request.content_type = "application/x-www-form-urlencoded"
    request.post = AsyncMock(return_value=form_data)
    request.headers = {}
    request.url = MagicMock()
    request.url.__str__ = lambda self: "https://auth.example.com/oauth2/device_authorization"
    return request


# ---------------------------------------------------------------------------
# test_device_authorization_response
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_authorization_response_public_client():
    """POST /oauth2/device_authorization returns all RFC 8628 fields."""
    from navigator_auth.backends.oauth2.pkce import generate_challenge

    client = _public_client()
    store = MemoryDeviceCodeStorage()
    provider = _make_provider(client, device_store=store)

    verifier = secrets.token_urlsafe(32)
    challenge = generate_challenge(verifier)

    request = _make_post_request({
        "client_id": client.client_id,
        "scope": "default offline_access",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    resp = await provider.device_authorization(request)
    assert resp.status == 200

    body = json.loads(resp.body)
    assert "device_code" in body
    assert "user_code" in body
    assert "verification_uri" in body
    assert "verification_uri_complete" in body
    assert "expires_in" in body
    assert "interval" in body
    assert body["expires_in"] > 0
    assert body["interval"] > 0
    assert body["user_code"] in body["verification_uri_complete"]

    # user_code persisted
    dc = await store.get_by_device_code(body["device_code"])
    assert dc is not None
    assert dc.status.value == "pending"
    assert "default" in dc.scopes
    assert dc.code_challenge == challenge


@pytest.mark.asyncio
async def test_device_authorization_confidential_client_no_pkce():
    """Confidential client does not require PKCE."""
    client = _confidential_client()
    store = MemoryDeviceCodeStorage()
    provider = _make_provider(client, device_store=store)

    request = _make_post_request({
        "client_id": client.client_id,
        "scope": "default",
    })
    resp = await provider.device_authorization(request)
    assert resp.status == 200

    body = json.loads(resp.body)
    assert "device_code" in body
    assert "user_code" in body


@pytest.mark.asyncio
async def test_device_authorization_scope_filtered():
    """Scope filtered to client allow-list (invalid scopes filtered out)."""
    client = _public_client()  # default_scopes = ["default", "profile", "offline_access"]
    store = MemoryDeviceCodeStorage()
    provider = _make_provider(client, device_store=store)

    from navigator_auth.backends.oauth2.pkce import generate_challenge
    verifier = secrets.token_urlsafe(32)
    challenge = generate_challenge(verifier)

    request = _make_post_request({
        "client_id": client.client_id,
        "scope": "default",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    resp = await provider.device_authorization(request)
    assert resp.status == 200


# ---------------------------------------------------------------------------
# test_device_invalid_scope
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_invalid_scope():
    """Scope outside client allow-list → invalid_scope error."""
    client = _public_client()  # default_scopes = ["default", "profile", "offline_access"]
    provider = _make_provider(client)

    from navigator_auth.backends.oauth2.pkce import generate_challenge
    verifier = secrets.token_urlsafe(32)
    challenge = generate_challenge(verifier)

    request = _make_post_request({
        "client_id": client.client_id,
        "scope": "admin",   # not in allow-list
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    resp = await provider.device_authorization(request)
    assert resp.status == 400
    body = json.loads(resp.body)
    assert body["error"] == "invalid_scope"


@pytest.mark.asyncio
async def test_device_missing_client_id_returns_400():
    """Missing client_id → 400 invalid_request."""
    client = _public_client()
    provider = _make_provider(client)
    request = _make_post_request({})
    resp = await provider.device_authorization(request)
    assert resp.status == 400


# ---------------------------------------------------------------------------
# test_device_public_requires_pkce (D4)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_public_requires_pkce_missing_challenge():
    """D4 — public client without code_challenge → rejected."""
    client = _public_client()
    provider = _make_provider(client)

    request = _make_post_request({
        "client_id": client.client_id,
        "scope": "default",
        # No code_challenge
    })
    resp = await provider.device_authorization(request)
    assert resp.status == 400
    body = json.loads(resp.body)
    assert body["error"] in ("invalid_request", "invalid_grant")


@pytest.mark.asyncio
async def test_device_public_requires_pkce_plain_rejected():
    """D4 — public client with code_challenge_method=plain → rejected."""
    client = _public_client()
    provider = _make_provider(client)

    request = _make_post_request({
        "client_id": client.client_id,
        "scope": "default",
        "code_challenge": "some_challenge",
        "code_challenge_method": "plain",  # not allowed
    })
    resp = await provider.device_authorization(request)
    assert resp.status == 400
    body = json.loads(resp.body)
    assert body["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_device_public_s256_accepted():
    """D4 — public client with S256 challenge → accepted."""
    from navigator_auth.backends.oauth2.pkce import generate_challenge

    client = _public_client()
    store = MemoryDeviceCodeStorage()
    provider = _make_provider(client, device_store=store)

    verifier = secrets.token_urlsafe(32)
    challenge = generate_challenge(verifier)

    request = _make_post_request({
        "client_id": client.client_id,
        "scope": "default",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    resp = await provider.device_authorization(request)
    assert resp.status == 200
    body = json.loads(resp.body)
    assert "device_code" in body
