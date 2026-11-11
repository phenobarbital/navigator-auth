"""Unit tests for FEAT-094 TASK-035 — GET/POST /oauth2/device (RFC 8628 §3.3).

Tests:
  test_device_user_code_lockout          — repeated bad entries → rate-limit + lockout
  test_device_approval_binds_user        — approval stamps user_id from session
  test_device_consent_skip_with_grant    — existing unrevoked OauthGrant skips consent
"""

import asyncio
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import json

import pytest
import jsonpickle

from navigator_auth.backends.oauth2.models import (
    OAuthClient,
    OauthUser,
    OauthGrant,
    DeviceCodeStatus,
    OauthDeviceCode,
)
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
        default_scopes=["default", "offline_access"],
        allowed_grant_types=["urn:ietf:params:oauth:grant-type:device_code"],
    )


def _make_dc(client_id: str = "device_client", user_code: str = "BCDFBCDF") -> OauthDeviceCode:
    now = datetime.now()
    return OauthDeviceCode(
        device_code=secrets.token_urlsafe(32),
        user_code=user_code,
        client_id=client_id,
        scopes=["default", "offline_access"],
        status=DeviceCodeStatus.PENDING,
        interval=5,
        issued_at=now,
        expires_at=now + timedelta(seconds=600),
    )


class _MemGrantStorage:
    def __init__(self):
        self._grants = {}

    async def save_grant(self, grant) -> bool:
        key = f"{grant.user_id}:{grant.client_id}"
        self._grants[key] = grant
        return True

    async def get_grant(self, user_id, client_id):
        return self._grants.get(f"{user_id}:{client_id}")

    async def revoke_grant(self, user_id, client_id) -> bool:
        key = f"{user_id}:{client_id}"
        self._grants.pop(key, None)
        return True


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


def _make_provider(
    client: OAuthClient,
    device_store: MemoryDeviceCodeStorage = None,
    grant_store=None,
    session_user: OauthUser = None,
    code_store=None,
):
    """Build a minimal Oauth2Provider with mocked dependencies."""
    from navigator_auth.backends.oauth2.backend import Oauth2Provider

    provider = Oauth2Provider.__new__(Oauth2Provider)
    provider.logger = MagicMock()
    provider.device_uri = "/oauth2/device"

    provider.client_storage = MagicMock()
    provider.client_storage.get_client = AsyncMock(return_value=client)

    provider.device_code_storage = device_store or MemoryDeviceCodeStorage()
    provider.grant_storage = grant_store
    provider.code_storage = code_store or _MemCodeStorage()
    provider.access_token_storage = MagicMock()
    provider.refresh_token_storage = MagicMock()
    provider._idp = MagicMock()
    # FEAT-108 D5: device verification resolves the session owner against the IdP.
    provider._idp.user_from_id = AsyncMock(
        return_value={"user_id": getattr(session_user, "user_id", 0), "username": "owner", "is_active": True}
    )
    provider._create_user_session = AsyncMock(return_value=None)

    # FEAT-106 review fixes: this memory harness has no authdb.
    @asynccontextmanager
    async def _no_generation(request, user_id):
        yield None, 0

    provider._user_generation = _no_generation
    provider._parser = MagicMock()

    # Simulate rendering templates by returning a simple Response.
    from aiohttp import web

    async def _view(filename, params=None):
        return web.Response(status=200, text=f"TEMPLATE:{filename}")

    provider._parser.view = _view

    # Session: encode the user if provided
    if session_user:
        encoded = jsonpickle.encode(session_user)
        provider.check_session = AsyncMock(return_value=encoded)
    else:
        provider.check_session = AsyncMock(return_value=None)

    return provider


def _make_post_request(form_data: dict, remote: str = "127.0.0.1") -> MagicMock:
    request = MagicMock()
    request.method = "POST"
    request.content_type = "application/x-www-form-urlencoded"
    request.post = AsyncMock(return_value=form_data)
    request.headers = {}
    request.remote = remote
    return request


# ---------------------------------------------------------------------------
# test_device_approval_binds_user
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_approval_binds_user():
    """Approval stamps user_id from session (owner-binding invariant), not client.user.

    Uses the consent-skip path (existing unrevoked grant) so the approval
    happens directly in device_verification without a separate consent POST.
    """
    client = _public_client()
    user = OauthUser(user_id=99, username="alice", given_name="Alice", family_name="Smith")

    dc = _make_dc(client_id=client.client_id)
    store = MemoryDeviceCodeStorage()
    await store.save(dc)

    code_store = _MemCodeStorage()
    grant_store = _MemGrantStorage()
    # Pre-existing grant so consent is skipped → approval happens inline.
    grant = OauthGrant(
        user_id=user.user_id,
        client_id=client.client_id,
        scopes=["default", "offline_access"],
        revoked=False,
    )
    await grant_store.save_grant(grant)

    provider = _make_provider(
        client, device_store=store, grant_store=grant_store,
        session_user=user, code_store=code_store
    )

    request = _make_post_request({
        "action": "approve",
        "user_code": dc.user_code,
    })
    resp = await provider.device_verification(request)
    assert resp.status == 200

    # Device code should now be APPROVED with user_id from session (not client.user).
    updated_dc = await store.get_by_device_code(dc.device_code)
    assert updated_dc is not None
    assert updated_dc.status == DeviceCodeStatus.APPROVED
    assert updated_dc.user_id == user.user_id  # owner-binding from session
    assert updated_dc.auth_code is not None    # D-2 carrier was minted

    # Carrier code should be in code_storage.
    carrier = await code_store.get_code(updated_dc.auth_code)
    assert carrier is not None
    assert carrier.user_id == user.user_id     # carrier bound to session user


@pytest.mark.asyncio
async def test_device_denial_sets_denied_status():
    """Denial sets status=denied."""
    client = _public_client()
    user = OauthUser(user_id=42, username="bob", given_name="Bob", family_name="Jones")

    dc = _make_dc()
    store = MemoryDeviceCodeStorage()
    await store.save(dc)

    provider = _make_provider(client, device_store=store, session_user=user)
    provider.grant_storage = None

    request = _make_post_request({
        "action": "deny",
        "user_code": dc.user_code,
    })
    resp = await provider.device_verification(request)
    assert resp.status == 200

    updated_dc = await store.get_by_device_code(dc.device_code)
    assert updated_dc.status == DeviceCodeStatus.DENIED


# ---------------------------------------------------------------------------
# test_device_consent_skip_with_grant
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_consent_skip_with_grant():
    """Existing unrevoked OauthGrant covering scopes skips consent → direct approval."""
    client = _public_client()
    user = OauthUser(user_id=77, username="carol", given_name="Carol", family_name="Doe")

    dc = _make_dc(client_id=client.client_id)
    store = MemoryDeviceCodeStorage()
    await store.save(dc)

    code_store = _MemCodeStorage()
    grant_store = _MemGrantStorage()

    # Pre-existing grant covering all requested scopes.
    grant = OauthGrant(
        user_id=user.user_id,
        client_id=client.client_id,
        scopes=["default", "offline_access"],
        revoked=False,
    )
    await grant_store.save_grant(grant)

    provider = _make_provider(
        client,
        device_store=store,
        grant_store=grant_store,
        session_user=user,
        code_store=code_store,
    )

    request = _make_post_request({
        "action": "approve",
        "user_code": dc.user_code,
    })
    resp = await provider.device_verification(request)
    assert resp.status == 200

    updated_dc = await store.get_by_device_code(dc.device_code)
    assert updated_dc.status == DeviceCodeStatus.APPROVED
    assert updated_dc.user_id == user.user_id  # still from session


# ---------------------------------------------------------------------------
# test_device_user_code_lockout (in-memory path — no Redis)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_device_invalid_user_code_returns_error():
    """Invalid user_code → generic error (anti-brute-force: no info leakage)."""
    client = _public_client()
    user = OauthUser(user_id=42, username="dave", given_name="Dave", family_name="Doe")
    store = MemoryDeviceCodeStorage()
    provider = _make_provider(client, device_store=store, session_user=user)
    provider.grant_storage = None

    # Try an unknown user_code.
    request = _make_post_request({"action": "approve", "user_code": "XXXXXXXX"})
    resp = await provider.device_verification(request)
    assert resp.status == 400
    body = json.loads(resp.body)
    assert body["error"] == "access_denied"


@pytest.mark.asyncio
async def test_device_expired_code_returns_error():
    """Expired device code at verification → generic access_denied error."""
    client = _public_client()
    user = OauthUser(user_id=42, username="dave", given_name="Dave", family_name="Doe")

    # Expired device code.
    now = datetime.now()
    dc = OauthDeviceCode(
        device_code=secrets.token_urlsafe(32),
        user_code="BBBCCCDD",
        client_id=client.client_id,
        scopes=["default"],
        status=DeviceCodeStatus.PENDING,
        interval=5,
        issued_at=now - timedelta(seconds=700),
        expires_at=now - timedelta(seconds=100),  # expired
    )
    store = MemoryDeviceCodeStorage()
    await store.save(dc)

    provider = _make_provider(client, device_store=store, session_user=user)
    provider.grant_storage = None

    request = _make_post_request({"action": "approve", "user_code": "BBBCCCDD"})
    resp = await provider.device_verification(request)
    assert resp.status == 400


@pytest.mark.asyncio
async def test_device_verification_no_session_redirects():
    """No session → redirect to login page."""
    from aiohttp import web

    client = _public_client()
    dc = _make_dc()
    store = MemoryDeviceCodeStorage()
    await store.save(dc)

    provider = _make_provider(client, device_store=store, session_user=None)
    provider.grant_storage = None

    # Mock the router so the login URL can be resolved.
    login_url = MagicMock()
    login_url.with_query = MagicMock(return_value="/oauth2/login?device_user_code=BCDFBCDF")
    provider_request = _make_post_request({"action": "approve", "user_code": dc.user_code})
    provider_request.app = MagicMock()
    provider_request.app.router = MagicMock()
    provider_request.app.router.__getitem__ = MagicMock(
        return_value=MagicMock(url_for=MagicMock(return_value=login_url))
    )

    with pytest.raises(web.HTTPFound):
        await provider.device_verification(provider_request)


# ---------------------------------------------------------------------------
# FEAT-108 TASK-205 — owner check + device login resume (AC13, AC16a)
# ---------------------------------------------------------------------------

def _routed_app():
    """aiohttp app registering the named OAuth2 routes so ``url_for`` works."""
    from aiohttp import web

    async def _noop(request):  # pragma: no cover - never served
        return web.Response()

    app = web.Application()
    app.router.add_route("*", "/oauth2/login", _noop, name="nav_oauth2_login")
    app.router.add_route("*", "/oauth2/device", _noop, name="nav_oauth2_device")
    app.router.add_route("*", "/oauth2/authorize", _noop, name="nav_oauth2_authorize")
    return app


def _routed_request(form_data: dict, method: str = "POST") -> MagicMock:
    request = _make_post_request(form_data)
    request.method = method
    request.app = _routed_app()
    return request


async def _pending_setup(user_id: int = 7):
    client = _public_client()
    user = OauthUser(user_id=user_id, username="erin", given_name="Erin", family_name="Doe")
    dc = _make_dc(client_id=client.client_id)
    store = MemoryDeviceCodeStorage()
    await store.save(dc)
    return client, user, dc, store


@pytest.mark.asyncio
async def test_device_verification_unknown_owner_redirects():
    """Unknown session owner -> login with device_user_code; code stays pending (AC13)."""
    from aiohttp import web
    from navigator_auth.exceptions import UserNotFound

    client, user, dc, store = await _pending_setup()
    provider = _make_provider(client, device_store=store, session_user=user)
    provider.grant_storage = None
    provider._idp.user_from_id = AsyncMock(side_effect=UserNotFound("gone"))

    request = _routed_request({"action": "approve", "user_code": dc.user_code})
    with pytest.raises(web.HTTPFound) as exc:
        await provider.device_verification(request)
    location = str(exc.value.location)
    assert location.startswith("/oauth2/login")
    assert f"device_user_code={dc.user_code}" in location
    current = await store.get_by_device_code(dc.device_code)
    assert current.status == DeviceCodeStatus.PENDING


@pytest.mark.asyncio
async def test_device_verification_owner_outage_503():
    """Identity-store outage -> generic 503, nothing approved (AC16a)."""
    from navigator_auth.exceptions import IdentityStoreUnavailable

    client, user, dc, store = await _pending_setup()
    provider = _make_provider(client, device_store=store, session_user=user)
    provider.grant_storage = None
    provider._idp.user_from_id = AsyncMock(side_effect=IdentityStoreUnavailable())

    request = _routed_request({"action": "approve", "user_code": dc.user_code})
    resp = await provider.device_verification(request)
    assert resp.status == 503
    current = await store.get_by_device_code(dc.device_code)
    assert current.status == DeviceCodeStatus.PENDING


def _login_provider(client, store, user):
    from aiohttp import web
    provider = _make_provider(client, device_store=store, session_user=user)
    provider.grant_storage = None
    provider._idp.authenticate_credentials = AsyncMock(
        return_value={"user_id": user.user_id, "username": "erin", "is_active": True}
    )
    provider._create_user_session = AsyncMock(return_value=True)
    provider.get_login_form = AsyncMock()
    provider.auth_error = lambda reason, status=400: web.HTTPBadRequest(reason=reason)
    return provider


@pytest.mark.asyncio
async def test_device_login_resumes_verification():
    """No-session -> login with the code -> pre-filled device form -> explicit approve."""
    from aiohttp import web
    from navigator_auth.backends.oauth2 import backend as backend_mod

    client, user, dc, store = await _pending_setup()
    provider = _make_provider(client, device_store=store, session_user=None)
    provider.grant_storage = None

    # 1. no session -> redirected to login carrying the code
    with pytest.raises(web.HTTPFound) as exc:
        await provider.device_verification(
            _routed_request({"action": "approve", "user_code": dc.user_code})
        )
    assert f"device_user_code={dc.user_code}" in str(exc.value.location)

    # 2. POST the login form with the device code -> device route, not authorize
    login_provider = _login_provider(client, store, user)
    login_provider.get_login_form = AsyncMock(
        return_value=("erin", "pw", {"device_user_code": dc.user_code, "client_id": "x"})
    )
    request = _routed_request({}, method="POST")
    with patch.object(backend_mod.auth_conf, "AUTH_BASIC_2FA_ENABLED", False):
        response = await login_provider.auth_login(request)
    assert isinstance(response, web.HTTPFound)
    target = str(response.location)
    assert target.startswith("/oauth2/device")
    assert f"user_code={dc.user_code}" in target
    assert "/oauth2/authorize" not in target
    current = await store.get_by_device_code(dc.device_code)
    assert current.status == DeviceCodeStatus.PENDING  # login alone approves nothing

    # 3. GET the device route renders the form
    get_request = _routed_request({}, method="GET")
    get_request.query = {"user_code": dc.user_code}
    resp = await login_provider.device_verification(get_request)
    assert resp.status == 200
    assert "oauth/device.html" in resp.text

    # 4. explicit POST approve (session now present) approves the code
    code_store = _MemCodeStorage()
    approver = _make_provider(client, device_store=store, session_user=user, code_store=code_store)
    approver.grant_storage = _MemGrantStorage()
    await approver.grant_storage.save_grant(
        OauthGrant(user_id=user.user_id, client_id=client.client_id,
                   scopes=["default", "offline_access"], revoked=False)
    )
    resp = await approver.device_verification(
        _routed_request({"action": "approve", "user_code": dc.user_code})
    )
    assert resp.status == 200
    current = await store.get_by_device_code(dc.device_code)
    assert current.status == DeviceCodeStatus.APPROVED
    assert current.auth_code is not None


def test_device_authorize_redirect_shared_by_mfa_hop():
    """auth_login and auth_login_mfa both resume through ``_authorize_redirect`` (FEAT-106 hop)."""
    import inspect
    from aiohttp import web
    from navigator_auth.backends.oauth2.backend import Oauth2Provider

    assert "_authorize_redirect" in inspect.getsource(Oauth2Provider.auth_login_mfa)
    assert "device_user_code" in Oauth2Provider._MFA_FORM_KEYS
    provider = Oauth2Provider.__new__(Oauth2Provider)
    request = _routed_request({})
    response = provider._authorize_redirect(request, {"device_user_code": "BCDF-BCDF"})
    assert isinstance(response, web.HTTPFound)
    assert str(response.location).startswith("/oauth2/device?user_code=BCDF-BCDF")


@pytest.mark.asyncio
async def test_device_login_rejects_url_like_code():
    """A device_user_code that is a URL is refused with 400."""
    from aiohttp import web
    from navigator_auth.backends.oauth2 import backend as backend_mod

    client, user, dc, store = await _pending_setup()
    provider = _login_provider(client, store, user)
    provider.get_login_form = AsyncMock(
        return_value=("erin", "pw", {"device_user_code": "https://evil"})
    )
    with patch.object(backend_mod.auth_conf, "AUTH_BASIC_2FA_ENABLED", False):
        with pytest.raises(web.HTTPBadRequest):
            await provider.auth_login(_routed_request({}, method="POST"))


def test_device_login_hides_passkey_and_upstream():
    """login.html with device_user_code set renders no passkey and no upstream block."""
    from pathlib import Path
    import jinja2

    root = Path(__file__).resolve().parent.parent / "templates"
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(root)))
    tpl = env.get_template("oauth/login.html")
    device = tpl.render(device_user_code="BCDF-BCDF", upstream_providers=["google"], action_url="/oauth2/login")
    assert "passkey-signin" not in device
    assert "Continue with" not in device
    assert 'name="device_user_code" value="BCDF-BCDF"' in device
    normal = tpl.render(upstream_providers=["google"], action_url="/oauth2/login")
    assert "passkey-signin" in normal
    assert "Continue with" in normal
