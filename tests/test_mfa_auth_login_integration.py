"""FEAT-106 TASK-139 — R2 regression: MfaSignal is terminal at every authenticate() call site.

Uses a real AuthHandler (BasicAuth configured, no server started) whose
``backends`` mapping is replaced by fakes, and a spy on load_session.
"""

import json
import warnings
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.exceptions import MFARefused, MFARequired
from navigator_auth.mfa.types import MFA_DEVICE_TOKEN_KEY, TRUSTED_COOKIE
from navigator_auth.responses import JSONResponse

pytestmark = [
    pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
    pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning"),
]


class SignalBackend:
    """authenticate() raises the signal given at construction; records calls."""

    def __init__(self, exc):
        self.exc = exc
        self.calls = 0

    async def authenticate(self, request):
        self.calls += 1
        raise self.exc


class AcceptBackend:
    """authenticate() would mint a session — must NEVER be reached after a signal."""

    def __init__(self):
        self.calls = 0

    async def authenticate(self, request):
        self.calls += 1
        return {"user_id": 1, "token": "minted"}


@pytest_asyncio.fixture
async def auth_app():
    import navigator_auth.conf as conf

    original = conf.AUTHENTICATION_BACKENDS
    conf.AUTHENTICATION_BACKENDS = ("navigator_auth.backends.BasicAuth",)
    try:
        from navigator_auth import AuthHandler

        app = web.Application()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            auth = AuthHandler(secure_cookies=False)
            auth.setup(app)
        auth._session.storage.load_session = AsyncMock()
        yield app, auth
    finally:
        conf.AUTHENTICATION_BACKENDS = original


def _req(app, path="/api/v1/login", headers=None):
    return make_mocked_request("POST", path, headers=headers or {}, app=app)


CHALLENGE = MFARequired(challenge="opaque-challenge", providers=["email"], preferred="email", expires_in=300)


def _assert_envelope(resp):
    assert resp.status == 401
    body = json.loads(resp.body)
    assert body == CHALLENGE.payload()
    assert resp.headers["Cache-Control"] == "no-store"


@pytest.mark.asyncio
async def test_api_login_mfa_required_does_not_try_next_backend(auth_app):
    """AC7: loop stops at the signal; the next backend is never called; 401 + envelope."""
    app, auth = auth_app
    accept = AcceptBackend()
    auth.backends = {"Signal": SignalBackend(CHALLENGE), "Accept": accept}
    resp = await auth.api_login(_req(app))
    _assert_envelope(resp)
    assert accept.calls == 0


@pytest.mark.asyncio
async def test_api_login_mfa_refused_does_not_try_next_backend(auth_app):
    """D1: MFARefused('mfa_unavailable', 503) is terminal too — 503, next backend untouched."""
    app, auth = auth_app
    accept = AcceptBackend()
    refused = MFARefused(MFARefused.MFA_UNAVAILABLE, status=503)
    auth.backends = {"Signal": SignalBackend(refused), "Accept": accept}
    resp = await auth.api_login(_req(app))
    assert resp.status == 503
    assert accept.calls == 0
    assert json.loads(resp.body) == refused.payload()


@pytest.mark.asyncio
async def test_api_login_mfa_required_creates_no_session(auth_app):
    """AC6: load_session never awaited; body has no token/refresh_token/session_id; no-store header."""
    app, auth = auth_app
    auth.backends = {"Signal": SignalBackend(CHALLENGE), "Accept": AcceptBackend()}
    resp = await auth.api_login(_req(app))
    auth._session.storage.load_session.assert_not_awaited()
    body = json.loads(resp.body)
    for key in ("token", "refresh_token", "session_id"):
        assert key not in body
    assert resp.headers["Cache-Control"] == "no-store"
    assert "Set-Cookie" not in resp.headers


@pytest.mark.asyncio
async def test_explicit_backend_mfa_response(auth_app):
    """AC32: X-Auth-Method path and ?auth= (TrocToken) path return the SAME 401 envelope as the loop."""
    app, auth = auth_app
    auth.backends = {"Signal": SignalBackend(CHALLENGE), "Accept": AcceptBackend()}
    resp = await auth.api_login(_req(app, headers={"X-Auth-Method": "Signal"}))
    _assert_envelope(resp)

    auth.backends["TrocToken"] = SignalBackend(CHALLENGE)
    resp = await auth.api_login(_req(app, path="/api/v1/login?auth=1"))
    _assert_envelope(resp)
    auth._session.storage.load_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_helpers_reraise_mfa_signal(auth_app):
    """AC32: _backend_auth and _login_token raise the signal itself — never a Response/HTTP error."""
    app, auth = auth_app
    with pytest.raises(MFARequired):
        await auth._backend_auth(_req(app), SignalBackend(CHALLENGE))
    auth.backends["TrocToken"] = SignalBackend(CHALLENGE)
    with pytest.raises(MFARequired):
        await auth._login_token(_req(app, path="/api/v1/login?auth=1"))


@pytest.mark.asyncio
async def test_finalize_login_sets_trusted_cookie_and_strips_token(auth_app):
    """D14/AC14: token only in Set-Cookie (HttpOnly, Secure, SameSite=Lax); absent from body and load_session arg."""
    app, auth = auth_app
    userdata = {"user_id": 1, MFA_DEVICE_TOKEN_KEY: {"token": "raw-device-token", "max_age": 3600}}
    resp = await auth.finalize_login(_req(app), userdata)
    assert MFA_DEVICE_TOKEN_KEY not in userdata
    assert b"raw-device-token" not in resp.body
    persisted = auth._session.storage.load_session.await_args.args[1]
    assert "raw-device-token" not in json.dumps(persisted, default=str)
    cookie = resp.cookies[TRUSTED_COOKIE]
    assert cookie.value == "raw-device-token"
    assert cookie["httponly"] and cookie["secure"]
    assert cookie["samesite"] == "Lax"
    assert cookie["path"] == "/"
    assert cookie["max-age"] == "3600"


@pytest.mark.asyncio
async def test_finalize_login_without_device_is_unchanged(auth_app):
    """AC20: no device key => body bytes equal JSONResponse(userdata).body; no nav_mfa_device cookie."""
    app, auth = auth_app
    userdata = {"user_id": 1, "username": "u"}
    expected = JSONResponse(dict(userdata), status=200).body
    resp = await auth.finalize_login(_req(app), userdata)
    assert resp.body == expected
    assert TRUSTED_COOKIE not in resp.cookies
