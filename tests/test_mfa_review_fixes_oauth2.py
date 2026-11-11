"""FEAT-106 review fix #1 (spec M6): the OAuth2 password form enforces the second factor.

These tests drive ``Oauth2Provider`` with a real aiohttp router/request and a stubbed
``SecondFactorGate`` / MFA lease, so they need neither Postgres nor Redis. Settings are
patched with ``monkeypatch`` (restored automatically); no process-wide state is mutated.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs, urlparse

import jinja2
import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

import navigator_auth.conf as conf
from navigator_auth.backends.oauth2 import backend as oauth_backend
from navigator_auth.backends.oauth2.backend import (
    OAUTH2_EVENT_COOKIE,
    OAUTH2_EVENT_KEY_PREFIX,
    Oauth2Provider,
)
from navigator_auth.mfa.login import GateResult, LoginChallenge, VerifyRefused
from navigator_auth.mfa.types import TRUSTED_COOKIE

AUTHORIZE_PARAMS = {
    "client_id": "mfa-oauth-client",
    "redirect_uri": "https://app.example/cb",
    "response_type": "code",
    "state": "s-123",
    "scope": "default",
    "code_challenge": "x" * 43,
    "code_challenge_method": "S256",
    "nonce": "n-1",
    "prompt": "login",
}
TEMPLATES = Path(__file__).resolve().parents[1] / "templates"


async def _noop(request):  # pragma: no cover - route placeholder
    return web.Response()


def _app() -> web.Application:
    app = web.Application()
    app.router.add_route("*", "/oauth2/authorize", _noop, name="nav_oauth2_authorize")
    app.router.add_route("*", "/oauth2/login", _noop, name="nav_oauth2_login")
    app.router.add_route("POST", "/oauth2/login/mfa", _noop, name="nav_oauth2_login_mfa")
    return app


def _request(app: web.Application, path: str = "/oauth2/login", cookies: dict | None = None):
    headers = {}
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return make_mocked_request("POST", path, headers=headers, app=app)


@pytest.fixture
def provider():
    prov = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    prov._create_user_session = AsyncMock(return_value=SimpleNamespace(session_id="sess-1"))
    prov._upstream_providers = lambda: []
    prov._parser = SimpleNamespace(
        view=AsyncMock(
            side_effect=lambda filename, params=None, status=200, **_: web.Response(text=filename, status=status)
        )
    )
    prov.get_login_form = AsyncMock(return_value=("bob", "pw", dict(AUTHORIZE_PARAMS)))
    prov._idp.authenticate_credentials = AsyncMock(return_value={"user_id": 7, "is_active": True, "username": "bob"})
    return prov


def _lease(services):
    @asynccontextmanager
    async def _cm(app):
        yield services

    return _cm


class _FakeGate:
    """Stand-in for SecondFactorGate: scripted decide/verify outcome."""

    decide_result = None
    verify_result = None
    verify_error = None
    decide_error = None

    def __init__(self, services, **kwargs):
        self.services = services

    async def decide(self, request, user, issue):
        if self.decide_error is not None:
            raise self.decide_error
        result = self.decide_result
        if result == "session":
            return GateResult(session=await issue(user, {}))
        if result == "trusted":
            session = await issue(user, {"mfa": True, "amr": ["pwd", "trusted_device"]})
            return GateResult(session=session, device={"token": "rotated", "max_age": 3600})
        return GateResult(
            challenge=LoginChallenge(token="chal-1", providers=("email", "totp"), preferred="email", expires_in=300)
        )

    async def verify(self, request, token, provider, code, issue, *, remember_device=False, device_label=""):
        if self.verify_error is not None:
            raise self.verify_error
        session = await issue({"user_id": 7, "username": "bob"}, {"mfa": True, "amr": ["pwd", "otp"]})
        device = {"token": "dev-1", "max_age": 3600} if remember_device else None
        return GateResult(session=session, device=device)


@pytest.fixture
def gate(monkeypatch):
    monkeypatch.setattr(conf, "AUTH_BASIC_2FA_ENABLED", True)
    monkeypatch.setattr(oauth_backend, "SecondFactorGate", _FakeGate)
    monkeypatch.setattr(oauth_backend, "mfa_services_lease", _lease(SimpleNamespace(available=True)))
    for attr in ("decide_result", "verify_result", "verify_error", "decide_error"):
        monkeypatch.setattr(_FakeGate, attr, None)
    return _FakeGate


@pytest.mark.asyncio
async def test_oauth2_login_factor_owed_renders_mfa_page(provider, gate):
    """AC1: 200 form, no-store, no session, no redirect."""
    response = await provider.auth_login(_request(_app()))
    assert response.status == 200
    assert response.text == "oauth/mfa.html"
    assert response.headers["Cache-Control"] == "no-store"
    assert "Set-Cookie" not in response.headers
    provider._create_user_session.assert_not_awaited()
    params = provider._parser.view.await_args.kwargs["params"]
    assert params["challenge"] == "chal-1"
    assert params["providers"] == ["email", "totp"]
    for key, value in AUTHORIZE_PARAMS.items():
        assert params[key] == value


@pytest.mark.asyncio
async def test_oauth2_login_mfa_success_redirects_with_pkce(provider, gate):
    """AC2: 302 to /oauth2/authorize with the 9 parameters; the event is requested with mfa/amr."""
    form = {**AUTHORIZE_PARAMS, "challenge": "chal-1", "provider": "otp", "code": "123456"}
    provider.get_payload = AsyncMock(return_value=form)
    response = await provider.auth_login_mfa(_request(_app(), "/oauth2/login/mfa"))
    assert response.status == 302
    location = urlparse(str(response.location))
    assert location.path == "/oauth2/authorize"
    assert {k: v[0] for k, v in parse_qs(location.query).items()} == AUTHORIZE_PARAMS
    extra = provider._create_user_session.await_args.kwargs["extra"]
    assert extra == {"mfa": True, "amr": ["pwd", "otp"], "auth_method": "oauth2"}
    assert provider._create_user_session.await_args.kwargs["response"] is response


@pytest.mark.asyncio
async def test_oauth2_login_mfa_invalid_and_stale(provider, gate, monkeypatch):
    """AC3: invalid code -> MFA page + attempts_remaining; stale/invalid challenge -> login page + error."""
    form = {**AUTHORIZE_PARAMS, "challenge": "chal-1", "provider": "totp", "providers": "email,totp", "code": "0"}
    provider.get_payload = AsyncMock(return_value=form)
    monkeypatch.setattr(_FakeGate, "verify_error", VerifyRefused("invalid_code", 401, attempts_remaining=2))
    response = await provider.auth_login_mfa(_request(_app(), "/oauth2/login/mfa"))
    assert (response.status, response.text) == (401, "oauth/mfa.html")
    params = provider._parser.view.await_args.kwargs["params"]
    assert params["attempts_remaining"] == 2
    assert params["providers"] == ["email", "totp"]
    assert params["challenge"] == "chal-1"
    provider._create_user_session.assert_not_awaited()

    for code in ("stale_challenge", "invalid_challenge"):
        monkeypatch.setattr(_FakeGate, "verify_error", VerifyRefused(code, 401))
        response = await provider.auth_login_mfa(_request(_app(), "/oauth2/login/mfa"))
        assert (response.status, response.text) == (401, "oauth/login.html")
        assert provider._parser.view.await_args.kwargs["params"]["error"]
    provider._create_user_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_oauth2_login_trusted_device(provider, gate, monkeypatch):
    """AC4: trusted-device decide issues amr pwd+trusted_device and sets the rotated cookie."""
    monkeypatch.setattr(_FakeGate, "decide_result", "trusted")
    response = await provider.auth_login(_request(_app(), cookies={TRUSTED_COOKIE: "old"}))
    assert response.status == 302
    extra = provider._create_user_session.await_args.kwargs["extra"]
    assert extra["amr"] == ["pwd", "trusted_device"] and extra["auth_method"] == "oauth2"
    assert response.cookies[TRUSTED_COOKIE].value == "rotated"

    provider.get_payload = AsyncMock(
        return_value={**AUTHORIZE_PARAMS, "challenge": "c", "provider": "otp", "code": "1", "remember_device": "1"}
    )
    response = await provider.auth_login_mfa(_request(_app(), "/oauth2/login/mfa"))
    assert response.cookies[TRUSTED_COOKIE].value == "dev-1"


@pytest.mark.asyncio
async def test_oauth2_login_no_factor_owed_still_records_event(provider, gate, monkeypatch):
    """No factor owed: the issuer always passes a dict so an event (mfa False) is recorded."""
    monkeypatch.setattr(_FakeGate, "decide_result", "session")
    response = await provider.auth_login(_request(_app()))
    assert response.status == 302
    assert provider._create_user_session.await_args.kwargs["extra"] == {"auth_method": "oauth2"}


@pytest.mark.asyncio
async def test_oauth2_login_2fa_disabled_unchanged(provider, monkeypatch):
    """AC5: 2FA off -> the session is created exactly as before (no ``extra``), no gate, no mfa route."""
    monkeypatch.setattr(conf, "AUTH_BASIC_2FA_ENABLED", False)
    response = await provider.auth_login(_request(_app()))
    assert response.status == 302
    provider._create_user_session.assert_awaited_once()
    assert "extra" not in provider._create_user_session.await_args.kwargs
    assert set(provider._create_user_session.await_args.kwargs) == {"response"}
    assert OAUTH2_EVENT_COOKIE not in response.cookies
    with pytest.raises(web.HTTPNotFound):
        await provider.auth_login_mfa(_request(_app(), "/oauth2/login/mfa"))


@pytest.mark.asyncio
@pytest.mark.parametrize("services", [None, SimpleNamespace(available=False)])
async def test_oauth2_login_mfa_unavailable_503(provider, monkeypatch, services):
    """AC6: slot missing or unavailable -> 503 and no session."""
    monkeypatch.setattr(conf, "AUTH_BASIC_2FA_ENABLED", True)
    monkeypatch.setattr(oauth_backend, "mfa_services_lease", _lease(services))
    with pytest.raises(web.HTTPServiceUnavailable):
        await provider.auth_login(_request(_app()))
    provider._create_user_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_oauth2_login_gate_refusals_create_no_session(provider, gate, monkeypatch):
    """FailedAuth / MFARefused render the login page with an error and no session."""
    from navigator_auth.exceptions import FailedAuth, MFARefused

    monkeypatch.setattr(_FakeGate, "decide_error", FailedAuth("credentials_changed", status=401))
    response = await provider.auth_login(_request(_app()))
    assert (response.status, response.text) == (401, "oauth/login.html")
    monkeypatch.setattr(_FakeGate, "decide_error", MFARefused("mfa_unavailable", "down", status=503))
    response = await provider.auth_login(_request(_app()))
    assert response.status == 503
    provider._create_user_session.assert_not_awaited()


class _FlowStore:
    """In-memory flow store; instance-local so no class-level state leaks."""

    def __init__(self):
        self.data = {}

    async def set(self, key, payload, ttl):
        self.data[key] = (payload, ttl)

    async def get(self, key):
        entry = self.data.get(key)
        return entry[0] if entry else None


@pytest.mark.asyncio
async def test_auth_event_roundtrip_dict_user(provider):
    """_issue_auth_event stores the assurance (dict-aware user id) and _load_auth_event reads it back."""
    provider._flow_store = _FlowStore()
    response = web.HTTPFound("/oauth2/authorize")
    session = SimpleNamespace(session_id="sess-9")
    await oauth_backend.Oauth2Provider._issue_auth_event(
        provider,
        _request(_app()),
        response,
        session,
        {"user_id": "7"},
        {"mfa": True, "amr": ["pwd", "totp"], "auth_method": "oauth2"},
    )
    handle = response.cookies[OAUTH2_EVENT_COOKIE].value
    assert response.cookies[OAUTH2_EVENT_COOKIE]["httponly"]
    ((key, (record, _ttl)),) = provider._flow_store.data.items()
    assert key.startswith(OAUTH2_EVENT_KEY_PREFIX) and handle not in key
    assert record["user_id"] == 7 and record["session_id"] == "sess-9"
    assert record["mfa"] is True and record["amr"] == ["pwd", "totp"]
    loaded = await provider._load_auth_event(_request(_app(), cookies={OAUTH2_EVENT_COOKIE: handle}))
    assert loaded == record
    assert await provider._load_auth_event(_request(_app())) is None
    assert await provider._load_auth_event(_request(_app(), cookies={OAUTH2_EVENT_COOKIE: "nope"})) is None


@pytest.mark.asyncio
async def test_auth_event_store_failure_fails_closed(provider):
    """An unrecorded event is never silently dropped."""
    store = _FlowStore()
    store.set = AsyncMock(side_effect=RuntimeError("redis down"))
    provider._flow_store = store
    with pytest.raises(web.HTTPServiceUnavailable):
        await provider._issue_auth_event(
            _request(_app()),
            web.HTTPFound("/x"),
            SimpleNamespace(session_id="s"),
            {"user_id": 1},
            {"auth_method": "oauth2"},
        )


def test_mfa_template_escapes_authorize_parameters():
    """Spec §7 risk: a `"><script>` state value is rendered escaped in oauth/mfa.html."""
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(TEMPLATES)))  # no autoescape, like TemplateParser
    html = env.get_template("oauth/mfa.html").render(
        action_url="/oauth2/login/mfa",
        challenge="c",
        providers=["email"],
        preferred="email",
        error='<b>"x"</b>',
        attempts_remaining=1,
        state='"><script>alert(1)</script>',
        client_id="c",
    )
    assert "<script>alert(1)</script>" not in html
    assert "&#34;&gt;&lt;script&gt;" in html
    assert "<b>" not in html
