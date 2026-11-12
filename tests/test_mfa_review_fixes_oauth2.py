"""FEAT-106 review fix #1 (spec M6): the OAuth2 password form enforces the second factor.

The first part drives ``Oauth2Provider`` with a real aiohttp router/request and a stubbed
``SecondFactorGate`` / MFA lease; it needs neither Postgres nor Redis. The "Live Postgres +
Redis" part (FEAT-114) drives a real ``AuthHandler(BasicAuth + Oauth2Provider)`` over HTTP and
skips when Postgres, Redis, the MFA services or the Vault keyring are unavailable. Settings are
patched with ``monkeypatch`` (restored automatically).
"""

import asyncio
import hashlib
import html
import re
import secrets
import warnings
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs, urlparse

import jinja2
import jwt
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer, make_mocked_request
from navigator_session import AUTH_SESSION_OBJECT, get_session

import navigator_auth.conf as conf
from navigator_auth import AuthHandler
from navigator_auth.abac.context import EvalContext
from navigator_auth.backends.oauth2 import backend as oauth_backend
from navigator_auth.backends.oauth2.backend import (
    OAUTH2_EVENT_COOKIE,
    OAUTH2_EVENT_KEY_PREFIX,
    Oauth2Provider,
)
from navigator_auth.backends.oauth2.client_backend import MemoryClientStorage
from navigator_auth.backends.oauth2.models import OAuthClient, OauthGrant
from navigator_auth.backends.oauth2.pkce import generate_challenge
from navigator_auth.conf import AUTH_MECHANISM_KEY
from navigator_auth.mfa.login import GateResult, LoginChallenge, VerifyRefused
from navigator_auth.mfa.services import get_mfa_services
from navigator_auth.mfa.types import PROVIDER_EMAIL, PROVIDER_TOTP, TRUSTED_COOKIE, MfaMode
from tests.fixtures.mfa import (  # noqa: F401
    frozen_totp_clock,
    mfa_db,
    mfa_redis_pool,
    mfa_secret,
    mfa_user_factory,
    single_connection_authdb,
)
from tests.test_mfa_e2e import CAPTURED, Live, _patch_settings, _stop, requires_fresh_factor

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
    location = urlparse(response.headers["Location"])
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


# ---------------------------------------------------------------------------
# Live Postgres + Redis (FEAT-114, issue:1a329591f638)
#
# A real AuthHandler(BasicAuth + Oauth2Provider) on live Postgres + Redis with
# AUTH_BASIC_2FA_ENABLED, driven over HTTP. Test-only seams, all installed after
# startup and none bypassing a security check: the client storage is an in-memory
# store holding one public PKCE client, each user gets a pre-seeded consent grant
# (consent is not under test), the TOTP clock is frozen and the e-mail OTP
# callback captures payloads (both as in tests/test_mfa_e2e.py).
# ---------------------------------------------------------------------------

OAUTH_CLIENT_ID = "mfa-live-oauth-client"
OAUTH_REDIRECT = "https://app.example/cb"
OAUTH_BACKENDS = ("navigator_auth.backends.BasicAuth", "navigator_auth.backends.Oauth2Provider")
EVALCTX_PATH = "/_test/oauth/evalctx"
_CHALLENGE_INPUT = re.compile(r'name="challenge" value="([^"]*)"')


def live_test(func):
    """Mark a live async test with the warning filters tests/test_mfa_e2e.py applies module-wide."""
    func = pytest.mark.filterwarnings("ignore::DeprecationWarning")(func)
    func = pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")(func)
    return pytest.mark.asyncio(func)


async def _oauth_evalctx_view(request: web.Request) -> web.Response:
    """Test-only bearer route: the EvalContext the PDP builds, plus the raw session's assurance.

    Not in the auth exclude list, so ``_auth_middleware`` authenticates the bearer token and
    publishes its request-local assurance before this runs.
    """
    session = await get_session(request, new=False)
    raw = session.get(AUTH_SESSION_OBJECT) if session else None
    raw = raw if isinstance(raw, dict) else {}
    ctx = EvalContext(request, raw, raw, session)
    effective = ctx.userinfo if isinstance(ctx.userinfo, dict) else {}
    return web.json_response(
        {
            "mechanism": request.get(AUTH_MECHANISM_KEY),
            "mfa": bool(ctx.mfa),
            "amr": list(effective.get("amr") or []),
            "fresh": requires_fresh_factor(ctx),
            "session_mfa": bool(raw.get("mfa")),
            "session_amr": list(raw.get("amr") or []),
        }
    )


async def _start_oauth(app: web.Application, *, enable_authdb: bool = True) -> tuple[AuthHandler, TestClient]:
    """Start AuthHandler(BasicAuth + Oauth2Provider); swap in a MemoryClientStorage with one PKCE client.

    ``secure_cookies=True`` because the session storage only writes the session cookie when it
    is set, and the ``/oauth2/login`` -> ``/oauth2/authorize`` hop needs that cookie.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        auth = AuthHandler(secure_cookies=True, backends=OAUTH_BACKENDS, enable_authdb=enable_authdb)
        auth.setup(app)
        client = TestClient(TestServer(app))
        await client.start_server()
    provider = auth.backends["Oauth2Provider"]
    # Production AUTH_SUCCESSFUL_CALLBACKS reach services unavailable here (see test_mfa_e2e._start).
    auth.backends["BasicAuth"]._callbacks = None
    provider._callbacks = None
    storage = MemoryClientStorage()
    await storage.save_client(
        OAuthClient(
            client_id=OAUTH_CLIENT_ID,
            client_name="MFA live client",
            client_type="public",
            redirect_uris=[OAUTH_REDIRECT],
            default_scopes=["default"],
        )
    )
    provider.client_storage = storage
    return auth, client


async def _stop_oauth(auth: AuthHandler, client: TestClient) -> None:
    """Disconnect the provider's lazily built flow-store pool, then the standard live teardown."""
    provider = auth.backends.get("Oauth2Provider")
    store = getattr(provider, "_flow_store", None)
    if provider is not None and store is not None:
        await store._pool.disconnect()
        provider._flow_store = None
    await _stop(auth, client)


class OAuthLive(Live):
    """Live app plus OAuth2 browser-leg helpers (explicit cookies, never the client jar)."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.granted: list[int] = []

    @property
    def provider(self) -> Oauth2Provider:
        """The application's Oauth2Provider backend."""
        return self.auth.backends["Oauth2Provider"]

    def authorize_params(self) -> tuple[dict, str]:
        """Return (the 9 authorize parameters with a real S256 challenge, the code_verifier)."""
        verifier = secrets.token_urlsafe(48)
        params = {
            "client_id": OAUTH_CLIENT_ID, "redirect_uri": OAUTH_REDIRECT, "response_type": "code",
            "state": secrets.token_urlsafe(8), "scope": "default",
            "code_challenge": generate_challenge(verifier), "code_challenge_method": "S256",
            "nonce": secrets.token_urlsafe(8), "prompt": "login",
        }  # fmt: skip
        return params, verifier

    async def grant(self, user: dict) -> None:
        """Pre-seed a consent grant so /oauth2/authorize issues the code directly."""
        await self.provider.grant_storage.save_grant(
            OauthGrant(user_id=user["user_id"], client_id=OAUTH_CLIENT_ID, scopes=["default"])
        )
        self.granted.append(user["user_id"])

    async def oauth_login(self, user: dict, params: dict, *, cookies: dict | None = None):
        """POST /oauth2/login (form); returns the raw response, redirects not followed."""
        self._no_jar()
        form = {**params, "username": user["username"], "password": user["password_current"]}
        return await self.client.post("/oauth2/login", data=form, cookies=cookies, allow_redirects=False)

    async def oauth_mfa(self, params: dict, challenge: str, provider: str, code: str, *, remember: bool = False):
        """POST /oauth2/login/mfa (form); returns the raw response, redirects not followed."""
        self._no_jar()
        form = {**params, "challenge": challenge, "provider": provider, "code": code}
        if remember:
            form["remember_device"] = "1"
        return await self.client.post("/oauth2/login/mfa", data=form, allow_redirects=False)

    @staticmethod
    async def challenge_of(response) -> str:
        """The challenge token carried by the rendered oauth/mfa.html form."""
        match = _CHALLENGE_INPUT.search(await response.text())
        assert match and match.group(1), "no challenge on the MFA page"
        return html.unescape(match.group(1))

    async def mint(self, login_response, verifier: str) -> str:
        """Follow a login 302 through /oauth2/authorize and the token endpoint; return the access token."""
        assert login_response.status == 302, await login_response.text()
        cookies = {name: morsel.value for name, morsel in login_response.cookies.items()}
        self._no_jar()
        authorize = await self.client.get(
            login_response.headers["Location"], cookies=cookies, allow_redirects=False
        )
        assert authorize.status == 302, await authorize.text()
        target = urlparse(authorize.headers["Location"])
        assert f"{target.scheme}://{target.netloc}{target.path}" == OAUTH_REDIRECT, target
        code = parse_qs(target.query)["code"][0]
        self._no_jar()
        response = await self.client.post(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": OAUTH_REDIRECT,
                "client_id": OAUTH_CLIENT_ID,
                "code_verifier": verifier,
            },
        )
        body = await response.json()
        assert response.status == 200, body
        return body["access_token"]

    async def evalctx(self, token: str) -> dict:
        """GET the test bearer route with ``token``; returns its JSON."""
        self._no_jar()
        response = await self.client.get(EVALCTX_PATH, headers={"Authorization": f"Bearer {token}"})
        assert response.status == 200, await response.text()
        return await response.json()

    async def cleanup(self) -> None:
        """Drop the pre-seeded grants (Redis), then the standard live cleanup."""
        storage = self.provider.grant_storage
        for user_id in self.granted:
            await storage.redis.delete(
                f"{storage.prefix}{user_id}:{OAUTH_CLIENT_ID}", f"{storage.user_index_prefix}{user_id}"
            )
        await super().cleanup()


@asynccontextmanager
async def _oauth_env(monkeypatch, *, db, clock, factory, secret, authdb=None):
    """Yield a started OAuthLive (2FA on, live Postgres + Redis) or skip; always tear down.

    ``authdb`` (AC10): a pool installed as ``app["authdb"]`` before startup instead of the
    one AuthHandler would create.
    """
    _patch_settings(monkeypatch, enabled=True, secret=secret)
    monkeypatch.setattr(conf, "AUTHENTICATION_BACKENDS", OAUTH_BACKENDS)
    CAPTURED.clear()
    app = web.Application()
    abac = SimpleNamespace(policies=[])
    app["abac"] = abac
    app.router.add_get(EVALCTX_PATH, _oauth_evalctx_view)
    if authdb is not None:
        app["authdb"] = authdb
    try:
        auth, client = await _start_oauth(app, enable_authdb=authdb is None)
    except Exception as err:  # pylint: disable=W0718
        pytest.skip(f"OAuth2 live application unavailable: {type(err).__name__}: {err}")
    services = get_mfa_services(app)
    if services is None or not services.available:
        await _stop_oauth(auth, client)
        pytest.skip("MFA services unavailable (tables, Redis or AUTH_OTP_SECRET)")
    if app.get("vault_keyring") is None:
        await _stop_oauth(auth, client)
        pytest.skip("Vault KeyRing not configured (VAULT_MASTER_KEY_v*): TOTP seeds cannot be sealed")
    services.providers[PROVIDER_TOTP]._clock = clock  # type: ignore[attr-defined]
    services.providers[PROVIDER_EMAIL]._callback = "tests.test_mfa_e2e._capture_otp"  # type: ignore[attr-defined]
    env = OAuthLive(app, auth, client, services, db, clock, factory, abac)
    try:
        yield env
    finally:
        await env.cleanup()
        await _stop_oauth(auth, client)
        CAPTURED.clear()


@pytest_asyncio.fixture
async def oauth_live(monkeypatch, mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory, frozen_totp_clock):  # noqa: F811
    """A real AuthHandler(BasicAuth + Oauth2Provider) app with 2FA on, on live Postgres + Redis."""
    async with _oauth_env(
        monkeypatch, db=mfa_db, clock=frozen_totp_clock, factory=mfa_user_factory, secret=mfa_secret
    ) as env:
        yield env


async def _email_challenge(live: OAuthLive, user: dict, params: dict):
    """OAuth password POST for an e-mail-OTP user; returns (MFA page response, challenge, code)."""
    page = await live.oauth_login(user, params)
    assert page.status == 200, await page.text()
    return page, await live.challenge_of(page), live.email_code(user)


@live_test
async def test_oauth2_live_email_otp_single_delivery_and_replay(oauth_live):
    """FEAT-106 AC1/AC2 live: one e-mail OTP and no session for the challenge; 302 with the 9
    authorize parameters for the code; the same challenge replayed is refused."""
    live = oauth_live
    user = await live.user()
    await live.org(user["user_id"], mode=MfaMode.ENFORCED)
    params, _ = live.authorize_params()

    page, challenge, code = await _email_challenge(live, user, params)
    assert page.headers["Cache-Control"] == "no-store"
    assert "Set-Cookie" not in page.headers
    assert "Location" not in page.headers
    sent = live.emails(user)
    assert len(sent) == 1
    assert sent[0].email == user["email"]
    assert sent[0].code not in repr(sent[0])

    response = await live.oauth_mfa(params, challenge, PROVIDER_EMAIL, code)
    assert response.status == 302, await response.text()
    location = urlparse(response.headers["Location"])
    assert location.path == "/oauth2/authorize"
    assert {key: values[0] for key, values in parse_qs(location.query).items()} == params

    replay = await live.oauth_mfa(params, challenge, PROVIDER_EMAIL, code)
    assert replay.status == 401, await replay.text()
    assert "Location" not in replay.headers
    assert "Set-Cookie" not in replay.headers
    assert len(live.emails(user)) == 1


@live_test
async def test_oauth2_live_event_record(oauth_live):
    """FEAT-106 AC2 live: the event cookie names a Redis record with the user, mfa true, amr [pwd, otp]."""
    live = oauth_live
    user = await live.user()
    await live.org(user["user_id"], mode=MfaMode.ENFORCED)
    params, _ = live.authorize_params()
    _, challenge, code = await _email_challenge(live, user, params)

    response = await live.oauth_mfa(params, challenge, PROVIDER_EMAIL, code)
    assert response.status == 302, await response.text()
    handle = response.cookies[OAUTH2_EVENT_COOKIE].value
    key = OAUTH2_EVENT_KEY_PREFIX + hashlib.sha256(handle.encode("utf-8")).hexdigest()
    assert handle not in key
    record = await live.provider.flow_store.get(key)
    assert record is not None
    assert record["user_id"] == user["user_id"]
    assert record["mfa"] is True
    assert record["amr"] == ["pwd", "otp"]
    assert record["auth_method"] == "oauth2"
    assert record["session_id"]


@live_test
async def test_oauth2_login_single_connection_pool(
    monkeypatch, single_connection_authdb, mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory, frozen_totp_clock  # noqa: F811
):
    """FEAT-106 AC10 (OAuth rows): /oauth2/login and /oauth2/login/mfa finish within 10 s on an
    authdb capped at one connection, with no acquire() while LOCK_CONNECTION is set."""
    async with _oauth_env(
        monkeypatch,
        db=mfa_db,
        clock=frozen_totp_clock,
        factory=mfa_user_factory,
        secret=mfa_secret,
        authdb=single_connection_authdb,
    ) as live:
        user = await live.user()
        await live.org(user["user_id"], mode=MfaMode.ENFORCED)
        params, _ = live.authorize_params()
        # Startup and the test-data helpers acquire legitimately; measure only the two calls.
        single_connection_authdb.acquires_inside_lock.clear()
        before = len(single_connection_authdb.acquires)
        single_connection_authdb.strict = True
        try:
            page = await asyncio.wait_for(live.oauth_login(user, params), 10)
            assert page.status == 200, await page.text()
            challenge = await live.challenge_of(page)
            response = await asyncio.wait_for(
                live.oauth_mfa(params, challenge, PROVIDER_EMAIL, live.email_code(user)), 10
            )
            assert response.status == 302, await response.text()
        finally:
            single_connection_authdb.strict = False
        # Non-vacuous: the measured calls really ran on the one-connection pool.
        assert len(single_connection_authdb.acquires) > before
        assert single_connection_authdb.acquires_inside_lock == []


def _oauth_claims(token: str) -> dict:
    """Unverified claims of a minted token: the middleware verifies it; this only reads assurance."""
    return jwt.decode(token, options={"verify_signature": False})


async def _drop_session(live: OAuthLive, user: dict, session_id: str) -> None:
    """Delete the identity-shared session so the next bearer request recreates it from the token."""
    pool = live.auth.session.storage._redis
    async with aioredis.Redis(connection_pool=pool) as redis_client:
        await redis_client.delete(f"session:{session_id}", f"user:{user['username']}")


async def _totp_mint(live: OAuthLive, user: dict, secret: str, *, remember: bool = False):
    """OAuth2 TOTP login through the browser leg; returns (access token, /oauth2/login/mfa response)."""
    params, verifier = live.authorize_params()
    page = await live.oauth_login(user, params)
    assert page.status == 200, await page.text()
    response = await live.oauth_mfa(
        params, await live.challenge_of(page), PROVIDER_TOTP, live.totp(secret), remember=remember
    )
    assert response.status == 302, await response.text()
    return await live.mint(response, verifier), response


async def _plain_mint(live: OAuthLive, user: dict, *, cookies: dict | None = None) -> str:
    """OAuth2 login with no factor owed (or a trusted device): the password POST redirects directly."""
    params, verifier = live.authorize_params()
    response = await live.oauth_login(user, params, cookies=cookies)
    return await live.mint(response, verifier)


@live_test
async def test_oauth2_live_abac_fresh_factor(oauth_live):
    """FEAT-106 AC27 end to end: tokens minted by /oauth2/token after a TOTP, a trusted-device and a
    no-MFA login carry the matching claims; through the real bearer middleware only the TOTP token
    satisfies requires_fresh_factor."""
    live = oauth_live
    user = await live.user()
    # OPTIONAL + no TOTP owes no factor; remember_days enables trusted devices (test_mfa_e2e.py:569).
    await live.org(user["user_id"], mode=MfaMode.OPTIONAL, remember_days=30)
    await live.grant(user)

    tokens = {"plain": await _plain_mint(live, user)}
    secret, _ = await live.enrol_totp(user, await live.plain_login(user))
    tokens["totp"], response = await _totp_mint(live, user, secret, remember=True)
    device = response.cookies[TRUSTED_COOKIE].value
    tokens["trusted"] = await _plain_mint(live, user, cookies={TRUSTED_COOKIE: device})

    claims = {name: _oauth_claims(token) for name, token in tokens.items()}
    for name, claim in claims.items():
        assert claim["user_id"] == user["user_id"], name
        assert claim["client_id"] == OAUTH_CLIENT_ID, name
    assert "mfa" not in claims["plain"] and "amr" not in claims["plain"]
    assert claims["totp"]["mfa"] is True and claims["totp"]["amr"] == ["pwd", "totp"]
    assert claims["trusted"]["mfa"] is True and claims["trusted"]["amr"] == ["pwd", "trusted_device"]

    views = {name: await live.evalctx(token) for name, token in tokens.items()}
    for name, view in views.items():
        assert view["mechanism"] == "bearer", (name, view)
    assert (views["totp"]["mfa"], views["totp"]["amr"], views["totp"]["fresh"]) == (True, ["pwd", "totp"], True)
    assert views["trusted"]["mfa"] is True and views["trusted"]["fresh"] is False
    assert views["plain"]["mfa"] is False and views["plain"]["fresh"] is False


@live_test
async def test_oauth2_live_assurance_isolation(oauth_live):
    """FEAT-106 AC29 end to end: a password-only token minted before a TOTP mint, and a trusted-device
    token minted after one TOTP mint and before another, stay denied while the identity-shared session
    holds a later TOTP login's assurance, and after the session is recreated from each token; both TOTP
    tokens stay granted."""
    live = oauth_live
    user = await live.user()
    await live.org(user["user_id"], mode=MfaMode.OPTIONAL, remember_days=30)
    await live.grant(user)

    tokens = {"pwd": await _plain_mint(live, user)}
    secret, _ = await live.enrol_totp(user, await live.plain_login(user))
    tokens["totp1"], response = await _totp_mint(live, user, secret, remember=True)
    device = response.cookies[TRUSTED_COOKIE].value
    tokens["trusted"] = await _plain_mint(live, user, cookies={TRUSTED_COOKIE: device})
    tokens["totp2"], _ = await _totp_mint(live, user, secret)
    # Last, so nothing overwrites it: a BasicAuth TOTP login writes mfa/amr into the shared session.
    response, body = await live.totp_login(user, secret)
    assert response.status == 200, body

    session_ids = {_oauth_claims(token)[live.provider.session_id_property] for token in tokens.values()}
    assert len(session_ids) == 1, "every token for one identity shares one session"
    session_id = session_ids.pop()

    # Precondition, so the test cannot pass vacuously: the shared session says "fresh TOTP".
    shared = await live.evalctx(tokens["pwd"])
    assert shared["session_mfa"] is True and "totp" in shared["session_amr"], shared

    expected = {"pwd": False, "trusted": False, "totp1": True, "totp2": True}
    for name, token in tokens.items():
        view = await live.evalctx(token)
        assert view["mechanism"] == "bearer", (name, view)
        assert view["fresh"] is expected[name], ("shared session", name, view)

    # Session recreation: each token's first request rebuilds the session from the token alone.
    for name, token in tokens.items():
        await _drop_session(live, user, session_id)
        view = await live.evalctx(token)
        assert view["session_mfa"] is False, ("recreated", name, view)
        assert view["fresh"] is expected[name], ("recreated", name, view)
