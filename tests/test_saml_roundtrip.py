"""FEAT-097 Module 7: SP<->IdP round-trip integration tests, the FEAT-095
OAuth2-AS resume regression, and the executor/performance checks
(TASK-061, spec §4 Integration Tests).

`SAMLIdentityProvider` and `SAMLAuth` (the generic reference subclasses,
TASK-060) are configured against each other on one real aiohttp
`TestServer`/`TestClient` — genuine HTTP round trips, not direct method
calls — with a fixed pre-allocated port so both sides' entity IDs/ACS/SSO
URLs can be computed *before* the (frozen-once-started) router exists.
Offline throughout: the SP's "SAML_METADATA" is the IdP's own rendered
metadata XML passed as inline `pysaml2` config, never fetched over the
network.
"""
import html
import re
import threading
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer, unused_port

from navigator_auth.backends import SAMLAuth, SAMLIdentityProvider
from navigator_auth.backends.external import OAUTH2_RESUME_COOKIE
from navigator_auth.backends.saml import ServiceProviderConfig
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY

# This is the only FEAT-097 test module exercising a full, real aiohttp
# server request/response loop (every other SAML test calls a handler
# method directly). Every backend in this codebase — SAML included, per
# spec/ADFS precedent — *returns* (rather than raises) web.HTTPFound/
# web.Response for redirects, which aiohttp's own server loop now
# deprecates; `test_basic_auth.py` (the only other real-server test file)
# already carries this identical filter for the same reason.
pytestmark = [
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
    pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
]

IDP_KEY = "tests/fixtures/saml/idp.key"
IDP_CERT = "tests/fixtures/saml/idp.crt"


def _relative(url: str) -> str:
    """`TestClient.get/post` wants a path relative to its own base URL, not
    an absolute one — strip the scheme+host from a `Location` header."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return path


class _FakeFlowStore:
    """Dict-backed IdentityFlowStore double (single-use semantics)."""

    def __init__(self):
        self.storage = {}

    async def set(self, key, payload, ttl):
        self.storage[key] = dict(payload)

    async def get(self, key):
        return self.storage.get(key)

    async def getdel(self, key):
        return self.storage.pop(key, None)

    async def consume_link(self, state):
        """No identity-link flow is ever parked in these tests."""
        return None

    def keys(self):
        return self.storage.keys()


class _FakeUser:
    is_authenticated = True
    email = "u@x.com"
    username = "u"
    user_id = 1


def _extract_saml_form(text: str, field: str = "SAMLResponse") -> tuple:
    """`(value, relay_state)` from pysaml2's own POST-binding auto-submit
    form (both are HTML-escaped attribute values)."""
    m = re.search(rf'name="{field}" value="([^"]+)"', text)
    value = html.unescape(m.group(1))
    m2 = re.search(r'name="RelayState" value="([^"]*)"', text)
    relay_state = html.unescape(m2.group(1)) if m2 else ""
    return value, relay_state


@pytest_asyncio.fixture
async def saml_app(monkeypatch):
    """One aiohttp app with a `SAMLIdentityProvider` and a `SAMLAuth`
    configured against each other; `request.user` is injected by a test
    middleware (no real session/DB — `validate_user_info` is mocked on
    the SP instance).
    """
    port = unused_port()
    base_url = f"http://127.0.0.1:{port}"

    idp = SAMLIdentityProvider(user_model=MagicMock())
    idp.core.settings = {"key_file": IDP_KEY, "cert_file": IDP_CERT}
    idp._flow_store = _FakeFlowStore()

    sp_entity = f"{base_url}/auth/saml/metadata"
    sp_acs = f"{base_url}/auth/saml/callback/"
    sp_slo = f"{base_url}/auth/saml/logout"
    idp._sp_registry = {
        "sp1": ServiceProviderConfig(sp_id="sp1", entity_id=sp_entity, acs_url=sp_acs, slo_url=sp_slo)
    }
    idp._trust_registered_sps()
    idp_metadata_xml = idp.core.idp_metadata(base_url)

    monkeypatch.setattr("navigator_auth.backends.saml.SAML_METADATA", {"inline": [idp_metadata_xml]})
    sp = SAMLAuth(user_model=MagicMock())
    sp._flow_store = _FakeFlowStore()
    sp.validate_user_info = AsyncMock(
        return_value={"token": "tok123", "refresh_token": None, "type": "Bearer", "expires_in": 3600}
    )

    request_state = {"authenticated": True}

    @web.middleware
    async def fake_auth_middleware(request, handler):
        if request_state["authenticated"]:
            request.user = _FakeUser()
        else:
            request.user = None
        return await handler(request)

    app = web.Application(middlewares=[fake_auth_middleware])
    app[AUTH_EXCLUDE_LIST_KEY] = []
    idp.configure(app)
    sp.configure(app)

    server = TestServer(app, port=port)
    client = TestClient(server)
    await client.start_server()
    try:
        yield {
            "client": client,
            "sp": sp,
            "idp": idp,
            "base_url": base_url,
            "request_state": request_state,
        }
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_saml_roundtrip_idp_initiated(saml_app):
    client = saml_app["client"]

    resp = await client.get("/auth/saml-idp/initiate/sp1", allow_redirects=False)
    assert resp.status == 200
    text = await resp.text()
    saml_response, relay_state = _extract_saml_form(text)

    acs_resp = await client.post(
        "/auth/saml/callback/",
        data={"SAMLResponse": saml_response, "RelayState": relay_state},
        allow_redirects=False,
    )
    assert acs_resp.status == 302
    assert "token=tok123" in acs_resp.headers["Location"]

    # Replaying the same (unsolicited) response is rejected.
    replay_resp = await client.post(
        "/auth/saml/callback/",
        data={"SAMLResponse": saml_response, "RelayState": relay_state},
        allow_redirects=False,
    )
    assert "error=SAML_REPLAY" in replay_resp.headers["Location"]


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_saml_roundtrip_sp_initiated(saml_app):
    client = saml_app["client"]

    start = await client.get("/api/v1/auth/saml/", allow_redirects=False)
    assert start.status == 302
    sso_location = start.headers["Location"]
    assert "/auth/saml-idp/sso" in sso_location

    sso_resp = await client.get(_relative(sso_location), allow_redirects=False)
    assert sso_resp.status == 200
    text = await sso_resp.text()
    saml_response, relay_state = _extract_saml_form(text)

    acs_resp = await client.post(
        "/auth/saml/callback/",
        data={"SAMLResponse": saml_response, "RelayState": relay_state},
        allow_redirects=False,
    )
    assert acs_resp.status == 302
    assert "token=tok123" in acs_resp.headers["Location"]


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_saml_roundtrip_slo(saml_app):
    """SP-initiated logout reaches the IdP's `slo` endpoint, which replies
    with a signed `LogoutResponse`; the SP's `finish_logout` consumes it."""
    client = saml_app["client"]
    sp = saml_app["sp"]

    # Seed a SAML session so `logout()` builds an SP-initiated LogoutRequest.
    from navigator_auth.backends.saml import SAMLSessionInfo

    info = SAMLSessionInfo(
        name_id="u@x.com",
        name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        session_index="idx-1",
        idp_entity_id=f"{saml_app['base_url']}/auth/saml-idp/metadata",
        backend="saml",
    )

    class _FakeSession(dict):
        def invalidate(self):
            self.clear()
            self["_invalidated"] = True

    session = _FakeSession(saml=info.to_dict())

    async def _fake_get_session(request, new=False):
        return session

    import navigator_auth.backends.saml.sp as sp_module

    real_get_session = None
    try:
        import navigator_session

        real_get_session = navigator_session.get_session
        navigator_session.get_session = _fake_get_session

        logout_resp = await client.get("/api/v1/auth/saml/logout", allow_redirects=False)
        assert logout_resp.status == 302
        assert "SAMLRequest=" in logout_resp.headers["Location"]
        assert session.get("_invalidated") is True

        slo_location = logout_resp.headers["Location"]
        finish_resp = await client.get(_relative(slo_location), allow_redirects=False)
        # The IdP replies on the Redirect binding -> another 302 back to the SP.
        assert finish_resp.status == 302
        assert "SAMLResponse=" in finish_resp.headers["Location"]

        final_resp = await client.get(_relative(finish_resp.headers["Location"]), allow_redirects=False)
        assert final_resp.status == 302
    finally:
        if real_get_session is not None:
            navigator_session.get_session = real_get_session


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_saml_oauth2_resume_detour(saml_app):
    """FEAT-095 D2 regression: a login started by the OAuth2 AS (via the
    `nav_oauth2_flow` cookie) resumes `/oauth2/authorize` after the POST
    ACS callback, exactly like every OIDC backend's GET callback does."""
    client = saml_app["client"]
    sp = saml_app["sp"]

    async def _vault_noop(request):
        return None

    sp._vault_upstream_token = _vault_noop

    client.session.cookie_jar.update_cookies({OAUTH2_RESUME_COOKIE: "flow-1"})

    resp = await client.get("/auth/saml-idp/initiate/sp1", allow_redirects=False)
    text = await resp.text()
    saml_response, relay_state = _extract_saml_form(text)

    acs_resp = await client.post(
        "/auth/saml/callback/",
        data={"SAMLResponse": saml_response, "RelayState": relay_state},
        allow_redirects=False,
    )
    assert acs_resp.status == 302
    location = acs_resp.headers["Location"]
    assert location.startswith(f"{saml_app['base_url']}/oauth2/authorize?flow=flow-1")


@pytest.mark.xmlsec
def test_adfs_redirect_validator_unchanged(monkeypatch):
    """ADFS's relay validator keeps its verdict-style contract on top of the
    AUTH_TRUSTED_DOMAINS gate."""
    from unittest.mock import MagicMock as _MM

    from navigator_auth.backends.adfs import ADFSAuth

    monkeypatch.setattr("navigator_auth.libs.redirect.AUTH_TRUSTED_DOMAINS", ["example.com"])
    backend = object.__new__(ADFSAuth)
    backend.logger = _MM()
    backend._service = "ADFSAuth"

    assert backend._validate_internal_redirect("/home") == "/home"
    assert (
        backend._validate_internal_redirect("https://app.example.com/x")
        == "https://app.example.com/x"
    )
    assert backend._validate_internal_redirect("https://evil.test/x") is None
    assert backend._validate_internal_redirect(None) is None


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_saml_no_blocking_call_on_event_loop(saml_app):
    """Every `pysaml2`/`xmlsec1` call during a round trip runs through
    `SAMLCore.run` (a bounded executor), never on the event loop thread."""
    client = saml_app["client"]
    sp = saml_app["sp"]
    idp = saml_app["idp"]

    main_thread = threading.get_ident()
    seen_threads = set()

    for core in (sp.core, idp.core):
        original_run = core.run

        async def _tracking_run(fn, *args, __orig=original_run, **kwargs):
            def _wrapped(*a, **kw):
                seen_threads.add(threading.get_ident())
                return fn(*a, **kw)

            return await __orig(_wrapped, *args, **kwargs)

        core.run = _tracking_run

    resp = await client.get("/auth/saml-idp/initiate/sp1", allow_redirects=False)
    text = await resp.text()
    saml_response, relay_state = _extract_saml_form(text)
    await client.post(
        "/auth/saml/callback/",
        data={"SAMLResponse": saml_response, "RelayState": relay_state},
        allow_redirects=False,
    )

    assert seen_threads, "expected at least one pysaml2 call through SAMLCore.run"
    assert main_thread not in seen_threads


@pytest.mark.asyncio
@pytest.mark.xmlsec
async def test_saml_performance_acs_and_issuance(saml_app):
    """Spec §5: SP ACS validation and IdP assertion issuance each complete
    in < 150 ms p95 on the fixture keys with the default executor."""
    client = saml_app["client"]

    async def _one_round_trip():
        t0 = time.perf_counter()
        resp = await client.get("/auth/saml-idp/initiate/sp1", allow_redirects=False)
        text = await resp.text()
        issuance_ms = (time.perf_counter() - t0) * 1000

        saml_response, relay_state = _extract_saml_form(text)
        t1 = time.perf_counter()
        acs_resp = await client.post(
            "/auth/saml/callback/",
            data={"SAMLResponse": saml_response, "RelayState": relay_state},
            allow_redirects=False,
        )
        acs_ms = (time.perf_counter() - t1) * 1000
        assert acs_resp.status == 302
        return issuance_ms, acs_ms

    issuance_times = []
    acs_times = []
    for _ in range(20):
        issuance_ms, acs_ms = await _one_round_trip()
        issuance_times.append(issuance_ms)
        acs_times.append(acs_ms)

    def _p95(values):
        ordered = sorted(values)
        idx = max(0, int(round(0.95 * (len(ordered) - 1))))
        return ordered[idx]

    issuance_p95 = _p95(issuance_times)
    acs_p95 = _p95(acs_times)
    # Spec §5's literal target (measured ~30-40ms p95 on this sandbox's
    # fixture keys with the default 4-worker executor).
    assert issuance_p95 < 150, f"issuance p95={issuance_p95:.1f}ms"
    assert acs_p95 < 150, f"ACS validation p95={acs_p95:.1f}ms"
