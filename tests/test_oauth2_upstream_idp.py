"""Tests for FEAT-095 TASK-041 — upstream IdP proxy login (D2).

Covers the park/resume round-trip that lets the OAuth2 AS delegate resource
owner authentication to Google/Azure without losing the pending authorize
request:

  test_upstream_flow_park_resume, test_upstream_flow_expired,
  test_upstream_identity_vault, test_local_login_unchanged
"""

from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web

from navigator_auth.backends.external import (
    OAUTH2_PENDING_FLOW_KEY,
    OAUTH2_RESUME_COOKIE,
)

AUTHORIZE_PARAMS = {
    "client_id": "cli_abc123",
    "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
    "response_type": "code",
    "scope": "default profile",
    "state": "xyzCSRF789",
    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    "code_challenge_method": "S256",
    "resource": "https://mcp.example.com",
}


class _FakeFlowStore:
    """In-memory stand-in for IdentityFlowStore with real getdel semantics."""

    def __init__(self):
        self.data = {}
        self.ttls = {}

    async def set(self, key, payload, ttl):
        self.data[key] = dict(payload)
        self.ttls[key] = ttl

    async def get(self, key):
        return self.data.get(key)

    async def getdel(self, key):
        self.ttls.pop(key, None)
        return self.data.pop(key, None)


@pytest.fixture
def provider():
    from navigator_auth.backends.oauth2.backend import Oauth2Provider

    prov = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    prov._flow_store = _FakeFlowStore()
    return prov


def _get_request(query: dict):
    request = MagicMock()
    request.method = "GET"
    request.query = dict(query)
    request.cookies = {}
    return request


# ---------------------------------------------------------------------------
# Parking the pending authorize request
# ---------------------------------------------------------------------------

class TestParkPendingRequest:
    @pytest.mark.asyncio
    async def test_park_stores_every_security_critical_field(
        self, provider, monkeypatch
    ):
        """state and the PKCE challenge MUST round-trip exactly."""
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend."
            "OAUTH_UPSTREAM_IDP_BACKENDS",
            ["google", "azure"],
        )
        response = await provider._start_upstream_login(
            _get_request({}), "google", dict(AUTHORIZE_PARAMS)
        )

        assert isinstance(response, web.HTTPFound)
        assert response.headers["Location"] == "/auth/google/login"

        (key,) = provider._flow_store.data.keys()
        parked = provider._flow_store.data[key]
        for field, value in AUTHORIZE_PARAMS.items():
            assert parked[field] == value, f"{field} did not survive parking"

    @pytest.mark.asyncio
    async def test_park_sets_opaque_httponly_cookie(self, provider, monkeypatch):
        """Only the handle travels in the browser, never the request."""
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend."
            "OAUTH_UPSTREAM_IDP_BACKENDS",
            ["google"],
        )
        response = await provider._start_upstream_login(
            _get_request({}), "google", dict(AUTHORIZE_PARAMS)
        )
        cookie = response.cookies[OAUTH2_RESUME_COOKIE]
        flow_id = cookie.value

        assert flow_id
        assert cookie["httponly"]
        assert cookie["samesite"] == "Lax"
        # The handle is opaque: no authorize data leaks into it.
        for value in AUTHORIZE_PARAMS.values():
            assert value not in flow_id
        assert (
            OAUTH2_PENDING_FLOW_KEY.format(flow_id=flow_id)
            in provider._flow_store.data
        )

    @pytest.mark.asyncio
    async def test_park_uses_configured_ttl(self, provider, monkeypatch):
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend."
            "OAUTH_UPSTREAM_IDP_BACKENDS",
            ["google"],
        )
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.OAUTH_UPSTREAM_FLOW_TTL",
            600,
        )
        await provider._start_upstream_login(
            _get_request({}), "google", dict(AUTHORIZE_PARAMS)
        )
        assert set(provider._flow_store.ttls.values()) == {600}

    @pytest.mark.asyncio
    async def test_unknown_provider_refused(self, provider, monkeypatch):
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend."
            "OAUTH_UPSTREAM_IDP_BACKENDS",
            ["google"],
        )
        response = await provider._start_upstream_login(
            _get_request({}), "evilcorp", dict(AUTHORIZE_PARAMS)
        )
        assert response.status == 400
        assert provider._flow_store.data == {}

    @pytest.mark.asyncio
    async def test_park_requires_a_pending_request(self, provider, monkeypatch):
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend."
            "OAUTH_UPSTREAM_IDP_BACKENDS",
            ["google"],
        )
        response = await provider._start_upstream_login(
            _get_request({}), "google", {"scope": "default"}
        )
        assert response.status == 400


# ---------------------------------------------------------------------------
# Resuming
# ---------------------------------------------------------------------------

class TestResumePendingRequest:
    @pytest.mark.asyncio
    async def test_upstream_flow_park_resume(self, provider, monkeypatch):
        """Full round-trip: parked params come back byte-for-byte."""
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend."
            "OAUTH_UPSTREAM_IDP_BACKENDS",
            ["google"],
        )
        response = await provider._start_upstream_login(
            _get_request({}), "google", dict(AUTHORIZE_PARAMS)
        )
        flow_id = response.cookies[OAUTH2_RESUME_COOKIE].value

        restored = await provider._resume_pending_authorize({"flow": flow_id})

        assert restored is not None
        for field, value in AUTHORIZE_PARAMS.items():
            assert restored[field] == value
        assert "flow" not in restored

    @pytest.mark.asyncio
    async def test_resume_is_single_use(self, provider, monkeypatch):
        """A replayed flow id must not resurrect the authorize request."""
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend."
            "OAUTH_UPSTREAM_IDP_BACKENDS",
            ["google"],
        )
        response = await provider._start_upstream_login(
            _get_request({}), "google", dict(AUTHORIZE_PARAMS)
        )
        flow_id = response.cookies[OAUTH2_RESUME_COOKIE].value

        assert await provider._resume_pending_authorize({"flow": flow_id})
        assert await provider._resume_pending_authorize({"flow": flow_id}) is None

    @pytest.mark.asyncio
    async def test_upstream_flow_expired(self, provider):
        """Expired/missing flow ⇒ None, so the caller can restart cleanly."""
        assert await provider._resume_pending_authorize(
            {"flow": "does-not-exist"}
        ) is None

    @pytest.mark.asyncio
    async def test_no_flow_param_is_not_a_resume(self, provider):
        assert await provider._resume_pending_authorize(dict(AUTHORIZE_PARAMS)) is None

    @pytest.mark.asyncio
    async def test_parked_values_win_over_url(self, provider, monkeypatch):
        """A tampered resume URL cannot override the parked PKCE/state."""
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend."
            "OAUTH_UPSTREAM_IDP_BACKENDS",
            ["google"],
        )
        response = await provider._start_upstream_login(
            _get_request({}), "google", dict(AUTHORIZE_PARAMS)
        )
        flow_id = response.cookies[OAUTH2_RESUME_COOKIE].value

        restored = await provider._resume_pending_authorize(
            {
                "flow": flow_id,
                "state": "ATTACKER",
                "code_challenge": "ATTACKER",
                "redirect_uri": "https://evil.example.com/cb",
            }
        )
        assert restored["state"] == AUTHORIZE_PARAMS["state"]
        assert restored["code_challenge"] == AUTHORIZE_PARAMS["code_challenge"]
        assert restored["redirect_uri"] == AUTHORIZE_PARAMS["redirect_uri"]

    @pytest.mark.asyncio
    async def test_expired_flow_yields_invalid_request_not_a_redirect(
        self, provider
    ):
        """Never emit a half-formed redirect for an expired flow."""
        provider.get_payload = AsyncMock(return_value={"flow": "expired-id"})
        request = MagicMock()

        response = await provider.authorize(request)

        assert response.status == 400
        assert not isinstance(response, web.HTTPFound)
        assert b"invalid_request" in response.body


# ---------------------------------------------------------------------------
# Login page rendering
# ---------------------------------------------------------------------------

class TestLoginPageProviders:
    @pytest.mark.asyncio
    async def test_login_page_offers_configured_providers(
        self, provider, monkeypatch
    ):
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend."
            "OAUTH_UPSTREAM_IDP_BACKENDS",
            ["google", "azure"],
        )
        provider._parser = MagicMock()
        provider._parser.view = AsyncMock(return_value="rendered")

        await provider.auth_login(_get_request(dict(AUTHORIZE_PARAMS)))

        params = provider._parser.view.await_args.kwargs["params"]
        assert params["upstream_providers"] == ["google", "azure"]
        # The authorize parameters are still handed to the template.
        assert params["state"] == AUTHORIZE_PARAMS["state"]

    @pytest.mark.asyncio
    async def test_local_login_unchanged(self, provider, monkeypatch):
        """Empty setting ⇒ no providers offered, page renders as before."""
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend."
            "OAUTH_UPSTREAM_IDP_BACKENDS",
            [],
        )
        provider._parser = MagicMock()
        provider._parser.view = AsyncMock(return_value="rendered")

        result = await provider.auth_login(_get_request(dict(AUTHORIZE_PARAMS)))

        assert result == "rendered"
        params = provider._parser.view.await_args.kwargs["params"]
        assert params["upstream_providers"] == []
        # Nothing was parked: the local password flow is untouched.
        assert provider._flow_store.data == {}

    @pytest.mark.asyncio
    async def test_local_login_post_path_untouched(self, provider, monkeypatch):
        """The POST (username/password) branch must not park anything."""
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend."
            "OAUTH_UPSTREAM_IDP_BACKENDS",
            ["google"],
        )
        request = MagicMock()
        request.method = "POST"
        provider.get_login_form = AsyncMock(
            side_effect=RuntimeError("reached the local password branch")
        )
        with pytest.raises(RuntimeError, match="local password branch"):
            await provider.auth_login(request)
        assert provider._flow_store.data == {}


# ---------------------------------------------------------------------------
# The ExternalAuth resume hook
# ---------------------------------------------------------------------------

class _FakeBackend:
    """Drives ExternalAuth's dispatch/resume hooks without a real provider."""

    _service_name = "google"
    scheme = "Bearer"
    userid_attribute = "user_id"

    def __init__(self, callback_response):
        from navigator_auth.backends.external import ExternalAuth

        self.logger = MagicMock()
        self._flow_store = MagicMock()
        self._flow_store.consume_link = AsyncMock(return_value=None)
        self._callback_response = callback_response
        self.vaulted = []
        # Bind the real implementations under test.
        self._pending_oauth2_flow = ExternalAuth._pending_oauth2_flow.__get__(self)
        self._resume_oauth2_authorize = (
            ExternalAuth._resume_oauth2_authorize.__get__(self)
        )
        self._auth_callback_dispatch = (
            ExternalAuth._auth_callback_dispatch.__get__(self)
        )
        # FEAT-097: `_auth_callback_dispatch` now awaits `get_callback_state`
        # (default: query `state`) instead of reading it inline.
        self.get_callback_state = ExternalAuth.get_callback_state.__get__(self)

    def get_domain(self, request):
        return "https://auth.example.com"

    async def auth_callback(self, request):
        return self._callback_response

    async def _vault_upstream_token(self, request):
        self.vaulted.append(request)


def _callback_request(cookies=None, state=None):
    request = MagicMock()
    request.cookies = cookies or {}
    request.rel_url.query = {"state": state} if state else {}
    request.get = MagicMock(return_value=None)
    return request


class TestExternalAuthResumeHook:
    @pytest.mark.asyncio
    async def test_callback_redirects_back_to_authorize(self):
        backend = _FakeBackend(web.HTTPFound("/home"))
        request = _callback_request({OAUTH2_RESUME_COOKIE: "flow-123"})

        response = await backend._auth_callback_dispatch(request)

        assert response.headers["Location"] == (
            "https://auth.example.com/oauth2/authorize?flow=flow-123"
        )

    @pytest.mark.asyncio
    async def test_upstream_identity_vault(self):
        """The upstream credential is vaulted on the AS-initiated login."""
        backend = _FakeBackend(web.HTTPFound("/home"))
        request = _callback_request({OAUTH2_RESUME_COOKIE: "flow-123"})

        await backend._auth_callback_dispatch(request)

        assert backend.vaulted == [request]

    @pytest.mark.asyncio
    async def test_no_marker_keeps_home_redirect(self):
        """A plain login is completely unaffected."""
        original = web.HTTPFound("/home")
        backend = _FakeBackend(original)

        response = await backend._auth_callback_dispatch(_callback_request())

        assert response is original
        assert response.headers["Location"] == "/home"
        assert backend.vaulted == []

    @pytest.mark.asyncio
    async def test_failed_login_is_not_resumed(self):
        """A provider error must not be turned into a consent redirect."""
        failure = web.json_response({"error": "Authenticate Error"}, status=403)
        backend = _FakeBackend(failure)

        response = await backend._auth_callback_dispatch(
            _callback_request({OAUTH2_RESUME_COOKIE: "flow-123"})
        )

        assert response is failure
        assert response.status == 403
        assert backend.vaulted == []

    @pytest.mark.asyncio
    async def test_identity_link_flow_still_wins(self):
        """The identity-link branch is checked before the AS resume."""
        from navigator_auth.backends.external import ExternalAuth

        backend = _FakeBackend(web.HTTPFound("/home"))
        backend._flow_store.consume_link = AsyncMock(
            return_value={"flow": "identity_link"}
        )
        backend.finish_identity_link = AsyncMock(return_value="linked")

        result = await backend._auth_callback_dispatch(
            _callback_request({OAUTH2_RESUME_COOKIE: "flow-123"}, state="s1")
        )

        assert result == "linked"
        assert backend.vaulted == []

    @pytest.mark.asyncio
    async def test_request_marker_takes_precedence_over_cookie(self):
        backend = _FakeBackend(web.HTTPFound("/home"))
        request = _callback_request({OAUTH2_RESUME_COOKIE: "from-cookie"})
        request.get = MagicMock(return_value="from-backend-record")

        response = await backend._auth_callback_dispatch(request)

        assert response.headers["Location"].endswith("flow=from-backend-record")

    @pytest.mark.asyncio
    async def test_resume_marker_cookie_is_cleared(self):
        backend = _FakeBackend(web.HTTPFound("/home"))
        response = await backend._auth_callback_dispatch(
            _callback_request({OAUTH2_RESUME_COOKIE: "flow-123"})
        )
        # del_cookie sets an immediate-expiry Set-Cookie.
        assert response.cookies[OAUTH2_RESUME_COOKIE].value == ""


# ---------------------------------------------------------------------------
# azure.py singleton fix
# ---------------------------------------------------------------------------

class TestAzureRedirectUriNotMutated:
    def test_azure_authenticate_uses_get_redirect_uri(self):
        """azure.py must not mutate the process-wide self.redirect_uri."""
        import inspect
        from navigator_auth.backends.azure import AzureAuth

        source = inspect.getsource(AzureAuth.authenticate)
        assert "self.redirect_uri = self.redirect_uri.format" not in source
        assert "self.get_redirect_uri(request)" in source

    def test_redirect_uri_template_survives(self):
        """The class template must remain unformatted for later requests."""
        import inspect
        from navigator_auth.backends.azure import AzureAuth

        source = inspect.getsource(AzureAuth.authenticate)
        # No assignment to the shared attribute anywhere in the method.
        assert "self.redirect_uri =" not in source
