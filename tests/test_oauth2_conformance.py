"""Tests for FEAT-095 TASK-044 — OAuth 2.1 / Claude conformance hardening.

Covers spec §4:
  test_token_endpoint_415_json, test_client_secret_basic,
  test_resource_param_aud, test_www_authenticate_challenge
"""

import base64
import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web

from navigator_auth.backends.oauth2.backend import (
    Oauth2Provider,
    validate_resource_uri,
)

RESOURCE = "https://mcp.example.com"


@pytest.fixture
def provider():
    return Oauth2Provider(user_model=MagicMock(), identity=MagicMock())


def _post_request(content_type="application/x-www-form-urlencoded", headers=None):
    request = MagicMock()
    request.method = "POST"
    request.content_type = content_type
    request.headers = headers or {}
    return request


# ---------------------------------------------------------------------------
# 415 on non-form bodies
# ---------------------------------------------------------------------------

class TestTokenEndpointContentType:
    @pytest.mark.asyncio
    async def test_token_endpoint_415_json(self, provider):
        """JSON-only servers are what make Claude fail; we refuse JSON."""
        response = await provider.token_request(
            _post_request(content_type="application/json")
        )

        assert response.status == 415
        body = json.loads(response.body)
        assert body["error"] == "invalid_request"
        assert response.headers["Accept"] == "application/x-www-form-urlencoded"

    @pytest.mark.asyncio
    async def test_form_urlencoded_is_accepted(self, provider):
        """The normal path is reached for form bodies."""
        provider.get_payload = AsyncMock(return_value={"grant_type": "nonsense"})
        response = await provider.token_request(_post_request())

        # Not a 415 — it got through to grant-type dispatch.
        assert response.status == 400
        assert json.loads(response.body)["error"] == "unsupported_grant_type"

    @pytest.mark.asyncio
    async def test_multipart_is_rejected(self, provider):
        response = await provider.token_request(
            _post_request(content_type="multipart/form-data")
        )
        assert response.status == 415

    @pytest.mark.asyncio
    async def test_content_type_is_case_insensitive(self, provider):
        provider.get_payload = AsyncMock(return_value={"grant_type": "nonsense"})
        response = await provider.token_request(
            _post_request(content_type="APPLICATION/X-WWW-FORM-URLENCODED")
        )
        assert response.status != 415

    @pytest.mark.asyncio
    async def test_missing_content_type_is_tolerated(self, provider):
        """An absent Content-Type must not 415 — keeps FEAT-093 tests green."""
        provider.get_payload = AsyncMock(return_value={"grant_type": "nonsense"})
        response = await provider.token_request(_post_request(content_type=""))
        assert response.status != 415


# ---------------------------------------------------------------------------
# client_secret_basic
# ---------------------------------------------------------------------------

def _basic(client_id, secret):
    raw = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {raw}"}


class TestClientSecretBasic:
    def test_client_secret_basic(self, provider):
        """RFC 8414 advertises Basic, so it must actually be accepted."""
        request = _post_request(headers=_basic("cli_abc", "s3cret"))
        merged = provider._merge_basic_auth(request, {"grant_type": "refresh_token"})

        assert merged["client_id"] == "cli_abc"
        assert merged["client_secret"] == "s3cret"
        assert merged["grant_type"] == "refresh_token"

    def test_body_credentials_win_over_basic(self, provider):
        """A Basic header must not override explicit body credentials."""
        request = _post_request(headers=_basic("from_header", "header_secret"))
        merged = provider._merge_basic_auth(
            request, {"client_id": "from_body", "client_secret": "body_secret"}
        )
        assert merged["client_id"] == "from_body"
        assert merged["client_secret"] == "body_secret"

    def test_basic_credentials_are_url_decoded(self, provider):
        """RFC 6749 §2.3.1 form-urlencodes both components."""
        request = _post_request(headers=_basic("cli%40app", "p%40ss+word"))
        merged = provider._merge_basic_auth(request, {})
        assert merged["client_id"] == "cli@app"
        assert merged["client_secret"] == "p@ss word"

    def test_secret_containing_colon_is_preserved(self, provider):
        request = _post_request(headers=_basic("cli", "a:b:c"))
        merged = provider._merge_basic_auth(request, {})
        assert merged["client_secret"] == "a:b:c"

    @pytest.mark.parametrize(
        "header",
        [
            {},
            {"Authorization": "Bearer sometoken"},
            {"Authorization": "Basic !!!not-base64!!!"},
            {"Authorization": "Basic " + base64.b64encode(b"nocolon").decode()},
        ],
    )
    def test_non_basic_or_malformed_headers_are_ignored(self, provider, header):
        """A malformed header is simply not credentials — never a crash."""
        payload = {"grant_type": "x"}
        assert provider._merge_basic_auth(_post_request(headers=header), payload) == payload

    def test_basic_is_wired_into_token_introspect_revoke(self):
        """All three endpoints RFC 8414 advertises must accept Basic."""
        import inspect

        for method in (
            Oauth2Provider.token_request,
            Oauth2Provider.introspect,
            Oauth2Provider.revoke,
        ):
            assert "_merge_basic_auth" in inspect.getsource(method), method.__name__


# ---------------------------------------------------------------------------
# RFC 8707 resource → aud
# ---------------------------------------------------------------------------

class TestResourceIndicator:
    @pytest.mark.parametrize(
        "uri",
        [
            "https://mcp.example.com",
            "https://mcp.example.com/tools",
            "https://mcp.example.com/path?q=1",
            "http://localhost:8080/mcp",
        ],
    )
    def test_valid_resource_uris(self, uri):
        assert validate_resource_uri(uri) is True

    @pytest.mark.parametrize(
        "uri",
        [
            "https://mcp.example.com/#frag",   # fragment forbidden
            "/relative/path",                  # not absolute
            "mcp.example.com",                 # no scheme
            "",
            None,
            12345,
        ],
    )
    def test_invalid_resource_uris(self, uri):
        assert validate_resource_uri(uri) is False

    def test_resource_param_aud(self, provider):
        """The canonical resource is reflected alongside the class marker."""
        assert provider._resource_audience("user", RESOURCE) == ["user", RESOURCE]
        assert provider._resource_audience("app", RESOURCE) == ["app", RESOURCE]

    def test_aud_unchanged_without_resource(self, provider):
        """No resource ⇒ the plain string aud FEAT-093 always emitted."""
        assert provider._resource_audience("user", None) == "user"
        assert provider._resource_audience("app", "") == "app"

    def test_resource_is_carried_on_the_authorization_code(self):
        from navigator_auth.backends.oauth2.models import (
            OAuthClient,
            OauthAuthorizationCode,
        )

        code = OauthAuthorizationCode(
            client=OAuthClient(client_id="c", client_name="C"),
            user_id=1,
            code="abc",
            redirect_uri="https://x/cb",
            scope="default",
            state="s",
            resource=RESOURCE,
        )
        assert code.resource == RESOURCE

    def test_resource_defaults_to_none_on_the_code(self):
        from navigator_auth.backends.oauth2.models import (
            OAuthClient,
            OauthAuthorizationCode,
        )

        code = OauthAuthorizationCode(
            client=OAuthClient(client_id="c", client_name="C"),
            user_id=1,
            code="abc",
            redirect_uri="https://x/cb",
            scope="default",
            state="s",
        )
        assert code.resource is None

    @pytest.mark.asyncio
    async def test_authorize_rejects_bad_resource(self, provider):
        """Bad values ⇒ invalid_target, before any client lookup."""
        provider.get_payload = AsyncMock(
            return_value={
                "response_type": "code",
                "resource": "https://mcp.example.com/#frag",
                "client_id": "cli",
            }
        )
        response = await provider.authorize(MagicMock())

        assert response.status == 400
        assert json.loads(response.body)["error"] == "invalid_target"

    def test_resource_survives_the_consent_hop(self):
        """The consent form must round-trip it, like the PKCE challenge."""
        from pathlib import Path

        template_path = (
            Path(__file__).resolve().parent.parent
            / "templates" / "oauth" / "consent.html"
        )
        template = template_path.read_text(encoding="utf-8")
        assert 'name="resource"' in template

    def test_issue_code_accepts_resource(self):
        import inspect

        signature = inspect.signature(Oauth2Provider._issue_code)
        assert "resource" in signature.parameters

    def test_token_exchange_validates_and_reflects(self):
        import inspect

        source = inspect.getsource(Oauth2Provider._handle_authorization_code)
        # Mismatch between the code's resource and the request's is refused.
        assert "invalid_target" in source
        assert "_resource_audience" in source


# ---------------------------------------------------------------------------
# WWW-Authenticate challenge
# ---------------------------------------------------------------------------

class _Auth:
    """Minimal stand-in exposing the real bearer_challenge implementation."""

    def __init__(self):
        from navigator_auth.auth import AuthHandler

        self.bearer_challenge = AuthHandler.bearer_challenge.__get__(self)


def _bearer_request(is_bearer=True, issuer="https://auth.example.com"):
    from navigator_auth.backends.api import BEARER_CHALLENGE_KEY

    store = {BEARER_CHALLENGE_KEY: is_bearer}
    request = MagicMock()
    request.get = store.get
    request.headers = {"Host": issuer.split("//")[1], "X-Forwarded-Proto": "https"}
    request.scheme = "https"
    return request


class TestWWWAuthenticateChallenge:
    def test_www_authenticate_challenge(self, monkeypatch):
        """Bearer 401s point the client at the PRM document."""
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.AUTH_ISSUER_URL",
            "https://auth.example.com",
        )
        headers = _Auth().bearer_challenge(_bearer_request())

        assert headers["WWW-Authenticate"] == (
            'Bearer resource_metadata='
            '"https://auth.example.com/.well-known/oauth-protected-resource"'
        )

    def test_challenge_leaks_no_failure_reason(self, monkeypatch):
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.AUTH_ISSUER_URL",
            "https://auth.example.com",
        )
        value = _Auth().bearer_challenge(_bearer_request())["WWW-Authenticate"]
        for leak in ("expired", "revoked", "invalid", "error", "signature"):
            assert leak not in value.lower()

    def test_no_challenge_for_non_bearer_requests(self, monkeypatch):
        """Session/cookie 401s get no bearer challenge they cannot act on."""
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.AUTH_ISSUER_URL",
            "https://auth.example.com",
        )
        assert _Auth().bearer_challenge(_bearer_request(is_bearer=False)) == {}

    def test_challenge_never_raises_without_issuer(self, monkeypatch):
        """A discovery convenience must never turn a 401 into a 500."""
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.AUTH_ISSUER_URL", ""
        )
        from navigator_auth.backends.api import BEARER_CHALLENGE_KEY

        # A request with no Host at all: the issuer cannot be derived.
        request = MagicMock()
        request.get = {BEARER_CHALLENGE_KEY: True}.get
        request.headers = {}
        request.scheme = ""
        request.url = None
        assert _Auth().bearer_challenge(request) == {}

    def test_middleware_decorates_every_401(self):
        """The challenge is applied once, at the middleware boundary."""
        import inspect
        from navigator_auth.auth import AuthHandler

        source = inspect.getsource(AuthHandler.auth_middleware)
        assert "HTTPUnauthorized" in source
        assert "bearer_challenge" in source

    def test_api_backend_marks_bearer_requests(self):
        import inspect
        from navigator_auth.backends.api import APIKeyAuth, BEARER_CHALLENGE_KEY

        assert BEARER_CHALLENGE_KEY
        source = inspect.getsource(APIKeyAuth.get_token_info)
        assert "BEARER_CHALLENGE_KEY" in source

    def test_middleware_does_not_clobber_existing_header(self):
        """An explicit WWW-Authenticate set upstream is preserved."""
        import inspect
        from navigator_auth.auth import AuthHandler

        source = inspect.getsource(AuthHandler.auth_middleware)
        assert "if header not in exc.headers" in source
