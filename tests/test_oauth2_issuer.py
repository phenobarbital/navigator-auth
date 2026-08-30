"""Tests for FEAT-095 TASK-038 — issuer identity + configuration foundation.

Covers:
  - ``AUTH_ISSUER_URL`` honoured verbatim when configured.
  - Derivation from the request when unset (scheme://host).
  - ``X-Forwarded-Proto`` / ``X-Forwarded-Host`` / ``Host`` (reverse-proxy safe).
  - https enforcement (plain http tolerated only for loopback hosts).
  - Presence + defaults of the full FEAT-095 configuration block (spec §6).
"""

from unittest.mock import MagicMock

import pytest
from aiohttp import web

from navigator_auth.backends.oauth2 import backend as oauth2_backend
from navigator_auth.backends.oauth2.backend import issuer_url


def _make_request(headers: dict = None, scheme: str = "http", netloc: str = ""):
    """Build a minimal mock request carrying only what issuer_url() reads."""
    req = MagicMock(spec=web.Request)
    req.headers = dict(headers or {})
    req.scheme = scheme
    url = MagicMock()
    url.netloc = netloc
    req.url = url
    return req


@pytest.fixture
def no_issuer_setting(monkeypatch):
    """Force AUTH_ISSUER_URL to be unset for the derivation tests."""
    monkeypatch.setattr(oauth2_backend, "AUTH_ISSUER_URL", "", raising=False)


# ---------------------------------------------------------------------------
# AUTH_ISSUER_URL configured
# ---------------------------------------------------------------------------

class TestIssuerFromSetting:
    """When AUTH_ISSUER_URL is configured it always wins."""

    def test_issuer_from_setting(self, monkeypatch):
        monkeypatch.setattr(
            oauth2_backend, "AUTH_ISSUER_URL", "https://auth.example.com",
            raising=False,
        )
        req = _make_request({"Host": "internal.local"}, scheme="http")
        assert issuer_url(req) == "https://auth.example.com"

    def test_setting_trailing_slash_stripped(self, monkeypatch):
        monkeypatch.setattr(
            oauth2_backend, "AUTH_ISSUER_URL", "https://auth.example.com/",
            raising=False,
        )
        assert issuer_url(None) == "https://auth.example.com"

    def test_setting_used_without_request(self, monkeypatch):
        """A static issuer makes the request argument optional."""
        monkeypatch.setattr(
            oauth2_backend, "AUTH_ISSUER_URL", "https://as.example.org",
            raising=False,
        )
        assert issuer_url() == "https://as.example.org"


# ---------------------------------------------------------------------------
# Derivation from the request
# ---------------------------------------------------------------------------

class TestIssuerDerivation:
    """AUTH_ISSUER_URL unset ⇒ derive scheme://host from the request."""

    def test_issuer_derived_from_request(self, no_issuer_setting):
        req = _make_request({"Host": "auth.example.com"}, scheme="https")
        assert issuer_url(req) == "https://auth.example.com"

    def test_issuer_derived_includes_port(self, no_issuer_setting):
        req = _make_request({"Host": "auth.example.com:8443"}, scheme="https")
        assert issuer_url(req) == "https://auth.example.com:8443"

    def test_issuer_falls_back_to_url_netloc(self, no_issuer_setting):
        req = _make_request({}, scheme="https", netloc="auth.example.com")
        assert issuer_url(req) == "https://auth.example.com"

    def test_no_request_and_no_setting_raises(self, no_issuer_setting):
        with pytest.raises(RuntimeError):
            issuer_url(None)

    def test_no_host_raises(self, no_issuer_setting):
        req = _make_request({}, scheme="https", netloc="")
        with pytest.raises(RuntimeError):
            issuer_url(req)


# ---------------------------------------------------------------------------
# Reverse-proxy headers
# ---------------------------------------------------------------------------

class TestIssuerProxyHeaders:
    """X-Forwarded-* must be honoured so the issuer matches the public URL."""

    def test_issuer_proxy_proto(self, no_issuer_setting):
        """TLS terminates at the proxy: request.scheme is http, issuer is https."""
        req = _make_request(
            {"X-Forwarded-Proto": "https", "Host": "auth.example.com"},
            scheme="http",
        )
        assert issuer_url(req) == "https://auth.example.com"

    def test_issuer_proxy_proto_first_value(self, no_issuer_setting):
        """A comma-joined X-Forwarded-Proto uses the first (client-most) value."""
        req = _make_request(
            {"X-Forwarded-Proto": "https, http", "Host": "auth.example.com"},
            scheme="http",
        )
        assert issuer_url(req) == "https://auth.example.com"

    def test_issuer_forwarded_host_wins_over_host(self, no_issuer_setting):
        req = _make_request(
            {
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "public.example.com",
                "Host": "internal.local:8080",
            },
            scheme="http",
        )
        assert issuer_url(req) == "https://public.example.com"


# ---------------------------------------------------------------------------
# https enforcement
# ---------------------------------------------------------------------------

class TestIssuerHttpsEnforcement:
    """RFC 8414 §2: the issuer identifier MUST use the https scheme."""

    def test_http_non_localhost_upgraded(self, no_issuer_setting):
        req = _make_request({"Host": "auth.example.com"}, scheme="http")
        assert issuer_url(req) == "https://auth.example.com"

    @pytest.mark.parametrize(
        "host",
        ["localhost:5000", "localhost", "127.0.0.1:8080", "[::1]:9000"],
    )
    def test_http_localhost_preserved(self, no_issuer_setting, host):
        """Loopback development keeps plain http."""
        req = _make_request({"Host": host}, scheme="http")
        assert issuer_url(req) == f"http://{host}"

    def test_localhost_https_preserved(self, no_issuer_setting):
        req = _make_request({"Host": "localhost:5000"}, scheme="https")
        assert issuer_url(req) == "https://localhost:5000"


# ---------------------------------------------------------------------------
# Configuration block (spec §6)
# ---------------------------------------------------------------------------

class TestFeat095Configuration:
    """Every spec §6 key exists with the documented default."""

    def test_all_keys_present(self):
        from navigator_auth import conf

        for key in (
            "AUTH_ISSUER_URL",
            "OAUTH_DCR_POLICY",
            "OAUTH_DCR_REDIRECT_ALLOWLIST",
            "OAUTH_DCR_DEFAULT_SCOPES",
            "OAUTH_DCR_GATE_NEW_CLIENTS",
            "OAUTH_DCR_RATE_LIMIT",
            "OAUTH_DCR_UNUSED_TTL",
            "OAUTH_UPSTREAM_IDP_BACKENDS",
            "OAUTH_UPSTREAM_FLOW_TTL",
            "OAUTH_ACCESS_GATE_ENABLED",
            "OAUTH_ACCESS_GATE_QUEUE",
            "OAUTH_JWT_SIGNING_ALG",
            "OAUTH_JWT_KEYS",
        ):
            assert hasattr(conf, key), f"missing FEAT-095 config key: {key}"

    def test_dcr_defaults(self):
        from navigator_auth import conf

        assert conf.OAUTH_DCR_POLICY == "open"
        assert conf.OAUTH_DCR_GATE_NEW_CLIENTS is True
        assert conf.OAUTH_DCR_UNUSED_TTL == 2592000
        assert conf.OAUTH_DCR_RATE_LIMIT == "10/hour"

    def test_claude_callbacks_allowlisted_by_default(self):
        from navigator_auth import conf

        assert (
            "https://claude.ai/api/mcp/auth_callback"
            in conf.OAUTH_DCR_REDIRECT_ALLOWLIST
        )
        assert (
            "https://claude.com/api/mcp/auth_callback"
            in conf.OAUTH_DCR_REDIRECT_ALLOWLIST
        )

    def test_upstream_and_gate_defaults(self):
        from navigator_auth import conf

        # Empty upstream list ⇒ current local-password behaviour preserved.
        assert conf.OAUTH_UPSTREAM_IDP_BACKENDS == []
        assert conf.OAUTH_UPSTREAM_FLOW_TTL == 600
        # Gate defaults OFF globally (opt-in per D3).
        assert conf.OAUTH_ACCESS_GATE_ENABLED is False
        # Approval queue on, but inert while no gate is enforced (D7).
        assert conf.OAUTH_ACCESS_GATE_QUEUE is True

    def test_signing_defaults_to_hs256(self):
        from navigator_auth import conf

        assert conf.OAUTH_JWT_SIGNING_ALG == "HS256"
        assert conf.OAUTH_JWT_KEYS == []

    def test_auth_token_issuer_semantics_unchanged(self):
        """AUTH_ISSUER_URL is additive: the JWT ``iss`` setting is untouched.

        ``AUTH_TOKEN_ISSUER`` keeps driving the JWT ``iss`` claim for every
        non-OAuth2 backend and is a *separate* setting from the RFC 8414
        issuer identifier — the two must never be aliased.
        """
        from navigator_auth import conf

        assert hasattr(conf, "AUTH_TOKEN_ISSUER")
        assert conf.AUTH_TOKEN_ISSUER  # deployment-configurable, never empty
        assert conf.AUTH_TOKEN_ISSUER is not conf.AUTH_ISSUER_URL
