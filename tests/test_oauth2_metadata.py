"""Tests for FEAT-095 TASK-039 — RFC 8414 / RFC 9728 discovery documents.

Covers:
  - the full RFC 8414 field set and its conditional members
    (``registration_endpoint``, ``jwks_uri``, ``scopes_supported``);
  - the RFC 9728 protected-resource document;
  - the builders being importable and usable with no aiohttp/server context
    (spec D6: ai-parrot MCP mounts consume the PRM builder standalone);
  - the well-known routes: registered at the origin root, aliased under the AS
    path, unauthenticated (exclude list), JSON, and served from cache.
"""

from unittest.mock import MagicMock

import pytest
from aiohttp import web

from navigator_auth.backends.oauth2.metadata import (
    DEFAULT_GRANT_TYPES_SUPPORTED,
    WELL_KNOWN_AS_PATH,
    WELL_KNOWN_PRM_PATH,
    build_as_metadata,
    build_protected_resource_metadata,
)

ISSUER = "https://auth.example.com"


# ---------------------------------------------------------------------------
# RFC 8414 — authorization server metadata
# ---------------------------------------------------------------------------

@pytest.fixture
def as_doc():
    return build_as_metadata(
        ISSUER,
        dcr_enabled=True,
        jwks=False,
        grant_types=DEFAULT_GRANT_TYPES_SUPPORTED,
        scopes=["default", "profile", "email", "offline_access"],
    )


class TestASMetadataDocument:
    """The document Claude's connector infrastructure reads first."""

    def test_as_metadata_document(self, as_doc):
        """All mandatory RFC 8414 members are present and absolute."""
        for field in (
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "introspection_endpoint",
            "revocation_endpoint",
            "device_authorization_endpoint",
            "response_types_supported",
            "grant_types_supported",
            "code_challenge_methods_supported",
            "token_endpoint_auth_methods_supported",
        ):
            assert field in as_doc, f"missing RFC 8414 field: {field}"
        for field, value in as_doc.items():
            if field.endswith("_endpoint") or field in ("issuer", "jwks_uri"):
                assert value.startswith("https://"), f"{field} must be absolute https"

    def test_issuer_matches_setting(self, as_doc):
        """RFC 8414 §2: issuer identifies the AS and anchors every endpoint."""
        assert as_doc["issuer"] == ISSUER
        assert as_doc["authorization_endpoint"] == f"{ISSUER}/oauth2/authorize"
        assert as_doc["token_endpoint"] == f"{ISSUER}/oauth2/token"
        assert as_doc["registration_endpoint"] == f"{ISSUER}/oauth2/register"

    def test_issuer_trailing_slash_normalised(self):
        doc = build_as_metadata(
            "https://auth.example.com/", dcr_enabled=True, jwks=False,
            grant_types=["authorization_code"], scopes=[],
        )
        assert doc["issuer"] == ISSUER
        assert doc["token_endpoint"] == f"{ISSUER}/oauth2/token"

    def test_s256_only(self, as_doc):
        """OAuth 2.1 forbids the ``plain`` PKCE transform."""
        assert as_doc["code_challenge_methods_supported"] == ["S256"]

    def test_response_types_code_only(self, as_doc):
        """Implicit/hybrid flows are not offered."""
        assert as_doc["response_types_supported"] == ["code"]

    def test_token_endpoint_auth_methods(self, as_doc):
        methods = as_doc["token_endpoint_auth_methods_supported"]
        assert "client_secret_post" in methods
        assert "client_secret_basic" in methods
        assert "none" in methods  # public clients (Claude registers as one)

    def test_grant_types_advertised(self, as_doc):
        grants = as_doc["grant_types_supported"]
        assert "authorization_code" in grants
        assert "refresh_token" in grants
        assert "urn:ietf:params:oauth:grant-type:device_code" in grants

    def test_scopes_supported_from_registry(self, as_doc):
        assert as_doc["scopes_supported"] == [
            "default", "profile", "email", "offline_access"
        ]

    def test_scopes_omitted_when_empty(self):
        """An empty registry means "unconstrained", not "no scopes"."""
        doc = build_as_metadata(
            ISSUER, dcr_enabled=True, jwks=False,
            grant_types=["authorization_code"], scopes=[],
        )
        assert "scopes_supported" not in doc

    def test_builder_returns_copies(self, as_doc):
        """Mutating the returned document must not poison the module defaults."""
        as_doc["grant_types_supported"].append("mutated")
        assert "mutated" not in DEFAULT_GRANT_TYPES_SUPPORTED


class TestASMetadataConditionalFields:
    """Conditional members must track configuration exactly."""

    def test_as_metadata_no_dcr(self):
        """policy=disabled ⇒ no registration_endpoint (never advertise a 400)."""
        doc = build_as_metadata(
            ISSUER, dcr_enabled=False, jwks=False,
            grant_types=["authorization_code"], scopes=[],
        )
        assert "registration_endpoint" not in doc

    def test_as_metadata_dcr_enabled(self):
        doc = build_as_metadata(
            ISSUER, dcr_enabled=True, jwks=False,
            grant_types=["authorization_code"], scopes=[],
        )
        assert doc["registration_endpoint"] == f"{ISSUER}/oauth2/register"

    def test_as_metadata_jwks_conditional(self):
        """jwks_uri appears only when a key registry is loaded."""
        without = build_as_metadata(
            ISSUER, dcr_enabled=True, jwks=False,
            grant_types=["authorization_code"], scopes=[],
        )
        assert "jwks_uri" not in without

        with_keys = build_as_metadata(
            ISSUER, dcr_enabled=True, jwks=True,
            grant_types=["authorization_code"], scopes=[],
        )
        assert with_keys["jwks_uri"] == f"{ISSUER}/oauth2/jwks"

    def test_custom_endpoint_paths(self):
        """Deployments that relocate an endpoint stay self-consistent."""
        doc = build_as_metadata(
            ISSUER, dcr_enabled=True, jwks=False,
            grant_types=["authorization_code"], scopes=[],
            paths={"token_endpoint": "/custom/token"},
        )
        assert doc["token_endpoint"] == f"{ISSUER}/custom/token"
        assert doc["authorization_endpoint"] == f"{ISSUER}/oauth2/authorize"


# ---------------------------------------------------------------------------
# RFC 9728 — protected resource metadata
# ---------------------------------------------------------------------------

class TestProtectedResourceMetadata:

    def test_prm_document(self):
        doc = build_protected_resource_metadata(
            resource="https://mcp.example.com",
            auth_servers=[ISSUER],
            scopes=["default", "profile"],
        )
        assert doc["resource"] == "https://mcp.example.com"
        assert doc["authorization_servers"] == [ISSUER]
        assert doc["bearer_methods_supported"] == ["header"]
        assert doc["scopes_supported"] == ["default", "profile"]

    def test_prm_scopes_omitted_when_empty(self):
        doc = build_protected_resource_metadata(
            resource="https://mcp.example.com", auth_servers=[ISSUER], scopes=[],
        )
        assert "scopes_supported" not in doc

    def test_prm_normalises_trailing_slashes(self):
        doc = build_protected_resource_metadata(
            resource="https://mcp.example.com/",
            auth_servers=["https://auth.example.com/"],
            scopes=[],
        )
        assert doc["resource"] == "https://mcp.example.com"
        assert doc["authorization_servers"] == [ISSUER]

    def test_prm_builder_importable_standalone(self):
        """D6: ai-parrot MCP mounts import the builder with no server context.

        The metadata module must not drag aiohttp (or any framework) in.
        """
        import importlib
        import sys

        module_name = "navigator_auth.backends.oauth2.metadata"
        module = importlib.import_module(module_name)
        with open(module.__file__, encoding="utf-8") as handle:
            source = handle.read()
        assert "import aiohttp" not in source
        assert "from aiohttp" not in source
        # And it is callable with plain data only:
        assert build_protected_resource_metadata("https://r", ["https://a"], [])
        assert module_name in sys.modules


# ---------------------------------------------------------------------------
# Routes on Oauth2Provider
# ---------------------------------------------------------------------------

class _RecordingRouter:
    """Captures add_route() calls without standing up an application."""

    def __init__(self):
        self.routes = []

    def add_route(self, method, path, handler, name=None):
        self.routes.append({"method": method, "path": path,
                            "handler": handler, "name": name})


@pytest.fixture
def configured_provider():
    """Run Oauth2Provider.configure() against a recording router/app."""
    from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY
    from navigator_auth.backends.oauth2.backend import Oauth2Provider

    provider = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    router = _RecordingRouter()
    app = {AUTH_EXCLUDE_LIST_KEY: []}
    fake_app = MagicMock()
    fake_app.router = router
    fake_app.__getitem__.side_effect = app.__getitem__
    fake_app.__setitem__.side_effect = app.__setitem__
    # configure() ends in BaseAuthBackend.configure(); short-circuit it.
    from navigator_auth.backends.abstract import BaseAuthBackend

    original = BaseAuthBackend.configure
    BaseAuthBackend.configure = lambda self, _app: None
    try:
        provider.configure(fake_app)
    finally:
        BaseAuthBackend.configure = original
    return provider, router, app[AUTH_EXCLUDE_LIST_KEY]


class TestWellKnownRoutes:

    def test_wellknown_routes_registered_at_origin_root(self, configured_provider):
        """RFC 8414 §3: the document lives at the origin root."""
        _, router, _ = configured_provider
        paths = {r["path"] for r in router.routes}
        assert WELL_KNOWN_AS_PATH in paths
        assert WELL_KNOWN_PRM_PATH in paths

    def test_wellknown_aliases_under_as_path(self, configured_provider):
        """Prefix-mounted deployments also get the documents under /oauth2."""
        _, router, _ = configured_provider
        paths = {r["path"] for r in router.routes}
        assert f"/oauth2{WELL_KNOWN_AS_PATH}" in paths
        assert f"/oauth2{WELL_KNOWN_PRM_PATH}" in paths

    def test_wellknown_routes_are_get_only(self, configured_provider):
        _, router, _ = configured_provider
        for route in router.routes:
            if ".well-known" in route["path"]:
                assert route["method"] == "GET"

    def test_wellknown_routes_excluded_from_auth(self, configured_provider):
        """Discovery must answer unauthenticated."""
        _, _, exclude_list = configured_provider
        assert WELL_KNOWN_AS_PATH in exclude_list
        assert WELL_KNOWN_PRM_PATH in exclude_list
        assert f"/oauth2{WELL_KNOWN_AS_PATH}" in exclude_list
        assert f"/oauth2{WELL_KNOWN_PRM_PATH}" in exclude_list


def _mock_request(issuer_host="auth.example.com"):
    req = MagicMock(spec=web.Request)
    req.headers = {"Host": issuer_host, "X-Forwarded-Proto": "https"}
    req.scheme = "https"
    return req


class TestMetadataHandlers:

    @pytest.mark.asyncio
    async def test_as_metadata_handler_serves_json(self, configured_provider):
        provider, _, _ = configured_provider
        response = await provider.as_metadata(_mock_request())
        assert response.status == 200
        assert response.content_type == "application/json"

    @pytest.mark.asyncio
    async def test_prm_metadata_handler_serves_json(self, configured_provider):
        provider, _, _ = configured_provider
        response = await provider.protected_resource_metadata(_mock_request())
        assert response.status == 200
        assert response.content_type == "application/json"

    @pytest.mark.asyncio
    async def test_documents_are_cached_per_issuer(self, configured_provider):
        """Repeated discovery must not rebuild — it is on Claude's hot path."""
        provider, _, _ = configured_provider
        assert provider._metadata_cache == {}
        await provider.as_metadata(_mock_request())
        assert "https://auth.example.com" in provider._metadata_cache
        first = provider._metadata_cache["https://auth.example.com"]["as"]
        await provider.as_metadata(_mock_request())
        assert provider._metadata_cache["https://auth.example.com"]["as"] is first
        # A different host gets its own entry (multi-host deployments).
        await provider.as_metadata(_mock_request("other.example.com"))
        assert "https://other.example.com" in provider._metadata_cache

    @pytest.mark.asyncio
    async def test_handler_document_issuer_matches_request_host(
        self, configured_provider, monkeypatch
    ):
        from navigator_auth.backends.oauth2 import backend as oauth2_backend

        monkeypatch.setattr(oauth2_backend, "AUTH_ISSUER_URL", "", raising=False)
        provider, _, _ = configured_provider
        await provider.as_metadata(_mock_request("proxy.example.com"))
        doc = provider._metadata_cache["https://proxy.example.com"]["as"]
        assert doc["issuer"] == "https://proxy.example.com"

    def test_dcr_and_jwks_flags_read_config(self, configured_provider, monkeypatch):
        from navigator_auth.backends.oauth2 import backend as oauth2_backend

        provider, _, _ = configured_provider
        monkeypatch.setattr(oauth2_backend, "OAUTH_DCR_POLICY", "disabled")
        assert provider._dcr_enabled() is False
        monkeypatch.setattr(oauth2_backend, "OAUTH_DCR_POLICY", "open")
        assert provider._dcr_enabled() is True
        monkeypatch.setattr(oauth2_backend, "OAUTH_JWT_KEYS", [])
        assert provider._jwks_enabled() is False
        monkeypatch.setattr(oauth2_backend, "OAUTH_JWT_KEYS", [{"kid": "k1"}])
        assert provider._jwks_enabled() is True
