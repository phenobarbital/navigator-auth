"""Tests for FEAT-095 TASK-040 — Dynamic Client Registration (RFC 7591).

Covers the matrix from spec §4:
  test_dcr_register_public_client, test_dcr_register_confidential,
  test_dcr_policy_allowlist, test_dcr_policy_disabled,
  test_dcr_invalid_metadata, test_dcr_rate_limit, test_dcr_client_born_gated
"""

from unittest.mock import MagicMock

import pytest

from navigator_auth.backends.oauth2.dcr import (
    DCRError,
    build_registration_response,
    parse_rate_limit,
    to_oauth_client,
    validate_registration,
)
from navigator_auth.backends.oauth2.models import (
    ClientRegistrationRequest,
    OAuthClient,
)

CLAUDE_CALLBACKS = [
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
]


@pytest.fixture
def claude_like_client_metadata():
    """An RFC 7591 body shaped exactly as Claude's connector sends it."""
    return {
        "client_name": "Claude",
        "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }


@pytest.fixture
def confidential_client_metadata():
    return {
        "client_name": "Backend Service",
        "redirect_uris": ["https://service.example.com/callback"],
        "token_endpoint_auth_method": "client_secret_post",
        "grant_types": ["authorization_code", "refresh_token"],
    }


# ---------------------------------------------------------------------------
# Public / confidential registration
# ---------------------------------------------------------------------------

class TestRegisterPublicClient:
    def test_dcr_register_public_client(self, claude_like_client_metadata):
        """token_endpoint_auth_method=none ⇒ public, and NO secret is minted."""
        reg = validate_registration(claude_like_client_metadata, "open", [])
        client = to_oauth_client(reg)

        assert isinstance(reg, ClientRegistrationRequest)
        assert isinstance(client, OAuthClient)
        assert client.client_type == "public"
        assert client.client_secret is None
        assert client.token_endpoint_auth_method == "none"
        assert client.redirect_uris == [
            "https://claude.ai/api/mcp/auth_callback"
        ]
        assert client.client_name == "Claude"

    def test_public_response_shape(self, claude_like_client_metadata):
        """RFC 7591 §3.2.1 body; client_secret absent for a public client."""
        reg = validate_registration(claude_like_client_metadata, "open", [])
        client = to_oauth_client(reg)
        body = build_registration_response(reg, client).model_dump(
            exclude_none=True
        )

        assert body["client_id"] == client.client_id
        assert "client_secret" not in body
        assert body["client_secret_expires_at"] == 0
        assert isinstance(body["client_id_issued_at"], int)
        assert body["client_id_issued_at"] > 0
        # Echo of the submitted metadata.
        assert body["redirect_uris"] == reg.redirect_uris
        assert body["token_endpoint_auth_method"] == "none"
        assert body["response_types"] == ["code"]

    def test_client_id_is_opaque_uid_not_int_pk(
        self, claude_like_client_metadata
    ):
        """The wire client_id is the opaque uid; the int PK stays internal."""
        reg = validate_registration(claude_like_client_metadata, "open", [])
        client = to_oauth_client(reg)
        assert isinstance(client.client_id, str)
        assert not client.client_id.isdigit()
        assert client.client_pk is None
        body = build_registration_response(reg, client).model_dump()
        assert "client_pk" not in body

    def test_client_ids_are_unique(self, claude_like_client_metadata):
        reg = validate_registration(claude_like_client_metadata, "open", [])
        ids = {to_oauth_client(reg).client_id for _ in range(25)}
        assert len(ids) == 25


class TestRegisterConfidentialClient:
    def test_dcr_register_confidential(self, confidential_client_metadata):
        """A secret is issued and never expires."""
        reg = validate_registration(confidential_client_metadata, "open", [])
        client = to_oauth_client(reg)

        assert client.client_type == "confidential"
        assert client.client_secret
        assert len(client.client_secret) >= 32

        body = build_registration_response(reg, client).model_dump(
            exclude_none=True
        )
        assert body["client_secret"] == client.client_secret
        assert body["client_secret_expires_at"] == 0

    @pytest.mark.asyncio
    async def test_dcr_persisted_via_client_storage(
        self, confidential_client_metadata
    ):
        """Round-trips through the memory tier of ClientStorage."""
        from navigator_auth.backends.oauth2.client_backend import (
            MemoryClientStorage,
        )

        reg = validate_registration(confidential_client_metadata, "open", [])
        client = to_oauth_client(reg)
        storage = MemoryClientStorage()

        assert await storage.save_client(client) is True
        loaded = await storage.get_client(client.client_id)

        assert loaded is not None
        assert loaded.client_id == client.client_id
        assert loaded.client_type == "confidential"
        assert loaded.registration_source == "dcr"


# ---------------------------------------------------------------------------
# Policy knob: open / allowlist / disabled
# ---------------------------------------------------------------------------

class TestRegistrationPolicy:
    def test_dcr_policy_disabled(self, claude_like_client_metadata):
        with pytest.raises(DCRError) as exc:
            validate_registration(claude_like_client_metadata, "disabled", [])
        assert exc.value.error == "registration_not_supported"
        assert exc.value.status == 400

    def test_dcr_policy_allowlist_claude_passes_by_default(
        self, claude_like_client_metadata
    ):
        """The shipped defaults let Claude register out of the box."""
        reg = validate_registration(
            claude_like_client_metadata, "allowlist", CLAUDE_CALLBACKS
        )
        assert reg.redirect_uris == [
            "https://claude.ai/api/mcp/auth_callback"
        ]

    def test_dcr_policy_allowlist_rejects_non_matching(self):
        with pytest.raises(DCRError) as exc:
            validate_registration(
                {"redirect_uris": ["https://evil.example.com/cb"]},
                "allowlist",
                CLAUDE_CALLBACKS,
            )
        assert exc.value.error == "invalid_client_metadata"

    def test_dcr_policy_allowlist_supports_globs(self):
        reg = validate_registration(
            {"redirect_uris": ["https://app.partner.com/oauth/cb"]},
            "allowlist",
            ["https://*.partner.com/*"],
        )
        assert reg.redirect_uris

    def test_dcr_policy_allowlist_empty_patterns_refuses(self):
        """Restricted mode with nothing configured must fail closed."""
        with pytest.raises(DCRError):
            validate_registration(
                {"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]},
                "allowlist",
                [],
            )

    def test_dcr_policy_open_accepts_anything_https(self):
        reg = validate_registration(
            {"redirect_uris": ["https://anything.example.org/cb"]}, "open", []
        )
        assert reg.redirect_uris

    def test_policy_is_case_insensitive(self, claude_like_client_metadata):
        with pytest.raises(DCRError):
            validate_registration(claude_like_client_metadata, "DISABLED", [])


# ---------------------------------------------------------------------------
# Metadata validation
# ---------------------------------------------------------------------------

class TestInvalidMetadata:
    def test_dcr_invalid_metadata_missing_redirect_uris(self):
        with pytest.raises(DCRError) as exc:
            validate_registration({"client_name": "X"}, "open", [])
        assert exc.value.error == "invalid_client_metadata"

    def test_dcr_invalid_metadata_empty_redirect_uris(self):
        with pytest.raises(DCRError) as exc:
            validate_registration({"redirect_uris": []}, "open", [])
        assert exc.value.error == "invalid_client_metadata"

    def test_dcr_invalid_metadata_http_uri(self):
        with pytest.raises(DCRError) as exc:
            validate_registration(
                {"redirect_uris": ["http://evil.example.com/cb"]}, "open", []
            )
        assert exc.value.error == "invalid_client_metadata"
        assert "https" in exc.value.description

    def test_localhost_http_allowed_for_development(self):
        for uri in (
            "http://localhost:8080/cb",
            "http://127.0.0.1:3000/callback",
        ):
            reg = validate_registration({"redirect_uris": [uri]}, "open", [])
            assert reg.redirect_uris == [uri]

    def test_dcr_invalid_metadata_bad_grant_type(self):
        with pytest.raises(DCRError) as exc:
            validate_registration(
                {
                    "redirect_uris": ["https://x.example.com/cb"],
                    "grant_types": ["implicit"],
                },
                "open",
                [],
            )
        assert exc.value.error == "invalid_client_metadata"
        assert "implicit" in exc.value.description

    def test_invalid_response_type_rejected(self):
        """OAuth 2.1 removed the implicit flow: code only."""
        with pytest.raises(DCRError):
            validate_registration(
                {
                    "redirect_uris": ["https://x.example.com/cb"],
                    "response_types": ["token"],
                },
                "open",
                [],
            )

    def test_invalid_auth_method_rejected(self):
        with pytest.raises(DCRError):
            validate_registration(
                {
                    "redirect_uris": ["https://x.example.com/cb"],
                    "token_endpoint_auth_method": "private_key_jwt",
                },
                "open",
                [],
            )

    def test_relative_uri_rejected(self):
        with pytest.raises(DCRError):
            validate_registration({"redirect_uris": ["/callback"]}, "open", [])

    def test_fragment_in_redirect_uri_rejected(self):
        """RFC 6749 §3.1.2 forbids fragments in redirect URIs."""
        with pytest.raises(DCRError):
            validate_registration(
                {"redirect_uris": ["https://x.example.com/cb#frag"]}, "open", []
            )

    def test_wildcard_redirect_uri_rejected(self):
        with pytest.raises(DCRError):
            validate_registration(
                {"redirect_uris": ["https://*.example.com/cb"]}, "open", []
            )

    def test_non_object_body_rejected(self):
        with pytest.raises(DCRError) as exc:
            validate_registration(["not", "an", "object"], "open", [])
        assert exc.value.error == "invalid_client_metadata"

    def test_unknown_members_are_ignored(self, claude_like_client_metadata):
        """RFC 7591 §2 permits metadata the server does not understand."""
        body = {**claude_like_client_metadata, "software_id": "abc", "x": 1}
        reg = validate_registration(body, "open", [])
        assert reg.client_name == "Claude"


# ---------------------------------------------------------------------------
# Access gate + scopes
# ---------------------------------------------------------------------------

class TestGateAndScopes:
    def test_dcr_client_born_gated(self, claude_like_client_metadata):
        reg = validate_registration(claude_like_client_metadata, "open", [])
        client = to_oauth_client(reg, gate_new_clients=True)
        assert client.enforce_access_gate is True
        assert client.registration_source == "dcr"

    def test_gate_flag_off_when_configured_off(
        self, claude_like_client_metadata
    ):
        reg = validate_registration(claude_like_client_metadata, "open", [])
        assert to_oauth_client(reg, gate_new_clients=False).enforce_access_gate is False

    def test_requested_scope_is_used(self):
        reg = validate_registration(
            {
                "redirect_uris": ["https://x.example.com/cb"],
                "scope": "profile email",
            },
            "open",
            [],
        )
        client = to_oauth_client(reg, default_scopes=["default"])
        assert client.default_scopes == ["profile", "email"]

    def test_default_scopes_applied_when_none_requested(self):
        reg = validate_registration(
            {"redirect_uris": ["https://x.example.com/cb"]}, "open", []
        )
        client = to_oauth_client(reg, default_scopes=["default", "profile"])
        assert client.default_scopes == ["default", "profile"]

    def test_grant_types_mapped_to_allowed_grant_types(self):
        reg = validate_registration(
            {
                "redirect_uris": ["https://x.example.com/cb"],
                "grant_types": ["authorization_code"],
            },
            "open",
            [],
        )
        assert to_oauth_client(reg).allowed_grant_types == ["authorization_code"]

    def test_anonymous_client_has_no_owner(self, claude_like_client_metadata):
        """DCR registration is anonymous — no owning user is invented."""
        reg = validate_registration(claude_like_client_metadata, "open", [])
        assert to_oauth_client(reg).user is None

    def test_missing_client_name_gets_placeholder(self):
        reg = validate_registration(
            {"redirect_uris": ["https://x.example.com/cb"]}, "open", []
        )
        client = to_oauth_client(reg)
        assert client.client_name.startswith("dcr-client-")


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimitParsing:
    @pytest.mark.parametrize(
        "spec,expected",
        [
            ("10/hour", (10, 3600)),
            ("5/minute", (5, 60)),
            ("100/day", (100, 86400)),
            ("2/second", (2, 1)),
            ("10/hours", (10, 3600)),
        ],
    )
    def test_parse_rate_limit(self, spec, expected):
        assert parse_rate_limit(spec) == expected

    @pytest.mark.parametrize(
        "spec", ["", None, "garbage", "10/fortnight", "0/hour", "-1/hour"]
    )
    def test_unparseable_disables_limiting(self, spec):
        """A malformed setting must not take the endpoint down."""
        assert parse_rate_limit(spec) == (0, 0)


class _FakeRedis:
    """Minimal INCR/EXPIRE counter."""

    def __init__(self, fail=False):
        self.counters = {}
        self.expires = {}
        self.fail = fail

    async def incr(self, key):
        if self.fail:
            raise RuntimeError("redis down")
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

    async def expire(self, key, ttl):
        self.expires[key] = ttl
        return True


@pytest.fixture
def provider_with_redis():
    from navigator_auth.backends.oauth2.backend import Oauth2Provider

    provider = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    provider.code_storage = MagicMock()
    provider.code_storage.redis = _FakeRedis()
    return provider


def _request(ip="203.0.113.7"):
    request = MagicMock()
    request.headers = {"X-Forwarded-For": ip}
    request.remote = ip
    return request


class TestRateLimitEnforcement:
    @pytest.mark.asyncio
    async def test_dcr_rate_limit(self, provider_with_redis, monkeypatch):
        """The (N+1)th registration from one source is refused."""
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.OAUTH_DCR_RATE_LIMIT",
            "3/hour",
        )
        request = _request()
        results = [
            await provider_with_redis._check_dcr_rate_limit(request)
            for _ in range(4)
        ]
        assert results == [True, True, True, False]

    @pytest.mark.asyncio
    async def test_rate_limit_is_per_source_ip(
        self, provider_with_redis, monkeypatch
    ):
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.OAUTH_DCR_RATE_LIMIT",
            "1/hour",
        )
        assert await provider_with_redis._check_dcr_rate_limit(
            _request("198.51.100.1")
        ) is True
        # A different source still has its own budget.
        assert await provider_with_redis._check_dcr_rate_limit(
            _request("198.51.100.2")
        ) is True
        assert await provider_with_redis._check_dcr_rate_limit(
            _request("198.51.100.1")
        ) is False

    @pytest.mark.asyncio
    async def test_window_ttl_set_once(self, provider_with_redis, monkeypatch):
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.OAUTH_DCR_RATE_LIMIT",
            "5/minute",
        )
        request = _request()
        await provider_with_redis._check_dcr_rate_limit(request)
        await provider_with_redis._check_dcr_rate_limit(request)
        assert list(provider_with_redis.code_storage.redis.expires.values()) == [60]

    @pytest.mark.asyncio
    async def test_rate_limit_fails_open_when_redis_down(
        self, provider_with_redis, monkeypatch
    ):
        """A broken cache must not make the AS unregisterable."""
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.OAUTH_DCR_RATE_LIMIT",
            "1/hour",
        )
        provider_with_redis.code_storage.redis = _FakeRedis(fail=True)
        assert await provider_with_redis._check_dcr_rate_limit(_request()) is True

    @pytest.mark.asyncio
    async def test_disabled_limit_always_allows(
        self, provider_with_redis, monkeypatch
    ):
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.OAUTH_DCR_RATE_LIMIT", ""
        )
        request = _request()
        for _ in range(50):
            assert await provider_with_redis._check_dcr_rate_limit(request) is True


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

class TestRegisterRoute:
    def test_register_route_is_public(self):
        """/oauth2/register must be POST and bypass authentication (D1)."""
        from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY
        from navigator_auth.backends.oauth2.backend import Oauth2Provider
        from navigator_auth.backends.abstract import BaseAuthBackend

        provider = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
        routes = []
        exclude = []
        router = MagicMock()
        router.add_route.side_effect = lambda m, p, h, name=None: routes.append(
            (m, p)
        )
        app = MagicMock()
        app.router = router
        app.__getitem__.side_effect = lambda k: exclude
        app.__setitem__.side_effect = lambda k, v: None

        original = BaseAuthBackend.configure
        BaseAuthBackend.configure = lambda self, _app: None
        try:
            provider.configure(app)
        finally:
            BaseAuthBackend.configure = original

        assert ("POST", "/oauth2/register") in routes
        assert "/oauth2/register" in exclude


# ---------------------------------------------------------------------------
# Unused-DCR-client reaper
# ---------------------------------------------------------------------------

class TestUnusedClientReaper:
    @pytest.mark.asyncio
    async def test_reaper_removes_old_unused_dcr_client(self):
        from datetime import datetime, timedelta
        from navigator_auth.backends.oauth2.client_backend import (
            MemoryClientStorage,
        )

        storage = MemoryClientStorage()
        old = to_oauth_client(
            validate_registration(
                {"redirect_uris": ["https://x.example.com/cb"]}, "open", []
            )
        )
        old.created_at = datetime.now() - timedelta(days=60)
        await storage.save_client(old)

        async def never_used(_uid):
            return False

        removed = await storage.reap_unused_dcr_clients(
            2592000, is_used=never_used
        )
        assert removed == 1
        assert await storage.get_client(old.client_id) is None

    @pytest.mark.asyncio
    async def test_reaper_spares_used_and_static_and_fresh_clients(self):
        from datetime import datetime, timedelta
        from navigator_auth.backends.oauth2.client_backend import (
            MemoryClientStorage,
        )

        storage = MemoryClientStorage()

        used = to_oauth_client(
            validate_registration(
                {"redirect_uris": ["https://used.example.com/cb"]}, "open", []
            )
        )
        used.created_at = datetime.now() - timedelta(days=60)

        fresh = to_oauth_client(
            validate_registration(
                {"redirect_uris": ["https://fresh.example.com/cb"]}, "open", []
            )
        )

        static = OAuthClient(
            client_id="static-1",
            client_name="Operator Provisioned",
            created_at=datetime.now() - timedelta(days=365),
        )

        for client in (used, fresh, static):
            await storage.save_client(client)

        async def is_used(uid):
            return uid == used.client_id

        removed = await storage.reap_unused_dcr_clients(
            2592000, is_used=is_used
        )
        assert removed == 0
        for client in (used, fresh, static):
            assert await storage.get_client(client.client_id) is not None

    @pytest.mark.asyncio
    async def test_reaper_never_deletes_when_usage_unknown(self):
        """Unknown usage must fail safe (never delete)."""
        from datetime import datetime, timedelta
        from navigator_auth.backends.oauth2.client_backend import (
            MemoryClientStorage,
        )

        storage = MemoryClientStorage()
        client = to_oauth_client(
            validate_registration(
                {"redirect_uris": ["https://x.example.com/cb"]}, "open", []
            )
        )
        client.created_at = datetime.now() - timedelta(days=90)
        await storage.save_client(client)

        async def unknown(_uid):
            return True

        assert await storage.reap_unused_dcr_clients(60, is_used=unknown) == 0
        assert await storage.get_client(client.client_id) is not None
