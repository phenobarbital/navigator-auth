"""
Shared test fixtures for navigator-auth tests.

Tenant fixtures for FEAT-092 per-tenant policy scoping tests are included here.
OAuth2 3LO fixtures for FEAT-093 integration tests are also included here.
"""
import pytest
from unittest.mock import MagicMock
from aiohttp import web

from navigator_auth.abac.policies.adapter import PolicyAdapter
from navigator_auth.abac.policies.evaluator import PolicyEvaluator
from navigator_auth.abac.context import EvalContext


# ---------------------------------------------------------------------------
# Generic request factory
# ---------------------------------------------------------------------------

@pytest.fixture
def make_request():
    """Return a factory that creates a mock web.Request."""
    def _factory(
        path: str = "/api/v1/test",
        method: str = "GET",
        headers: dict = None,
    ) -> MagicMock:
        req = MagicMock(spec=web.Request)
        req.path = path
        req.method = method
        req.path_qs = path
        req.rel_url = path
        req.remote = "127.0.0.1"
        _headers = {"referer": "http://localhost"}
        if headers:
            _headers.update(headers)
        req.headers = _headers
        req.is_authenticated = True
        return req

    return _factory


# ---------------------------------------------------------------------------
# Tenant fixtures (FEAT-092)
# ---------------------------------------------------------------------------

@pytest.fixture
def tenant_policies():
    """
    Three policy dicts for tenant-scoping integration tests.

    - global_tools:   org_id=1 / client_id=1  →  allow all tenants tool:*
    - t5_block_jira:  org_id=5 / client_id=1  →  enforcing deny jira for tenant 5
    """
    return [
        {
            "name": "global_tools",
            "effect": "ALLOW",
            "policy_type": "policy",
            "resource": ["tool:*"],
            "actions": ["tool:execute"],
            "groups": ["engineering"],
            "priority": 1,
            "org_id": 1,
            "client_id": 1,
        },
        {
            "name": "t5_block_jira",
            "effect": "DENY",
            "policy_type": "policy",
            "resource": ["tool:jira_*"],
            "actions": ["tool:execute"],
            "groups": ["engineering"],
            "priority": 10,
            "enforcing": True,
            "org_id": 5,
            "client_id": 1,
        },
    ]


@pytest.fixture
def engineering_userinfo():
    """Userinfo dict for an engineering group member."""
    return {
        "username": "alice",
        "groups": ["engineering"],
        "roles": [],
    }


@pytest.fixture
def ctx_tenant_5(make_request, engineering_userinfo):
    """EvalContext whose userinfo carries org_id=5, client_id=1."""
    userinfo = {**engineering_userinfo, "org_id": 5, "client_id": 1}
    return EvalContext(make_request(), None, userinfo, None)


@pytest.fixture
def ctx_tenant_7(make_request, engineering_userinfo):
    """EvalContext whose userinfo carries org_id=7, client_id=1."""
    userinfo = {**engineering_userinfo, "org_id": 7, "client_id": 1}
    return EvalContext(make_request(), None, userinfo, None)


@pytest.fixture
def ctx_no_tenant(make_request, engineering_userinfo):
    """EvalContext with no tenant info (falls back to global 1/1)."""
    return EvalContext(make_request(), None, engineering_userinfo, None)


def build_evaluator_from_dicts(policy_dicts: list) -> PolicyEvaluator:
    """Helper: adapt policy dicts and load into a fresh PolicyEvaluator."""
    resource_policies, _ = PolicyAdapter.adapt_batch(policy_dicts)
    ev = PolicyEvaluator()
    ev.load_policies(resource_policies)
    return ev


# ---------------------------------------------------------------------------
# OAuth2 3LO fixtures (FEAT-093 TASK-031)
# ---------------------------------------------------------------------------


class MemoryAuthCodeStorage:
    """In-memory authorization code store for tests (no Redis required)."""

    def __init__(self):
        self._codes: dict = {}
        self.prefix = "oauth2:code:"

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


class MemoryRefreshTokenStorage:
    """In-memory refresh token store for tests.

    Mirrors RefreshTokenStorage API but uses memory instead of Redis.
    Key: token.refresh_token (string value of the OauthRefreshToken).
    """

    def __init__(self):
        self._tokens: dict = {}
        self._user_index: dict = {}  # user_id -> set of refresh_token strings
        self.prefix = "oauth2:refresh:"
        self.user_index_prefix = "oauth2:refresh:user:"

    async def save_token(self, token) -> bool:
        self._tokens[token.refresh_token] = token
        user_id = str(token.user_id) if token.user_id else ""
        if user_id:
            self._user_index.setdefault(user_id, set()).add(token.refresh_token)
        return True

    async def get_token(self, token_str: str):
        return self._tokens.get(token_str)

    async def revoke_token(self, token_str: str, reason: str = "revoked") -> bool:
        entry = self._tokens.get(token_str)
        if entry:
            entry.revoked = True
            entry.revoked_reason = reason
            return True
        return False

    async def revoke_chain(self, token_str: str) -> bool:
        """Revoke all tokens derived from the same root."""
        entry = self._tokens.get(token_str)
        if not entry:
            return False
        user_id = str(entry.user_id) if entry.user_id else ""
        for t in list(self._user_index.get(user_id, [])):
            await self.revoke_token(t, "cascade")
        return True

    async def delete_token(self, token_str: str) -> bool:
        self._tokens.pop(token_str, None)
        return True

    async def list_tokens(self, user_id) -> list:
        token_keys = self._user_index.get(str(user_id), set())
        return [self._tokens[k] for k in token_keys if k in self._tokens]


class MemoryGrantStorage:
    """In-memory grant (consent) store for tests."""

    def __init__(self):
        self._grants: dict = {}

    def _key(self, user_id, client_id):
        return f"{user_id}:{client_id}"

    async def save_grant(self, grant) -> bool:
        key = self._key(grant.user_id, grant.client_id)
        self._grants[key] = grant
        return True

    async def get_grant(self, user_id, client_id):
        return self._grants.get(self._key(user_id, client_id))

    async def revoke_grant(self, user_id, client_id) -> bool:
        key = self._key(user_id, client_id)
        entry = self._grants.pop(key, None)
        return entry is not None

    async def list_grants(self, user_id) -> list:
        prefix = f"{user_id}:"
        return [v for k, v in self._grants.items() if k.startswith(prefix)]


class MemoryAccessTokenStorage:
    """In-memory access token (jti) store for tests."""

    def __init__(self):
        self._tokens: dict = {}
        self._revoked: set = set()

    async def save(self, token_record) -> bool:
        self._tokens[token_record.jti] = token_record
        return True

    async def get(self, jti: str):
        return self._tokens.get(jti)

    async def revoke(self, jti: str) -> bool:
        self._revoked.add(jti)
        return True

    async def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked


@pytest.fixture
def memory_oauth_storages():
    """All four in-memory OAuth2 storage objects for tests.

    Returns a dict with keys:
        code_storage, refresh_storage, grant_storage, access_token_storage
    """
    return {
        "code_storage": MemoryAuthCodeStorage(),
        "refresh_storage": MemoryRefreshTokenStorage(),
        "grant_storage": MemoryGrantStorage(),
        "access_token_storage": MemoryAccessTokenStorage(),
    }


@pytest.fixture
def public_client():
    """A public OAuth2 client (no secret; PKCE required)."""
    from navigator_auth.backends.oauth2.models import OAuthClient, OauthUser
    user = OauthUser(
        user_id=1,
        username="resource_owner",
        given_name="Resource",
        family_name="Owner",
    )
    return OAuthClient(
        client_id="public_test_client",      # opaque string uid
        client_name="Test Public App",
        client_secret=None,
        client_type="public",
        redirect_uris=["https://app.example.com/callback"],
        policy_uri="",
        client_logo_uri="",
        user=user,
        default_scopes=["default", "profile", "email", "offline_access"],
        allowed_grant_types=["authorization_code"],
    )


@pytest.fixture
def confidential_client():
    """A confidential OAuth2 client (has a secret)."""
    from navigator_auth.backends.oauth2.models import OAuthClient, OauthUser
    user = OauthUser(
        user_id=2,
        username="service_account",
        given_name="Service",
        family_name="Account",
    )
    return OAuthClient(
        client_id="confidential_test_client",
        client_name="Test Confidential App",
        client_secret="super_secret_s3cr3t",
        client_type="confidential",
        redirect_uris=["https://app.example.com/callback"],
        policy_uri="",
        client_logo_uri="",
        user=user,
        default_scopes=["default", "profile", "email"],
        allowed_grant_types=["authorization_code", "client_credentials", "refresh_token"],
    )


# ---------------------------------------------------------------------------
# SAML fixtures (FEAT-097) — self-signed test keys, an in-memory
# IdentityFlowStore double, a real POST-request factory (aiohttp
# StreamReader-backed, so ``request.post()`` parses form bodies), and a
# factory for signed SAMLResponse XML built with a real ``pysaml2`` IdP
# ``Server`` against the committed test fixtures.
# ---------------------------------------------------------------------------

SAML_FIXTURES_DIR = "tests/fixtures/saml"


def _saml_scheme() -> str:
    """Every URL baked into the committed SAML fixtures
    (idp-metadata.xml/sp-metadata.xml entity IDs) uses "https". `get_domain()`
    always builds URLs with `PREFERRED_AUTH_SCHEME` (never the inbound
    request's own scheme), so tests must force that setting to "https"
    regardless of this environment's own config (this sandbox's
    `env/dev/.env` sets "http") — see `force_https_scheme` below."""
    return "https"


def _saml_url(host: str, path: str) -> str:
    return f"{_saml_scheme()}://{host}{path}"


class SAMLFlowStoreStub:
    """Dict-backed IdentityFlowStore double (single-use semantics),
    same shape as `navigator_auth.identity.flow_store.IdentityFlowStore`."""

    def __init__(self):
        self.storage = {}
        self.ttls = {}

    async def set(self, key, payload, ttl):
        self.storage[key] = dict(payload)
        self.ttls[key] = ttl

    async def get(self, key):
        return self.storage.get(key)

    async def getdel(self, key):
        self.ttls.pop(key, None)
        return self.storage.pop(key, None)

    async def delete(self, key):
        self.storage.pop(key, None)

    def keys(self):
        return self.storage.keys()


@pytest.fixture
def saml_keys() -> dict:
    """Paths to the committed self-signed IdP/SP key pairs and metadata."""
    return {
        "idp_key": f"{SAML_FIXTURES_DIR}/idp.key",
        "idp_cert": f"{SAML_FIXTURES_DIR}/idp.crt",
        "sp_key": f"{SAML_FIXTURES_DIR}/sp.key",
        "sp_cert": f"{SAML_FIXTURES_DIR}/sp.crt",
        "idp_metadata": f"{SAML_FIXTURES_DIR}/idp-metadata.xml",
        "sp_metadata": f"{SAML_FIXTURES_DIR}/sp-metadata.xml",
    }


@pytest.fixture
def redis_stub():
    return SAMLFlowStoreStub()


@pytest.fixture
def post_request():
    """Factory building a real (aiohttp) POST web.Request with a
    form-urlencoded body, so ``await request.post()`` works exactly like
    in production (no ``.json()``/``.post()`` mocking needed)."""
    import asyncio
    from urllib.parse import urlencode

    from aiohttp.base_protocol import BaseProtocol
    from aiohttp.streams import StreamReader
    from aiohttp.test_utils import make_mocked_request

    def _factory(
        form: dict, path: str = "/auth/saml/callback/", host: str = "sp.example.com"
    ):
        body = urlencode(form).encode("utf-8")
        loop = asyncio.get_event_loop()
        protocol = BaseProtocol(loop=loop)
        payload = StreamReader(protocol, limit=2**16, loop=loop)
        payload.feed_data(body)
        payload.feed_eof()
        return make_mocked_request(
            "POST",
            _saml_url(host, path),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(body)),
                "Host": host,
            },
            payload=payload,
        )

    return _factory


@pytest.fixture
def saml_idp_core(saml_keys):
    """A `SAMLCore` (IdP role) trusting the SP test metadata, used only to
    mint signed test responses — a stand-in for a real external IdP."""
    from navigator_auth.backends.saml import SAMLCore

    return SAMLCore(
        prefix="SAML_IDP",
        settings={
            "key_file": saml_keys["idp_key"],
            "cert_file": saml_keys["idp_cert"],
            "metadata": {"local": [saml_keys["sp_metadata"]]},
        },
        role="idp",
        logger=None,
    )


@pytest.fixture
def signed_response(saml_idp_core):
    """Factory: build a signed SAMLResponse (base64-encoded, for form POST)
    from a fake IdP `Server` targeting the SP test fixture's entity/ACS.

    ``in_response_to=None`` produces an unsolicited response. Synchronous
    (like the real `saml2.server.Server` API) so it can be called directly
    from test bodies without an `await`; `SAMLCore.idp_server`'s executor
    wrapping is only needed on the request-handling path, not here.
    """
    import base64

    from saml2.saml import AUTHN_PASSWORD

    def _factory(
        in_response_to: str = None,
        attrs: dict = None,
        not_on_or_after=None,
        destination: str = None,
        sp_entity_id: str = None,
        idp_entity_id: str = None,
        userid: str = "a@x.com",
        sign_response: bool = True,
        sign_assertion: bool = True,
    ) -> str:
        destination = destination or _saml_url("sp.example.com", "/auth/saml/callback/")
        sp_entity_id = sp_entity_id or _saml_url("sp.example.com", "/auth/saml/metadata")
        idp_entity_id = idp_entity_id or _saml_url(
            "idp.example.com", "/auth/saml-idp/metadata"
        )
        server = saml_idp_core._load_idp_config(idp_entity_id.rsplit("/auth/", 1)[0])
        from saml2.server import Server

        server = Server(config=server)
        kwargs = {}
        if not_on_or_after is not None:
            kwargs["session_not_on_or_after"] = not_on_or_after
        resp = server.create_authn_response(
            identity=attrs or {"mail": ["a@x.com"], "uid": ["auser"]},
            in_response_to=in_response_to,
            destination=destination,
            sp_entity_id=sp_entity_id,
            userid=userid,
            sign_response=sign_response,
            sign_assertion=sign_assertion,
            authn={"class_ref": AUTHN_PASSWORD, "authn_auth": idp_entity_id},
            **kwargs,
        )
        return base64.b64encode(str(resp).encode("utf-8")).decode("utf-8")

    return _factory


@pytest.fixture
def force_https_scheme(monkeypatch):
    """Force `get_domain()` (used by every SAML URL derivation) to build
    "https://" URLs, matching the scheme baked into the committed
    `idp-metadata.xml`/`sp-metadata.xml` entity IDs, regardless of this
    environment's own `PREFERRED_AUTH_SCHEME` (this sandbox's
    `env/dev/.env` sets "http")."""
    monkeypatch.setattr("navigator_auth.backends.external.PREFERRED_AUTH_SCHEME", "https")
    monkeypatch.setattr("navigator_auth.backends.abstract.PREFERRED_AUTH_SCHEME", "https")


@pytest.fixture
def sp_backend(saml_keys, redis_stub, force_https_scheme):
    """A minimal, concrete `AbstractSAMLBackend` subclass configured
    against the committed IdP test fixture, `_flow_store` backed by
    `redis_stub`. `validate_user_info` is left to the real implementation
    of `ExternalAuth` in most tests — callers that need a DB-free login
    should monkeypatch it explicitly."""
    from navigator_auth.backends.saml import AbstractSAMLBackend

    class MinimalSP(AbstractSAMLBackend):
        def get_idp_metadata(self):
            return saml_keys["idp_metadata"]

        def get_attribute_mapping(self):
            return {"email": "mail", "username": "uid"}

        async def resolve_user_identifier(self, result):
            return result.attributes.get("email")

    backend = object.__new__(MinimalSP)
    backend.logger = MagicMock()
    backend._flow_store = redis_stub
    backend.scheme = "Bearer"
    backend.session_key_property = "session_key"
    backend.session_id_property = "session_id"
    backend.user_property = "user"
    backend.username_attribute = "username"
    backend.userid_attribute = "user_id"
    backend.finish_redirect_url = None
    backend._service_name = "saml"
    backend.config_prefix = "SAML"
    settings = {"metadata": {"local": [saml_keys["idp_metadata"]]}}
    from navigator_auth.backends.saml import SAMLCore

    backend.core = SAMLCore(
        prefix="SAML", settings=settings, role="sp", logger=backend.logger
    )
    return backend
