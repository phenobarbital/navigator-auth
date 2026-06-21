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
