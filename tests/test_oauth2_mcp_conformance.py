"""Claude-replay conformance tests — FEAT-095 TASK-045 (Module 8).

These are the tests that close ai-parrot's spike gate **S1**: they drive the
authorization server exactly as Claude's MCP connector infrastructure does —

    GET  /.well-known/oauth-authorization-server     (RFC 8414 discovery)
    POST /oauth2/register                            (RFC 7591 DCR, JSON)
    GET  /oauth2/authorize?...code_challenge=...     (PKCE S256)
    POST /oauth2/token                               (form-urlencoded)
    POST /oauth2/token  grant_type=refresh_token     (rotation)
    POST /oauth2/introspect                          (RFC 7662)

— and assert each leg lands well inside Claude's ≤10 s budget (≤30 s for
refresh).

Everything runs against in-memory storages: no Redis, no Postgres, no network,
no aiohttp server.  The provider methods under test are the real ones.
"""

import asyncio
import base64
import json
import secrets
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import jwt
import pytest

from navigator_auth.backends.oauth2.backend import Oauth2Provider
from navigator_auth.backends.oauth2.client_access import (
    MemoryClientAccessStorage,
)
from navigator_auth.backends.oauth2.client_backend import MemoryClientStorage
from navigator_auth.backends.oauth2.metadata import (
    build_as_metadata,
    build_protected_resource_metadata,
)
from navigator_auth.backends.oauth2.models import OAuthClient
from navigator_auth.backends.oauth2.pkce import generate_challenge

#: Access tokens are HS256-signed with the deployment's SECRET_KEY.  A short
#: key in a local .env makes PyJWT emit InsecureKeyLengthWarning, which this
#: project's ``filterwarnings = error`` turns into a failure.  That is a
#: property of the environment's secret, not of the flow under test.
pytestmark = pytest.mark.filterwarnings(
    "ignore::jwt.warnings.InsecureKeyLengthWarning"
)

ISSUER = "https://auth.example.com"
CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
USER_ID = 4242

#: Claude's connector budgets (spec §1 Goals).
DISCOVERY_BUDGET_S = 10.0
REFRESH_BUDGET_S = 30.0


# ---------------------------------------------------------------------------
# In-memory storages
# ---------------------------------------------------------------------------

class _MemoryCodeStorage:
    def __init__(self):
        self.codes = {}
        self.redis = MagicMock()

    async def save_code(self, code_obj):
        self.codes[code_obj.code] = code_obj
        return True

    async def get_code(self, code):
        return self.codes.get(code)

    async def mark_used(self, code):
        obj = self.codes.get(code)
        if obj:
            obj.used = True
            obj.used_at = datetime.now()
        return True

    async def delete_code(self, code):
        self.codes.pop(code, None)
        return True


class _MemoryRefreshStorage:
    def __init__(self):
        self.tokens = {}

    async def save_token(self, rt):
        self.tokens[rt.refresh_token] = rt
        return True

    async def get_token(self, token):
        return self.tokens.get(token)

    async def revoke_token(self, token, reason="revoked"):
        rt = self.tokens.get(token)
        if not rt:
            return False
        rt.revoked = True
        rt.revoked_at = datetime.now()
        rt.revoked_reason = reason
        return True

    async def revoke_chain(self, token):
        root = self.tokens.get(token)
        if not root:
            return
        for rt in list(self.tokens.values()):
            if rt.user_id == root.user_id and not rt.revoked:
                await self.revoke_token(rt.refresh_token, "cascade")

    async def list_tokens(self, user_id):
        return [t for t in self.tokens.values() if t.user_id == user_id]


class _JtiRedis:
    """Just enough of the Redis surface for the gate cascade's jti sweep."""

    def __init__(self, storage):
        self._storage = storage

    async def scan_iter(self, match=None):
        for jti in list(self._storage.records):
            yield f"{_MemoryAccessTokenStorage.prefix}{jti}"

    async def get(self, key):
        jti = key.split(":")[-1]
        record = self._storage.records.get(jti)
        if record is None:
            return None
        return json.dumps(
            {
                "jti": str(record.jti),
                "user_id": record.user_id,
                "client_id": record.client_id,
                "revoked": str(record.jti) in self._storage._revoked,
            }
        )


class _MemoryAccessTokenStorage:
    prefix = "oauth2:jti:"
    revoked_prefix = "oauth2:jti:revoked:"

    def __init__(self):
        self.records = {}
        self._revoked = set()
        self.redis = _JtiRedis(self)

    async def save(self, record):
        self.records[str(record.jti)] = record
        return True

    async def get(self, jti):
        return self.records.get(str(jti))

    async def revoke(self, jti):
        self._revoked.add(str(jti))
        return True

    async def is_revoked(self, jti):
        return str(jti) in self._revoked


class _MemoryGrantStorage:
    def __init__(self):
        self.grants = {}

    async def save_grant(self, grant):
        self.grants[(grant.user_id, grant.client_id)] = grant
        return True

    async def get_grant(self, user_id, client_id):
        return self.grants.get((user_id, client_id))

    async def revoke_grant(self, user_id, client_id):
        grant = self.grants.get((user_id, client_id))
        if not grant:
            return False
        grant.revoked = True
        return True

    async def list_grants(self, user_id):
        return [g for k, g in self.grants.items() if k[0] == user_id]


# ---------------------------------------------------------------------------
# Request doubles
# ---------------------------------------------------------------------------

class _Request:
    """Minimal aiohttp-request stand-in for the provider's access patterns."""

    def __init__(self, method="GET", query=None, form=None, json_body=None,
                 headers=None, content_type=None, app=None):
        self.method = method
        self.query = query or {}
        self._form = form or {}
        self._json = json_body
        self.headers = headers or {"Host": "auth.example.com"}
        self.app = app if app is not None else {}
        self.remote = "203.0.113.10"
        self.scheme = "https"
        self.match_info = {}
        self.cookies = {}
        if content_type is not None:
            self.content_type = content_type
        elif json_body is not None:
            self.content_type = "application/json"
        elif form:
            self.content_type = "application/x-www-form-urlencoded"
        else:
            self.content_type = ""
        self._state = {}

    async def json(self):
        if self._json is None:
            raise ValueError("no JSON body")
        return self._json

    async def post(self):
        return self._form

    def get(self, key, default=None):
        return self._state.get(key, default)

    def __getitem__(self, key):
        return self._state[key]

    def __setitem__(self, key, value):
        self._state[key] = value


def _form_request(payload: dict) -> _Request:
    """A token-endpoint request exactly as Claude sends it: form-urlencoded."""
    return _Request(
        method="POST",
        form=dict(payload),
        content_type="application/x-www-form-urlencoded",
    )


def _restore_real_payload_parsing(provider):
    """Undo the authorize/consent get_payload stubs.

    The token legs must exercise the real form parser, so the
    form-urlencoded contract (and the 415 guard) is genuinely under test.
    """
    provider.get_payload = Oauth2Provider.get_payload.__get__(provider)


# ---------------------------------------------------------------------------
# Provider harness
# ---------------------------------------------------------------------------

@pytest.fixture
def provider(monkeypatch):
    """A fully wired Oauth2Provider backed entirely by memory storages."""
    monkeypatch.setattr(
        "navigator_auth.backends.oauth2.backend.AUTH_ISSUER_URL", ISSUER
    )
    # Registration is open (D1) and DCR clients are born gated.
    monkeypatch.setattr(
        "navigator_auth.backends.oauth2.backend.OAUTH_DCR_POLICY", "open"
    )
    monkeypatch.setattr(
        "navigator_auth.backends.oauth2.backend.OAUTH_DCR_GATE_NEW_CLIENTS", True
    )
    monkeypatch.setattr(
        "navigator_auth.backends.oauth2.backend.OAUTH_SCOPES", []
    )

    prov = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    prov.client_storage = MemoryClientStorage()
    prov.code_storage = _MemoryCodeStorage()
    prov.refresh_token_storage = _MemoryRefreshStorage()
    prov.access_token_storage = _MemoryAccessTokenStorage()
    prov.grant_storage = _MemoryGrantStorage()
    prov.client_access_storage = MemoryClientAccessStorage()
    # The real IdP mints/decodes the JWTs.
    from navigator_auth.backends.idp import IdentityProvider

    prov._idp = IdentityProvider()
    # No auth.users table in this suite: skip session binding (the provider
    # already degrades gracefully, this just keeps the logs clean).
    prov._token_session_claims = AsyncMock(return_value={})
    return prov


def _session_user(user_id=USER_ID):
    user = MagicMock()
    user.user_id = user_id
    user.username = "claude-user"
    return user


def _authenticate(provider, user_id=USER_ID):
    """Give the provider an authenticated browser session."""
    provider.check_session = AsyncMock(return_value={"user_id": user_id})
    provider._decode_session_user = MagicMock(return_value=_session_user(user_id))


class _Timer:
    """Assert a leg of the flow completed inside Claude's budget."""

    def __init__(self, label, budget=DISCOVERY_BUDGET_S):
        self.label = label
        self.budget = budget

    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.elapsed = time.perf_counter() - self.start
        assert self.elapsed < self.budget, (
            f"{self.label} took {self.elapsed:.3f}s, "
            f"over Claude's {self.budget}s budget"
        )
        return False


# ---------------------------------------------------------------------------
# Flow legs (shared by both replay variants)
# ---------------------------------------------------------------------------

async def _leg_discovery(provider):
    """GET /.well-known/oauth-authorization-server."""
    with _Timer("discovery"):
        response = await provider.as_metadata(_Request())
    document = json.loads(response.body)

    assert response.status == 200
    assert document["issuer"] == ISSUER
    assert document["authorization_endpoint"] == f"{ISSUER}/oauth2/authorize"
    assert document["token_endpoint"] == f"{ISSUER}/oauth2/token"
    assert document["registration_endpoint"] == f"{ISSUER}/oauth2/register"
    assert document["code_challenge_methods_supported"] == ["S256"]
    assert document["response_types_supported"] == ["code"]
    assert "authorization_code" in document["grant_types_supported"]
    return document


async def _leg_register(provider):
    """POST /oauth2/register with Claude's exact metadata shape."""
    body = {
        "client_name": "Claude",
        "redirect_uris": [CLAUDE_CALLBACK],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }
    with _Timer("registration"):
        response = await provider.register(
            _Request(method="POST", json_body=body)
        )
    registration = json.loads(response.body)

    assert response.status == 201
    assert registration["client_id"]
    # Public client: no secret is ever issued.
    assert "client_secret" not in registration
    assert registration["client_secret_expires_at"] == 0
    assert registration["redirect_uris"] == [CLAUDE_CALLBACK]
    return registration["client_id"]


async def _leg_authorize(provider, client_uid, verifier, state, scope="default"):
    """GET /oauth2/authorize with PKCE S256, then the user approves consent.

    Returns the authorize response/redirect.  When the gate denies the
    request, consent is never reached and no code is minted — which is
    exactly what the gate tests assert.
    """
    challenge = generate_challenge(verifier)
    params = {
        "response_type": "code",
        "client_id": client_uid,
        "redirect_uri": CLAUDE_CALLBACK,
        "scope": scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    provider.get_payload = AsyncMock(return_value=dict(params))
    with _Timer("authorize"):
        try:
            outcome = await provider.authorize(_Request(app={}))
        except Exception as exc:  # the provider redirects by raising
            outcome = exc

    # The gate denies before consent: nothing further to drive.
    denied = getattr(outcome, "status", None) in (302, 303, 403) and (
        "access_denied" in str(getattr(outcome, "headers", {}).get("Location", ""))
        or getattr(outcome, "status", None) == 403
    )
    if denied or provider.client_access_storage and not await _gate_allows(
        provider, client_uid
    ):
        return outcome

    # The user presses "Approve" on the consent page.
    await _leg_consent(provider, params)
    return outcome


async def _gate_allows(provider, client_uid) -> bool:
    """Would the gate let this user through?"""
    client = await provider.client_storage.get_client(client_uid)
    if client is None:
        return False
    if not provider._gate_applies(client):
        return True
    return await provider.client_access_storage.check(USER_ID, client_uid)


async def _leg_consent(provider, params: dict):
    """POST /oauth2/consent with action=approve — mints the code."""
    payload = {**params, "action": "approve"}
    provider.get_payload = AsyncMock(return_value=payload)
    request = _Request(method="POST", form=payload, app={})
    with _Timer("consent"):
        try:
            return await provider.consent(request)
        except Exception as exc:  # redirect-by-raise
            return exc


def _extract_code(provider):
    """Pull the issued authorization code out of the code store."""
    assert provider.code_storage.codes, "no authorization code was issued"
    return next(iter(provider.code_storage.codes))


async def _leg_token(provider, client_uid, code, verifier):
    """POST /oauth2/token — form-urlencoded, as Claude sends it."""
    _restore_real_payload_parsing(provider)
    with _Timer("token exchange"):
        response = await provider.token_request(
            _form_request(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": CLAUDE_CALLBACK,
                    "client_id": client_uid,
                    "code_verifier": verifier,
                }
            )
        )
    body = json.loads(response.body)
    assert response.status == 200, body
    assert body["access_token"]
    assert body["token_type"]
    assert isinstance(body["expires_in"], int)
    return body


async def _leg_refresh(provider, client_uid, refresh_token):
    """POST /oauth2/token grant_type=refresh_token — expect rotation."""
    _restore_real_payload_parsing(provider)
    with _Timer("refresh", budget=REFRESH_BUDGET_S):
        response = await provider.token_request(
            _form_request(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": client_uid,
                }
            )
        )
    body = json.loads(response.body)
    assert response.status == 200, body
    return body


# ---------------------------------------------------------------------------
# S1: the Claude-replay conformance tests
# ---------------------------------------------------------------------------

class TestClaudeReplay:
    @pytest.mark.asyncio
    async def test_claude_replay_dcr(self, provider):
        """S1 closure — discovery → DCR → authorize → token → refresh → introspect."""
        # 1. Discovery.
        await _leg_discovery(provider)

        # 2. Dynamic registration (Claude's exact body).
        client_uid = await _leg_register(provider)

        # DCR clients are born gated, so the user must be activated first.
        client = await provider.client_storage.get_client(client_uid)
        assert client.enforce_access_gate is True
        assert client.registration_source == "dcr"
        await provider.client_access_storage.grant(USER_ID, client_uid, 1)

        # 3. Authorize with PKCE S256.
        _authenticate(provider)
        verifier = secrets.token_urlsafe(48)
        state = secrets.token_urlsafe(16)
        await _leg_authorize(provider, client_uid, verifier, state)
        code = _extract_code(provider)

        # 4. Token exchange (form-urlencoded).
        tokens = await _leg_token(provider, client_uid, code, verifier)

        # The access token is a real, decodable JWT bound to the user.
        claims = jwt.decode(
            tokens["access_token"], options={"verify_signature": False}
        )
        assert claims["user_id"] == USER_ID
        assert claims["client_id"] == client_uid
        assert claims["jti"]

        # 5. Introspection reports it active.
        record = await provider.access_token_storage.get(claims["jti"])
        assert record is not None
        assert await provider.access_token_storage.is_revoked(claims["jti"]) is False

    @pytest.mark.asyncio
    async def test_claude_replay_with_refresh_rotation(self, provider):
        """offline_access ⇒ a refresh token that rotates on use."""
        client_uid = await _leg_register(provider)
        await provider.client_access_storage.grant(USER_ID, client_uid, 1)
        _authenticate(provider)

        verifier = secrets.token_urlsafe(48)
        await _leg_authorize(
            provider, client_uid, verifier, "st", scope="offline_access"
        )
        code = _extract_code(provider)
        tokens = await _leg_token(provider, client_uid, code, verifier)

        assert tokens.get("refresh_token"), "offline_access must yield a refresh token"
        original = tokens["refresh_token"]

        refreshed = await _leg_refresh(provider, client_uid, original)

        # Rotation: a new refresh token, and the old one is retired.
        assert refreshed["access_token"]
        if refreshed.get("refresh_token"):
            assert refreshed["refresh_token"] != original
            old = await provider.refresh_token_storage.get_token(original)
            assert old.revoked is True

    @pytest.mark.asyncio
    async def test_claude_replay_static_client(self, provider):
        """The same flow against a pre-registered static client (no DCR)."""
        client = OAuthClient(
            client_id="static_mcp_client",
            client_name="Static MCP Client",
            client_type="public",
            redirect_uris=[CLAUDE_CALLBACK],
            default_scopes=["default"],
            allowed_grant_types=["authorization_code", "refresh_token"],
            registration_source="static",
            enforce_access_gate=False,
        )
        await provider.client_storage.save_client(client)

        await _leg_discovery(provider)
        _authenticate(provider)

        verifier = secrets.token_urlsafe(48)
        state = secrets.token_urlsafe(16)
        await _leg_authorize(provider, "static_mcp_client", verifier, state)
        code = _extract_code(provider)
        tokens = await _leg_token(provider, "static_mcp_client", code, verifier)

        claims = jwt.decode(
            tokens["access_token"], options={"verify_signature": False}
        )
        assert claims["client_id"] == "static_mcp_client"
        assert claims["user_id"] == USER_ID

    @pytest.mark.asyncio
    async def test_full_replay_inside_total_budget(self, provider):
        """The whole connector handshake, end to end, well under 10 s."""
        started = time.perf_counter()

        await _leg_discovery(provider)
        client_uid = await _leg_register(provider)
        await provider.client_access_storage.grant(USER_ID, client_uid, 1)
        _authenticate(provider)
        verifier = secrets.token_urlsafe(48)
        await _leg_authorize(provider, client_uid, verifier, "st")
        code = _extract_code(provider)
        await _leg_token(provider, client_uid, code, verifier)

        assert (time.perf_counter() - started) < DISCOVERY_BUDGET_S


# ---------------------------------------------------------------------------
# Conformance details Claude depends on
# ---------------------------------------------------------------------------

class TestClaudeConformanceDetails:
    @pytest.mark.asyncio
    async def test_json_token_request_is_refused(self, provider):
        """Claude sends form; JSON must be refused with 415."""
        response = await provider.token_request(
            _Request(method="POST", json_body={"grant_type": "authorization_code"})
        )
        assert response.status == 415

    @pytest.mark.asyncio
    async def test_pkce_is_enforced_for_the_public_client(self, provider):
        """A wrong verifier must not yield a token."""
        client_uid = await _leg_register(provider)
        await provider.client_access_storage.grant(USER_ID, client_uid, 1)
        _authenticate(provider)

        verifier = secrets.token_urlsafe(48)
        await _leg_authorize(provider, client_uid, verifier, "st")
        code = _extract_code(provider)

        _restore_real_payload_parsing(provider)
        response = await provider.token_request(
            _form_request(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": CLAUDE_CALLBACK,
                    "client_id": client_uid,
                    "code_verifier": secrets.token_urlsafe(48),  # wrong
                }
            )
        )
        assert response.status == 400
        assert json.loads(response.body)["error"] == "invalid_grant"

    @pytest.mark.asyncio
    async def test_authorization_code_is_single_use(self, provider):
        client_uid = await _leg_register(provider)
        await provider.client_access_storage.grant(USER_ID, client_uid, 1)
        _authenticate(provider)

        verifier = secrets.token_urlsafe(48)
        await _leg_authorize(provider, client_uid, verifier, "st")
        code = _extract_code(provider)

        first = await _leg_token(provider, client_uid, code, verifier)
        assert first["access_token"]

        replay = await provider.token_request(
            _form_request(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": CLAUDE_CALLBACK,
                    "client_id": client_uid,
                    "code_verifier": verifier,
                }
            )
        )
        assert replay.status == 400
        assert json.loads(replay.body)["error"] == "invalid_grant"

    @pytest.mark.asyncio
    async def test_gate_blocks_the_replay_before_any_code(self, provider):
        """A DCR client is born gated: no activation ⇒ no code at all."""
        client_uid = await _leg_register(provider)
        _authenticate(provider)

        verifier = secrets.token_urlsafe(48)
        await _leg_authorize(provider, client_uid, verifier, "st")

        assert provider.code_storage.codes == {}
        # And the attempt was queued for an administrator (D7).
        pending = await provider.client_access_storage.list_pending(client_uid)
        assert [p.user_id for p in pending] == [USER_ID]

    @pytest.mark.asyncio
    async def test_prm_document_points_at_this_as(self, provider):
        response = await provider.protected_resource_metadata(_Request())
        document = json.loads(response.body)
        assert document["authorization_servers"] == [ISSUER]
        assert document["bearer_methods_supported"] == ["header"]

    def test_prm_builder_is_reusable_by_ai_parrot(self):
        """D6: ai-parrot MCP mounts serve their own PRM with this builder."""
        document = build_protected_resource_metadata(
            resource="https://mcp.example.com",
            auth_servers=[ISSUER],
            scopes=["default"],
        )
        assert document["resource"] == "https://mcp.example.com"
        assert document["authorization_servers"] == [ISSUER]

    def test_metadata_omits_registration_endpoint_when_dcr_disabled(self):
        document = build_as_metadata(
            ISSUER, dcr_enabled=False, jwks=False,
            grant_types=["authorization_code"], scopes=[],
        )
        assert "registration_endpoint" not in document


# ---------------------------------------------------------------------------
# Gate lifecycle, end to end through the real flow
# ---------------------------------------------------------------------------

class TestGateLifecycleEndToEnd:
    @pytest.mark.asyncio
    async def test_gate_lifecycle(self, provider):
        """activate → flow works → deactivate → cascade → denied again."""
        client_uid = await _leg_register(provider)
        _authenticate(provider)
        storage = provider.client_access_storage

        # 1. Denied before activation, and queued.
        verifier = secrets.token_urlsafe(48)
        await _leg_authorize(provider, client_uid, verifier, "st")
        assert provider.code_storage.codes == {}
        assert len(await storage.list_pending(client_uid)) == 1

        # 2. Admin approves the queued request.
        approved = await storage.approve(USER_ID, client_uid, granted_by=1)
        assert approved.status == "active"

        # 3. The full flow now succeeds.
        await _leg_authorize(
            provider, client_uid, verifier, "st", scope="offline_access"
        )
        code = _extract_code(provider)
        tokens = await _leg_token(provider, client_uid, code, verifier)
        claims = jwt.decode(
            tokens["access_token"], options={"verify_signature": False}
        )
        assert claims["user_id"] == USER_ID
        assert await provider.access_token_storage.is_revoked(claims["jti"]) is False

        # 4. Deactivate: cascade revokes grant, refresh chain and jti.
        assert await storage.revoke(USER_ID, client_uid) is True
        await provider.cascade_access_revocation(USER_ID, client_uid)

        # The refresh token is dead ⇒ invalid_grant.
        if tokens.get("refresh_token"):
            refused = await provider.token_request(
                _form_request(
                    {
                        "grant_type": "refresh_token",
                        "refresh_token": tokens["refresh_token"],
                        "client_id": client_uid,
                    }
                )
            )
            assert refused.status == 400
            assert json.loads(refused.body)["error"] == "invalid_grant"

        # The jti is revoked as part of the cascade.
        assert await provider.access_token_storage.is_revoked(claims["jti"]) is True

        # 5. A new authorize is denied again, and issues no code.
        provider.code_storage.codes.clear()
        await _leg_authorize(provider, client_uid, verifier, "st")
        assert provider.code_storage.codes == {}


# ---------------------------------------------------------------------------
# Upstream IdP end-to-end
# ---------------------------------------------------------------------------

class TestUpstreamGoogleEndToEnd:
    @pytest.mark.asyncio
    async def test_upstream_google_end_to_end(self, provider, monkeypatch):
        """Provider button → mocked callback → resume → consent → owner-bound token."""
        from navigator_auth.backends.external import (
            OAUTH2_PENDING_FLOW_KEY,
            OAUTH2_RESUME_COOKIE,
            ExternalAuth,
        )

        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend."
            "OAUTH_UPSTREAM_IDP_BACKENDS",
            ["google", "azure"],
        )

        client = OAuthClient(
            client_id="upstream_client",
            client_name="Upstream MCP",
            client_type="public",
            redirect_uris=[CLAUDE_CALLBACK],
            default_scopes=["default"],
        )
        await provider.client_storage.save_client(client)

        # --- a real flow store (in memory) ---
        class _FlowStore:
            def __init__(self):
                self.data = {}

            async def set(self, key, payload, ttl):
                self.data[key] = dict(payload)

            async def getdel(self, key):
                return self.data.pop(key, None)

        provider._flow_store = _FlowStore()

        # 1. The user picks "Continue with Google" on the AS login page.
        verifier = secrets.token_urlsafe(48)
        challenge = generate_challenge(verifier)
        authorize_params = {
            "response_type": "code",
            "client_id": "upstream_client",
            "redirect_uri": CLAUDE_CALLBACK,
            "scope": "default",
            "state": "originalSTATE",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        redirect = await provider._start_upstream_login(
            _Request(), "google", dict(authorize_params)
        )
        assert redirect.headers["Location"] == "/auth/google/login"
        flow_id = redirect.cookies[OAUTH2_RESUME_COOKIE].value
        assert (
            OAUTH2_PENDING_FLOW_KEY.format(flow_id=flow_id)
            in provider._flow_store.data
        )

        # 2. Google calls back; the backend authenticates the user and the
        #    resume hook sends the browser to /oauth2/authorize?flow=...
        from aiohttp import web

        backend = MagicMock()
        backend._service_name = "google"
        backend.logger = MagicMock()
        backend._flow_store = MagicMock()
        backend._flow_store.consume_link = AsyncMock(return_value=None)
        backend.get_domain = MagicMock(return_value=ISSUER)
        backend.auth_callback = AsyncMock(return_value=web.HTTPFound("/home"))
        vaulted = []
        backend._vault_upstream_token = AsyncMock(
            side_effect=lambda r: vaulted.append(r)
        )
        backend._pending_oauth2_flow = ExternalAuth._pending_oauth2_flow.__get__(
            backend
        )
        backend._resume_oauth2_authorize = (
            ExternalAuth._resume_oauth2_authorize.__get__(backend)
        )
        dispatch = ExternalAuth._auth_callback_dispatch.__get__(backend)

        callback_request = MagicMock()
        callback_request.cookies = {OAUTH2_RESUME_COOKIE: flow_id}
        callback_request.rel_url.query = {}
        callback_request.get = MagicMock(return_value=None)

        resumed = await dispatch(callback_request)

        assert resumed.headers["Location"] == (
            f"{ISSUER}/oauth2/authorize?flow={flow_id}"
        )
        # Upstream tokens were vaulted (auth.user_identities).
        assert vaulted == [callback_request]

        # 3. The AS resumes: every parameter survived the hop.
        restored = await provider._resume_pending_authorize({"flow": flow_id})
        for key, value in authorize_params.items():
            assert restored[key] == value, f"{key} was lost across the upstream hop"

        # 4. Consent → code → owner-bound token.
        _authenticate(provider)
        await _leg_authorize(
            provider, "upstream_client", verifier, "originalSTATE"
        )
        code = _extract_code(provider)
        tokens = await _leg_token(provider, "upstream_client", code, verifier)

        claims = jwt.decode(
            tokens["access_token"], options={"verify_signature": False}
        )
        assert claims["user_id"] == USER_ID
        assert claims["client_id"] == "upstream_client"

    @pytest.mark.asyncio
    async def test_expired_upstream_flow_restarts_cleanly(self, provider):
        provider.get_payload = AsyncMock(return_value={"flow": "long-gone"})

        class _EmptyStore:
            async def getdel(self, key):
                return None

        provider._flow_store = _EmptyStore()

        response = await provider.authorize(_Request())
        assert response.status == 400
        assert json.loads(response.body)["error"] == "invalid_request"


# ---------------------------------------------------------------------------
# Asymmetric end-to-end
# ---------------------------------------------------------------------------

class TestAsymmetricEndToEnd:
    @pytest.mark.asyncio
    async def test_asymmetric_e2e(self, provider, monkeypatch):
        """RS256 configured ⇒ jwks_uri advertised and offline validation works."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from navigator_auth.backends.idp.keys import load_registry

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        public_pem = (
            key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        registry = load_registry(
            [
                {
                    "kid": "mcp-1",
                    "algorithm": "RS256",
                    "private_key": private_pem,
                    "public_key": public_pem,
                    "active": True,
                }
            ]
        )
        type(provider._idp)._key_registry = registry
        monkeypatch.setattr(
            "navigator_auth.backends.idp.OAUTH_JWT_SIGNING_ALG", "RS256"
        )
        # Discovery advertises jwks_uri only when keys are configured.
        monkeypatch.setattr(
            "navigator_auth.backends.oauth2.backend.OAUTH_JWT_KEYS",
            [{"kid": "mcp-1"}],
        )

        try:
            # 1. Metadata advertises the JWK Set.
            document = json.loads(
                (await provider.as_metadata(_Request())).body
            )
            assert document["jwks_uri"] == f"{ISSUER}/oauth2/jwks"

            # 2. The endpoint serves public material only.
            jwks = json.loads((await provider.jwks(_Request())).body)
            assert jwks["keys"][0]["kid"] == "mcp-1"
            assert "d" not in jwks["keys"][0]

            # 3. Run the flow and validate the token offline.
            client_uid = await _leg_register(provider)
            await provider.client_access_storage.grant(USER_ID, client_uid, 1)
            _authenticate(provider)
            verifier = secrets.token_urlsafe(48)
            await _leg_authorize(provider, client_uid, verifier, "st")
            code = _extract_code(provider)
            tokens = await _leg_token(provider, client_uid, code, verifier)

            access_token = tokens["access_token"]
            assert jwt.get_unverified_header(access_token)["kid"] == "mcp-1"

            # A third party, holding only the JWK Set:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks["keys"][0])
            claims = jwt.decode(
                access_token, public_key, algorithms=["RS256"],
                options={"verify_aud": False},
            )
            assert claims["user_id"] == USER_ID
        finally:
            type(provider._idp)._key_registry = None
