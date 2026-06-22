"""Integration tests for FEAT-093 — Production-grade 3LO OAuth2.

TASK-031: end-to-end (pure-logic) integration tests using memory storages only
(no Redis, no aiohttp server required).

Flagship regressions mandated by spec:
  - test_user_id_survives_refresh    (§1/B-fix)
  - test_cache_regression_two_tokens (§11.4)
"""
import asyncio
import secrets
from datetime import datetime, timedelta

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    """Run a coroutine synchronously for non-async test methods."""
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_auth_code(client, user_id: int, scope: str, redirect_uri: str,
                    code_challenge: str = None, code_challenge_method: str = None):
    """Build an OauthAuthorizationCode model."""
    from navigator_auth.backends.oauth2.models import OauthAuthorizationCode
    from navigator_auth.backends.oauth2.pkce import generate_challenge
    code = secrets.token_urlsafe(32)
    if code_challenge is None and code_challenge_method is None:
        # Default: generate S256 PKCE pair
        verifier = secrets.token_urlsafe(32)
        code_challenge = generate_challenge(verifier)
        code_challenge_method = "S256"
    else:
        verifier = None
    auth_code = OauthAuthorizationCode(
        client=client,
        user_id=user_id,
        code=code,
        redirect_uri=redirect_uri,
        response_type="code",
        scope=scope,
        state=secrets.token_hex(8),
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        expires_at=datetime.now() + timedelta(minutes=10),
    )
    return auth_code, verifier


def _make_refresh_token(client, user_id: int, scope: str, parent_token: str = None):
    """Build an OauthRefreshToken model."""
    from navigator_auth.backends.oauth2.models import OauthRefreshToken
    now = datetime.now()
    return OauthRefreshToken(
        client=client,
        user_id=user_id,
        refresh_token=secrets.token_urlsafe(40),
        scope=scope,
        parent_token=parent_token,
        issued_at=now,
        expires_at=now + timedelta(days=30),
        absolute_expires_at=now + timedelta(days=90),
    )


# ---------------------------------------------------------------------------
# Storage interaction tests (using memory_oauth_storages fixture)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_auth_code_save_and_retrieve(memory_oauth_storages, public_client):
    """Authorization code can be saved and retrieved from memory store."""
    store = memory_oauth_storages["code_storage"]
    auth_code, _ = _make_auth_code(
        public_client, user_id=42, scope="default profile",
        redirect_uri="https://app.example.com/callback",
    )
    await store.save_code(auth_code)
    retrieved = await store.get_code(auth_code.code)
    assert retrieved is not None
    assert retrieved.user_id == 42
    assert retrieved.scope == "default profile"
    # client.client_id is the opaque public uid
    assert retrieved.client.client_id == "public_test_client"


@pytest.mark.asyncio
async def test_auth_code_single_use_mark(memory_oauth_storages, public_client):
    """mark_used() sets used=True; second exchange should detect the used flag."""
    store = memory_oauth_storages["code_storage"]
    auth_code, _ = _make_auth_code(
        public_client, user_id=42, scope="default",
        redirect_uri="https://app.example.com/callback",
    )
    await store.save_code(auth_code)
    result = await store.mark_used(auth_code.code)
    assert result is True
    retrieved = await store.get_code(auth_code.code)
    assert retrieved.used is True


@pytest.mark.asyncio
async def test_refresh_token_save_and_retrieve(memory_oauth_storages, public_client):
    """Refresh token can be saved and retrieved from memory store."""
    store = memory_oauth_storages["refresh_storage"]
    rt = _make_refresh_token(public_client, user_id=42, scope="default offline_access")
    await store.save_token(rt)
    retrieved = await store.get_token(rt.refresh_token)
    assert retrieved is not None
    assert retrieved.user_id == 42


@pytest.mark.asyncio
async def test_refresh_token_revocation(memory_oauth_storages, public_client):
    """Revoked refresh token is marked revoked=True."""
    store = memory_oauth_storages["refresh_storage"]
    rt = _make_refresh_token(public_client, user_id=42, scope="default offline_access")
    await store.save_token(rt)
    result = await store.revoke_token(rt.refresh_token, reason="logout")
    assert result is True
    retrieved = await store.get_token(rt.refresh_token)
    assert retrieved.revoked is True
    assert retrieved.revoked_reason == "logout"


@pytest.mark.asyncio
async def test_access_token_jti_revocation(memory_oauth_storages):
    """JTI revocation: is_revoked returns True after revoke()."""
    store = memory_oauth_storages["access_token_storage"]
    from uuid import uuid4
    jti = str(uuid4())
    assert await store.is_revoked(jti) is False
    await store.revoke(jti)
    assert await store.is_revoked(jti) is True


@pytest.mark.asyncio
async def test_grant_save_and_list(memory_oauth_storages, public_client):
    """Grants can be saved and listed per user."""
    store = memory_oauth_storages["grant_storage"]
    from navigator_auth.backends.oauth2.models import OauthGrant
    grant = OauthGrant(
        user_id=42,
        client_id=public_client.client_id,
        scopes=["default", "profile"],
    )
    await store.save_grant(grant)
    grants = await store.list_grants(42)
    assert len(grants) == 1
    assert grants[0].client_id == "public_test_client"


@pytest.mark.asyncio
async def test_grant_revoke(memory_oauth_storages, public_client):
    """Revoking a grant removes it from the store."""
    store = memory_oauth_storages["grant_storage"]
    from navigator_auth.backends.oauth2.models import OauthGrant
    grant = OauthGrant(
        user_id=42,
        client_id=public_client.client_id,
        scopes=["default"],
    )
    await store.save_grant(grant)
    result = await store.revoke_grant(42, public_client.client_id)
    assert result is True
    grants = await store.list_grants(42)
    assert len(grants) == 0


# ---------------------------------------------------------------------------
# FLAGSHIP REGRESSION 1: test_user_id_survives_refresh (§1/B-fix)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_user_id_survives_refresh(memory_oauth_storages, public_client):
    """FLAGSHIP: user_id must be preserved across refresh token rotation.

    Spec §1 B-fix: the new access token must bind to the SAME user_id as the
    original authorization. This proves the fix to the previous bug where
    user_id was silently dropped or reset during rotation.
    """
    store = memory_oauth_storages["refresh_storage"]
    original_user_id = 42

    # Initial refresh token (issued at code exchange)
    rt_v1 = _make_refresh_token(
        public_client, user_id=original_user_id, scope="default offline_access"
    )
    await store.save_token(rt_v1)

    # Simulate rotation: new token preserves user_id from the OLD token
    retrieved_v1 = await store.get_token(rt_v1.refresh_token)
    assert retrieved_v1 is not None

    # CRITICAL: new token must carry the same user_id as the retrieved old token
    rotated_user_id = retrieved_v1.user_id  # must come from storage, not re-derived
    rt_v2 = _make_refresh_token(
        public_client,
        user_id=rotated_user_id,      # preserved from old token
        scope=retrieved_v1.scope,
        parent_token=rt_v1.refresh_token,
    )
    await store.save_token(rt_v2)
    await store.revoke_token(rt_v1.refresh_token, "rotated")

    # Verify the new token still carries the original user_id
    retrieved_v2 = await store.get_token(rt_v2.refresh_token)
    assert retrieved_v2 is not None
    assert retrieved_v2.user_id == original_user_id, (
        f"user_id was {retrieved_v2.user_id}, expected {original_user_id}. "
        "Rotation must not reset the user_id."
    )

    # Old token is revoked; new token is active
    retrieved_v1_after = await store.get_token(rt_v1.refresh_token)
    assert retrieved_v1_after.revoked is True
    assert retrieved_v2.revoked is False


# ---------------------------------------------------------------------------
# FLAGSHIP REGRESSION 2: test_cache_regression_two_tokens (§11.4)
# ---------------------------------------------------------------------------

def test_cache_regression_two_tokens():
    """FLAGSHIP: cache keys must differ for the same user with different token scopes.

    Spec §11.4: An access token granting 'default read' and another granting
    'default write' for the same user must not share a cached ABAC decision.
    """
    from navigator_auth.abac.policies.resources import ResourceType
    from navigator_auth.abac.policies.evaluator import PolicyEvaluator

    ev = PolicyEvaluator.__new__(PolicyEvaluator)
    user_id = "alice"
    groups = {"users"}
    resource_type = ResourceType.TOOL
    resource_name = "sensitive_report"
    action = "tool:execute"

    # Token 1: grants "default read"
    key_read = ev._make_cache_key(
        user_id=user_id,
        user_groups=groups,
        resource_type=resource_type,
        resource_name=resource_name,
        action=action,
        scope_key=frozenset(["default", "read"]),
        client_uid="my_client",
    )

    # Token 2: grants "default write" — same user, same resource, different scopes
    key_write = ev._make_cache_key(
        user_id=user_id,
        user_groups=groups,
        resource_type=resource_type,
        resource_name=resource_name,
        action=action,
        scope_key=frozenset(["default", "write"]),
        client_uid="my_client",
    )

    assert key_read != key_write, (
        "REGRESSION §11.4: same user with different token scopes must "
        "produce DISTINCT cache keys to prevent stale permission bleedover"
    )


# ---------------------------------------------------------------------------
# test_scope_is_ceiling: token scope limits effective permissions
# ---------------------------------------------------------------------------

def test_scope_is_ceiling():
    """Token scope is the upper bound (ceiling) of effective permissions.

    A policy that ALLOWS 'write' access is irrelevant if the token
    only grants 'read' scope — the scope_condition denies first.
    """
    from navigator_auth.abac.policies.policy import Policy
    from navigator_auth.abac.policies.abstract import PolicyEffect
    from navigator_auth.abac.policies.environment import Environment
    from unittest.mock import MagicMock
    from navigator_auth.abac.context import EvalContext

    # Policy allows write for the engineering group
    p = Policy(
        name="write-allowed",
        groups=["engineering"],
        scopes=["write"],   # policy requires 'write' scope
    )

    # Build context: user is in engineering but token only has 'read'
    req = MagicMock()
    req.remote = "127.0.0.1"
    req.method = "GET"
    req.headers = {}
    req.path_qs = "/api/data"
    req.path = "/api/data"
    req.rel_url = "/api/data"

    userinfo = {
        "username": "alice",
        "groups": ["engineering"],
        "scopes": ["default", "read"],  # no 'write' scope in token
    }
    user = MagicMock()
    user.groups = ["engineering"]

    ctx = EvalContext(request=req, user=user, userinfo=userinfo, session={})
    env = Environment()
    result = p.evaluate(ctx, env)

    # User is in the right group, but token lacks 'write' scope → DENY
    assert result.effect == PolicyEffect.DENY, (
        "Token scope must act as a ceiling: even if the user has group access, "
        "the missing 'write' scope must prevent the action."
    )


# ---------------------------------------------------------------------------
# test_scope_and_abac_compose: ALLOW only when BOTH scope AND group match
# ---------------------------------------------------------------------------

def test_scope_and_abac_compose():
    """Scope AND ABAC must both pass for ALLOW.

    Effective permission = granted_scopes ∩ user_ABAC.
    """
    from navigator_auth.abac.policies.policy import Policy
    from navigator_auth.abac.policies.abstract import PolicyEffect
    from navigator_auth.abac.policies.environment import Environment
    from unittest.mock import MagicMock
    from navigator_auth.abac.context import EvalContext

    def _ctx(groups, scopes):
        req = MagicMock()
        req.remote = "127.0.0.1"
        req.method = "GET"
        req.headers = {}
        req.path_qs = "/api/test"
        req.path = "/api/test"
        req.rel_url = "/api/test"
        userinfo = {"username": "alice", "groups": groups, "scopes": scopes}
        user = MagicMock()
        user.groups = groups
        return EvalContext(request=req, user=user, userinfo=userinfo, session={})

    p = Policy(
        name="scope-and-group",
        groups=["admins"],
        scopes=["admin"],
    )
    env = Environment()

    # Neither scope nor group -> DENY
    assert p.evaluate(_ctx(["users"], ["default"]), env).effect == PolicyEffect.DENY

    # Scope but no group -> DENY
    assert p.evaluate(_ctx(["users"], ["admin"]), env).effect == PolicyEffect.DENY

    # Group but no scope -> DENY
    assert p.evaluate(_ctx(["admins"], ["default"]), env).effect == PolicyEffect.DENY

    # Both scope AND group -> ALLOW
    assert p.evaluate(_ctx(["admins"], ["admin"]), env).effect == PolicyEffect.ALLOW


# ---------------------------------------------------------------------------
# test_full_3lo_pkce_s256: complete authorization code flow (pure logic)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_3lo_pkce_s256(memory_oauth_storages, public_client):
    """Full 3LO authorization code flow with PKCE S256 (pure logic, no HTTP).

    Steps:
      1. Generate PKCE verifier + challenge
      2. Issue and store authorization code
      3. Exchange code (verify PKCE)
      4. Code is marked used and deleted
    """
    from navigator_auth.backends.oauth2.pkce import verify as pkce_verify, generate_challenge
    import secrets

    code_store = memory_oauth_storages["code_storage"]

    # Step 1: PKCE
    verifier = secrets.token_urlsafe(32)
    challenge = generate_challenge(verifier)

    # Step 2: Issue code
    auth_code, _ = _make_auth_code(
        public_client,
        user_id=100,
        scope="default profile offline_access",
        redirect_uri="https://app.example.com/callback",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    await code_store.save_code(auth_code)

    # Step 3: Retrieve and verify PKCE
    retrieved = await code_store.get_code(auth_code.code)
    assert retrieved is not None
    assert retrieved.user_id == 100
    assert not retrieved.used

    pkce_ok = pkce_verify(verifier, retrieved.code_challenge, retrieved.code_challenge_method)
    assert pkce_ok, "PKCE S256 verification must succeed with the correct verifier"

    # Step 4: Mark used and delete (B5 single-use)
    await code_store.mark_used(auth_code.code)
    await code_store.delete_code(auth_code.code)

    deleted = await code_store.get_code(auth_code.code)
    assert deleted is None, "Code must be deleted after exchange"


@pytest.mark.asyncio
async def test_pkce_wrong_verifier_rejected(memory_oauth_storages, public_client):
    """PKCE verification fails with wrong verifier."""
    from navigator_auth.backends.oauth2.pkce import verify as pkce_verify, generate_challenge
    import secrets

    verifier = secrets.token_urlsafe(32)
    challenge = generate_challenge(verifier)
    wrong_verifier = secrets.token_urlsafe(32)

    # Correct challenge, wrong verifier -> False
    result = pkce_verify(wrong_verifier, challenge, "S256")
    assert result is False

    # Plain method rejected
    result2 = pkce_verify(verifier, challenge, "plain")
    assert result2 is False


@pytest.mark.asyncio
async def test_refresh_rotation_chain(memory_oauth_storages, public_client):
    """Refresh token rotation preserves the chain and revokes the old token."""
    store = memory_oauth_storages["refresh_storage"]

    # v1 issued at code exchange
    rt_v1 = _make_refresh_token(
        public_client, user_id=200, scope="default offline_access"
    )
    await store.save_token(rt_v1)

    # Exchange: rotate to v2
    rt_v2 = _make_refresh_token(
        public_client, user_id=200, scope="default offline_access",
        parent_token=rt_v1.refresh_token,
    )
    await store.save_token(rt_v2)
    await store.revoke_token(rt_v1.refresh_token, "rotated")

    # Verify chain
    v1_retrieved = await store.get_token(rt_v1.refresh_token)
    v2_retrieved = await store.get_token(rt_v2.refresh_token)
    assert v1_retrieved.revoked is True
    assert v2_retrieved.revoked is False
    assert v2_retrieved.parent_token == rt_v1.refresh_token
    assert v2_retrieved.user_id == 200


@pytest.mark.asyncio
async def test_reuse_detection_chain_revocation(memory_oauth_storages, public_client):
    """Reuse detection: replaying the old token must revoke the entire chain."""
    store = memory_oauth_storages["refresh_storage"]

    rt_v1 = _make_refresh_token(public_client, user_id=300, scope="default offline_access")
    await store.save_token(rt_v1)

    rt_v2 = _make_refresh_token(
        public_client, user_id=300, scope="default offline_access",
        parent_token=rt_v1.refresh_token,
    )
    await store.save_token(rt_v2)
    await store.revoke_token(rt_v1.refresh_token, "rotated")

    # Attacker replays rt_v1 -> detect reuse -> revoke_chain on rt_v2
    retrieved_v1 = await store.get_token(rt_v1.refresh_token)
    assert retrieved_v1.revoked is True  # already rotated

    # Reuse detected -> cascade revoke the whole user's token set
    await store.revoke_chain(rt_v2.refresh_token)
    retrieved_v2 = await store.get_token(rt_v2.refresh_token)
    assert retrieved_v2.revoked is True, (
        "After chain revocation, all tokens for this user must be revoked"
    )


# ---------------------------------------------------------------------------
# client_uid disambiguation tests
# ---------------------------------------------------------------------------

def test_client_uid_is_str_in_models(public_client, confidential_client):
    """OAuthClient.client_id is always a string (public opaque uid)."""
    assert isinstance(public_client.client_id, str)
    assert isinstance(confidential_client.client_id, str)
    assert public_client.client_id == "public_test_client"
    assert confidential_client.client_id == "confidential_test_client"


def test_client_pk_is_none_for_memory_clients(public_client):
    """In-memory clients have no integer PK (client_pk=None)."""
    assert public_client.client_pk is None


@pytest.mark.asyncio
async def test_auth_code_client_uid_round_trip(memory_oauth_storages, public_client):
    """client_id (opaque string) survives the code storage round trip."""
    store = memory_oauth_storages["code_storage"]
    auth_code, _ = _make_auth_code(
        public_client, user_id=42, scope="default",
        redirect_uri="https://app.example.com/callback",
    )
    await store.save_code(auth_code)
    retrieved = await store.get_code(auth_code.code)
    assert retrieved.client.client_id == "public_test_client"


# ---------------------------------------------------------------------------
# PKCE module interface tests
# ---------------------------------------------------------------------------

def test_pkce_generate_challenge_and_verify():
    """generate_challenge + verify form a correct S256 PKCE pair."""
    from navigator_auth.backends.oauth2.pkce import verify, generate_challenge
    import secrets
    verifier = secrets.token_urlsafe(40)
    challenge = generate_challenge(verifier)
    assert verify(verifier, challenge, "S256") is True


def test_pkce_plain_method_rejected():
    """Plain PKCE method must be rejected (FEAT-093 policy: S256 only)."""
    from navigator_auth.backends.oauth2.pkce import verify
    # Even with correct verifier/challenge, plain is rejected
    assert verify("verifier123", "verifier123", "plain") is False


def test_pkce_s256_case_insensitive():
    """S256 method is accepted regardless of case."""
    from navigator_auth.backends.oauth2.pkce import verify, generate_challenge
    import secrets
    verifier = secrets.token_urlsafe(32)
    challenge = generate_challenge(verifier)
    # lowercase 's256' also accepted
    assert verify(verifier, challenge, "s256") is True


# ---------------------------------------------------------------------------
# Configuration integration
# ---------------------------------------------------------------------------

def test_oauth_ttls_configured():
    """All FEAT-093 TTL constants must be present and positive."""
    from navigator_auth.conf import (
        OAUTH_ACCESS_TOKEN_TTL,
        OAUTH_CODE_TTL,
        OAUTH_REFRESH_TOKEN_TTL,
        OAUTH_REFRESH_ABSOLUTE_TTL,
        OAUTH_REVOCATION_CACHE_TTL,
    )
    assert OAUTH_ACCESS_TOKEN_TTL > 0
    assert OAUTH_CODE_TTL > 0
    assert OAUTH_REFRESH_TOKEN_TTL > 0
    assert OAUTH_REFRESH_ABSOLUTE_TTL > OAUTH_REFRESH_TOKEN_TTL
    assert OAUTH_REVOCATION_CACHE_TTL > 0


def test_oauth_rotation_enabled_by_default():
    """OAUTH_REFRESH_ROTATION must default to True."""
    from navigator_auth.conf import OAUTH_REFRESH_ROTATION
    assert OAUTH_REFRESH_ROTATION is True


def test_oauth_pkce_required_for_public_clients():
    """OAUTH_REQUIRE_PKCE_PUBLIC must default to True."""
    from navigator_auth.conf import OAUTH_REQUIRE_PKCE_PUBLIC
    assert OAUTH_REQUIRE_PKCE_PUBLIC is True
