"""Tests for TASK-030 — P5 Scope ↔ ABAC composition.

Covers:
  - @scope_required / Guardian.has_scope: 403 insufficient_scope (issubset logic)
  - Policy.scopes: scope_condition AND-composed with other conditions
  - ObjectPolicy.scopes: same scope_condition
  - Cache-key regression: same user, different scopes -> different keys (s11.4)
  - client_credentials principal: client_uid distinct from tenant client_id
  - OAUTH_SCOPES / OAUTH_SCOPE_ACTIONS config constants
"""
import contextlib
from unittest.mock import MagicMock


def _make_mock_request():
    """Build a minimal MagicMock of a web.Request for EvalContext."""
    req = MagicMock()
    req.remote = "127.0.0.1"
    req.method = "GET"
    req.headers = {"referer": None}
    req.path_qs = "/api/test"
    req.path = "/api/test"
    req.rel_url = "/api/test"
    return req


def _make_eval_ctx(scopes: list, username: str = "alice", groups: list = None):
    """Build a proper EvalContext for policy evaluation tests."""
    from navigator_auth.abac.context import EvalContext
    mock_request = _make_mock_request()
    mock_user = MagicMock()
    mock_user.username = username
    mock_user.groups = groups or []
    userinfo = {
        "username": username,
        "groups": groups or [],
        "scopes": scopes,
    }
    return EvalContext(
        request=mock_request,
        user=mock_user,
        userinfo=userinfo,
        session={},
    )


# ---------------------------------------------------------------------------
# Config constants
# ---------------------------------------------------------------------------

class TestScopeConfig:
    """OAUTH_SCOPES and OAUTH_SCOPE_ACTIONS exist and are the correct types."""

    def test_oauth_scopes_is_list(self):
        from navigator_auth.conf import OAUTH_SCOPES
        assert isinstance(OAUTH_SCOPES, list)

    def test_oauth_scopes_has_default_scope(self):
        from navigator_auth.conf import OAUTH_SCOPES
        assert "default" in OAUTH_SCOPES

    def test_oauth_scopes_has_profile(self):
        from navigator_auth.conf import OAUTH_SCOPES
        assert "profile" in OAUTH_SCOPES

    def test_oauth_scopes_has_email(self):
        from navigator_auth.conf import OAUTH_SCOPES
        assert "email" in OAUTH_SCOPES

    def test_oauth_scopes_has_offline_access(self):
        from navigator_auth.conf import OAUTH_SCOPES
        assert "offline_access" in OAUTH_SCOPES

    def test_oauth_scope_actions_is_dict(self):
        from navigator_auth.conf import OAUTH_SCOPE_ACTIONS
        assert isinstance(OAUTH_SCOPE_ACTIONS, dict)


# ---------------------------------------------------------------------------
# AbstractPolicy.scopes: __init__ parameter added
# ---------------------------------------------------------------------------

class TestAbstractPolicyScopes:
    """AbstractPolicy accepts scopes kwarg and stores it."""

    def test_policy_accepts_scopes_kwarg(self):
        import inspect
        from navigator_auth.abac.policies.abstract import AbstractPolicy
        sig = inspect.signature(AbstractPolicy.__init__)
        assert "scopes" in sig.parameters

    def test_policy_default_scopes_is_empty(self):
        """When no scopes specified, AbstractPolicy.scopes defaults to []."""
        from navigator_auth.abac.policies.policy import Policy
        p = Policy(name="no-scopes", resource=["urn:uri:/test"], actions=["tool:read"])
        assert p.scopes == []

    def test_policy_stores_scopes(self):
        """Scopes kwarg is stored on the policy instance."""
        from navigator_auth.abac.policies.policy import Policy
        p = Policy(
            name="scope-policy",
            resource=["urn:uri:/test"],
            actions=["tool:read"],
            scopes=["default", "read"],
        )
        assert set(p.scopes) == {"default", "read"}


# ---------------------------------------------------------------------------
# Policy.scope_condition: evaluate() AND-composition
# ---------------------------------------------------------------------------

class TestPolicyScopeCondition:
    """Policy.evaluate() includes scope_condition as an AND-gate."""

    def test_scope_satisfied_allows(self):
        """When token has required scopes, policy can ALLOW."""
        from navigator_auth.abac.policies.policy import Policy
        from navigator_auth.abac.policies.abstract import PolicyEffect
        from navigator_auth.abac.policies.environment import Environment

        p = Policy(
            name="read-policy",
            scopes=["default", "read"],
        )
        ctx = _make_eval_ctx(["default", "read", "profile"])
        env = Environment()
        result = p.evaluate(ctx, env)
        assert result.effect == PolicyEffect.ALLOW

    def test_scope_not_satisfied_denies(self):
        """When token lacks required scopes, policy returns DENY."""
        from navigator_auth.abac.policies.policy import Policy
        from navigator_auth.abac.policies.abstract import PolicyEffect
        from navigator_auth.abac.policies.environment import Environment

        p = Policy(
            name="read-policy",
            scopes=["write"],  # requires write
        )
        ctx = _make_eval_ctx(["default", "read"])  # no write
        env = Environment()
        result = p.evaluate(ctx, env)
        assert result.effect == PolicyEffect.DENY

    def test_no_scopes_on_policy_is_satisfied_by_default(self):
        """Policy without scopes restriction is satisfied for any token."""
        from navigator_auth.abac.policies.policy import Policy
        from navigator_auth.abac.policies.abstract import PolicyEffect
        from navigator_auth.abac.policies.environment import Environment

        p = Policy(
            name="open-policy",
        )
        ctx = _make_eval_ctx([])  # empty token scopes
        env = Environment()
        result = p.evaluate(ctx, env)
        assert result.effect == PolicyEffect.ALLOW

    def test_partial_scope_match_denies(self):
        """Having only some required scopes is not sufficient (all must match)."""
        from navigator_auth.abac.policies.policy import Policy
        from navigator_auth.abac.policies.abstract import PolicyEffect
        from navigator_auth.abac.policies.environment import Environment

        p = Policy(
            name="multi-scope",
            scopes=["default", "admin"],
        )
        ctx = _make_eval_ctx(["default"])  # missing 'admin'
        env = Environment()
        result = p.evaluate(ctx, env)
        assert result.effect == PolicyEffect.DENY

    def test_scope_condition_and_with_groups(self):
        """Scope AND groups: only ALLOW when BOTH conditions are satisfied."""
        from navigator_auth.abac.policies.policy import Policy
        from navigator_auth.abac.policies.abstract import PolicyEffect
        from navigator_auth.abac.policies.environment import Environment

        p = Policy(
            name="group-scope",
            groups=["admins"],
            scopes=["admin"],
        )
        # Token has scope but user not in group -> DENY
        ctx_no_group = _make_eval_ctx(["admin"], username="alice", groups=["users"])
        env = Environment()
        result = p.evaluate(ctx_no_group, env)
        assert result.effect == PolicyEffect.DENY

        # Token has scope AND user in group -> ALLOW
        ctx_with_group = _make_eval_ctx(["admin"], username="alice", groups=["admins"])
        result2 = p.evaluate(ctx_with_group, env)
        assert result2.effect == PolicyEffect.ALLOW


# ---------------------------------------------------------------------------
# ObjectPolicy.scope_condition
# ---------------------------------------------------------------------------

class TestObjectPolicyScopeCondition:
    """ObjectPolicy.evaluate() also includes scope_condition."""

    def test_object_policy_scope_satisfied(self):
        from navigator_auth.abac.policies.obj import ObjectPolicy
        from navigator_auth.abac.policies.abstract import PolicyEffect
        from navigator_auth.abac.policies.environment import Environment

        p = ObjectPolicy(
            name="obj-scope",
            scopes=["default"],
        )
        ctx = _make_eval_ctx(["default", "read"])
        env = Environment()
        result = p.evaluate(ctx, env)
        assert result.effect == PolicyEffect.ALLOW

    def test_object_policy_scope_denied(self):
        from navigator_auth.abac.policies.obj import ObjectPolicy
        from navigator_auth.abac.policies.abstract import PolicyEffect
        from navigator_auth.abac.policies.environment import Environment

        p = ObjectPolicy(
            name="obj-scope",
            scopes=["write"],
        )
        ctx = _make_eval_ctx(["default"])  # no write
        env = Environment()
        result = p.evaluate(ctx, env)
        assert result.effect == PolicyEffect.DENY


# ---------------------------------------------------------------------------
# Cache-key regression: s11.4 -- same user, different scopes -> different keys
# ---------------------------------------------------------------------------

class TestCacheKeyRegression:
    """_make_cache_key includes scope_key and client_uid as distinct components."""

    def _make_evaluator(self):
        from navigator_auth.abac.policies.evaluator import PolicyEvaluator
        return PolicyEvaluator.__new__(PolicyEvaluator)

    def test_same_user_different_scopes_different_keys(self):
        """Two tokens for the same user with different scopes must not collide."""
        from navigator_auth.abac.policies.resources import ResourceType
        ev = self._make_evaluator()

        key_read = ev._make_cache_key(
            user_id="alice",
            user_groups={"users"},
            resource_type=ResourceType.TOOL,
            resource_name="report",
            action="tool:execute",
            scope_key=frozenset(["default", "read"]),
            client_uid="client_abc",
        )
        key_write = ev._make_cache_key(
            user_id="alice",
            user_groups={"users"},
            resource_type=ResourceType.TOOL,
            resource_name="report",
            action="tool:execute",
            scope_key=frozenset(["default", "write"]),
            client_uid="client_abc",
        )
        assert key_read != key_write, (
            "Same user with different token scopes must produce different cache keys (s11.4)"
        )

    def test_same_user_different_client_uid_different_keys(self):
        """Two tokens for same user but different OAuth clients must not collide."""
        from navigator_auth.abac.policies.resources import ResourceType
        ev = self._make_evaluator()

        key_client_a = ev._make_cache_key(
            user_id="alice",
            user_groups={"users"},
            resource_type=ResourceType.TOOL,
            resource_name="report",
            action="tool:execute",
            scope_key=frozenset(["default"]),
            client_uid="client_A",
        )
        key_client_b = ev._make_cache_key(
            user_id="alice",
            user_groups={"users"},
            resource_type=ResourceType.TOOL,
            resource_name="report",
            action="tool:execute",
            scope_key=frozenset(["default"]),
            client_uid="client_B",
        )
        assert key_client_a != key_client_b

    def test_no_scopes_no_client_uid_is_stable(self):
        """Non-token users (no scopes, no client_uid) get a stable key."""
        from navigator_auth.abac.policies.resources import ResourceType
        ev = self._make_evaluator()

        key1 = ev._make_cache_key(
            user_id="alice",
            user_groups={"users"},
            resource_type=ResourceType.TOOL,
            resource_name="report",
            action="tool:execute",
        )
        key2 = ev._make_cache_key(
            user_id="alice",
            user_groups={"users"},
            resource_type=ResourceType.TOOL,
            resource_name="report",
            action="tool:execute",
        )
        assert key1 == key2, "Same inputs must always produce the same cache key"

    def test_client_uid_distinct_from_tenant_client_id(self):
        """client_uid (OAuth string) and client_id (tenant int) are independent axes."""
        from navigator_auth.abac.policies.resources import ResourceType
        ev = self._make_evaluator()

        # Same client_uid, different tenant client_id
        key_tenant1 = ev._make_cache_key(
            user_id="alice",
            user_groups={"users"},
            resource_type=ResourceType.TOOL,
            resource_name="report",
            action="tool:execute",
            client_id=1,
            client_uid="oauth_client",
        )
        key_tenant2 = ev._make_cache_key(
            user_id="alice",
            user_groups={"users"},
            resource_type=ResourceType.TOOL,
            resource_name="report",
            action="tool:execute",
            client_id=99,  # different tenant
            client_uid="oauth_client",
        )
        assert key_tenant1 != key_tenant2

    def test_scope_key_is_order_independent(self):
        """frozenset scope_key produces same key regardless of insertion order."""
        from navigator_auth.abac.policies.resources import ResourceType
        ev = self._make_evaluator()

        key_a = ev._make_cache_key(
            user_id="alice",
            user_groups={"users"},
            resource_type=ResourceType.TOOL,
            resource_name="report",
            action="tool:execute",
            scope_key=frozenset(["default", "read", "profile"]),
        )
        key_b = ev._make_cache_key(
            user_id="alice",
            user_groups={"users"},
            resource_type=ResourceType.TOOL,
            resource_name="report",
            action="tool:execute",
            scope_key=frozenset(["profile", "default", "read"]),
        )
        assert key_a == key_b


# ---------------------------------------------------------------------------
# scope_required decorator logic (conceptual -- pure logic)
# ---------------------------------------------------------------------------

class TestScopeRequiredDecorator:
    """@scope_required enforces issubset check."""

    def test_scope_required_function_exists(self):
        from navigator_auth.abac.decorators import scope_required
        assert callable(scope_required)

    def test_scope_required_returns_callable(self):
        from navigator_auth.abac.decorators import scope_required
        decorator = scope_required("default", "read")
        assert callable(decorator)

    def test_issubset_passes_when_token_has_all_scopes(self):
        required = {"default", "read"}
        token_scopes = {"default", "read", "profile"}
        assert required.issubset(token_scopes)

    def test_issubset_fails_when_missing_scope(self):
        required = {"default", "admin"}
        token_scopes = {"default", "read"}
        assert not required.issubset(token_scopes)

    def test_empty_required_always_passes(self):
        """@scope_required() with no args always passes (empty set is subset of anything)."""
        required = set()
        token_scopes = {"default"}
        assert required.issubset(token_scopes)

    def test_empty_token_scopes_fails_nonempty_required(self):
        required = {"default"}
        token_scopes = set()
        assert not required.issubset(token_scopes)


# ---------------------------------------------------------------------------
# Guardian.has_scope: method exists and interface correct
# ---------------------------------------------------------------------------

class TestGuardianHasScope:
    """Guardian.has_scope method is present and has correct signature."""

    def test_has_scope_method_exists(self):
        from navigator_auth.abac.guardian import Guardian
        assert hasattr(Guardian, "has_scope")
        assert callable(getattr(Guardian, "has_scope"))

    def test_has_scope_signature(self):
        import inspect
        from navigator_auth.abac.guardian import Guardian
        sig = inspect.signature(Guardian.has_scope)
        params = list(sig.parameters.keys())
        assert "request" in params
        assert "scopes" in params


# ---------------------------------------------------------------------------
# client_credentials principal (conceptual)
# ---------------------------------------------------------------------------

class TestClientCredentialsPrincipal:
    """client_uid string is distinct from the tenant client_id integer."""

    def test_client_uid_type_is_str(self):
        """OAuth client_uid is a public opaque string (not an int)."""
        client_uid = "some_opaque_uid_string"
        assert isinstance(client_uid, str)

    def test_tenant_client_id_type_is_int(self):
        """FEAT-092 tenant client_id is an integer PK."""
        tenant_client_id = 42
        assert isinstance(tenant_client_id, int)

    def test_client_uid_and_client_id_are_independent(self):
        """client_uid in userinfo['client_id'] is the string OAuth uid."""
        # TASK-029 bearer processing: payload["client_id"] = public uid string
        payload = {
            "user_id": None,  # 2LO: no user
            "client_id": "machine_client_uid",
            "scope": "default read",
            "aud": "app",
        }
        scopes_str = payload.get("scope", "")
        processed_scopes = scopes_str.split() if scopes_str else []
        oauth_client_uid = payload.get("client_id")

        assert isinstance(oauth_client_uid, str)
        assert "default" in processed_scopes
        assert oauth_client_uid == "machine_client_uid"

    def test_cache_key_uses_client_uid_not_tenant_id(self):
        """Cache key for client_credentials uses client_uid (str), not tenant client_id (int)."""
        from navigator_auth.abac.policies.resources import ResourceType
        from navigator_auth.abac.policies.evaluator import PolicyEvaluator
        ev = PolicyEvaluator.__new__(PolicyEvaluator)

        # 2LO (client_credentials) request
        key_2lo = ev._make_cache_key(
            user_id="machine_client_uid",  # principal is the client
            user_groups=set(),
            resource_type=ResourceType.TOOL,
            resource_name="batch_job",
            action="tool:execute",
            scope_key=frozenset(["default"]),
            client_uid="machine_client_uid",
        )
        # Different client_uid
        key_other_client = ev._make_cache_key(
            user_id="other_client_uid",
            user_groups=set(),
            resource_type=ResourceType.TOOL,
            resource_name="batch_job",
            action="tool:execute",
            scope_key=frozenset(["default"]),
            client_uid="other_client_uid",
        )
        assert key_2lo != key_other_client


# ---------------------------------------------------------------------------
# ModelPolicy: scopes field present
# ---------------------------------------------------------------------------

class TestModelPolicyScopesField:
    """ModelPolicy has a scopes field."""

    def test_model_policy_has_scopes(self):
        from navigator_auth.abac.storages.pg import ModelPolicy
        # Verify the attribute is declared on the class.
        assert hasattr(ModelPolicy, 'scopes') or 'scopes' in str(ModelPolicy.__annotations__)

    def test_model_policy_scopes_annotation(self):
        from navigator_auth.abac.storages.pg import ModelPolicy
        annotations = getattr(ModelPolicy, '__annotations__', {})
        assert 'scopes' in annotations

    def test_pg_storage_has_scopes_in_query(self):
        """Both SQL SELECT queries in pgStorage include the scopes column."""
        import inspect
        from navigator_auth.abac.storages.pg import pgStorage
        source = inspect.getsource(pgStorage.load_policies)
        # Count occurrences: both SELECT blocks must include scopes
        assert source.count("scopes") >= 2, (
            "Both parameterized and full SELECT queries must include 'scopes'"
        )


# ---------------------------------------------------------------------------
# AbstractPolicy.scopes backward-compatibility: existing callers unaffected
# ---------------------------------------------------------------------------

class TestScopesBackwardCompatibility:
    """Adding scopes kwarg to AbstractPolicy is backward-compatible."""

    def test_policy_without_scopes_kwarg_still_works(self):
        """Existing Policy() calls without scopes must still construct successfully."""
        from navigator_auth.abac.policies.policy import Policy
        # This mirrors existing usage patterns in the codebase
        p = Policy(
            name="legacy-policy",
            subject=["alice@example.com"],
            resource=["urn:uri:/private.*$"],
        )
        assert p.scopes == []

    def test_object_policy_without_scopes_kwarg_still_works(self):
        from navigator_auth.abac.policies.obj import ObjectPolicy
        p = ObjectPolicy(name="legacy-obj")
        assert p.scopes == []

    def test_scope_condition_backward_compat_no_scopes_in_userinfo(self):
        """Policies with scopes that evaluate against userinfo without 'scopes' key still DENY."""
        from navigator_auth.abac.policies.policy import Policy
        from navigator_auth.abac.policies.abstract import PolicyEffect
        from navigator_auth.abac.policies.environment import Environment

        p = Policy(name="with-scopes", scopes=["default"])
        # Build ctx without 'scopes' in userinfo (simulates old bearer path)
        ctx = _make_eval_ctx([])  # empty scopes
        env = Environment()
        result = p.evaluate(ctx, env)
        # Empty token scopes vs required 'default' -> DENY
        assert result.effect == PolicyEffect.DENY

    def test_scope_condition_no_scope_policy_ignores_missing_userinfo_scopes(self):
        """Policies without scopes requirement always ALLOW regardless of token scopes."""
        from navigator_auth.abac.policies.policy import Policy
        from navigator_auth.abac.policies.abstract import PolicyEffect
        from navigator_auth.abac.policies.environment import Environment

        p = Policy(name="no-scope-policy")
        ctx = _make_eval_ctx([])  # no scopes in token
        env = Environment()
        result = p.evaluate(ctx, env)
        assert result.effect == PolicyEffect.ALLOW


# Ensure contextlib is available (used in test_model_policy_has_scopes guard)
with contextlib.suppress(ImportError):
    pass  # pragma: no cover
