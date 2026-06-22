"""
Integration tests for per-tenant policy scoping (FEAT-092).

These tests exercise the full stack:
  ResourcePolicy → PolicyAdapter → PolicyEvaluator → Rust engine (real, no mocks).

Test matrix (from spec §4):
  - test_e2e_tenant_isolation
  - test_e2e_global_policy_applies_to_all
  - test_e2e_tenant_overrides_global_deny
  - test_e2e_backward_compat_no_tenant
  - test_e2e_reload_preserves_tenant

Unit tests (inline, no DB/mock needed):
  - test_resourcepolicy_tenant_defaults
  - test_resourcepolicy_tenant_explicit
  - test_adapter_carries_tenant
  - test_adapter_negated_inherits_tenant
  - test_serialize_includes_tenant
  - test_cache_key_tenant_isolation
  - test_evalcontext_tenant_resolution
  - test_evalcontext_header_gated
  - test_evalcontext_partial_header_ignored
"""
import json
from unittest.mock import MagicMock
from aiohttp import web

from navigator_auth.abac.policies.resource_policy import ResourcePolicy
from navigator_auth.abac.policies.adapter import PolicyAdapter
from navigator_auth.abac.policies.evaluator import PolicyEvaluator
from navigator_auth.abac.policies.resources import ResourceType
from navigator_auth.abac.context import EvalContext

from tests.conftest import build_evaluator_from_dicts


# ===========================================================================
# Unit tests — ResourcePolicy (Module 1)
# ===========================================================================

class TestResourcePolicyTenantAttrs:
    def test_resourcepolicy_tenant_defaults(self):
        p = ResourcePolicy(name="p")
        assert p.org_id == 1
        assert p.client_id == 1

    def test_resourcepolicy_tenant_explicit(self):
        p = ResourcePolicy(name="p", org_id=5, client_id=3)
        assert (p.org_id, p.client_id) == (5, 3)

    def test_resourcepolicy_tenant_zero_is_stored(self):
        """0 is not a valid sentinel but must be stored as-is (validation elsewhere)."""
        p = ResourcePolicy(name="p", org_id=0, client_id=0)
        assert (p.org_id, p.client_id) == (0, 0)


# ===========================================================================
# Unit tests — PolicyAdapter (Module 2)
# ===========================================================================

class TestAdapterCarriesTenant:
    def test_adapter_carries_tenant_from_dict(self):
        """A policy dict with org_id/client_id produces matching ResourcePolicy."""
        d = {
            "name": "p",
            "effect": "ALLOW",
            "resource": ["tool:*"],
            "actions": ["tool:execute"],
            "groups": ["eng"],
            "org_id": 5,
            "client_id": 3,
        }
        result = PolicyAdapter.adapt(d)
        assert not result.skipped
        assert (result.policy.org_id, result.policy.client_id) == (5, 3)

    def test_adapter_defaults_tenant_when_missing(self):
        """A dict without tenant keys defaults to (1, 1)."""
        d = {
            "name": "p",
            "effect": "ALLOW",
            "resource": ["tool:*"],
            "actions": ["tool:execute"],
            "groups": ["eng"],
        }
        result = PolicyAdapter.adapt(d)
        assert not result.skipped
        assert (result.policy.org_id, result.policy.client_id) == (1, 1)

    def test_adapter_negated_inherits_tenant(self):
        """The auto-generated _negated DENY policy inherits the parent's tenant."""
        d = {
            "name": "p",
            "effect": "ALLOW",
            "resource": ["tool:jira_*", "!tool:jira_admin"],
            "actions": ["tool:execute"],
            "groups": ["eng"],
            "org_id": 7,
            "client_id": 2,
        }
        result = PolicyAdapter.adapt(d)
        assert not result.skipped
        assert (result.policy.org_id, result.policy.client_id) == (7, 2)
        # The negated deny policies must carry the same tenant
        assert result.additional_policies, "Expected negated deny policy"
        for deny in result.additional_policies:
            assert (deny.org_id, deny.client_id) == (7, 2), (
                f"Negated policy tenant mismatch: got ({deny.org_id}, {deny.client_id})"
            )

    def test_adapter_coerces_non_int_tenant(self):
        """String org_id/client_id values are coerced to int."""
        d = {
            "name": "p",
            "effect": "ALLOW",
            "resource": ["tool:*"],
            "actions": ["tool:execute"],
            "groups": ["eng"],
            "org_id": "5",
            "client_id": "3",
        }
        result = PolicyAdapter.adapt(d)
        assert not result.skipped
        assert (result.policy.org_id, result.policy.client_id) == (5, 3)

    def test_adapter_coerces_none_tenant_to_1(self):
        """None org_id/client_id values fall back to 1."""
        d = {
            "name": "p",
            "effect": "ALLOW",
            "resource": ["tool:*"],
            "actions": ["tool:execute"],
            "groups": ["eng"],
            "org_id": None,
            "client_id": None,
        }
        result = PolicyAdapter.adapt(d)
        assert not result.skipped
        assert (result.policy.org_id, result.policy.client_id) == (1, 1)


# ===========================================================================
# Unit tests — PolicyEvaluator serialization + cache key (Module 3)
# ===========================================================================

class TestEvaluatorTenantSerialization:
    def test_serialize_includes_tenant(self):
        """Serialized policy JSON must include org_id and client_id."""
        ev = PolicyEvaluator()
        policy = ResourcePolicy(
            name="p",
            resources=["tool:*"],
            actions=["tool:execute"],
            subjects={"groups": ["eng"]},
            org_id=5,
            client_id=3,
        )
        ev.load_policies([policy])
        data = json.loads(ev._policies_json)
        assert len(data) == 1
        assert data[0]["org_id"] == 5
        assert data[0]["client_id"] == 3

    def test_serialize_defaults_to_1_when_no_tenant_attr(self):
        """Policies without org_id/client_id serialize to 1 (global)."""
        ev = PolicyEvaluator()
        policy = ResourcePolicy(name="p", resources=["tool:*"])
        # Explicitly delete the attribute to simulate old code path
        del policy.org_id
        del policy.client_id
        ev.load_policies([policy])
        data = json.loads(ev._policies_json)
        assert data[0]["org_id"] == 1
        assert data[0]["client_id"] == 1

    def test_cache_key_tenant_isolation(self):
        """Same user/resource/action but different org_id → different cache keys."""
        ev = PolicyEvaluator()
        k1 = ev._make_cache_key(
            "u", {"eng"}, ResourceType.TOOL, "jira", "tool:execute",
            org_id=1, client_id=1,
        )
        k2 = ev._make_cache_key(
            "u", {"eng"}, ResourceType.TOOL, "jira", "tool:execute",
            org_id=5, client_id=1,
        )
        assert k1 != k2, "Different org_id must produce different cache keys"

    def test_cache_key_client_isolation(self):
        """Same user/resource/action but different client_id → different cache keys."""
        ev = PolicyEvaluator()
        k1 = ev._make_cache_key(
            "u", {"eng"}, ResourceType.TOOL, "jira", "tool:execute",
            org_id=5, client_id=1,
        )
        k2 = ev._make_cache_key(
            "u", {"eng"}, ResourceType.TOOL, "jira", "tool:execute",
            org_id=5, client_id=3,
        )
        assert k1 != k2, "Different client_id must produce different cache keys"


# ===========================================================================
# Unit tests — EvalContext resolution (Module 4)
# ===========================================================================

class TestEvalContextTenantResolution:
    """Resolution order: kwarg > header > userinfo > default 1."""

    def _make_req(self, headers=None):
        req = MagicMock(spec=web.Request)
        req.path = "/test"
        req.method = "GET"
        req.path_qs = "/test"
        req.rel_url = "/test"
        req.remote = "127.0.0.1"
        req.headers = headers or {}
        req.is_authenticated = True
        return req

    def test_kwarg_wins_over_userinfo(self):
        """Explicit kwarg overrides userinfo."""
        userinfo = {"org_id": 9, "client_id": 9, "username": "u", "groups": []}
        ctx = EvalContext(
            self._make_req(), None, userinfo, None,
            org_id=5, client_id=3,
        )
        assert (ctx.org_id, ctx.client_id) == (5, 3)

    def test_userinfo_resolves_tenant(self):
        """When no kwarg, userinfo values are used."""
        userinfo = {"org_id": 5, "client_id": 3, "username": "u", "groups": []}
        ctx = EvalContext(self._make_req(), None, userinfo, None)
        assert (ctx.org_id, ctx.client_id) == (5, 3)

    def test_missing_userinfo_defaults_to_1(self):
        """When userinfo has no tenant keys, default (1, 1) is used."""
        userinfo = {"username": "u", "groups": []}
        ctx = EvalContext(self._make_req(), None, userinfo, None)
        assert (ctx.org_id, ctx.client_id) == (1, 1)

    def test_none_userinfo_defaults_to_1(self):
        """When userinfo is None, default (1, 1) is used."""
        ctx = EvalContext(self._make_req(), None, None, None)
        assert (ctx.org_id, ctx.client_id) == (1, 1)

    def test_headers_ignored_when_trust_headers_false(self):
        """X-Org-Id / X-Client-Id headers are ignored when ABAC_TENANT_TRUST_HEADERS=False."""
        import navigator_auth.abac.context as ctx_mod
        orig = ctx_mod._ABAC_TENANT_TRUST_HEADERS
        try:
            ctx_mod._ABAC_TENANT_TRUST_HEADERS = False
            userinfo = {"org_id": 1, "client_id": 1, "username": "u", "groups": []}
            req = self._make_req(headers={"X-Org-Id": "5", "X-Client-Id": "3"})
            ctx = EvalContext(req, None, userinfo, None)
            # Should fall through to userinfo (1, 1), NOT headers (5, 3)
            assert (ctx.org_id, ctx.client_id) == (1, 1)
        finally:
            ctx_mod._ABAC_TENANT_TRUST_HEADERS = orig

    def test_partial_header_ignored(self):
        """Only X-Org-Id without X-Client-Id → header pair ignored."""
        import navigator_auth.abac.context as ctx_mod
        orig = ctx_mod._ABAC_TENANT_TRUST_HEADERS
        try:
            ctx_mod._ABAC_TENANT_TRUST_HEADERS = True
            userinfo = {"org_id": 9, "client_id": 9, "username": "u", "groups": []}
            req = self._make_req(headers={"X-Org-Id": "5"})  # only org, no client
            ctx = EvalContext(req, None, userinfo, None)
            # Partial header set → skip to userinfo (9, 9)
            assert (ctx.org_id, ctx.client_id) == (9, 9)
        finally:
            ctx_mod._ABAC_TENANT_TRUST_HEADERS = orig

    def test_headers_honored_when_trust_headers_true(self):
        """Headers are used when ABAC_TENANT_TRUST_HEADERS=True and both present."""
        import navigator_auth.abac.context as ctx_mod
        orig = ctx_mod._ABAC_TENANT_TRUST_HEADERS
        try:
            ctx_mod._ABAC_TENANT_TRUST_HEADERS = True
            userinfo = {"org_id": 9, "client_id": 9, "username": "u", "groups": []}
            req = self._make_req(headers={"X-Org-Id": "5", "X-Client-Id": "3"})
            ctx = EvalContext(req, None, userinfo, None)
            # Headers should win over userinfo when trust_headers=True
            assert (ctx.org_id, ctx.client_id) == (5, 3)
        finally:
            ctx_mod._ABAC_TENANT_TRUST_HEADERS = orig


# ===========================================================================
# Integration tests — full stack through real Rust engine (Module 6)
# ===========================================================================

class TestE2ETenantScoping:
    """End-to-end tenant isolation tests using the real Rust engine (no mocks)."""

    def test_e2e_tenant_isolation(self, tenant_policies, ctx_tenant_5, ctx_tenant_7):
        """Tenant A's enforcing deny does NOT apply to Tenant B."""
        ev = build_evaluator_from_dicts(tenant_policies)

        # Tenant 5 is blocked from jira by the enforcing deny
        r5 = ev.check_access(
            ctx_tenant_5, ResourceType.TOOL, "jira_create", "tool:execute",
            org_id=5, client_id=1,
        )
        assert not r5.allowed, "Tenant 5 should be denied jira by its enforcing policy"

        # Tenant 7 only sees the global allow
        r7 = ev.check_access(
            ctx_tenant_7, ResourceType.TOOL, "jira_create", "tool:execute",
            org_id=7, client_id=1,
        )
        assert r7.allowed, "Tenant 7 should be allowed (only global allow applies)"

    def test_e2e_global_policy_applies_to_all(self, tenant_policies, ctx_tenant_5, ctx_tenant_7):
        """The org_id=1 allow policy grants access to all tenants for non-blocked tools."""
        ev = build_evaluator_from_dicts(tenant_policies)

        # Both tenants can use slack (global allow covers tool:*)
        for ctx, tenant_name, org_id in [
            (ctx_tenant_5, "tenant 5", 5),
            (ctx_tenant_7, "tenant 7", 7),
        ]:
            result = ev.check_access(
                ctx, ResourceType.TOOL, "slack_send", "tool:execute",
                org_id=org_id, client_id=1,
            )
            assert result.allowed, f"{tenant_name} should be allowed slack by global policy"

    def test_e2e_tenant_overrides_global_deny(self, ctx_tenant_5, ctx_tenant_7):
        """A higher-priority tenant-specific deny overrides a global allow for that tenant only."""
        policies = [
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
                "name": "t5_block_github",
                "effect": "DENY",
                "policy_type": "policy",
                "resource": ["tool:github_*"],
                "actions": ["tool:execute"],
                "groups": ["engineering"],
                "priority": 20,
                "enforcing": True,
                "org_id": 5,
                "client_id": 1,
            },
        ]
        ev = build_evaluator_from_dicts(policies)

        # Tenant 5 is blocked from github
        r5 = ev.check_access(
            ctx_tenant_5, ResourceType.TOOL, "github_pr", "tool:execute",
            org_id=5, client_id=1,
        )
        assert not r5.allowed, "Tenant 5 must be denied github by tenant-specific deny"

        # Tenant 7 is still allowed github (only global allow)
        r7 = ev.check_access(
            ctx_tenant_7, ResourceType.TOOL, "github_pr", "tool:execute",
            org_id=7, client_id=1,
        )
        assert r7.allowed, "Tenant 7 must NOT be affected by tenant-5 deny"

    def test_e2e_backward_compat_no_tenant(self, ctx_no_tenant):
        """With all defaults (org_id=1, client_id=1) and no tenant on requests,
        decisions are identical to pre-feature behaviour."""
        policies = [
            {
                "name": "global_allow",
                "effect": "ALLOW",
                "policy_type": "policy",
                "resource": ["tool:*"],
                "actions": ["tool:execute"],
                "groups": ["engineering"],
                "priority": 1,
                # No org_id / client_id — defaults to 1/1 via adapter
            },
        ]
        ev = build_evaluator_from_dicts(policies)

        # No tenant args → behaves exactly like pre-feature (global defaults)
        result = ev.check_access(
            ctx_no_tenant, ResourceType.TOOL, "jira_create", "tool:execute",
        )
        assert result.allowed, "Backward-compat: global allow must still work without tenant args"

    def test_e2e_reload_preserves_tenant(self, tenant_policies, ctx_tenant_5, ctx_tenant_7):
        """After reload_policies (swap_index), tenant scoping still holds."""
        from navigator_auth.abac.policies.evaluator import PolicyIndex

        ev = build_evaluator_from_dicts(tenant_policies)

        # Simulate a reload by building a new index and swapping it in
        resource_policies, _ = PolicyAdapter.adapt_batch(tenant_policies)
        new_index = PolicyIndex()
        for p in resource_policies:
            new_index.add(p)
        new_index.finalize()
        ev.swap_index(new_index)

        # Tenant 5 still blocked
        r5 = ev.check_access(
            ctx_tenant_5, ResourceType.TOOL, "jira_create", "tool:execute",
            org_id=5, client_id=1,
        )
        assert not r5.allowed, "After reload, tenant 5 must still be denied jira"

        # Tenant 7 still allowed
        r7 = ev.check_access(
            ctx_tenant_7, ResourceType.TOOL, "jira_create", "tool:execute",
            org_id=7, client_id=1,
        )
        assert r7.allowed, "After reload, tenant 7 must still be allowed jira"

    def test_e2e_batch_filter_tenant_isolation(self, tenant_policies, ctx_tenant_5, ctx_tenant_7):
        """filter_resources (batch path) also respects tenant scoping."""
        ev = build_evaluator_from_dicts(tenant_policies)

        # Tenant 5: jira tools should be denied, slack allowed
        result5 = ev.filter_resources(
            ctx_tenant_5, ResourceType.TOOL,
            ["jira_create", "jira_search", "slack_send"],
            "tool:execute",
            org_id=5, client_id=1,
        )
        # jira_* denied by enforcing policy for tenant 5
        for denied_tool in ["jira_create", "jira_search"]:
            assert denied_tool in result5.denied, (
                f"Tenant 5: {denied_tool} must be in denied list"
            )
        assert "slack_send" in result5.allowed, "Tenant 5: slack_send must be allowed"

        # Tenant 7: all tools allowed (only global allow)
        result7 = ev.filter_resources(
            ctx_tenant_7, ResourceType.TOOL,
            ["jira_create", "jira_search", "slack_send"],
            "tool:execute",
            org_id=7, client_id=1,
        )
        for allowed_tool in ["jira_create", "jira_search", "slack_send"]:
            assert allowed_tool in result7.allowed, (
                f"Tenant 7: {allowed_tool} must be allowed"
            )
