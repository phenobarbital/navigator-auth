import pytest
from unittest.mock import MagicMock
from aiohttp import web
from navigator_auth.abac.policies.evaluator import PolicyEvaluator, EvaluationResult
from navigator_auth.abac.policies.resource_policy import ResourcePolicy
from navigator_auth.abac.policies.resources import ResourceType
from navigator_auth.abac.policies import PolicyEffect
from navigator_auth.abac.policies.environment import Environment
from navigator_auth.abac.context import EvalContext

def make_eval_context(username="testuser", groups=None):
    request = MagicMock(spec=web.Request)
    request.remote = "127.0.0.1"
    request.method = "GET"
    request.headers = {}
    request.path = "/test"
    request.path_qs = "/test"
    request.rel_url = MagicMock()
    
    user = MagicMock()
    user.__dict__ = {}
    
    userinfo = {
        "username": username,
        "groups": groups or []
    }
    
    return EvalContext(request, user, userinfo, None)

class TestEvaluatorRust:
    @pytest.fixture
    def evaluator_with_policies(self):
        evaluator = PolicyEvaluator()
        policy = ResourcePolicy(
            name="allow_engineering_tools",
            effect=PolicyEffect.ALLOW,
            resources=["tool:jira_*", "tool:github_*"],
            actions=["tool:execute"],
            subjects={"groups": ["engineering"]},
            priority=10,
        )
        evaluator.load_policies([policy])
        return evaluator

    def test_check_access_allowed(self, evaluator_with_policies):
        ctx = make_eval_context(username="dev", groups=["engineering"])
        result = evaluator_with_policies.check_access(
            ctx, ResourceType.TOOL, "jira_create", "tool:execute"
        )
        assert result.allowed is True
        assert result.matched_policy == "allow_engineering_tools"

    def test_check_access_denied(self, evaluator_with_policies):
        ctx = make_eval_context(username="guest", groups=["visitors"])
        result = evaluator_with_policies.check_access(
            ctx, ResourceType.TOOL, "jira_create", "tool:execute"
        )
        assert result.allowed is False
        assert result.matched_policy is None

    def test_filter_resources_batch(self, evaluator_with_policies):
        ctx = make_eval_context(username="dev", groups=["engineering"])
        result = evaluator_with_policies.filter_resources(
            ctx, ResourceType.TOOL,
            ["jira_create", "slack_send", "github_pr"],
            "tool:execute"
        )
        assert "jira_create" in result.allowed
        assert "github_pr" in result.allowed
        assert "slack_send" in result.denied

    def test_policies_json_cached(self, evaluator_with_policies):
        json1 = evaluator_with_policies._policies_json
        json2 = evaluator_with_policies._policies_json
        assert json1 is json2  # Same object, not rebuilt

    def test_cache_hit_no_rust_call(self, evaluator_with_policies):
        ctx = make_eval_context(username="dev", groups=["engineering"])
        # First call hits Rust
        r1 = evaluator_with_policies.check_access(
            ctx, ResourceType.TOOL, "jira_create", "tool:execute"
        )
        assert r1.cached is False
        
        # Second call hits LRU cache
        r2 = evaluator_with_policies.check_access(
            ctx, ResourceType.TOOL, "jira_create", "tool:execute"
        )
        assert r2.cached is True

    def test_rust_regex_deny(self):
        evaluator = PolicyEvaluator()
        policy = ResourcePolicy(
            name="block_printers",
            effect=PolicyEffect.DENY,
            resources=["uri:epson.*$"],
            actions=[],
            subjects={"groups": ["*"]},
            priority=100,
            enforcing=True
        )
        evaluator.load_policies([policy])
        
        ctx = make_eval_context(username="dev", groups=["engineering"])
        result = evaluator.check_access(
            ctx, ResourceType.URI, "epson_lx350", "uri:read"
        )
        assert result.allowed is False
        assert result.matched_policy == "block_printers"
