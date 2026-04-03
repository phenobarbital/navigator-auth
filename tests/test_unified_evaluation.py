import pytest
import asyncio
from datetime import datetime
from unittest.mock import MagicMock
from aiohttp import web
from navigator_auth.abac.policies import (
    Policy, 
    FilePolicy, 
    ObjectPolicy, 
    PolicyEffect, 
    Environment
)
from navigator_auth.abac.policies.resource_policy import ResourcePolicy
from navigator_auth.abac.policies.evaluator import PolicyEvaluator
from navigator_auth.abac.policies.adapter import PolicyAdapter
from navigator_auth.abac.policies.resources import ResourceType
from navigator_auth.abac.context import EvalContext

@pytest.fixture
def user_info():
    return {
        "username": "jlara@trocglobal.com",
        "groups": ["superuser", "engineering"],
        "roles": ["admin"]
    }

@pytest.fixture
def eval_context(user_info):
    request = MagicMock(spec=web.Request)
    request.path = "/api/v1/admin/dashboard"
    request.method = "GET"
    
    class User:
        def __init__(self):
            self.username = user_info["username"]
            self.groups = user_info["groups"]
            self.id = 1
            
    return EvalContext(request, User(), user_info, None)

@pytest.fixture
def environment():
    return Environment()

@pytest.fixture
def evaluator():
    return PolicyEvaluator()

class TestUnifiedPolicyEvaluation:
    """Tests 'real' evaluation of policy objects through the unified Rust-backed pipeline."""

    def test_resource_policy_evaluation(self, evaluator, eval_context, environment):
        """Test ResourcePolicy (native to new engine)."""
        policy = ResourcePolicy(
            name="allow_eng_tools",
            effect=PolicyEffect.ALLOW,
            resources=["tool:jira_*"],
            actions=["tool:execute"],
            subjects={"groups": ["engineering"]},
            priority=10
        )
        evaluator.load_policies([policy])
        
        result = evaluator.check_access(
            eval_context, ResourceType.TOOL, "jira_create", "tool:execute", environment
        )
        assert result.allowed is True
        assert result.matched_policy == "allow_eng_tools"

    def test_classic_uri_policy_evaluation(self, evaluator, eval_context, environment):
        """Test classic Policy object (URI resources)."""
        # PDP converts this to ResourcePolicy via Adapter
        policy_dict = {
            "name": "admin_uri_access",
            "policy_type": "policy",
            "effect": "ALLOW",
            "resources": ["urn:uri:/api/v1/admin/*"],
            "groups": ["superuser"],
            "priority": 5
        }
        
        policies, _ = PolicyAdapter.adapt_batch([policy_dict])
        evaluator.load_policies(policies)
        
        # Test success
        result = evaluator.check_access(
            eval_context, ResourceType.URI, "/api/v1/admin/users", "uri:read", environment
        )
        assert result.allowed is True
        assert result.matched_policy == "admin_uri_access"
        
        # Test failure (non-matching path)
        result2 = evaluator.check_access(
            eval_context, ResourceType.URI, "/api/v1/public", "uri:read", environment
        )
        assert result2.allowed is False

    def test_file_policy_evaluation(self, evaluator, eval_context, environment):
        """Test classic FilePolicy object."""
        policy_dict = {
            "name": "reports_access",
            "policy_type": "file",
            "effect": "ALLOW",
            "resources": ["urn:uri:/reports/*.pdf"],
            "groups": ["engineering"],
            "priority": 10
        }
        
        policies, _ = PolicyAdapter.adapt_batch([policy_dict])
        evaluator.load_policies(policies)
        
        result = evaluator.check_access(
            eval_context, ResourceType.URI, "/reports/q1_results.pdf", "uri:read", environment
        )
        assert result.allowed is True
        assert result.matched_policy == "reports_access"

    def test_object_policy_evaluation(self, evaluator, eval_context, environment):
        """Test classic ObjectPolicy object."""
        policy_dict = {
            "name": "widget_management",
            "policy_type": "object",
            "effect": "ALLOW",
            "type": "widget",
            "objects": ["dashboard_widget", "summary_widget"],
            "actions": ["widget:edit"],
            "groups": ["superuser"]
        }

        policies, _ = PolicyAdapter.adapt_batch([policy_dict])
        evaluator.load_policies(policies)

        result = evaluator.check_access(
            eval_context, ResourceType.WIDGET, "dashboard_widget", "widget:edit", environment
        )
        assert result.allowed is True
        assert result.matched_policy == "widget_management"

    def test_card_resource_evaluation(self, evaluator, eval_context, environment):
        """Test the new CARD resource type."""
        policy = ResourcePolicy(
            name="allow_specific_cards",
            effect=PolicyEffect.ALLOW,
            resources=["card:kpi_*", "card:sales_chart"],
            actions=["card:view"],
            subjects={"groups": ["engineering"]},
            priority=50
        )
        evaluator.load_policies([policy])

        # Test success (glob)
        r1 = evaluator.check_access(eval_context, ResourceType.CARD, "kpi_users", "card:view")
        assert r1.allowed is True

        # Test success (exact)
        r2 = evaluator.check_access(eval_context, ResourceType.CARD, "sales_chart", "card:view")
        assert r2.allowed is True

        # Test failure
        r3 = evaluator.check_access(eval_context, ResourceType.CARD, "admin_config", "card:view")
        assert r3.allowed is False
    def test_regex_policy_evaluation(self, evaluator, eval_context, environment):
        """Test policy with regex resources."""
        policy = ResourcePolicy(
            name="block_printers_regex",
            effect=PolicyEffect.DENY,
            resources=["uri:^/printers/.*$"],
            subjects={"groups": ["*"]},
            priority=100,
            enforcing=True
        )
        evaluator.load_policies([policy])
        
        result = evaluator.check_access(
            eval_context, ResourceType.URI, "/printers/epson/status", "uri:read", environment
        )
        assert result.allowed is False
        assert result.matched_policy == "block_printers_regex"

    def test_negated_resource_evaluation(self, evaluator, eval_context, environment):
        """Test classic policy with negated resource (!pattern)."""
        policy_dict = {
            "name": "allow_except_secret",
            "policy_type": "policy",
            "effect": "ALLOW",
            "resources": ["urn:uri:/api/v1/public/*", "!urn:uri:/api/v1/public/secret"],
            "groups": ["*"],
            "priority": 10
        }
        
        # Adapter should create an ALLOW and a higher priority DENY enforcing policy
        policies, _ = PolicyAdapter.adapt_batch([policy_dict])
        evaluator.load_policies(policies)
        
        # Should allow normal public path
        r1 = evaluator.check_access(
            eval_context, ResourceType.URI, "/api/v1/public/home", "uri:read", environment
        )
        assert r1.allowed is True
        
        # Should deny secret path (negated)
        r2 = evaluator.check_access(
            eval_context, ResourceType.URI, "/api/v1/public/secret", "uri:read", environment
        )
        assert r2.allowed is False
        assert r2.matched_policy == "allow_except_secret_negated"

    def test_mixed_policy_priorities(self, evaluator, eval_context, environment):
        """Test complex priority and tie-breaking (Deny beats Allow on same priority)."""
        p1 = ResourcePolicy(
            name="allow_low", effect=PolicyEffect.ALLOW, 
            resources=["tool:*"], actions=["tool:execute"],
            subjects={"groups": ["*"]}, priority=10
        )
        p2 = ResourcePolicy(
            name="deny_high", effect=PolicyEffect.DENY, 
            resources=["tool:forbidden"], actions=["tool:execute"],
            subjects={"groups": ["*"]}, priority=20
        )
        p3 = ResourcePolicy(
            name="allow_tied", effect=PolicyEffect.ALLOW, 
            resources=["tool:tied"], actions=["tool:execute"],
            subjects={"groups": ["*"]}, priority=30
        )
        p4 = ResourcePolicy(
            name="deny_tied", effect=PolicyEffect.DENY, 
            resources=["tool:tied"], actions=["tool:execute"],
            subjects={"groups": ["*"]}, priority=30
        )
        
        evaluator.load_policies([p1, p2, p3, p4])
        
        # Deny high wins over Allow low
        r1 = evaluator.check_access(eval_context, ResourceType.TOOL, "forbidden", "tool:execute")
        assert r1.allowed is False
        assert r1.matched_policy == "deny_high"
        
        # Deny tied wins over Allow tied (equal priority)
        r2 = evaluator.check_access(eval_context, ResourceType.TOOL, "tied", "tool:execute")
        assert r2.allowed is False
        assert r2.matched_policy == "deny_tied"
