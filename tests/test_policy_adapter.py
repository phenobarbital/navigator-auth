import pytest
from navigator_auth.abac.policies.adapter import PolicyAdapter
from navigator_auth.abac.policies.abstract import PolicyEffect
from navigator_auth.abac.policies.resources import ResourceType

def get_pattern_str(rp):
    # rp.resource_type can be an Enum or a string
    rtype = rp.resource_type.value if hasattr(rp.resource_type, 'value') else rp.resource_type
    return f"{rtype}:{rp.pattern}"

@pytest.fixture
def classic_policy_dict():
    return {
        "name": "admin_dashboard",
        "policy_type": "policy",
        "effect": "allow",
        "groups": ["admin"],
        "subject": ["jlara@trocglobal.com"],
        "resources": ["urn:uri:/api/v1/admin/*"],
        "actions": ["dashboard:view", "dashboard:edit"],
        "environment": {"is_business_hours": True},
        "priority": 10,
        "enforcing": False
    }

@pytest.fixture
def file_policy_dict():
    return {
        "name": "reports_access",
        "policy_type": "file",
        "effect": "allow",
        "groups": ["analytics"],
        "resources": ["urn:uri:/reports/*.pdf"],
        "actions": ["file:read"],
        "priority": 5
    }

@pytest.fixture
def resource_policy_dict():
    return {
        "name": "engineering_tools",
        "policy_type": "resource",
        "effect": "allow",
        "resources": ["tool:jira_*", "tool:github_*"],
        "actions": ["tool:execute"],
        "subjects": {"groups": ["engineering"]},
        "priority": 10
    }

class TestPolicyAdapter:
    def test_adapt_classic_policy(self, classic_policy_dict):
        result = PolicyAdapter.adapt(classic_policy_dict)
        assert not result.skipped
        assert result.policy is not None
        assert result.policy.name == "admin_dashboard"
        # Check resources conversion
        resources = [get_pattern_str(r) for r in result.policy._resource_patterns]
        assert "uri:/api/v1/admin/*" in resources
        assert result.policy.effect == PolicyEffect.ALLOW

    def test_adapt_urn_uri(self):
        d = {"name": "test", "policy_type": "policy", "effect": "allow",
             "resources": ["urn:uri:/api/v1/example/"], "groups": ["admin"]}
        result = PolicyAdapter.adapt(d)
        assert not result.skipped
        resources = [get_pattern_str(r) for r in result.policy._resource_patterns]
        assert "uri:/api/v1/example/" in resources

    def test_adapt_urn_regex(self):
        d = {"name": "test", "policy_type": "policy", "effect": "deny",
             "resources": ["urn:uri:/epson.*$"], "groups": ["*"]}
        result = PolicyAdapter.adapt(d)
        assert not result.skipped
        resources = [get_pattern_str(r) for r in result.policy._resource_patterns]
        assert "uri:/epson.*$" in resources

    def test_adapt_negated_resource(self):
        d = {"name": "test", "policy_type": "policy", "effect": "allow",
             "resources": ["!urn:uri:/api/v1/secret/"], "groups": ["admin"]}
        result = PolicyAdapter.adapt(d)
        assert not result.skipped
        assert result.policy is not None
        assert len(result.additional_policies) == 1
        deny_policy = result.additional_policies[0]
        assert deny_policy.effect == PolicyEffect.DENY
        assert "uri:/api/v1/secret/" in [get_pattern_str(r) for r in deny_policy._resource_patterns]

    def test_adapt_file_policy(self, file_policy_dict):
        result = PolicyAdapter.adapt(file_policy_dict)
        assert not result.skipped
        assert result.policy is not None
        resources = [get_pattern_str(r) for r in result.policy._resource_patterns]
        assert "uri:/reports/*.pdf" in resources

    def test_adapt_object_policy(self):
        d = {
            "name": "object_policy",
            "policy_type": "object",
            "effect": "allow",
            "type": "dashboard",
            "objects": ["sales", "marketing"],
            "groups": ["managers"]
        }
        result = PolicyAdapter.adapt(d)
        assert not result.skipped
        resources = [get_pattern_str(r) for r in result.policy._resource_patterns]
        assert "dashboard:sales" in resources
        assert "dashboard:marketing" in resources

    def test_adapt_resource_passthrough(self, resource_policy_dict):
        result = PolicyAdapter.adapt(resource_policy_dict)
        assert result.policy.name == "engineering_tools"
        resources = [get_pattern_str(r) for r in result.policy._resource_patterns]
        assert "tool:jira_*" in resources

    def test_adapt_batch_mixed(self, classic_policy_dict, file_policy_dict, resource_policy_dict):
        dicts = [classic_policy_dict, file_policy_dict, resource_policy_dict]
        policies, warnings = PolicyAdapter.adapt_batch(dicts)
        # classic_policy_dict, file_policy_dict, resource_policy_dict
        assert len(policies) == 3
        assert len(warnings) == 0

    def test_adapt_invalid_regex_skipped(self):
        d = {"name": "bad", "policy_type": "policy", "effect": "allow",
             "resources": ["urn:uri:invalid(regex["], "groups": ["admin"]}
        result = PolicyAdapter.adapt(d)
        assert len(result.warnings) > 0
        assert len(result.policy._resource_patterns) == 0

    def test_adapt_urn_complex(self):
        # urn:namespace:type::parts -> type:parts
        urn = "urn:navigator:dashboard::12345"
        conv, negated = PolicyAdapter._convert_urn(urn)
        assert conv == "dashboard:12345"
        assert not negated

        urn2 = "urn:navigator:dashboard::*"
        conv2, negated2 = PolicyAdapter._convert_urn(urn2)
        assert conv2 == "dashboard:*"

    def test_action_mapping(self):
        d = {"name": "test", "policy_type": "policy", "effect": "allow",
             "resources": ["uri:/test"], "actions": ["GET", "POST", "custom:action"]}
        result = PolicyAdapter.adapt(d)
        assert "uri:read" in result.policy._actions
        assert "uri:write" in result.policy._actions
        assert "custom:action" in result.policy._actions
