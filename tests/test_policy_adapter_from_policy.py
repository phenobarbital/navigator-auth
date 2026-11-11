"""Tests for PolicyAdapter.from_policy and AbstractPolicy.raw_resources (FEAT-109 M1)."""
import copy

import pytest

from navigator_auth.abac.policies import FilePolicy, ObjectPolicy, Policy, PolicyEffect
from navigator_auth.abac.policies.adapter import PolicyAdapter
from navigator_auth.abac.policies.resource_policy import ResourcePolicy


def _resources(policy: ResourcePolicy) -> list[str]:
    """Return ``type:pattern`` strings of an adapted policy."""
    return [
        f"{pattern.resource_type.value if hasattr(pattern.resource_type, 'value') else pattern.resource_type}:{pattern.pattern}"
        for pattern in policy._resource_patterns
    ]


def test_raw_resources_captured():
    """A string, list, and no resource retain the intended raw values."""
    string_policy = Policy(name="string", resource="urn:uri:/a")
    supplied_resources = ["urn:uri:/b"]
    list_policy = Policy(name="list", resource=supplied_resources)
    unrestricted_policy = Policy(name="unrestricted")

    supplied_resources.append("urn:uri:/c")

    assert string_policy.raw_resources == ["urn:uri:/a"]
    assert len(string_policy.resources) == 1
    assert list_policy.raw_resources == ["urn:uri:/b"]
    assert unrestricted_policy.raw_resources == []


def test_from_policy_resource_policy_passthrough():
    """ResourcePolicy instances remain unchanged."""
    resource_policy = ResourcePolicy(name="rp", resources=["tool:*"], actions=["tool:execute"])

    assert PolicyAdapter.from_policy(resource_policy).policy is resource_policy


def test_from_policy_classic_uri_regex():
    """Classic URI regex policies preserve resources and groups."""
    result = PolicyAdapter.from_policy(Policy(name="admin", resource=["urn:uri:/admin.*$"], groups=["admin"]))

    assert not result.skipped
    assert _resources(result.policy) == ["uri:/admin.*$"]
    assert result.policy._subjects.groups == {"admin"}


def test_from_policy_object_policy_urn():
    """Object-policy URNs become evaluator resource patterns."""
    result = PolicyAdapter.from_policy(
        ObjectPolicy(name="deploy", resource=["urn:navigator:deployment::*"], actions=["deployment:approve"])
    )

    assert not result.skipped
    assert _resources(result.policy) == ["deployment:*"]
    assert result.policy._actions == {"deployment:approve"}


def test_from_policy_negated_resource():
    """Negated resources generate a higher-priority enforcing deny policy."""
    result = PolicyAdapter.from_policy(
        Policy(name="api", resource=["urn:uri:/api/.*", "!urn:uri:/api/admin.*"])
    )

    assert not result.skipped
    assert result.additional_policies[0].name == "api_negated"
    assert result.additional_policies[0].effect == PolicyEffect.DENY


@pytest.mark.parametrize("resources", [["urn:uri:/admin["], ["!urn:uri:/admin["], ["urn:uri:/ok", "urn:uri:/bad["]])
def test_from_policy_invalid_regex_skipped(resources):
    """Any invalid positive or negated regex rejects the whole policy."""
    result = PolicyAdapter.from_policy(Policy(name="bad", resource=resources))

    assert result.skipped and result.reason
    assert result.policy is None and result.additional_policies == []


@pytest.mark.parametrize("policy_class", [Policy, ObjectPolicy, FilePolicy])
@pytest.mark.parametrize("effect", [PolicyEffect.ALLOW, PolicyEffect.DENY])
@pytest.mark.parametrize(
    ("restriction", "value"),
    [("context", {"department": "engineering"}), ("conditions", {"method": "GET"}), ("scopes", ["read"])],
)
def test_from_policy_unsupported_restrictions_rejected(policy_class, effect, restriction, value):
    """Unsupported classic restrictions are rejected for every policy type and effect."""
    result = PolicyAdapter.from_policy(policy_class(name="restricted", effect=effect, **{restriction: value}))

    assert result.skipped
    assert restriction in result.reason
    assert result.policy is None and result.additional_policies == []


def test_from_policy_environment_normalization():
    """Environment aliases normalize while unsupported engine shapes are rejected."""
    environment = {"day_of_week": [1, 2, 3, 4, 5], "hour": {"min": 9, "max": 17}}
    policy = Policy(name="hours", environment=environment)
    before = copy.deepcopy(policy.environment)

    result = PolicyAdapter.from_policy(policy)

    assert not result.skipped
    assert result.policy._env_conditions == {"dow": [1, 2, 3, 4, 5], "hour": {"min": 9, "max": 17}}
    assert policy.environment == before
    assert not PolicyAdapter.from_policy(Policy(name="aliases", environment={"day_of_week": 1, "dow": 1})).skipped

    invalid_environments = [
        {"day_of_week": 1, "dow": 2},
        {"unknown": True},
        {"hour": range(9, 17)},
        {"hour": {"min": 9, "foo": 1}},
        {"hour": True},
        {"is_weekend": "yes"},
    ]
    for invalid_environment in invalid_environments:
        rejected = PolicyAdapter.from_policy(Policy(name="invalid", environment=invalid_environment))
        assert rejected.skipped
        assert rejected.policy is None and rejected.additional_policies == []
