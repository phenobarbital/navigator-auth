"""The FEAT-107 policy pack parses and declares what the five guards expect.

Contract test between a YAML file and handler classes: a renamed policy or
action silently kills the superuser path, because policy_allows() fails closed
on a policy it cannot find by name. Mirrors test_auth_model_policy_pack.py.
"""

from pathlib import Path

import pytest

from navigator_auth.abac.policies.abstract import ActionKey
from navigator_auth.abac.storages.yaml_storage import YAMLStorage

POLICIES = Path(__file__).resolve().parents[3] / "navigator_auth" / "abac" / "default_policies"
PACK = POLICIES / "auth_crud_admin_access.yaml"
ADMIN_FULL = POLICIES / "admin_full_access.yaml"

EXPECTED_ACTIONS = {
    "users_admin_access": {"user:read", "user:create", "user:update", "user:delete"},
    "groups_admin_access": {"group:read", "group:create", "group:update", "group:delete"},
    "user_groups_admin_access": {"user_group:read", "user_group:create", "user_group:delete"},
    "group_permissions_admin_access": {"group_permission:read", "group_permission:create", "group_permission:delete"},
    "permissions_admin_access": {"permission:read", "permission:create", "permission:update", "permission:delete"},
    "users_grant_role": {"users:grant_role"},
}
EXPECTED_RESOURCES = {
    "users_admin_access": ["uri:/api/v1/users*"],
    "groups_admin_access": ["uri:/api/v1/groups*"],
    "user_groups_admin_access": ["uri:/api/v1/user_groups*", "uri:/api/v1/usergroups*"],
    "group_permissions_admin_access": ["uri:/api/v1/group_permissions*"],
    "permissions_admin_access": ["uri:/api/v1/permissions*"],
    "users_grant_role": [
        "uri:/api/v1/users*",
        "uri:/api/v1/user_groups*",
        "uri:/api/v1/usergroups*",
        "uri:/api/v1/groups*",
    ],
}


@pytest.fixture(scope="module")
def parsed():
    """The pack as `_parse_file` sees it (a list of policy dicts)."""
    assert PACK.exists(), f"policy pack missing: {PACK}"
    return {policy["name"]: policy for policy in YAMLStorage._parse_file(PACK)}


class TestPolicyPack:
    def test_policy_pack_parses(self, parsed):
        assert set(parsed) == set(EXPECTED_ACTIONS)
        assert len(parsed) == 6

    def test_actions_match_the_handler_contract(self, parsed):
        for name, expected in EXPECTED_ACTIONS.items():
            assert set(parsed[name]["actions"]) == expected

    def test_every_action_is_object_colon_verb(self, parsed):
        for policy in parsed.values():
            for action in policy["actions"]:
                ActionKey(action)
                assert action.count(":") == 1
                obj, verb = action.split(":")
                assert obj and verb

    def test_resources_cover_every_route(self, parsed):
        for name, expected in EXPECTED_RESOURCES.items():
            assert set(parsed[name]["resources"]) == set(expected)

    def test_surface_policies_grant_superuser_only(self, parsed):
        for name in EXPECTED_ACTIONS:
            if name != "users_grant_role":
                assert parsed[name]["subjects"]["groups"] == ["superuser"]

    def test_grant_role_held_by_security_admin(self, parsed):
        assert parsed["users_grant_role"]["subjects"]["groups"] == ["security_admin"]
        assert "superuser" not in parsed["users_grant_role"]["subjects"]["groups"]

    def test_effect_priority_enforcing(self, parsed):
        for policy in parsed.values():
            assert policy["effect"] == "ALLOW"
            assert policy["priority"] == 90
            assert policy["enforcing"] is True


class TestSeparationOfDuties:
    def test_grant_role_absent_from_admin_full_access(self):
        for policy in YAMLStorage._parse_file(ADMIN_FULL):
            for action in policy["actions"]:
                assert action != "*"
                assert not action.endswith(":*")
                assert action != "users:grant_role"
