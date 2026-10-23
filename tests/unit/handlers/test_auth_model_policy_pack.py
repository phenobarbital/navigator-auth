"""The FEAT-105 default policy pack parses and declares what the guards expect.

Contract test between a YAML file and three handler classes: if either side
renames a policy or an action, the superuser path silently dies, because
``policy_allows()`` fails closed on a policy it cannot find by name.
"""

from pathlib import Path

import pytest

from navigator_auth.abac.storages.yaml_storage import YAMLStorage

PACK = (
    Path(__file__).resolve().parents[3]
    / "navigator_auth"
    / "abac"
    / "default_policies"
    / "auth_model_admin_access.yaml"
)

EXPECTED_ACTIONS = {
    "user_identities_admin_access": {
        "identity:read",
        "identity:revoke",
        "identity:delete",
    },
    "user_accounts_admin_access": {
        "account:read",
        "account:delete",
    },
    "partner_keys_admin_access": {
        "partner:read",
        "partner:create",
        "partner:revoke",
        "partner:delete",
    },
}
EXPECTED_RESOURCE = {
    "user_identities_admin_access": "uri:/api/v1/user_identity*",
    "user_accounts_admin_access": "uri:/api/v1/user_accounts*",
    "partner_keys_admin_access": "uri:/api/v1/partner/tokens*",
}


@pytest.fixture(scope="module")
def parsed():
    """The pack as `_parse_file` sees it (a list of policy dicts)."""
    assert PACK.exists(), f"policy pack missing: {PACK}"
    return YAMLStorage._parse_file(PACK)


class TestPolicyPack:
    def test_all_three_policies_parse(self, parsed):
        assert len(parsed) == 3
        assert {p["name"] for p in parsed} == set(EXPECTED_ACTIONS)

    def test_actions_match_the_handler_contract(self, parsed):
        for p in parsed:
            assert set(p["actions"]) == EXPECTED_ACTIONS[p["name"]]

    def test_every_action_is_object_colon_verb(self, parsed):
        for p in parsed:
            for action in p["actions"]:
                assert action.count(":") == 1
                obj, verb = action.split(":")
                assert obj and verb

    def test_subjects_grant_superuser_only(self, parsed):
        for p in parsed:
            groups = p["subjects"]["groups"]
            assert groups == ["superuser"]
            assert "*" not in groups and "admin" not in groups

    def test_effect_and_enforcing(self, parsed):
        for p in parsed:
            assert p["effect"] == "ALLOW"
            assert p["enforcing"] is True
            assert p["priority"] == 90

    def test_resources_cover_both_route_shapes(self, parsed):
        for p in parsed:
            assert p["resources"] == [EXPECTED_RESOURCE[p["name"]]]
            assert not p["resources"][0].endswith("/*")

    def test_policy_type_defaults_to_resource(self, parsed):
        for p in parsed:
            assert p["policy_type"] == "resource"
            assert "resources" in p
