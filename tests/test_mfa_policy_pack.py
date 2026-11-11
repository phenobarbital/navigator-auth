"""FEAT-106 Module 11 — the `mfa_admin_access` pack parses and stays exclusive.

Contract test between this YAML and TASK-142's admin_disenroll handler: if
either side renames the policy or the action, admin disenrolment silently dies,
because policy_allows() fails closed on a policy or action it cannot match.
"""

from pathlib import Path

import pytest

from navigator_auth.abac.storages.yaml_storage import YAMLStorage

POLICY_DIR = Path(__file__).resolve().parents[1] / "navigator_auth" / "abac" / "default_policies"
PACK = POLICY_DIR / "mfa_admin_access.yaml"
ADMIN_FULL = POLICY_DIR / "admin_full_access.yaml"

ACTION = "mfa:disenroll"
POLICY_NAME = "mfa_admin_access"


@pytest.fixture(scope="module")
def parsed():
    """Parse the MFA administrative policy pack."""
    assert PACK.exists(), f"policy pack missing: {PACK}"
    return YAMLStorage._parse_file(PACK)


@pytest.fixture(scope="module")
def admin_full():
    """Parse the full administrative policy pack for exclusivity checks."""
    return YAMLStorage._parse_file(ADMIN_FULL)


def test_policy_pack_parses(parsed):
    """The YAML parses and yields the action, group and effect (spec §4 M11)."""
    assert len(parsed) == 1
    policy = parsed[0]
    assert policy["name"] == POLICY_NAME
    assert policy["actions"] == [ACTION]
    assert policy["subjects"]["groups"] == ["security_admin"]
    assert policy["effect"] == "ALLOW"
    assert policy["policy_type"] == "resource"
    assert policy["resources"] == ["uri:/auth/mfa/*"]


def test_priority_and_enforcing(parsed):
    """The policy uses the fixed priority and is enforcing."""
    policy = parsed[0]
    assert policy["priority"] == 90
    assert policy["enforcing"] is True


def test_not_granted_to_superuser_or_admin(parsed):
    """Separation of duties (R1): neither superuser, admin nor a wildcard holds the action."""
    for policy in parsed:
        assert not set(policy["subjects"].get("groups", [])) & {"superuser", "admin", "*"}


def test_grants_nothing_but_disenroll(parsed):
    """The pack grants exactly one capability — no password reset, no account edit."""
    actions = [action for policy in parsed for action in policy["actions"]]
    assert set(actions) == {ACTION}
    for action in actions:
        object_name, verb = action.split(":")
        assert object_name == "mfa"
        assert verb


def test_admin_full_access_does_not_cover_mfa_disenroll(admin_full):
    """admin_full_access enumerates actions with no wildcard, so it cannot grant mfa:disenroll."""
    for policy in admin_full:
        for action in policy["actions"]:
            assert action != ACTION
            assert action != "*"
            assert action != "mfa:*"
            assert not action.endswith(":*")
