"""By-name ABAC checks evaluate every policy that shares the name.

``check_access`` / ``policy_allows`` look a policy up by name. Two cases used
to evaluate only one policy and skip a DENY:

* the same name loaded from two sources (DB and YAML): ``PolicyIndex`` kept
  only the last one, so a YAML ``allow`` replaced a DB ``deny``;
* ``!`` resources: ``PolicyAdapter`` moves them to a ``<name>_negated`` DENY,
  which the lookup by ``<name>`` never saw.

Now every policy of the group is evaluated and an applicable DENY wins.
"""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.abac.context import EvalContext
from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.policies import Environment, PolicyEffect
from navigator_auth.abac.policies.evaluator import PolicyIndex
from navigator_auth.abac.policies.resource_policy import ResourcePolicy
from navigator_auth.abac.policies.resources import ResourceType, SubjectSpec
from navigator_auth.abac.storages.yaml_storage import YAMLStorage
from navigator_auth.decorators import policy_allows

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

NAME = "groups_admin_access"

ALLOW_YAML = f"""
version: "1.0"
policies:
  - name: {NAME}
    effect: allow
    resources: ["uri:/api/v1/groups*"]
    actions: ["group:read"]
    subjects:
      groups: ["superuser"]
    priority: 90
    enforcing: true
"""

DENY_YAML = f"""
version: "1.0"
policies:
  - name: {NAME}
    effect: deny
    resources: ["uri:/api/v1/groups*"]
    actions: ["group:read"]
    subjects:
      groups: ["superuser"]
    priority: 95
    enforcing: true
"""


def _storage(policies=None) -> MagicMock:
    storage = MagicMock()
    storage.load_policies = AsyncMock(return_value=list(policies or []))
    storage.close = AsyncMock()
    return storage


async def _allowed(pdp: PDP, path: str, action: str = "group:read", groups=("superuser",)) -> bool:
    app = web.Application()
    app["abac"] = pdp
    request = make_mocked_request("GET", path, app=app)
    request["authenticated"] = True
    session = MagicMock()
    session.__getitem__ = MagicMock(return_value={"username": "root", "groups": list(groups)})
    session.decode = MagicMock(return_value=None)
    with patch("navigator_auth.decorators.get_session", new=AsyncMock(return_value=session)):
        allowed, _, _ = await policy_allows(NAME, request, action=action, resource=path)
    return allowed


def _resource_policy(name: str, effect: PolicyEffect, resources: list, priority: int = 0) -> ResourcePolicy:
    return ResourcePolicy(
        name=name,
        effect=effect,
        resources=resources,
        actions=["group:read"],
        subjects=SubjectSpec.from_dict({"groups": ["superuser"]}),
        priority=priority,
    )


# ---------------------------------------------------------------------------
# PolicyIndex
# ---------------------------------------------------------------------------


def test_index_keeps_every_policy_with_a_name():
    index = PolicyIndex()
    first = _resource_policy(NAME, PolicyEffect.DENY, ["uri:/api/v1/groups*"])
    second = _resource_policy(NAME, PolicyEffect.ALLOW, ["uri:/api/v1/groups*"])
    index.add(first)
    index.add(second)
    index.finalize()
    assert index.get_all_by_name(NAME) == [first, second]
    assert index.get_by_name(NAME) is second  # unchanged: last added wins
    assert index.get_all_by_name("missing") == []
    clone = index.copy()
    clone.add(_resource_policy(NAME, PolicyEffect.ALLOW, ["uri:/other*"]))
    assert len(clone.get_all_by_name(NAME)) == 3
    assert len(index.get_all_by_name(NAME)) == 2


# ---------------------------------------------------------------------------
# ResourcePolicy.applies_to mirrors is_allowed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "groups, resource, action, applies",
    [
        (["superuser"], "/api/v1/groups/1", "group:read", True),
        (["users"], "/api/v1/groups/1", "group:read", False),
        (["superuser"], "/api/v1/users/1", "group:read", False),
        (["superuser"], "/api/v1/groups/1", "group:delete", False),
    ],
)
def test_applies_to_matches_is_allowed(groups, resource, action, applies):
    policy = _resource_policy(NAME, PolicyEffect.DENY, ["uri:/api/v1/groups*"])
    ctx = EvalContext(MagicMock(), None, {"username": "root", "groups": groups}, None)
    env = Environment()
    args = {"resource_type": ResourceType.URI, "resource_name": resource, "action": action}
    assert policy.applies_to(ctx, env, **args) is applies
    response = policy.is_allowed(ctx, env, **args)
    assert response.response.startswith("Access") is applies


# ---------------------------------------------------------------------------
# Same name from two sources
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_yaml_allow_does_not_override_same_name_deny(tmp_path):
    # Sorted by file name: the DENY loads first, the ALLOW last — the order in
    # which the last-wins index used to hand the ALLOW to the decorators.
    (tmp_path / "0_deny.yaml").write_text(DENY_YAML)
    (tmp_path / "1_allow.yaml").write_text(ALLOW_YAML)
    pdp = PDP(storage=_storage(), yaml_storage=YAMLStorage(directory=tmp_path))
    await pdp.on_startup(web.Application())
    assert pdp.evaluator._index.get_by_name(NAME).effect == PolicyEffect.ALLOW
    assert await _allowed(pdp, "/api/v1/groups/1") is False


@pytest.mark.asyncio
async def test_db_deny_wins_over_yaml_allow_with_same_name(tmp_path):
    (tmp_path / "allow.yaml").write_text(ALLOW_YAML)
    db_deny = {
        "name": NAME,
        "policy_type": "resource",
        "effect": "deny",
        "resources": ["uri:/api/v1/groups*"],
        "actions": ["group:read"],
        "subjects": {"groups": ["superuser"]},
        "priority": 95,
        "enforcing": True,
    }
    pdp = PDP(storage=_storage([db_deny]), yaml_storage=YAMLStorage(directory=tmp_path))
    await pdp.on_startup(web.Application())
    assert await _allowed(pdp, "/api/v1/groups/1") is False


@pytest.mark.asyncio
async def test_same_name_allows_with_different_scopes_both_grant():
    pdp = PDP(storage=_storage())
    pdp.evaluator.load_policies(
        [
            _resource_policy(NAME, PolicyEffect.ALLOW, ["uri:/api/v1/groups*"]),
            _resource_policy(NAME, PolicyEffect.ALLOW, ["uri:/api/v1/teams*"]),
        ]
    )
    assert await _allowed(pdp, "/api/v1/groups/1") is True
    assert await _allowed(pdp, "/api/v1/teams/1") is True
    assert await _allowed(pdp, "/api/v1/users/1") is False


@pytest.mark.asyncio
async def test_same_name_deny_that_does_not_apply_does_not_block():
    pdp = PDP(storage=_storage())
    pdp.evaluator.load_policies(
        [
            _resource_policy(NAME, PolicyEffect.ALLOW, ["uri:/api/v1/groups*"]),
            _resource_policy(NAME, PolicyEffect.DENY, ["uri:/api/v1/groups/secret*"]),
        ]
    )
    assert await _allowed(pdp, "/api/v1/groups/1") is True
    assert await _allowed(pdp, "/api/v1/groups/secret") is False


@pytest.mark.asyncio
async def test_non_superuser_still_denied():
    pdp = PDP(storage=_storage())
    pdp.evaluator.load_policies([_resource_policy(NAME, PolicyEffect.ALLOW, ["uri:/api/v1/groups*"])])
    assert await _allowed(pdp, "/api/v1/groups/1", groups=("users",)) is False


# ---------------------------------------------------------------------------
# Negated resources
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_negated_resource_is_enforced_by_name():
    classic = {
        "name": NAME,
        "effect": "allow",
        "resources": ["urn:uri:/api/v1/groups*", "!urn:uri:/api/v1/groups/secret*"],
        "actions": ["group:read"],
        "groups": ["superuser"],
    }
    pdp = PDP(storage=_storage([classic]))
    await pdp.on_startup(web.Application())
    assert pdp.evaluator._index.get_by_name(f"{NAME}_negated") is not None
    assert await _allowed(pdp, "/api/v1/groups/1") is True
    assert await _allowed(pdp, "/api/v1/groups/secret") is False


# ---------------------------------------------------------------------------
# Load-time warning
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_duplicate_name_across_sources_is_warned(tmp_path, caplog):
    (tmp_path / "allow.yaml").write_text(ALLOW_YAML)
    db_policy = {
        "name": NAME,
        "policy_type": "resource",
        "effect": "deny",
        "resources": ["uri:/api/v1/groups*"],
        "actions": ["group:read"],
        "subjects": {"groups": ["superuser"]},
    }
    pdp = PDP(storage=_storage([db_policy]), yaml_storage=YAMLStorage(directory=tmp_path))
    with caplog.at_level(logging.WARNING):
        await pdp.on_startup(web.Application())
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any(NAME in msg and "more than once" in msg for msg in warnings)


@pytest.mark.asyncio
async def test_unique_names_are_not_warned(tmp_path, caplog):
    (tmp_path / "allow.yaml").write_text(ALLOW_YAML)
    pdp = PDP(storage=_storage(), yaml_storage=YAMLStorage(directory=tmp_path))
    with caplog.at_level(logging.WARNING):
        await pdp.on_startup(web.Application())
    assert not any("more than once" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# Review cases (second adversarial review)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unrelated_negated_allow_never_grants():
    pdp = PDP(storage=_storage())
    pdp.evaluator.load_policies([_resource_policy(f"{NAME}_negated", PolicyEffect.ALLOW, ["uri:/api/v1/groups*"])])
    # NAME itself is not declared: a policy that merely carries the suffix
    # must not stand in for it.
    assert await _allowed(pdp, "/api/v1/groups/1") is False


@pytest.mark.asyncio
async def test_unrelated_negated_allow_does_not_bypass_subject_check():
    pdp = PDP(storage=_storage())
    pdp.evaluator.load_policies(
        [
            _resource_policy(NAME, PolicyEffect.ALLOW, ["uri:/api/v1/groups*"]),
            ResourcePolicy(
                name=f"{NAME}_negated",
                effect=PolicyEffect.ALLOW,
                resources=["uri:/api/v1/groups*"],
                actions=["group:read"],
                subjects=SubjectSpec.from_dict({"groups": ["users"]}),
            ),
        ]
    )
    assert await _allowed(pdp, "/api/v1/groups/1", groups=("users",)) is False


class _LastWinsIndex:
    """An index without get_all_by_name: last policy per name only."""

    def __init__(self, policies):
        self._by_name = {policy.name: policy for policy in policies}

    def get_by_name(self, name):
        return self._by_name.get(name)


class _LegacyIndexPDP:
    """PDP-like object whose index cannot list every policy of a name."""

    def __init__(self, policies):
        self._policies = list(policies)
        self._evaluator = MagicMock()
        self._evaluator._index = _LastWinsIndex(self._policies)

    def policies(self):
        return self._policies


@pytest.mark.asyncio
async def test_index_without_get_all_by_name_falls_back_to_full_scan():
    deny = _resource_policy(NAME, PolicyEffect.DENY, ["uri:/api/v1/groups*"])
    allow = _resource_policy(NAME, PolicyEffect.ALLOW, ["uri:/api/v1/groups*"])
    pdp = _LegacyIndexPDP([deny, allow])
    assert pdp._evaluator._index.get_by_name(NAME) is allow
    assert await _allowed(pdp, "/api/v1/groups/1") is False


async def _allowed_name_only(pdp, path: str) -> bool:
    app = web.Application()
    app["abac"] = pdp
    request = make_mocked_request("GET", path, app=app)
    request["authenticated"] = True
    session = MagicMock()
    session.__getitem__ = MagicMock(return_value={"username": "root", "groups": ["superuser"]})
    session.decode = MagicMock(return_value=None)
    with patch("navigator_auth.decorators.get_session", new=AsyncMock(return_value=session)):
        allowed, _, _ = await policy_allows(NAME, request, action="group:read")
    return allowed


@pytest.mark.asyncio
async def test_name_only_check_applies_negated_exclusions_to_request_path():
    classic = {
        "name": NAME,
        "effect": "allow",
        "resources": ["urn:uri:/api/v1/groups*", "!urn:uri:/api/v1/groups/secret*"],
        "actions": ["group:read"],
        "groups": ["superuser"],
    }
    pdp = PDP(storage=_storage([classic]))
    await pdp.on_startup(web.Application())
    # Without resource= the exclusion is checked against the request path: it
    # neither turns into a blanket denial nor disappears.
    assert await _allowed_name_only(pdp, "/api/v1/groups/1") is True
    assert await _allowed_name_only(pdp, "/api/v1/groups/secret") is False
    assert await _allowed(pdp, "/api/v1/groups/secret") is False


@pytest.mark.asyncio
async def test_deny_whose_conditions_fail_does_not_veto():
    pdp = PDP(storage=_storage())
    pdp.evaluator.load_policies(
        [
            _resource_policy(NAME, PolicyEffect.ALLOW, ["uri:/api/v1/groups*"]),
            ResourcePolicy(
                name=NAME,
                effect=PolicyEffect.DENY,
                resources=["uri:/api/v1/groups*"],
                actions=["group:read"],
                subjects=SubjectSpec.from_dict({"groups": ["superuser"]}),
                environment={"hour": {"min": 99}},  # never true
            ),
        ]
    )
    assert await _allowed(pdp, "/api/v1/groups/1") is True


class _LegacyDenyThatAllows:
    """Legacy shape (no ``decide``): DENY effect whose evaluate() answers ALLOW,
    as ``ObjectPolicy`` does when it matches."""

    name = NAME
    effect = PolicyEffect.DENY

    def evaluate(self, ctx, env):
        from navigator_auth.abac.policies.abstract import PolicyResponse

        return PolicyResponse(effect=PolicyEffect.ALLOW, response="legacy allow", rule=NAME)

    def is_allowed(self, ctx, env, **kwargs):
        return self.evaluate(ctx, env)


class _ListPDP:
    _evaluator = None

    def __init__(self, policies):
        self._policies = policies

    def policies(self):
        return self._policies


@pytest.mark.asyncio
async def test_single_legacy_policy_decision_is_preserved():
    assert await _allowed(_ListPDP([_LegacyDenyThatAllows()]), "/api/v1/groups/1") is True


@pytest.mark.asyncio
async def test_context_failure_denies_instead_of_raising():
    pdp = PDP(storage=_storage())
    pdp.evaluator.load_policies([_resource_policy(NAME, PolicyEffect.ALLOW, ["uri:/api/v1/groups*"])])
    app = web.Application()
    app["abac"] = pdp
    request = make_mocked_request("GET", "/api/v1/groups/1", app=app)
    request["authenticated"] = True
    with patch("navigator_auth.decorators.get_session", new=AsyncMock(side_effect=OSError("redis down"))):
        allowed, reason, response = await policy_allows(NAME, request, action="group:read")
    assert allowed is False
    assert reason
    assert response is None


@pytest.mark.asyncio
async def test_check_access_decorator_applies_group_decision(tmp_path):
    from navigator_auth.decorators import check_access

    (tmp_path / "0_deny.yaml").write_text(DENY_YAML)
    (tmp_path / "1_allow.yaml").write_text(ALLOW_YAML)
    pdp = PDP(storage=_storage(), yaml_storage=YAMLStorage(directory=tmp_path))
    await pdp.on_startup(web.Application())

    @check_access(NAME, action="group:read", resource="/api/v1/groups/1")
    async def handler(request):
        return web.json_response({"ok": True})

    app = web.Application()
    app["abac"] = pdp
    request = make_mocked_request("GET", "/api/v1/groups/1", app=app)
    request["authenticated"] = True
    session = MagicMock()
    session.__getitem__ = MagicMock(return_value={"username": "root", "groups": ["superuser"]})
    session.decode = MagicMock(return_value=None)
    with patch("navigator_auth.decorators.get_session", new=AsyncMock(return_value=session)):
        with pytest.raises(web.HTTPForbidden):
            await handler(request)


# ---------------------------------------------------------------------------
# Review cases (third pass)
# ---------------------------------------------------------------------------


class _DenyingEvaluate(ResourcePolicy):
    """A ResourcePolicy subclass whose evaluate() override always denies."""

    def evaluate(self, ctx, environ):
        from navigator_auth.abac.policies.abstract import PolicyResponse

        return PolicyResponse(effect=PolicyEffect.DENY, response="custom deny", rule=self.name)


class _DenyingIsAllowed(ResourcePolicy):
    """A ResourcePolicy subclass whose is_allowed() override always denies."""

    def is_allowed(self, ctx, env, resource_type=None, resource_name=None, action=None, **kwargs):
        from navigator_auth.abac.policies.abstract import PolicyResponse

        return PolicyResponse(effect=PolicyEffect.DENY, response="custom deny", rule=self.name)


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [_DenyingEvaluate, _DenyingIsAllowed])
async def test_resource_policy_subclass_overrides_are_honoured(cls):
    policy = cls(
        name=NAME,
        effect=PolicyEffect.ALLOW,
        resources=["uri:/api/v1/groups*"],
        actions=["group:read"],
        subjects=SubjectSpec.from_dict({"groups": ["superuser"]}),
    )
    pdp = PDP(storage=_storage())
    pdp.add_policy(policy)
    assert await _allowed(pdp, "/api/v1/groups/1") is False
    assert await _allowed_name_only(pdp, "/api/v1/groups/1") is False


def test_is_allowed_still_delegates_to_overridden_evaluate():
    policy = _DenyingEvaluate(
        name=NAME,
        effect=PolicyEffect.ALLOW,
        resources=["uri:/api/v1/groups*"],
        actions=["group:read"],
        subjects=SubjectSpec.from_dict({"groups": ["superuser"]}),
    )
    ctx = EvalContext(MagicMock(), None, {"username": "root", "groups": ["superuser"]}, None)
    response = policy.is_allowed(
        ctx, Environment(), resource_type=ResourceType.URI, resource_name="/api/v1/groups/1", action="group:read"
    )
    assert response.response == "custom deny"


class _LegacyNegated:
    """Legacy-shaped (no ``decide``) ``<name>_negated`` DENY."""

    name = f"{NAME}_negated"
    effect = PolicyEffect.DENY

    def evaluate(self, ctx, env):
        from navigator_auth.abac.policies.abstract import PolicyResponse

        return PolicyResponse(effect=PolicyEffect.DENY, response="legacy negated", rule=self.name)

    def is_allowed(self, ctx, env, **kwargs):
        return self.evaluate(ctx, env)


@pytest.mark.asyncio
async def test_legacy_negated_deny_is_not_discarded():
    allow = _resource_policy(NAME, PolicyEffect.ALLOW, ["uri:/api/v1/groups*"])
    assert await _allowed(_ListPDP([allow]), "/api/v1/groups/1") is True
    assert await _allowed(_ListPDP([allow, _LegacyNegated()]), "/api/v1/groups/1") is False


class _ExplodingResponse:
    effect = PolicyEffect.ALLOW

    @property
    def response(self):
        raise RuntimeError("broken response")


class _PolicyWithExplodingResponse:
    name = NAME
    effect = PolicyEffect.ALLOW

    def evaluate(self, ctx, env):
        return _ExplodingResponse()

    def is_allowed(self, ctx, env, **kwargs):
        return _ExplodingResponse()


@pytest.mark.asyncio
async def test_response_metadata_errors_deny_instead_of_raising():
    assert await _allowed(_ListPDP([_PolicyWithExplodingResponse()]), "/api/v1/groups/1") is False
