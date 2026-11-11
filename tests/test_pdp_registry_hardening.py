"""PDP policy registry hardening (FEAT-112): atomic load, name collisions, iterable policies=."""

import asyncio
from collections import defaultdict
from unittest.mock import AsyncMock, MagicMock

import pytest

from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.policies import Policy, PolicyEffect
from navigator_auth.abac.policies.evaluator import PolicyEvaluator, PolicyIndex
from navigator_auth.abac.policies.resource_policy import ResourcePolicy
from navigator_auth.abac.policies.resources import ResourceType


@pytest.fixture(scope="module", autouse=True)
def _restore_event_loop():
    """pytest-asyncio leaves no current loop; legacy tests call get_event_loop()."""
    yield
    asyncio.set_event_loop(asyncio.new_event_loop())


@pytest.fixture(autouse=True)
def _stub_audit_log(monkeypatch):
    """Keep PDP tests local; audit-log construction otherwise resolves host DNS."""
    monkeypatch.setattr("navigator_auth.abac.pdp.AuditLog", lambda: MagicMock(log=AsyncMock()))


def _storage(rows=None):
    storage = AsyncMock()
    storage.load_policies = AsyncMock(return_value=list(rows or []))
    return storage


@pytest.fixture
def pdp():
    """A PDP with empty mocked storage and the native evaluator."""
    return PDP(storage=_storage())


def _ctx(username: str = "someone@acme.com"):
    ctx = MagicMock()
    ctx.user = None
    ctx.userinfo = {"username": username, "groups": []}
    return ctx


def _allow(name: str, path: str = "/dashboard/", priority: int = 5) -> Policy:
    return Policy(name=name, effect=PolicyEffect.ALLOW, resource=[f"urn:uri:{path}"], priority=priority)


def _resource_policy(name: str, path: str = "/x/", priority: int = 5, enforcing: bool = False) -> ResourcePolicy:
    return ResourcePolicy(
        name=name,
        effect=PolicyEffect.ALLOW,
        resources=[f"uri:{path}"],
        actions=["uri:read"],
        priority=priority,
        enforcing=enforcing,
    )


def _fail_serializing(monkeypatch, name: str = "boom") -> None:
    """Make the evaluator's JSON serialization raise once policy ``name`` is in the index."""
    original = PolicyEvaluator._serialize_policies_from_index

    def _serialize(self, index):
        if any(policy.name == name for policy in index.all()):
            raise TypeError("Object of type datetime is not JSON serializable")
        return original(self, index)

    monkeypatch.setattr(PolicyEvaluator, "_serialize_policies_from_index", _serialize)


# --- Module 1: atomic evaluator load (issue:5430348ff68e) -------------------------------------


def test_policy_index_copy_is_independent():
    low = _resource_policy("shared", priority=1)
    high = _resource_policy("shared", priority=9, enforcing=True)
    index = PolicyIndex()
    index.add(low)
    index.add(high)
    index.finalize()

    clone = index.copy()
    clone.add(_resource_policy("extra", enforcing=True))
    clone.finalize()

    assert [policy.name for policy in index.all()] == ["shared", "shared"]
    assert index.get_by_name("extra") is None
    assert index.get_enforcing() == [high]
    assert len(index.get_for_resource_type(ResourceType.URI)) == 2
    assert isinstance(clone._by_type, defaultdict)
    assert clone.get_by_name("shared") is index.get_by_name("shared") is high
    assert sorted(policy.name for policy in clone.all()) == ["extra", "shared", "shared"]
    assert len(clone.get_for_resource_type(ResourceType.URI)) == 3


def test_load_policies_failure_leaves_evaluator_unchanged(pdp, monkeypatch):
    pdp.add_policy(_allow("ok"))
    evaluator = pdp.evaluator
    index = evaluator._index
    policy_ids = [id(policy) for policy in index.all()]
    policies_json = evaluator._policies_json
    _fail_serializing(monkeypatch)

    with pytest.raises(TypeError):
        evaluator.load_policies([_resource_policy("boom")])

    assert evaluator._index is index
    assert [id(policy) for policy in evaluator._index.all()] == policy_ids
    assert evaluator._index.get_by_name("boom") is None
    assert evaluator._policies_json == policies_json


def test_add_policy_load_failure_is_atomic(pdp, monkeypatch):
    pdp.add_policy(_allow("ok"))
    pdp._tenant_evaluators[(5, 7)] = MagicMock()
    pdp.evaluator.check_access(_ctx(), ResourceType.URI, "/unrelated", "uri:read")
    snapshots = (
        [id(policy) for policy in pdp._registered],
        [id(policy) for policy in pdp._policies],
        [id(policy) for policy in pdp.evaluator._index.all()],
        pdp.evaluator._policies_json,
        dict(pdp.evaluator._cache),
        dict(pdp._tenant_evaluators),
    )
    _fail_serializing(monkeypatch)

    with pytest.raises(ValueError, match="cannot be loaded into the evaluator") as excinfo:
        pdp.add_policy(_allow("boom", "/boom/"))

    assert isinstance(excinfo.value.__cause__, TypeError)
    assert [id(policy) for policy in pdp._registered] == snapshots[0]
    assert [id(policy) for policy in pdp._policies] == snapshots[1]
    assert [id(policy) for policy in pdp.evaluator._index.all()] == snapshots[2]
    assert pdp.evaluator._policies_json == snapshots[3]
    assert pdp.evaluator._cache == snapshots[4]
    assert dict(pdp._tenant_evaluators) == snapshots[5]
    # The startup guard must not mistake a half-loaded policy for an external pre-load.
    assert not pdp._has_external_policies()

    loaded = pdp.add_policy(_allow("after", "/after/"))

    assert [policy.name for policy in loaded] == ["after"]
    assert pdp.evaluator.check_access(_ctx(), ResourceType.URI, "/after/", "uri:read").allowed


def test_load_policy_dicts_failure_keeps_compat_list(pdp, monkeypatch):
    pdp.add_policy(_allow("ok"))
    policies_before = [id(policy) for policy in pdp._policies]
    index_before = [id(policy) for policy in pdp.evaluator._index.all()]
    _fail_serializing(monkeypatch)

    with pytest.raises(TypeError):
        pdp._load_policy_dicts([{"name": "boom", "effect": "allow", "resources": ["uri:/x/"], "actions": ["uri:read"]}])

    assert [id(policy) for policy in pdp._policies] == policies_before
    assert [id(policy) for policy in pdp.evaluator._index.all()] == index_before


# --- Module 2: name collisions (issue:518d25bdd2ff) ------------------------------------------


def _row(name: str, effect: str, path: str, priority: int = 50) -> dict:
    return {"name": name, "effect": effect, "resources": [f"uri:{path}"], "actions": ["uri:read"], "priority": priority}


def _collision_warnings(logger: MagicMock) -> list:
    return [call for call in logger.warning.call_args_list if "also a registered policy" in call.args[0]]


@pytest.mark.asyncio
async def test_add_policy_rejects_name_loaded_from_storage():
    pdp = PDP(storage=_storage([_row("x", "allow", "/x/")]))
    await pdp._load_policies()
    index_before = [id(policy) for policy in pdp.evaluator._index.all()]

    with pytest.raises(ValueError, match="already loaded in the evaluator"):
        pdp.add_policy(_allow("x", "/other/"))

    assert pdp._registered == []
    assert [id(policy) for policy in pdp.evaluator._index.all()] == index_before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "registered, stored",
    [
        (_allow("dup", "/dup/", priority=5), _row("dup", "deny", "/dup/")),
        (
            Policy(name="dup", effect=PolicyEffect.DENY, resource=["urn:uri:/dup/"], priority=50),
            _row("dup", "allow", "/dup/", 5),
        ),
    ],
    ids=["storage-deny", "registered-deny"],
)
async def test_storage_collision_with_registered_warns_and_keeps_both(registered, stored):
    pdp = PDP(storage=_storage([stored]), policies=[registered])
    pdp.logger = MagicMock()

    await pdp._load_policies()

    startup = _collision_warnings(pdp.logger)
    assert len(startup) == 1
    assert startup[0].args[1:] == ("dup", "DB storage")
    assert [policy.name for policy in pdp.evaluator._index.all()] == ["dup", "dup"]
    assert not pdp.evaluator.check_access(_ctx(), ResourceType.URI, "/dup/", "uri:read").allowed

    pdp.logger.reset_mock()
    await pdp.reload_policies()

    reload = _collision_warnings(pdp.logger)
    assert len(reload) == 1
    assert reload[0].args[1:] == ("dup", "storage reload")
    assert [policy.name for policy in pdp.evaluator._index.all()] == ["dup", "dup"]
    assert not pdp.evaluator.check_access(_ctx(), ResourceType.URI, "/dup/", "uri:read").allowed


@pytest.mark.asyncio
async def test_no_collision_no_warning():
    pdp = PDP(storage=_storage([_row("stored", "deny", "/stored/")]), policies=[_allow("registered")])
    pdp.logger = MagicMock()

    await pdp._load_policies()
    await pdp.reload_policies()

    assert _collision_warnings(pdp.logger) == []
    assert sorted(policy.name for policy in pdp.evaluator._index.all()) == ["registered", "stored"]


# --- Module 3: iterable policies= (issue:d1c06c381acc) ---------------------------------------


@pytest.mark.parametrize(
    "make",
    [tuple, lambda items: (item for item in items), set],
    ids=["tuple", "generator", "set"],
)
def test_constructor_accepts_iterables(make):
    pdp = PDP(storage=_storage(), policies=make([_allow("a", "/a/"), _allow("b", "/b/")]))

    assert sorted(policy.name for policy in pdp._registered) == ["a", "b"]
    assert pdp.evaluator.check_access(_ctx(), ResourceType.URI, "/a/", "uri:read").allowed
    assert pdp.evaluator.check_access(_ctx(), ResourceType.URI, "/b/", "uri:read").allowed


@pytest.mark.parametrize(
    "bad",
    ["public_dashboard", b"public_dashboard", {"name": "x"}, _allow("single"), 42],
    ids=["str", "bytes", "dict", "policy", "int"],
)
def test_constructor_rejects_non_iterables(bad):
    with pytest.raises(TypeError, match=f"got {type(bad).__name__}"):
        PDP(storage=_storage(), policies=bad)


@pytest.mark.parametrize("empty", [None, ()], ids=["none", "empty-tuple"])
def test_constructor_empty_policies(empty):
    pdp = PDP(storage=_storage(), policies=empty)

    assert pdp._registered == []
    assert pdp.evaluator._index.all() == []
