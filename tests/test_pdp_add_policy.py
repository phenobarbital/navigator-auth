"""PDP.add_policy / PDP(policies=) are enforced by the evaluator (FEAT-109 M2)."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.policies import Policy, PolicyEffect
from navigator_auth.abac.policies.resources import ResourceType
from navigator_auth.conf import AUTH_SESSION_OBJECT


def _dashboard_policy(name: str = "public_dashboard") -> Policy:
    return Policy(
        name=name,
        effect=PolicyEffect.ALLOW,
        resource=["urn:uri:/dashboard/"],
        priority=5,
    )


def _ctx(username: str = "someone@acme.com", groups=None):
    ctx = MagicMock()
    ctx.user = None
    ctx.userinfo = {"username": username, "groups": list(groups or [])}
    return ctx


@pytest.fixture(autouse=True)
def _stub_audit_log(monkeypatch):
    """Keep PDP tests local; audit-log construction otherwise resolves host DNS."""
    monkeypatch.setattr("navigator_auth.abac.pdp.AuditLog", lambda: MagicMock(log=AsyncMock()))


@pytest.fixture
def pdp_with_storage(_stub_audit_log):
    """Build a PDP with local mocked storage and the native evaluator."""
    storage = AsyncMock()
    storage.load_policies = AsyncMock(return_value=[])
    pdp = PDP(storage=storage)
    pdp._auditlog = MagicMock(log=AsyncMock())
    return pdp


def test_add_policy_loads_into_evaluator(pdp_with_storage):
    pdp_with_storage.add_policy(_dashboard_policy())
    assert "public_dashboard" in [p.name for p in pdp_with_storage.evaluator._index.all()]


def test_add_policy_returns_adapted_resources(pdp_with_storage):
    loaded = pdp_with_storage.add_policy(_dashboard_policy())

    assert [policy.name for policy in loaded] == ["public_dashboard"]
    assert loaded[0] is pdp_with_storage._registered[0]


def test_add_policy_empty_subject_allows_dashboard(pdp_with_storage):
    pdp_with_storage.add_policy(_dashboard_policy())
    result = pdp_with_storage.evaluator.check_access(_ctx(), ResourceType.URI, "/dashboard/", "uri:read")
    assert result.allowed


@pytest.mark.asyncio
async def test_authorize_dashboard_no_428(pdp_with_storage):
    pdp_with_storage.add_policy(_dashboard_policy())
    request = make_mocked_request("GET", "/dashboard/", app=web.Application())
    session = {AUTH_SESSION_OBJECT: {"username": "someone@acme.com", "groups": []}}

    response = await pdp_with_storage.authorize(request=request, session=session)

    assert response.effect == PolicyEffect.ALLOW


@pytest.mark.asyncio
async def test_authorize_unmatched_still_428(pdp_with_storage):
    pdp_with_storage.add_policy(_dashboard_policy())
    request = make_mocked_request("GET", "/nothing-here", app=web.Application())
    session = {AUTH_SESSION_OBJECT: {"username": "someone@acme.com", "groups": []}}
    with pytest.raises(web.HTTPPreconditionRequired):
        await pdp_with_storage.authorize(request=request, session=session)


def test_constructor_policies_registered(pdp_with_storage):
    policies = [_dashboard_policy()]
    pdp = PDP(storage=pdp_with_storage.storage, policies=policies)
    pdp._auditlog = MagicMock(log=AsyncMock())

    result = pdp.evaluator.check_access(_ctx(), ResourceType.URI, "/dashboard/", "uri:read")

    assert result.allowed
    assert pdp._policies is not policies
    assert [policy.name for policy in pdp._registered] == ["public_dashboard"]


def test_add_policy_duplicate_name_raises(pdp_with_storage):
    pdp_with_storage.add_policy(_dashboard_policy())
    before = [id(policy) for policy in pdp_with_storage._registered]

    with pytest.raises(ValueError, match="already registered"):
        pdp_with_storage.add_policy(_dashboard_policy())

    assert [id(policy) for policy in pdp_with_storage._registered] == before


def test_add_policy_unadaptable_raises(pdp_with_storage):
    invalid = Policy(name="restricted", resource=["urn:uri:/restricted"], context={"username": "u"})

    with pytest.raises(ValueError, match="context"):
        pdp_with_storage.add_policy(invalid)

    assert pdp_with_storage._registered == []
    assert pdp_with_storage.evaluator._index.all() == []


def test_add_policy_rejection_is_atomic(pdp_with_storage):
    pdp_with_storage.add_policy(_dashboard_policy())
    tenant_evaluator = MagicMock()
    pdp_with_storage._tenant_evaluators[(5, 7)] = tenant_evaluator
    pdp_with_storage.evaluator.check_access(_ctx(), ResourceType.URI, "/unrelated", "uri:read")
    snapshots = (
        [id(policy) for policy in pdp_with_storage._registered],
        [id(policy) for policy in pdp_with_storage._policies],
        [id(policy) for policy in pdp_with_storage.evaluator._index.all()],
        pdp_with_storage.evaluator._policies_json,
        dict(pdp_with_storage.evaluator._cache),
        dict(pdp_with_storage._tenant_evaluators),
    )

    invalid_policies = [
        Policy(name="invalid_regex", resource=["urn:uri:/admin["]),
        Policy(name="restricted", resource=["urn:uri:/x"], context={"username": "u"}),
    ]
    for invalid in invalid_policies:
        with pytest.raises(ValueError):
            pdp_with_storage.add_policy(invalid)

    assert [id(policy) for policy in pdp_with_storage._registered] == snapshots[0]
    assert [id(policy) for policy in pdp_with_storage._policies] == snapshots[1]
    assert [id(policy) for policy in pdp_with_storage.evaluator._index.all()] == snapshots[2]
    assert pdp_with_storage.evaluator._policies_json == snapshots[3]
    assert pdp_with_storage.evaluator._cache == snapshots[4]
    assert dict(pdp_with_storage._tenant_evaluators) == snapshots[5]
    denied = pdp_with_storage.evaluator.check_access(_ctx(), ResourceType.URI, "/unrelated", "uri:read")
    assert not denied.allowed


def test_add_policy_invalidates_cache(pdp_with_storage):
    before = pdp_with_storage.evaluator.check_access(_ctx(), ResourceType.URI, "/cache-target", "uri:read")
    assert not before.allowed
    assert pdp_with_storage.evaluator._cache

    pdp_with_storage.add_policy(
        Policy(name="cache_target", effect=PolicyEffect.ALLOW, resource=["urn:uri:/cache-target"])
    )

    after = pdp_with_storage.evaluator.check_access(_ctx(), ResourceType.URI, "/cache-target", "uri:read")
    assert after.allowed


class _FakeIndex:
    """Minimal PolicyIndex stand-in for startup guard coverage."""

    def __init__(self):
        self._policies = []

    def add(self, policy):
        self._policies.append(policy)

    def finalize(self):
        pass

    def all(self):
        return list(self._policies)


def _make_fake_evaluator(policies=None):
    """Build a fake evaluator that tracks loaded policies without Rust."""
    evaluator = MagicMock()
    index = _FakeIndex()
    for policy in policies or []:
        index.add(policy)
    evaluator._index = index
    evaluator.load_policies = MagicMock(side_effect=lambda items: [index.add(policy) for policy in items])
    evaluator.swap_index = MagicMock()
    return evaluator


@pytest.mark.asyncio
async def test_load_policies_runs_with_only_registered():
    storage = AsyncMock()
    storage.load_policies = AsyncMock(return_value=[])
    evaluator = _make_fake_evaluator()
    pdp = PDP(storage=storage, evaluator=evaluator)
    pdp.add_policy(_dashboard_policy())

    await pdp._load_policies()

    storage.load_policies.assert_awaited_once_with()
    assert evaluator.load_policies.call_count == 2


@pytest.mark.asyncio
async def test_reload_keeps_registered(pdp_with_storage):
    pdp_with_storage.add_policy(_dashboard_policy())

    count = await pdp_with_storage.reload_policies()

    assert count == 1
    assert "public_dashboard" in [policy.name for policy in pdp_with_storage._policies]
    assert pdp_with_storage.evaluator._index.get_by_name("public_dashboard") is not None


@pytest.mark.asyncio
async def test_tenant_evaluator_includes_registered(pdp_with_storage):
    pdp_with_storage.add_policy(_dashboard_policy())

    evaluator = await pdp_with_storage._build_tenant_evaluator(5, 7)

    assert evaluator._index.get_by_name("public_dashboard") is not None
