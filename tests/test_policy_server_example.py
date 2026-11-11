"""The PBAC example registers cleanly and enforces its restrictions (FEAT-109 M5)."""

import asyncio
import importlib.util
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.policies.adapter import PolicyAdapter
from navigator_auth.abac.policies.environment import Environment
from navigator_auth.abac.policies.evaluator import PolicyLoader
from navigator_auth.abac.policies.resources import ResourceType

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module", autouse=True)
def _restore_event_loop():
    """pytest-asyncio leaves no current loop; legacy tests call get_event_loop()."""
    yield
    asyncio.set_event_loop(asyncio.new_event_loop())


@pytest.fixture(scope="module")
def example():
    """Load examples/policy_server.py by path without live services."""
    spec = importlib.util.spec_from_file_location("policy_server_example", ROOT / "examples" / "policy_server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pdp(example, monkeypatch) -> PDP:
    """Create a PDP holding the example policies and mocked storage."""
    monkeypatch.setattr("navigator_auth.abac.audit.socket.gethostbyname", lambda _: "127.0.0.1")
    storage = AsyncMock()
    storage.load_policies = AsyncMock(return_value=[])
    pdp = PDP(storage=storage)
    pdp._auditlog = MagicMock(log=AsyncMock())
    for policy in example.EXAMPLE_POLICIES:
        pdp.add_policy(policy)
    return pdp


def _ctx(username: str, groups=()):
    """Build the evaluator context required for a user decision."""
    ctx = MagicMock()
    ctx.user = None
    ctx.userinfo = {"username": username, "groups": list(groups)}
    return ctx


async def _evaluator_paths(pdp: PDP):
    """Return evaluator paths for registration, reload, and a tenant."""
    paths = [("registered", pdp.evaluator, 1, 1)]
    await pdp.reload_policies()
    paths.append(("reloaded", pdp.evaluator, 1, 1))
    paths.append(("tenant", await pdp._build_tenant_evaluator(5, 7), 5, 7))
    return paths


def test_example_policies_adapt_cleanly(example):
    """Ensure each example policy can enter the resource evaluator."""
    for policy in example.EXAMPLE_POLICIES:
        result = PolicyAdapter.from_policy(policy)
        assert not result.skipped, (policy.name, result.reason)


def test_example_policy_names_disjoint_from_packs(example):
    """Ensure example policy names cannot collide with the default packs."""
    default_policies = PolicyLoader.load_from_directory(ROOT / "navigator_auth" / "abac" / "default_policies")
    example_names = set()
    for policy in example.EXAMPLE_POLICIES:
        result = PolicyAdapter.from_policy(policy)
        example_names.add(result.policy.name)
        example_names.update(additional.name for additional in result.additional_policies)

    assert example_names.isdisjoint({policy.name for policy in default_policies})


@pytest.mark.asyncio
async def test_example_config_user_restriction(example, monkeypatch):
    """Allow the platform lead to manage production configuration only."""
    for label, evaluator, org_id, client_id in await _evaluator_paths(_pdp(example, monkeypatch)):
        for action in ("config:edit", "config:deploy"):
            allowed = evaluator.check_access(
                _ctx("platform-lead@acme.com"),
                "config",
                "production",
                action,
                org_id=org_id,
                client_id=client_id,
            )
            assert allowed.allowed, (label, action)
        denied = evaluator.check_access(
            _ctx("intruder@acme.com"),
            "config",
            "production",
            "config:edit",
            org_id=org_id,
            client_id=client_id,
        )
        assert not denied.allowed, label


@pytest.mark.asyncio
async def test_example_analytics_weekday_restriction(example, monkeypatch):
    """Allow analytics reads only during weekday business hours."""
    for label, evaluator, org_id, client_id in await _evaluator_paths(_pdp(example, monkeypatch)):

        def allowed_at(environment: Environment) -> bool:
            return evaluator.check_access(
                _ctx("analyst@acme.com", ["analytics"]),
                ResourceType.URI,
                "/api/v1/analytics/",
                "uri:read",
                env=environment,
                org_id=org_id,
                client_id=client_id,
            ).allowed

        assert allowed_at(Environment(dow=0, hour=12)), label
        assert not allowed_at(Environment(dow=5, hour=12)), label
        assert not allowed_at(Environment(dow=6, hour=12)), label
        assert not allowed_at(Environment(dow=2, hour=20)), label
