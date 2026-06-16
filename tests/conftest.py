"""
Shared test fixtures for navigator-auth tests.

Tenant fixtures for FEAT-092 per-tenant policy scoping tests are included here.
"""
import pytest
from unittest.mock import MagicMock
from aiohttp import web

from navigator_auth.abac.policies.adapter import PolicyAdapter
from navigator_auth.abac.policies.evaluator import PolicyEvaluator
from navigator_auth.abac.context import EvalContext


# ---------------------------------------------------------------------------
# Generic request factory
# ---------------------------------------------------------------------------

@pytest.fixture
def make_request():
    """Return a factory that creates a mock web.Request."""
    def _factory(
        path: str = "/api/v1/test",
        method: str = "GET",
        headers: dict = None,
    ) -> MagicMock:
        req = MagicMock(spec=web.Request)
        req.path = path
        req.method = method
        req.path_qs = path
        req.rel_url = path
        req.remote = "127.0.0.1"
        _headers = {"referer": "http://localhost"}
        if headers:
            _headers.update(headers)
        req.headers = _headers
        req.is_authenticated = True
        return req

    return _factory


# ---------------------------------------------------------------------------
# Tenant fixtures (FEAT-092)
# ---------------------------------------------------------------------------

@pytest.fixture
def tenant_policies():
    """
    Three policy dicts for tenant-scoping integration tests.

    - global_tools:   org_id=1 / client_id=1  →  allow all tenants tool:*
    - t5_block_jira:  org_id=5 / client_id=1  →  enforcing deny jira for tenant 5
    """
    return [
        {
            "name": "global_tools",
            "effect": "ALLOW",
            "policy_type": "policy",
            "resource": ["tool:*"],
            "actions": ["tool:execute"],
            "groups": ["engineering"],
            "priority": 1,
            "org_id": 1,
            "client_id": 1,
        },
        {
            "name": "t5_block_jira",
            "effect": "DENY",
            "policy_type": "policy",
            "resource": ["tool:jira_*"],
            "actions": ["tool:execute"],
            "groups": ["engineering"],
            "priority": 10,
            "enforcing": True,
            "org_id": 5,
            "client_id": 1,
        },
    ]


@pytest.fixture
def engineering_userinfo():
    """Userinfo dict for an engineering group member."""
    return {
        "username": "alice",
        "groups": ["engineering"],
        "roles": [],
    }


@pytest.fixture
def ctx_tenant_5(make_request, engineering_userinfo):
    """EvalContext whose userinfo carries org_id=5, client_id=1."""
    userinfo = {**engineering_userinfo, "org_id": 5, "client_id": 1}
    return EvalContext(make_request(), None, userinfo, None)


@pytest.fixture
def ctx_tenant_7(make_request, engineering_userinfo):
    """EvalContext whose userinfo carries org_id=7, client_id=1."""
    userinfo = {**engineering_userinfo, "org_id": 7, "client_id": 1}
    return EvalContext(make_request(), None, userinfo, None)


@pytest.fixture
def ctx_no_tenant(make_request, engineering_userinfo):
    """EvalContext with no tenant info (falls back to global 1/1)."""
    return EvalContext(make_request(), None, engineering_userinfo, None)


def build_evaluator_from_dicts(policy_dicts: list) -> PolicyEvaluator:
    """Helper: adapt policy dicts and load into a fresh PolicyEvaluator."""
    resource_policies, _ = PolicyAdapter.adapt_batch(policy_dicts)
    ev = PolicyEvaluator()
    ev.load_policies(resource_policies)
    return ev
