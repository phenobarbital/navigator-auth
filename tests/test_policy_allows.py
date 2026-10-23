"""Tests for the public ``policy_allows()`` ABAC evaluation API (FEAT-105).

Covers the fail-closed cases from spec §4: no PDP, a PDP without the named
policy, a policy that raises while evaluating, and the allow path (a
``superuser``-group subject).
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.decorators import policy_allows
from navigator_auth.abac.policies import Policy, PolicyEffect

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

POLICY = "user_identities_admin_access"


class FakePDP:
    """Minimal PDP stub exposing the ``policies`` collection."""

    def __init__(self, policies):
        self._evaluator = None
        self._policies = policies

    @property
    def policies(self):
        return self._policies


class ExplodingPolicy:
    """A policy whose evaluation raises, to prove nothing escapes."""

    name = POLICY

    def evaluate(self, ctx, env):
        raise RuntimeError("policy backend is down")

    def is_allowed(self, ctx, env, **kwargs):
        raise RuntimeError("policy backend is down")


def _make_request(pdp=None, path="/api/v1/user_identity/1"):
    app = web.Application()
    if pdp is not None:
        app["abac"] = pdp
    request = make_mocked_request("GET", path, app=app)
    request["authenticated"] = True
    return request


def _session(groups: list, username: str = "admin@example.com"):
    userinfo = {"username": username, "groups": groups, "email": username}
    session = MagicMock()
    session.__getitem__ = MagicMock(return_value=userinfo)
    session.decode = MagicMock(return_value=None)
    return session


def _patch_session(session):
    return patch(
        "navigator_auth.decorators.get_session",
        new=AsyncMock(return_value=session),
    )


def _admin_policy():
    return Policy(
        POLICY,
        description="Superuser access to identities",
        effect=PolicyEffect.ALLOW,
        actions=["identity:read"],
        groups=["superuser"],
        priority=1,
    )


@pytest.mark.asyncio
async def test_policy_allows_denies_without_pdp():
    request = _make_request(pdp=None)
    with _patch_session(_session(["superuser"])):
        allowed, reason, response = await policy_allows(POLICY, request)
    assert allowed is False
    assert isinstance(reason, str) and reason
    assert response is None


@pytest.mark.asyncio
async def test_policy_allows_denies_undeclared_policy():
    request = _make_request(pdp=FakePDP([]))
    with _patch_session(_session(["superuser"])):
        allowed, reason, _ = await policy_allows(POLICY, request)
    assert allowed is False
    assert POLICY in reason


@pytest.mark.asyncio
async def test_policy_allows_denies_on_evaluation_error():
    request = _make_request(pdp=FakePDP([ExplodingPolicy()]))
    with _patch_session(_session(["superuser"])):
        allowed, reason, _ = await policy_allows(POLICY, request, action="identity:read")
    assert allowed is False
    assert reason


@pytest.mark.asyncio
async def test_policy_allows_grants_for_superuser_group():
    request = _make_request(pdp=FakePDP([_admin_policy()]))
    with _patch_session(_session(["superuser"])):
        allowed, reason, response = await policy_allows(POLICY, request, action="identity:read")
    assert allowed is True
    assert response is not None


@pytest.mark.asyncio
async def test_policy_allows_denies_non_superuser():
    request = _make_request(pdp=FakePDP([_admin_policy()]))
    with _patch_session(_session(["users"])):
        allowed, _, _ = await policy_allows(POLICY, request, action="identity:read")
    assert allowed is False


@pytest.mark.asyncio
async def test_policy_allows_accepts_str_and_list_identically():
    pdp = FakePDP([_admin_policy()])
    with _patch_session(_session(["superuser"])):
        a, _, _ = await policy_allows(POLICY, _make_request(pdp), action="identity:read")
        b, _, _ = await policy_allows([POLICY], _make_request(pdp), action="identity:read")
    assert a is b is True


@pytest.mark.asyncio
async def test_policy_allows_rejects_empty_policy_list():
    with pytest.raises(ValueError):
        await policy_allows([], _make_request())
