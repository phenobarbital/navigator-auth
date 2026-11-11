"""Protected groups at the guard level (FEAT-107, TASK-152)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.handlers import guards
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard, protected_groups

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")


class Host(OwnerOrSuperuserGuard):
    def __init__(self, request):
        self.request = request

    def error(self, response=None, status=400, **kwargs):
        exception = {403: web.HTTPForbidden, 401: web.HTTPUnauthorized}.get(status, web.HTTPBadRequest)
        raise exception(text=str(response or {}))


def request():
    return make_mocked_request("POST", "/api/v1/groups", app=web.Application())


def session(user_id=42, groups=("superuser", "security_admin")):
    info = {"user_id": user_id, "groups": list(groups)}
    value = {"session": info}
    result = MagicMock()
    result.__contains__ = lambda key: key in value
    result.__getitem__ = lambda key: value[key]
    result.decode = lambda key: None
    return result


class TestProtectedSet:
    def test_protected_groups_always_include_superuser(self, monkeypatch):
        monkeypatch.setattr(guards, "AUTH_PROTECTED_GROUPS", [])
        assert protected_groups() == {"superuser"}

    def test_setting_adds_groups(self, monkeypatch):
        monkeypatch.setattr(guards, "AUTH_PROTECTED_GROUPS", ["ops"])
        assert protected_groups() == {"ops", "superuser"}


class TestAuthorizeProtectedGroup:
    @pytest.mark.asyncio
    async def test_ordinary_group_is_noop(self):
        with patch.object(guards, "policy_allows", new=AsyncMock(side_effect=AssertionError)):
            await Host(request()).authorize_protected_group([None, "sales"])

    @pytest.mark.asyncio
    async def test_superuser_without_grant_role_refused(self):
        with (
            patch.object(guards, "policy_allows", new=AsyncMock(return_value=(False, "denied", None))),
            patch.object(Host, "audit_decision", new=AsyncMock()),
            patch.object(guards, "get_session", new=AsyncMock(return_value=session())),
        ):
            with pytest.raises(web.HTTPForbidden):
                await Host(request()).authorize_protected_group(["superuser"], member_id=99)

    @pytest.mark.asyncio
    async def test_grantor_can_add_member_to_protected_group(self):
        with (
            patch.object(guards, "policy_allows", new=AsyncMock(return_value=(True, "allowed", None))),
            patch.object(Host, "audit_decision", new=AsyncMock()),
            patch.object(guards, "get_session", new=AsyncMock(return_value=session())),
        ):
            await Host(request()).authorize_protected_group(["security_admin"], member_id=99)

    @pytest.mark.asyncio
    async def test_no_self_add_to_protected_group(self):
        with (
            patch.object(guards, "policy_allows", new=AsyncMock(return_value=(True, "allowed", None))),
            patch.object(Host, "audit_decision", new=AsyncMock()),
            patch.object(guards, "get_session", new=AsyncMock(return_value=session())),
        ):
            with pytest.raises(web.HTTPForbidden):
                await Host(request()).authorize_protected_group(["security_admin"], member_id=42)

    @pytest.mark.asyncio
    async def test_cannot_add_to_protected_group_not_held(self):
        with (
            patch.object(guards, "policy_allows", new=AsyncMock(return_value=(True, "allowed", None))),
            patch.object(Host, "audit_decision", new=AsyncMock()),
            patch.object(guards, "get_session", new=AsyncMock(return_value=session(groups=("security_admin",)))),
        ):
            with pytest.raises(web.HTTPForbidden):
                await Host(request()).authorize_protected_group(["superuser"], member_id=99)
