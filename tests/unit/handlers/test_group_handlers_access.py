"""Access configuration and protected-group resolution for group handlers."""

from unittest.mock import AsyncMock, MagicMock, patch

from asyncdb.exceptions import NoDataFound
import pytest

from navigator_auth.handlers.groups import (
    GroupManager,
    GroupPermissionManager,
    UserGroupManager,
    _stored_group_name,
)


class _Connection:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _Row:
    group_name = "security_admin"


class TestConfiguration:
    def test_mapping_handlers_have_no_owner(self):
        assert UserGroupManager.owner_column is None
        assert GroupPermissionManager.owner_column is None

    def test_policy_actions_match_pack(self):
        assert GroupManager.superuser_actions == {
            "group:read",
            "group:create",
            "group:update",
            "group:delete",
        }
        assert UserGroupManager.superuser_actions == {
            "user_group:read",
            "user_group:create",
            "user_group:delete",
        }
        assert GroupPermissionManager.superuser_actions == {
            "group_permission:read",
            "group_permission:create",
            "group_permission:delete",
        }


@pytest.mark.asyncio
async def test_stored_group_name_uses_database_value():
    view = MagicMock()
    view.request = MagicMock()
    view.handler = AsyncMock(return_value=_Connection())
    with patch("navigator_auth.handlers.groups.Group.get", new=AsyncMock(return_value=_Row())) as lookup:
        result = await _stored_group_name(view, 2)
    assert result == "security_admin"
    lookup.assert_awaited_once_with(group_id=2)


@pytest.mark.asyncio
async def test_stored_group_name_returns_none_for_missing_group():
    view = MagicMock()
    view.request = MagicMock()
    view.handler = AsyncMock(return_value=_Connection())
    with patch("navigator_auth.handlers.groups.Group.get", new=AsyncMock(side_effect=NoDataFound("missing"))):
        assert await _stored_group_name(view, 999) is None


class TestQueryStringCannotBypassProtectedGroups:
    """navigator PUT merges ``{**query, **body}``; authorization must see it."""

    @staticmethod
    def _view(cls, body, query):
        view = object.__new__(cls)
        view._request = MagicMock()
        view.json_data = AsyncMock(return_value=body)
        view.query_parameters = MagicMock(return_value=query)
        return view

    @pytest.mark.asyncio
    async def test_membership_group_id_only_in_query_is_checked(self):
        from navigator_auth.handlers.guard_hooks import GuardedModelViewHooks

        view = self._view(UserGroupManager, {"user_id": 7}, {"group_id": "1", "bogus": "x"})
        view.authorize_protected_group = AsyncMock()
        with (
            patch.object(GuardedModelViewHooks, "_pre_put", new=AsyncMock(return_value=True)),
            patch(
                "navigator_auth.handlers.groups._stored_group_name", new=AsyncMock(return_value="security_admin")
            ) as stored,
        ):
            await view._pre_put()
        stored.assert_awaited_once_with(view, "1")
        view.authorize_protected_group.assert_awaited_once_with({"security_admin"}, member_id=7)

    @pytest.mark.asyncio
    async def test_group_name_only_in_query_is_checked(self):
        view = self._view(GroupManager, {"description": "x"}, {"group_name": "security_admin"})
        assert await view._payload_names() == {"security_admin"}

    @pytest.mark.asyncio
    async def test_body_wins_over_query(self):
        view = self._view(GroupManager, {"group_name": "ordinary"}, {"group_name": "security_admin"})
        assert await view._payload_names() == {"ordinary"}
