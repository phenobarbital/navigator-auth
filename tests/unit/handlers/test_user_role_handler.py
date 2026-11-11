"""Focused contract tests for the privileged user-role handler."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.handlers.users.role import UserRoleHandler

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")


def _handler(payload):
    request = make_mocked_request("POST", "/api/v1/users/2/role", app={})
    handler = UserRoleHandler.__new__(UserRoleHandler)
    handler.request = request
    handler._request = request
    handler.json_data = AsyncMock(return_value=payload)
    handler.error = MagicMock(side_effect=lambda **kwargs: (_ for _ in ()).throw(web.HTTPBadRequest()))
    return handler


@pytest.mark.asyncio
async def test_role_payload_rejects_unknown_keys():
    with pytest.raises(web.HTTPBadRequest):
        await _handler({"email": "x"})._role_payload()


@pytest.mark.asyncio
async def test_role_payload_accepts_strict_boolean():
    assert await _handler({"is_staff": True})._role_payload() == {"is_staff": True}


def test_role_handler_configuration():
    assert UserRoleHandler.model.__name__ == "User"
    assert UserRoleHandler.superuser_actions == frozenset()
