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


class _Conn:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    async def fetch_one(self, sql, *args):
        self.calls.append((sql, args))
        return self.rows.get(args[0])


@pytest.mark.asyncio
async def test_missing_actor_row_is_refused_not_500():
    """issue:952f6c12269b — an absent actor row is an audited 403, never AttributeError."""
    handler = _handler({"is_staff": True})
    handler.audit_decision = AsyncMock()
    handler._refuse = MagicMock(side_effect=web.HTTPForbidden())
    conn = _Conn({3: {"user_id": 3, "is_staff": False, "is_superuser": False, "user_role": 0}})
    with pytest.raises(web.HTTPForbidden):
        await handler._change_roles(conn, "SELECT", '"s"."t"', {"is_staff": True}, 1, False, 3)
    assert not [sql for sql, _ in conn.calls if sql.startswith("UPDATE")]
    handler.audit_decision.assert_awaited()


@pytest.mark.asyncio
async def test_rows_are_locked_in_id_order():
    handler = _handler({"is_staff": True})
    handler.audit_decision = AsyncMock()
    handler._refuse = MagicMock(side_effect=web.HTTPForbidden())
    conn = _Conn({})
    with pytest.raises(web.HTTPException):
        await handler._change_roles(conn, "SELECT", '"s"."t"', {"is_staff": True}, 9, True, 2)
    assert [args[0] for _, args in conn.calls] == [2, 9]
