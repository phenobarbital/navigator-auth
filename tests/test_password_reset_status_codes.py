"""Status codes of ``UserSession.password_reset`` for the two refusal paths.

* A superuser who resets a user that does not exist gets 404, not 500. The
  handler raises ``HTTPNotFound`` inside a ``try`` whose generic
  ``except Exception`` used to turn it into a 500 "Error getting User: User not
  found" (``password_change`` already re-raises ``web.HTTPException``).
* A signed-in caller who is not a superuser gets 403 with a permission message,
  not 406 "Access Denied, Session Missing": the session is present.

In-process: the request is built with ``make_mocked_request``; the database is
replaced at the ``User.get`` boundary and the security transition is patched so
the test can assert it was never entered.
"""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from asyncdb.exceptions import NoDataFound
from navigator_session import AUTH_SESSION_OBJECT, SESSION_KEY

from navigator_auth.handlers.users.session import UserSession
from navigator_auth.models import User

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

ACTOR_ID, MISSING_ID, VICTIM_ID = 7, 424242, 99
MODULE = "navigator_auth.handlers.users.session"


class FakeSession(dict):
    """Session double exposing ``decode`` like the real one."""

    def decode(self, key):
        return self.get(key)


class _Conn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _session(superuser: bool) -> FakeSession:
    info = {"user_id": ACTOR_ID, "username": "actor", "groups": [], "superuser": superuser}
    return FakeSession({AUTH_SESSION_OBJECT: info, SESSION_KEY: "sid"})


def _request(userid: int) -> web.Request:
    return make_mocked_request(
        "POST",
        f"/api/v2/user/password_reset/{userid}",
        match_info={"userid": str(userid)},
        app={"authdb": MagicMock(acquire=AsyncMock(return_value=_Conn()))},
    )


def _transition_spy():
    entered = []

    @asynccontextmanager
    async def _transition(app, user_id, event, **kwargs):
        entered.append(user_id)
        yield MagicMock()

    return entered, patch(f"{MODULE}.security_transition", new=_transition)


async def _reset(session: FakeSession, userid: int, user_get: AsyncMock):
    handler = UserSession()
    handler.json_data = AsyncMock(return_value={"password": "reset-789"})
    entered, transition = _transition_spy()
    with (
        patch(f"{MODULE}.get_session", new=AsyncMock(return_value=session)),
        patch.object(User, "get", new=user_get),
        transition,
        pytest.raises(web.HTTPException) as caught,
    ):
        await handler.password_reset(_request(userid))
    return caught.value, entered


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "user_get",
    [AsyncMock(side_effect=NoDataFound("no row")), AsyncMock(return_value=None)],
    ids=["get-raises-NoDataFound", "get-returns-None"],
)
async def test_reset_of_unknown_user_is_404(user_get):
    error, entered = await _reset(_session(superuser=True), MISSING_ID, user_get)
    assert error.status == 404, error.text
    assert isinstance(error, web.HTTPNotFound)
    assert entered == []


@pytest.mark.asyncio
async def test_reset_by_non_superuser_is_403_permission_refusal():
    user_get = AsyncMock()
    error, entered = await _reset(_session(superuser=False), VICTIM_ID, user_get)
    assert error.status == 403, error.text
    assert "Session Missing" not in (error.text or "")
    assert "superuser" in (error.text or "").lower()
    user_get.assert_not_awaited()
    assert entered == []
