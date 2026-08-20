"""Tests for @user_session attribute attachment on the bare-function path."""
from unittest.mock import AsyncMock, patch

import pytest

from navigator_auth.decorators import user_session


class FakeRequest:
    """Minimal stand-in for web.Request: mapping access plus settable attributes."""

    def __init__(self, data: dict = None):
        self._data = dict(data or {})
        self.method = "GET"

    def get(self, key, default=None):
        return self._data.get(key, default)

    def __getitem__(self, key):
        return self._data[key]

    def __setitem__(self, key, value):
        self._data[key] = value


class FakeSession:
    def __init__(self, user=None):
        self._user = user

    def decode(self, key):
        if self._user is None:
            raise RuntimeError("no user in session")
        return self._user

    def get(self, key, default=None):
        return default


def _patched(session):
    return (
        patch(
            "navigator_auth.decorators.get_session",
            new_callable=AsyncMock,
            return_value=session,
        ),
        patch("navigator_auth.decorators._attach_vault_to_request"),
    )


@pytest.mark.asyncio
async def test_func_path_attaches_session_and_user_to_request():
    """Bare-function handlers get request.session/request.user, like class views."""
    session_user = object()
    session = FakeSession(user=session_user)
    request = FakeRequest()
    get_sess, vault = _patched(session)

    with get_sess, vault:
        @user_session()
        async def handler(request, session=None, user=None):
            return "ok"

        await handler(request)

    assert request.session is session
    assert request.user is session_user
    assert request["session"] is session


@pytest.mark.asyncio
async def test_func_path_adopts_middleware_user_without_clobbering():
    """A middleware-attached request.user survives when the session has no user."""
    middleware_user = object()
    session = FakeSession(user=None)
    request = FakeRequest()
    request.user = middleware_user
    get_sess, vault = _patched(session)
    received = {}

    with get_sess, vault:
        @user_session()
        async def handler(request, session=None, user=None):
            received["user"] = user
            return "ok"

        await handler(request)

    assert request.user is middleware_user
    assert received["user"] is middleware_user


@pytest.mark.asyncio
async def test_func_path_never_writes_none_user():
    """With no user anywhere, request.user is left unset rather than set to None."""
    session = FakeSession(user=None)
    request = FakeRequest()
    get_sess, vault = _patched(session)
    received = {}

    with get_sess, vault:
        @user_session()
        async def handler(request, session=None, user=None):
            received["user"] = user
            return "ok"

        await handler(request)

    assert not hasattr(request, "user")
    assert request.session is session
    assert received["user"] is None


@pytest.mark.asyncio
async def test_func_path_still_attaches_to_view_like_first_arg():
    """When args[0] is a view-like instance, it keeps receiving session/user."""

    class ViewLike:
        session = None
        user = None

    view = ViewLike()
    session_user = object()
    session = FakeSession(user=session_user)
    request = FakeRequest()
    get_sess, vault = _patched(session)

    with get_sess, vault:
        @user_session()
        async def handler(self, request, session=None, user=None):
            return "ok"

        await handler(view, request)

    assert view.session is session
    assert view.user is session_user
    assert request.session is session
    assert request.user is session_user
