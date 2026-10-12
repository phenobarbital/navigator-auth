"""
Regression test: AuthHandler.get_session() must not crash when the session
storage returns ``None`` (session removed by logout or expired) instead of
raising. Previously this fell through to ``session.session_data()`` and
raised ``AttributeError: 'NoneType' object has no attribute 'session_data'``.
"""
from types import SimpleNamespace

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.auth import AuthHandler


class _NoneStorage:
    """Storage stub: no session exists, and creating one also yields nothing."""

    def __init__(self) -> None:
        self.get_calls = 0
        self.new_calls = 0

    async def get_session(self, request: web.Request):
        self.get_calls += 1
        return None

    async def new_session(self, request: web.Request, data: dict):
        self.new_calls += 1
        return None


class _NewSessionStorage(_NoneStorage):
    """Storage stub: no session exists, but a fresh empty one can be created."""

    async def new_session(self, request: web.Request, data: dict):
        self.new_calls += 1
        return SimpleNamespace(session_data=lambda: dict(data))


def _handler(storage) -> AuthHandler:
    handler = object.__new__(AuthHandler)
    handler._session = SimpleNamespace(storage=storage)
    return handler


@pytest.mark.asyncio
async def test_get_session_returns_empty_when_storage_yields_none():
    storage = _NoneStorage()
    request = make_mocked_request("GET", "/api/v1/session")
    response = await _handler(storage).get_session(request)
    assert response.status == 200
    assert response.text == "{}"
    assert storage.get_calls == 2
    assert storage.new_calls == 1


@pytest.mark.asyncio
async def test_get_session_uses_fresh_session_after_logout():
    storage = _NewSessionStorage()
    request = make_mocked_request("GET", "/api/v1/session")
    response = await _handler(storage).get_session(request)
    assert response.status == 200
    assert response.text == "{}"
    assert storage.new_calls == 1
