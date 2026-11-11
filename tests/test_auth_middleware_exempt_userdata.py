"""FEAT-108 M5 — the exempt branch publishes the bearer claims."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import hdrs

from navigator_auth.auth import AuthHandler
from navigator_auth.conf import AUTH_MECHANISM_BEARER, AUTH_MECHANISM_KEY

PAYLOAD = {"user_id": 1, "username": "demo", "client_id": "nav_example_spa", "jti": "j-1", "scope": "default"}


class RequestDouble(dict):
    """Minimal request double used by ``AuthHandler._auth_middleware``."""

    def __init__(self):
        super().__init__()
        self.headers = {hdrs.AUTHORIZATION: "Bearer tok"}


def _handler_under_test(user) -> AuthHandler:
    auth = object.__new__(AuthHandler)
    auth.logger = MagicMock()
    auth.verify_exceptions = AsyncMock(return_value=True)
    auth._token_is_revoked = AsyncMock(return_value=False)
    auth._oauth_generation_ok = AsyncMock(return_value=True)
    auth.get_session_user = AsyncMock(return_value=user)
    auth._idp = MagicMock()
    auth._idp.get_payload = AsyncMock(return_value="tok")
    auth._idp.decode_token = MagicMock(return_value=("Bearer", PAYLOAD))
    return auth


def _request() -> RequestDouble:
    """Return a request double with the mapping and attribute APIs used by the middleware."""
    return RequestDouble()


@pytest.mark.asyncio
async def test_exempt_branch_publishes_userdata():
    user = MagicMock()
    auth = _handler_under_test(user)
    request = _request()
    handler = AsyncMock(return_value="ok")
    with patch("navigator_auth.auth.get_session", AsyncMock(return_value=MagicMock())):
        await auth._auth_middleware(request, handler)
    assert request["userdata"] == PAYLOAD
    assert request.user is user
    assert request["authenticated"] is True
    assert request[AUTH_MECHANISM_KEY] == AUTH_MECHANISM_BEARER


@pytest.mark.asyncio
async def test_exempt_branch_invalid_token_unchanged():
    auth = _handler_under_test(MagicMock())
    auth._idp.decode_token = MagicMock(side_effect=ValueError("bad token"))
    request = _request()
    handler = AsyncMock(return_value="ok")
    assert await auth._auth_middleware(request, handler) == "ok"
    assert "userdata" not in request
    assert "authenticated" not in request
