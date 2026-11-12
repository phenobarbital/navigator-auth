"""Revocation outages must never authenticate a bearer request."""

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.auth import AuthHandler
from navigator_auth.backends.oauth2.backend import Oauth2Provider
from navigator_auth.exceptions import InvalidAuth


def _auth(payload: dict, lookup: AsyncMock) -> AuthHandler:
    """Build middleware with only token decoding and storage stubbed."""
    auth = AuthHandler.__new__(AuthHandler)
    auth.logger = logging.getLogger(__name__)
    auth.backends = {"oauth2": SimpleNamespace(access_token_storage=SimpleNamespace(is_revoked=lookup))}
    auth._idp = SimpleNamespace(get_payload=AsyncMock(return_value="token"), decode_token=lambda **kw: (None, payload))
    auth.verify_exceptions = AsyncMock(return_value=False)
    return auth


@pytest.mark.asyncio
@pytest.mark.parametrize("public", [False, True])
async def test_middleware_outage_never_authenticates(public: bool, caplog: pytest.LogCaptureFixture) -> None:
    """Protected routes return 503; public routes continue anonymously."""
    payload = {"user_id": 42, "jti": "private-jti"}
    lookup = AsyncMock(side_effect=RuntimeError("private-store-detail"))
    auth = _auth(payload, lookup)
    auth.verify_exceptions.return_value = public
    request = make_mocked_request("GET", "/resource", headers={"Authorization": "Bearer token"})
    handler = AsyncMock(return_value=web.Response())
    with patch("navigator_auth.auth.get_session", new=AsyncMock()) as session:
        if public:
            response = await auth.auth_middleware(request, handler)
            assert response.status == 200
            handler.assert_awaited_once_with(request)
        else:
            with pytest.raises(web.HTTPServiceUnavailable):
                await auth.auth_middleware(request, handler)
            handler.assert_not_awaited()
        session.assert_not_awaited()
    assert not request.get("authenticated", False)
    lookup.assert_awaited_once_with("private-jti")
    assert "private-jti" not in caplog.text
    assert "private-store-detail" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("revoked", [False, True])
async def test_middleware_revocation_result(revoked: bool) -> None:
    """Successful lookups preserve the stored revocation result."""
    lookup = AsyncMock(return_value=revoked)
    payload = {"jti": "jti"}
    assert await _auth(payload, lookup)._token_is_revoked(payload) is revoked
    lookup.assert_awaited_once_with("jti")


@pytest.mark.asyncio
async def test_legacy_token_skips_lookup() -> None:
    """Tokens minted without a JTI retain their compatibility path."""
    lookup = AsyncMock(side_effect=RuntimeError())
    assert await _auth({}, lookup)._token_is_revoked({"user_id": 42}) is False
    lookup.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome, status", [(RuntimeError("private-store-detail"), 503), (True, 401), (False, 200)])
async def test_provider_revocation_result(outcome: object, status: int, caplog: pytest.LogCaptureFixture) -> None:
    """Direct authentication refuses outage/revocation before loading a session."""
    payload = {"user_id": 42, "jti": "private-jti"}
    lookup = AsyncMock(side_effect=outcome) if isinstance(outcome, Exception) else AsyncMock(return_value=outcome)
    provider = Oauth2Provider.__new__(Oauth2Provider)
    provider.logger = logging.getLogger(__name__)
    provider._idp = _auth(payload, lookup)._idp
    provider.access_token_storage = SimpleNamespace(is_revoked=lookup)
    provider.get_session_user = AsyncMock(return_value=SimpleNamespace(user_id=42))
    provider._set_user_request = MagicMock()
    request = make_mocked_request("GET", "/resource")
    with patch(
        "navigator_auth.backends.oauth2.backend.get_session", new=AsyncMock(return_value={"id": "sid"})
    ) as session:
        if status == 200:
            assert await provider.authenticate(request) == payload
            assert request["authenticated"] is True
            session.assert_awaited_once()
        else:
            with pytest.raises(InvalidAuth) as caught:
                await provider.authenticate(request)
            assert caught.value.status == status
            session.assert_not_awaited()
            provider._set_user_request.assert_not_called()
            assert not request.get("authenticated", False)
    assert "private-jti" not in caplog.text
    assert "private-store-detail" not in caplog.text
