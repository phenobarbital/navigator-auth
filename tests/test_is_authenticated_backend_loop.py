"""FEAT-108 M4 — ``@is_authenticated`` backend loop (D1, D2, FEAT-106 MFA)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web

from navigator_auth.backends.abstract import BaseAuthBackend
from navigator_auth.backends.noauth import NoAuth
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY
from navigator_auth.decorators import is_authenticated
from navigator_auth.exceptions import MfaSignal


def _backend(*, result=None, raises=None, anonymous=False) -> MagicMock:
    """Build a backend double with an explicit anonymous marker."""
    backend = MagicMock()
    backend._anonymous_auth = anonymous
    backend.authenticate = AsyncMock(return_value=result, side_effect=raises)
    return backend


def _request(backends: dict) -> MagicMock:
    """Build a request double with the configured authentication backends."""
    request = MagicMock(spec=web.Request)
    request.method = "GET"
    request.path = "/api/v1/me"
    request.app = {AUTH_EXCLUDE_LIST_KEY: [], "auth": MagicMock(backends=backends)}
    request.get = lambda key, default=None: default
    request.allow_anonymous = False
    return request


def test_noauth_class_flag():
    """NoAuth is explicitly identified as a guest backend."""
    assert NoAuth._anonymous_auth is True
    assert BaseAuthBackend._anonymous_auth is False


@pytest.mark.asyncio
async def test_anonymous_backend_is_never_called():
    """Anonymous backends cannot authenticate a protected function handler."""
    guest = _backend(result={"user": "guest"}, anonymous=True)
    handler = AsyncMock(return_value=web.Response(status=200))

    with pytest.raises(web.HTTPUnauthorized):
        await is_authenticated()(handler)(_request({"NoAuth": guest}))

    guest.authenticate.assert_not_awaited()
    handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_unexpected_error_is_logged_and_skipped():
    """Unexpected backend errors are logged and do not prevent later success."""
    first = _backend(raises=TypeError("token-secret-value"))
    second = _backend(result={"user": "demo"})
    handler = AsyncMock(return_value=web.Response(status=200))

    with patch("navigator_auth.decorators.logger") as log:
        response = await is_authenticated()(handler)(_request({"A": first, "B": second}))

    assert response.status == 200
    handler.assert_awaited_once()
    log.exception.assert_called_once()
    log_args = log.exception.call_args.args
    assert log_args[0] == "is_authenticated: backend %s failed; trying the next one"
    assert log_args[1] == "A"
    assert "token-secret-value" not in str(log.exception.call_args)


@pytest.mark.asyncio
async def test_unexpected_error_only_backend_gives_401():
    """An unexpected error from the only backend fails closed with 401."""
    only = _backend(raises=TypeError("boom"))

    with patch("navigator_auth.decorators.logger"):
        with pytest.raises(web.HTTPUnauthorized):
            await is_authenticated()(AsyncMock())(_request({"A": only}))


@pytest.mark.asyncio
async def test_mfa_signal_still_stops_the_loop():
    """MFA remains terminal and prevents a later backend from authenticating."""
    first = _backend(raises=MfaSignal("second factor required"))
    second = _backend(result={"user": "demo"})

    with pytest.raises(web.HTTPUnauthorized):
        await is_authenticated()(AsyncMock())(_request({"A": first, "B": second}))

    second.authenticate.assert_not_awaited()


@pytest.mark.asyncio
async def test_method_wrapper_same_semantics():
    """Class-based views share anonymous, error, and MFA backend semantics."""

    class ProtectedView:
        def __init__(self, request):
            self.request = request

        async def get(self):
            return web.Response(status=200)

    guest = _backend(result={"user": "guest"}, anonymous=True)
    error = _backend(raises=TypeError("boom"))
    success = _backend(result={"user": "demo"})
    decorated = is_authenticated()(ProtectedView)

    with patch("navigator_auth.decorators.logger") as log:
        response = await decorated(_request({"guest": guest, "error": error, "success": success})).get()

    assert response.status == 200
    guest.authenticate.assert_not_awaited()
    error.authenticate.assert_awaited_once()
    success.authenticate.assert_awaited_once()
    log.exception.assert_called_once()

    mfa = _backend(raises=MfaSignal("second factor required"))
    later = _backend(result={"user": "demo"})
    with pytest.raises(web.HTTPUnauthorized):
        await decorated(_request({"mfa": mfa, "later": later})).get()
    later.authenticate.assert_not_awaited()
