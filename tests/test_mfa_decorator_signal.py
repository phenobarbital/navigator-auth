"""FEAT-106 R2: decorators must not let a later backend authenticate after an MFA signal."""

from types import SimpleNamespace

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.decorators import is_authenticated
from navigator_auth.exceptions import MFARequired


class _ChallengingBackend:
    """Backend that owes a second factor."""

    async def authenticate(self, request):
        raise MFARequired("chal", ["email"], "email", 300)


class _AcceptingBackend:
    """A later backend that would accept the very same request."""

    called = False

    async def authenticate(self, request):
        type(self).called = True
        return {"user_id": 1}


def _request(backends: dict) -> web.Request:
    app = {"auth": SimpleNamespace(backends=backends)}
    return make_mocked_request("GET", "/protected", app=app)


@pytest.mark.asyncio
async def test_function_decorator_does_not_fall_through_after_mfa_signal():
    """An owed second factor yields 401, and the next backend is never consulted."""
    _AcceptingBackend.called = False

    @is_authenticated()
    async def handler(request):
        return web.Response(text="ok")

    request = _request({"BasicAuth": _ChallengingBackend(), "Other": _AcceptingBackend()})
    with pytest.raises(web.HTTPUnauthorized):
        await handler(request)
    assert _AcceptingBackend.called is False


@pytest.mark.asyncio
async def test_function_decorator_still_authenticates_without_signal():
    """Control: without an MFA signal the second backend authenticates as before."""
    _AcceptingBackend.called = False

    @is_authenticated()
    async def handler(request):
        return web.Response(text="ok")

    request = _request({"Other": _AcceptingBackend()})
    response = await handler(request)
    assert response.text == "ok"
    assert _AcceptingBackend.called is True
