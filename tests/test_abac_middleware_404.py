"""abac_middleware skips unrouted (404) requests cleanly and logs at DEBUG (FEAT-109 M3)."""

import inspect
import logging

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from navigator_auth.abac import middleware as abac_mw
from navigator_auth.abac.middleware import abac_middleware
from navigator_auth.conf import EXCLUDE_DEFAULTS


def _app(calls: list) -> web.Application:
    """Build an app whose inner middleware records each pass through the handler chain."""

    @web.middleware
    async def count_calls(request, handler):
        calls.append(request.path)
        return await handler(request)

    async def ok(request):
        return web.Response(text="ok")

    app = web.Application(middlewares=[abac_middleware, count_calls])
    app.router.add_get("/routed", ok)
    return app


@pytest.mark.asyncio
async def test_unrouted_path_no_warning_single_call(caplog):
    """GET of an unrouted path: 404, no WARNING, the 404 handler runs once."""

    caplog.set_level(logging.DEBUG)
    calls: list = []
    async with TestClient(TestServer(_app(calls))) as client:
        response = await client.get("/favicon.ico")
        assert response.status == 404
    assert calls == ["/favicon.ico"]
    noisy = [
        record
        for record in caplog.records
        if record.levelno >= logging.WARNING and "not Authenticated" in record.getMessage()
    ]
    assert noisy == []


@pytest.mark.asyncio
async def test_unauthenticated_routed_logs_debug(caplog):
    """An unauthenticated routed request is logged once, at DEBUG."""

    caplog.set_level(logging.DEBUG)
    calls: list = []
    async with TestClient(TestServer(_app(calls))) as client:
        response = await client.get("/routed")
        assert response.status == 200
    assert calls == ["/routed"]
    levels = [
        record.levelno for record in caplog.records if "Access to /routed is not Authenticated." in record.getMessage()
    ]
    assert levels == [logging.DEBUG]


def test_is_system_route_false_when_route_unreadable():
    """An error while reading match_info means 'not a system route'."""

    class _Broken:
        @property
        def match_info(self):
            raise RuntimeError("no match info")

    assert abac_mw._is_system_route(_Broken()) is False


def test_single_type_key_except_clause():
    """The duplicated, unreachable except clause is gone."""

    source = inspect.getsource(abac_mw.abac_middleware)
    assert source.count("except (TypeError, KeyError)") == 1


def test_exclude_defaults_unchanged():
    """Probe paths are not added to the default auth exclude list."""

    assert "/favicon.ico" not in EXCLUDE_DEFAULTS
    assert not any(path.startswith("/.well-known") for path in EXCLUDE_DEFAULTS)
