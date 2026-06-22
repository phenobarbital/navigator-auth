from types import SimpleNamespace

import pytest
from aiohttp import hdrs

from navigator_auth.middlewares.abstract import base_middleware


class DummyMiddleware(base_middleware):
    async def middleware(self, app, handler):
        return handler


def make_request(path="/api/v1/items", method=hdrs.METH_GET):
    return SimpleNamespace(
        path=path,
        method=method,
        match_info=SimpleNamespace(route=object()),
        user="placeholder",
    )


@pytest.mark.asyncio
async def test_valid_routes_allows_options_before_static_check():
    middleware = DummyMiddleware()
    middleware.check_static = True

    request = make_request(method=hdrs.METH_OPTIONS)

    assert await middleware.valid_routes(request) is True


@pytest.mark.asyncio
async def test_valid_routes_honors_excluded_routes_with_wildcards():
    middleware = DummyMiddleware()
    middleware.exclude_routes = ("/api/v1/public/*",)

    request = make_request(path="/api/v1/public/ping")

    assert await middleware.valid_routes(request) is True
