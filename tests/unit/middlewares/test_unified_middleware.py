import pytest
from unittest.mock import AsyncMock
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from navigator_auth.middlewares.strategies import TokenStrategy
from navigator_auth.middlewares.unified import UnifiedAuthMiddleware


class DummyStrategy(TokenStrategy):
    """Strategy that always extracts token='VALID' and validates to {'user_id': 1}."""

    # Opt into sanitization of the ``apikey`` query param (per-strategy design).
    query_params = frozenset({"apikey"})

    def extract(self, request: web.Request) -> tuple:
        token = request.headers.get("X-Test-Token")
        return (token, "test") if token else (None, None)

    async def validate(self, token: str, scheme: str, app) -> dict:
        if token == "VALID":
            return {"user_id": 1, "name": "test"}
        raise web.HTTPForbidden(reason="Bad token")

    def should_enforce(self, request: web.Request, protected_routes: tuple) -> bool:
        return request.path in protected_routes


class TestUnifiedMiddleware:
    def test_instantiation(self):
        mw = UnifiedAuthMiddleware(
            strategy=DummyStrategy(),
            protected_routes=("/api/data",),
        )
        assert mw.strategy is not None
        assert mw.protected_routes == ("/api/data",)

    def test_new_style_middleware_version(self):
        mw = UnifiedAuthMiddleware(strategy=DummyStrategy())
        assert getattr(mw, "__middleware_version__", None) == 1

    @pytest.mark.asyncio
    async def test_skips_unprotected_route(self):
        user_fn = AsyncMock(return_value={"id": 1})
        mw = UnifiedAuthMiddleware(
            strategy=DummyStrategy(),
            user_fn=user_fn,
            protected_routes=("/api/protected",),
        )
        request = make_mocked_request("GET", "/api/public")
        handler = AsyncMock(return_value=web.Response(text="ok"))
        resp = await mw(request, handler)
        assert resp.status == 200
        user_fn.assert_not_called()

    @pytest.mark.asyncio
    async def test_enforces_protected_route_no_token(self):
        mw = UnifiedAuthMiddleware(
            strategy=DummyStrategy(),
            protected_routes=("/api/data",),
        )
        request = make_mocked_request("GET", "/api/data")
        handler = AsyncMock()
        with pytest.raises(web.HTTPForbidden, match="Missing credentials"):
            await mw(request, handler)

    @pytest.mark.asyncio
    async def test_authenticated_sets_user(self):
        async def user_fn(payload, request):
            return {"id": payload["user_id"]}

        mw = UnifiedAuthMiddleware(
            strategy=DummyStrategy(),
            user_fn=user_fn,
            protected_routes=("/api/data",),
        )
        request = make_mocked_request(
            "GET", "/api/data",
            headers={"X-Test-Token": "VALID"},
        )
        handler = AsyncMock(return_value=web.Response(text="ok"))
        await mw(request, handler)
        handler.assert_called_once()
        called_request = handler.call_args[0][0]
        assert called_request.user == {"id": 1}

    @pytest.mark.asyncio
    async def test_sanitizes_auth_query_params(self):
        mw = UnifiedAuthMiddleware(
            strategy=DummyStrategy(),
            protected_routes=(),
        )
        request = make_mocked_request("GET", "/api/data?apikey=SECRET&page=1")
        handler = AsyncMock(return_value=web.Response(text="ok"))
        await mw(request, handler)
        called_request = handler.call_args[0][0]
        assert "apikey" not in dict(called_request.query)
        assert called_request.query.get("page") == "1"

    @pytest.mark.asyncio
    async def test_no_user_fn_still_works(self):
        mw = UnifiedAuthMiddleware(
            strategy=DummyStrategy(),
            protected_routes=("/api/data",),
        )
        request = make_mocked_request(
            "GET", "/api/data",
            headers={"X-Test-Token": "VALID"},
        )
        handler = AsyncMock(return_value=web.Response(text="ok"))
        await mw(request, handler)
        handler.assert_called_once()

    @pytest.mark.asyncio
    async def test_legacy_factory_pattern(self):
        mw = UnifiedAuthMiddleware(
            strategy=DummyStrategy(),
            protected_routes=("/api/data",),
        )
        request = make_mocked_request(
            "GET", "/api/data",
            headers={"X-Test-Token": "VALID"},
        )
        handler = AsyncMock(return_value=web.Response(text="ok"))
        app = web.Application()
        inner = await mw.middleware(app, handler)
        await inner(request)
        handler.assert_called_once()
