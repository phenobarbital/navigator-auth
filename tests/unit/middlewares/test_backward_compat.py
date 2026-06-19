"""Backward-compatibility tests for old middleware class names.

Verifies that the legacy class names remain importable with their original
constructor signatures after they were refactored to delegate to
UnifiedAuthMiddleware.
"""
import pytest
import warnings
from unittest.mock import AsyncMock, MagicMock
from aiohttp import web
from aiohttp.test_utils import make_mocked_request


class TestAPIKeyMiddlewareCompat:
    def test_old_import_works(self):
        from navigator_auth.middlewares.apikey import apikey_middleware
        mw = apikey_middleware(
            user_fn=AsyncMock(),
            protected_routes=("/api/v2",),
        )
        assert hasattr(mw, "strategy")

    def test_no_user_fn(self):
        from navigator_auth.middlewares.apikey import apikey_middleware
        mw = apikey_middleware()
        assert mw._fn is None

    @pytest.mark.asyncio
    async def test_middleware_callable(self):
        from navigator_auth.middlewares.apikey import apikey_middleware
        mw = apikey_middleware(user_fn=AsyncMock())
        handler = AsyncMock(return_value=web.Response(text="ok"))
        app = web.Application()
        inner = await mw.middleware(app, handler)
        assert callable(inner)


class TestTokenMiddlewareCompat:
    def test_old_import_works(self):
        from navigator_auth.middlewares.token import token_middleware
        mw = token_middleware(user_fn=AsyncMock())
        assert hasattr(mw, "strategy")

    def test_with_exclude_routes(self):
        from navigator_auth.middlewares.token import token_middleware
        mw = token_middleware(
            user_fn=AsyncMock(),
            exclude_routes=("/health",),
        )
        assert "/health" in mw.exclude_routes


class TestTrocMiddlewareCompat:
    def test_old_import_works(self):
        from navigator_auth.middlewares.troc import troctoken_middleware
        mw = troctoken_middleware(
            user_fn=AsyncMock(),
            protected_routes=("/partner",),
        )
        assert hasattr(mw, "strategy")


class TestJWTMiddlewareCompat:
    def test_old_import_works(self):
        from navigator_auth.middlewares.jwt import jwt_middleware
        mw = jwt_middleware(user_fn=AsyncMock())
        assert hasattr(mw, "strategy")

    def test_custom_algorithm(self):
        from navigator_auth.middlewares.jwt import jwt_middleware
        mw = jwt_middleware(user_fn=AsyncMock(), jwt_algorithm="HS512")
        assert mw.strategy._algorithm == "HS512"


class TestDjangoMiddlewareCompat:
    def test_old_import_works(self):
        from navigator_auth.middlewares.django import django_middleware
        mw = django_middleware(user_fn=AsyncMock())
        assert hasattr(mw, "strategy")


class TestPackageExports:
    def test_old_exports(self):
        from navigator_auth.middlewares import (
            jwt_middleware,
            token_middleware,
            apikey_middleware,
        )
        assert jwt_middleware is not None

    def test_new_exports(self):
        from navigator_auth.middlewares import (
            UnifiedAuthMiddleware,
            TokenStrategy,
        )
        assert UnifiedAuthMiddleware is not None
        assert TokenStrategy is not None
