"""Unit tests for is_authenticated exclude-list short-circuit (FEAT-241 M3).

Tests cover:
- Excluded path reaches handler without 401
- Non-excluded path still fails authentication
- Glob pattern matching
- allow_anonymous bypass
"""
import fnmatch
import pytest
from unittest.mock import AsyncMock, MagicMock
from aiohttp import web
from navigator_auth.decorators import is_authenticated
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY


def _make_request(
    path: str,
    exclude_list: list[str],
    authenticated: bool = False,
    allow_anonymous: bool = False,
):
    """Build a minimal mock web.Request."""
    req = MagicMock(spec=web.Request)
    req.method = "GET"
    req.path = path
    req.app = {AUTH_EXCLUDE_LIST_KEY: exclude_list}
    req.get = lambda key, default=None: authenticated if key == "authenticated" else default
    req.allow_anonymous = allow_anonymous
    return req


class TestIsAuthenticatedExcludeList:
    @pytest.mark.asyncio
    async def test_excluded_path_reaches_handler(self):
        """Anonymous request to excluded path must not 401."""
        handler = AsyncMock(return_value=web.Response(status=200))
        decorated = is_authenticated()(handler)
        request = _make_request(
            "/api/v1/forms/contact",
            exclude_list=["/api/v1/forms/contact"],
        )
        response = await decorated(request)
        assert response.status == 200
        handler.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_non_excluded_path_fails_authentication(self):
        """Anonymous request to non-excluded path fails (either 401 or 400 when no auth backend)."""
        handler = AsyncMock(return_value=web.Response(status=200))
        decorated = is_authenticated()(handler)
        request = _make_request("/api/v1/forms/contact", exclude_list=[])
        # Without auth backend in app, get_auth raises HTTPBadRequest.
        # With auth backend that rejects, raises HTTPUnauthorized.
        # Either way, the handler is NOT called.
        with pytest.raises((web.HTTPUnauthorized, web.HTTPBadRequest)):
            await decorated(request)
        handler.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_glob_pattern_matches(self):
        """Glob pattern /api/v1/forms/*/render/* should match correctly."""
        handler = AsyncMock(return_value=web.Response(status=200))
        decorated = is_authenticated()(handler)
        request = _make_request(
            "/api/v1/forms/contact/render/html",
            exclude_list=["/api/v1/forms/*/render/*"],
        )
        response = await decorated(request)
        assert response.status == 200
        handler.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_allow_anonymous_short_circuits(self):
        """Request with allow_anonymous=True must bypass auth."""
        handler = AsyncMock(return_value=web.Response(status=200))
        decorated = is_authenticated()(handler)
        request = _make_request(
            "/api/v1/forms/private",
            exclude_list=[],
            allow_anonymous=True,
        )
        response = await decorated(request)
        assert response.status == 200
        handler.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_exact_path_in_list(self):
        """Exact path in exclude list: handler reached."""
        handler = AsyncMock(return_value=web.Response(status=200))
        decorated = is_authenticated()(handler)
        request = _make_request(
            "/api/v1/forms/survey/schema",
            exclude_list=["/api/v1/forms/survey/schema"],
        )
        response = await decorated(request)
        assert response.status == 200

    @pytest.mark.asyncio
    async def test_non_matching_glob_does_not_bypass(self):
        """Non-matching glob should not short-circuit to handler."""
        handler = AsyncMock(return_value=web.Response(status=200))
        decorated = is_authenticated()(handler)
        # Exclude /forms/other/* — not matching /forms/contact/*
        request = _make_request(
            "/api/v1/forms/contact/schema",
            exclude_list=["/api/v1/forms/other/*"],
        )
        with pytest.raises((web.HTTPUnauthorized, web.HTTPBadRequest)):
            await decorated(request)
        handler.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_exclude_list_no_bypass(self):
        """Empty exclude list: no bypass for anonymous requests."""
        handler = AsyncMock(return_value=web.Response(status=200))
        decorated = is_authenticated()(handler)
        request = _make_request("/api/v1/forms/contact", exclude_list=[])
        with pytest.raises((web.HTTPUnauthorized, web.HTTPBadRequest)):
            await decorated(request)
        handler.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_data_path_excluded(self):
        """POST /data path exclusion reaches handler."""
        handler = AsyncMock(return_value=web.Response(status=200))
        decorated = is_authenticated()(handler)
        request = _make_request(
            "/api/v1/forms/contact/data",
            exclude_list=["/api/v1/forms/contact/data"],
        )
        response = await decorated(request)
        assert response.status == 200
