"""Unified auth middleware driven by pluggable TokenStrategy."""
from typing import Optional, Any
from collections.abc import Callable, Awaitable, Coroutine
import logging
from aiohttp import web
from navigator_session import SESSION_USER_PROPERTY
from ..libs.sanitize import sanitize_request
from .abstract import base_middleware
from .strategies import TokenStrategy


class UnifiedAuthMiddleware(base_middleware):
    """Single middleware that handles all token-based auth via a strategy."""

    def __init__(
        self,
        strategy: TokenStrategy,
        user_fn: Optional[Coroutine] = None,
        user_property: str = SESSION_USER_PROPERTY,
        protected_routes: Optional[tuple] = tuple(),
        exclude_routes: Optional[tuple] = tuple(),
    ):
        if user_fn is not None and not callable(user_fn):
            raise RuntimeError(
                f"If defined, User Function {user_fn!s} need to be Callable."
            )
        self.strategy = strategy
        self._fn = user_fn
        self.user_property = user_property
        if protected_routes:
            self.protected_routes = protected_routes
        if exclude_routes:
            self.exclude_routes = exclude_routes

    async def middleware(self, app, handler):
        @web.middleware
        async def mw(request):
            if await self.valid_routes(request):
                return await handler(request)

            token, scheme = self.strategy.extract(request)

            if self.strategy.should_enforce(request, self.protected_routes):
                if not token:
                    raise web.HTTPForbidden(reason="Missing credentials")
                payload = await self.strategy.validate(token, scheme, app)
                if self._fn:
                    user = await self._fn(payload, request)
                    if not user:
                        raise web.HTTPForbidden(reason="Access Restricted")
                    request[self.user_property] = user
                    request.user = user

            return await handler(sanitize_request(request))

        return mw
