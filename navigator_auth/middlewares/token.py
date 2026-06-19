"""Token Middleware — backward-compatible alias for UnifiedAuthMiddleware."""
from typing import Optional
from collections.abc import Coroutine
from navconfig import config
from navigator_session import SESSION_USER_PROPERTY
from .unified import UnifiedAuthMiddleware
from .strategies import PlainTokenStrategy


class token_middleware(UnifiedAuthMiddleware):
    def __init__(
        self,
        user_fn: Coroutine,
        user_property: str = SESSION_USER_PROPERTY,
        exclude_routes: Optional[tuple] = tuple(),
    ):
        if exclude_routes is None:
            exclude_routes = config.get("EXCLUDED_ROUTES", tuple())

        # The original token_middleware called user_fn(token, scheme, request)
        # with 3 args. UnifiedAuthMiddleware calls user_fn(payload, request)
        # where payload is {"token": ..., "scheme": ...}. Adapt the interface.
        async def _adapted_fn(payload, request):
            return await user_fn(payload["token"], payload["scheme"], request)

        super().__init__(
            strategy=PlainTokenStrategy(),
            user_fn=_adapted_fn,
            user_property=user_property,
            exclude_routes=exclude_routes,
        )
