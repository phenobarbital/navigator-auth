"""API Key Middleware — backward-compatible alias for UnifiedAuthMiddleware."""
from typing import Optional
from collections.abc import Coroutine
from .unified import UnifiedAuthMiddleware
from .strategies import APIKeyStrategy


class apikey_middleware(UnifiedAuthMiddleware):
    def __init__(
        self,
        user_fn: Optional[Coroutine] = None,
        protected_routes: Optional[tuple] = tuple(),
    ):
        super().__init__(
            strategy=APIKeyStrategy(),
            user_fn=user_fn,
            protected_routes=protected_routes,
        )
