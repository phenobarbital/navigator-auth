"""Django Session Middleware — backward-compatible alias for UnifiedAuthMiddleware."""
from typing import Optional
from collections.abc import Coroutine
from navigator_auth.conf import DJANGO_SESSION_PREFIX
from .unified import UnifiedAuthMiddleware
from .strategies import DjangoSessionStrategy


class django_middleware(UnifiedAuthMiddleware):
    def __init__(
        self,
        user_fn: Optional[Coroutine] = None,
        protected_routes: Optional[tuple] = tuple(),
    ):
        super().__init__(
            strategy=DjangoSessionStrategy(session_prefix=DJANGO_SESSION_PREFIX),
            user_fn=user_fn,
            protected_routes=protected_routes,
        )
