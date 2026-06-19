"""JWT Middleware — backward-compatible alias for UnifiedAuthMiddleware."""
from typing import Optional
from collections.abc import Coroutine
from navconfig import config
from navigator_session import SESSION_USER_PROPERTY
from navigator_auth.conf import SECRET_KEY
from .unified import UnifiedAuthMiddleware
from .strategies import JWTStrategy


class jwt_middleware(UnifiedAuthMiddleware):
    def __init__(
        self,
        user_fn: Coroutine,
        user_property: str = SESSION_USER_PROPERTY,
        exclude_routes: Optional[tuple] = tuple(),
        jwt_algorithm: str = "HS256",
    ):
        if exclude_routes is None:
            exclude_routes = config.get("EXCLUDED_ROUTES", tuple())
        super().__init__(
            strategy=JWTStrategy(secret_key=SECRET_KEY, algorithm=jwt_algorithm),
            user_fn=user_fn,
            user_property=user_property,
            exclude_routes=exclude_routes,
        )
