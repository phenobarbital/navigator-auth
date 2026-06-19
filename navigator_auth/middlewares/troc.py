"""RNC Token Middleware — backward-compatible alias for UnifiedAuthMiddleware."""
from typing import Optional
from collections.abc import Coroutine
from navigator_auth.libs.cipher import Cipher
from navigator_auth.conf import PARTNER_KEY, CYPHER_TYPE
from .unified import UnifiedAuthMiddleware
from .strategies import TrocTokenStrategy

CIPHER = Cipher(PARTNER_KEY, type=CYPHER_TYPE)


class troctoken_middleware(UnifiedAuthMiddleware):
    def __init__(
        self,
        user_fn: Optional[Coroutine] = None,
        protected_routes: Optional[tuple] = tuple(),
    ):
        super().__init__(
            strategy=TrocTokenStrategy(cipher=CIPHER),
            user_fn=user_fn,
            protected_routes=protected_routes,
        )
