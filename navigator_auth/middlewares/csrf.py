"""CSRF protection middleware — signed double-submit cookie.

Scope: only requests whose *sole* credential is the ambient session cookie
are checked. A request carrying an ``Authorization`` header (Bearer token,
API key, ...) cannot be forged cross-site — an attacker's page has no way
to set that header with a valid credential it doesn't possess — so it is
exempt. This mirrors how ``_auth_middleware`` (navigator_auth/auth.py)
itself distinguishes the two paths: the bearer path always requires
``Authorization``; the cookie-only fallback (``elif self.secure_cookies``)
never does.

Must run *after* ``AuthHandler.auth_middleware`` in the middleware chain,
so ``request['authenticated']`` and the session id are already resolved
when this middleware runs. See ``AuthHandler.setup`` (auth.py).
"""
import hmac
from typing import Optional
from collections.abc import Callable, Awaitable
from aiohttp import web, hdrs
from navigator_session import SESSION_ID
from ..conf import (
    ENABLE_CSRF_PROTECTION,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    CSRF_COOKIE_MAX_AGE,
    SECRET_KEY,
    PREFERRED_AUTH_SCHEME,
)
from ..libs.csrf import generate_csrf_token, verify_csrf_token

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _is_cookie_only_session(request: web.Request) -> bool:
    """True when the request was authenticated purely by the session cookie."""
    return bool(request.get("authenticated")) and hdrs.AUTHORIZATION not in request.headers


def _valid_csrf_request(request: web.Request, session_id: Optional[str]) -> bool:
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    header_token = request.headers.get(CSRF_HEADER_NAME)
    if not session_id or not cookie_token or not header_token:
        return False
    if not hmac.compare_digest(cookie_token, header_token):
        return False
    return verify_csrf_token(SECRET_KEY, session_id, header_token)


@web.middleware
async def csrf_middleware(
    request: web.Request,
    handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
) -> web.StreamResponse:
    """Reject unsafe cookie-session requests missing a valid CSRF token,
    and (re)issue the CSRF cookie whenever it's missing or stale.
    """
    if (
        ENABLE_CSRF_PROTECTION
        and request.method in UNSAFE_METHODS
        and _is_cookie_only_session(request)
        and not _valid_csrf_request(request, request.get(SESSION_ID))
    ):
        raise web.HTTPForbidden(reason="Missing or invalid CSRF token")

    response = await handler(request)

    if ENABLE_CSRF_PROTECTION and response is not None and _is_cookie_only_session(request):
        session_id = request.get(SESSION_ID)
        if session_id:
            current = request.cookies.get(CSRF_COOKIE_NAME)
            if not current or not verify_csrf_token(SECRET_KEY, session_id, current):
                token = generate_csrf_token(SECRET_KEY, session_id)
                response.set_cookie(
                    CSRF_COOKIE_NAME,
                    token,
                    max_age=CSRF_COOKIE_MAX_AGE,
                    httponly=False,
                    secure=(PREFERRED_AUTH_SCHEME == "https"),
                    samesite="Lax",
                    path="/",
                )

    return response
