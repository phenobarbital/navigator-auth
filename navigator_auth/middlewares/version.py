import socket
from collections.abc import Callable, Awaitable
from aiohttp import web
from aiohttp.web import middleware
from ..conf import (
    ENABLE_VERSION_HEADERS,
    APP_VERSION,
    GIT_SHA,
)

# Resolve the hostname once at import time (it does not change per-request).
HOSTNAME = socket.gethostname()


@middleware
async def version_middleware(
    request: web.Request,
    handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
) -> web.StreamResponse:
    """
    Version Headers Middleware.
    Description: Adds deployment/version metadata headers to every response
    (application version, git SHA and serving hostname).
    """
    response = await handler(request)
    if response is None:
        return response
    if ENABLE_VERSION_HEADERS is True:
        response.headers['X-App-Version'] = APP_VERSION
        response.headers['X-Git-SHA'] = GIT_SHA
        response.headers['X-Hostname'] = HOSTNAME
    return response
