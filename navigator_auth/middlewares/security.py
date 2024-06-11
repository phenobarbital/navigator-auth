from collections.abc import Callable, Awaitable
from aiohttp import web
from aiohttp.web import middleware
from ..conf import (
    XFRAME_OPTIONS,
    XREFERER_POLICY,
    XCONTENT_TYPE_OPTIONS
)


@middleware
async def security_middleware(
    request: web.Request,
    handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
) -> web.StreamResponse:
    """
    Basic Security Response Middleware.
    Description: This middleware adds security headers to the response.
    """
    response = await handler(request)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = XCONTENT_TYPE_OPTIONS
    response.headers['X-Frame-Options'] = XFRAME_OPTIONS
    response.headers['Referrer-Policy'] = XREFERER_POLICY
    # Add the Strict-Transport-Security header
    if request.scheme == 'https':  # Only set HSTS over HTTPS
        age = 'max-age=31536000; includeSubDomains'
        response.headers['Strict-Transport-Security'] = age

    return response
