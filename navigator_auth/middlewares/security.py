from collections.abc import Callable, Awaitable
from aiohttp import web
from aiohttp.web import middleware
from ..conf import (
    ENABLE_XFRAME_OPTIONS,
    XFRAME_OPTIONS,
    ENABLE_XREFERER_POLICY,
    XREFERER_POLICY,
    XCONTENT_TYPE_OPTIONS,
    XSS_PROTECTION,
    ENABLE_XSS_PROTECTION,
    HSTS_MAX_AGE,
    STRICT_INCLUDE_SUBDOMAINS
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
    if ENABLE_XSS_PROTECTION is True:
        response.headers['X-XSS-Protection'] = XSS_PROTECTION
    response.headers['X-Content-Type-Options'] = XCONTENT_TYPE_OPTIONS
    if ENABLE_XFRAME_OPTIONS is True:
        response.headers['X-Frame-Options'] = XFRAME_OPTIONS
    if ENABLE_XREFERER_POLICY is True:
        response.headers['Referrer-Policy'] = XREFERER_POLICY
    # Add the Strict-Transport-Security header
    if request.scheme == 'https':  # Only set HSTS over HTTPS
        age_string = f"max-age={HSTS_MAX_AGE};"
        if STRICT_INCLUDE_SUBDOMAINS is True:
            age_string += '; includeSubDomains'
        age_string += '; preload'
        response.headers['Strict-Transport-Security'] = age_string

    return response
