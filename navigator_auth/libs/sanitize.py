"""Sanitize auth-related query parameters from request URLs, and
arbitrary values destined for HTTP response headers."""
import re
from typing import Any

from aiohttp import web

AUTH_QUERY_PARAMS = frozenset({
    "apikey",
    "api_key",
    "auth",
    "access_token",
})


def sanitize_request(
    request: web.Request,
    params: frozenset[str] = AUTH_QUERY_PARAMS,
) -> web.Request:
    """Strip auth-related query parameters from the request URL.

    Returns a cloned request with sensitive params removed so they
    don't leak to downstream handlers. If no params need stripping,
    returns the original request unchanged.
    """
    query = request.rel_url.query
    if not any(p in query for p in params):
        return request
    clean_query = {k: v for k, v in query.items() if k not in params}
    clean_url = request.rel_url.with_query(clean_query)
    new_request = request.clone(rel_url=clean_url)
    if hasattr(request, "user"):
        new_request.user = request.user
    return new_request


#: Characters forbidden in an HTTP header value (RFC 9110 section 5.5):
#: CR, LF, NUL and the remaining C0 and C1 control ranges.
HEADER_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def header_safe(value: Any, max_length: int = 256) -> str:
    """Make an arbitrary value safe to use as an HTTP header value.

    Collapses CR/LF/NUL and every other C0/C1 control character to a single
    space, collapses runs of whitespace, strips the result, and truncates it
    to ``max_length`` characters. Always returns a ``str``; ``None`` and
    non-string values are coerced via ``str()`` first (``None`` -> ``""``).

    This is the last line of defence against header injection — it must be
    applied to every header value derived from a request, a provider
    response, or an exception message.

    Args:
        value: The untrusted value destined for a header.
        max_length: Maximum length of the returned string.

    Returns:
        A single-line, control-character-free string.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = HEADER_FORBIDDEN.sub(" ", text)
    text = " ".join(text.split())
    return text[:max_length].strip()
