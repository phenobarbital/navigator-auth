"""Sanitize auth-related query parameters from request URLs."""
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
