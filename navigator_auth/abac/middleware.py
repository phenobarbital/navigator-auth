from collections.abc import Awaitable, Callable
from aiohttp import web, hdrs
from aiohttp.web_urldispatcher import SystemRoute
from navconfig.logging import logging
from navigator_auth.conf import exclude_list


exceptions = (
    "/api/v1/abac/authorize",
    "/api/v1/abac/is_allowed",
    "/api/v1/abac/reload"
)

@web.middleware
async def abac_middleware(
    request: web.Request,
    handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
) -> web.StreamResponse:
    """
    Basic AUthorizacion/Access Middleware.
    Description: Authorization/Access Middleware for ABAC
    """
    # avoid authorization backend on excluded methods:
    if request.method == hdrs.METH_OPTIONS:
        return await handler(request)
    # avoid check system routes
    try:
        if isinstance(request.match_info.route, SystemRoute):  # eg. 404
            return await handler(request)
    except Exception:  # pylint: disable=W0703
        pass
    # avoid authorization on exclude list
    if request.path in exclude_list:
        return await handler(request)
    if request.path in exceptions:
        return await handler(request)
    logging.debug(' == ABAC MIDDLEWARE == ')
    ### verify if request is authenticated
    if request.get('authenticated', False) is False:
        logging.warning(f'Access to {request.path} is not Authenticated.')
        return await handler(request)
    ### get Guardian:
    try:
        response = await request.app['security'].authorize(request=request)
    except (TypeError, KeyError) as ex:
        ### there is no ABAC access backend enabled:
        logging.warning(
            f'ABAC Warning: there is no backend installed on this system: {ex}'
        )
    return await handler(request)
