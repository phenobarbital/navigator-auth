from collections.abc import Awaitable, Callable
from aiohttp import web, hdrs
from aiohttp.web_urldispatcher import SystemRoute
from navconfig.logging import logging
from navigator_auth.conf import exclude_list


exceptions = (
    "/api/v1/abac/authorize",
    "/api/v1/abac/is_allowed",
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
    ### get Guardian:
    try:
        guardian = request.app['security']
        response = await guardian.authorize(request=request)
        logging.info(
            f"Access based on Authorize response: {response!r}"
        )
    except (TypeError, KeyError) as ex:
        print(ex)
        ### there is no ABAC access backend enabled:
        logging.warning(
            'ABAC Warning: there is no backend installed on this system.'
        )
    return await handler(request)
