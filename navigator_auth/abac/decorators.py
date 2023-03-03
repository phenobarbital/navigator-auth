from functools import wraps
from typing import Any, TypeVar
from collections.abc import Callable
from aiohttp import web, hdrs
from aiohttp.abc import AbstractView
from navigator_session import get_session
from navigator_auth.conf import AUTH_SESSION_OBJECT

F = TypeVar("F", bound=Callable[..., Any])

def groups_protected(groups: list, content_type: str = "application/json") -> Callable:
    """Restrict the Handler only to certain Groups in User information."""

    def _wrapper(handler: F):
        @wraps(handler)
        async def _wrap(*args, **kwargs) -> web.StreamResponse:
            # Supports class based views see web.View
            if isinstance(args[0], AbstractView):
                request = args[0].request
            else:
                request = args[-1]
            if request is None:
                raise ValueError(
                    f"web.Request was not found in arguments. {handler!s}"
                )
            if request.get("authenticated", False) is False:
                # check credentials:
                raise web.HTTPUnauthorized(
                    reason="Access Denied",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                )
            else:
                session = await get_session(request)
                member = False
                try:
                    userinfo = session[AUTH_SESSION_OBJECT]
                except KeyError:
                    member = False
                if "groups" in userinfo:
                    member = bool(not set(userinfo["groups"]).isdisjoint(groups))
                else:
                    user = session.decode("user")
                    for group in user.groups:
                        if group.group in groups:
                            member = True
                if member is True:
                    ## Check Groups belong to User
                    return await handler(*args, **kwargs)
                else:
                    raise web.HTTPUnauthorized(
                        reason="Access Denied",
                        headers={
                            hdrs.CONTENT_TYPE: content_type,
                            hdrs.CONNECTION: "keep-alive",
                        },
                    )

        return _wrap
    return _wrapper
