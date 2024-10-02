from functools import wraps
import inspect
from typing import Any, TypeVar, Union
from collections.abc import Callable, Awaitable
from aiohttp import web, hdrs
from aiohttp.abc import AbstractView
from navigator_session import get_session
from .exceptions import AuthException
from .conf import AUTH_SESSION_OBJECT


F = TypeVar("F", bound=Callable[..., Any])

def get_auth(app) -> Awaitable:
    try:
        return app["auth"]
    except KeyError as ex:
        raise web.HTTPBadRequest(
            reason="Authentication Backend is not enabled.",
            headers={
                hdrs.CONTENT_TYPE: 'application/json',
                hdrs.CONNECTION: "keep-alive",
            },
        ) from ex

def user_session() -> Callable[[F], F]:
    """Decorator for getting User in the request."""

    def _wrapper(handler: F):
        if inspect.isclass(handler):
            # We are decorating a class-based view
            for method_name in hdrs.METH_ALL:
                method = getattr(handler, method_name.lower(), None)
                if method is not None and callable(method):
                    # Wrap the method
                    setattr(
                        handler,
                        method_name.lower(),
                        _wrap_method(method)
                    )
            return handler
        else:
            # We are decorating a function handler
            @wraps(handler)
            async def _wrap(*args, **kwargs) -> web.StreamResponse:
                # Get the request object
                request = args[0] if isinstance(args[0], web.Request) else args[-1]
                session = await get_session(request, new=False)
                try:
                    user = session.decode("user")
                except (AttributeError, TypeError, RuntimeError):
                    user = None
                request['session'] = session
                request['user'] = user
                args[0].user = user
                args[0].session = session
                return await handler(*args, session, user, **kwargs)
            return _wrap

    def _wrap_method(method):
        @wraps(method)
        async def wrapped_method(self, *args, **kwargs):
            request = self.request
            session = await get_session(request, new=False)
            try:
                user = session.decode("user")
            except (AttributeError, TypeError, RuntimeError):
                user = None
            # Attach session and user to self
            self.session = session
            self.user = user
            # also, added to request:
            request.session = session
            request.user = user
            return await method(self, *args, **kwargs)
        return wrapped_method

    return _wrapper


def is_authenticated(content_type: str = "application/json") -> Callable:
    """Decorator to check if a user has been authenticated for this request."""

    def _wrapper(handler):
        if inspect.isclass(handler):
            # We are decorating a class
            for method_name in hdrs.METH_ALL:
                method = getattr(handler, method_name.lower(), None)
                if method is not None and callable(method):
                    # Wrap the method
                    setattr(
                        handler,
                        method_name.lower(),
                        _wrap_method(method)
                    )
            return handler
        else:
            # We are decorating a function
            @wraps(handler)
            async def _wrap(*args, **kwargs) -> web.StreamResponse:
                request = args[-1]
                if request is None or not isinstance(request, web.Request):
                    raise ValueError(
                        f"web.Request was not found in arguments. {handler!s}"
                    )
                if request.get("authenticated", False) is True:
                    # Already authenticated
                    return await handler(*args, **kwargs)
                else:
                    app = request.app
                    auth = get_auth(app)
                    userdata = None
                    for _, backend in auth.backends.items():
                        try:
                            userdata = await backend.authenticate(request)
                            if userdata:
                                break
                        except AuthException:
                            pass
                    if userdata:
                        return await handler(*args, **kwargs)
                    else:
                        # Credentials check failed
                        raise web.HTTPUnauthorized(
                            reason="Access Denied",
                            headers={
                                hdrs.CONTENT_TYPE: content_type,
                                hdrs.CONNECTION: "keep-alive",
                            },
                        )
            return _wrap

    def _wrap_method(method):
        @wraps(method)
        async def wrapped_method(self, *args, **kwargs):
            request = self.request
            if request.get("authenticated", False):
                return await method(self, *args, **kwargs)
            app = request.app
            auth = get_auth(app)
            userdata = None
            for _, backend in auth.backends.items():
                try:
                    userdata = await backend.authenticate(request)
                    if userdata:
                        break
                except AuthException:
                    pass
            if userdata:
                return await method(*args, **kwargs)
            else:
                # Credentials check failed
                raise web.HTTPUnauthorized(
                    reason="Access Denied",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                )
        return wrapped_method

    return _wrapper


def allowed_groups(groups: list, content_type: str = "application/json") -> Callable:
    """Restrict the Handler only to certain Groups in User information."""

    def _wrapper(handler: F):
        @wraps(handler)
        async def _wrap(*args, **kwargs) -> web.StreamResponse:
            # Supports class based views see web.View
            if inspect.isclass(handler) and issubclass(handler, AbstractView):
                request = args[0]
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


def allowed_programs(
    programs: list, content_type: str = "application/json"
) -> Callable:
    """Restrict the Handler only to certain Programs in User information."""

    def _wrapper(handler: F):
        @wraps(handler)
        async def _wrap(*args, **kwargs) -> web.StreamResponse:
            # Supports class based views see web.View
            if inspect.isclass(handler) and issubclass(handler, AbstractView):
                request = args[0]
            else:
                request = args[-1]
            if request is None:
                raise ValueError(f"web.Request was not found in arguments. {handler!s}")
            if request.get("authenticated", False) is False:
                # check credentials:
                raise web.HTTPUnauthorized(
                    reason=f"Access Denied to Handler {handler!s}",
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
                if "programs" in userinfo:
                    member = bool(not set(userinfo["programs"]).isdisjoint(programs))
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


def allowed_organizations(
    org: list, content_type: str = "application/json"
) -> Callable:
    """Restrict the Handler only to certain Programs in User information."""

    def _wrapper(handler: F):
        @wraps(handler)
        async def _wrap(*args, **kwargs) -> web.StreamResponse:
            # Supports class based views see web.View
            if inspect.isclass(handler) and issubclass(handler, AbstractView):
                request = args[0]
            else:
                request = args[-1]
            if request is None:
                raise ValueError(f"web.Request was not found in arguments. {handler!s}")
            if request.get("authenticated", False) is False:
                # check credentials:
                raise web.HTTPUnauthorized(
                    reason=f"Access Denied to Handler {handler!s}",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                )
            else:
                session = await get_session(request)
                member = False
                try:
                    user = session.decode("user")
                    for o in user.organizations:
                        if o.organization in org:
                            member = True
                except (AttributeError, TypeError, RuntimeError):
                    member = False
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


def apikey_required(content_type: str = "application/json") -> Callable:
    """Allow only API Keys on Request."""

    def _wrapper(handler: F):
        @wraps(handler)
        async def _wrap(*args, **kwargs) -> web.StreamResponse:
            # Supports class based views see web.View
            if inspect.isclass(handler) and issubclass(handler, AbstractView):
                request = args[0]
            else:
                request = args[-1]
            if request is None:
                raise ValueError(f"web.Request was not found in arguments. {handler!s}")
            ###
            app = request.app
            try:
                auth = app["auth"]
            except KeyError as ex:
                raise web.HTTPBadRequest(
                    reason="Auth is required",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                ) from ex
            userdata = None
            try:
                backend = auth.backends["APIKeyAuth"]
                if userdata := await backend.authenticate(request):
                    request["userdata"] = userdata
                    return await handler(*args, **kwargs)
                else:
                    raise web.HTTPUnauthorized(
                        reason="Unauthorized: Access Denied to this resource.",
                        headers={
                            hdrs.CONTENT_TYPE: content_type,
                            hdrs.CONNECTION: "keep-alive",
                        },
                    )
            except KeyError as ex:
                raise web.HTTPBadRequest(
                    reason="API Key Backend Auth is not enabled.",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                ) from ex

        return _wrap

    return _wrapper
