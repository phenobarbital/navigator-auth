from functools import wraps
import inspect
from typing import Any, TypeVar, Union
from collections.abc import Callable, Awaitable
from aiohttp import web, hdrs
from aiohttp.abc import AbstractView
from navigator_session import get_session
from .exceptions import AuthException
from .conf import AUTH_SESSION_OBJECT, exclude_list


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

def _apply_decorator(handler, func_wrapper, method_wrapper):
    """
    Apply the wrapper either to a function-based handler or to each method
    of a class-based view.
    """
    if not inspect.isclass(handler):
        return func_wrapper(handler)
    if inspect.isclass(handler):
        # For class-based views, wrap each HTTP method.
        for method_name in hdrs.METH_ALL:
            method = getattr(handler, method_name.lower(), None)
            if method is not None and callable(method):
                setattr(handler, method_name.lower(), method_wrapper(method))
        return handler

def allow_anonymous(handler: F) -> F:
    """
    Marks a handler or view as allowing anonymous access, bypassing authentication.
    This decorator adds the request path to the exclude list so that authentication
    is not required for this endpoint.

    Args:
        func: The handler function or class-based view to decorate.

    Returns:
        Callable: The decorated handler that allows anonymous access.
    """
    def _func_wrapper(handler):
        @wraps(handler)
        async def _wrap(*args, **kwargs) -> web.StreamResponse:
            request = args[0] if isinstance(args[0], web.Request) else args[-1]
            if request is not None:
                setattr(request, "allow_anonymous", True)
            return await handler(*args, **kwargs)
        return _wrap

    def _method_wrapper(method):
        @wraps(method)
        async def wrapped_method(self, *args, **kwargs):
            request = self.request
            if request is not None:
                setattr(request, "allow_anonymous", True)
            return await method(self, *args, **kwargs)
        return wrapped_method

    return lambda handler: _apply_decorator(handler, _func_wrapper, _method_wrapper)

def user_session() -> Callable[[F], F]:
    """Decorator for attaching a User from session to the request and view instance."""

    def _func_wrapper(handler):
        @wraps(handler)
        async def _wrap(*args, **kwargs) -> web.StreamResponse:
            request = args[0] if isinstance(args[0], web.Request) else args[-1]
            session = await get_session(request, new=False)
            try:
                user = session.decode("user")
            except (AttributeError, TypeError, RuntimeError):
                user = None
            if not user and request.get("user"):
                user = request.get("user")
            request["session"] = session
            if hasattr(args[0], "session"):
                args[0].session = session
                args[0].user = user
            return await handler(*args, session=session, user=user, **kwargs)
        return _wrap

    def _method_wrapper(method):
        @wraps(method)
        async def wrapped_method(self, *args, **kwargs):
            request = self.request
            session = await get_session(request, new=False)
            try:
                user = session.decode("user")
            except (AttributeError, TypeError, RuntimeError):
                user = None
            # Use middleware-attached user if available.
            if not user and hasattr(request, "user") and request.user is not None:
                user = request.user
            # Attach session and user to both the view and request.
            self.session = session
            self.user = user
            request.session = session
            request.user = user
            return await method(self, *args, **kwargs)
        return wrapped_method

    return lambda handler: _apply_decorator(handler, _func_wrapper, _method_wrapper)


def is_authenticated(content_type: str = "application/json") -> Callable[[F], F]:
    """
    Checks if a user is authenticated before allowing access to the handler.
    This decorator ensures that only authenticated users can access the handler,
    attempting authentication with available backends if necessary.

    Args:
        content_type: The content type to use in HTTP responses
        (default is "application/json").

    Returns:
        Callable: A decorator that wraps the handler to enforce authentication.

    Raises:
        web.HTTPUnauthorized: If the user is not authenticated and authentication fails.
        ValueError: If a web.Request object is not found in the handler arguments.
    """

    def _func_wrapper(handler):
        @wraps(handler)
        async def _wrap(*args, **kwargs) -> web.StreamResponse:
            request = args[-1]
            if request is None or not isinstance(request, web.Request):
                raise ValueError(f"web.Request was not found in arguments. {handler!s}")
            if request.get("authenticated", False):
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
                    raise web.HTTPUnauthorized(
                        reason="Access Denied",
                        headers={
                            hdrs.CONTENT_TYPE: content_type,
                            hdrs.CONNECTION: "keep-alive",
                        },
                    )
        return _wrap

    def _method_wrapper(method):
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
                return await method(self, *args, **kwargs)
            else:
                raise web.HTTPUnauthorized(
                    reason="Access Denied",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                )
        return wrapped_method

    return lambda handler: _apply_decorator(handler, _func_wrapper, _method_wrapper)


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

    def _wrap_function(handler):
        @wraps(handler)
        async def _wrapped(*args, **kwargs) -> web.StreamResponse:
            # For function-based handlers, assume request is the last argument.
            request = args[-1]
            if request is None:
                raise ValueError(f"web.Request was not found in arguments. {handler!s}")
            if not request.get("authenticated", False):
                raise web.HTTPUnauthorized(
                    reason=f"Access Denied to Handler {handler!s}",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                )
            session = await get_session(request)
            try:
                userinfo = session[AUTH_SESSION_OBJECT]
            except KeyError:
                userinfo = {}
            # Check if any allowed program appears in the userinfo programs
            member = "programs" in userinfo and bool(
                not set(userinfo["programs"]).isdisjoint(programs)
            )
            if member:
                return await handler(*args, **kwargs)
            else:
                raise web.HTTPUnauthorized(
                    reason="Access Denied",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                )
        return _wrapped

    def _wrap_method(method):
        @wraps(method)
        async def _wrapped(self, *args, **kwargs) -> web.StreamResponse:
            request = self.request
            if request is None:
                raise ValueError(f"web.Request was not found in arguments. {method!s}")
            if not request.get("authenticated", False):
                raise web.HTTPUnauthorized(
                    reason=f"Access Denied to Handler {method!s}",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                )
            session = await get_session(request)
            try:
                userinfo = session[AUTH_SESSION_OBJECT]
            except KeyError:
                userinfo = {}
            member = "programs" in userinfo and bool(
                not set(userinfo["programs"]).isdisjoint(programs)
            )
            if member:
                return await method(self, *args, **kwargs)
            else:
                raise web.HTTPUnauthorized(
                    reason="Access Denied",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                )
        return _wrapped

    def _wrapper(handler: F):
        # If it's a class-based view (a subclass of AbstractView), wrap each HTTP method.
        if inspect.isclass(handler) and issubclass(handler, AbstractView):
            for method_name in hdrs.METH_ALL:
                method = getattr(handler, method_name.lower(), None)
                if method is not None and callable(method):
                    wrapped_method = _wrap_method(method)
                    setattr(handler, method_name.lower(), wrapped_method)
            return handler
        else:
            # Otherwise, assume it's a function-based view.
            return _wrap_function(handler)

    return _wrapper


def apikey_required(content_type: str = "application/json") -> Callable:
    """Allow only API Keys on Request."""

    def _wrap_function(handler):
        @wraps(handler)
        async def _wrapped(*args, **kwargs) -> web.StreamResponse:
            # For function-based views, assume request is the last argument.
            request = args[-1]
            if request is None:
                raise ValueError(f"web.Request was not found in arguments. {handler!s}")
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
        return _wrapped

    def _wrap_method(method):
        @wraps(method)
        async def _wrapped(self, *args, **kwargs) -> web.StreamResponse:
            request = self.request
            if request is None:
                raise ValueError(f"web.Request was not found in arguments. {method!s}")
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
            try:
                backend = auth.backends["APIKeyAuth"]
                if userdata := await backend.authenticate(request):
                    request["userdata"] = userdata
                    return await method(self, *args, **kwargs)
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
        return _wrapped

    def _wrapper(handler: F):
        # If it's a class-based view, wrap all HTTP methods.
        if inspect.isclass(handler) and issubclass(handler, AbstractView):
            for method_name in hdrs.METH_ALL:
                method = getattr(handler, method_name.lower(), None)
                if method is not None and callable(method):
                    wrapped_method = _wrap_method(method)
                    setattr(handler, method_name.lower(), wrapped_method)
            return handler
        else:
            return _wrap_function(handler)

    return _wrapper

def allowed_organizations(
    org: list, content_type: str = "application/json"
) -> Callable:
    """Restrict the Handler only to certain organizations in User information."""

    def _wrap_function(handler):
        @wraps(handler)
        async def _wrapped(*args, **kwargs) -> web.StreamResponse:
            # For function-based handlers, assume request is the last argument.
            request = args[-1]
            if request is None:
                raise ValueError(f"web.Request was not found in arguments. {handler!s}")
            if not request.get("authenticated", False):
                raise web.HTTPUnauthorized(
                    reason=f"Access Denied to Handler {handler!s}",
                    headers={hdrs.CONTENT_TYPE: content_type, hdrs.CONNECTION: "keep-alive"},
                )
            session = await get_session(request)
            member = False
            try:
                user = session.decode("user")
                for o in user.organizations:
                    if o.organization in org:
                        member = True
                        break
            except (AttributeError, TypeError, RuntimeError):
                member = False
            if member:
                return await handler(*args, **kwargs)
            else:
                raise web.HTTPUnauthorized(
                    reason="Access Denied",
                    headers={hdrs.CONTENT_TYPE: content_type, hdrs.CONNECTION: "keep-alive"},
                )
        return _wrapped

    def _wrap_method(method):
        @wraps(method)
        async def _wrapped(self, *args, **kwargs) -> web.StreamResponse:
            # For class-based views, use self.request.
            request = self.request
            if request is None:
                raise ValueError(f"web.Request was not found in arguments. {method!s}")
            if not request.get("authenticated", False):
                raise web.HTTPUnauthorized(
                    reason=f"Access Denied to Handler {method!s}",
                    headers={hdrs.CONTENT_TYPE: content_type, hdrs.CONNECTION: "keep-alive"},
                )
            session = await get_session(request)
            member = False
            try:
                user = session.decode("user")
                for o in user.organizations:
                    if o.organization in org:
                        member = True
                        break
            except (AttributeError, TypeError, RuntimeError):
                member = False
            if member:
                return await method(self, *args, **kwargs)
            else:
                raise web.HTTPUnauthorized(
                    reason="Access Denied",
                    headers={hdrs.CONTENT_TYPE: content_type, hdrs.CONNECTION: "keep-alive"},
                )
        return _wrapped

    def _wrapper(handler: F):
        # If the handler is a class-based view (subclass of AbstractView), wrap each HTTP method.
        if inspect.isclass(handler) and issubclass(handler, AbstractView):
            for method_name in hdrs.METH_ALL:
                method = getattr(handler, method_name.lower(), None)
                if method is not None and callable(method):
                    setattr(handler, method_name.lower(), _wrap_method(method))
            return handler
        else:
            return _wrap_function(handler)

    return _wrapper
