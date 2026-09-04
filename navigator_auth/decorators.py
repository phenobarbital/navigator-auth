from functools import wraps
import fnmatch
import inspect
from typing import Any, Optional, TypeVar, Union
from collections.abc import Callable, Awaitable
from aiohttp import web, hdrs
from aiohttp.abc import AbstractView
from navigator_session import get_session
from navconfig.logging import logger
from .exceptions import AuthException
from .conf import AUTH_SESSION_OBJECT, AUTH_EXCLUDE_LIST_KEY
from .vault.integration import _attach_vault_to_request


def _is_path_excluded(request: web.Request) -> bool:
    """Return True if the request path is in the per-app auth exclude list.

    Uses the same fnmatch semantics as AuthHandler.verify_exceptions so that
    glob patterns (e.g. ``/api/v1/forms/*/render/*``) match correctly.

    Args:
        request: The incoming HTTP request.

    Returns:
        True if the path matches any pattern in ``app[AUTH_EXCLUDE_LIST_KEY]``,
        False otherwise (including when the key is not present).
    """
    exclude_list = request.app.get(AUTH_EXCLUDE_LIST_KEY, [])
    return any(fnmatch.fnmatch(request.path, pattern) for pattern in exclude_list)


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

def allow_anonymous(handler: F = None) -> F:
    """
    Marks a handler or view as allowing anonymous access, bypassing authentication.
    The decorated handler flags the request with ``allow_anonymous``, which
    ``@is_authenticated()`` and ``AuthHandler.verify_exceptions()`` honour, so
    no authentication is required for this endpoint.

    Usable both bare and called, as the sibling decorators in this module are
    factories and the parenthesised form is an easy mistake to make::

        @allow_anonymous
        async def public(request): ...

        @allow_anonymous()
        async def also_public(request): ...

    Args:
        handler: The handler function or class-based view to decorate. When
            omitted (``@allow_anonymous()``) the decorator itself is returned.

    Returns:
        Callable: The decorated handler that allows anonymous access, or the
        decorator when used as a factory.
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

    def _decorate(handler: F) -> F:
        return _apply_decorator(handler, _func_wrapper, _method_wrapper)

    # bare usage (@allow_anonymous) decorates now; factory usage
    # (@allow_anonymous()) gets the decorator back to apply itself.
    return _decorate if handler is None else _decorate(handler)

def user_session() -> Callable[[F], F]:
    """Decorator for attaching a User from session to the request and view instance."""

    def _func_wrapper(handler):
        @wraps(handler)
        async def _wrap(*args, **kwargs) -> web.StreamResponse:
            request = args[0] if isinstance(args[0], web.Request) else args[-1]
            # avoid check on OPTION method:
            if request.method == hdrs.METH_OPTIONS:
                return await handler(*args, **kwargs)
            session = await get_session(request, new=False)
            try:
                user = session.decode("user")
            except (AttributeError, TypeError, RuntimeError):
                user = None
            if not user and request.get("user"):
                user = request.get("user")
            # Use middleware-attached user if available.
            if not user and hasattr(request, "user") and request.user is not None:
                user = request.user
            request["session"] = session
            _attach_vault_to_request(request, session)
            # Attach session and user to the request, as _method_wrapper does;
            # a middleware-attached user must never be replaced with None.
            request.session = session
            if user is not None:
                request.user = user
            if args[0] is not request and hasattr(args[0], "session"):
                args[0].session = session
                args[0].user = user
            return await handler(*args, session=session, user=user, **kwargs)
        return _wrap

    def _method_wrapper(method):
        @wraps(method)
        async def wrapped_method(self, *args, **kwargs):
            request = self.request
            # avoid check on OPTION method:
            if request.method == hdrs.METH_OPTIONS:
                return await method(self, *args, **kwargs)
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
            _attach_vault_to_request(request, session)
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
            # avoid check on OPTION method:
            if request.method == hdrs.METH_OPTIONS:
                return await handler(*args, **kwargs)
            # Short-circuit for explicitly excluded paths (public form URLs etc.)
            if _is_path_excluded(request) or getattr(request, "allow_anonymous", False):
                return await handler(*args, **kwargs)
            if request.get("authenticated", False):
                return await handler(*args, **kwargs)
            else:
                app = request.app
                auth = get_auth(app)
                userdata = None
                for _, backend in auth.backends.items():
                    try:
                        result = await backend.authenticate(request)
                    except AuthException:
                        continue
                    if not result:
                        continue
                    if isinstance(result, web.StreamResponse):
                        # External backends answer an unauthenticated request
                        # with a redirect to their IdP: that is the start of an
                        # interactive login, not a credential. Never let it pass
                        # as "authenticated" (the handler would then run with no
                        # user at all); try the next backend instead.
                        continue
                    userdata = result
                    break
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
            # avoid check on OPTION method:
            if request.method == hdrs.METH_OPTIONS:
                return await method(self, *args, **kwargs)
            # Short-circuit for explicitly excluded paths (public form URLs etc.)
            if _is_path_excluded(request) or getattr(request, "allow_anonymous", False):
                return await method(self, *args, **kwargs)
            if request.get("authenticated", False):
                return await method(self, *args, **kwargs)
            app = request.app
            auth = get_auth(app)
            userdata = None
            for _, backend in auth.backends.items():
                try:
                    result = await backend.authenticate(request)
                except AuthException:
                    continue
                if not result:
                    continue
                if isinstance(result, web.StreamResponse):
                    # a redirect to an external IdP is not a credential:
                    # see the note in the function-based wrapper above.
                    continue
                userdata = result
                break
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


SUPERUSER_GROUP = "superuser"


def _check_superuser(userinfo: dict, user: object = None) -> bool:
    """Return True if the user has superuser privileges.

    Checks ``userinfo["superuser"]`` first, then falls back to group
    membership (either ``userinfo["groups"]`` or ``user.groups``).
    """
    if userinfo.get("superuser") is True or userinfo.get("is_superuser") is True:
        return True
    groups = userinfo.get("groups")
    # Membership only on a real collection: `in` on a str is SUBSTRING
    # matching, so an unguarded test would grant superuser to any value
    # merely containing the word (e.g. groups="ex_superuser_revoked"),
    # and raise TypeError on groups=None.
    if isinstance(groups, (list, tuple, set, frozenset)):
        if SUPERUSER_GROUP in groups:
            return True
    if user is not None and hasattr(user, "groups"):
        for g in user.groups:
            name = getattr(g, "group", None) or getattr(g, "group_name", None)
            if name == SUPERUSER_GROUP:
                return True
    return False


def is_superuser(content_type: str = "application/json") -> Callable:
    """Restrict the handler to superusers only.

    A user is considered a superuser when ``userinfo["superuser"]`` (or
    ``is_superuser``) is True **or** the user belongs to the ``superuser``
    group.
    """

    def _wrap_function(handler):
        @wraps(handler)
        async def _wrapped(*args, **kwargs) -> web.StreamResponse:
            request = args[-1]
            if request is None:
                raise ValueError(f"web.Request was not found in arguments. {handler!s}")
            if request.method == hdrs.METH_OPTIONS:
                return await handler(*args, **kwargs)
            if not request.get("authenticated", False):
                raise web.HTTPUnauthorized(
                    reason="Access Denied",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                )
            session = await get_session(request)
            userinfo = {}
            user = None
            try:
                userinfo = session[AUTH_SESSION_OBJECT]
            except KeyError:
                pass
            try:
                user = session.decode("user")
            except (AttributeError, TypeError, RuntimeError):
                pass
            if _check_superuser(userinfo, user):
                return await handler(*args, **kwargs)
            raise web.HTTPForbidden(
                reason="Superuser privileges required",
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
            if request.method == hdrs.METH_OPTIONS:
                return await method(self, *args, **kwargs)
            if not request.get("authenticated", False):
                raise web.HTTPUnauthorized(
                    reason="Access Denied",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                )
            session = await get_session(request)
            userinfo = {}
            user = None
            try:
                userinfo = session[AUTH_SESSION_OBJECT]
            except KeyError:
                pass
            try:
                user = session.decode("user")
            except (AttributeError, TypeError, RuntimeError):
                pass
            if _check_superuser(userinfo, user):
                return await method(self, *args, **kwargs)
            raise web.HTTPForbidden(
                reason="Superuser privileges required",
                headers={
                    hdrs.CONTENT_TYPE: content_type,
                    hdrs.CONNECTION: "keep-alive",
                },
            )
        return _wrapped

    def _wrapper(handler: F):
        if inspect.isclass(handler) and issubclass(handler, AbstractView):
            for method_name in hdrs.METH_ALL:
                method = getattr(handler, method_name.lower(), None)
                if method is not None and callable(method):
                    setattr(handler, method_name.lower(), _wrap_method(method))
            return handler
        else:
            return _wrap_function(handler)

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
            # avoid check on OPTION method:
            if request.method == hdrs.METH_OPTIONS:
                return await handler(*args, **kwargs)
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
                    # `userinfo` must be bound: the check below dereferences it,
                    # and an unbound name here turned a missing session object
                    # into an UnboundLocalError (500) instead of a clean deny.
                    userinfo = {}
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
            # avoid check on OPTION method:
            if request.method == hdrs.METH_OPTIONS:
                return await handler(*args, **kwargs)
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
            # avoid check on OPTION method:
            if request.method == hdrs.METH_OPTIONS:
                return await method(self, *args, **kwargs)
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
            # avoid check on OPTION method:
            if request.method == hdrs.METH_OPTIONS:
                return await handler(*args, **kwargs)
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
            # avoid check on OPTION method:
            if request.method == hdrs.METH_OPTIONS:
                return await method(self, *args, **kwargs)
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
            # avoid check on OPTION method:
            if request.method == hdrs.METH_OPTIONS:
                return await handler(*args, **kwargs)
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
            # avoid check on OPTION method:
            if request.method == hdrs.METH_OPTIONS:
                return await method(self, *args, **kwargs)
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


def is_restricted(
    users: list = None, groups: list = None, content_type: str = "application/json"
) -> Callable:
    """
    Restrict access to specific Users or Groups.
    Logic:
      - If 'users' is provided, current user MUST be in the list.
      - If 'groups' is provided, current user MUST have at least one group in the list.
      - If both are provided, BOTH conditions must be met (Intersection).
    """
    def _wrap_function(handler):
        @wraps(handler)
        async def _wrapped(*args, **kwargs) -> web.StreamResponse:
            # For function-based handlers, assume request is the last argument.
            request = args[-1]
            if request is None:
                raise ValueError(f"web.Request was not found in arguments. {handler!s}")
            # check on OPTION method:
            if request.method == hdrs.METH_OPTIONS:
                return await handler(*args, **kwargs)
            if not request.get("authenticated", False):
                raise web.HTTPUnauthorized(
                    reason=f"Access Denied to Handler {handler!s}",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                )
            # 1. Get Session
            session = await get_session(request)
            # 2. Extract User Info
            username = None
            user_groups = set()
            try:
                # Try getting from cached session dict
                userinfo = session[AUTH_SESSION_OBJECT]
                username = userinfo.get("username")
                if "groups" in userinfo:
                    user_groups = set(userinfo["groups"])
            except KeyError:
                # Fallback to decoding the User object
                try:
                    user = session.decode("user")
                    username = getattr(user, "username", None)
                    if hasattr(user, "groups"):
                        for g in user.groups:
                            if hasattr(g, "group"):
                                user_groups.add(g.group)
                            elif hasattr(g, "group_name"):
                                user_groups.add(g.group_name)
                except (AttributeError, TypeError, RuntimeError):
                    pass
            # 3. Check Constraints
            # User Check
            if users is not None:
                if not username or username not in users:
                    raise web.HTTPUnauthorized(
                        reason="Access Denied",
                        headers={
                            hdrs.CONTENT_TYPE: content_type,
                            hdrs.CONNECTION: "keep-alive",
                        },
                    )
            # Group Check
            if groups is not None:
                # user_groups must have intersection with allowed groups
                if user_groups.isdisjoint(groups):
                    raise web.HTTPUnauthorized(
                        reason="Access Denied",
                        headers={
                            hdrs.CONTENT_TYPE: content_type,
                            hdrs.CONNECTION: "keep-alive",
                        },
                    )
            return await handler(*args, **kwargs)
        return _wrapped

    def _wrap_method(method):
        @wraps(method)
        async def _wrapped(self, *args, **kwargs) -> web.StreamResponse:
            request = self.request
            if request is None:
                raise ValueError(f"web.Request was not found in arguments. {method!s}")
            # check on OPTION method:
            if request.method == hdrs.METH_OPTIONS:
                return await method(self, *args, **kwargs)
            if not request.get("authenticated", False):
                raise web.HTTPUnauthorized(
                    reason=f"Access Denied to Handler {method!s}",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                )
            # 1. Get Session
            session = await get_session(request)
            # 2. Extract User Info
            username = None
            user_groups = set()
            try:
                # Try getting from cached session dict
                userinfo = session[AUTH_SESSION_OBJECT]
                username = userinfo.get("username")
                if "groups" in userinfo:
                    user_groups = set(userinfo["groups"])
            except KeyError:
                # Fallback to decoding the User object
                try:
                    user = session.decode("user")
                    username = getattr(user, "username", None)
                    if hasattr(user, "groups"):
                        for g in user.groups:
                            if hasattr(g, "group"):
                                user_groups.add(g.group)
                            elif hasattr(g, "group_name"):
                                user_groups.add(g.group_name)
                except (AttributeError, TypeError, RuntimeError):
                    pass
            # 3. Check Constraints
            # User Check
            if users is not None:
                if not username or username not in users:
                    raise web.HTTPUnauthorized(
                        reason="Access Denied",
                        headers={
                            hdrs.CONTENT_TYPE: content_type,
                            hdrs.CONNECTION: "keep-alive",
                        },
                    )
            # Group Check
            if groups is not None:
                # user_groups must have intersection with allowed groups
                if user_groups.isdisjoint(groups):
                    raise web.HTTPUnauthorized(
                        reason="Access Denied",
                        headers={
                            hdrs.CONTENT_TYPE: content_type,
                            hdrs.CONNECTION: "keep-alive",
                        },
                    )
            return await method(self, *args, **kwargs)
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


# --------------------------------------------------------------------------
# ABAC: access check against a named Policy.
# --------------------------------------------------------------------------
# NOTE: every ABAC import below is done lazily, inside the functions, because
# ``navigator_auth.abac.decorators`` imports ``_apply_decorator`` from this
# module; importing ABAC at module level would create a circular import.


def _find_request(args: tuple, kwargs: dict) -> Optional[web.Request]:
    """Locate the ``web.Request`` among the arguments of a decorated callable.

    Supports the three call shapes that ``check_access`` must serve:

    * bare function handlers — ``async def handler(request)`` (aiohttp may also
      pass the request in last position),
    * class-based views — ``self`` is an ``AbstractView`` carrying ``.request``,
    * plain class methods — ``self`` exposes a ``request`` attribute.

    Args:
        args: Positional arguments the wrapped callable was called with.
        kwargs: Keyword arguments the wrapped callable was called with.

    Returns:
        The request, or None when no request could be found.
    """
    request = kwargs.get("request")
    if isinstance(request, web.Request):
        return request
    for arg in args:
        if isinstance(arg, web.Request):
            return arg
    if args:
        this = args[0]
        if isinstance(this, AbstractView):
            return this.request
        candidate = getattr(this, "request", None)
        if isinstance(candidate, web.Request):
            return candidate
    return None


def _apply_to_callable(handler: F, wrapper: Callable) -> F:
    """Apply a single (request-resolving) wrapper to a function or a class.

    Unlike :func:`_apply_decorator`, one wrapper serves both functions and
    methods, because the request is resolved at call time by
    :func:`_find_request`.  For classes:

    * class-based views (or any class exposing HTTP-verb methods) get every
      HTTP method wrapped,
    * any other class gets every public coroutine method wrapped
      (``staticmethod``/``classmethod`` members are left untouched).
    """
    if not inspect.isclass(handler):
        return wrapper(handler)
    wrapped_any = False
    for method_name in hdrs.METH_ALL:
        method = getattr(handler, method_name.lower(), None)
        if method is not None and callable(method):
            setattr(handler, method_name.lower(), wrapper(method))
            wrapped_any = True
    if wrapped_any:
        return handler
    # Not a view: protect every public coroutine method of the class.
    for name, member in inspect.getmembers(handler, inspect.iscoroutinefunction):
        if name.startswith("_"):
            continue
        raw = inspect.getattr_static(handler, name, None)
        if isinstance(raw, (staticmethod, classmethod)):
            continue
        setattr(handler, name, wrapper(member))
    return handler


def _get_pdp(request: web.Request) -> Any:
    """Return the ABAC PDP registered on the Application (or None)."""
    pdp = request.app.get("abac")
    if pdp is None:
        guardian = request.app.get("security")
        pdp = getattr(guardian, "pdp", None)
    return pdp


def _find_policy(pdp: Any, name: str) -> Any:
    """Find a Policy by name on the PDP (indexed lookup, then linear scan)."""
    evaluator = getattr(pdp, "_evaluator", None)
    index = getattr(evaluator, "_index", None) if evaluator is not None else None
    if index is not None:
        found = index.get_by_name(name)
        if found is not None:
            return found
    for policy in getattr(pdp, "policies", None) or []:
        if getattr(policy, "name", None) == name:
            return policy
    return None


def _coerce_resource_type(value: Any) -> Any:
    """Coerce a ``ResourceType`` given as string (``"kb"``, ``"KB"``)."""
    from navigator_auth.abac.policies.resources import ResourceType

    if value is None or isinstance(value, ResourceType):
        return value
    if isinstance(value, str):
        try:
            return ResourceType(value.lower())
        except ValueError:
            return ResourceType[value.upper()]
    return value


def _policy_allows(effect: Any) -> bool:
    """Normalize a PolicyResponse effect (enum, str or bool) into a boolean."""
    from navigator_auth.abac.policies import PolicyEffect

    if isinstance(effect, PolicyEffect):
        return bool(effect)
    if isinstance(effect, str):
        return effect.strip().lower() in ("allow", "true", "1")
    if isinstance(effect, (bool, int)):
        return bool(effect)
    return False


async def _abac_eval_context(request: web.Request) -> Any:
    """Build an ``EvalContext`` for the current request, as the PDP does."""
    from navigator_auth.abac.context import EvalContext

    try:
        session = await get_session(request, new=False)
    except RuntimeError:
        session = None
    user = None
    userinfo = None
    if session is not None:
        try:
            user = session.decode("user")
        except (AttributeError, KeyError, TypeError, RuntimeError):
            user = None
        try:
            userinfo = session[AUTH_SESSION_OBJECT]
        except (KeyError, TypeError):
            userinfo = None
    if user is None and isinstance(userinfo, dict) and userinfo:
        # Same fallback as PDP.authorize(): userinfo stands in for the User.
        user = userinfo
    if user is None:
        user = request.get("user", getattr(request, "user", None))
    return EvalContext(request, user, userinfo, session)


def _evaluate_policy(
    policy: Any,
    ctx: Any,
    env: Any,
    action: str,
    resource: str,
    resource_type: Any,
) -> Any:
    """Evaluate one Policy object, honouring both Policy implementations.

    ``ResourcePolicy`` and the legacy ``Policy`` expose different
    ``is_allowed()`` signatures, so the resource/action arguments are routed
    to whichever one the policy actually understands.  Without any
    resource/action constraint the policy is simply evaluated against the
    context (subject, groups, conditions, scopes and environment).
    """
    is_resource_policy = hasattr(policy, "covers_resource")
    if is_resource_policy:
        if action or resource or resource_type:
            return policy.is_allowed(
                ctx,
                env,
                resource_type=resource_type,
                resource_name=resource,
                action=action,
            )
        return policy.evaluate(ctx, env)
    if action:
        return policy.is_allowed(ctx, env, action=action)
    return policy.evaluate(ctx, env)


async def _check_policies(
    request: web.Request,
    names: list,
    action: str,
    resource: str,
    resource_type: Any,
    require_all: bool,
) -> tuple:
    """Evaluate the named policies for the current request.

    Returns:
        Tuple ``(allowed, reason, response)`` where ``response`` is the last
        ``PolicyResponse`` produced (or None when nothing could be evaluated).
    """
    from navigator_auth.abac.policies import Environment

    pdp = _get_pdp(request)
    if pdp is None:
        logger.error(
            "check_access: ABAC is not enabled on this Application, "
            "denying access to %s", request.path
        )
        return False, "ABAC is not enabled on this Application.", None

    try:
        rtype = _coerce_resource_type(resource_type)
    except (KeyError, ValueError):
        logger.error("check_access: unknown resource type %r", resource_type)
        return False, f"Unknown resource type: {resource_type}", None
    if resource and rtype is None:
        from navigator_auth.abac.policies.resources import ResourceType

        rtype = ResourceType.URI

    ctx = await _abac_eval_context(request)
    env = Environment()
    reasons = []
    last_response = None

    for name in names:
        policy = _find_policy(pdp, name)
        if policy is None:
            # Fail closed: a policy that is not declared can never grant access.
            logger.error(
                "check_access: Policy '%s' is not declared on ABAC.", name
            )
            reasons.append(f"Policy '{name}' is not declared on ABAC.")
            if require_all:
                return False, "; ".join(reasons), None
            continue
        try:
            response = _evaluate_policy(
                policy, ctx, env, action, resource, rtype
            )
        except Exception as exc:  # noqa: BLE001 - never leak a 500 from a check
            logger.exception(
                "check_access: Policy '%s' failed to evaluate: %s", name, exc
            )
            reasons.append(f"Policy '{name}' failed to evaluate.")
            if require_all:
                return False, "; ".join(reasons), None
            continue
        last_response = response
        reason = getattr(response, "response", None) or f"Policy '{name}'"
        reasons.append(reason)
        if _policy_allows(getattr(response, "effect", response)):
            if not require_all:
                return True, reason, response
        elif require_all:
            return False, reason, response

    if require_all and reasons:
        return True, "; ".join(reasons), last_response
    return False, "; ".join(reasons) or "Access Denied", last_response


def check_access(
    policy: Union[str, list],
    action: str = None,
    resource: str = None,
    resource_type: Any = None,
    require_all: bool = False,
    content_type: str = "application/json",
) -> Callable:
    """Restrict a Handler to users allowed by an existing ABAC Policy.

    Works like :func:`allowed_groups` or :func:`allowed_programs`, but the
    decision is delegated to a Policy already declared on the ABAC PDP
    (loaded from DB or YAML storage) and looked up **by name**, so the access
    rules live with the policies instead of being hardcoded on the handler.

    Usable on the three handler shapes:

    * bare functions::

        @check_access('view_articles')
        async def handler(request): ...

    * methods of a class (the request is taken from ``self.request``)::

        class ArticleView(web.View):
            @check_access('post_articles')
            async def post(self): ...

    * whole classes (class-based views get every HTTP method protected; any
      other class gets every public coroutine method protected)::

        @check_access('admin_articles')
        class AdminView(web.View): ...

    Args:
        policy: Name of the ABAC Policy — or a list of names.  With a list,
            access is granted when **any** of them allows it, unless
            ``require_all`` is True.
        action: Optional action (``"article:create"``) that the policy must
            cover for access to be granted.
        resource: Optional resource name the policy must cover (defaults the
            resource type to ``ResourceType.URI`` when none is given).
        resource_type: Optional ``ResourceType`` (or its string value, e.g.
            ``"kb"``) used together with ``resource``.
        require_all: Require every named policy to allow access.
        content_type: Content-Type header for the error responses.

    Returns:
        Callable: the decorator to apply to the handler, method or class.

    Raises:
        web.HTTPUnauthorized: the request is not authenticated.
        web.HTTPForbidden: the policy denied access, is not declared on the
            ABAC, or ABAC is not enabled (the check always fails closed).
        ValueError: no ``web.Request`` was found in the handler arguments.
    """
    names = [policy] if isinstance(policy, str) else list(policy)
    if not names:
        raise ValueError(
            "check_access requires at least one ABAC Policy name."
        )

    def _wrapper(func):
        @wraps(func)
        async def _wrap(*args, **kwargs) -> web.StreamResponse:
            request = _find_request(args, kwargs)
            if request is None:
                raise ValueError(
                    f"web.Request was not found in arguments. {func!s}"
                )
            # avoid check on OPTION method:
            if request.method == hdrs.METH_OPTIONS:
                return await func(*args, **kwargs)
            # Short-circuit for explicitly excluded paths (public URLs etc.)
            if _is_path_excluded(request) or getattr(
                request, "allow_anonymous", False
            ):
                return await func(*args, **kwargs)
            if request.get("authenticated", False) is False:
                raise web.HTTPUnauthorized(
                    reason="Access Denied",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                )
            allowed, reason, response = await _check_policies(
                request,
                names,
                action,
                resource,
                resource_type,
                require_all,
            )
            if allowed:
                # Expose the decision, as the ABAC middleware does.
                request["policy_response"] = response
                return await func(*args, **kwargs)
            raise web.HTTPForbidden(
                reason=f"Access Denied: {reason}".replace("\n", " "),
                headers={
                    hdrs.CONTENT_TYPE: content_type,
                    hdrs.CONNECTION: "keep-alive",
                },
            )

        return _wrap

    return lambda handler: _apply_to_callable(handler, _wrapper)
