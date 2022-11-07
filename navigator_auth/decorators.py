from functools import wraps
from typing import Any, TypeVar
from collections.abc import Callable
from aiohttp import web, hdrs
from aiohttp.abc import AbstractView
from navigator_session import get_session
from navigator_auth.exceptions import AuthException
from navigator_auth.conf import AUTH_SESSION_OBJECT
#from navigator.auth import get_userdata


F = TypeVar('F', bound=Callable[..., Any])


def user_session() -> Callable[[F], F]:
    """Decorator for getting User in the request.
    """
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
                    f'web.Request was not found in arguments. {handler!s}'
                )
            session = await get_session(request, new = False)
            try:
                user = session.decode('user')
            except (AttributeError, TypeError, RuntimeError):
                user = None
            response = await handler(*args, session, user, **kwargs)
            return response
        return _wrap
    return _wrapper

def is_authenticated(content_type: str = 'application/json') -> Callable:
    """Decorator to check if an user has been authenticated for this request.
    """
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
                    f'web.Request was not found in arguments. {handler!s}'
                )
            if request.get('authenticated', False) is True:
                # already authenticated
                return await handler(*args, **kwargs)
            else:
                app = request.app
                auth = app["auth"]
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
                    # check credentials:
                    raise web.HTTPUnauthorized(
                        reason="Access Denied",
                        headers={
                            hdrs.CONTENT_TYPE: content_type,
                            hdrs.CONNECTION: 'keep-alive',
                        }
                    )
        return _wrap
    return _wrapper


def allowed_groups(groups: list, content_type: str = 'application/json') -> Callable:
    """Restrict the Handler only to certain Groups in User information.
    """
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
                    f'web.Request was not found in arguments. {handler!s}'
                )
            if request.get('authenticated', False) is False:
                # check credentials:
                raise web.HTTPUnauthorized(
                    reason="Access Denied",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: 'keep-alive',
                    }
                )
            else:
                session = await get_session(request)
                member = False
                try:
                    userinfo = session[AUTH_SESSION_OBJECT]
                except KeyError:
                    member = False
                if 'groups' in userinfo:
                    member = bool(not set(userinfo['groups']).isdisjoint(groups))
                else:
                    user = session.decode('user')
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
                            hdrs.CONNECTION: 'keep-alive',
                        }
                    )
        return _wrap
    return _wrapper

def allowed_programs(programs: list, content_type: str = 'application/json') -> Callable:
    """Restrict the Handler only to certain Programs in User information.
    """
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
                    f'web.Request was not found in arguments. {handler!s}'
                )
            if request.get('authenticated', False) is False:
                # check credentials:
                raise web.HTTPUnauthorized(
                    reason=f"Access Denied to Handler {handler!s}",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: 'keep-alive',
                    }
                )
            else:
                session = await get_session(request)
                member = False
                try:
                    userinfo = session[AUTH_SESSION_OBJECT]
                except KeyError:
                    member = False
                if 'programs' in userinfo:
                    member = bool(not set(userinfo['programs']).isdisjoint(programs))
                if member is True:
                    ## Check Groups belong to User
                    return await handler(*args, **kwargs)
                else:
                    raise web.HTTPUnauthorized(
                        reason="Access Denied",
                        headers={
                            hdrs.CONTENT_TYPE: content_type,
                            hdrs.CONNECTION: 'keep-alive',
                        }
                    )
        return _wrap
    return _wrapper

def allowed_organizations(org: list, content_type: str = 'application/json') -> Callable:
    """Restrict the Handler only to certain Programs in User information.
    """
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
                    f'web.Request was not found in arguments. {handler!s}'
                )
            if request.get('authenticated', False) is False:
                # check credentials:
                raise web.HTTPUnauthorized(
                    reason=f"Access Denied to Handler {handler!s}",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: 'keep-alive',
                    }
                )
            else:
                session = await get_session(request)
                member = False
                try:
                    user = session.decode('user')
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
                            hdrs.CONNECTION: 'keep-alive',
                        }
                    )
        return _wrap
    return _wrapper

# def has_permission(func, permission, context=None):
#     """Check user permissions.
#     Return Function if the identity is allowed the permission in the
#     current context, else raise ``web.HTTPUnauthorized()``
#     """
#     @wraps(func)
#     async def _wrap(*args, **kwargs):
#         pass
#     return _wrap
