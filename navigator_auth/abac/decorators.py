"""
ABAC Decorators for aiohttp handlers and class-based views.

Provides `groups_protected` and `requires_permission` decorators that
work with both function-based handlers and `aiohttp.web.View` subclasses
via the `_apply_decorator` pattern.
"""
from functools import wraps
from typing import Any, TypeVar
from collections.abc import Callable
from aiohttp import web, hdrs
from aiohttp.abc import AbstractView
import inspect
from navigator_session import get_session
from navigator_auth.conf import AUTH_SESSION_OBJECT
from navigator_auth.decorators import _apply_decorator

from navigator_auth.abac.context import EvalContext
from navigator_auth.abac.policies.resources import ResourceType

F = TypeVar("F", bound=Callable[..., Any])


def _get_request(*args) -> web.Request:
    """Extract web.Request from handler arguments.

    Handles both function-based handlers (request is last positional arg)
    and class-based views (request is on the view instance).
    """
    if not args:
        return None
    if isinstance(args[0], AbstractView):
        return args[0].request
    # For function handlers, request is typically last arg
    for arg in args:
        if isinstance(arg, web.Request):
            return arg
    return None


async def _get_userinfo(request: web.Request) -> tuple:
    """Extract session and userinfo from request.

    Returns:
        (session, userinfo, member_check_possible)
    """
    session = await get_session(request)
    userinfo = None
    try:
        userinfo = session[AUTH_SESSION_OBJECT]
    except (KeyError, TypeError):
        pass
    return session, userinfo


def groups_protected(
    groups: list,
    content_type: str = "application/json"
) -> Callable:
    """Restrict the handler to certain groups in user information.

    Works with both function-based handlers and class-based views
    (``aiohttp.web.View`` subclasses) via ``_apply_decorator``.

    Args:
        groups: List of group names. Access is granted if the user
            belongs to at least one of these groups.
        content_type: Content-Type header for error responses.
    """

    def _func_wrapper(handler):
        @wraps(handler)
        async def _wrap(*args, **kwargs) -> web.StreamResponse:
            request = _get_request(*args)
            if request is None:
                raise ValueError(
                    f"web.Request was not found in arguments. {handler!s}"
                )
            return await _check_groups_and_call(
                request, handler, args, kwargs, groups, content_type
            )
        return _wrap

    def _method_wrapper(method):
        @wraps(method)
        async def _wrap(self, *args, **kwargs) -> web.StreamResponse:
            request = self.request
            return await _check_groups_and_call(
                request, method, (self, *args), kwargs, groups, content_type
            )
        return _wrap

    return lambda handler: _apply_decorator(handler, _func_wrapper, _method_wrapper)


async def _check_groups_and_call(
    request: web.Request,
    handler,
    args: tuple,
    kwargs: dict,
    groups: list,
    content_type: str,
) -> web.StreamResponse:
    """Shared logic for groups_protected — works for both func and method."""
    if request.get("authenticated", False) is False:
        raise web.HTTPUnauthorized(
            reason="Access Denied",
            headers={
                hdrs.CONTENT_TYPE: content_type,
                hdrs.CONNECTION: "keep-alive",
            },
        )

    session, userinfo = await _get_userinfo(request)
    member = False

    if userinfo is not None and "groups" in userinfo:
        member = bool(not set(userinfo["groups"]).isdisjoint(groups))
    elif session is not None:
        try:
            user = session.decode("user")
            if user and hasattr(user, 'groups'):
                for group in user.groups:
                    if group.group in groups:
                        member = True
                        break
        except Exception:
            pass

    if member:
        return await handler(*args, **kwargs)

    raise web.HTTPUnauthorized(
        reason="Access Denied",
        headers={
            hdrs.CONTENT_TYPE: content_type,
            hdrs.CONNECTION: "keep-alive",
        },
    )


def requires_permission(
    resource_type: ResourceType,
    action: str,
    resource_name_param: str = None
):
    """Decorator for methods/handlers that require permission checks.

    Works with both function-based handlers and class-based views
    (``aiohttp.web.View`` subclasses) via ``_apply_decorator``.

    The decorator looks for a ``policy_evaluator`` or ``_policy_evaluator``
    attribute on ``self`` (for methods) or on the first positional argument
    (for functions). If no evaluator is found, the handler is called without
    permission checking (fail-open for backward compatibility).

    Example::

        @requires_permission(ResourceType.KB, "kb:query", "kb_name")
        async def query_knowledge_base(self, kb_name: str, question: str, ctx: EvalContext):
            ...
    """

    def _func_wrapper(handler):
        @wraps(handler)
        async def _wrap(*args, **kwargs) -> web.StreamResponse:
            ctx = _find_eval_context(args, kwargs)
            if ctx is None:
                raise ValueError("EvalContext required for permission check")

            resource_name = _resolve_resource_name(
                handler, resource_name_param, args, kwargs
            )

            evaluator = None
            if args and hasattr(args[0], '_policy_evaluator'):
                evaluator = getattr(args[0], '_policy_evaluator')
            elif args and hasattr(args[0], 'policy_evaluator'):
                evaluator = getattr(args[0], 'policy_evaluator')

            if evaluator is None:
                return await handler(*args, **kwargs)

            result = evaluator.check_access(
                ctx=ctx,
                resource_type=resource_type,
                resource_name=resource_name,
                action=action
            )

            if not result.allowed:
                raise web.HTTPForbidden(
                    reason=f"Access denied: {resource_type.value}:{resource_name} - {result.reason}"
                )

            return await handler(*args, **kwargs)
        return _wrap

    def _method_wrapper(method):
        @wraps(method)
        async def _wrap(self, *args, **kwargs):
            ctx = _find_eval_context(args, kwargs)
            if ctx is None:
                raise ValueError("EvalContext required for permission check")

            resource_name = _resolve_resource_name(
                method, resource_name_param, args, kwargs, is_method=True
            )

            evaluator = getattr(
                self, '_policy_evaluator',
                getattr(self, 'policy_evaluator', None)
            )

            if evaluator is None:
                return await method(self, *args, **kwargs)

            result = evaluator.check_access(
                ctx=ctx,
                resource_type=resource_type,
                resource_name=resource_name,
                action=action
            )

            if not result.allowed:
                raise web.HTTPForbidden(
                    reason=f"Access denied: {resource_type.value}:{resource_name} - {result.reason}"
                )

            return await method(self, *args, **kwargs)
        return _wrap

    return lambda handler: _apply_decorator(handler, _func_wrapper, _method_wrapper)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _find_eval_context(args: tuple, kwargs: dict):
    """Find EvalContext in args or kwargs."""
    ctx = kwargs.get('ctx')
    if ctx is not None:
        return ctx
    for arg in args:
        if isinstance(arg, EvalContext):
            return arg
    return None


def _resolve_resource_name(
    handler,
    resource_name_param: str,
    args: tuple,
    kwargs: dict,
    is_method: bool = False,
) -> str:
    """Resolve the resource name from handler arguments."""
    if not resource_name_param:
        return "*"

    resource_name = kwargs.get(resource_name_param)
    if resource_name is not None:
        return resource_name

    if args:
        try:
            sig = inspect.signature(handler)
            params = list(sig.parameters.keys())
            if resource_name_param in params:
                idx = params.index(resource_name_param)
                # For methods, adjust index since self is params[0]
                # but not in args (already bound)
                if is_method and params and params[0] == 'self':
                    idx -= 1
                if 0 <= idx < len(args):
                    return args[idx]
        except (ValueError, TypeError):
            pass

    return "*"
