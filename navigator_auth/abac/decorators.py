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

def requires_permission(
    resource_type: ResourceType,
    action: str,
    resource_name_param: str = None
):
    """
    Decorator for methods that require permission checks.

    Example:
        @requires_permission(ResourceType.KB, "kb:query", "kb_name")
        async def query_knowledge_base(self, kb_name: str, question: str, ctx: EvalContext):
            ...
    """

    def _func_wrapper(handler):
        @wraps(handler)
        async def _wrap(*args, **kwargs) -> web.StreamResponse:
            # Safe way: inspect args for EvalContext
            ctx = kwargs.get('ctx')
            if ctx is None:
                for arg in args:
                    if isinstance(arg, EvalContext):
                        ctx = arg
                        break
            
            # If not found, we cannot proceed as per spec
            if ctx is None:
                 raise ValueError("EvalContext required for permission check")
                 
            # Resource Name logic
            resource_name = "*"
            if resource_name_param:
                resource_name = kwargs.get(resource_name_param)
                if resource_name is None and args:
                    try:
                        # Inspect the handler to find parameter index
                        sig = inspect.signature(handler)
                        params = list(sig.parameters.keys())
                        if resource_name_param in params:
                            idx = params.index(resource_name_param)
                            if idx < len(args):
                                resource_name = args[idx]
                    except ValueError:
                        pass
            
            # Policy Evaluator retrieval
            # For function handlers, we check if the first arg has an evaluator (e.g. self-like object)
            # or if the handler itself has one attached? 
            # In aiohttp cbv, the view instance is args[0] for method calls, but here we are in _func_wrapper.
            # However, _apply_decorator might pass the view instance if logic allows?
            # Actually, _apply_decorator uses _method_wrapper for methods.
            # So _func_wrapper handles pure functions. Pure functions likely rely on context or global evaluators?
            # Or maybe args[0] is 'self' if it's a bound method passed as function?
            
            evaluator = None
            if args and hasattr(args[0], '_policy_evaluator'):
                evaluator = getattr(args[0], '_policy_evaluator')
            elif args and hasattr(args[0], 'policy_evaluator'):
                 evaluator = getattr(args[0], 'policy_evaluator')
            
            if evaluator is None:
                 # fallback/warning
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
            # Find context
            ctx = kwargs.get('ctx')
            if ctx is None:
                for arg in args:
                    if isinstance(arg, EvalContext):
                        ctx = arg
                        break
            
            if ctx is None:
                raise ValueError("EvalContext required for permission check")

            # Resource name
            resource_name = "*"
            if resource_name_param:
                resource_name = kwargs.get(resource_name_param)
                if resource_name is None and args:
                    try:
                        sig = inspect.signature(method)
                        params = list(sig.parameters.keys())
                        if resource_name_param in params:
                            idx = params.index(resource_name_param)
                            # method signature usually has self as first param? 
                            # If bound method is inspected, self is matching params[0]?
                            if params and params[0] == 'self':
                                idx = idx - 1
                            
                            if idx >= 0 and idx < len(args):
                                resource_name = args[idx]
                    except ValueError:
                        pass
            
            # Evaluator from self
            evaluator = getattr(self, '_policy_evaluator', getattr(self, 'policy_evaluator', None))
            
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
