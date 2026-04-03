from typing import List, Optional, TYPE_CHECKING
from collections.abc import Callable
from aiohttp import web
from navigator.views import BaseHandler
from navigator_session import get_session
from navconfig.logging import logger
from .errors import PreconditionFailed, AccessDenied
from .policies import PolicyEffect, Environment
from .context import EvalContext
from .decorators import groups_protected
from .policies.resources import ResourceType
if TYPE_CHECKING:
    from .policies.evaluator import FilteredResources

class Guardian:
    """Guardian.

    PEP: Policy Enforcement Point.

    Given a PDP it can decide via several methods if an inquiry is allowed or not.
    """
    def __init__(self, pdp: Callable):
        self.pdp = pdp

    def is_authenticated(self, request: web.Request):
        if request.get("authenticated", False) is False:
            # check credentials:
            raise AccessDenied(
                reason="User not authenticated."
            )

    async def get_user(self, request: web.Request) -> tuple:
        try:
            session = await get_session(request, new=False)
        except RuntimeError as ex:
            logger.error('NAV User Session system is not installed.')
            raise PreconditionFailed(
                reason="Missing User session for validating Access.",
                exception=ex
            ) from ex
        try:
            user = session.decode('user')
        except KeyError:
            user = None
        except AttributeError as ex:
            logger.error(
                f"User is not authenticated: {ex}"
            )
            user = None
        return (session, user)

    async def authorize(self, request: web.Request):
        """authorize.

            Check if user has access based on PDP Policies.
        Args:
            request (web.Request): Web Request.

        Raises:
            web.HTTPUnauthorized: Access is Denied.
        """
        self.is_authenticated(request=request)
        session, user = await self.get_user(request)
        return await self.pdp.authorize(
            request=request,
            session=session,
            user=user
        )

    async def filter_files(self, files: List[str], request: web.Request):
        """filter_files.

            Retrieve filtered list of files with permissions.
        Args:
            request (web.Request): Web Request.
        """
        self.is_authenticated(request=request)
        session, user = await self.get_user(request)
        return await self.pdp.filter_files(
            request=request,
            session=session,
            user=user,
            files=files
        )

    async def has_permission(self, request: web.Request, permissions: list):
        """has_permission.

            Check if user has the permission to access this resource.
        Args:
            request (web.Request): Web Request.
            permissions (list): List of requested permissions.

        Raises:
            web.HTTPUnauthorized: Access is Denied.
        """
        self.is_authenticated(request=request)
        session, user = await self.get_user(request)
        return await self.pdp.has_permission(
            request=request,
            permission=permissions,
            session=session,
            user=user
        )

    async def allowed_groups(
            self,
            request: web.Request,
            groups: list,
            effect: PolicyEffect = PolicyEffect.ALLOW
    ):
        """allowed_groups.

            Check if user is belong to any permitted groups.
        Args:
            request (web.Request): Web request.
            groups (list): List of allowed groups.
            effect (PolicyEffect): Effect to be applied, Defaults to PolicyEffect.ALLOW.

        Raises:
            web.HTTPUnauthorized: Access is Denied.
        """
        self.is_authenticated(request=request)
        session, user = await self.get_user(request)
        return await self.pdp.allowed_groups(
            request=request,
            session=session,
            user=user,
            groups=groups,
            effect=effect
        )

    async def is_allowed(
            self,
            request: web.Request,
            **kwargs
    ):
        """is_allowed.

            Check if user is allowed to access some object resources and return
            (in response) the list of allowed objects.
        Args:
            request (web.Request): Web request.
            objects (list): List of objects to be evaluated.
            objtype (str): kind of object to be evaluated (default=file)
        Raises:
            web.HTTPUnauthorized: Access is Denied.
        """
        self.is_authenticated(request=request)
        session, user = await self.get_user(request)
        _type = type
        return await self.pdp.is_allowed(
            request=request,
            session=session,
            user=user,
            **kwargs
        )

    async def filter_resources(
        self,
        resources: List[str],
        request: web.Request,
        resource_type: ResourceType = ResourceType.TOOL,
        action: str = "tool:execute",
    ) -> "FilteredResources":
        """Filter resources by PBAC policies for the authenticated user.

        Follows the same pattern as filter_files(): extracts session,
        builds EvalContext, delegates to PolicyEvaluator.filter_resources().

        Args:
            resources: List of resource name strings to filter.
            request: The current aiohttp web request (must be authenticated).
            resource_type: The type of resource being filtered (e.g., TOOL, DATASET).
            action: The action being requested (e.g., "tool:execute").

        Returns:
            FilteredResources with .allowed and .denied lists.

        Raises:
            AccessDenied: If the user is not authenticated.
            PreconditionFailed: If the session system is unavailable.
        """
        from .policies.evaluator import PolicyEvaluator, FilteredResources

        self.is_authenticated(request=request)
        session, user = await self.get_user(request)

        # Extract evaluator from PDP
        evaluator = getattr(self.pdp, '_evaluator', None)
        if evaluator is None or not isinstance(evaluator, PolicyEvaluator):
            # No PolicyEvaluator configured — allow all resources
            return FilteredResources(allowed=list(resources), denied=[])

        # Extract userinfo from session
        try:
            from navigator_auth.conf import AUTH_SESSION_OBJECT
            userinfo = session[AUTH_SESSION_OBJECT]
        except (KeyError, TypeError):
            userinfo = {}

        env = Environment()

        # Build a lightweight EvalContext
        ctx = EvalContext.__new__(EvalContext)
        ctx.store = {}
        ctx.store['request'] = request
        ctx.store['user'] = user
        ctx.store['userinfo'] = userinfo if isinstance(userinfo, dict) else {}
        ctx.store['session'] = session
        ctx._columns = list(ctx.store.keys())

        return evaluator.filter_resources(
            ctx=ctx,
            resource_type=resource_type,
            resource_names=resources,
            action=action,
            env=env,
        )

    async def filter(
            self,
            request: web.Request,
            objects: list,
            type: str = 'file',
            effect: PolicyEffect = PolicyEffect.ALLOW
    ):
        """filter.

            Check if user is allowed to access some object resources and return filtered
            list of resources. (in response) the list of allowed objects.
        Args:
            request (web.Request): Web request.
            objects (list): List of objects to be evaluated.
            objtype (str): kind of object to be evaluated (default=file)
            effect (PolicyEffect, optional): Effect to be applied,
            Defaults to PolicyEffect.ALLOW.

        Raises:
            web.HTTPUnauthorized: Access is Denied.
        """
        self.is_authenticated(request=request)
        session, user = await self.get_user(request)
        return await self.pdp.filter_obj(
            request=request,
            session=session,
            user=user,
            objects=objects,
            _type=type,
            effect=effect
        )


class PEP(BaseHandler):

    def get_guardian(self, request: web.Request):
        try:
            return request.app['security']
        except (ValueError, KeyError):
            self.critical(
                reason="ABAC System is not Installed."
            )

    @groups_protected(groups=['superuser'])
    async def reload(self, request: web.Request) -> web.Response:
        guardian = self.get_guardian(request)
        ## reload policies:
        await guardian.pdp.reload_policies()
        policies = guardian.pdp.policies()
        if len(policies) > 0:
            msg = {
                "message": "Policy PDP reloaded from Storage",
                "policies": f"{len(policies)} policies"
            }
            return self.json_response(
                response=msg,
                status=202
            )
        else:
            self.critical(
                reason="ABAC Failed to reload Policies"
            )

    async def authorize(self, request: web.Request) -> web.Response:
        """authorize.

            Check if user has access based on PDP Policies.
        Args:
            request (web.Request): Web Request.

        Raises:
            web.HTTPUnauthorized: Access is Denied.
        """
        guardian = self.get_guardian(request)
        policy = await guardian.authorize(request=request)
        if policy.effect:
            msg = {
                "message": "Access Granted",
                "response": policy.response,
                "policy": policy.rule
            }
            return self.json_response(
                response=msg,
                status=202
            )
        else:
            msg = {
                "error": "Access Denied",
                "response": policy.response,
                "policy": policy.rule
            }
            return self.json_response(
                response=msg,
                status=403
            )

    async def is_allowed(self, request: web.Request) -> web.Response:
        """is_allowed.

            Check if user has access based on PDP Policies.
        Args:
            request (web.Request): Web Request.

        Raises:
            web.HTTPUnauthorized: Access is Denied.
        """
        guardian = self.get_guardian(request)
        data = await self.data(request)
        try:
            action = data['action']
        except KeyError:
            self.error(
                reason="IS_ALLOWED Method requires *actions* list on request",
                status=401
            )
        args = {
            "action": action,
            "request": request
        }
        try:
            args['resource'] = data['resource']
        except KeyError:
            pass
        policy = await guardian.is_allowed(
            **args
        )
        if policy.effect:
            msg = {
                "message": f"Action(s) {action!s} Granted",
                "response": policy.response,
                "policy": policy.rule
            }
            return self.json_response(
                response=msg,
                status=202
            )
        else:
            msg = {
                "error": f"Access Denied: Action {action!s} not allowed",
                "response": policy.response,
                "policy": policy.rule
            }
            return self.json_response(
                response=msg,
                status=403
            )

    async def check(self, request: web.Request) -> web.Response:
        """POST /api/v1/abac/check — PBAC decision endpoint.

        Accepts a JSON body with:
            - user: str (username or email)
            - resource: str (e.g. "tool:jira_create")
            - action: str (e.g. "tool:execute")

        Returns:
            JSON: {allowed, effect, policy, reason}
        """
        try:
            data = await self.data(request)
        except Exception as exc:
            return self.json_response(
                response={"error": f"Invalid request body: {exc}"},
                status=400
            )

        user_id = data.get('user', '')
        resource = data.get('resource', '')
        action = data.get('action', '')

        if not resource or not action:
            return self.json_response(
                response={"error": "Both 'resource' and 'action' are required."},
                status=400
            )

        # Try resource-based evaluation via PolicyEvaluator first
        try:
            pdp = request.app.get('abac')
            if pdp is None:
                return self.json_response(
                    response={"error": "ABAC system not configured"},
                    status=503
                )

            # Build a lightweight EvalContext for the check
            userinfo = {
                'username': user_id,
                'groups': data.get('groups', []),
                'roles': data.get('roles', []),
            }

            # If the request is authenticated, enrich from session
            if request.get("authenticated", False):
                try:
                    session = await get_session(request, new=False)
                    from navigator_auth.conf import AUTH_SESSION_OBJECT
                    session_userinfo = session.get(AUTH_SESSION_OBJECT, {})
                    if session_userinfo:
                        # Merge — session data wins for groups/roles if not provided
                        if not userinfo.get('groups'):
                            userinfo['groups'] = session_userinfo.get('groups', [])
                        if not userinfo.get('roles'):
                            userinfo['roles'] = session_userinfo.get('roles', [])
                        if not userinfo.get('username'):
                            userinfo['username'] = session_userinfo.get('username', '')
                except Exception:
                    pass

            env = Environment()

            # Try resource-type based evaluation (ResourcePolicy via PolicyEvaluator)
            from navigator_auth.abac.policies.resources import ResourceType
            from navigator_auth.abac.policies.evaluator import PolicyEvaluator

            # Check if PDP has an evaluator attribute
            evaluator = getattr(pdp, '_evaluator', None)
            if evaluator and isinstance(evaluator, PolicyEvaluator):
                # Parse resource type
                parts = resource.split(':', 1)
                if len(parts) == 2:
                    try:
                        resource_type = ResourceType(parts[0])
                        resource_name = parts[1]
                        ctx = EvalContext.__new__(EvalContext)
                        ctx.userinfo = userinfo
                        result = evaluator.check_access(
                            ctx=ctx,
                            resource_type=resource_type,
                            resource_name=resource_name,
                            action=action,
                            env=env,
                        )
                        return self.json_response(
                            response={
                                "allowed": result.allowed,
                                "effect": result.effect.name,
                                "policy": result.matched_policy or "",
                                "reason": result.reason,
                            },
                            status=200
                        )
                    except (ValueError, KeyError):
                        pass

            # Fallback: use PDP authorize flow
            # Create a mock EvalContext from the provided data
            guardian = self.get_guardian(request)
            try:
                policy = await guardian.is_allowed(
                    request=request,
                    resource=resource,
                    action=action
                )
                allowed = bool(policy.effect)
                return self.json_response(
                    response={
                        "allowed": allowed,
                        "effect": PolicyEffect(policy.effect).name if policy.effect else "DENY",
                        "policy": getattr(policy, 'rule', ''),
                        "reason": getattr(policy, 'response', ''),
                    },
                    status=200
                )
            except (AccessDenied, PreconditionFailed) as exc:
                return self.json_response(
                    response={
                        "allowed": False,
                        "effect": "DENY",
                        "policy": "",
                        "reason": str(exc),
                    },
                    status=200
                )

        except Exception as exc:
            logger.error(f"Error in /check endpoint: {exc}")
            return self.json_response(
                response={
                    "allowed": False,
                    "effect": "DENY",
                    "policy": "",
                    "reason": f"Internal error: {exc}",
                },
                status=500
            )
