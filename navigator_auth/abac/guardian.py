from typing import List
from collections.abc import Callable
from aiohttp import web
from navigator.views import BaseHandler
from navigator_session import get_session
from .errors import PreconditionFailed, AccessDenied
from .policies import PolicyEffect
from .decorators import groups_protected

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
            self._logger.error('NAV User Session system is not installed.')
            raise PreconditionFailed(
               reason="Missing User session for validating Access.",
               exception=ex
            ) from ex
        try:
            user = session.decode('user')
        except KeyError:
            user = None
        except AttributeError as ex:
            self._logger.error(
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
