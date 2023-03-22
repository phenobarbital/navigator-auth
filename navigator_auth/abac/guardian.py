from collections.abc import Callable
from aiohttp import web
from navigator_session import get_session
from .errors import PreconditionFailed, AccessDenied
from .policies import PolicyEffect


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
        return (session, user)

    async def authorize(self, request: web.Request):
        """authorize.

            Check if user has access based on PDP Policies.
        Args:
            request (web.Request): _description_

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
            effect (PolicyEffect, optional): Effect to be applied, Defaults to PolicyEffect.ALLOW.

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
