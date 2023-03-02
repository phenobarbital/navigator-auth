from aiohttp import web, hdrs
from navigator_session import get_session
from navigator_auth.conf import AUTH_SESSION_OBJECT
from navigator_auth.exceptions import (
    Forbidden, Unauthorized
)
from .policy import PolicyEffect
from .pdp import PDP

class Guardian:
    """Guardian.

    PEP: Policy Enforcement Point.

    Given a PDP it can decide via several methods if an inquiry is allowed or not.
    """
    def __init__(self, pdp: PDP):
        self.pdp = pdp

    async def get_user(self, request: web.Request) -> tuple:
        try:
            session = await get_session(request, new=False)
        except RuntimeError as ex:
            self._logger.error('QS: User Session system is not installed.')
            raise Unauthorized(
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

        Returns:
            PolicyEffect: ALLOW or DENY Resource.
        """
        if request.get("authenticated", False) is False:
            # check credentials:
            return PolicyEffect.DENY
        session, user = await self.get_user(request)

    async def has_permission(self, request: web.Request, permission: list):
        """has_permission.

            Check if user has the permission to access this resource.
        Args:
            request (web.Request): Web Request.
            permission (list): List of requested permissions.

        Returns:
            PolicyEffect: ALLOW or DENY Resource.
        """

    async def allowed_groups(self, request: web.Request, groups: list, effect: PolicyEffect = PolicyEffect.ALLOW):
        """allowed_groups.

            Check if user is belong to any permitted groups.
        Args:
            request (web.Request): Web request.
            groups (list): List of allowed groups.
            effect (PolicyEffect, optional): Effect to be applied, Defaults to PolicyEffect.ALLOW.

        Raises:
            web.HTTPUnauthorized: Access is Denied.

        Returns:
            PolicyEffect: ALLOW or DENY Resource.
        """
        if request.get("authenticated", False) is False:
            # check credentials:
            return PolicyEffect.DENY
        session, user = await self.get_user(request)
        try:
            userinfo = session[AUTH_SESSION_OBJECT]
        except KeyError:
            member = False
        if "groups" in userinfo:
            member = bool(not set(userinfo["groups"]).isdisjoint(groups))
        else:
            for group in user.groups:
                if group.group in groups:
                    member = True
                    break
        if member is True:
            ## TODO: Return an ABAC Response (allow/deny with )
            return effect
        else:
            ## TODO migrate to a custom response.
            raise web.HTTPUnauthorized(
                reason="Access Denied",
                headers={
                    hdrs.CONTENT_TYPE: 'application/json',
                    hdrs.CONNECTION: "keep-alive",
                },
            )
            # return PolicyEffect.DENY
