from typing import List, Optional, Any
from aiohttp import web
from navigator_session import SessionData
from navigator_auth.conf import AUTH_SESSION_OBJECT
from .policy import Policy
from .policy import PolicyEffect
from .errors import PreconditionFailed, Unauthorized, AccessDenied

class PDP:
    """ABAC Policy Decision Point implementation.
    """
    def __init__(self, policies: Optional[List[Policy]] = None):
        self._policies: list = []
        if policies:
            self._policies = policies

    def add_policy(self, policy: Policy):
        self._policies.append(policy)
        self.sorted_policies()

    def sorted_policies(self):
        self._policies.sort(key=lambda policy: policy.priority)

    async def authorize(
            self,
            request: web.Request,
            session: SessionData = None,
            user: Any = None,
            effect: PolicyEffect = PolicyEffect.ALLOW
        ):
        # Filter policies that fit Inquiry by its attributes.
        filtered = [p for p in self._policies]
        print('POLICIES > ', filtered)
        # no policies -> deny access!
        if len(filtered) == 0:
            raise PreconditionFailed(
                "No Matching Policies were found, deny access."
            )
        ## return default effect:
        return effect

    async def allowed_groups(
            self,
            request: web.Request,
            session: SessionData = None,
            user: Any = None,
            groups: list = None,
            effect: PolicyEffect = PolicyEffect.ALLOW
        ):
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
            raise AccessDenied(
                "Access Denied"
            )
