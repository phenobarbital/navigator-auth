from typing import List, Optional, Any
from aiohttp import web
from navigator_session import SessionData
from navigator_auth.conf import AUTH_SESSION_OBJECT
from .policy import Policy
from .policy import PolicyEffect
from .errors import PreconditionFailed, Unauthorized, AccessDenied
from .context import EvalContext
from .guardian import Guardian
from .storages.abstract import AbstractStorage
from .middleware import abac_middleware

class PDP:
    """ABAC Policy Decision Point implementation.
    """
    def __init__(self, storage: AbstractStorage, policies: Optional[List[Policy]] = None):
        self._policies: list = []
        if isinstance(policies, list):
            self._policies = policies
        ### Loading an Storage and registering for Load Policies.
        self.storage = storage

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
        try:
            userinfo = session[AUTH_SESSION_OBJECT]
        except KeyError:
            userinfo = None
        ctx = EvalContext(request, user, userinfo)
        # Filter policies that fit Inquiry by its attributes.
        filtered = [p for p in self._policies if p.fits(ctx)]

        print('FILTERED POLICIES > ', filtered)
        # no policies -> deny access!
        if len(filtered) == 0:
            raise PreconditionFailed(
                "No Matching Policies were found, deny access."
            )
        # we have policies - all of them should have allow effect, otherwise -> deny access!
        answer = False
        for policy in filtered:
            answer = await policy.allowed(ctx)
            if answer.effect == PolicyEffect.DENY:
                raise Unauthorized(
                    f"Access Denied: {answer.response}"
                )
        ## return default effect:
        return answer

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

    async def on_startup(self, app: web.Application):
        """Signal Handler for loading Policies from Storage.
        """
        policies = await self.storage.load_policies()
        for policy in policies:
            if policy['effect'] == 'ALLOW':
                policy['effect'] = PolicyEffect.ALLOW
            else:
                policy['effect'] = PolicyEffect.DENY
            p = Policy(**policy)
            self._policies.append(p)
        self._policies.sort(key=lambda policy: policy.priority)

    async def on_shutdown(self, app: web.Application):
        await self.storage.close()

    def setup(self, app: web.Application):
        if isinstance(app, web.Application):
            self.app = app # register the app into the Extension
        elif hasattr(app, "get_app"):
            self.app = app.get_app()
        else:
            raise TypeError(
                f"Invalid type for Application Setup: {app}:{type(app)}"
            )
        ### Also creates a PEP (Policy Enforcing Point)
        self.app['security'] = Guardian(pdp=self)
        ## and the PDP itself:
        self.app['abac'] = self
        # startup operations over storage backend
        self.app.on_startup.append(
            self.on_startup
        )
        # cleanup operations over storage backend
        self.app.on_shutdown.append(
            self.on_shutdown
        )
        # the backend add a middleware to the app
        mdl = self.app.middlewares
        # add the middleware for this backend Authentication
        mdl.append(abac_middleware)
