from typing import List, Optional, Union, Any
import asyncio
from aiohttp import web
from navconfig.logging import logger
from navigator_session import SessionData
from navigator_auth.conf import AUTH_SESSION_OBJECT
from .policies import (
    Resource,
    RequestResource,
    ActionKey,
    Policy,
    ObjectPolicy,
    FilePolicy,
    PolicyEffect,
    Environment
)
from .errors import PreconditionFailed, AccessDenied
from .context import EvalContext
from .guardian import Guardian, PEP
from .policyhandler import PolicyHandler
from .storages.abstract import AbstractStorage
from .audit import AuditLog
from .middleware import abac_middleware


async def find_deny_policy(ctx, policies):
    for policy in policies:
        answer = await policy.allowed(ctx)
        if answer.effect == PolicyEffect.DENY:
            return answer
    return None


class PDP:
    """ABAC Policy Decision Point implementation.
    """
    def __init__(
        self,
        storage: AbstractStorage,
        policies: Optional[List[Policy]] = None
    ):
        self._policies: list = []
        if isinstance(policies, list):
            self._policies = policies
        ### Loading an Storage and registering for Load Policies.
        self.storage = storage
        self.logger = logger
        self._auditlog = AuditLog()

    def policies(self):
        return self._policies

    def add_policy(self, policy: Policy):
        self._policies.append(policy)
        self.sorted_policies()

    def sorted_policies(self):
        self._policies.sort(key=lambda policy: policy.priority)

    async def _load_policies(self):
        # Load policies from storage
        policies = await self.storage.load_policies()
        for policy in policies:
            try:
                policy_type = policy['policy_type']
                del policy['policy_type']
            except KeyError:
                policy_type = 'policy'
            if policy['effect'] == 'ALLOW':
                policy['effect'] = PolicyEffect.ALLOW
            else:
                policy['effect'] = PolicyEffect.DENY
            if policy_type == 'policy':
                p = Policy(**policy)
            elif policy_type == 'file':
                p = FilePolicy(**policy)
            elif policy_type == 'object':
                p = ObjectPolicy(**policy)
            self._policies.append(p)
        self._policies.sort(key=lambda policy: policy.priority)


    async def on_startup(self, app: web.Application):
        """Signal Handler for loading Policies from Storage.
        """
        # Call the _load_policies function
        await self._load_policies()

    async def on_shutdown(self, app: web.Application):
        await self.storage.close()

    async def reload_policies(self):
        # Clear the current list of policies
        self._policies = []

        # Call the _load_policies function
        await self._load_policies()

    def setup(self, app: web.Application):
        if isinstance(app, web.Application):
            self.app = app  # register the app into the Extension
        elif hasattr(app, "get_app"):
            self.app = app.get_app()
        else:
            raise TypeError(
                f"Invalid type for Application Setup: {app}:{type(app)}"
            )
        ### Also creates a PEP (Policy Enforcing Point) on backend
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
        ### create the API endpoint for this ABAC
        pep = PEP()
        self.app.router.add_get(
            "/api/v1/abac/reload", pep.reload
        )
        self.app.router.add_post(
            "/api/v1/abac/authorize", pep.authorize
        )
        self.app.router.add_get(
            "/api/v1/abac/authorize", pep.authorize
        )
        self.app.router.add_post(
            "/api/v1/abac/is_allowed", pep.is_allowed
        )
        ## Policy Handler:
        self.app.router.add_view(
            r"/api/v1/abac/policies/{id:.*}", PolicyHandler,
            name="api_abac_policies_id"
        )
        self.app.router.add_view(
            r"/api/v1/abac/policies/{meta:\:?.*}", PolicyHandler,
            name="api_abac_policies"
        )
        ## end
        self.logger.debug(' == ABAC is Started == ')

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
        ctx = EvalContext(request, user, userinfo, session)
        # Get filtered policies based on targets from storage
        # Filter policies that fit Inquiry by its attributes.
        filtered = [p for p in self._policies if type(p) == Policy and p.fits(ctx)]
        self.logger.verbose(f'FILTERED POLICIES > {filtered!r}')
        # no policies -> deny access!
        if len(filtered) == 0:
            raise PreconditionFailed(
                "No Matching Policies were found, Deny access."
            )
        # we have policies - all of them should have allow effect, otherwise -> deny access!
        answer = False
        for policy in filtered:
            self.logger.notice(f'Policy: {policy}')
            #answer = await policy.allowed(ctx)
            answer = await asyncio.to_thread(policy.evaluate, ctx, Environment())
            if policy.enforcing is True:
                # This policy will be enforced and return is mandatory.
                await self.auditlog(answer, user)
                ## return default effect:
                return answer
            if answer.effect == effect:
                await self.auditlog(answer, user)
                ## return default effect:
                return answer
        if answer and answer.effect == PolicyEffect.DENY:
            ## Audit Log
            await self.auditlog(answer, user)
            raise AccessDenied(
                f"Access Denied: {answer.response}"
            )
        return answer

    ## Audit Log
    async def auditlog(self, answer, user):
        try:
            self.logger.notice(f'Policy: {answer}')
            await self._auditlog.log(answer, PolicyEffect(answer.effect).name, user)
        except Exception as exc:
            self.logger.warning(f'Error saving policy Log: {exc}')

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
            # await self.auditlog(answer, PolicyEffect(effect).name , user)
            return effect
        else:
            ## TODO migrate to a custom response.
            # await self.auditlog.log(answer, PolicyEffect('deny').name , user)
            raise AccessDenied(
                "Access Denied"
            )

    async def filter_files(
            self,
            request: web.Request,
            files: list[str],
            session: SessionData = None,
            user: Any = None
    ):
        try:
            userinfo = session[AUTH_SESSION_OBJECT]
        except KeyError:
            userinfo = None
        ctx = EvalContext(request, user, userinfo, session)
        ctx.objects = files
        # Get filtered policies based on targets from storage
        # Filter policies that fit Inquiry by its attributes.
        filtered = [p for p in self._policies if type(p) == FilePolicy and p.fits(ctx)]  # pylint: disable=C0123
        self.logger.verbose(f'FILTERED POLICIES > {filtered!r}')
        # no policies -> deny access!
        if len(filtered) == 0:
            raise PreconditionFailed(
                "No Matching Policies were found, Deny access."
            )
        _files = set(files)
        denied_files_set = set()
        for policy in filtered:
            self.logger.notice(f'Filter Policy: {policy}')
            #answer = await policy.allowed(ctx)
            files_allowed = await asyncio.to_thread(policy.filter_files, ctx, Environment())
            files_allowed_set = set(files_allowed)
            if policy.effect == PolicyEffect.ALLOW:
                _files = _files.intersection(files_allowed_set)
            elif policy.effect == PolicyEffect.DENY:
                denied_files = set(ctx.objects).difference(files_allowed_set)
                denied_files_set = denied_files_set.union(denied_files)
        final_allowed_files = list(_files.difference(denied_files_set))
        return final_allowed_files

    async def is_allowed(
            self,
            request: web.Request,
            session: SessionData = None,
            user: Any = None,
            **kwargs
    ):
        try:
            userinfo = session[AUTH_SESSION_OBJECT]
        except KeyError:
            userinfo = None
        ctx = EvalContext(request, user, userinfo, session)
        # Get filtered policies based on targets from storage
        # Filter policies that fit Inquiry by its attributes.
        obj = kwargs.get('resource', None)
        if obj:
            if isinstance(obj, str):
                ctx.objects = RequestResource(obj)
            elif isinstance(obj, list):
                ctx.objects = [RequestResource(r) for r in obj]
            else:
                raise ValueError(
                    f"Invalid type for Resource: {obj}:{type(obj)}"
                )
            filtered = [
                p for p in self._policies if isinstance(p, ObjectPolicy) and p.fits(ctx)
                # p for p in self._policies if p.fits(ctx)
            ]
        else:
            filtered = [p for p in self._policies if p.fits(ctx)]
        self.logger.verbose(f'FILTERED ALLOWED POLICIES > {filtered!r}')
        # no policies -> deny access!
        if len(filtered) == 0:
            raise PreconditionFailed(
                "No Matching Policies were found, Deny access."
            )
        # we have policies - all of them should have allow, otherwise -> deny access
        answer = False
        for policy in filtered:
            self.logger.notice(f'Allowed Policy: {policy!r}')
            answer = await asyncio.to_thread(
                policy.is_allowed,
                ctx,
                Environment(),
                **kwargs
            )
            if policy.enforcing is True:
                # This policy will be enforced and return is mandatory.
                await self.auditlog(answer, user)
                return answer
            if answer.effect == PolicyEffect.ALLOW:
                await self.auditlog(answer, user)
                ## return default effect:
                return answer
        ## Audit Log
        await self.auditlog(answer, user)
        return answer

    async def filter_obj(
            self,
            request: web.Request,
            objects: Union[str, list],
            _type: str,
            session: SessionData = None,
            user: Any = None,
            effect: PolicyEffect = PolicyEffect.ALLOW
    ):
        try:
            userinfo = session[AUTH_SESSION_OBJECT]
        except KeyError:
            userinfo = None
        ctx = EvalContext(request, user, userinfo, session)
        if not isinstance(objects, list):
            objects = [objects]
        ctx.objects = objects
        ctx.objectype = _type
        # Get filtered policies based on targets from storage
        # Filter policies that fit Inquiry by its attributes.
        filtered = [p for p in self._policies if hasattr(p, '_filter') and p.fits(ctx)]
        self.logger.verbose(f'FILTERED POLICIES > {filtered!r}')
        # no policies -> deny access!
        if len(filtered) == 0:
            raise PreconditionFailed(
                "No Matching Policies were found, Deny access."
            )
        # we have policies - all of them should have allow, otherwise -> deny access
        answer = False
        for policy in filtered:
            self.logger.notice(f'Policy: {policy!r}')
            answer = await asyncio.to_thread(
                policy._filter,
                objects,
                _type,
                ctx,
                Environment()
            )
            if answer.effect == effect:
                await self.auditlog(answer, user)
                ## return default effect:
                return answer
        if answer and answer.effect == PolicyEffect.DENY:
            ## Audit Log
            await self.auditlog(answer, user)
            raise AccessDenied(
                f"Access Denied: {answer.response}"
            )
        return answer
