from typing import List, Optional, Union, Any
import asyncio
from aiohttp import web
from navconfig.logging import logger
from navigator_session import SessionData
from navigator_auth.conf import AUTH_SESSION_OBJECT, ABAC_RELOAD_INTERVAL
from .policies import (
    Resource,
    RequestResource,
    ActionKey,
    Policy,
    ObjectPolicy,
    FilePolicy,
    PolicyEffect,
    PolicyResponse,
    Environment
)
from .policies.adapter import PolicyAdapter
from .policies.evaluator import PolicyEvaluator, PolicyIndex
from .policies.resources import ResourceType
from .errors import PreconditionFailed, AccessDenied
from .context import EvalContext
from .guardian import Guardian, PEP
from .policyhandler import PolicyHandler
from .storages.abstract import AbstractStorage
from .storages.yaml_storage import YAMLStorage
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
        policies: Optional[List[Policy]] = None,
        yaml_storage: Optional[YAMLStorage] = None
    ):
        self._policies: list = []
        if isinstance(policies, list):
            self._policies = policies
        ### Loading an Storage and registering for Load Policies.
        self.storage = storage
        self.yaml_storage = yaml_storage
        self.logger = logger
        self._auditlog = AuditLog()
        self._evaluator: PolicyEvaluator = PolicyEvaluator()
        self._reload_task: Optional[asyncio.Task] = None

    @property
    def evaluator(self) -> PolicyEvaluator:
        return self._evaluator

    def policies(self):
        return self._policies

    def add_policy(self, policy: Policy):
        self._policies.append(policy)
        self.sorted_policies()

    def sorted_policies(self):
        self._policies.sort(key=lambda policy: policy.priority)

    async def _load_policies(self):
        # Load policies from DB storage
        try:
            policies = await self.storage.load_policies()
            self._load_policy_dicts(policies)
        except Exception as exc:
            self.logger.error('Error loading policies from DB storage: %s', exc)

        # Load policies from YAML storage (if configured)
        if self.yaml_storage is not None:
            try:
                yaml_policies = await self.yaml_storage.load_policies()
                self._load_policy_dicts(yaml_policies)
            except Exception as exc:
                self.logger.error(
                    f'Error loading policies from YAML storage: {exc}'
                )

        self._policies.sort(key=lambda policy: policy.priority)

    def _load_policy_dicts(self, policies: list):
        """Convert all policy dicts and load into evaluator."""
        resource_policies, warnings = PolicyAdapter.adapt_batch(policies)
        for w in warnings:
            self.logger.warning("Policy adaptation warning: %s", w)

        # Also keep them in self._policies for backward compatibility
        # (mostly for filter_files which still uses them)
        self._policies.extend(resource_policies)

        # Load into evaluator
        self._evaluator.load_policies(resource_policies)


    async def on_startup(self, app: web.Application):
        """Signal Handler for loading Policies from Storage.
        """
        # Call the _load_policies function
        await self._load_policies()
        # Register evaluator for handler-level access
        app['policy_evaluator'] = self._evaluator
        # Start periodic reload if configured (must be in async context)
        if ABAC_RELOAD_INTERVAL > 0:
            self._reload_task = asyncio.ensure_future(self._periodic_reload())

    async def on_shutdown(self, app: web.Application):
        if self._reload_task:
            self._reload_task.cancel()
            with asyncio.suppress(asyncio.CancelledError):
                await self._reload_task
        await self.storage.close()
        if self.yaml_storage is not None:
            await self.yaml_storage.close()

    async def reload_policies(self) -> int:
        """Hot-reload policies from DB/YAML without restart."""
        policy_dicts = []

        # Re-load from DB
        try:
            db_policies = await self.storage.load_policies()
            if db_policies:
                policy_dicts.extend(db_policies)
        except Exception as exc:
            self.logger.error('Reload: Error loading from DB: %s', exc)

        # Re-load from YAML
        if self.yaml_storage is not None:
            try:
                yaml_policies = await self.yaml_storage.load_policies()
                if yaml_policies:
                    policy_dicts.extend(yaml_policies)
            except Exception as exc:
                self.logger.error('Reload: Error loading from YAML: %s', exc)

        # Convert and swap
        resource_policies, warnings = PolicyAdapter.adapt_batch(policy_dicts)
        for w in warnings:
            self.logger.warning("Reload warning: %s", w)

        # Build new index
        new_index = PolicyIndex()
        for p in resource_policies:
            new_index.add(p)
        new_index.finalize()

        # Atomic swap (serialization handled internally)
        self._evaluator.swap_index(new_index)

        # Update local list for compatibility
        self._policies = resource_policies

        self.logger.info("Hot-reloaded %d policies", len(resource_policies))
        return len(resource_policies)

    async def _periodic_reload(self):
        """Background task for periodic policy reload."""
        if ABAC_RELOAD_INTERVAL <= 0:
            return

        self.logger.info("Starting periodic ABAC reload (interval: %ds)", ABAC_RELOAD_INTERVAL)
        while True:
            try:
                await asyncio.sleep(ABAC_RELOAD_INTERVAL)
                await self.reload_policies()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.logger.error("Error during periodic policy reload: %s", exc)

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
        self.app.router.add_post(
            "/api/v1/abac/reload", PolicyHandler.reload
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
        self.app.router.add_post(
            "/api/v1/abac/check", pep.check
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
        except (KeyError, TypeError):
            userinfo = None
        ctx = EvalContext(request, user, userinfo, session)

        # Map HTTP method to action
        action = PolicyAdapter.METHOD_ACTION_MAP.get(request.method, "uri:read")

        # Delegate to evaluator
        result = self._evaluator.check_access(
            ctx, ResourceType.URI, request.path, action
        )

        # auditlog expects an object with effect, response, rule
        # EvaluationResult has allowed, effect, matched_policy, reason
        response = PolicyResponse(
            effect=result.effect,
            response=result.reason,
            rule=result.matched_policy or "default",
            actions=[action]
        )

        await self.auditlog(response, user)

        if not result.allowed:
            if result.matched_policy:
                raise AccessDenied(f"Access Denied: {result.reason}")
            else:
                raise PreconditionFailed(
                    "No Matching Policies were found, Deny access."
                )

        return response

    ## Audit Log
    async def auditlog(self, answer, user):
        try:
            self.logger.notice(f'Policy: {answer}')
            await self._auditlog.log(answer, PolicyEffect(answer.effect).name, user)
        except Exception as exc:
            self.logger.warning('Error saving policy Log: %s', exc)

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
        except (KeyError, TypeError):
            raise AccessDenied(
                "Access Denied: no session information available"
            )
        member = False
        if "groups" in userinfo:
            member = bool(not set(userinfo["groups"]).isdisjoint(groups))
        elif user and hasattr(user, 'groups'):
            for group in user.groups:
                if group.group in groups:
                    member = True
                    break
        if member is True:
            return effect
        else:
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
        except (KeyError, TypeError):
            userinfo = None
        ctx = EvalContext(request, user, userinfo, session)
        # Delegate to the PolicyEvaluator (Rust-backed) for URI filtering.
        # Each file is treated as a URI resource for policy evaluation.
        result = self._evaluator.filter_resources(
            ctx, ResourceType.URI, files, "uri:read"
        )
        if not result.allowed and not result.denied:
            raise PreconditionFailed(
                "No Matching Policies were found, Deny access."
            )
        return result.allowed

    async def is_allowed(
            self,
            request: web.Request,
            session: SessionData = None,
            user: Any = None,
            **kwargs
    ):
        try:
            userinfo = session[AUTH_SESSION_OBJECT]
        except (KeyError, TypeError):
            userinfo = None
        ctx = EvalContext(request, user, userinfo, session)

        obj = kwargs.get('resource', None)
        action = kwargs.get('action', 'uri:read')
        owner_reports_to = kwargs.get('owner_reports_to')

        if not obj:
            # If no resource specified, we use URI authorization from request
            return await self.authorize(request, session, user)

        # Extract resource type and name from "type:name" or assume URI
        if isinstance(obj, str):
            if ':' in obj:
                try:
                    rtype_str, rname = obj.split(':', 1)
                    try:
                        rtype = ResourceType(rtype_str)
                    except ValueError:
                        # Fallback for custom types
                        rtype = rtype_str
                except (ValueError, KeyError):
                    rtype = ResourceType.URI
                    rname = obj
            else:
                rtype = ResourceType.URI
                rname = obj
        else:
            raise ValueError(f"Invalid type for Resource: {obj}:{type(obj)}")

        # Delegate to evaluator
        result = self._evaluator.check_access(
            ctx, rtype, rname, action, owner_reports_to=owner_reports_to
        )

        response = PolicyResponse(
            effect=result.effect,
            response=result.reason,
            rule=result.matched_policy or "default",
            actions=[action]
        )

        await self.auditlog(response, user)
        return response

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
        except (KeyError, TypeError):
            userinfo = None
        ctx = EvalContext(request, user, userinfo, session)
        if not isinstance(objects, list):
            objects = [objects]

        # Map the object type to a ResourceType (fallback to the string)
        try:
            resource_type = ResourceType(_type)
        except ValueError:
            resource_type = _type

        # Delegate to the PolicyEvaluator for batch filtering
        result = self._evaluator.filter_resources(
            ctx, resource_type, objects, f"{_type}:read"
        )
        if not result.allowed and not result.denied:
            raise PreconditionFailed(
                "No Matching Policies were found, Deny access."
            )

        # Build response compatible with legacy callers
        response = PolicyResponse(
            effect=effect if result.allowed else PolicyEffect.DENY,
            response="Filtered by PolicyEvaluator",
            rule="evaluator",
            actions=[f"{_type}:read"]
        )
        await self.auditlog(response, user)

        if not result.allowed:
            raise AccessDenied(
                f"Access Denied: no allowed objects of type '{_type}'"
            )
        return response
