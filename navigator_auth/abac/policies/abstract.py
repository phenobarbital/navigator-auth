from abc import ABC, abstractmethod
from typing import Union, Optional
import logging
import uuid
from enum import Enum
from datamodel.libs.mapping import ClassDict
from .resources import Resource
from ..context import EvalContext
from .environment import Environment


class PolicyEffect(Enum):
    ALLOW = 1, 'allow'
    DENY = 0, 'deny'

    def __bool__(self):
        return bool(self.value[0])


class PolicyResponse(ClassDict):
    effect: PolicyEffect
    response: str
    rule: str
    actions: list[str]


class ActionKey:
    def __init__(self, action: str):
        self.object, self.action = action.split(':', 1)

    def __eq__(self, other):
        if isinstance(other, ActionKey):
            return self.action == other.action and self.object == other.object
        return False

    def __str__(self) -> str:
        return f"<Action: {self.object}:{self.action}>"

    def __repr__(self) -> str:
        return f"<Action: {self.object}:{self.action}>"


class AbstractPolicy(ABC):
    """Abstract Policy class.

    Base class for all ABAC policies.

    Attributes:
    ----------
    name: str: name of the policy
    description: str: description of the policy
    actions: list: a List of actions (what the user is trying to do with the resource.
        Common action attributes include “read,” “write,” “edit,” “copy,” and “delete.”) in form [object:action]
    resource: list of assets (objects) covered by the policy
    objects: dict: a dictionary of objects covered by the policy
    conditions: dict: optional dictionary of conditions affecting the
        Resource object (example: HTTP method, resource limits, resource creation, etc)
    effect: PolicyEffect: the policy effect (ALLOW, DENY)
    context: optional dict: dictionary of context (user specific attributes) to be used for policy
    environment: The Environment is an object with a broader context of each access request.
        All environmental attributes speak to contextual factors like the time and location of an access attempt
    subject: list: a List of users requesting access, will be allowed to access the resource
        based on policy effect
    groups: list: a List of groups the user belongs to (e.g. administrators)
    priority: int: Every Policy will be evaluated in order of priority.
    enforcing: bool: If True, the policy will be enforced (no other policies will be evaluated).
    """
    def __init__(
            self,
            name: str = None,
            description: str = None,
            actions: list = None,
            resource: Union[list,str] = None,
            objects: Optional[dict] = None,
            conditions: Optional[dict] = None,
            effect: PolicyEffect = PolicyEffect.ALLOW,
            subject: Optional[list[str]] = None,
            groups: Optional[list] = None,
            context: Optional[dict] = None,
            environment: Optional[Environment] = None,
            priority: int = None,
            enforcing: bool = False,
            **kwargs
    ):
        self.name = name if name else uuid.uuid1().hex
        self.description = description
        self.resources: list[Resource] = []
        self.context: dict = {}
        self.context_attrs: list = []
        self.actions: list = []
        self.conditions: dict = {}
        if isinstance(actions, list):
            self.actions = [ActionKey(r) for r in actions]
        if type(resource) == str:  # pylint: disable=C0123
            self.resources = list(Resource(resource))
        elif isinstance(resource, list):
            self.resources = [Resource(r) for r in resource]
        else:
            self.resources = None
        if isinstance(context, dict):
            self.context = context
            self.context_attrs = list(self.context.keys())
        if isinstance(conditions, dict):
            self.conditions = conditions
        self.groups: list = groups
        self.effect: PolicyEffect = effect
        self.environment: Environment = environment
        #### Subject:
        if isinstance(subject, str):
            self.subject = subject.split(',')
        elif isinstance(subject, list):
            self.subject = subject
        else:
            self.subject = None
        self.priority = priority if priority else 0
        ### Objects:
        self.objects = objects
        ### any other attributes so far
        self.attributes = kwargs
        ### this policy is enforcing or not
        self.enforcing: bool = enforcing

    def __str__(self) -> str:
        return f"<{type(self).__name__}({self.name}, {self.resources!r})>"

    def __repr__(self) -> str:
        return f"<{type(self).__name__}({self.name})>"

    def _fits_policy(self, resource: Resource, ctx: EvalContext) -> bool:
        """Internal Method for checking if Policy fits the Context."""
        if resource.match(ctx):
            return True
        return False

    def fits(self, ctx: EvalContext) -> bool:
        """This method evaluates if the policy matches the current EvalContext and request.
         It checks if the resources and conditions match the given context.
         If the policy fits the context, it returns True, otherwise, it returns False
        """
        ## firstly evaluates the resources:
        fit_result = False
        if not self.resources:
            ### applicable to any resource:
            return True
        for resource in self.resources:
            ## first: check by resource context
            if resource.resource_type == "uri":
                # print('HERE >> ', resource.resource_type, ctx.path, resource.match(ctx.path))
                if resource.match(ctx.path) is not None:
                    fit_result = True
                    ## second: check if match with conditions:
                    for key, value in self.conditions.items():
                        if not hasattr(ctx, key):
                            # If the key is not covered by EvalContext, skip the condition
                            continue
                        ctx_value = getattr(ctx, key)
                        if isinstance(value, dict):
                             # Check if value is a subset of ctx_value
                            if not all(item in ctx_value.items() for item in value.items()):
                                fit_result = False
                                break
                        elif isinstance(value, list):
                            if ctx_value not in value:
                                fit_result = False
                                break
                        else:
                            if value != ctx_value:
                                fit_result = False
                                break
            else:
                # ... handle application (Extensible) resources ...
                # print('HERE >> ', resource.resource_type, resource.match(ctx))
                fit_result = self._fits_policy(resource, ctx)
        if fit_result is True:
            ## third: check if user of session has contexts attributes required:
            fit_context = False
            fit_context = any(
                a in ctx.user_keys or a in ctx.userinfo_keys or getattr(ctx, a, None) is not None for a in self.context_attrs
            )
            if not fit_context and not fit_result:
                # this policy is enforcing over Context Attributes.
                fit_result = False
        return fit_result

    def evaluate_environment(self, current_environment: Environment) -> bool:
        matches = (
            # Check if the value in the policy environment is a range or list
            (isinstance(val, (range, list)) and current_environment[key] in val) or
            # If not, check for equality
            (current_environment[key] == val)
            for key, val in self.environment.items()
        )
        return all(matches)

    @abstractmethod
    def evaluate(self, ctx: EvalContext, environ: Environment) -> bool:
        """
        Evaluates the policy against the provided context and environment.

        :param ctx: The evaluation context, containing user, userinfo, and session
           information.
        :param environ: The environment information, such as the current time and date.
        :return: A PolicyResponse instance, indicating whether access is allowed or
           denied.
        """
        pass

    @abstractmethod
    def is_allowed(
            self,
            ctx: EvalContext,
            env: Environment
    ) -> PolicyResponse:
        """
        Evaluates the policy against the provided context and environment.
        :param ctx: The evaluation context, containing user, userinfo, and session
           information.
        :param env: The environment information, such as the current time and date.
        :return: A PolicyResponse instance, indicating whether access is allowed or
           denied.
        """
        pass
