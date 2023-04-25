from abc import ABC, abstractmethod
from typing import Union, Optional
import logging
import uuid
import re
from enum import Enum
from datamodel.libs.mapping import ClassDict
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


class Exp:
    def __init__(self, value):
        self._negative = False
        try:
            self.resource_type, self.raw_value = value.split(':', 1)
        except (ValueError, TypeError):
            self.resource_type = 'uri'
            self.raw_value = value
        if self.raw_value.startswith('!'):
            self._negative = True
            self.raw_value = self.raw_value[1:]
        self.is_regex = False
        try:
            self.value = re.compile(f'^{self.raw_value}$')
            self.is_regex = True
        except re.error:
            logging.warning(f'Resource {value} is not a Regular Expression.')
            self.value = value

    def __str__(self) -> str:
        return self.raw_value
        # return f"<{type(self).__name__}({self.resource_type}: {self.value!r})>"

    def __repr__(self) -> str:
        return f"<{type(self).__name__}({self.resource_type}: {self.value!r})>"

    def is_negative(self):
        return self._negative

    def match(self, value):
        if self.is_regex:
            return self.value.match(value)
        elif self.raw_value == '*':
            return True
        else:
            return self.raw_value == value


class AbstractPolicy(ABC):
    def __init__(
            self,
            name: str = None,
            actions: list = None,
            resource: Union[list,str] = None,
            effect: PolicyEffect = PolicyEffect.ALLOW,
            subject: Optional[list[str]] = None,
            groups: Optional[list] = None,
            context: Optional[dict] = None,
            method: Optional[Union[list, str]] = None,
            environment: Optional[Environment] = None,
            objects: Optional[dict] = None,
            description: str = None,
            priority: int = None,
            enforcing: bool = False,
            **kwargs
    ):
        self.name = name if name else uuid.uuid1().hex
        self.actions = actions
        self.enforcing: bool = enforcing
        if type(resource) == str:  # pylint: disable=C0123
            self.resources = list(Exp(resource))
        elif isinstance(resource, list):
            self.resources = [Exp(r) for r in resource]
        else:
            self.resources = None
        self.description = description
        self.context = context if context else {}
        self.context_attrs = list(self.context.keys())
        self.groups: list = groups
        self.effect: PolicyEffect = effect
        self.environment: Environment = environment
        if isinstance(method, str):
            self.method = [method]
        else:
            self.method = method
        #### Subject:
        if isinstance(subject, str):
            self.subject = subject.split(',')
        else:
            self.subject = subject
        self.priority = priority if priority else 0
        ### Objects:
        self.objects = objects
        ### any other attributes so far
        self.attributes = kwargs

    def __str__(self) -> str:
        return f"<{type(self).__name__}({self.name}, {self.resources!r})>"

    def __repr__(self) -> str:
        return f"<{type(self).__name__}({self.name})>"

    @abstractmethod
    def _fits_policy(self, ctx: EvalContext) -> bool:
        """Internal Method for checking if Policy fits the Context."""

    def fits(self, ctx: EvalContext) -> bool:
        ## firstly evaluates the resources:
        fit_result = False
        if not self.resources:
            ### applicable to any resource:
            return True
        for resource in self.resources:
            ## first: check by resource context
            if resource.resource_type == "uri":
                if resource.match(ctx.path) is not None:
                    ## second: check if match a request method:
                    if self.method:
                        if ctx.method in self.method:
                            fit_result = True
                    else:
                        fit_result = True
            else:
                # ... handle application (Extensible) resources ...
                fit_result = self._fits_policy(ctx)
        if fit_result is True:
            ## third: check if user of session has contexts attributes required:
            fit_context = False
            fit_context = any(
                a in ctx.user_keys or a in ctx.userinfo_keys for a in self.context_attrs
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
