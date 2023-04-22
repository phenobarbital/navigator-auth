from typing import Union, Optional, List
import uuid
import logging
import re
from enum import Enum
from datamodel.libs.mapping import ClassDict
from .context import EvalContext
from .environment import Environment

class PolicyEffect(Enum):
    ALLOW = 1, 'allow'
    DENY = 0, 'deny'

class PolicyResponse(ClassDict):
    effect: PolicyEffect
    response: str
    rule: str

class Exp:
    def __init__(self, value):
        try:
            self.resource_type, self.raw_value = value.split(':', 1)
        except ValueError:
            self.resource_type = 'uri'
            self.raw_value = value
        self.is_regex = False
        try:
            self.value = re.compile(self.raw_value)
            self.is_regex = True
        except re.error:
            logging.warning(f'Resource {value} is not a Regular Expression.')
            self.value = value

    def __str__(self) -> str:
        return f"<{type(self).__name__}({self.resource_type}: {self.value!r})>"

    def __repr__(self) -> str:
        return f"<{type(self).__name__}({self.resource_type}: {self.value!r})>"

    def match(self, value):
        if self.is_regex:
            return self.value.match(value)
        elif self.raw_value == '*':
            return True
        else:
            return self.raw_value == value

class Policy:
    def __init__(
            self,
            name: str = None,
            actions: list = None,
            resource: Union[list,str] = None,
            effect: PolicyEffect = PolicyEffect.ALLOW,
            subject: Optional[List[str]] = None,
            groups: Optional[list] = None,
            context: Optional[dict] = None,
            method: Optional[Union[list, str]] = None,
            environment: Optional[Environment] = None,
            description: str = None,
            priority: int = None,
            **kwargs
    ):
        self.name = name if name else uuid.uuid1().hex
        self.actions = actions
        if type(resource) == str:  # pylint: disable=C0123
            self.resources = list(Exp(resource))
        else:
            self.resources = [Exp(r) for r in resource]
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
        ### any other attributes so far
        self.attributes = kwargs

    def __str__(self) -> str:
        return f"<{type(self).__name__}({self.name}, {self.resources!r})>"

    def __repr__(self) -> str:
        return f"<{type(self).__name__}({self.name})>"

    def fits(self, ctx: EvalContext) -> bool:
        ## firstly evaluates the resources:
        fit_result = False
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
            elif resource.resource_type == "file":
                # ... handle file resources ...
                pass
            elif resource.resource_type == "app":
                # ... handle app resources ...
                pass
        if fit_result is True:
            ## third: check if user of session has contexts attributes required:
            fit_context = False
            fit_context = any(a in ctx.user_keys or a in ctx.userinfo_keys for a in self.context_attrs)
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

    def evaluate(self, ctx: EvalContext, environ: Environment) -> bool:
        # Check if user belongs to any allowed groups
        groups_condition = False
        if self.groups:
            try:
                if bool(not set(ctx.userinfo["groups"]).isdisjoint(self.groups)):
                    ### allowed by groups:
                    groups_condition = True
            except (KeyError, TypeError, ValueError):
                pass
        else:
            groups_condition = True
        subject_condition = False
        if self.subject:
            if ctx.userinfo['username'] in self.subject:
                subject_condition = True
        else:
            subject_condition = True
        # Check if current environment matches the environment policy
        environment_condition = False
        if self.environment:
            if self.evaluate_environment(environ):
                environment_condition = True
        else:
            environment_condition = True
        # Check if other contexts match the context rules in Policy Attributes
        context_condition = False
        if self.context:
            ### check attributes
            if self.context_attrs:
                for a in self.context_attrs:
                    att = self.context[a]
                    try:
                        if att == getattr(ctx.user, a, None):
                            context_condition = True
                    except TypeError:
                        pass
                    val = getattr(ctx.userinfo, a, ctx.userinfo.get(a, None))
                    if att == val:
                        context_condition = True
                    try:
                        val = getattr(ctx.session, a, None)
                        if isinstance(att, list):
                            if val in att:
                                context_condition = True
                        else:
                            if att == val:
                                context_condition = True
                    except (KeyError, TypeError):
                        pass
        else:
            context_condition = True
        # If all conditions are true, set is_allowed to True
        if groups_condition and environment_condition and context_condition and subject_condition:
            return PolicyResponse(
                effect=self.effect,
                response=f"Access {self.effect} by {self.name}",
                rule=self.name
            )
        ### default return False
        return PolicyResponse(
            effect=PolicyEffect.DENY,
            response=f"Unauthorized by Policy {self.name}",
            rule=self.name
        )
