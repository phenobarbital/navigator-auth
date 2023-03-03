from typing import Union, Optional
import uuid
import re
from enum import Enum
from .context import EvalContext

class PolicyEffect(Enum):
    ALLOW = 1, 'allow'
    DENY = 0, 'deny'

class Exp:
    def __init__(self, value):
        self.is_regex = False
        self.raw_value = value
        try:
            self.value = re.compile(value)
            self.is_regex = True
        except re.error:
            self.value = value

    def __str__(self) -> str:
        return f"<{type(self).__name__}({self.value!r})>"

    def __repr__(self) -> str:
        return f"<{type(self).__name__}({self.value!r})>"

class Policy:
    def __init__(
            self,
            name: str = None,
            actions: list = None,
            resource: Union[list,str] = None,
            effect: PolicyEffect = PolicyEffect.ALLOW,
            groups: Optional[list] = None,
            context: Optional[dict] = None,
            method: Optional[Union[list, str]] = None,
            environment: Optional[list] = None,
            description: str = None,
            priority: int = None
    ):
        self.name = name if name else uuid.uuid1()
        self.actions = actions
        if type(resource) == str:  # pylint: disable=C0123
            self.resources = list(Exp(resource))
        else:
            self.resources = []
            for r in resource:
                self.resources.append(Exp(r))
        self.description = description
        self.context = context if context else {}
        self.context_attrs = self.context.keys()
        self.groups = groups
        self.effect = effect
        self.environment = environment
        self.method = method
        self.priority = priority if priority else 0

    def __str__(self) -> str:
        return f"<{type(self).__name__}({self.name}, {self.resources!r})>"

    def __repr__(self) -> str:
        return f"<{type(self).__name__}({self.name})>"

    def fits(self, ctx: EvalContext) -> bool:
        ## TODO: More rules for a policy Fits evaluation
        ## firstly evaluates the resources:
        fit_result = False
        for resource in self.resources:
            ## first: check by resource context
            if resource.value.match(ctx.path):
                fit_result = True
            ## second: check if user of session has contexts attributes required:
            fit_context = False
            for a in self.context_attrs:
                if a in ctx.user_keys:
                    fit_context = True
                if a in ctx.session_keys:
                    fit_context = True
            if not fit_context: # this policy is enforcing over Context Attributes.
                fit_result = False
        return fit_result
