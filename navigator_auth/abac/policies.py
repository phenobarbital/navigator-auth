from typing import Union, Optional
from dataclasses import dataclass
import uuid
import re
from enum import Enum
from .context import EvalContext

class PolicyEffect(Enum):
    ALLOW = 1, 'allow'
    DENY = 0, 'deny'

@dataclass
class PolicyResponse:
    effect: PolicyEffect
    response: str
    rule: str

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
            priority: int = None,
            **kwargs
    ):
        self.name = name if name else uuid.uuid1().hex
        self.actions = actions
        if type(resource) == str:  # pylint: disable=C0123
            self.resources = list(Exp(resource))
        else:
            self.resources = []
            for r in resource:
                self.resources.append(Exp(r))
        self.description = description
        self.context = context if context else {}
        self.context_attrs = list(self.context.keys())
        self.groups = groups
        self.effect = effect
        self.environment = environment
        if isinstance(method, str):
            self.method = [method]
        else:
            self.method = method
        self.priority = priority if priority else 0
        ### any other attributes so far
        self.attributes = kwargs

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
            if resource.value.match(ctx.path) is not None:
                ## second: check if match a request method:
                if self.method:
                    if ctx.method in self.method:
                        fit_result = True
                else:
                    fit_result = True

        if fit_result:
            ## third: check if user of session has contexts attributes required:
            fit_context = False
            fit_context = any(a in ctx.user_keys or a in ctx.userinfo_keys for a in self.context_attrs)
            if not fit_context and not fit_result:
                # this policy is enforcing over Context Attributes.
                fit_result = False
        return fit_result

    async def allowed(self, ctx: EvalContext) -> bool:
        ## first: check groups or contexts:
        if self.groups:
            try:
                if bool(not set(ctx.userinfo["groups"]).isdisjoint(self.groups)):
                    ### allowed by groups:
                    return PolicyResponse(
                        effect=self.effect,
                        response=f"Declared by Policy {self.name} with effect: {self.effect}",
                        rule=self.name
                    )
            except (KeyError, TypeError):
                pass
        if not self.context:
            ## there is no contexts to match with this resource, return default:
            return PolicyResponse(
                    effect=self.effect,
                    response=f"Default by Policy {self.name} with effect: {self.effect}",
                    rule=self.name
                )
        else:
            is_allowed = False
            ### check attributes
            if self.context_attrs:
                for a in self.context_attrs:
                    att = self.context[a]
                    try:
                        if att == getattr(ctx.user, a, None):
                            is_allowed = True
                    except TypeError:
                        pass
                    val = getattr(ctx.userinfo, a, ctx.userinfo.get(a, None))
                    if att == val:
                        is_allowed = True
                    try:
                        val = getattr(ctx.session, a, None)
                        if isinstance(att, list):
                            if val in att:
                                is_allowed = True
                        else:
                            if att == val:
                                is_allowed = True
                    except (KeyError, TypeError):
                        pass
                if is_allowed is True:
                    return PolicyResponse(
                        effect=self.effect,
                        response=f"Access by {self.name} with effect: {self.effect}",
                        rule=self.name
                    )
        ### default return False
        return PolicyResponse(
            effect=PolicyEffect.DENY,
            response=f"Unauthorized by Policy {self.name}",
            rule=self.name
        )
