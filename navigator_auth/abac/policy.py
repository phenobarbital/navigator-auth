from typing import Union, Optional
import uuid
from enum import Enum


class PolicyEffect(Enum):
    ALLOW = 1, 'allow'
    DENY = 0, 'deny'


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
        self.resources = resource
        self.description = description
        self.context = context
        self.groups = groups
        self.effect = effect
        self.environment = environment
        self.method = method
        self.priority = priority
