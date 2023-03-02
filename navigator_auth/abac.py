"""ABAC Proof of Concept.
"""
from typing import Union, Optional, List
import uuid
from enum import Enum
from aiohttp import web
from navigator_session import get_session, SessionData, SESSION_KEY
from navigator_auth.exceptions import (
    Forbidden, Unauthorized
)


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


class Guardian:
    """Guardian.

    PEP: Policy Enforcement Point.

    Given a PDP it can decide via several methods if an inquiry is allowed or not.
    """
    def __init__(self, pdp: PDP):
        self.pdp = pdp

    async def get_user(self, request: web.Request) -> tuple:
        try:
            session = await get_session(request, new=False)
        except RuntimeError as ex:
            self._logger.error('QS: User Session system is not installed.')
            raise Unauthorized(
               reason="Missing User session for validating Access.",
               exception=ex
            ) from ex
        try:
            print('HERE >> ', session.decode('user'))
            user = session[SESSION_KEY]
        except KeyError:
            user = None
        return (session, user)

    async def is_allowed(self, request: web.Request):
        session, user = await self.get_user(request)
        print('USER ', user, session)
