"""
Abstract Class for Authorization Policies and decorators
"""
from abc import ABC, abstractmethod
from aiohttp import web


class AuthorizationPolicy(ABC):
    @abstractmethod
    async def permits(self, identity, permission, context=None):
        """Check user permissions.
        Return True if the identity is allowed the permission in the
        current context, else return False.
        """

    @abstractmethod
    async def is_authorized(self, identity):
        """Retrieve authorized user id.
        Return the user_id of the user identified by the identity
        or 'None' if no user exists related to the identity.
        """

class BaseAuthzHandler(ABC):
    """ Abstract handler for Authorization Middleware."""
    @abstractmethod
    async def check_authorization(self, request: web.Request) -> bool:
        pass
