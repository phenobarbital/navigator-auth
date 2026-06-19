"""Pluggable token strategies for the unified auth middleware."""
from abc import ABC, abstractmethod
from typing import Any
from aiohttp import web


class TokenStrategy(ABC):
    """Base class for authentication token strategies.

    Each strategy encapsulates three concerns:
    - How to extract a token from the request
    - How to validate/decode the token
    - When to enforce authentication
    """

    @abstractmethod
    def extract(self, request: web.Request) -> tuple[str | None, str | None]:
        """Extract token and scheme from the request.

        Returns:
            (token, scheme) tuple. Both None if no credentials found.
        """

    @abstractmethod
    async def validate(self, token: str, scheme: str | None, app: web.Application) -> Any:
        """Validate/decode a token and return the payload.

        Raises:
            web.HTTPForbidden or web.HTTPUnauthorized on invalid token.
        """

    def should_enforce(self, request: web.Request, protected_routes: tuple) -> bool:
        """Whether auth is required for this request."""
        return request.path in protected_routes
