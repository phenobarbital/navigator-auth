"""AbstractOTPProvider — the second-factor contract (FEAT-106)."""

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any, Optional

from aiohttp import web

from .types import EnrollmentAuthorization, MfaChallenge


class AbstractOTPProvider(ABC):
    """A second factor that cannot mint a session on its own."""

    _provider_name: str
    _is_strong: bool

    @property
    def name(self) -> str:
        """Return the provider name."""
        return self._provider_name

    @property
    def is_strong(self) -> bool:
        """Return whether this provider is a strong factor."""
        return self._is_strong

    @abstractmethod
    async def is_enrolled(self, user: Mapping) -> bool:
        """Return whether the user can answer this provider now."""

    @abstractmethod
    async def start_enrollment(self, user: Mapping, authorization: EnrollmentAuthorization) -> dict:
        """Return provider-specific enrolment data."""

    @abstractmethod
    async def confirm_enrollment(
        self, user: Mapping, code: str, enrollment_token: str, session_id: str, *, conn: Any = None
    ) -> bool:
        """Confirm enrolment inside the caller's optional transaction."""

    @abstractmethod
    async def challenge(self, request: web.Request, user: Mapping) -> dict:
        """Deliver or prepare a provider challenge."""

    @abstractmethod
    async def verify(
        self, request: web.Request, user: Mapping, code: str, challenge: Optional[MfaChallenge] = None
    ) -> bool:
        """Return whether the supplied code is valid."""

    @abstractmethod
    async def disenroll(self, user: Mapping, *, conn: Any = None) -> None:
        """Remove enrolment inside the caller's optional transaction."""
