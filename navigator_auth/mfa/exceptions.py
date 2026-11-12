"""MFA exceptions (FEAT-106)."""

from navigator_auth.exceptions import MFARefused, MFARequired, MfaSignal

__all__ = ("MfaSignal", "MFARequired", "MFARefused", "MfaStorageError", "MfaUnavailable")


class MfaStorageError(Exception):
    """Internal error from an MFA dependency, never shown to a client."""


class MfaUnavailable(MfaStorageError):
    """2FA is enabled but MFA services are unavailable; callers answer 503 mfa_unavailable."""
