"""MFA exceptions (FEAT-106)."""

from navigator_auth.exceptions import MFARefused, MFARequired, MfaSignal

__all__ = ("MfaSignal", "MFARequired", "MFARefused", "MfaStorageError")


class MfaStorageError(Exception):
    """Internal error from an MFA dependency, never shown to a client."""
