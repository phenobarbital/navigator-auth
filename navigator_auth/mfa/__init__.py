"""Second-factor (OTP) support for BasicAuth (FEAT-106)."""

from .abstract import AbstractOTPProvider
from .exceptions import MFARefused, MFARequired, MfaSignal
from .types import MfaMode, MfaState, TenantMfaPolicy

__all__ = (
    "AbstractOTPProvider",
    "MfaState",
    "MfaMode",
    "TenantMfaPolicy",
    "MFARequired",
    "MFARefused",
    "MfaSignal",
)
