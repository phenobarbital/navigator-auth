"""FEAT-106 MFA data structures — frozen Pydantic v2 models, no I/O."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

MFA_VAULT_PREFIX = "mfa:"
PROVIDER_TOTP, PROVIDER_EMAIL, PROVIDER_BACKUP = "totp", "email", "backup"
AMR_PASSWORD, AMR_TRUSTED_DEVICE = "pwd", "trusted_device"
AMR_BY_PROVIDER = {"email": "otp", "totp": "totp", "backup": "backup"}
NO_TENANT_ORG_ID = 0
TRUSTED_COOKIE = "nav_mfa_device"
MFA_DEVICE_TOKEN_KEY = "_mfa_trusted_device"


class MfaModel(BaseModel):
    """Base frozen model for MFA values."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class MfaState(str, Enum):
    """Per-user second-factor state."""

    NONE = "none"
    EMAIL = "email"
    TOTP = "totp"


class MfaMode(str, Enum):
    """Per-tenant policy mode."""

    OFF = "off"
    OPTIONAL = "optional"
    ENFORCED = "enforced"


MODE_STRICTNESS = {MfaMode.OFF: 0, MfaMode.OPTIONAL: 1, MfaMode.ENFORCED: 2}


class TenantMfaPolicy(MfaModel):
    """Second-factor policy for a tenant."""

    org_id: int
    mode: MfaMode
    remember_days: int
    enforced_at: Optional[datetime]
    enforced_by: Optional[str]


class MfaChallenge(MfaModel):
    """Redis-persisted challenge record keyed by a token digest."""

    user_id: int
    username: str
    providers: tuple[str, ...]
    preferred: str
    issued_at: float
    security_version: int
    context_digest: str
    email_code_hash: Optional[str] = Field(default=None, repr=False)
    signature: str


class OtpNotificationPayload(MfaModel):
    """Hand-off to the configured e-mail OTP callback."""

    email: str
    display_name: str
    username: str
    code: str = Field(repr=False)
    expires_at: datetime
    found: bool


class EnrollmentAuthorization(MfaModel):
    """Internal proof constructed after fresh authentication."""

    user_id: int
    session_id: str = Field(repr=False)
    security_version: int
    context_digest: str
    expires_at: datetime


class TrustedDevice(MfaModel):
    """Trusted-device record."""

    user_id: int
    token_hash: str
    label: str
    family_id: str
    expires_at: datetime
    last_used_at: Optional[datetime]
    revoked_at: Optional[datetime]


class PendingEnrollment(MfaModel):
    """Redis-persisted pending TOTP enrolment."""

    user_id: int
    session_hash: str
    security_version: int
    sealed_seed: str = Field(repr=False)
    issued_at: float
    signature: str


class MfaAuditEntry(MfaModel):
    """One durable MFA audit row."""

    actor_user_id: Optional[int]
    target_user_id: Optional[int]
    org_id: Optional[int]
    action: str
    old_state: Optional[str] = None
    new_state: Optional[str] = None
    method: Optional[str] = None
    request_id: Optional[str] = None
    outcome: str
    detail: dict = Field(default_factory=dict)


class MfaSecurityNotice(MfaModel):
    """Notification hand-off for a factor downgrade."""

    email: Optional[str]
    display_name: str
    username: str
    event: str
    occurred_at: datetime
    actor: Optional[str] = None


class MfaEvaluation(MfaModel):
    """Consistent snapshot used to issue and re-validate a challenge."""

    user_id: int
    policy: TenantMfaPolicy
    memberships: tuple[int, ...]
    state: MfaState
    has_strong_factor: bool
    totp_confirmed: bool
    providers: tuple[str, ...]
    preferred: Optional[str]
    security_version: int
    context_digest: str


def trusted_cookie_kwargs(max_age: int) -> dict:
    """Return secure cookie kwargs for a positive trusted-device lifetime."""
    if max_age <= 0:
        raise ValueError("max_age must be positive")
    return {
        "max_age": int(max_age),
        "httponly": True,
        "secure": True,
        "samesite": "Lax",
        "path": "/",
    }
