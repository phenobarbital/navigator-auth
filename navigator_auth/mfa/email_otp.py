"""E-mail OTP — the zero-enrolment floor (FEAT-106, spec Module 4)."""

import asyncio
import hashlib
import hmac
import logging
import secrets
import string
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from aiohttp import web

from navigator_auth import conf as auth_conf

from .abstract import AbstractOTPProvider
from .notify import invoke_callback
from .types import PROVIDER_EMAIL, EnrollmentAuthorization, MfaChallenge, OtpNotificationPayload

logger = logging.getLogger("navigator.mfa.email")


def hash_code(code: str, secret: bytes) -> str:
    """Return the keyed SHA-256 digest of an OTP code."""
    return hmac.new(secret, b"mfa-email-otp|" + code.strip().encode("utf-8"), hashlib.sha256).hexdigest()


def mask_email(email: str) -> str:
    """Mask an address while retaining its first local-part character and domain."""
    local, separator, domain = email.rpartition("@")
    if not separator or not local or not domain:
        return "***"
    return f"{local[0]}***@{domain}"


def _field(user: Any, name: str, default: Any = None) -> Any:
    """Read a user field from mapping or model-like records."""
    try:
        value = user[name]
    except (KeyError, TypeError, IndexError):
        value = getattr(user, name, default)
    return default if value is None else value


def _usable_email(user: Any) -> Optional[str]:
    """Return a stripped, structurally usable user email address."""
    value = _field(user, "email")
    if value is None:
        return None
    address = str(value).strip()
    if address.count("@") != 1:
        return None
    local, domain = address.split("@")
    return address if local and domain else None


class EmailOTPProvider(AbstractOTPProvider):
    """Zero-enrolment, weak second factor."""

    _provider_name = PROVIDER_EMAIL
    _is_strong = False

    def __init__(
        self,
        *,
        secret: bytes,
        callback: Optional[str] = auth_conf.AUTH_OTP_EMAIL_CALLBACK,
        code_length: int = auth_conf.AUTH_OTP_CODE_LENGTH,
        ttl: int = auth_conf.AUTH_OTP_CHALLENGE_TTL,
    ) -> None:
        self._secret = secret
        self._callback = callback
        self._code_length = code_length
        self._ttl = ttl

    def _new_code(self) -> str:
        return "".join(secrets.choice(string.digits) for _ in range(self._code_length))

    async def is_enrolled(self, user: Mapping) -> bool:
        """Return whether the user has a usable email address."""
        return _usable_email(user) is not None

    async def start_enrollment(self, user: Mapping, authorization: EnrollmentAuthorization) -> dict:
        """Return the masked implicit enrollment address."""
        address = _usable_email(user)
        return {"email": mask_email(address) if address else None}

    async def confirm_enrollment(
        self, user: Mapping, code: str, enrollment_token: str, session_id: str, *, conn: Any = None
    ) -> bool:
        """Reject confirmation because email enrollment is implicit."""
        return False

    async def challenge(self, request: web.Request, user: Mapping) -> dict:
        """Generate and hand off an email code, returning only its keyed hash."""
        code = self._new_code()
        address = _usable_email(user)
        payload = OtpNotificationPayload(
            email=address or "",
            display_name=str(_field(user, "display_name") or _field(user, "username") or ""),
            username=str(_field(user, "username") or ""),
            code=code,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self._ttl),
            found=address is not None,
        )
        # The send runs while the caller may hold the per-user advisory lock and its transaction, so a slow
        # delivery backend must not stall every other transition for the user: bound it by the lock timeout.
        # A timeout is contained like any other callback failure; the HTTP response stays identical.
        try:
            await asyncio.wait_for(
                invoke_callback(self._callback, payload, label="otp-email"),
                timeout=float(auth_conf.AUTH_MFA_LOCK_TIMEOUT),
            )
        except asyncio.TimeoutError:
            logger.warning("MFA e-mail OTP callback timed out after %ss", auth_conf.AUTH_MFA_LOCK_TIMEOUT)
        return {"code_hash": hash_code(code, self._secret)}

    async def verify(
        self, request: web.Request, user: Mapping, code: str, challenge: Optional[MfaChallenge] = None
    ) -> bool:
        """Constant-time verify a supplied code against the challenge hash."""
        if challenge is None or not challenge.email_code_hash:
            return False
        try:
            if int(challenge.user_id) != int(_field(user, "user_id")):
                return False
        except (TypeError, ValueError):
            return False
        if not isinstance(code, str) or len(code.strip()) != self._code_length or not code.strip().isdigit():
            return False
        return secrets.compare_digest(hash_code(code, self._secret), challenge.email_code_hash)

    async def disenroll(self, user: Mapping, *, conn: Any = None) -> None:
        """Leave the implicit email factor unchanged."""
        return None
