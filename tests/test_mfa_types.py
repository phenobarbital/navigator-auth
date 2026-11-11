"""FEAT-106 TASK-129 — MFA models, exceptions, provider ABC, settings."""

import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from navigator_auth import conf
from navigator_auth.exceptions import AuthException, MFARefused, MFARequired, MfaSignal
from navigator_auth.mfa import AbstractOTPProvider, MfaMode, MfaState, TenantMfaPolicy
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.types import MfaChallenge, OtpNotificationPayload, trusted_cookie_kwargs

MFA_PKG = Path(__file__).resolve().parents[1] / "navigator_auth" / "mfa"
FORBIDDEN = re.compile(r"remember\(|create_token|open_session")


def test_mfa_models_frozen_and_redacted():
    """Models reject mutation and extras, while redacting values with low entropy."""
    now = datetime.now(timezone.utc)
    policy = TenantMfaPolicy(
        org_id=1,
        mode=MfaMode.OPTIONAL,
        remember_days=0,
        enforced_at=None,
        enforced_by=None,
    )
    with pytest.raises(ValidationError):
        policy.org_id = 2
    with pytest.raises(ValidationError):
        TenantMfaPolicy(
            org_id=1,
            mode=MfaMode.OFF,
            remember_days=0,
            enforced_at=None,
            enforced_by=None,
            extra_field=1,
        )
    payload = OtpNotificationPayload(
        email="user@example.test", display_name="User", username="user", code="493817", expires_at=now, found=True
    )
    challenge = MfaChallenge(
        user_id=1,
        username="user",
        providers=("email",),
        preferred="email",
        issued_at=1.0,
        security_version=1,
        context_digest="digest",
        email_code_hash="hash",
        signature="signature",
    )
    assert "493817" not in repr(payload)
    assert "493817" not in str(payload)
    assert "hash" not in repr(challenge)
    assert "hash" not in str(challenge)


def test_notification_payload_repr_redacted():
    """The callback payload representation does not reveal the code."""
    payload = OtpNotificationPayload(
        email="user@example.test",
        display_name="User",
        username="user",
        code="493817",
        expires_at=datetime.now(timezone.utc),
        found=True,
    )
    assert "493817" not in repr(payload)


def test_mfa_required_payload_has_no_token():
    """Challenge exception keeps the token out of exception diagnostics."""
    err = MFARequired("chal-tok", ["email"], "email", 300)
    assert set(err.payload()) == {"mfa_required", "challenge", "providers", "preferred", "expires_in"}
    assert "chal-tok" not in str(err)
    assert "chal-tok" not in repr(err)
    assert "chal-tok" not in err.args
    assert err.status == 401


def test_mfa_signal_hierarchy():
    """Signals are handled separately from internal storage errors."""
    assert issubclass(MFARequired, MfaSignal)
    assert issubclass(MFARefused, MfaSignal)
    assert issubclass(MfaSignal, AuthException)
    assert not issubclass(MfaStorageError, AuthException)


def test_mfa_refused_payload_and_status():
    """Refusals expose the safe code and their supplied status."""
    err = MFARefused("mfa_unavailable", status=503)
    assert err.payload() == {"error": "mfa_unavailable", "message": "mfa_unavailable"}
    assert err.status == 503


def test_abstract_provider_contract():
    """The provider ABC requires every factor operation."""
    class Provider(AbstractOTPProvider):
        _provider_name = "email"
        _is_strong = False

        async def is_enrolled(self, user):
            return True

        async def start_enrollment(self, user, authorization):
            return {}

        async def confirm_enrollment(self, user, code, enrollment_token, session_id, *, conn=None):
            return True

        async def challenge(self, request, user):
            return {}

        async def verify(self, request, user, code, challenge=None):
            return True

        async def disenroll(self, user, *, conn=None):
            return None

    with pytest.raises(TypeError):
        AbstractOTPProvider()
    provider = Provider()
    assert provider.name == "email"
    assert provider.is_strong is False


def test_trusted_cookie_kwargs():
    """Trusted-device cookies use exactly the required security attributes."""
    assert trusted_cookie_kwargs(60) == {
        "max_age": 60,
        "httponly": True,
        "secure": True,
        "samesite": "Lax",
        "path": "/",
    }
    with pytest.raises(ValueError):
        trusted_cookie_kwargs(0)
    with pytest.raises(ValueError):
        trusted_cookie_kwargs(-1)


def test_settings_defaults_and_types():
    """Settings preserve their declared defaults and secret coercion contract."""
    assert MfaState.EMAIL == "email"
    assert isinstance(conf.AUTH_BASIC_2FA_ENABLED, bool)
    assert conf.AUTH_OTP_SECRET is None or isinstance(conf.AUTH_OTP_SECRET, bytes)
    assert conf.AUTH_OTP_SECRET != b""
    assert all(
        isinstance(value, int)
        for value in (
            conf.AUTH_OTP_CHALLENGE_TTL,
            conf.AUTH_OTP_MAX_ATTEMPTS,
            conf.AUTH_OTP_CODE_LENGTH,
            conf.AUTH_MFA_BACKUP_CODE_COUNT,
            conf.AUTH_MFA_BACKUP_CODE_LENGTH,
        )
    )


def test_no_session_minting_text_in_mfa_package():
    """D5 forbids provider references to session-minting methods."""
    offenders = [
        f"{path.relative_to(MFA_PKG.parent.parent)}:{n}"
        for path in sorted(MFA_PKG.rglob("*"))
        if path.is_file() and path.suffix in {".py", ".sql"}
        for n, line in enumerate(path.read_text().splitlines(), 1)
        if FORBIDDEN.search(line)
    ]
    assert offenders == [], offenders
