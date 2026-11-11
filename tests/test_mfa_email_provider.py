"""Unit tests for the FEAT-106 email OTP provider and callbacks."""

from types import SimpleNamespace

import pytest

from navigator_auth.mfa.email_otp import EmailOTPProvider, hash_code, mask_email
from navigator_auth.mfa import notify

SECRET = b"test-mfa-email-secret"
USER = {"user_id": 4242, "username": "otp_user", "email": "otp_user@example.com", "display_name": "Otp User"}
CAPTURED = []


def capture(payload):
    CAPTURED.append(payload)


async def capture_async(payload):
    CAPTURED.append(payload)


def explode(payload):
    raise RuntimeError(f"smtp down while sending {payload.code}")


@pytest.fixture(autouse=True)
def reset():
    CAPTURED.clear()


def callback(name):
    return f"{__name__}.{name}"


@pytest.mark.asyncio
async def test_challenge_hands_code_to_callback():
    provider = EmailOTPProvider(secret=SECRET, callback=callback("capture"))
    result = await provider.challenge(None, USER)
    payload = CAPTURED[0]
    assert result == {"code_hash": hash_code(payload.code, SECRET)}
    assert payload.found is True
    assert len(payload.code) == 6 and payload.code.isdigit()
    assert payload.expires_at.tzinfo is not None


@pytest.mark.asyncio
async def test_challenge_shape_is_stable_for_missing_address_and_callback_failure(caplog):
    provider = EmailOTPProvider(secret=SECRET, callback=callback("capture"))
    known = await provider.challenge(None, USER)
    missing = await provider.challenge(None, {"user_id": 1, "username": "unknown"})
    failed = await EmailOTPProvider(secret=SECRET, callback=callback("explode")).challenge(None, USER)
    assert all(set(value) == {"code_hash"} and len(value["code_hash"]) == 64 for value in (known, missing, failed))
    assert CAPTURED[-1].found is False
    assert CAPTURED[-1].email == ""
    assert "RuntimeError" in caplog.text


@pytest.mark.asyncio
async def test_async_and_missing_callbacks(caplog):
    await EmailOTPProvider(secret=SECRET, callback=callback("capture_async")).challenge(None, USER)
    await EmailOTPProvider(secret=SECRET, callback=None).challenge(None, USER)
    assert CAPTURED
    assert "no otp-email callback" in caplog.text


@pytest.mark.asyncio
async def test_verify_accepts_matching_code():
    provider = EmailOTPProvider(secret=SECRET, callback=callback("capture"))
    await provider.challenge(None, USER)
    code = CAPTURED[0].code
    challenge = SimpleNamespace(user_id=USER["user_id"], email_code_hash=hash_code(code, SECRET))
    assert await provider.verify(None, USER, code, challenge)


@pytest.mark.asyncio
async def test_verify_rejects_wrong_missing_or_malformed():
    provider = EmailOTPProvider(secret=SECRET, callback=callback("capture"))
    challenge = SimpleNamespace(user_id=USER["user_id"], email_code_hash=hash_code("123456", SECRET))
    assert not await provider.verify(None, USER, "000000", challenge)
    assert not await provider.verify(None, USER, "123456", None)
    assert not await provider.verify(None, USER, "123456", SimpleNamespace(user_id=1, email_code_hash=challenge.email_code_hash))
    assert not await provider.verify(None, USER, "12a456", challenge)
    assert not await provider.verify(None, USER, "1234567", challenge)


def test_mask_email_and_notify_model():
    assert mask_email("jane@example.com") == "j***@example.com"
    assert mask_email("bad") == "***"


@pytest.mark.asyncio
async def test_notify_security_event_uses_configured_callback(monkeypatch):
    monkeypatch.setattr(notify.auth_conf, "AUTH_MFA_NOTIFY_CALLBACK", callback("capture"))
    notice = SimpleNamespace(event="disenrolled", username="otp_user")
    await notify.invoke_callback(callback("capture"), notice, label="security-notice")
    assert CAPTURED == [notice]
