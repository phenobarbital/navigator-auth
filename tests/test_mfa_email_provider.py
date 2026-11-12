"""Unit tests for the FEAT-106 email OTP provider and callbacks."""

import asyncio
import sys
import threading
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
    assert not await provider.verify(
        None, USER, "123456", SimpleNamespace(user_id=1, email_code_hash=challenge.email_code_hash)
    )
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


@pytest.mark.asyncio
async def test_sync_callback_allows_loop_progress_and_timeout(monkeypatch) -> None:
    """A blocked synchronous delivery cannot block the loop or prevent a caller's timeout."""
    loop = asyncio.get_running_loop()
    started = asyncio.Event()
    release, finished = threading.Event(), threading.Event()

    def blocking(payload: object) -> None:
        """Model a blocked external delivery and always signal its thread has settled."""
        loop.call_soon_threadsafe(started.set)
        try:
            release.wait(2)
        finally:
            finished.set()

    monkeypatch.setattr(sys.modules[__name__], "blocking", blocking, raising=False)
    task = asyncio.create_task(notify.invoke_callback(callback("blocking"), SimpleNamespace(), label="test"))
    try:
        await asyncio.wait_for(started.wait(), 1)
        assert not finished.is_set()
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(task, 0.01)
        assert task.cancelled()
        assert not finished.is_set()
    finally:
        release.set()
        assert await asyncio.to_thread(finished.wait, 1)
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_callback_awaitables_stay_on_event_loop(monkeypatch) -> None:
    """Async callbacks and awaitables returned by sync callbacks execute on the calling loop."""
    loop_thread = threading.get_ident()
    seen = []

    async def on_loop(payload: object) -> None:
        """Record where async work executes."""
        assert threading.get_ident() == loop_thread
        seen.append(payload)

    def returns_awaitable(payload: object) -> object:
        """Return async work from a synchronous I/O callback's worker thread."""
        assert threading.get_ident() != loop_thread
        return on_loop(payload)

    monkeypatch.setattr(sys.modules[__name__], "on_loop", on_loop, raising=False)
    monkeypatch.setattr(sys.modules[__name__], "returns_awaitable", returns_awaitable, raising=False)
    payload = SimpleNamespace()
    assert await notify.invoke_callback(callback("on_loop"), payload, label="test")
    assert await notify.invoke_callback(callback("returns_awaitable"), payload, label="test")
    assert seen == [payload, payload]


def test_shared_field_helpers_preserve_none_semantics() -> None:
    """Factor reads retain explicit None, while email/security reads apply their supplied default."""
    from navigator_auth.mfa import email_otp, security, state, totp

    for user in ({"value": None}, SimpleNamespace(value=None)):
        assert state._field(user, "value", "fallback") is None
        assert totp._field(user, "value", "fallback") is None
        assert email_otp._field(user, "value", "fallback") == "fallback"
        assert security._user_field(user, "value", "fallback") == "fallback"
    assert totp._field is state._field
    assert email_otp._field is security._user_field
