"""FEAT-106 review fixes — SecondFactorGate core (spec §3 M5; AC11, AC17, AC18, AC33, D16)."""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from navigator_auth.exceptions import FailedAuth, MFARefused
from navigator_auth.backends.basic import BasicAuth
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.login import SecondFactorGate, VerifyRefused
from navigator_auth.mfa.security import LOCK_CONNECTION
from navigator_auth.mfa.services import MFA_APP_KEY, MfaServices, MfaServicesSlot
from navigator_auth.mfa.types import MfaChallenge, MfaMode, MfaState, TenantMfaPolicy

USER = {"user_id": 7, "username": "alice", "email": "alice@example.test", "password": "hash", "is_active": True}


def _record(**over) -> MfaChallenge:
    """Build a deterministic signed challenge record."""
    values = {
        "user_id": 7,
        "username": "alice",
        "providers": ("email",),
        "preferred": "email",
        "issued_at": 1.0,
        "security_version": 1,
        "context_digest": "digest",
        "email_code_hash": "code-hash",
        "signature": "signature",
    }
    values.update(over)
    return MfaChallenge(**values)


def _evaluation(**over):
    """Build an evaluation matching the default challenge record."""
    values = {
        "user_id": 7,
        "policy": TenantMfaPolicy(org_id=1, mode=MfaMode.ENFORCED, remember_days=0, enforced_at=None, enforced_by=None),
        "state": MfaState.EMAIL,
        "has_strong_factor": False,
        "providers": ("email",),
        "preferred": "email",
        "security_version": 1,
        "context_digest": "digest",
    }
    values.update(over)
    return SimpleNamespace(**values)


class FakeStore:
    """In-memory challenge store preserving the gate's observable contracts."""

    def __init__(self, record: MfaChallenge | None = None) -> None:
        self.record = record or _record()
        self.remaining = 5

    async def issue(self, user, providers, preferred, **kwargs):
        """Persist and return a deterministic challenge."""
        self.record = _record(
            providers=tuple(providers),
            preferred=preferred,
            security_version=kwargs["security_version"],
            context_digest=kwargs["context_digest"],
            email_code_hash=kwargs["email_code_hash"],
        )
        return "challenge", self.record

    async def peek(self, token: str):
        """Return the live challenge for its sole test token."""
        return self.record if token == "challenge" else None

    async def consume(self, token: str):
        """Atomically remove and return the challenge."""
        if token != "challenge" or self.record is None:
            return None
        record, self.record = self.record, None
        return record

    async def discard(self, token: str) -> None:
        """Discard the live challenge."""
        if token == "challenge":
            self.record = None

    async def register_failure(self, token: str) -> int:
        """Decrement the challenge retry budget."""
        if token != "challenge" or self.record is None:
            return -1
        self.remaining -= 1
        return self.remaining


class FakeLock:
    """user_lock stand-in that publishes LOCK_CONNECTION like TASK-171's real lock."""

    def __init__(self, fail: bool = False) -> None:
        self.conn = object()
        self.fail = fail

    @asynccontextmanager
    async def user_lock(self, user_id: int):
        """Yield the lock connection or raise the configured storage failure."""
        if self.fail:
            raise MfaStorageError("lock unavailable")
        context_token = LOCK_CONNECTION.set(self.conn)
        try:
            yield self.conn
        finally:
            LOCK_CONNECTION.reset(context_token)


def _services(**over) -> MfaServices:
    """Build gate collaborators as in-memory fakes."""
    backend = SimpleNamespace(_idp=SimpleNamespace(user_from_id=AsyncMock(return_value=dict(USER))))
    services = MfaServices(backend=backend, available=True)
    services.store = over.pop("store", FakeStore())
    services.security = over.pop("security", FakeLock())
    services.user_limiter = over.pop("user_limiter", SimpleNamespace(check=AsyncMock(return_value=True)))
    services.ip_limiter = over.pop("ip_limiter", SimpleNamespace(check=AsyncMock(return_value=True)))
    services.trusted_devices = over.pop(
        "trusted_devices", SimpleNamespace(consume_and_rotate=AsyncMock(return_value=None), issue=AsyncMock())
    )
    services.backup_codes = over.pop("backup_codes", SimpleNamespace(consume=AsyncMock(return_value=True)))
    services.providers = over.pop(
        "providers",
        {
            "email": SimpleNamespace(
                challenge=AsyncMock(return_value={"code_hash": "code-hash"}), verify=AsyncMock(return_value=True)
            )
        },
    )
    services.evaluate = over.pop("evaluate", AsyncMock(return_value=_evaluation()))
    for key, value in over.items():
        setattr(services, key, value)
    return services


def _request(**over):
    """Build the request attributes used by the gate."""
    values = {"cookies": {}, "remote": "127.0.0.1"}
    values.update(over)
    return SimpleNamespace(**values)


@pytest.mark.asyncio
async def test_login_refused_when_password_changed_mid_flight():
    """AC17: hash drift refuses before issuer or device rotation."""
    services = _services()
    services.backend._idp.user_from_id = AsyncMock(return_value={**USER, "password": "new-hash"})
    issue = AsyncMock()
    with pytest.raises(FailedAuth, match="credentials_changed") as exc:
        await SecondFactorGate(services).decide(_request(cookies={"nav_mfa_device": "device"}), USER, issue)
    assert exc.value.status == 401
    issue.assert_not_awaited()
    services.trusted_devices.consume_and_rotate.assert_not_awaited()


@pytest.mark.asyncio
async def test_trusted_device_session_issued_under_lock():
    """AC18: a trusted-device issuer runs with the lock connection published."""
    services = _services(
        evaluate=AsyncMock(return_value=_evaluation(has_strong_factor=True, policy=SimpleNamespace(remember_days=2)))
    )
    services.trusted_devices.consume_and_rotate = AsyncMock(return_value=(7, "replacement"))

    async def issue(user, extra):
        assert LOCK_CONNECTION.get() is services.security.conn
        assert extra["amr"] == ["pwd", "trusted_device"]
        return "session"

    result = await SecondFactorGate(services).decide(_request(cookies={"nav_mfa_device": "old"}), USER, issue)
    assert result.session == "session"
    assert result.device == {"token": "replacement", "max_age": 172800}


@pytest.mark.asyncio
async def test_no_factor_owed_issued_under_lock_with_empty_extra():
    """AC18: no-factor issuer receives an empty extra envelope while locked."""
    services = _services(evaluate=AsyncMock(return_value=_evaluation(state=MfaState.NONE)))

    async def issue(user, extra):
        assert LOCK_CONNECTION.get() is services.security.conn
        assert extra == {}
        return "session"

    assert (await SecondFactorGate(services).decide(_request(), USER, issue)).session == "session"


@pytest.mark.asyncio
async def test_basic_adapter_issues_session_inside_gate():
    """AC10/AC18: BasicAuth's adapter invokes its issuer while the user lock is held."""
    services = _services(evaluate=AsyncMock(return_value=_evaluation(state=MfaState.NONE)))
    app = {MFA_APP_KEY: MfaServicesSlot(services)}
    request = _request(app=app)
    backend = BasicAuth.__new__(BasicAuth)
    backend.userid_attribute = "user_id"
    backend.pwd_atrribute = "password"

    async def open_session(_request, _user, extra=None):
        assert LOCK_CONNECTION.get() is services.security.conn
        assert extra is None
        return {"token": "session"}

    backend.open_session = open_session

    result = await backend._second_factor(request, USER)

    assert result == {"token": "session"}


@pytest.mark.asyncio
async def test_decide_owed_factor_returns_challenge():
    """An owed email factor sends once and returns the expected challenge envelope."""
    services = _services()
    result = await SecondFactorGate(services).decide(_request(), USER, AsyncMock())
    assert result.challenge is not None
    assert result.challenge.token == "challenge"
    assert result.challenge.providers == ("email",)
    services.providers["email"].challenge.assert_awaited_once()


@pytest.mark.asyncio
async def test_decide_lock_timeout_is_mfa_unavailable():
    """AC11: a lock storage failure maps both gate paths to unavailable MFA."""
    services = _services(security=FakeLock(fail=True))
    with pytest.raises(MFARefused) as exc:
        await SecondFactorGate(services).decide(_request(), USER, AsyncMock())
    assert (exc.value.code, exc.value.status) == ("mfa_unavailable", 503)
    with pytest.raises(VerifyRefused) as exc:
        await SecondFactorGate(services).verify(_request(), "challenge", "email", "code", AsyncMock())
    assert (exc.value.code, exc.value.status) == ("mfa_unavailable", 503)


@pytest.mark.asyncio
async def test_email_gate_verify_and_totp_uses_lock_connection():
    """AC33: email receives no conn while TOTP receives the lock connection."""
    services = _services()
    await SecondFactorGate(services).verify(
        _request(), "challenge", "email", "correct", AsyncMock(return_value="session")
    )
    assert "conn" not in services.providers["email"].verify.await_args.kwargs

    record = _record(providers=("totp",), preferred="totp")
    services = _services(
        store=FakeStore(record), providers={"totp": SimpleNamespace(verify=AsyncMock(return_value=True))}
    )
    services.evaluate = AsyncMock(return_value=_evaluation(providers=("totp",), preferred="totp"))
    await SecondFactorGate(services).verify(
        _request(), "challenge", "totp", "correct", AsyncMock(return_value="session")
    )
    assert services.providers["totp"].verify.await_args.kwargs["conn"] is services.security.conn


@pytest.mark.asyncio
async def test_backup_consumed_before_lock_and_last_code_verifies():
    """D16/D5: backup consumption precedes the lock and the last code remains valid."""
    record = _record(providers=("backup",), preferred="backup")
    services = _services(store=FakeStore(record), providers={"backup": SimpleNamespace()})
    services.evaluate = AsyncMock(return_value=_evaluation(providers=(), preferred=None))

    async def consume(user_id, code):
        assert LOCK_CONNECTION.get() is None
        return True

    services.backup_codes.consume = AsyncMock(side_effect=consume)
    assert (
        await SecondFactorGate(services).verify(
            _request(), "challenge", "backup", "last", AsyncMock(return_value="session")
        )
    ).session == "session"


@pytest.mark.asyncio
async def test_verify_refusals_keep_handler_envelopes():
    """Invalid input, absent challenges, failures, and rate limits preserve their response shapes."""
    gate = SecondFactorGate(_services())
    with pytest.raises(VerifyRefused) as exc:
        await gate.verify(_request(), "", "email", "code", AsyncMock())
    assert (exc.value.code, exc.value.status) == ("invalid_request", 400)

    with pytest.raises(VerifyRefused) as exc:
        await gate.verify(_request(), "missing", "email", "code", AsyncMock())
    assert (exc.value.code, exc.value.status) == ("invalid_challenge", 401)

    services = _services(evaluate=AsyncMock(return_value=_evaluation(context_digest="new-digest")))
    with pytest.raises(VerifyRefused) as exc:
        await SecondFactorGate(services).verify(_request(), "challenge", "email", "code", AsyncMock())
    assert (exc.value.code, exc.value.status) == ("stale_challenge", 401)

    services = _services()
    services.providers["email"].verify = AsyncMock(return_value=False)
    with pytest.raises(VerifyRefused) as exc:
        await SecondFactorGate(services).verify(_request(), "challenge", "email", "bad", AsyncMock())
    assert (exc.value.code, exc.value.status, exc.value.extra) == ("invalid_code", 401, {"attempts_remaining": 4})

    services = _services(user_limiter=SimpleNamespace(check=AsyncMock(return_value=False)))
    with pytest.raises(VerifyRefused) as exc:
        await SecondFactorGate(services).verify(_request(), "challenge", "email", "code", AsyncMock())
    assert (exc.value.code, exc.value.status) == ("rate_limited", 429)


@pytest.mark.asyncio
async def test_gate_logs_no_secrets(caplog):
    """Dependency failures log only their error type, never the code or tokens."""
    secret_token, secret_code, secret_device = "challenge-secret", "code-secret", "device-secret"
    services = _services()
    services.store.peek = AsyncMock(side_effect=RuntimeError(secret_token))
    with pytest.raises(VerifyRefused):
        await SecondFactorGate(services).verify(
            _request(cookies={"nav_mfa_device": secret_device}), secret_token, "email", secret_code, AsyncMock()
        )
    text = caplog.text
    assert secret_token not in text
    assert secret_code not in text
    assert secret_device not in text
