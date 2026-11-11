"""Security-transition semantics for FEAT-106 credential changes."""

from contextlib import asynccontextmanager

import pytest

from navigator_auth.mfa.events import SECURITY_EVENTS, security_transition
from navigator_auth.mfa.exceptions import MfaStorageError


@pytest.mark.asyncio
async def test_security_transition_without_services_requires_authdb():
    """M3 changes no MFA from yielding None to an authdb transaction, failing closed without one."""
    ran = []
    with pytest.raises(MfaStorageError):
        async with security_transition({}, 42, "password_change"):
            ran.append(True)
    assert ran == []


@pytest.mark.asyncio
async def test_security_transition_rejects_unknown_event():
    """Only the contract's event names are accepted."""
    with pytest.raises(ValueError):
        async with security_transition({}, 42, "unknown"):
            pass


class _FakeLock:
    """Async lock context recording how it was exited."""

    def __init__(self, exits: list, fail_enter: bool = False):
        self._exits = exits
        self._fail_enter = fail_enter

    async def __aenter__(self):
        if self._fail_enter:
            raise RuntimeError("lock unavailable")
        return "conn"

    async def __aexit__(self, exc_type, exc, tb):
        self._exits.append(exc_type)
        return False


def _fake_services(monkeypatch, *, fail_enter=False, fail_bump=False):
    """Install fake MFA services and return the call log and lock exit log."""
    calls: list = []
    exits: list = []

    class _Security:
        def user_lock(self, user_id):
            return _FakeLock(exits, fail_enter)

        async def bump_version(self, conn, user_id):
            if fail_bump:
                raise RuntimeError("bump failed")
            calls.append("bump")

        async def write_audit(self, conn, entry):
            calls.append("audit")

    class _Devices:
        async def revoke_all(self, user_id, event, conn=None):
            calls.append("revoke")

    services = type("S", (), {"available": True, "security": _Security(), "trusted_devices": _Devices()})()
    @asynccontextmanager
    async def _lease(app):
        yield services

    monkeypatch.setattr("navigator_auth.mfa.events.mfa_services_lease", _lease)
    return calls, exits


@pytest.mark.asyncio
async def test_security_transition_propagates_body_exception(monkeypatch):
    """A failing credential change must never look like success (bump/revoke/audit skipped)."""
    calls, exits = _fake_services(monkeypatch)
    with pytest.raises(RuntimeError, match="body failed"):
        async with security_transition({}, 42, "password_change"):
            raise RuntimeError("body failed")
    assert calls == []
    assert exits == [RuntimeError]


@pytest.mark.asyncio
async def test_security_transition_success_bumps_revokes_and_audits(monkeypatch):
    """A successful change bumps the version, revokes devices and writes the audit row once."""
    calls, exits = _fake_services(monkeypatch)
    async with security_transition({}, 42, "password_change") as conn:
        assert conn == "conn"
    assert calls == ["bump", "revoke", "audit"]
    assert exits == [None]


@pytest.mark.asyncio
async def test_security_transition_lock_failure_fails_closed(monkeypatch):
    """When the lock cannot be taken the body must not run unprotected."""
    _fake_services(monkeypatch, fail_enter=True)
    ran = []
    with pytest.raises(RuntimeError, match="lock unavailable"):
        async with security_transition({}, 42, "password_change"):
            ran.append(True)
    assert ran == []


@pytest.mark.asyncio
async def test_security_transition_post_body_failure_is_not_swallowed(monkeypatch):
    """A failing version bump after the change must surface instead of reporting success."""
    _, exits = _fake_services(monkeypatch, fail_bump=True)
    with pytest.raises(RuntimeError, match="bump failed"):
        async with security_transition({}, 42, "password_change"):
            pass
    assert exits == [RuntimeError]


def test_security_events_are_complete():
    """The exported event set includes wired and future global logout transitions."""
    assert SECURITY_EVENTS == frozenset(
        {
            "password_change",
            "password_reset",
            "recovery_completion",
            "passkey_registered",
            "passkey_removed",
            "global_logout",
        }
    )
