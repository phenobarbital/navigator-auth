"""FEAT-106 code-review follow-ups: lock-acquire cancellation, deferred gate refusal, target transaction."""

import asyncio
from types import SimpleNamespace

import pytest

from navigator_auth.exceptions import MFARefused
from navigator_auth.mfa.login import SecondFactorGate
from navigator_auth.mfa.security import advisory_user_lock
from navigator_auth.mfa.targets import MfaSecretTarget
from navigator_auth.mfa.types import MfaState


class _SlowPool:
    """A pool whose acquire() completes only when ``gate`` is set; records connection exits."""

    def __init__(self) -> None:
        self.gate = asyncio.Event()
        self.closed = asyncio.Event()

    async def acquire(self):
        await self.gate.wait()
        pool = self

        class _Conn:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                pool.closed.set()

        return _Conn()


@pytest.mark.asyncio
async def test_lock_acquire_released_when_caller_cancelled():
    """A caller cancelled while the pool acquire is pending must not leak the connection."""
    pool = _SlowPool()

    async def _use():
        async with advisory_user_lock(pool, 7, timeout=30):
            pass

    task = asyncio.create_task(_use())
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    pool.gate.set()  # the shielded acquire now completes after the caller is gone
    await asyncio.wait_for(pool.closed.wait(), timeout=2)


class _LockRecorder:
    """user_lock() stand-in recording whether the scope exited normally (commit) or by exception."""

    def __init__(self) -> None:
        self.committed = None

    def user_lock(self, uid):
        recorder = self

        class _Scope:
            async def __aenter__(self):
                return object()

            async def __aexit__(self, exc_type, exc, tb):
                recorder.committed = exc_type is None
                return False

        return _Scope()


@pytest.mark.asyncio
async def test_gate_refusal_leaves_lock_scope_normally():
    """no_factor_available must be raised AFTER the lock scope commits (replay revocation survives)."""
    recorder = _LockRecorder()

    async def _user_from_id(uid, conn=None):
        return {"user_id": uid, "password": "h", "is_active": True}

    async def _evaluate(user, conn=None):
        return SimpleNamespace(
            state=MfaState.EMAIL,
            providers=[],
            preferred=None,
            has_strong_factor=False,
            policy=SimpleNamespace(remember_days=0),
            user_id=1,
        )

    services = SimpleNamespace(
        security=recorder,
        backend=SimpleNamespace(_idp=SimpleNamespace(user_from_id=_user_from_id)),
        evaluate=_evaluate,
        trusted_devices=None,
    )
    gate = SecondFactorGate(services)
    request = SimpleNamespace(cookies={}, remote="127.0.0.1")
    with pytest.raises(MFARefused) as err:
        await gate.decide(request, {"user_id": 1, "password": "h"}, lambda *_: None)
    assert err.value.code == "no_factor_available"
    assert recorder.committed is True


@pytest.mark.asyncio
async def test_mfa_target_transaction_supports_asyncdb_style_connections():
    """asyncdb drivers return an already-started awaitable from transaction(); commit/rollback exist."""
    events = []

    class _Driver:
        def transaction(self):
            async def _start():
                events.append("start")
                return self

            return _start()

        async def commit(self):
            events.append("commit")

        async def rollback(self):
            events.append("rollback")

        async def close(self):
            events.append("close")

        async def release(self, *args, **kwargs):
            events.append("release")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class _Pool:
        async def acquire(self):
            return _Driver()

    target = MfaSecretTarget(_Pool())
    async with target.transaction():
        pass
    with pytest.raises(RuntimeError):
        async with target.transaction():
            raise RuntimeError("boom")
    started = [event for event in events if event in ("start", "commit", "rollback")]
    assert started == ["start", "commit", "start", "rollback"]
