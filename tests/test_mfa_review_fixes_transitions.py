"""FEAT-106 review fixes — lock core (M2): bounded user_lock and LOCK_CONNECTION (AC10, AC11)."""

import asyncio

import pytest

from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.security import LOCK_CONNECTION, MfaSecurity, advisory_user_lock
from tests.fixtures.mfa import mfa_db, mfa_secret, mfa_user_factory, single_connection_authdb  # noqa: F401


@pytest.mark.asyncio
async def test_user_lock_timeout(mfa_db, mfa_user_factory, mfa_secret, monkeypatch):
    """A held advisory lock makes a second user lock time out within the configured bound."""
    monkeypatch.setattr("navigator_auth.mfa.security.AUTH_MFA_LOCK_TIMEOUT", 0.3)
    user = await mfa_user_factory()
    security = MfaSecurity(mfa_db, mfa_secret)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def hold_lock() -> None:
        async with security.user_lock(user["user_id"]):
            entered.set()
            await release.wait()

    holder = asyncio.create_task(hold_lock())
    await entered.wait()
    started = asyncio.get_running_loop().time()
    with pytest.raises(MfaStorageError):
        async with security.user_lock(user["user_id"]):
            pass
    assert asyncio.get_running_loop().time() - started < 2
    release.set()
    await holder


@pytest.mark.asyncio
async def test_user_lock_acquire_timeout(single_connection_authdb, mfa_user_factory):
    """With the only pool connection held, acquisition itself is bounded."""
    first_user, second_user = await mfa_user_factory(), await mfa_user_factory()
    async with advisory_user_lock(single_connection_authdb, first_user["user_id"]):
        with pytest.raises(MfaStorageError):
            async with advisory_user_lock(single_connection_authdb, second_user["user_id"], timeout=0.2):
                pass


@pytest.mark.asyncio
async def test_lock_connection_published(mfa_db, mfa_user_factory, mfa_secret):
    """The lock context holds the connection only for successful and failing bodies."""
    user = await mfa_user_factory()
    security = MfaSecurity(mfa_db, mfa_secret)
    assert LOCK_CONNECTION.get() is None
    async with security.user_lock(user["user_id"]) as conn:
        assert LOCK_CONNECTION.get() is conn
    assert LOCK_CONNECTION.get() is None
    with pytest.raises(RuntimeError, match="body failed"):
        async with security.user_lock(user["user_id"]) as conn:
            assert LOCK_CONNECTION.get() is conn
            raise RuntimeError("body failed")
    assert LOCK_CONNECTION.get() is None


@pytest.mark.asyncio
async def test_no_acquire_inside_lock_guard(single_connection_authdb, mfa_user_factory):
    """The fixture records and refuses an acquisition attempted inside a lock scope."""
    user = await mfa_user_factory()
    single_connection_authdb.strict = True
    async with advisory_user_lock(single_connection_authdb, user["user_id"]):
        with pytest.raises(AssertionError, match="inside a user_lock scope"):
            single_connection_authdb.acquire()
    assert len(single_connection_authdb.acquires_inside_lock) == 1
    assert LOCK_CONNECTION.get() is None
    async with await single_connection_authdb.acquire():
        pass
    assert single_connection_authdb.acquires == [False, True, False]


@pytest.mark.asyncio
async def test_advisory_user_lock_serializes_without_mfa_security(mfa_db, mfa_user_factory):
    """The standalone advisory lock serializes a user without an MFA secret or service."""
    user = await mfa_user_factory()
    entered = asyncio.Event()
    release = asyncio.Event()
    timestamps = {}
    loop = asyncio.get_running_loop()

    async def first() -> None:
        async with advisory_user_lock(mfa_db, user["user_id"]):
            timestamps["first_enter"] = loop.time()
            entered.set()
            await release.wait()
            timestamps["first_exit"] = loop.time()

    async def second() -> None:
        await entered.wait()
        async with advisory_user_lock(mfa_db, user["user_id"]):
            timestamps["second_enter"] = loop.time()

    first_task = asyncio.create_task(first())
    await entered.wait()
    second_task = asyncio.create_task(second())
    await asyncio.sleep(0.05)
    assert "second_enter" not in timestamps
    release.set()
    await asyncio.gather(first_task, second_task)
    assert timestamps["second_enter"] >= timestamps["first_exit"]
