"""FEAT-106 TASK-132 advisory lock, version, durable audit, and digest tests."""

import asyncio
from datetime import datetime, timezone

import pytest

from navigator_auth.conf import AUTH_DB_SCHEMA
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.security import LOCK_NAMESPACE, MfaSecurity, _lock_key
from navigator_auth.mfa.types import MfaAuditEntry, MfaMode, MfaState, TenantMfaPolicy
from tests.fixtures.mfa import mfa_db, mfa_secret, mfa_user_factory  # noqa: F401

POLICY = TenantMfaPolicy(
    org_id=5,
    mode=MfaMode.ENFORCED,
    remember_days=30,
    enforced_at=datetime(2026, 11, 1, tzinfo=timezone.utc),
    enforced_by="t",
)
USER = {
    "user_id": 42,
    "password": "pbkdf2_sha256$80000$salt$hash",
    "is_active": True,
    "is_superuser": False,
    "email": "A@Example.com",
}


def _digest(security, **over):
    values = dict(
        user=USER,
        memberships=(7, 5),
        policy=POLICY,
        state=MfaState.EMAIL,
        has_strong_factor=False,
    )
    values.update(over)
    return security.context_digest(**values)


def test_context_digest_stable_and_normalized(mfa_secret):
    security = MfaSecurity(None, mfa_secret)
    assert _digest(security) == _digest(security, memberships=(5, 7))
    normalized_user = {**USER, "email": " a@example.COM "}
    assert _digest(security) == _digest(security, user=normalized_user)
    model_user = type("User", (), USER)()
    digest = _digest(security)
    assert digest == _digest(security, user=model_user)
    assert USER["password"] not in digest


@pytest.mark.parametrize(
    "change",
    [
        "password",
        "is_active",
        "is_superuser",
        "email",
        "memberships",
        "policy_mode",
        "remember_days",
        "policy_org",
        "state",
        "strong",
    ],
)
def test_context_digest_changes_per_input(mfa_secret, change):
    security = MfaSecurity(None, mfa_secret)
    baseline = _digest(security)
    overrides = {
        "password": {"user": {**USER, "password": "other-verifier"}},
        "is_active": {"user": {**USER, "is_active": False}},
        "is_superuser": {"user": {**USER, "is_superuser": True}},
        "email": {"user": {**USER, "email": "other@example.com"}},
        "memberships": {"memberships": (5, 8)},
        "policy_mode": {"policy": POLICY.model_copy(update={"mode": MfaMode.OPTIONAL})},
        "remember_days": {"policy": POLICY.model_copy(update={"remember_days": 7})},
        "policy_org": {"policy": POLICY.model_copy(update={"org_id": 6})},
        "state": {"state": MfaState.TOTP},
        "strong": {"has_strong_factor": True},
    }
    assert baseline != _digest(security, **overrides[change])


def test_context_digest_keyed(mfa_secret):
    assert _digest(MfaSecurity(None, mfa_secret)) != _digest(MfaSecurity(None, b"other-secret"))


def test_lock_key_folding():
    assert _lock_key(42) == 42
    assert 0 <= _lock_key(2**40) < 2**31
    with pytest.raises(ValueError):
        _lock_key(True)
    with pytest.raises(ValueError):
        _lock_key(-1)
    assert LOCK_NAMESPACE < 2**31 - 1


@pytest.mark.asyncio
async def test_version_initializes_and_is_monotonic(mfa_db, mfa_user_factory, mfa_secret):
    user = await mfa_user_factory()
    security = MfaSecurity(mfa_db, mfa_secret)
    async with security.user_lock(user["user_id"]) as conn:
        assert await security.current_version(conn, user["user_id"]) == 0
        assert await security.bump_version(conn, user["user_id"]) == 1
        assert await security.bump_version(conn, user["user_id"]) == 2
        assert await security.current_version(conn, user["user_id"]) == 2


@pytest.mark.asyncio
async def test_user_lock_rolls_back_on_error(mfa_db, mfa_user_factory, mfa_secret):
    user = await mfa_user_factory()
    security = MfaSecurity(mfa_db, mfa_secret)
    with pytest.raises(RuntimeError, match="rollback"):
        async with security.user_lock(user["user_id"]) as conn:
            await security.bump_version(conn, user["user_id"])
            raise RuntimeError("rollback")
    async with security.user_lock(user["user_id"]) as conn:
        assert await security.current_version(conn, user["user_id"]) == 0


@pytest.mark.asyncio
async def test_user_lock_serializes_same_user(mfa_db, mfa_user_factory, mfa_secret):
    user = await mfa_user_factory()
    security = MfaSecurity(mfa_db, mfa_secret)
    entered = asyncio.Event()
    release = asyncio.Event()
    timestamps = {}
    loop = asyncio.get_running_loop()

    async def first():
        async with security.user_lock(user["user_id"]):
            timestamps["first_enter"] = loop.time()
            entered.set()
            await release.wait()
            timestamps["first_exit"] = loop.time()

    async def second():
        await entered.wait()
        async with security.user_lock(user["user_id"]):
            timestamps["second_enter"] = loop.time()

    first_task = asyncio.create_task(first())
    await entered.wait()
    second_task = asyncio.create_task(second())
    await asyncio.sleep(0.05)
    assert "second_enter" not in timestamps
    release.set()
    await asyncio.gather(first_task, second_task)
    assert timestamps["second_enter"] >= timestamps["first_exit"]


@pytest.mark.asyncio
async def test_user_lock_independent_users(mfa_db, mfa_user_factory, mfa_secret):
    first_user, second_user = await mfa_user_factory(), await mfa_user_factory()
    security = MfaSecurity(mfa_db, mfa_secret)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def first():
        async with security.user_lock(first_user["user_id"]):
            entered.set()
            await release.wait()

    async def second():
        await entered.wait()
        async with security.user_lock(second_user["user_id"]):
            return True

    first_task = asyncio.create_task(first())
    assert await asyncio.wait_for(second(), timeout=0.5)
    release.set()
    await first_task


@pytest.mark.asyncio
async def test_audit_row_is_durable_and_complete(mfa_db, mfa_user_factory, mfa_secret):
    user = await mfa_user_factory()
    security = MfaSecurity(mfa_db, mfa_secret)
    entry = MfaAuditEntry(
        actor_user_id=user["user_id"],
        target_user_id=user["user_id"],
        org_id=5,
        action="totp_confirm",
        old_state="email",
        new_state="totp",
        method="totp",
        request_id="request-1",
        outcome="success",
        detail={"reason": "test"},
    )
    async with security.user_lock(user["user_id"]) as conn:
        await security.write_audit(conn, entry)
    async with await mfa_db.acquire() as conn:
        row = await conn.fetch_one(
            f"SELECT * FROM {AUTH_DB_SCHEMA}.user_mfa_audit WHERE target_user_id = $1 ORDER BY id DESC LIMIT 1",
            user["user_id"],
        )
    assert row["actor_user_id"] == entry.actor_user_id
    assert row["target_user_id"] == entry.target_user_id
    assert row["org_id"] == entry.org_id
    assert row["action"] == entry.action
    assert row["old_state"] == entry.old_state
    assert row["new_state"] == entry.new_state
    assert row["outcome"] == entry.outcome
    assert row["detail"] == entry.detail


@pytest.mark.asyncio
async def test_audit_rolls_back_with_transition(mfa_db, mfa_user_factory, mfa_secret):
    user = await mfa_user_factory()
    security = MfaSecurity(mfa_db, mfa_secret)
    entry = MfaAuditEntry(
        actor_user_id=user["user_id"],
        target_user_id=user["user_id"],
        org_id=5,
        action="rollback_test",
        outcome="success",
    )
    with pytest.raises(RuntimeError):
        async with security.user_lock(user["user_id"]) as conn:
            await security.write_audit(conn, entry)
            raise RuntimeError("rollback")
    async with await mfa_db.acquire() as conn:
        count = await conn.fetchval(
            f"SELECT count(*) FROM {AUTH_DB_SCHEMA}.user_mfa_audit WHERE action = $1 AND target_user_id = $2",
            entry.action,
            user["user_id"],
        )
    assert count == 0


@pytest.mark.asyncio
async def test_storage_failures_raise(mfa_db, mfa_secret):
    security = MfaSecurity(mfa_db, mfa_secret)
    async with security.user_lock(9_000_000_000_000_000_000) as conn:
        with pytest.raises(MfaStorageError):
            await security.bump_version(conn, 9_000_000_000_000_000_000)
