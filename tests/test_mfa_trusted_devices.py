"""TrustedDeviceStore tests for FEAT-106 TASK-133."""

import pytest

from navigator_auth.mfa.trusted_devices import TrustedDeviceStore, may_offer_trusted_device
from tests.fixtures.mfa import mfa_db, mfa_user_factory  # noqa: F401


def test_trusted_device_not_offered_to_email_state():
    """Trusted devices require a strong factor and a positive window."""
    assert may_offer_trusted_device(has_strong_factor=True, remember_days=30)
    assert not may_offer_trusted_device(has_strong_factor=False, remember_days=30)
    assert not may_offer_trusted_device(has_strong_factor=True, remember_days=0)


@pytest.mark.asyncio
async def test_consume_and_rotate_on_caller_conn(mfa_db, mfa_user_factory):
    """Caller transaction controls rotation and replay-family revocation durability."""
    user = await mfa_user_factory()
    store = TrustedDeviceStore(mfa_db)
    raw = await store.issue(user["user_id"], 30, "test")

    async with await mfa_db.acquire() as conn:
        await conn.transaction()
        rotated = await store.consume_and_rotate(raw, user["user_id"], conn=conn)
        assert rotated is not None
        await conn.rollback()

    assert await store.consume_and_rotate(raw, user["user_id"]) is not None

    raw = await store.issue(user["user_id"], 30, "test")
    async with await mfa_db.acquire() as conn:
        await conn.transaction()
        rotated = await store.consume_and_rotate(raw, user["user_id"], conn=conn)
        assert rotated is not None
        await conn.commit()

    assert await store.consume_and_rotate(raw, user["user_id"]) is None
    assert await store.consume_and_rotate(rotated[1], user["user_id"]) is None


@pytest.mark.asyncio
async def test_consume_and_rotate_pooled_path_unchanged(mfa_db, mfa_user_factory):
    """Without conn, rotation still owns its transaction."""
    user = await mfa_user_factory()
    store = TrustedDeviceStore(mfa_db)
    raw = await store.issue(user["user_id"], 30, "test")

    rotated = await store.consume_and_rotate(raw, user["user_id"])
    assert rotated is not None
    assert rotated[0] == user["user_id"]
    assert await store.consume_and_rotate(raw, user["user_id"]) is None
