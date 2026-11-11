"""BackupCodeStore / BackupCodeProvider — FEAT-106 spec §3 Module 5 (TASK-134)."""
import asyncio
import hashlib
import inspect

import pytest

from navigator_auth.conf import AUTH_DB_SCHEMA
from navigator_auth.mfa.backup_codes import (
    BACKUP_CODE_ALPHABET, BackupCodeProvider, BackupCodeStore, normalize_code,
)
from navigator_auth.mfa.exceptions import MfaStorageError
from tests.fixtures.mfa import mfa_db, mfa_secret, mfa_user_factory  # noqa: F401


def test_normalize_code_accepts_spacing_and_case():
    assert normalize_code(" abcd-2345 ") == "ABCD2345"
    assert normalize_code(None) == ""


def test_consume_has_no_conn_parameter():
    """D16: consumption can never join a caller's (rollback-able) transaction."""
    assert "conn" not in inspect.signature(BackupCodeStore.consume).parameters


@pytest.mark.asyncio
async def test_backup_codes_generate_count_and_shape(mfa_db, mfa_user_factory, mfa_secret):
    """10 codes, 8 chars, all from BACKUP_CODE_ALPHABET, unique."""
    user = await mfa_user_factory()
    store = BackupCodeStore(mfa_db, mfa_secret)
    codes = await store.generate(user["user_id"])
    assert len(codes) == 10 == len(set(codes))
    assert all(len(c) == 8 and set(c) <= set(BACKUP_CODE_ALPHABET) for c in codes)
    assert await store.remaining(user["user_id"]) == 10


@pytest.mark.asyncio
async def test_backup_code_single_use(mfa_db, mfa_user_factory, mfa_secret):
    """A consumed code fails on reuse; remaining() drops by one."""
    user = await mfa_user_factory()
    store = BackupCodeStore(mfa_db, mfa_secret)
    codes = await store.generate(user["user_id"])
    spaced = codes[0][:4].lower() + "-" + codes[0][4:]
    assert await store.consume(user["user_id"], spaced) is True
    assert await store.consume(user["user_id"], codes[0]) is False
    assert await store.consume(user["user_id"], "ZZZ") is False
    assert await store.remaining(user["user_id"]) == 9


@pytest.mark.asyncio
async def test_backup_code_regeneration_invalidates_previous(mfa_db, mfa_user_factory, mfa_secret):
    """The old set stops working after generate() runs again."""
    user = await mfa_user_factory()
    store = BackupCodeStore(mfa_db, mfa_secret)
    old = await store.generate(user["user_id"])
    new = await store.generate(user["user_id"])
    assert await store.consume(user["user_id"], old[0]) is False
    assert await store.consume(user["user_id"], new[0]) is True
    assert await store.remaining(user["user_id"]) == 9


@pytest.mark.asyncio
async def test_codes_stored_as_keyed_hash_only(mfa_db, mfa_user_factory, mfa_secret):
    """No plaintext and no unkeyed sha256(code) in the table (D16, AC14)."""
    user = await mfa_user_factory()
    store = BackupCodeStore(mfa_db, mfa_secret)
    codes = await store.generate(user["user_id"])
    async with await mfa_db.acquire() as conn:
        rows = await conn.fetch_all(
            f"SELECT code_hash FROM {AUTH_DB_SCHEMA}.user_mfa_backup_codes WHERE user_id = $1",
            user["user_id"],
        )
    stored = {r["code_hash"] for r in rows}
    assert len(stored) == 10
    for code in codes:
        assert code not in stored
        assert hashlib.sha256(code.encode()).hexdigest() not in stored
        assert store._hash(user["user_id"], code) in stored


@pytest.mark.asyncio
async def test_code_bound_to_user(mfa_db, mfa_user_factory, mfa_secret):
    """User B cannot consume user A's code."""
    a = await mfa_user_factory()
    b = await mfa_user_factory()
    store = BackupCodeStore(mfa_db, mfa_secret)
    codes_a = await store.generate(a["user_id"])
    await store.generate(b["user_id"])
    assert await store.consume(b["user_id"], codes_a[0]) is False
    assert await store.consume(a["user_id"], codes_a[0]) is True


@pytest.mark.asyncio
async def test_concurrent_consume_succeeds_once(mfa_db, mfa_user_factory, mfa_secret):
    """asyncio.gather of two consume() of the same code -> exactly one True."""
    user = await mfa_user_factory()
    store = BackupCodeStore(mfa_db, mfa_secret)
    codes = await store.generate(user["user_id"])
    results = await asyncio.gather(*(store.consume(user["user_id"], codes[0]) for _ in range(4)))
    assert results.count(True) == 1


@pytest.mark.asyncio
async def test_provider_contract(mfa_db, mfa_user_factory, mfa_secret):
    """name == 'backup', is_strong is False, verify() consumes, disenroll() invalidates."""
    user = await mfa_user_factory()
    store = BackupCodeStore(mfa_db, mfa_secret)
    provider = BackupCodeProvider(store)
    assert provider.name == "backup"
    assert provider.is_strong is False
    assert await provider.is_enrolled(user) is False
    codes = await store.generate(user["user_id"])
    assert await provider.is_enrolled(user) is True
    assert await provider.verify(None, user, codes[0]) is True
    assert await provider.verify(None, user, codes[0]) is False
    await provider.disenroll(user)
    assert await store.remaining(user["user_id"]) == 0


class _BrokenPool:
    async def acquire(self):
        raise ConnectionError("down")


@pytest.mark.asyncio
async def test_storage_error_fails_closed(mfa_secret):
    """A pool that raises on acquire() surfaces MfaStorageError from every method."""
    store = BackupCodeStore(_BrokenPool(), mfa_secret)
    for call in (
        store.generate(1),
        store.consume(1, "ABCD2345"),
        store.remaining(1),
        store.invalidate_all(1),
    ):
        with pytest.raises(MfaStorageError):
            await call
