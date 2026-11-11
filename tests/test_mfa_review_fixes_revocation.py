"""FEAT-106 review fixes — durable security state (spec M4)."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from navigator_auth.security_state import (
    GENERATION_CLAIM,
    SECURITY_STATE_TABLES,
    SecurityStateError,
    confirmation_recorded,
    current_generation,
    ensure_security_state_tables,
    generation_matches,
    generation_of,
    increment_generation,
    record_confirmation,
    setup_security_state_tables,
    stamp_generation,
)
from navigator_auth.security_state.migrations import SQL_DIR, _MIGRATION_FILES
from navigator_auth.conf import AUTH_DB_SCHEMA
from tests.fixtures.mfa import mfa_db, mfa_user_factory  # noqa: F401


class _FakeConn:
    """Configurable asyncdb connection for migration error-path tests."""

    def __init__(self, execute_result=("CREATE", None), present=len(SECURITY_STATE_TABLES), raise_on=None):
        self._execute_result = execute_result
        self._present = present
        self._raise_on = raise_on

    async def execute(self, sql):
        """Return the configured asyncdb execute result."""
        return self._execute_result

    async def fetchval(self, sql, *args):
        """Return the configured relation count or raise an error."""
        if self._raise_on == "fetchval":
            raise RuntimeError("fetchval")
        return self._present


class _FakeContext:
    """Async context manager yielding a supplied connection."""

    def __init__(self, conn):
        self._conn = conn

    async def __aenter__(self):
        """Yield the connection."""
        return self._conn

    async def __aexit__(self, *exc):
        """Do not suppress errors."""
        return False


class _FakePool:
    """Pool exposing the context-manager acquire shape."""

    def __init__(self, **kwargs):
        self.conn = _FakeConn(**kwargs)

    def acquire(self):
        """Return an async context yielding the fake connection."""
        return _FakeContext(self.conn)


class _BrokenPool:
    """Pool whose acquisition fails."""

    async def acquire(self):
        """Raise a deterministic storage failure."""
        raise ConnectionError("down")


def test_generation_encoding_absent_means_zero():
    """Missing claim is zero; zero is absent; positive generations round-trip."""
    assert generation_of({}) == 0
    assert stamp_generation({"sub": "1"}, 0) == {"sub": "1"}
    assert generation_of(stamp_generation({}, 3)) == 3 and GENERATION_CLAIM == "gen"


@pytest.mark.parametrize("bad", [True, "2", -1, 1.5])
def test_generation_of_rejects_forged_values(bad):
    """Forged or corrupt generation claims fail closed."""
    with pytest.raises(SecurityStateError):
        generation_of({GENERATION_CLAIM: bad})


def test_migration_declares_both_tables():
    """The migration declares both durable security-state relations."""
    sql = "\n".join((SQL_DIR / name).read_text() for name in _MIGRATION_FILES)
    for table in SECURITY_STATE_TABLES:
        assert f"CREATE TABLE IF NOT EXISTS {{schema}}.{table}" in sql


@pytest.mark.asyncio
async def test_setup_never_raises():
    """Setup reports DDL and readiness failures as false."""
    assert await setup_security_state_tables(_FakePool(execute_result=(None, RuntimeError("x")))) is False
    assert await setup_security_state_tables(_FakePool(raise_on="fetchval")) is False
    assert await setup_security_state_tables(None) is False


@pytest_asyncio.fixture
async def state_db(mfa_db):
    """Provide a pool whose security-state tables have been created."""
    await ensure_security_state_tables(mfa_db)
    yield mfa_db


@pytest.mark.asyncio
async def test_generation_increment_and_match(state_db, mfa_user_factory):
    """Absent generation is zero and committed increments are monotonic."""
    user = await mfa_user_factory()
    async with await state_db.acquire() as conn:
        assert await current_generation(conn, user["user_id"]) == 0
        assert await increment_generation(conn, user["user_id"]) == 1
        assert await increment_generation(conn, user["user_id"]) == 2
    assert await generation_matches(state_db, user["user_id"], 2) is True
    assert await generation_matches(state_db, user["user_id"], 0) is False


@pytest.mark.asyncio
async def test_generation_matches_fails_closed():
    """An unreadable generation raises SecurityStateError instead of matching."""
    with pytest.raises(SecurityStateError):
        await generation_matches(_BrokenPool(), 1, 0)


@pytest.mark.asyncio
async def test_record_confirmation_single_use_and_transactional(state_db, mfa_user_factory):
    """Rollback removes markers; committed markers reject a replay."""
    user = await mfa_user_factory()
    digest = hashlib.sha256(secrets.token_bytes(16)).hexdigest()
    expires = datetime.now(timezone.utc) + timedelta(minutes=15)
    try:
        async with await state_db.acquire() as conn:
            await conn.transaction()
            assert await record_confirmation(conn, digest, user["user_id"], expires) is True
            await conn.rollback()
            assert await confirmation_recorded(conn, digest) is False

            await conn.transaction()
            assert await record_confirmation(conn, digest, user["user_id"], expires) is True
            await conn.commit()
            assert await record_confirmation(conn, digest, user["user_id"], expires) is False
            with pytest.raises(ValueError):
                await record_confirmation(conn, digest.upper(), user["user_id"], expires)
            await conn.fetchval(
                f"DELETE FROM {AUTH_DB_SCHEMA}.recovery_confirm_consumptions WHERE digest = $1 RETURNING digest", digest
            )
    finally:
        async with await state_db.acquire() as conn:
            await conn.fetchval(
                f"DELETE FROM {AUTH_DB_SCHEMA}.recovery_confirm_consumptions WHERE digest = $1 RETURNING digest", digest
            )
