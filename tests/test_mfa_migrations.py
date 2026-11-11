"""FEAT-106 TASK-130 — MFA DDL, migration, and usability flag."""

import pytest

from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.migrations import (
    MFA_TABLES,
    SQL_DIR,
    _MIGRATION_FILES,
    ensure_mfa_tables,
    mfa_tables_present,
    render_sql,
    setup_mfa_tables,
)
from tests.fixtures.mfa import mfa_db  # noqa: F401


class _FakeConn:
    """Fake connection returning configurable asyncdb-style values."""

    def __init__(self, execute_result=("CREATE", None), present=len(MFA_TABLES), raise_on=None):
        self.executed = []
        self._result = execute_result
        self._present = present
        self._raise_on = raise_on

    async def execute(self, sql):
        """Record SQL and return the configured execution value."""
        self.executed.append(sql)
        if self._raise_on == "execute":
            raise RuntimeError("execute")
        return list(self._result)

    async def fetchval(self, sql, *args):
        """Return the configured relation count or raise as requested."""
        if self._raise_on == "fetchval":
            raise RuntimeError("fetchval")
        return self._present


class _FakeCtx:
    """Async context manager yielding a supplied fake connection."""

    def __init__(self, conn):
        self._conn = conn

    async def __aenter__(self):
        """Yield the fake connection."""
        return self._conn

    async def __aexit__(self, *exc):
        """Do not suppress exceptions."""
        return False


class _FakePool:
    """Pool exposing the context-manager acquire shape."""

    def __init__(self, **kwargs):
        self.conn = _FakeConn(**kwargs)

    def acquire(self):
        """Return an async context yielding the shared connection."""
        return _FakeCtx(self.conn)


def test_render_sql_substitutes_placeholders():
    """Rendering leaves no migration placeholders."""
    sql = render_sql((SQL_DIR / _MIGRATION_FILES[0]).read_text())
    assert "{schema}" not in sql
    assert "{users_table}" not in sql


def test_migration_declares_six_tables():
    """DDL contains required MFA tables and security-specific columns."""
    sql = (SQL_DIR / _MIGRATION_FILES[0]).read_text()
    for table in MFA_TABLES:
        assert f"CREATE TABLE IF NOT EXISTS {{schema}}.{table}" in sql
    trusted_devices = sql.split("CREATE TABLE IF NOT EXISTS {schema}.user_trusted_devices", 1)[1]
    audit = sql.split("CREATE TABLE IF NOT EXISTS {schema}.user_mfa_audit", 1)[1]
    assert "rotated_at" in trusted_devices
    assert "revoke_reason" in trusted_devices
    assert "REFERENCES" not in audit.split("CREATE INDEX", 1)[0]


@pytest.mark.asyncio
async def test_ensure_raises_on_swallowed_execute_error():
    """asyncdb-style execute error slots become MFA storage errors."""
    pool = _FakePool(execute_result=(None, RuntimeError("x")))
    with pytest.raises(MfaStorageError):
        await ensure_mfa_tables(pool)


@pytest.mark.asyncio
async def test_setup_returns_false_and_never_raises():
    """Failure paths are reported as False rather than raised."""
    assert await setup_mfa_tables(_FakePool(execute_result=(None, RuntimeError("x")))) is False
    assert await setup_mfa_tables(_FakePool(raise_on="fetchval")) is False
    assert await setup_mfa_tables(_FakePool(present=5)) is False
    assert await setup_mfa_tables(None) is False


@pytest.mark.asyncio
async def test_setup_returns_true_when_all_present():
    """A healthy pool with all relations reports usable migration state."""
    pool = _FakePool()
    assert await setup_mfa_tables(pool) is True
    assert len(pool.conn.executed) == len(_MIGRATION_FILES)


@pytest.mark.asyncio
async def test_live_setup_is_idempotent(mfa_db):
    """Live PostgreSQL accepts the idempotent migration twice."""
    assert await setup_mfa_tables(mfa_db) is True
    assert await setup_mfa_tables(mfa_db) is True
    assert await mfa_tables_present(mfa_db) is True
