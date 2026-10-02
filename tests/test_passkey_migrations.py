"""FEAT-101 TASK-87 — passkey migration rendering and idempotency."""

import pytest

from navigator_auth.conf import default_dsn
from navigator_auth.passkey.migrations import (
    SQL_DIR,
    _MIGRATION_FILES,
    ensure_passkey_tables,
    render_sql,
    setup_passkey_tables,
)


class _FakeConn:
    def __init__(self, log):
        self.log = log

    async def execute(self, sql):
        self.log.append(sql)


class _FakeCtx:
    def __init__(self, log):
        self.log = log

    async def __aenter__(self):
        return _FakeConn(self.log)

    async def __aexit__(self, *exc):
        return False


class _FakePool:
    def __init__(self):
        self.executed = []

    def acquire(self):
        return _FakeCtx(self.executed)


def test_render_sql_substitutes_placeholders():
    """No {schema}/{users_table} placeholder survives rendering."""
    sql = render_sql((SQL_DIR / "001_passkey_credentials.sql").read_text())
    assert "{schema}" not in sql and "{users_table}" not in sql


@pytest.mark.asyncio
async def test_ensure_passkey_tables_uses_pool():
    """One execute per migration file, with rendered SQL."""
    pool = _FakePool()
    await ensure_passkey_tables(pool)
    assert len(pool.executed) == len(_MIGRATION_FILES)
    assert "user_credentials" in pool.executed[0]
    assert "{schema}" not in pool.executed[0]


@pytest.mark.asyncio
async def test_setup_passkey_tables_never_raises():
    """The startup wrapper swallows pool errors."""

    class _Boom:
        def acquire(self):
            raise RuntimeError("db down")

    await setup_passkey_tables(_Boom())


@pytest.mark.asyncio
async def test_migration_idempotent():
    """Live Postgres: ensure_passkey_tables twice succeeds (spec §4)."""
    asyncpg = pytest.importorskip("asyncpg")
    try:
        pool = await asyncpg.create_pool(default_dsn, min_size=1, max_size=1, timeout=3)
    except Exception as err:  # pylint: disable=W0703
        pytest.skip(f"Postgres unreachable: {err}")
    try:
        try:
            await ensure_passkey_tables(pool)
        except asyncpg.PostgresError as err:
            pytest.skip(f"auth schema not provisioned: {err}")
        await ensure_passkey_tables(pool)
    finally:
        await pool.close()
