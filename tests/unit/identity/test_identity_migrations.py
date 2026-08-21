"""Unit tests for navigator_auth.identity.migrations."""
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from navigator_auth.identity.migrations import (
    SQL_DIR,
    ensure_identity_columns,
    setup_identity_columns,
)


def _make_pool_async_cm():
    """Pool whose acquire() returns an async context manager."""
    conn = AsyncMock()
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=conn)
    ctx.__aexit__ = AsyncMock(return_value=False)
    pool = MagicMock()
    pool.acquire = MagicMock(return_value=ctx)
    return pool, conn


class TestSQLFile:
    def test_sql_file_exists(self):
        assert (SQL_DIR / "001_identity_credentials.sql").is_file()

    def test_sql_is_idempotent_and_additive(self):
        sql = (SQL_DIR / "001_identity_credentials.sql").read_text()
        assert "ADD COLUMN IF NOT EXISTS" in sql
        assert "CREATE UNIQUE INDEX IF NOT EXISTS" in sql
        assert "DROP" not in sql.upper()
        for column in (
            "provider_user_id",
            "scopes",
            "access_token",
            "refresh_token",
            "token_type",
            "expires_at",
            "refreshed_at",
            "enabled",
            "key_version",
        ):
            assert column in sql


class TestEnsureIdentityColumns:
    @pytest.mark.asyncio
    async def test_executes_ddl(self):
        pool, conn = _make_pool_async_cm()
        await ensure_identity_columns(pool)
        conn.execute.assert_awaited_once()
        executed = conn.execute.await_args.args[0]
        assert "auth.user_identities" in executed

    @pytest.mark.asyncio
    async def test_awaitable_acquire_releases(self):
        conn = AsyncMock()

        async def _acquire():
            return conn

        pool = MagicMock()
        pool.acquire = MagicMock(side_effect=lambda: _acquire())
        pool.release = AsyncMock()
        await ensure_identity_columns(pool)
        conn.execute.assert_awaited_once()
        pool.release.assert_awaited_once_with(conn)


class TestSetupIdentityColumns:
    @pytest.mark.asyncio
    async def test_swallows_errors(self):
        pool = MagicMock()
        pool.acquire = MagicMock(side_effect=RuntimeError("db down"))
        # must not raise
        await setup_identity_columns(pool)

    @pytest.mark.asyncio
    async def test_calls_through(self):
        pool, conn = _make_pool_async_cm()
        await setup_identity_columns(pool)
        conn.execute.assert_awaited_once()
