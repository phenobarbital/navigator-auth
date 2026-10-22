"""Unit tests for navigator_auth.identity.migrations."""
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

    def test_id_token_sql_file_exists_and_additive(self):
        assert (SQL_DIR / "002_identity_id_token.sql").is_file()
        sql = (SQL_DIR / "002_identity_id_token.sql").read_text()
        assert "ADD COLUMN IF NOT EXISTS" in sql
        assert "DROP" not in sql.upper()
        assert "id_token" in sql

    def test_key_version_integer_sql_is_conditional(self):
        sql = (SQL_DIR / "003_identity_key_version_integer.sql").read_text()
        assert "data_type = 'smallint'" in sql
        assert "ALTER COLUMN key_version TYPE INTEGER" in sql
        assert "DROP" not in sql.upper()

    def test_base_columns_sql_is_additive_and_guarded(self):
        """FEAT-103 Module 0: 004 adds the model's base columns, never drops."""
        sql = (SQL_DIR / "004_identity_base_columns.sql").read_text()
        assert "ADD COLUMN IF NOT EXISTS" in sql
        for column in (
            "identity_id", "display_name", "title", "nickname",
            "email", "phone", "short_bio", "avatar",
        ):
            assert column in sql
        # The legacy (user_id, uid) PK and the uid column stay put.
        code = "\n".join(
            ln for ln in sql.splitlines() if not ln.lstrip().startswith("--")
        ).upper()
        assert "DROP" not in code
        assert "ADD PRIMARY KEY" not in code
        # Guards: table-absent, and only when identity_id is not already PK.
        assert "to_regclass('auth.user_identities') IS NULL" in sql
        assert "contype = 'p'" in sql
        assert "IS DISTINCT FROM 'identity_id'" in sql

    def test_legacy_uid_default_sql_is_guarded_and_additive(self):
        """FEAT-103 Module 0: 005 unblocks G2 on a legacy table.

        004 adds the model's columns but leaves `uid VARCHAR NOT NULL` with no
        default, so a model insert (which omits `uid`) still fails. 005 gives
        it a surrogate default without dropping the column or the legacy PK.
        """
        path = SQL_DIR / "005_identity_legacy_uid_default.sql"
        assert path.is_file()
        sql = path.read_text()
        code = "\n".join(
            ln for ln in sql.splitlines() if not ln.lstrip().startswith("--")
        )
        # The one and only effect: a DEFAULT on the legacy uid column.
        assert "ALTER COLUMN uid SET DEFAULT gen_random_uuid()::varchar" in code
        # Nothing is dropped, no NOT NULL is touched, no PK is rewritten.
        upper = code.upper()
        assert "DROP" not in upper
        assert "NOT NULL" not in upper
        assert "PRIMARY KEY" not in upper
        # Guards: table absent -> skip; canonical table (no uid) -> skip;
        # already defaulted -> skip, so steady-state startups take no lock.
        assert "to_regclass('auth.user_identities') IS NULL" in code
        assert "column_name = 'uid'" in code
        assert "column_default IS NULL" in code


class TestEnsureIdentityColumns:
    @pytest.mark.asyncio
    async def test_executes_ddl(self):
        pool, conn = _make_pool_async_cm()
        await ensure_identity_columns(pool)
        # FEAT-096 TASK-047: 001 then 002; FEAT-099: 003 (INTEGER key_version).
        assert conn.execute.await_count == 5
        # FEAT-103 TASK-102: 004 (base columns), 005 (legacy uid default).
        first, second, third, fourth, fifth = (
            c.args[0] for c in conn.execute.await_args_list
        )
        assert "auth.user_identities" in first
        assert "id_token" in second
        assert "key_version TYPE INTEGER" in third
        assert "identity_id" in fourth
        assert "ALTER COLUMN uid SET DEFAULT" in fifth

    @pytest.mark.asyncio
    async def test_awaitable_acquire_releases(self):
        conn = AsyncMock()

        async def _acquire():
            return conn

        pool = MagicMock()
        pool.acquire = MagicMock(side_effect=lambda: _acquire())
        pool.release = AsyncMock()
        await ensure_identity_columns(pool)
        assert conn.execute.await_count == 5
        assert pool.release.await_count == 5
        pool.release.assert_awaited_with(conn)


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
        assert conn.execute.await_count == 5
