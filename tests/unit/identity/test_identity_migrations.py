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


def _make_failing_pool(marker: str, error: Exception):
    """Pool whose connection raises ``error`` for the SQL containing ``marker``."""
    async def _execute(sql):
        if marker in sql:
            raise error

    conn = AsyncMock()
    conn.execute = AsyncMock(side_effect=_execute)
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

    def test_drop_legacy_uid_sql_is_guarded(self):
        """006 drops the legacy uid column — the one removal in this set.

        It is what makes ``SELECT *`` readers (navigator-api's ModelHandler
        behind ``/api/v1/user_identity``) able to hydrate ``UserIdentity`` on
        a legacy table at all. Verified against a real PostgreSQL 17 in three
        shapes: legacy (drops, identity_id becomes the PK), canonical
        (no-op) and legacy-with-a-view-on-uid (warns, changes nothing).
        """
        path = SQL_DIR / "006_identity_drop_legacy_uid.sql"
        assert path.is_file()
        sql = path.read_text()
        # Drops comments and the continuation lines of the RAISE messages, so
        # the CASCADE assertion below sees statements only.
        code = "\n".join(
            ln for ln in sql.splitlines()
            if not ln.lstrip().startswith(("--", "'"))
        )
        # The effects: identity_id becomes the key, uid goes.
        assert "ALTER COLUMN identity_id SET NOT NULL" in code
        assert "DROP COLUMN uid" in code
        assert "PRIMARY KEY USING INDEX uq_user_identities_identity_id" in code
        # Never CASCADE: a dependent view/rule/constraint means skip instead.
        assert "CASCADE" not in code.upper()
        assert "pg_rewrite" in code
        assert "RAISE WARNING" in code
        # Guards: table absent -> skip; no uid column (canonical) -> skip;
        # identity_id missing or duplicated -> skip.
        assert "to_regclass('auth.user_identities') IS NULL" in code
        assert "IF uid_attnum IS NULL THEN" in code
        assert "HAVING count(*) > 1" in code
        # Replaces the user_id lookup the legacy (user_id, uid) PK served.
        assert "idx_user_identities_user" in code


class TestEnsureIdentityColumns:
    @pytest.mark.asyncio
    async def test_executes_ddl(self):
        pool, conn = _make_pool_async_cm()
        await ensure_identity_columns(pool)
        # FEAT-096 TASK-047: 001 then 002; FEAT-099: 003 (INTEGER key_version).
        assert conn.execute.await_count == 6
        # FEAT-103 TASK-102: 004 (base columns), 005 (legacy uid default).
        # FEAT-104: 006 (drop the legacy uid column).
        first, second, third, fourth, fifth, sixth = (
            c.args[0] for c in conn.execute.await_args_list
        )
        assert "auth.user_identities" in first
        assert "id_token" in second
        assert "key_version TYPE INTEGER" in third
        assert "identity_id" in fourth
        assert "ALTER COLUMN uid SET DEFAULT" in fifth
        assert "DROP COLUMN uid" in sixth

    @pytest.mark.asyncio
    async def test_awaitable_acquire_releases(self):
        conn = AsyncMock()

        async def _acquire():
            return conn

        pool = MagicMock()
        pool.acquire = MagicMock(side_effect=lambda: _acquire())
        pool.release = AsyncMock()
        await ensure_identity_columns(pool)
        assert conn.execute.await_count == 6
        assert pool.release.await_count == 6
        pool.release.assert_awaited_with(conn)

    @pytest.mark.asyncio
    async def test_one_failure_does_not_block_later_migrations(self):
        """issue:b9f6225031e0 — 003 failing must not skip 004/005/006.

        Every file guards its own effect, so the set is run to the end and the
        failures are reported together instead of the first one aborting the
        loop and leaving the schema half-migrated.
        """
        pool, conn = _make_failing_pool(
            "key_version TYPE INTEGER", RuntimeError("lock timeout")
        )
        with pytest.raises(RuntimeError) as excinfo:
            await ensure_identity_columns(pool)

        # All six were attempted, in order, despite 003 blowing up.
        assert conn.execute.await_count == 6
        executed = [c.args[0] for c in conn.execute.await_args_list]
        assert "identity_id" in executed[3]
        assert "ALTER COLUMN uid SET DEFAULT" in executed[4]
        assert "DROP COLUMN uid" in executed[5]
        # The error names the file that failed, and only that one.
        message = str(excinfo.value)
        assert "003_identity_key_version_integer.sql" in message
        assert "1 of 6" in message
        assert isinstance(excinfo.value.__cause__, RuntimeError)

    @pytest.mark.asyncio
    async def test_reports_every_failing_file(self):
        pool, conn = _make_failing_pool(
            "auth.user_identities", RuntimeError("db exploded")
        )
        with pytest.raises(RuntimeError) as excinfo:
            await ensure_identity_columns(pool)
        message = str(excinfo.value)
        assert "6 of 6" in message
        for filename in (
            "001_identity_credentials.sql",
            "006_identity_drop_legacy_uid.sql",
        ):
            assert filename in message


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
        assert conn.execute.await_count == 6

    @pytest.mark.asyncio
    async def test_applies_the_rest_when_one_migration_fails(self):
        """issue:b9f6225031e0 — startup applies what it can, then logs."""
        pool, conn = _make_failing_pool(
            "key_version TYPE INTEGER", RuntimeError("lock timeout")
        )
        # must not raise, and must still have run 004/005/006
        await setup_identity_columns(pool)
        assert conn.execute.await_count == 6
