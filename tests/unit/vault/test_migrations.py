"""Unit tests for navigator_auth.vault.migrations module."""
import warnings
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

# Suppress pre-existing Pydantic deprecation from oauth2/models.py
# triggered by navigator_auth.__init__ import chain.
warnings.filterwarnings("ignore", message=".*extra keyword arguments on.*Field.*")

from navigator_auth.vault.migrations import ensure_vault_tables, SQL_DIR


# ---------------------------------------------------------------------------
# SQL file existence and content
# ---------------------------------------------------------------------------

class TestMigrationSQL:
    def test_sql_dir_exists(self):
        """SQL directory exists."""
        assert SQL_DIR.is_dir()

    def test_sql_file_exists(self):
        """Migration SQL file exists."""
        sql_file = SQL_DIR / "001_create_vault_tables.sql"
        assert sql_file.exists()

    def test_sql_file_is_not_empty(self):
        """SQL file has content."""
        sql = (SQL_DIR / "001_create_vault_tables.sql").read_text()
        assert len(sql.strip()) > 0


# ---------------------------------------------------------------------------
# Table definitions
# ---------------------------------------------------------------------------

class TestTableDefinitions:
    @pytest.fixture
    def sql(self) -> str:
        return (SQL_DIR / "001_create_vault_tables.sql").read_text()

    def test_creates_user_vault_secrets(self, sql):
        """SQL creates user_vault_secrets table."""
        assert "user_vault_secrets" in sql

    def test_creates_user_vault_audit(self, sql):
        """SQL creates user_vault_audit table."""
        assert "user_vault_audit" in sql

    def test_creates_vault_key_registry(self, sql):
        """SQL creates vault_key_registry table."""
        assert "vault_key_registry" in sql

    def test_uses_auth_schema_secrets(self, sql):
        """user_vault_secrets is in auth schema."""
        assert "auth.user_vault_secrets" in sql

    def test_uses_auth_schema_audit(self, sql):
        """user_vault_audit is in auth schema."""
        assert "auth.user_vault_audit" in sql

    def test_uses_auth_schema_registry(self, sql):
        """vault_key_registry is in auth schema."""
        assert "auth.vault_key_registry" in sql

    def test_uses_if_not_exists(self, sql):
        """Tables use IF NOT EXISTS for idempotency."""
        assert sql.count("IF NOT EXISTS") >= 3  # 3 tables minimum

    def test_partial_unique_index(self, sql):
        """Partial unique index for active secrets exists."""
        assert "WHERE deleted_at IS NULL" in sql

    def test_foreign_key_to_auth_users(self, sql):
        """Foreign key references auth.users(user_id)."""
        assert "auth.users(user_id)" in sql

    def test_ciphertext_db_bytea(self, sql):
        """ciphertext_db column is BYTEA type."""
        assert "BYTEA" in sql

    def test_audit_operation_check_constraint(self, sql):
        """Audit table has CHECK constraint on operation column."""
        assert "'set'" in sql
        assert "'get'" in sql
        assert "'delete'" in sql
        assert "'rotate'" in sql

    def test_soft_delete_column(self, sql):
        """user_vault_secrets has deleted_at column."""
        assert "deleted_at" in sql

    def test_key_version_column(self, sql):
        """user_vault_secrets has key_version column."""
        assert "key_version" in sql

    def test_audit_index_exists(self, sql):
        """Audit table has index on user_id + created_at."""
        assert "idx_vault_audit_user" in sql

    def test_secrets_user_active_index(self, sql):
        """Secrets table has index on user_id for active rows."""
        assert "idx_vault_user_active" in sql


# ---------------------------------------------------------------------------
# ensure_vault_tables function
# ---------------------------------------------------------------------------

class TestEnsureVaultTables:
    @pytest.mark.asyncio
    async def test_reads_and_executes_sql(self):
        """ensure_vault_tables reads SQL file and executes it."""
        conn = AsyncMock()
        pool_ctx = AsyncMock()
        pool_ctx.__aenter__ = AsyncMock(return_value=conn)
        pool_ctx.__aexit__ = AsyncMock(return_value=False)
        pool = MagicMock()
        # acquire() must return the context manager itself, not a coroutine, the
        # way an asyncpg pool does. As an AsyncMock it returned a coroutine, so
        # `hasattr(ctx, "__aenter__")` was False and production fell into the
        # manual-release branch -- where `hasattr(db_pool, "release")` is True on
        # any MagicMock and awaiting that MagicMock raised TypeError.
        pool.acquire = MagicMock(return_value=pool_ctx)

        await ensure_vault_tables(pool)

        assert conn.execute.await_count == 2
        first, second = (c.args[0] for c in conn.execute.await_args_list)
        assert "user_vault_secrets" in first
        assert "user_vault_audit" in first
        assert "vault_key_registry" in first
        assert "integrity_fail" in second

    @pytest.mark.asyncio
    async def test_callable(self):
        """ensure_vault_tables is an async callable."""
        import asyncio
        assert asyncio.iscoroutinefunction(ensure_vault_tables)


class TestCryptoHardeningMigration:
    """FEAT-099: 002 schema changes for envelope v2 (conditional, lock-free when applied)."""

    @pytest.fixture
    def sql(self):
        from navigator_auth.vault.migrations import SQL_DIR
        return (SQL_DIR / "002_vault_crypto_hardening.sql").read_text()

    def test_registered_after_001(self):
        from navigator_auth.vault.migrations import MIGRATION_FILES
        assert MIGRATION_FILES == ("001_create_vault_tables.sql", "002_vault_crypto_hardening.sql")

    def test_widens_session_id_to_64(self, sql):
        assert "ALTER COLUMN session_id TYPE VARCHAR(64)" in sql
        assert "character_maximum_length < 64" in sql

    def test_operation_check_allows_new_operations(self, sql):
        assert "'quarantine'" in sql and "'integrity_fail'" in sql
        assert "NOT LIKE '%integrity_fail%'" in sql  # only replaced when outdated

    def test_key_versions_become_integer_only_when_smallint(self, sql):
        assert "data_type = 'smallint'" in sql
        for pair in ("('user_vault_secrets', 'key_version')", "('user_vault_audit', 'key_version')",
                     "('vault_key_registry', 'key_id')"):
            assert pair in sql

    def test_every_change_is_guarded(self, sql):
        """Unconditional ALTERs would lock tables on every startup."""
        body = sql.split("DO $$")[1:]
        assert len(body) == 4
        assert all("IF " in block or "FOR target IN" in block for block in body)
