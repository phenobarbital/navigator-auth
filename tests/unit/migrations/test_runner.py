"""Tests for the FEAT-110 migration runner foundation."""

from collections.abc import Generator
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from asyncdb.interfaces.abstract import AbstractDriver

from navigator_auth.migrations import MigrationStatus, UpgradeReport, get_status as exported_get_status
from navigator_auth.migrations import catalog
from navigator_auth.migrations.runner import (
    MigrationError,
    MigrationState,
    acquire_pooled,
    acquire_raw,
    ensure_ledger,
    execute_checked,
    ledger_exists,
    quote_ident,
)


class AwaitableAcquire:
    """Awaitable pool-acquire result without async-context-manager methods."""

    def __init__(self, connection: object) -> None:
        self.connection = connection

    def __await__(self) -> Generator[object, None, object]:
        async def resolve() -> object:
            return self.connection

        return resolve().__await__()


@pytest.mark.asyncio
async def test_execute_checked_raises_on_asyncdb_error_pair() -> None:
    """Asyncdb error pairs raise while successful pairs and native statuses pass."""
    conn = MagicMock()
    error = RuntimeError("database error")
    conn.execute = AsyncMock(return_value=["ignored", error])
    with pytest.raises(MigrationError) as raised:
        await execute_checked(conn, "SELECT secret")
    assert raised.value.__cause__ is error
    assert "SELECT secret" not in str(raised.value)

    conn.execute = AsyncMock(return_value=["ignored", "message"])
    with pytest.raises(MigrationError) as raised:
        await execute_checked(conn, "SELECT secret")
    assert raised.value.__cause__ is None

    conn.execute = AsyncMock(return_value=["ignored", ""])
    with pytest.raises(MigrationError):
        await execute_checked(conn, "SELECT secret")

    conn.execute = AsyncMock(return_value=["ok", None])
    assert await execute_checked(conn, "SELECT 1") == ["ok", None]
    conn.execute = AsyncMock(return_value="CREATE TABLE")
    assert await execute_checked(conn, "SELECT 1") == "CREATE TABLE"


@pytest.mark.asyncio
async def test_acquire_raw_unwraps_asyncdb_and_releases() -> None:
    """Asyncdb drivers unwrap while context and awaitable pools release correctly."""
    raw_connection = object()
    asyncdb_connection = MagicMock(spec=AbstractDriver)
    asyncdb_connection.get_connection.return_value = raw_connection

    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=asyncdb_connection)
    context.__aexit__ = AsyncMock(return_value=None)
    context_pool = MagicMock()
    context_pool.acquire.return_value = context
    async with acquire_raw(context_pool) as connection:
        assert connection is raw_connection
    context.__aenter__.assert_awaited_once()
    context.__aexit__.assert_awaited_once()

    awaitable_pool = MagicMock()
    awaitable_pool.acquire.return_value = AwaitableAcquire(asyncdb_connection)
    awaitable_pool.release = AsyncMock()
    async with acquire_raw(awaitable_pool) as connection:
        assert connection is raw_connection
    awaitable_pool.release.assert_awaited_once_with(asyncdb_connection)


@pytest.mark.asyncio
async def test_acquire_pooled_yields_pool_connection_unchanged() -> None:
    """Pooled connections are yielded without attempting asyncdb unwrapping."""
    connection = AsyncMock()
    pool = MagicMock()
    pool.acquire.return_value = AwaitableAcquire(connection)
    pool.release = AsyncMock()

    async with acquire_pooled(pool) as acquired:
        assert acquired is connection
    connection.get_connection.assert_not_called()
    pool.release.assert_awaited_once_with(connection)


@pytest.mark.asyncio
async def test_status_without_ledger_is_all_pending_and_writes_nothing(tmp_catalog, fake_conn) -> None:
    """A missing ledger reports every discovered file as pending without DDL."""
    statuses = await exported_get_status(fake_conn)
    assert statuses
    assert all(status.state is MigrationState.PENDING for status in statuses)
    assert not fake_conn.writes()


@pytest.mark.asyncio
async def test_status_marks_changed_on_checksum_mismatch(tmp_catalog, fake_conn) -> None:
    """Ledger checksum mismatches report changed while matches report applied."""
    files = catalog.discover()
    fake_conn.ledger_present = True
    applied_at = datetime.now(timezone.utc)
    fake_conn.ledger[(files[0].migration_set, files[0].filename)] = {
        "migration_set": files[0].migration_set,
        "filename": files[0].filename,
        "checksum": files[0].checksum,
        "applied_at": applied_at,
    }
    fake_conn.ledger[(files[1].migration_set, files[1].filename)] = {
        "migration_set": files[1].migration_set,
        "filename": files[1].filename,
        "checksum": "different",
        "applied_at": applied_at,
    }

    statuses = await exported_get_status(fake_conn)
    assert statuses[0].state is MigrationState.APPLIED
    assert statuses[1].state is MigrationState.CHANGED
    assert statuses[1].recorded_checksum == "different"


@pytest.mark.asyncio
async def test_ensure_ledger_requires_schema_and_grants_public(fake_conn) -> None:
    """Schema absence fails before DDL; a present schema creates and grants the ledger."""
    fake_conn.schema_missing = True
    with pytest.raises(MigrationError):
        await ensure_ledger(fake_conn)
    assert not fake_conn.writes()

    fake_conn.schema_missing = False
    await ensure_ledger(fake_conn)
    assert await ledger_exists(fake_conn)
    writes = fake_conn.writes()
    assert any("CREATE TABLE IF NOT EXISTS" in statement[1] for statement in writes)
    assert any("GRANT SELECT" in statement[1] and "TO PUBLIC" in statement[1] for statement in writes)


def test_quote_ident_doubles_quotes_and_rejects_empty() -> None:
    """Identifiers quote embedded double quotes and reject an empty name."""
    assert quote_ident('a"b') == '"a""b"'
    with pytest.raises(MigrationError):
        quote_ident("")


def test_migrations_package_exports_runner_models() -> None:
    """The package exposes the runner's public status and report models."""
    assert exported_get_status is not None
    assert MigrationStatus is not None
    assert UpgradeReport is not None
