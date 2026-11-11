"""Migration runner — fail-closed execution, ledger and status (FEAT-110, spec M2)."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import datetime
from enum import Enum
from typing import Any

from asyncdb.interfaces.abstract import AbstractDriver
from pydantic import BaseModel, Field

from ..conf import AUTH_DB_SCHEMA
from .catalog import MigrationFile, discover

logger = logging.getLogger("navigator.migrations")

LEDGER_TABLE = "schema_migrations"
ADVISORY_LOCK_KEY: int = 1102026

_LEDGER_DDL = """
CREATE TABLE IF NOT EXISTS {ledger} (
    migration_set   VARCHAR(64)  NOT NULL,
    filename        VARCHAR(255) NOT NULL,
    checksum        CHAR(64)     NOT NULL,
    applied_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    applied_by      TEXT         NOT NULL DEFAULT current_user,
    package_version VARCHAR(32),
    execution_ms    INTEGER,
    PRIMARY KEY (migration_set, filename)
)
"""


class MigrationError(Exception):
    """A statement failed, or the database is not usable for migrations."""


class MigrationState(str, Enum):
    """Ledger state of one catalog file."""

    APPLIED = "applied"
    PENDING = "pending"
    CHANGED = "changed"


class MigrationStatus(BaseModel):
    """State of one catalog file against the ledger."""

    file: MigrationFile
    state: MigrationState
    applied_at: datetime | None = None
    recorded_checksum: str | None = None


class MigrationResult(BaseModel):
    """Outcome of applying one file."""

    file: MigrationFile
    ok: bool
    error: str | None = None
    duration_ms: int = 0


class UpgradeReport(BaseModel):
    """Outcome of one ``upgrade()`` run."""

    applied: list[MigrationResult] = Field(default_factory=list)
    failed: list[MigrationResult] = Field(default_factory=list)
    skipped_changed: list[MigrationStatus] = Field(default_factory=list)
    access_errors: list[str] = Field(default_factory=list)


def quote_ident(name: str) -> str:
    """Quote a PostgreSQL identifier.

    Args:
        name: Identifier to quote.

    Raises:
        MigrationError: When ``name`` is empty.
    """
    if not name:
        raise MigrationError("Empty SQL identifier")
    return '"' + name.replace('"', '""') + '"'


def ledger_name() -> str:
    """Return the quoted ``<AUTH_DB_SCHEMA>.schema_migrations`` name."""
    return f"{quote_ident(AUTH_DB_SCHEMA)}.{quote_ident(LEDGER_TABLE)}"


@asynccontextmanager
async def acquire_pooled(db_pool: Any) -> AsyncIterator[Any]:
    """Yield a connection from ``db_pool`` exactly as the pool returns it.

    Handles both asynchronous context-manager and awaitable ``acquire()``
    styles, releasing awaitable-acquired connections like the legacy runners.
    """
    ctx = db_pool.acquire()
    if hasattr(ctx, "__aenter__"):
        async with ctx as conn:
            yield conn
        return
    conn = await ctx
    try:
        yield conn
    finally:
        if hasattr(db_pool, "release"):
            await db_pool.release(conn)
        elif hasattr(conn, "release"):
            await conn.release()
        else:
            await conn.close()


@asynccontextmanager
async def acquire_raw(db_pool: Any) -> AsyncIterator[Any]:
    """Yield a raw asyncpg connection from an asyncpg or asyncdb pool."""
    async with acquire_pooled(db_pool) as conn:
        yield conn.get_connection() if isinstance(conn, AbstractDriver) else conn


async def execute_checked(conn: Any, sql: str, *args: Any) -> Any:
    """Execute SQL and translate asyncdb's returned errors into exceptions."""
    result = await conn.execute(sql, *args)
    if isinstance(result, (list, tuple)) and len(result) == 2 and result[1] is not None:
        error = result[1]
        message = f"Migration statement failed: {error}"
        if isinstance(error, BaseException):
            raise MigrationError(message) from error
        raise MigrationError(message)
    return result


async def ledger_exists(conn: Any) -> bool:
    """Return whether ``<schema>.schema_migrations`` exists."""
    return bool(await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", ledger_name()))


async def ensure_ledger(conn: Any) -> None:
    """Create the ledger table and grant public read access.

    Raises:
        MigrationError: When the Navigator-owned base schema does not exist.
    """
    exists = await conn.fetchval("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)", AUTH_DB_SCHEMA)
    if not exists:
        raise MigrationError(f"Schema {AUTH_DB_SCHEMA!r} does not exist; it is provisioned by the Navigator platform")
    await execute_checked(conn, _LEDGER_DDL.format(ledger=ledger_name()))
    await execute_checked(conn, f"GRANT SELECT ON {ledger_name()} TO PUBLIC")


async def get_status(conn: Any, sets: Iterable[str] | None = None) -> list[MigrationStatus]:
    """Return each catalog file's ledger state without creating the ledger."""
    files = discover(sets)
    rows: dict[tuple[str, str], Any] = {}
    if await ledger_exists(conn):
        for row in await conn.fetch(f"SELECT migration_set, filename, checksum, applied_at FROM {ledger_name()}"):
            rows[(row["migration_set"], row["filename"])] = row

    statuses: list[MigrationStatus] = []
    for file in files:
        row = rows.get((file.migration_set, file.filename))
        if row is None:
            statuses.append(MigrationStatus(file=file, state=MigrationState.PENDING))
        elif row["checksum"] == file.checksum:
            statuses.append(
                MigrationStatus(
                    file=file,
                    state=MigrationState.APPLIED,
                    applied_at=row["applied_at"],
                    recorded_checksum=row["checksum"],
                )
            )
        else:
            statuses.append(
                MigrationStatus(
                    file=file,
                    state=MigrationState.CHANGED,
                    applied_at=row["applied_at"],
                    recorded_checksum=row["checksum"],
                )
            )
    return statuses
