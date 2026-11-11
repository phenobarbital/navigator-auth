"""Migration runner — fail-closed execution, ledger and status (FEAT-110, spec M2)."""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import datetime
from enum import Enum
from typing import Any

from asyncdb.interfaces.abstract import AbstractDriver
from pydantic import BaseModel, Field

from ..conf import AUTH_DB_SCHEMA
from ..version import __version__
from .catalog import MigrationFile, discover, render_sql

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


_UPSERT_SQL = """
INSERT INTO {ledger} (migration_set, filename, checksum, package_version, execution_ms)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (migration_set, filename) DO UPDATE SET
    checksum = EXCLUDED.checksum,
    applied_at = now(),
    applied_by = current_user,
    package_version = EXCLUDED.package_version,
    execution_ms = EXCLUDED.execution_ms
"""


async def _upsert_ledger(conn: Any, file: MigrationFile, duration_ms: int) -> None:
    """Record ``file`` as applied with its current checksum."""
    await execute_checked(
        conn,
        _UPSERT_SQL.format(ledger=ledger_name()),
        file.migration_set,
        file.filename,
        file.checksum,
        __version__,
        duration_ms,
    )


async def _apply_file(conn: Any, file: MigrationFile, runtime_role: str) -> MigrationResult:
    """Apply one file in one transaction; never raises — failures become ``ok=False``."""
    from .access import grant_runtime_access, verify_runtime_access  # noqa: PLC0415 — cycle
    from .checks import check_postconditions, check_prerequisites  # noqa: PLC0415 — cycle

    started = time.monotonic()
    try:
        async with conn.transaction():
            await check_prerequisites(conn, file)
            await execute_checked(conn, render_sql(file.path.read_text(encoding="utf-8")))
            await check_postconditions(conn, file)
            await grant_runtime_access(conn, file.migration_set, runtime_role)
            await verify_runtime_access(conn, file.migration_set, runtime_role)
            duration_ms = int((time.monotonic() - started) * 1000)
            await _upsert_ledger(conn, file, duration_ms)
    except Exception as err:  # pylint: disable=W0703
        duration_ms = int((time.monotonic() - started) * 1000)
        logger.error("Migration %s/%s failed: %s", file.migration_set, file.filename, err)
        return MigrationResult(file=file, ok=False, error=str(err), duration_ms=duration_ms)
    return MigrationResult(file=file, ok=True, duration_ms=duration_ms)


async def _reconcile_access(conn: Any, migration_set: str, runtime_role: str) -> list[str]:
    """Grant + verify one set's runtime access in its own transaction; return error strings."""
    from .access import grant_runtime_access, verify_runtime_access  # noqa: PLC0415 — cycle

    try:
        async with conn.transaction():
            await grant_runtime_access(conn, migration_set, runtime_role)
            await verify_runtime_access(conn, migration_set, runtime_role)
    except Exception as err:  # pylint: disable=W0703
        logger.error("Runtime access for set %s could not be reconciled: %s", migration_set, err)
        return [f"{migration_set}: {err}"]
    return []


async def upgrade(
    conn: Any,
    sets: Iterable[str] | None = None,
    *,
    runtime_role: str,
    reapply_changed: bool = False,
    fail_fast: bool = False,
) -> UpgradeReport:
    """Apply pending files (and changed ones when ``reapply_changed``).

    Holds ``pg_advisory_lock(ADVISORY_LOCK_KEY)`` for the run. Each file: prerequisite
    checks + SQL + postcondition checks + runtime grants + ledger upsert in one
    transaction. A failure rolls back the entire file, is recorded in ``report.failed``
    and the run continues, unless ``fail_fast``. Access for already-applied selected
    files is reconciled as well; failures appear in ``report.access_errors``.

    Raises:
        MigrationError: invalid runtime role, missing schema, or the lock cannot be taken.
    """
    from .access import validate_runtime_role  # noqa: PLC0415 — cycle

    await validate_runtime_role(conn, runtime_role)
    report = UpgradeReport()
    await execute_checked(conn, "SELECT pg_advisory_lock($1)", ADVISORY_LOCK_KEY)
    try:
        await ensure_ledger(conn)
        statuses = await get_status(conn, sets)
        applied_sets: list[str] = []
        stopped = False
        for status in statuses:
            if status.state is MigrationState.APPLIED:
                if status.file.migration_set not in applied_sets:
                    applied_sets.append(status.file.migration_set)
                continue
            if status.state is MigrationState.CHANGED and not reapply_changed:
                report.skipped_changed.append(status)
                continue
            result = await _apply_file(conn, status.file, runtime_role)
            if result.ok:
                report.applied.append(result)
            else:
                report.failed.append(result)
                if fail_fast:
                    stopped = True
                    break
        if not stopped:
            for migration_set in applied_sets:
                errors = await _reconcile_access(conn, migration_set, runtime_role)
                report.access_errors.extend(errors)
                if errors and fail_fast:
                    break
    finally:
        try:
            await execute_checked(conn, "SELECT pg_advisory_unlock($1)", ADVISORY_LOCK_KEY)
        except Exception as err:  # pylint: disable=W0703
            logger.warning("Could not release migration advisory lock: %s", err)
    return report
