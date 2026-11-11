"""MFA tables — idempotent startup migration with a usability flag (FEAT-106, spec M8)."""

import logging
from pathlib import Path
from typing import Any

from ..conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE
from .exceptions import MfaStorageError

logger = logging.getLogger("navigator.mfa")

SQL_DIR = Path(__file__).parent / "sql"
_MIGRATION_FILES = ("001_mfa_tables.sql",)
MFA_TABLES = (
    "tenant_mfa_policy",
    "user_mfa",
    "user_mfa_backup_codes",
    "user_trusted_devices",
    "user_mfa_audit",
    "user_mfa_security",
)


def render_sql(sql: str) -> str:
    """Substitute migration schema and users-table placeholders.

    Args:
        sql: Migration SQL containing placeholder names.

    Returns:
        Rendered migration SQL.
    """
    return sql.replace("{schema}", AUTH_DB_SCHEMA).replace("{users_table}", AUTH_USERS_TABLE)


async def _with_conn(db_pool: Any, fn: Any) -> Any:
    """Run a coroutine on a connection from either supported pool acquire shape.

    Args:
        db_pool: Database pool exposing ``acquire``.
        fn: Coroutine function that receives the acquired connection.

    Returns:
        The result returned by ``fn``.
    """
    ctx = db_pool.acquire()
    if hasattr(ctx, "__aenter__"):
        async with ctx as conn:
            return await fn(conn)
    conn = await ctx
    try:
        return await fn(conn)
    finally:
        if hasattr(db_pool, "release"):
            await db_pool.release(conn)
        elif hasattr(conn, "release"):
            await conn.release()
        else:
            await conn.close()


def _raise_on_execute_error(result: Any, filename: str) -> None:
    """Raise storage error when asyncdb returns an execute error slot.

    Args:
        result: Value returned by ``conn.execute``.
        filename: Migration filename used in the safe error message.

    Raises:
        MfaStorageError: If the returned error slot is populated.
    """
    if isinstance(result, (list, tuple)) and len(result) == 2 and result[1]:
        err = result[1]
        raise MfaStorageError(f"MFA migration {filename} failed: {type(err).__name__}")


async def ensure_mfa_tables(db_pool: Any) -> None:
    """Create the six MFA tables if missing.

    Args:
        db_pool: Database pool used to execute migrations.

    Raises:
        MfaStorageError: If asyncdb reports an execution error.
    """
    for filename in _MIGRATION_FILES:
        sql = render_sql((SQL_DIR / filename).read_text())

        async def _apply(conn: Any, _sql: str = sql, _name: str = filename) -> None:
            _raise_on_execute_error(await conn.execute(_sql), _name)

        await _with_conn(db_pool, _apply)
    logger.info("MFA tables ensured.")


async def mfa_tables_present(db_pool: Any) -> bool:
    """Return whether all required MFA relations exist.

    Args:
        db_pool: Database pool used for the relation probe.

    Returns:
        True only when every MFA relation exists.
    """
    names = [f"{AUTH_DB_SCHEMA}.{table}" for table in MFA_TABLES]

    async def _probe(conn: Any) -> bool:
        count = await conn.fetchval(
            "SELECT count(*) FROM unnest($1::text[]) AS t(name) " "WHERE to_regclass(t.name) IS NOT NULL",
            names,
        )
        return count == len(MFA_TABLES)

    return await _with_conn(db_pool, _probe)


async def setup_mfa_tables(db_pool: Any) -> bool:
    """Ensure tables and return whether all of them are usable.

    Args:
        db_pool: Database pool used at application startup.

    Returns:
        True only after successful DDL and relation probe; otherwise False.
    """
    if db_pool is None:
        logger.error("MFA tables unavailable: NoneType")
        return False
    try:
        await ensure_mfa_tables(db_pool)
        return await mfa_tables_present(db_pool)
    except Exception as err:  # pylint: disable=W0703
        logger.error("MFA tables unavailable: %s", type(err).__name__)
        return False
