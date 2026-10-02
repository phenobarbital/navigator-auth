"""Passkey tables — idempotent startup migration (FEAT-101).

Mirrors ``navigator_auth/identity/migrations.py``. Run by
``PasskeyAuth.on_startup`` so the tables only exist when the backend is enabled.
"""
import logging
from pathlib import Path
from typing import Any

from ..conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE

logger = logging.getLogger("navigator.passkey")

SQL_DIR = Path(__file__).parent / "sql"

_MIGRATION_FILES = ("001_passkey_credentials.sql",)


def render_sql(sql: str) -> str:
    """Substitute ``{schema}`` and ``{users_table}`` in a migration file."""
    return sql.replace("{schema}", AUTH_DB_SCHEMA).replace("{users_table}", AUTH_USERS_TABLE)


async def _run_sql(db_pool: Any, sql: str) -> None:
    ctx = db_pool.acquire()
    if hasattr(ctx, "__aenter__"):
        async with ctx as conn:
            await conn.execute(sql)
    else:
        conn = await ctx
        try:
            await conn.execute(sql)
        finally:
            if hasattr(db_pool, "release"):
                await db_pool.release(conn)
            elif hasattr(conn, "release"):
                await conn.release()
            else:
                await conn.close()


async def ensure_passkey_tables(db_pool: Any) -> None:
    """Create the passkey tables if they don't already exist.

    Args:
        db_pool: asyncpg-compatible pool with an ``acquire()`` method (``app["authdb"]``).
    """
    for filename in _MIGRATION_FILES:
        sql = render_sql((SQL_DIR / filename).read_text())
        await _run_sql(db_pool, sql)
    logger.info("Passkey tables ensured.")


async def setup_passkey_tables(db_pool: Any) -> None:
    """Non-blocking wrapper used at startup: logs errors, never raises."""
    try:
        await ensure_passkey_tables(db_pool)
    except Exception as err:  # pylint: disable=W0703
        logger.error("Failed to ensure passkey tables: %s", err)
