"""
Identity Vault Migrations — credential columns on ``auth.user_identities``.

Additive and idempotent (``ADD COLUMN IF NOT EXISTS``); executed at
application startup, mirroring the Session Vault migration.
"""
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("navigator.identity")

SQL_DIR = Path(__file__).parent / "sql"


async def ensure_identity_columns(db_pool: Any) -> None:
    """Add identity-credential columns if they don't already exist.

    Args:
        db_pool: asyncpg-compatible connection pool with ``acquire()`` method.
    """
    sql_file = SQL_DIR / "001_identity_credentials.sql"
    sql = sql_file.read_text()

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

    logger.info("Identity credential columns ensured.")


async def setup_identity_columns(db_pool: Any) -> None:
    """Non-blocking wrapper used at startup: logs errors, never raises."""
    try:
        await ensure_identity_columns(db_pool)
    except Exception as err:  # pylint: disable=W0703
        logger.error("Failed to ensure identity credential columns: %s", err)
