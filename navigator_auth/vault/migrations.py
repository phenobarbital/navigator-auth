"""
Vault Database Migrations — Create and maintain vault tables.

Provides idempotent table creation for the Session Vault system.
All tables are created in the ``auth`` schema using ``IF NOT EXISTS``.
"""
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("navigator.vault")

SQL_DIR = Path(__file__).parent / "sql"


async def ensure_vault_tables(db_pool: Any) -> None:
    """Create vault tables if they don't already exist.

    Reads the DDL from ``sql/001_create_vault_tables.sql`` and executes it.
    Safe to call multiple times (idempotent).

    Args:
        db_pool: asyncpg-compatible connection pool with ``acquire()`` method.
    """
    sql_file = SQL_DIR / "001_create_vault_tables.sql"
    sql = sql_file.read_text()
    async with db_pool.acquire() as conn:
        await conn.execute(sql)
    logger.info("Vault tables ensured.")
