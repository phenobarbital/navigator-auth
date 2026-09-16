"""
Vault Database Migrations — Create and maintain vault tables.

Provides idempotent DDL for the Session Vault system, applied in order at every
startup:

- ``001_create_vault_tables.sql`` — tables in the ``auth`` schema (``IF NOT EXISTS``).
- ``002_vault_crypto_hardening.sql`` — envelope v2 schema changes (FEAT-099):
  64-char HMAC ``session_id``, ``quarantine``/``integrity_fail`` audit operations
  and INTEGER key versions. Each change is applied only when needed.
"""
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("navigator.vault")

SQL_DIR = Path(__file__).parent / "sql"

# Applied in order, at every startup. Each file is idempotent.
MIGRATION_FILES = (
    "001_create_vault_tables.sql",
    "002_vault_crypto_hardening.sql",
)


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
            if hasattr(db_pool, 'release'):
                await db_pool.release(conn)
            elif hasattr(conn, 'release'):
                await conn.release()
            else:
                await conn.close()


async def ensure_vault_tables(db_pool: Any) -> None:
    """Create vault tables and apply schema changes if needed.

    Executes every file in ``MIGRATION_FILES`` in order. Safe to call
    multiple times (idempotent).

    Args:
        db_pool: asyncpg-compatible connection pool with ``acquire()`` method.
    """
    for filename in MIGRATION_FILES:
        await _run_sql(db_pool, (SQL_DIR / filename).read_text())

    logger.info("Vault tables ensured.")
