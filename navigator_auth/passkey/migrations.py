"""Passkey tables — idempotent startup migration (FEAT-101).

Mirrors ``navigator_auth/identity/migrations.py``. Applied by
`navauth self upgrade`; kept for programmatic use and tests.
"""

import logging
from typing import Any

from ..migrations.catalog import render_sql, set_dir, set_filenames
from ..migrations.runner import acquire_pooled, execute_checked

logger = logging.getLogger("navigator.passkey")

SQL_DIR = set_dir("passkey")

_MIGRATION_FILES = set_filenames("passkey")


async def ensure_passkey_tables(db_pool: Any) -> None:
    """Create the passkey tables if they don't already exist.

    Args:
        db_pool: asyncpg-compatible pool with an ``acquire()`` method (``app["authdb"]``).
    """
    for filename in _MIGRATION_FILES:
        sql = render_sql((SQL_DIR / filename).read_text())
        async with acquire_pooled(db_pool) as conn:
            await execute_checked(conn, sql)
    logger.info("Passkey tables ensured.")


async def setup_passkey_tables(db_pool: Any) -> None:
    """Non-blocking wrapper used at startup: logs errors, never raises."""
    try:
        await ensure_passkey_tables(db_pool)
    except Exception as err:  # pylint: disable=W0703
        logger.error("Failed to ensure passkey tables: %s", err)
