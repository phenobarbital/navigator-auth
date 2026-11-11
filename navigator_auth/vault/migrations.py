"""
Vault Database Migrations — Create and maintain vault tables.

Provides idempotent DDL for the Session Vault system, applied in order by
`navauth self upgrade`; kept for programmatic use and tests:

- ``001_create_vault_tables.sql`` — tables in the ``auth`` schema (``IF NOT EXISTS``).
- ``002_vault_crypto_hardening.sql`` — envelope v2 schema changes (FEAT-099):
  64-char HMAC ``session_id``, ``quarantine``/``integrity_fail`` audit operations
  and INTEGER key versions. Each change is applied only when needed.
"""

import logging
from typing import Any

from ..migrations.catalog import set_dir, set_filenames
from ..migrations.runner import acquire_pooled, execute_checked

logger = logging.getLogger("navigator.vault")

SQL_DIR = set_dir("vault")

# Discovered from navigator_auth/migrations/sql/vault/ (FEAT-110): no hand-written list.
MIGRATION_FILES = set_filenames("vault")


async def ensure_vault_tables(db_pool: Any) -> None:
    """Create vault tables and apply schema changes if needed.

    Executes every file in ``MIGRATION_FILES`` in order. Safe to call
    multiple times (idempotent).

    Args:
        db_pool: asyncpg-compatible connection pool with ``acquire()`` method.
    """
    for filename in MIGRATION_FILES:
        async with acquire_pooled(db_pool) as conn:
            await execute_checked(conn, (SQL_DIR / filename).read_text())

    logger.info("Vault tables ensured.")
