"""Startup migration checks — read-only (FEAT-110, spec M6).

Application startup no longer applies schema changes; ``navauth self upgrade`` does.
These helpers only read the ledger and the catalog.
"""

from __future__ import annotations

import logging
from typing import Any

from .runner import MigrationState, MigrationStatus, acquire_raw, get_status

logger = logging.getLogger("navigator.migrations")


async def pending_migrations(db_pool: Any) -> list[MigrationStatus]:
    """Return catalog files whose ledger state is not applied.

    Args:
        db_pool: Database pool used for the read-only ledger query.
    """
    async with acquire_raw(db_pool) as conn:
        return [status for status in await get_status(conn) if status.state is not MigrationState.APPLIED]


async def warn_pending_migrations(db_pool: Any) -> None:
    """Log the migration state without blocking application startup.

    Args:
        db_pool: Database pool used for the read-only ledger query.
    """
    try:
        pending = await pending_migrations(db_pool)
    except Exception as err:  # pylint: disable=W0703
        logger.warning(
            "Could not verify database migration state (%s); run `navauth self upgrade --check`",
            type(err).__name__,
        )
        return

    if pending:
        files = ", ".join(
            f"{status.file.migration_set}/{status.file.filename} ({status.state.value})" for status in pending
        )
        logger.warning("Database migrations are pending or changed: %s. Run `navauth self upgrade`.", files)
        return

    logger.info("All database migrations are applied.")


async def tables_present(db_pool: Any, *qualified_names: str) -> bool:
    """Return whether every qualified relation name resolves with ``to_regclass``.

    Args:
        db_pool: Database pool used for the read-only relation probes.
        qualified_names: Schema-qualified relation names to verify.
    """
    async with acquire_raw(db_pool) as conn:
        for name in qualified_names:
            if not await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", name):
                return False
    return True
