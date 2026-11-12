"""Startup migration checks — read-only (FEAT-110, spec M6).

Application startup no longer applies schema changes; ``navauth self upgrade`` does.
These helpers only read the ledger and the catalog.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from .. import conf
from .runner import MigrationState, MigrationStatus, acquire_raw, get_status

logger = logging.getLogger("navigator.migrations")


def enabled_migration_sets(backends: Sequence[Any] | None = None) -> list[str]:
    """Return the migration sets this deployment actually uses.

    ``vault`` and ``identity`` are core. ``passkey`` and ``oauth2`` count only when an
    authentication backend names them, and ``mfa`` only when BasicAuth 2FA is enabled,
    so operators who never use a feature get no permanent startup warning.

    Args:
        backends: Backend dotted paths or classes in use; ``conf.AUTHENTICATION_BACKENDS``
            when omitted.
    """
    configured = conf.AUTHENTICATION_BACKENDS if backends is None else backends
    names = " ".join(
        item if isinstance(item, str) else f"{getattr(item, '__module__', '')}.{getattr(item, '__name__', item)}"
        for item in configured
    ).lower()
    sets = ["vault", "identity"]
    if "passkey" in names:
        sets.append("passkey")
    if conf.AUTH_BASIC_2FA_ENABLED:
        sets.append("mfa")
    if "oauth2" in names:
        sets.append("oauth2")
    return sets


async def pending_migrations(db_pool: Any, sets: Sequence[str] | None = None) -> list[MigrationStatus]:
    """Return catalog files whose ledger state is not applied.

    Args:
        db_pool: Database pool used for the read-only ledger query.
        sets: Migration sets to inspect; every set when omitted.
    """
    async with acquire_raw(db_pool) as conn:
        return [status for status in await get_status(conn, sets) if status.state is not MigrationState.APPLIED]


async def warn_pending_migrations(db_pool: Any, backends: Sequence[Any] | None = None) -> None:
    """Log the state of the enabled migration sets without blocking application startup.

    Args:
        db_pool: Database pool used for the read-only ledger query.
        backends: Authentication backends in use, to decide which sets are enabled.
    """
    try:
        pending = await pending_migrations(db_pool, enabled_migration_sets(backends))
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
