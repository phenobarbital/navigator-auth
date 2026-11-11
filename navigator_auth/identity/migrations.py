"""
Identity Vault Migrations — credential columns on ``auth.user_identities``.

Idempotent. Applied by `navauth self upgrade`; kept for programmatic use and tests. Every file is additive (``ADD COLUMN IF NOT EXISTS``) except
``006``, which removes the legacy ``uid`` column so that ``SELECT *`` readers
— navigator-api's ``ModelHandler`` among them — can hydrate ``UserIdentity``
at all. ``006`` is a guarded no-op on a canonical database and on every
run after the first.
"""

import logging
from typing import Any

from ..migrations.catalog import set_dir, set_filenames
from ..migrations.runner import acquire_pooled, execute_checked

logger = logging.getLogger("navigator.identity")

SQL_DIR = set_dir("identity")


# Discovered from navigator_auth/migrations/sql/identity/ (FEAT-110): no hand-written list.
_MIGRATION_FILES = set_filenames("identity")


async def ensure_identity_columns(db_pool: Any) -> None:
    """Bring ``auth.user_identities`` in line with the ``UserIdentity`` model.

    Runs every migration file in ``_MIGRATION_FILES``, in order. Each file is
    idempotent; ``006`` additionally drops the legacy ``uid`` column when a
    legacy table still carries one, and skips with a warning when another
    object depends on it.

    A failing file does **not** stop the ones after it: every file is run in
    its own connection and its own transaction, and each guards its effect on
    a catalog lookup, so a later migration is never invalidated by an earlier
    failure — it either applies or skips on its own terms (``006`` warns and
    leaves ``uid`` alone when ``004`` never added ``identity_id``). Each
    failure is logged with the file that caused it, and the whole set is
    re-raised as one error after every file has had its turn, so a partial
    application is reported rather than hidden behind the first exception.

    Args:
        db_pool: asyncpg-compatible connection pool with ``acquire()`` method.

    Raises:
        RuntimeError: when one or more migration files failed, naming each of
            them and chained to the first underlying exception.
    """
    failures: list[str] = []
    first_error: Exception | None = None

    for filename in _MIGRATION_FILES:
        try:
            sql = (SQL_DIR / filename).read_text()
            async with acquire_pooled(db_pool) as conn:
                await execute_checked(conn, sql)
        except Exception as err:  # pylint: disable=W0703
            failures.append(filename)
            if first_error is None:
                first_error = err
            logger.error(f"Identity migration {filename} failed: {err} — continuing with the remaining migrations.")

    if failures:
        raise RuntimeError(
            f"{len(failures)} of {len(_MIGRATION_FILES)} identity migrations failed: {', '.join(failures)}"
        ) from first_error

    logger.info("Identity credential columns ensured.")


async def setup_identity_columns(db_pool: Any) -> None:
    """Non-blocking wrapper used at startup: logs errors, never raises.

    ``ensure_identity_columns`` has already logged each individual failure and
    applied every migration it could, so what is logged here is the summary of
    what is still missing on this database.
    """
    try:
        await ensure_identity_columns(db_pool)
    except Exception as err:  # pylint: disable=W0703
        logger.error(f"Failed to ensure identity credential columns: {err}")
