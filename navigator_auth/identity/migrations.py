"""
Identity Vault Migrations — credential columns on ``auth.user_identities``.

Idempotent; executed at application startup, mirroring the Session Vault
migration. Every file is additive (``ADD COLUMN IF NOT EXISTS``) except
``006``, which removes the legacy ``uid`` column so that ``SELECT *`` readers
— navigator-api's ``ModelHandler`` among them — can hydrate ``UserIdentity``
at all. ``006`` is a guarded no-op on a canonical database and on every
startup after the first.
"""

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("navigator.identity")

SQL_DIR = Path(__file__).parent / "sql"


# Applied in order, at every startup. Idempotent: each file uses
# `ADD COLUMN IF NOT EXISTS` / `CREATE ... IF NOT EXISTS`, or guards its
# effect on a catalog lookup (003, 005, 006).
_MIGRATION_FILES = (
    "001_identity_credentials.sql",
    "002_identity_id_token.sql",
    "003_identity_key_version_integer.sql",
    "004_identity_base_columns.sql",
    "005_identity_legacy_uid_default.sql",
    "006_identity_drop_legacy_uid.sql",
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
            if hasattr(db_pool, "release"):
                await db_pool.release(conn)
            elif hasattr(conn, "release"):
                await conn.release()
            else:
                await conn.close()


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
            await _run_sql(db_pool, sql)
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
