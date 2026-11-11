"""Durable security-state tables — idempotent startup migration (FEAT-106 review fixes, spec M4)."""

import logging
from pathlib import Path
from typing import Any

from ..conf import AUTH_DB_SCHEMA
from ..mfa.migrations import _with_conn, render_sql
from .store import SecurityStateError

logger = logging.getLogger("navigator.auth.security_state")

SQL_DIR = Path(__file__).parent / "sql"
_MIGRATION_FILES = ("001_security_state.sql",)
SECURITY_STATE_TABLES = ("recovery_confirm_consumptions", "oauth_user_generation")


async def ensure_security_state_tables(db_pool: Any) -> None:
    """Create the security-state tables if missing.

    Args:
        db_pool: Database pool (``app["authdb"]``).

    Raises:
        SecurityStateError: If asyncdb reports an execution error.
    """
    for filename in _MIGRATION_FILES:
        sql = render_sql((SQL_DIR / filename).read_text())

        async def _apply(conn: Any, _sql: str = sql, _name: str = filename) -> None:
            result = await conn.execute(_sql)
            if isinstance(result, (list, tuple)) and len(result) == 2 and result[1]:
                raise SecurityStateError(f"security-state migration {_name} failed: {type(result[1]).__name__}")

        await _with_conn(db_pool, _apply)
    logger.info("Security-state tables ensured.")


async def security_state_tables_present(db_pool: Any) -> bool:
    """Return whether every security-state relation exists (to_regclass probe)."""
    names = [f"{AUTH_DB_SCHEMA}.{table}" for table in SECURITY_STATE_TABLES]

    async def _probe(conn: Any) -> bool:
        count = await conn.fetchval(
            "SELECT count(*) FROM unnest($1::text[]) AS t(name) WHERE to_regclass(t.name) IS NOT NULL",
            names,
        )
        return count == len(SECURITY_STATE_TABLES)

    return await _with_conn(db_pool, _probe)


async def setup_security_state_tables(db_pool: Any) -> bool:
    """Ensure the tables and report readiness; never raises (startup must not fail).

    Returns:
        True only after successful DDL and a successful relation probe.
    """
    if db_pool is None:
        logger.critical("Security-state tables unavailable: no authdb pool")
        return False
    try:
        await ensure_security_state_tables(db_pool)
        ready = await security_state_tables_present(db_pool)
    except Exception as err:  # pylint: disable=W0703
        logger.critical("Security-state tables unavailable: %s", type(err).__name__)
        return False
    if not ready:
        logger.critical("Security-state tables missing; password reset, recovery and OAuth tokens will fail closed")
    return ready
