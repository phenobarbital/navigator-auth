"""MFA tables applied by ``navauth self upgrade``; kept for programmatic use and tests."""

import logging
from typing import Any

from ..conf import AUTH_DB_SCHEMA
from ..migrations.catalog import render_sql, set_dir, set_filenames
from .exceptions import MfaStorageError

logger = logging.getLogger("navigator.mfa")

SQL_DIR = set_dir("mfa")
_MIGRATION_FILES = set_filenames("mfa")
MFA_TABLES = (
    "tenant_mfa_policy",
    "user_mfa",
    "user_mfa_backup_codes",
    "user_trusted_devices",
    "user_mfa_audit",
    "user_mfa_security",
    "user_mfa_secrets",
)
MFA_COLUMNS = {
    "tenant_mfa_policy": "org_id mode remember_days enforced_at enforced_by updated_at",
    "user_mfa": "user_id provider enabled confirmed_at created_at last_used_at",
    "user_mfa_backup_codes": "id user_id code_hash used_at created_at",
    "user_trusted_devices": "id user_id token_hash family_id label created_at expires_at last_used_at rotated_at revoked_at revoke_reason",
    "user_mfa_audit": "id occurred_at actor_user_id target_user_id org_id action old_state new_state method request_id outcome detail",
    "user_mfa_security": "user_id version updated_at",
    "user_mfa_secrets": "id user_id provider key ciphertext_db key_version created_at updated_at deleted_at",
}
MFA_INDEXES = {
    "tenant_mfa_policy_pkey": ("tenant_mfa_policy", True),
    "user_mfa_pkey": ("user_mfa", True),
    "user_mfa_backup_codes_pkey": ("user_mfa_backup_codes", True),
    "user_mfa_backup_codes_user_idx": ("user_mfa_backup_codes", False),
    "user_trusted_devices_pkey": ("user_trusted_devices", True),
    "user_trusted_devices_token_hash_key": ("user_trusted_devices", True),
    "user_trusted_devices_user_idx": ("user_trusted_devices", False),
    "user_trusted_devices_family_idx": ("user_trusted_devices", False),
    "user_mfa_audit_pkey": ("user_mfa_audit", True),
    "user_mfa_audit_target_idx": ("user_mfa_audit", False),
    "user_mfa_security_pkey": ("user_mfa_security", True),
    "user_mfa_secrets_pkey": ("user_mfa_secrets", True),
    "user_mfa_secrets_active_unique": ("user_mfa_secrets", True),
}


async def _with_conn(db_pool: Any, fn: Any) -> Any:
    """Run a coroutine on a connection from either supported pool acquire shape.

    Args:
        db_pool: Database pool exposing ``acquire``.
        fn: Coroutine function that receives the acquired connection.

    Returns:
        The result returned by ``fn``.
    """
    ctx = db_pool.acquire()
    if hasattr(ctx, "__aenter__"):
        async with ctx as conn:
            return await fn(conn)
    conn = await ctx
    try:
        return await fn(conn)
    finally:
        if hasattr(db_pool, "release"):
            await db_pool.release(conn)
        elif hasattr(conn, "release"):
            await conn.release()
        else:
            await conn.close()


def _raise_on_execute_error(result: Any, filename: str) -> None:
    """Raise storage error when asyncdb returns an execute error slot.

    Args:
        result: Value returned by ``conn.execute``.
        filename: Migration filename used in the safe error message.

    Raises:
        MfaStorageError: If the returned error slot is populated.
    """
    if isinstance(result, (list, tuple)) and len(result) == 2 and result[1]:
        err = result[1]
        raise MfaStorageError(f"MFA migration {filename} failed: {type(err).__name__}")


async def ensure_mfa_tables(db_pool: Any) -> None:
    """Apply MFA migrations; kept for programmatic use and tests.

    Args:
        db_pool: Database pool used to execute migrations.

    Raises:
        MfaStorageError: If asyncdb reports an execution error.
    """
    for filename in _MIGRATION_FILES:
        sql = render_sql((SQL_DIR / filename).read_text())

        async def _apply(conn: Any, _sql: str = sql, _name: str = filename) -> None:
            _raise_on_execute_error(await conn.execute(_sql), _name)

        await _with_conn(db_pool, _apply)
    logger.info("MFA tables ensured.")


async def mfa_tables_present(db_pool: Any) -> bool:
    """Return whether required relations, columns and usable indexes exist.

    Args:
        db_pool: Database pool used for the relation probe.

    Returns:
        True only when every MFA relation exists.
    """
    names = [f"{AUTH_DB_SCHEMA}.{table}" for table in MFA_TABLES]

    async def _probe(conn: Any) -> bool:
        count = await conn.fetchval(
            "SELECT count(*) FROM unnest($1::text[]) AS t(name) " "WHERE to_regclass(t.name) IS NOT NULL",
            names,
        )
        if count != len(MFA_TABLES):
            return False
        columns = [
            (f"{AUTH_DB_SCHEMA}.{table}", column) for table, names in MFA_COLUMNS.items() for column in names.split()
        ]
        count = await conn.fetchval(
            "SELECT count(*) FROM unnest($1::text[], $2::text[]) AS required(relation, name) "
            "WHERE EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid=to_regclass(required.relation) "
            "AND a.attname=required.name AND a.attnum>0 AND NOT a.attisdropped)",
            [table for table, _ in columns],
            [column for _, column in columns],
        )
        if count != len(columns):
            return False
        count = await conn.fetchval(
            "SELECT count(*) FROM unnest($1::text[], $2::text[], $3::bool[]) AS required(name, relation, unique_index) "
            "WHERE EXISTS (SELECT 1 FROM pg_index i WHERE i.indexrelid=to_regclass(required.name) "
            "AND i.indrelid=to_regclass(required.relation) AND i.indisvalid AND i.indisready "
            "AND (NOT required.unique_index OR i.indisunique))",
            [f"{AUTH_DB_SCHEMA}.{name}" for name in MFA_INDEXES],
            [f"{AUTH_DB_SCHEMA}.{table}" for table, _ in MFA_INDEXES.values()],
            [unique for _, unique in MFA_INDEXES.values()],
        )
        return count == len(MFA_INDEXES)

    return await _with_conn(db_pool, _probe)


async def setup_mfa_tables(db_pool: Any) -> bool:
    """Ensure tables and return whether all of them are usable.

    Args:
        db_pool: Database pool used at application startup.

    Returns:
        True only after successful DDL and relation probe; otherwise False.
    """
    if db_pool is None:
        logger.error("MFA tables unavailable: NoneType")
        return False
    try:
        await ensure_mfa_tables(db_pool)
        return await mfa_tables_present(db_pool)
    except Exception as err:  # pylint: disable=W0703
        logger.error("MFA tables unavailable: %s", type(err).__name__)
        return False
