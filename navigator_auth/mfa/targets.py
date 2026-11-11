"""Vault target for sealed MFA seeds."""

import inspect
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, AsyncIterator, Mapping, Optional
from uuid import UUID

from navigator_session.vault.context import ContextValue
from navigator_session.vault.targets.postgres import PostgresTarget, acquire_connection

from ..conf import AUTH_DB_SCHEMA
from .totp import MFA_SEED_PURPOSE


class MfaSecretTarget(PostgresTarget):
    """Sealed TOTP seeds in ``<AUTH_DB_SCHEMA>.user_mfa_secrets``."""

    name = "auth.user_mfa_secrets"
    table = "auth.user_mfa_secrets"
    purpose = MFA_SEED_PURPOSE
    pk_column = "id"
    identity_columns = ("user_id", "provider", "key")
    encrypted_fields = ("ciphertext_db",)
    include_field_in_context = False
    key_version_column = "key_version"
    touch_column = "updated_at"
    state_columns = ("deleted_at", "updated_at")
    quarantine_assignments = "deleted_at = COALESCE(deleted_at, NOW())"

    def __init__(self, db_pool: Any, schema: str = AUTH_DB_SCHEMA) -> None:
        """Bind the target to the auth schema's MFA secret table."""
        self.table = f"{schema}.user_mfa_secrets"
        self.name = self.table
        super().__init__(db_pool)

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[Any]:
        """Run writes on one connection inside a transaction, for asyncpg and asyncdb pools.

        The library implementation calls ``await conn.transaction().start()`` (asyncpg API). An asyncdb
        driver's ``transaction()`` is an awaitable that has already started the transaction and returns the
        driver, which exposes ``commit()``/``rollback()``; this override accepts both. Nested calls reuse
        the outer transaction.
        """
        current = self._conn.get()
        if current is not None:
            yield current
            return
        async with acquire_connection(self._pool) as conn:
            tx = conn.transaction()
            if inspect.isawaitable(tx):
                started = await tx
                tx = conn if started is None else started
            else:
                await tx.start()
            token = self._conn.set(conn)
            try:
                yield conn
            except BaseException:
                await tx.rollback()
                raise
            else:
                await tx.commit()
            finally:
                self._conn.reset(token)

    def context_value(self, column: str, value: Any) -> ContextValue:
        """Match ``mfa_seed_context`` identity types."""
        if column == "user_id":
            return int(value)
        return str(value)

    def pk_from_json(self, value: Any) -> Any:
        """Convert the UUID primary key from a backup record."""
        return value if isinstance(value, UUID) else UUID(str(value))

    def state_from_json(self, column: str, value: Any) -> Any:
        """Convert lifecycle timestamps from a backup record."""
        if value is None or isinstance(value, datetime):
            return value
        return datetime.fromisoformat(value)


def factory(resources: Mapping[str, Any]) -> Optional[MfaSecretTarget]:
    """Build an MFA secret target when an auth database pool is configured."""
    pool = resources.get("db_pool")
    if pool is None:
        return None
    return MfaSecretTarget(pool)
