"""Runtime-role grants and access checks (FEAT-110, spec ``Runtime access contract``).

Migrations run as an admin role; the application connects as the runtime role
(``--runtime-role`` or ``DBUSER``). This module grants that role exactly the access the
application needs on the tables each migration set owns, and verifies it.
"""

from __future__ import annotations

import logging
from typing import Any

from ..conf import AUTH_DB_SCHEMA
from .runner import MigrationError, execute_checked, quote_ident

logger = logging.getLogger("navigator.migrations")

RELEASED_SCHEMA = "auth"
TABLE_PRIVILEGES: tuple[str, ...] = ("SELECT", "INSERT", "UPDATE", "DELETE")
SEQUENCE_PRIVILEGES: tuple[str, ...] = ("USAGE", "SELECT")

# (schema, table); a schema of None means AUTH_DB_SCHEMA (templated migrations).
RUNTIME_TABLES: dict[str, tuple[tuple[str | None, str], ...]] = {
    "vault": (
        (RELEASED_SCHEMA, "user_vault_secrets"),
        (RELEASED_SCHEMA, "user_vault_audit"),
        (RELEASED_SCHEMA, "vault_key_registry"),
    ),
    "identity": ((RELEASED_SCHEMA, "user_identities"),),
    "passkey": ((None, "user_credentials"), (None, "user_passkey_handles")),
    "mfa": (
        (None, "tenant_mfa_policy"),
        (None, "user_mfa"),
        (None, "user_mfa_backup_codes"),
        (None, "user_trusted_devices"),
        (None, "user_mfa_audit"),
        (None, "user_mfa_security"),
        (None, "user_mfa_secrets"),
    ),
    "oauth2": (
        (None, "clients"),
        (None, "policies"),
        (None, "oauth_refresh_tokens"),
        (None, "oauth_grants"),
        (None, "oauth_access_tokens"),
        (None, "oauth_device_codes"),
        (None, "client_access"),
    ),
}

_SEQUENCES_SQL = (
    "SELECT n.nspname AS schema, s.relname AS name FROM pg_depend d "
    "JOIN pg_class s ON s.oid = d.objid JOIN pg_namespace n ON n.oid = s.relnamespace "
    "WHERE d.classid = 'pg_class'::regclass AND d.refclassid = 'pg_class'::regclass "
    "AND d.refobjid = to_regclass($1) AND d.deptype IN ('a', 'i') AND s.relkind = 'S'"
)


def _qualified(schema: str, name: str) -> str:
    """Return a safely quoted qualified PostgreSQL identifier."""
    return f"{quote_ident(schema)}.{quote_ident(name)}"


def scope_for(migration_set: str) -> list[tuple[str, str]]:
    """Resolve the ``(schema, table)`` grant scope for a migration set."""
    return [(schema or AUTH_DB_SCHEMA, table) for schema, table in RUNTIME_TABLES.get(migration_set, ())]


async def validate_runtime_role(conn: Any, role: str | None) -> str:
    """Return ``role`` when it is non-empty and exists in ``pg_roles``.

    Args:
        conn: Database connection used for the catalog lookup.
        role: Runtime database role to validate.

    Raises:
        MigrationError: If ``role`` is empty or does not exist.
    """
    if role is None or not role.strip():
        raise MigrationError("runtime role is empty; pass --runtime-role or set DBUSER")

    exists = await conn.fetchval("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", role)
    if not exists:
        raise MigrationError(f"runtime role {role!r} does not exist")
    return role


async def existing_tables(conn: Any, migration_set: str) -> list[tuple[str, str]]:
    """Return the set's scoped tables that currently exist."""
    return [
        (schema, table)
        for schema, table in scope_for(migration_set)
        if await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", _qualified(schema, table))
    ]


async def owned_sequences(conn: Any, schema: str, table: str) -> list[tuple[str, str]]:
    """Return sequences owned by columns of ``schema.table``."""
    rows = await conn.fetch(_SEQUENCES_SQL, _qualified(schema, table))
    return [(row["schema"], row["name"]) for row in rows or ()]


async def grant_runtime_access(conn: Any, migration_set: str, role: str) -> None:
    """Grant ``role`` the set's runtime access on existing objects.

    Args:
        conn: Database connection used for discovery and grants.
        migration_set: Migration set whose runtime objects are being granted.
        role: Runtime database role receiving the grants.

    Raises:
        MigrationError: If a grant or its required catalog discovery fails.
    """
    tables = await existing_tables(conn, migration_set)
    role_q = quote_ident(role)
    schemas: list[str] = []
    for schema, _ in tables:
        if schema not in schemas:
            schemas.append(schema)

    for schema in schemas:
        sql = f"GRANT USAGE ON SCHEMA {quote_ident(schema)} TO {role_q}"
        try:
            await execute_checked(conn, sql)
        except Exception as err:
            raise MigrationError(f"could not grant USAGE on schema {schema} to {role}: {err}") from err

    for schema, table in tables:
        qualified = _qualified(schema, table)
        sql = f"GRANT {', '.join(TABLE_PRIVILEGES)} ON TABLE {qualified} TO {role_q}"
        try:
            await execute_checked(conn, sql)
        except Exception as err:
            raise MigrationError(f"could not grant table access on {schema}.{table} to {role}: {err}") from err

        try:
            sequences = await owned_sequences(conn, schema, table)
        except Exception as err:
            raise MigrationError(f"could not discover sequences for {schema}.{table} to {role}: {err}") from err
        for sequence_schema, sequence in sequences:
            sequence_name = _qualified(sequence_schema, sequence)
            sql = f"GRANT {', '.join(SEQUENCE_PRIVILEGES)} ON SEQUENCE {sequence_name} TO {role_q}"
            try:
                await execute_checked(conn, sql)
            except Exception as err:
                raise MigrationError(
                    f"could not grant sequence access on {sequence_schema}.{sequence} to {role}: {err}"
                ) from err

    logger.debug("Granted runtime access for set %s to %s", migration_set, role)


async def missing_runtime_access(conn: Any, migration_set: str, role: str) -> list[str]:
    """Return one message for each missing privilege on existing scoped objects."""
    tables = await existing_tables(conn, migration_set)
    missing: list[str] = []
    schemas: list[str] = []
    for schema, _ in tables:
        if schema not in schemas:
            schemas.append(schema)

    for schema in schemas:
        granted = await conn.fetchval("SELECT has_schema_privilege($1, $2, 'USAGE')", role, schema)
        if not granted:
            missing.append(f"{role} lacks USAGE on {schema}")

    for schema, table in tables:
        qualified = _qualified(schema, table)
        for privilege in TABLE_PRIVILEGES:
            granted = await conn.fetchval("SELECT has_table_privilege($1, $2, $3)", role, qualified, privilege)
            if not granted:
                missing.append(f"{role} lacks {privilege} on {schema}.{table}")

        for sequence_schema, sequence in await owned_sequences(conn, schema, table):
            qualified_sequence = _qualified(sequence_schema, sequence)
            for privilege in SEQUENCE_PRIVILEGES:
                granted = await conn.fetchval(
                    "SELECT has_sequence_privilege($1, $2, $3)", role, qualified_sequence, privilege
                )
                if not granted:
                    missing.append(f"{role} lacks {privilege} on {sequence_schema}.{sequence}")
    return missing


async def verify_runtime_access(conn: Any, migration_set: str, role: str) -> None:
    """Raise ``MigrationError`` listing every missing privilege; return when complete."""
    missing = await missing_runtime_access(conn, migration_set, role)
    if missing:
        raise MigrationError("; ".join(missing))
