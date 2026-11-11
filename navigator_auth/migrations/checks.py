"""Prerequisite and completion checks for migration files (FEAT-110, spec M2 completion contract).

Read-only: every function here runs catalog queries only. ``runner.upgrade()`` calls
``check_prerequisites`` before a file's SQL and ``check_postconditions`` after it, inside
the file's transaction, so an unmet condition rolls the file back and leaves it pending.
"""
from __future__ import annotations

import logging
from typing import Any

from ..conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE
from .catalog import MigrationFile
from .runner import MigrationError, quote_ident

logger = logging.getLogger("navigator.migrations")

RELEASED_SCHEMA = "auth"

OAUTH2_FILE = ("oauth2", "001_oauth2_schema.sql")
OAUTH2_TABLES: tuple[str, ...] = (
    "oauth_refresh_tokens",
    "oauth_grants",
    "oauth_access_tokens",
    "oauth_device_codes",
    "client_access",
)
OAUTH2_CLIENT_COLUMNS: tuple[str, ...] = (
    "client",
    "client_name",
    "client_type",
    "client_secret",
    "redirect_uris",
    "policy_uri",
    "client_logo_uri",
    "user_id",
    "default_scopes",
    "allowed_grant_types",
    "is_active",
    "expiration_date",
    "created_at",
    "updated_at",
    "client_uid",
    "token_endpoint_auth_method",
    "registration_source",
    "enforce_access_gate",
)
OAUTH2_NOT_NULL: tuple[tuple[str, str], ...] = (("clients", "client_name"), ("clients", "client_uid"))
OAUTH2_NULLABLE: tuple[tuple[str, str], ...] = (("clients", "client_secret"), ("clients", "user_id"))
OAUTH2_UNIQUE: tuple[tuple[str, str], ...] = (("clients", "client_uid"),)
OAUTH2_FOREIGN_KEYS: tuple[tuple[str, str, str], ...] = (
    ("clients", "user_id", AUTH_USERS_TABLE),
    ("oauth_refresh_tokens", "client_id", "clients"),
    ("oauth_refresh_tokens", "user_id", AUTH_USERS_TABLE),
    ("oauth_grants", "user_id", AUTH_USERS_TABLE),
    ("oauth_access_tokens", "user_id", AUTH_USERS_TABLE),
    ("oauth_access_tokens", "client_id", "clients"),
    ("oauth_device_codes", "client_id", "clients"),
    ("oauth_device_codes", "user_id", AUTH_USERS_TABLE),
    ("client_access", "user_id", AUTH_USERS_TABLE),
    ("client_access", "client_id", "clients"),
    ("client_access", "granted_by", AUTH_USERS_TABLE),
)
OAUTH2_INDEXES: tuple[str, ...] = (
    "idx_oauth_refresh_tokens_user",
    "idx_oauth_refresh_tokens_client",
    "idx_oauth_refresh_tokens_parent",
    "idx_oauth_grants_user",
    "idx_oauth_access_tokens_jti",
    "idx_oauth_access_tokens_user",
    "idx_oauth_device_codes_device_code",
    "idx_oauth_device_codes_user_code",
    "idx_oauth_device_codes_client",
    "idx_oauth_device_codes_status_expires",
    "idx_clients_registration_source",
    "uq_client_access_user_client",
    "uq_client_access_user_client_uid",
    "idx_client_access_client_uid",
    "idx_client_access_client_status",
)

_COLUMN_SQL = (
    "SELECT a.attnotnull FROM pg_attribute a "
    "WHERE a.attrelid = to_regclass($1) AND a.attname = $2 AND a.attnum > 0 AND NOT a.attisdropped"
)
_UNIQUE_SQL = (
    "SELECT EXISTS (SELECT 1 FROM pg_index i "
    "JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0] "
    "WHERE i.indrelid = to_regclass($1) AND i.indisunique AND i.indnkeyatts = 1 "
    "AND i.indpred IS NULL AND a.attname = $2)"
)
_FK_SQL = (
    "SELECT EXISTS (SELECT 1 FROM pg_constraint c "
    "JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey) "
    "WHERE c.contype = 'f' AND c.conrelid = to_regclass($1) AND c.confrelid = to_regclass($2) "
    "AND a.attname = $3)"
)


def qualified(schema: str, name: str) -> str:
    """Return ``\"schema\".\"name\"`` with both parts quoted."""
    return f"{quote_ident(schema)}.{quote_ident(name)}"


async def relation_exists(conn: Any, schema: str, name: str) -> bool:
    """Return whether ``schema.name`` resolves with ``to_regclass``."""
    return bool(await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", qualified(schema, name)))


async def column_not_null(conn: Any, schema: str, table: str, column: str) -> bool | None:
    """Return a column's ``attnotnull``, or ``None`` when it is absent."""
    row = await conn.fetchrow(_COLUMN_SQL, qualified(schema, table), column)
    return None if row is None else bool(row["attnotnull"])


async def has_unique_on(conn: Any, schema: str, table: str, column: str) -> bool:
    """Return whether a non-partial, single-column unique index exists."""
    return bool(await conn.fetchval(_UNIQUE_SQL, qualified(schema, table), column))


async def has_foreign_key(conn: Any, schema: str, table: str, column: str, ref_table: str) -> bool:
    """Return whether a foreign key references ``schema.ref_table``."""
    return bool(await conn.fetchval(_FK_SQL, qualified(schema, table), qualified(schema, ref_table), column))


def prerequisite_tables(migration_set: str) -> tuple[tuple[str, str], ...]:
    """Return ``(schema, table)`` base tables needed by a migration set."""
    if migration_set == "vault":
        return ((RELEASED_SCHEMA, "users"),)
    if migration_set == "identity":
        return ((RELEASED_SCHEMA, "user_identities"),)
    if migration_set == "passkey":
        return ((AUTH_DB_SCHEMA, AUTH_USERS_TABLE),)
    if migration_set == "oauth2":
        return ((AUTH_DB_SCHEMA, AUTH_USERS_TABLE), (AUTH_DB_SCHEMA, "clients"), (AUTH_DB_SCHEMA, "policies"))
    return ()


async def check_prerequisites(conn: Any, file: MigrationFile) -> None:
    """Raise ``MigrationError`` naming every absent base table for ``file``."""
    missing = [
        f"{schema}.{table}"
        for schema, table in prerequisite_tables(file.migration_set)
        if not await relation_exists(conn, schema, table)
    ]
    if missing:
        raise MigrationError(
            f"{file.migration_set}/{file.filename}: missing base table(s) {', '.join(missing)}; "
            "base tables are provisioned by the Navigator platform"
        )


async def _oauth2_unmet(conn: Any) -> list[str]:
    """Return every unmet OAuth2 schema-completion condition."""
    unmet = await _tables_unmet(conn, AUTH_DB_SCHEMA, OAUTH2_TABLES)
    columns: dict[tuple[str, str], bool | None] = {}

    for column in OAUTH2_CLIENT_COLUMNS:
        state = await column_not_null(conn, AUTH_DB_SCHEMA, "clients", column)
        columns[("clients", column)] = state
        if state is None:
            unmet.append(f"clients.{column} is missing")

    scopes_state = await column_not_null(conn, AUTH_DB_SCHEMA, "policies", "scopes")
    columns[("policies", "scopes")] = scopes_state
    if scopes_state is None:
        unmet.append("policies.scopes is missing")

    for table, column in OAUTH2_NOT_NULL:
        state = columns[(table, column)]
        if state is False:
            unmet.append(f"{table}.{column} is nullable (backfill {column}, then re-run)")

    for table, column in OAUTH2_NULLABLE:
        state = columns[(table, column)]
        if state is True:
            unmet.append(f"{table}.{column} is not nullable")

    for table, column in OAUTH2_UNIQUE:
        if not await has_unique_on(conn, AUTH_DB_SCHEMA, table, column):
            unmet.append(f"{table}.{column} is not uniquely constrained")

    for table, column, ref_table in OAUTH2_FOREIGN_KEYS:
        if not await has_foreign_key(conn, AUTH_DB_SCHEMA, table, column, ref_table):
            unmet.append(f"{table}.{column} is missing foreign key to {ref_table}")

    for index in OAUTH2_INDEXES:
        if not await relation_exists(conn, AUTH_DB_SCHEMA, index):
            unmet.append(f"index {index} is missing")
    return unmet


async def _identity_006_unmet(conn: Any) -> list[str]:
    """Return an error when ``auth.user_identities.uid`` remains."""
    uid_state = await column_not_null(conn, RELEASED_SCHEMA, "user_identities", "uid")
    if uid_state is None:
        return []
    return [
        "auth.user_identities.uid remains; repair missing identity_id, dependent objects, or duplicate identifiers and re-run"
    ]


async def _tables_unmet(conn: Any, schema: str, tables: tuple[str, ...]) -> list[str]:
    """Return names of tables absent from ``schema``."""
    return [f"{schema}.{table} is missing" for table in tables if not await relation_exists(conn, schema, table)]


async def check_postconditions(conn: Any, file: MigrationFile) -> None:
    """Raise ``MigrationError`` naming every unmet completion condition of ``file``."""
    key = (file.migration_set, file.filename)
    unmet: list[str] = []
    if key == ("vault", "001_create_vault_tables.sql"):
        unmet = await _tables_unmet(
            conn,
            RELEASED_SCHEMA,
            ("user_vault_secrets", "user_vault_audit", "vault_key_registry"),
        )
    elif key == ("passkey", "001_passkey_credentials.sql"):
        unmet = await _tables_unmet(conn, AUTH_DB_SCHEMA, ("user_passkey_handles", "user_credentials"))
    elif key == ("identity", "006_identity_drop_legacy_uid.sql"):
        unmet = await _identity_006_unmet(conn)
    elif key == OAUTH2_FILE:
        unmet = await _oauth2_unmet(conn)

    if unmet:
        raise MigrationError(f"{file.migration_set}/{file.filename} incomplete: {'; '.join(unmet)}")
