"""Tests for migration prerequisites and completion checks."""
from pathlib import Path

import pytest

from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE
from navigator_auth.migrations.catalog import MigrationFile
from navigator_auth.migrations.checks import (
    OAUTH2_CLIENT_COLUMNS,
    OAUTH2_INDEXES,
    OAUTH2_TABLES,
    check_postconditions,
    check_prerequisites,
)
from navigator_auth.migrations.runner import MigrationError


def _file(migration_set: str, filename: str) -> MigrationFile:
    """Create a migration file model that need not exist on disk."""
    return MigrationFile(migration_set=migration_set, filename=filename, path=Path(filename), checksum="a" * 64)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("migration_set", "filename", "missing"),
    [
        ("vault", "001_create_vault_tables.sql", "auth.users"),
        ("identity", "006_identity_drop_legacy_uid.sql", "auth.user_identities"),
        ("passkey", "001_passkey_credentials.sql", f"{AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE}"),
        ("oauth2", "001_oauth2_schema.sql", f"{AUTH_DB_SCHEMA}.clients"),
    ],
)
async def test_missing_prerequisite_fails_each_set(fake_conn, migration_set, filename, missing):
    """Every set reports its absent prerequisite table."""
    with pytest.raises(MigrationError, match=missing):
        await check_prerequisites(fake_conn, _file(migration_set, filename))


@pytest.mark.asyncio
async def test_identity_006_incomplete_while_uid_exists(fake_conn):
    """Identity 006 remains pending until its legacy uid column is absent."""
    file = _file("identity", "006_identity_drop_legacy_uid.sql")
    fake_conn.respond("pg_attribute", {"attnotnull": False})

    with pytest.raises(MigrationError, match="uid"):
        await check_postconditions(fake_conn, file)

    fake_conn = type(fake_conn)()
    await check_postconditions(fake_conn, file)


def _configure_complete_oauth2(fake_conn, broken: str | None = None) -> None:
    """Configure the fake catalog responses for a complete OAuth2 migration."""
    tables = {f"{AUTH_DB_SCHEMA}.{table}" for table in OAUTH2_TABLES}
    tables.update(f"{AUTH_DB_SCHEMA}.{index}" for index in OAUTH2_INDEXES)
    if broken == "missing_table":
        tables.remove(f"{AUTH_DB_SCHEMA}.oauth_grants")
    if broken != "missing_index":
        fake_conn.relations = tables
    else:
        fake_conn.relations = tables.difference({f"{AUTH_DB_SCHEMA}.{OAUTH2_INDEXES[0]}"})

    def catalog_response(sql, args):
        if "pg_index" in sql:
            return broken != "client_uid_not_unique"
        if "pg_constraint" in sql:
            return broken != "missing_fk"
        if "pg_attribute" in sql:
            column = args[1]
            if broken == "nullable_client_name" and column == "client_name":
                return {"attnotnull": False}
            return {"attnotnull": column in {"client_name", "client_uid"}}
        if "to_regclass" in sql:
            return str(args[0]).replace('"', "") in fake_conn.relations
        return None

    fake_conn.respond("SELECT", catalog_response)


@pytest.mark.asyncio
async def test_oauth2_complete_passes(fake_conn):
    """All required OAuth2 catalog objects satisfy the completion rule."""
    _configure_complete_oauth2(fake_conn)
    await check_postconditions(fake_conn, _file("oauth2", "001_oauth2_schema.sql"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("broken", "expected"),
    [
        ("missing_table", "oauth_grants"),
        ("nullable_client_name", "client_name"),
        ("client_uid_not_unique", "client_uid"),
        ("missing_fk", "foreign key"),
        ("missing_index", OAUTH2_INDEXES[0]),
    ],
)
async def test_oauth2_each_unmet_condition_fails(fake_conn, broken, expected):
    """Each independently broken OAuth2 condition is reported."""
    _configure_complete_oauth2(fake_conn, broken)

    with pytest.raises(MigrationError, match=expected):
        await check_postconditions(fake_conn, _file("oauth2", "001_oauth2_schema.sql"))


@pytest.mark.asyncio
async def test_file_without_rule_passes_and_checks_never_execute(fake_conn):
    """Files with no completion rule issue no writes and pass."""
    await check_postconditions(fake_conn, _file("identity", "001_identity_credentials.sql"))
    assert not fake_conn.writes()
