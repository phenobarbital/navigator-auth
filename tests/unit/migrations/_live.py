"""Live PostgreSQL helpers for the FEAT-110 migration tests.

Set ``NAVAUTH_MIGRATIONS_TEST_DSN`` to an admin DSN (CREATEDB + CREATEROLE) of a server you can
create throwaway databases on. Each test gets a fresh, randomly named database and roles, dropped
afterwards; no existing database is ever touched. Without the variable every live test skips.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest

from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE

LIVE_DSN_ENV = "NAVAUTH_MIGRATIONS_TEST_DSN"


def live_admin_dsn() -> str:
    """Return the configured admin DSN, or skip the live test."""
    dsn = os.environ.get(LIVE_DSN_ENV)
    if not dsn:
        pytest.skip(f"{LIVE_DSN_ENV} not set — live migration tests need a disposable PostgreSQL")
    return dsn


def with_database(dsn: str, database: str) -> str:
    """Return ``dsn`` pointing at ``database``."""
    parts = urlsplit(dsn)
    return urlunsplit(parts._replace(path=f"/{database}"))


def _quote_ident(name: str) -> str:
    """Quote a generated or configured PostgreSQL identifier."""
    return '"' + name.replace('"', '""') + '"'


@asynccontextmanager
async def throwaway_database() -> AsyncIterator[str]:
    """Create a random database, yield its admin DSN, and drop it afterwards."""
    admin_dsn = live_admin_dsn()
    try:
        admin_conn = await asyncpg.connect(admin_dsn)
    except (OSError, TimeoutError, asyncpg.InterfaceError, asyncpg.PostgresError) as error:
        pytest.skip(f"disposable PostgreSQL is unavailable: {error}")

    database = f"navauth_mig_{secrets.token_hex(8)}"
    database_created = False
    try:
        await admin_conn.execute(f"CREATE DATABASE {_quote_ident(database)}")
        database_created = True
        yield with_database(admin_dsn, database)
    finally:
        try:
            if database_created:
                await admin_conn.execute(
                    "SELECT pg_terminate_backend(pid) "
                    "FROM pg_stat_activity "
                    "WHERE datname = $1 AND pid <> pg_backend_pid()",
                    database,
                )
                await admin_conn.execute(f"DROP DATABASE IF EXISTS {_quote_ident(database)}")
        finally:
            await admin_conn.close()


@asynccontextmanager
async def runtime_role(admin_conn: asyncpg.Connection) -> AsyncIterator[tuple[str, str]]:
    """Create a random ``LOGIN NOINHERIT`` role and remove it on exit."""
    name = f"navauth_rt_{secrets.token_hex(8)}"
    password = secrets.token_urlsafe(24)
    quoted_name = _quote_ident(name)
    await admin_conn.execute(f"CREATE ROLE {quoted_name} LOGIN NOINHERIT PASSWORD '{password}'")
    try:
        yield name, password
    finally:
        await admin_conn.execute(f"REASSIGN OWNED BY {quoted_name} TO CURRENT_USER")
        await admin_conn.execute(f"DROP OWNED BY {quoted_name}")
        await admin_conn.execute(f"DROP ROLE IF EXISTS {quoted_name}")


async def provision_base_tables(
    conn: asyncpg.Connection,
    *,
    legacy_identity: bool = False,
    with_oauth_base: bool = True,
) -> None:
    """Create the minimal platform-owned tables required by the live migrations."""
    await conn.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    await conn.execute("CREATE SCHEMA IF NOT EXISTS auth")
    if AUTH_DB_SCHEMA != "auth":
        await conn.execute(f"CREATE SCHEMA IF NOT EXISTS {_quote_ident(AUTH_DB_SCHEMA)}")

    auth_users = f'{_quote_ident("auth")}.{_quote_ident("users")}'
    await conn.execute(
        f"CREATE TABLE IF NOT EXISTS {auth_users} " "(user_id SERIAL PRIMARY KEY, username VARCHAR(255))"
    )
    if AUTH_DB_SCHEMA != "auth":
        configured_users = f"{_quote_ident(AUTH_DB_SCHEMA)}.{_quote_ident(AUTH_USERS_TABLE)}"
        await conn.execute(
            f"CREATE TABLE IF NOT EXISTS {configured_users} " "(user_id SERIAL PRIMARY KEY, username VARCHAR(255))"
        )

    identity_table = '"auth"."user_identities"'
    if legacy_identity:
        identity_definition = (
            "user_id INTEGER NOT NULL, auth_provider VARCHAR(255) NOT NULL, "
            "uid VARCHAR(255) NOT NULL, PRIMARY KEY (user_id, uid)"
        )
    else:
        identity_definition = (
            "identity_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id INTEGER NOT NULL, "
            "auth_provider VARCHAR(255) NOT NULL, provider_user_id VARCHAR(255)"
        )
    await conn.execute(f"CREATE TABLE IF NOT EXISTS {identity_table} ({identity_definition})")

    if with_oauth_base:
        schema = _quote_ident(AUTH_DB_SCHEMA)
        clients = f"{schema}.{_quote_ident('clients')}"
        policies = f"{schema}.{_quote_ident('policies')}"
        await conn.execute(
            f"CREATE TABLE IF NOT EXISTS {clients} "
            "(client_id SERIAL PRIMARY KEY, client VARCHAR(255), client_name VARCHAR(255))"
        )
        await conn.execute(f"CREATE TABLE IF NOT EXISTS {policies} (policy_id SERIAL PRIMARY KEY)")
