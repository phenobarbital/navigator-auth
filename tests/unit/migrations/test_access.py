"""Unit tests for runtime-role access grants and checks."""

import pytest

from navigator_auth.conf import AUTH_DB_SCHEMA
from navigator_auth.migrations.access import (
    grant_runtime_access,
    missing_runtime_access,
    scope_for,
    validate_runtime_role,
)
from navigator_auth.migrations.runner import MigrationError


def test_scope_matches_spec_and_excludes_unrelated_tables() -> None:
    """Scope released tables correctly and exclude unrelated tables."""
    assert scope_for("vault") == [
        ("auth", "user_vault_secrets"),
        ("auth", "user_vault_audit"),
        ("auth", "vault_key_registry"),
    ]
    assert scope_for("identity") == [("auth", "user_identities")]
    assert scope_for("passkey") == [
        (AUTH_DB_SCHEMA, "user_credentials"),
        (AUTH_DB_SCHEMA, "user_passkey_handles"),
    ]
    assert scope_for("mfa") == []
    assert all(
        table not in {"users", "schema_migrations"}
        for tables in [scope_for("vault"), scope_for("identity")]
        for _, table in tables
    )


@pytest.mark.asyncio
async def test_validate_runtime_role(fake_conn) -> None:
    """Reject blank and absent roles and return an existing role."""
    with pytest.raises(MigrationError, match="runtime role is empty"):
        await validate_runtime_role(fake_conn, "")
    with pytest.raises(MigrationError, match="runtime role is empty"):
        await validate_runtime_role(fake_conn, "  ")

    fake_conn.respond("pg_roles", False)
    with pytest.raises(MigrationError, match="missing-role"):
        await validate_runtime_role(fake_conn, "missing-role")

    fake_conn = type(fake_conn)()
    fake_conn.respond("pg_roles", True)
    assert await validate_runtime_role(fake_conn, "app") == "app"


@pytest.mark.asyncio
async def test_grants_are_scoped_quoted_and_include_owned_sequences(fake_conn) -> None:
    """Grant quoted schema, table, and owned sequence access."""
    fake_conn.relations = {"auth.user_vault_secrets", "auth.user_vault_audit", "auth.vault_key_registry"}
    fake_conn.respond(
        "pg_depend",
        lambda _sql, args: (
            [{"schema": "auth", "name": "user_vault_audit_id_seq"}] if "user_vault_audit" in args[0] else []
        ),
    )

    await grant_runtime_access(fake_conn, "vault", 'app"role')

    grants = [sql for method, sql, _ in fake_conn.statements if method == "execute"]
    assert grants == [
        'GRANT USAGE ON SCHEMA "auth" TO "app""role"',
        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "auth"."user_vault_secrets" TO "app""role"',
        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "auth"."user_vault_audit" TO "app""role"',
        'GRANT USAGE, SELECT ON SEQUENCE "auth"."user_vault_audit_id_seq" TO "app""role"',
        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "auth"."vault_key_registry" TO "app""role"',
    ]


@pytest.mark.asyncio
async def test_absent_tables_are_not_granted(fake_conn) -> None:
    """Do not grant OAuth tables that are not present."""
    fake_conn.relations = {f"{AUTH_DB_SCHEMA}.clients", f"{AUTH_DB_SCHEMA}.policies"}
    fake_conn.respond("pg_depend", [])
    await grant_runtime_access(fake_conn, "oauth2", "app")

    grants = [sql for method, sql, _ in fake_conn.statements if method == "execute"]
    assert len(grants) == 3
    assert all("oauth_" not in sql and "client_access" not in sql for sql in grants)


@pytest.mark.asyncio
async def test_grant_failure_raises_migration_error(fake_conn) -> None:
    """Wrap grant failures with the object and role context."""
    fake_conn.relations = {"auth.user_vault_secrets"}
    fake_conn.fail_on("GRANT", RuntimeError("permission denied"))

    with pytest.raises(MigrationError, match=r"auth.*app.*permission denied"):
        await grant_runtime_access(fake_conn, "vault", "app")


@pytest.mark.asyncio
async def test_missing_runtime_access_reports_without_writes(fake_conn) -> None:
    """Report missing privileges using read-only catalog probes."""
    fake_conn.relations = {"auth.user_vault_secrets"}
    fake_conn.respond("has_schema_privilege", False)
    fake_conn.respond("has_table_privilege", False)
    fake_conn.respond("pg_depend", [])

    missing = await missing_runtime_access(fake_conn, "vault", "app")

    assert missing == [
        "app lacks USAGE on auth",
        "app lacks SELECT on auth.user_vault_secrets",
        "app lacks INSERT on auth.user_vault_secrets",
        "app lacks UPDATE on auth.user_vault_secrets",
        "app lacks DELETE on auth.user_vault_secrets",
    ]
    assert not fake_conn.writes()
