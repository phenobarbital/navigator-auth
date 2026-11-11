import re

import asyncpg
import pytest

from navigator_auth.migrations.catalog import render_sql, set_dir
from navigator_auth.migrations.runner import upgrade

from ._live import provision_base_tables, runtime_role, throwaway_database

SQL_PATH = set_dir("oauth2") / "001_oauth2_schema.sql"
TABLES = ("oauth_refresh_tokens", "oauth_grants", "oauth_access_tokens", "oauth_device_codes", "client_access")
CLIENT_COLUMNS = (
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
INDEXES = (
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


def test_oauth2_sql_is_guarded_and_has_no_seed_data():
    """Check safety guards, placeholders, and the absence of fabricated client data."""
    sql = SQL_PATH.read_text()

    assert "test_client_secret" not in sql
    assert "localhost" not in sql
    assert "DROP CONSTRAINT" not in sql
    assert not re.search(r"\bauth\.", sql)
    assert re.search(r"ALTER TABLE IF EXISTS \{schema\}\.clients", sql)
    assert all(re.search(rf"ADD COLUMN IF NOT EXISTS\s+{re.escape(column)}\b", sql) for column in CLIENT_COLUMNS)

    add_constraint_block = re.search(r"(?s)DO \$\$.*?ADD CONSTRAINT clients_client_uid_key.*?END\s*\$\$;", sql)
    assert add_constraint_block
    assert "FROM pg_constraint" in add_constraint_block.group(0)
    assert re.findall(r"ALTER COLUMN (\w+) SET NOT NULL", sql) == ["client_name", "client_uid"]
    assert "{schema}" in sql
    assert "{users_table}" in sql


def test_oauth2_sql_covers_every_object_of_old_ddl():
    """Check coverage of the legacy OAuth2 schema and removal of its source file."""
    sql = SQL_PATH.read_text()

    for name in (*TABLES, *CLIENT_COLUMNS, *INDEXES, "scopes"):
        assert re.search(rf"\b{re.escape(name)}\b", sql), name
    assert not (SQL_PATH.parents[4] / "backends/oauth2/ddl.sql").exists()


@pytest.mark.asyncio
async def test_oauth2_completion_live() -> None:
    """OAuth2 completion remains pending until client names are repaired, then is idempotent."""
    async with throwaway_database() as dsn:
        admin_conn = await asyncpg.connect(dsn)
        try:
            await provision_base_tables(admin_conn)
            await admin_conn.execute(
                'INSERT INTO "auth"."clients" (client, client_name) VALUES (NULL, NULL)'
            )
            async with runtime_role(admin_conn) as (role, _password):
                blocked = await upgrade(admin_conn, sets=["oauth2"], runtime_role=role)
                assert [result.file.filename for result in blocked.failed] == ["001_oauth2_schema.sql"]
                assert not await admin_conn.fetchval(
                    "SELECT EXISTS (SELECT 1 FROM \"auth\".\"schema_migrations\" "
                    "WHERE migration_set = 'oauth2' AND filename = '001_oauth2_schema.sql')"
                )

                await admin_conn.execute(
                    'UPDATE "auth"."clients" SET client = \'live-client\', client_name = \'Live Client\' '
                    "WHERE client IS NULL OR client_name IS NULL"
                )
                repaired = await upgrade(admin_conn, sets=["oauth2"], runtime_role=role)
                assert [result.file.filename for result in repaired.applied] == ["001_oauth2_schema.sql"]
                assert not repaired.failed

                rendered_sql = render_sql(SQL_PATH.read_text(encoding="utf-8"))
                await admin_conn.execute(rendered_sql)
                await admin_conn.execute(rendered_sql)
        finally:
            await admin_conn.close()
