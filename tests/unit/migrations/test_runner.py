"""Tests for the FEAT-110 migration runner foundation."""

from collections.abc import Generator
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import asyncpg
import pytest
from asyncdb.interfaces.abstract import AbstractDriver

from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE
from navigator_auth.migrations import MigrationStatus, UpgradeReport, get_status as exported_get_status
from navigator_auth.migrations import catalog
from navigator_auth.migrations.access import missing_runtime_access
from navigator_auth.migrations.runner import (
    get_status,
    MigrationError,
    MigrationState,
    acquire_pooled,
    acquire_raw,
    ensure_ledger,
    execute_checked,
    ledger_exists,
    quote_ident,
    upgrade,
)


class AwaitableAcquire:
    """Awaitable pool-acquire result without async-context-manager methods."""

    def __init__(self, connection: object) -> None:
        self.connection = connection

    def __await__(self) -> Generator[object, None, object]:
        async def resolve() -> object:
            return self.connection

        return resolve().__await__()


@pytest.mark.asyncio
async def test_execute_checked_raises_on_asyncdb_error_pair() -> None:
    """Asyncdb error pairs raise while successful pairs and native statuses pass."""
    conn = MagicMock()
    error = RuntimeError("database error")
    conn.execute = AsyncMock(return_value=["ignored", error])
    with pytest.raises(MigrationError) as raised:
        await execute_checked(conn, "SELECT secret")
    assert raised.value.__cause__ is error
    assert "SELECT secret" not in str(raised.value)

    conn.execute = AsyncMock(return_value=["ignored", "message"])
    with pytest.raises(MigrationError) as raised:
        await execute_checked(conn, "SELECT secret")
    assert raised.value.__cause__ is None

    conn.execute = AsyncMock(return_value=["ignored", ""])
    with pytest.raises(MigrationError):
        await execute_checked(conn, "SELECT secret")

    conn.execute = AsyncMock(return_value=["ok", None])
    assert await execute_checked(conn, "SELECT 1") == ["ok", None]
    conn.execute = AsyncMock(return_value="CREATE TABLE")
    assert await execute_checked(conn, "SELECT 1") == "CREATE TABLE"


@pytest.mark.asyncio
async def test_acquire_raw_unwraps_asyncdb_and_releases() -> None:
    """Asyncdb drivers unwrap while context and awaitable pools release correctly."""
    raw_connection = object()
    asyncdb_connection = MagicMock(spec=AbstractDriver)
    asyncdb_connection.get_connection.return_value = raw_connection

    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=asyncdb_connection)
    context.__aexit__ = AsyncMock(return_value=None)
    context_pool = MagicMock()
    context_pool.acquire.return_value = context
    async with acquire_raw(context_pool) as connection:
        assert connection is raw_connection
    context.__aenter__.assert_awaited_once()
    context.__aexit__.assert_awaited_once()

    awaitable_pool = MagicMock()
    awaitable_pool.acquire.return_value = AwaitableAcquire(asyncdb_connection)
    awaitable_pool.release = AsyncMock()
    async with acquire_raw(awaitable_pool) as connection:
        assert connection is raw_connection
    awaitable_pool.release.assert_awaited_once_with(asyncdb_connection)


@pytest.mark.asyncio
async def test_acquire_pooled_yields_pool_connection_unchanged() -> None:
    """Pooled connections are yielded without attempting asyncdb unwrapping."""
    connection = AsyncMock()
    pool = MagicMock()
    pool.acquire.return_value = AwaitableAcquire(connection)
    pool.release = AsyncMock()

    async with acquire_pooled(pool) as acquired:
        assert acquired is connection
    connection.get_connection.assert_not_called()
    pool.release.assert_awaited_once_with(connection)


@pytest.mark.asyncio
async def test_status_without_ledger_is_all_pending_and_writes_nothing(tmp_catalog, fake_conn) -> None:
    """A missing ledger reports every discovered file as pending without DDL."""
    statuses = await exported_get_status(fake_conn)
    assert statuses
    assert all(status.state is MigrationState.PENDING for status in statuses)
    assert not fake_conn.writes()


@pytest.mark.asyncio
async def test_status_marks_changed_on_checksum_mismatch(tmp_catalog, fake_conn) -> None:
    """Ledger checksum mismatches report changed while matches report applied."""
    files = catalog.discover()
    fake_conn.ledger_present = True
    applied_at = datetime.now(timezone.utc)
    fake_conn.ledger[(files[0].migration_set, files[0].filename)] = {
        "migration_set": files[0].migration_set,
        "filename": files[0].filename,
        "checksum": files[0].checksum,
        "applied_at": applied_at,
    }
    fake_conn.ledger[(files[1].migration_set, files[1].filename)] = {
        "migration_set": files[1].migration_set,
        "filename": files[1].filename,
        "checksum": "different",
        "applied_at": applied_at,
    }

    statuses = await exported_get_status(fake_conn)
    assert statuses[0].state is MigrationState.APPLIED
    assert statuses[1].state is MigrationState.CHANGED
    assert statuses[1].recorded_checksum == "different"


@pytest.mark.asyncio
async def test_ensure_ledger_requires_schema_and_grants_public(fake_conn) -> None:
    """Schema absence fails before DDL; a present schema creates and grants the ledger."""
    fake_conn.schema_missing = True
    with pytest.raises(MigrationError):
        await ensure_ledger(fake_conn)
    assert not fake_conn.writes()

    fake_conn.schema_missing = False
    await ensure_ledger(fake_conn)
    assert await ledger_exists(fake_conn)
    writes = fake_conn.writes()
    assert any("CREATE TABLE IF NOT EXISTS" in statement[1] for statement in writes)
    assert any("GRANT SELECT" in statement[1] and "TO PUBLIC" in statement[1] for statement in writes)


def test_quote_ident_doubles_quotes_and_rejects_empty() -> None:
    """Identifiers quote embedded double quotes and reject an empty name."""
    assert quote_ident('a"b') == '"a""b"'
    with pytest.raises(MigrationError):
        quote_ident("")


def test_migrations_package_exports_runner_models() -> None:
    """The package exposes the runner's public status and report models."""
    assert exported_get_status is not None
    assert MigrationStatus is not None
    assert UpgradeReport is not None


ROLE = "app"


def _ready(fake_conn, *relations: str) -> None:
    """Configure the fake for a valid role, satisfied privileges and base tables."""
    fake_conn.relations = {"auth.users", "auth.user_identities", *relations}
    fake_conn.respond("pg_roles", True)
    fake_conn.respond("has_schema_privilege", True)
    fake_conn.respond("has_table_privilege", True)
    fake_conn.respond("has_sequence_privilege", True)
    fake_conn.respond("pg_depend", [])


def _sqls(fake_conn) -> list[str]:
    return [sql for method, sql, _ in fake_conn.statements if method == "execute"]


@pytest.mark.asyncio
async def test_upgrade_applies_pending_in_order_and_records_ledger(tmp_catalog, fake_conn) -> None:
    """Each file runs in a transaction and is recorded; three ledger rows."""
    _ready(fake_conn)
    report = await upgrade(fake_conn, runtime_role=ROLE)
    assert sorted(r.file.filename for r in report.applied) == ["001_first.sql", "001_third.sql", "002_second.sql"]
    vault = [r.file.filename for r in report.applied if r.file.migration_set == "vault"]
    assert vault == ["001_first.sql", "002_second.sql"]
    assert not report.failed
    assert len(fake_conn.ledger) == 3
    transactions = [s[1] for s in fake_conn.statements if s[0] == "transaction"]
    assert transactions.count("BEGIN") == 3 and transactions.count("COMMIT") == 3
    sqls = _sqls(fake_conn)
    insert_positions = [i for i, q in enumerate(sqls) if "INSERT INTO" in q]
    assert len(insert_positions) == 3
    assert any("GRANT" in q for q in sqls[: insert_positions[0]])


@pytest.mark.asyncio
async def test_upgrade_continues_after_failure_and_reports_it(tmp_catalog, fake_conn) -> None:
    """A failing file is reported, has no row, and later files still run."""
    _ready(fake_conn)
    (tmp_catalog / "vault" / "002_second.sql").write_text("SELECT 'BOOM';")
    fake_conn.fail_on("BOOM", RuntimeError("boom"))
    report = await upgrade(fake_conn, runtime_role=ROLE)
    assert [r.file.filename for r in report.failed] == ["002_second.sql"]
    assert ("vault", "002_second.sql") not in fake_conn.ledger
    assert ("identity", "001_third.sql") in fake_conn.ledger
    assert ("vault", "001_first.sql") in fake_conn.ledger


@pytest.mark.asyncio
async def test_upgrade_fail_fast_stops(tmp_catalog, fake_conn) -> None:
    """fail_fast stops at the first failure."""
    _ready(fake_conn)
    (tmp_catalog / "vault" / "002_second.sql").write_text("SELECT 'BOOM';")
    fake_conn.fail_on("BOOM", RuntimeError("boom"))
    report = await upgrade(fake_conn, runtime_role=ROLE, fail_fast=True)
    assert len(report.failed) == 1
    assert ("identity", "001_third.sql") not in fake_conn.ledger
    assert not any("'identity'" in q for q in _sqls(fake_conn))


@pytest.mark.asyncio
async def test_upgrade_skips_changed_unless_reapply(tmp_catalog, fake_conn) -> None:
    """Changed files are skipped unless reapply_changed, which updates the row."""
    _ready(fake_conn)
    fake_conn.ledger_present = True
    files = catalog.discover()
    target = files[0]
    key = (target.migration_set, target.filename)
    fake_conn.ledger[key] = {
        "migration_set": key[0],
        "filename": key[1],
        "checksum": "stale",
        "applied_at": datetime.now(timezone.utc),
    }
    report = await upgrade(fake_conn, runtime_role=ROLE)
    assert [s.file.filename for s in report.skipped_changed] == [target.filename]
    assert fake_conn.ledger[key]["checksum"] == "stale"

    report = await upgrade(fake_conn, runtime_role=ROLE, reapply_changed=True)
    assert not report.skipped_changed
    assert fake_conn.ledger[key]["checksum"] == target.checksum


@pytest.mark.asyncio
async def test_upgrade_takes_and_releases_advisory_lock(tmp_catalog, fake_conn) -> None:
    """The lock is taken once and released on success and on run-level errors."""
    _ready(fake_conn)
    await upgrade(fake_conn, runtime_role=ROLE)
    sqls = _sqls(fake_conn)
    assert sum("pg_advisory_lock" in q for q in sqls) == 1
    assert sum("pg_advisory_unlock" in q for q in sqls) == 1

    broken = type(fake_conn)()
    _ready(broken)
    broken.schema_missing = True
    with pytest.raises(MigrationError):
        await upgrade(broken, runtime_role=ROLE)
    sqls = _sqls(broken)
    assert sum("pg_advisory_lock" in q for q in sqls) == 1
    assert sum("pg_advisory_unlock" in q for q in sqls) == 1


@pytest.mark.asyncio
async def test_guarded_skip_stays_pending_and_retries(tmp_catalog, fake_conn) -> None:
    """Identity 006 fails while uid exists, stays pending, and applies once it is gone."""
    _ready(fake_conn)
    (tmp_catalog / "identity" / "006_identity_drop_legacy_uid.sql").write_text("SELECT 6;")
    uid_present = {"on": True}
    fake_conn.respond("pg_attribute", lambda _s, _a: {"attnotnull": False} if uid_present["on"] else None)
    report = await upgrade(fake_conn, runtime_role=ROLE)
    assert [r.file.filename for r in report.failed] == ["006_identity_drop_legacy_uid.sql"]
    assert ("identity", "006_identity_drop_legacy_uid.sql") not in fake_conn.ledger

    uid_present["on"] = False
    report = await upgrade(fake_conn, runtime_role=ROLE)
    assert [r.file.filename for r in report.applied] == ["006_identity_drop_legacy_uid.sql"]
    assert ("identity", "006_identity_drop_legacy_uid.sql") in fake_conn.ledger


@pytest.mark.asyncio
async def test_missing_prerequisites_and_oauth2_postconditions_fail(tmp_catalog, fake_conn) -> None:
    """OAuth2 fails without base tables and without its postconditions; no rows are written."""
    _ready(fake_conn)
    (tmp_catalog / "oauth2").mkdir()
    (tmp_catalog / "oauth2" / "001_oauth2_schema.sql").write_text("SELECT 'oauth';")
    report = await upgrade(fake_conn, sets=["oauth2"], runtime_role=ROLE)
    assert len(report.failed) == 1 and "missing base table" in report.failed[0].error
    assert not fake_conn.ledger

    fake_conn.relations |= {
        f"{AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE}",
        f"{AUTH_DB_SCHEMA}.clients",
        f"{AUTH_DB_SCHEMA}.policies",
    }
    report = await upgrade(fake_conn, sets=["oauth2"], runtime_role=ROLE)
    assert len(report.failed) == 1 and "client_access" in report.failed[0].error
    assert not fake_conn.ledger


@pytest.mark.asyncio
async def test_runtime_grants_and_reconciliation(tmp_catalog, fake_conn) -> None:
    """Grants precede the upsert, applied files are reconciled without SQL, failures are reported."""
    _ready(fake_conn, "auth.user_vault_secrets")
    await upgrade(fake_conn, sets=["vault"], runtime_role=ROLE)
    assert len(fake_conn.ledger) == 2

    fake_conn.statements.clear()
    report = await upgrade(fake_conn, sets=["vault"], runtime_role=ROLE)
    sqls = _sqls(fake_conn)
    assert not report.applied and not report.access_errors
    assert any("GRANT" in q for q in sqls)
    assert not any(q.startswith("SELECT 1;") or q.startswith("SELECT 2;") for q in sqls)

    fake_conn.fail_on("GRANT USAGE ON SCHEMA", RuntimeError("denied"))
    report = await upgrade(fake_conn, sets=["vault"], runtime_role=ROLE)
    assert report.access_errors and "denied" in report.access_errors[0]

    other = type(fake_conn)()
    _ready(other, "auth.user_vault_secrets")
    other.fail_on("GRANT USAGE ON SCHEMA", RuntimeError("denied"))
    report = await upgrade(other, sets=["vault"], runtime_role=ROLE)
    assert len(report.failed) == 2
    assert not other.ledger


@pytest.mark.asyncio
async def test_upgrade_rejects_invalid_runtime_role_before_writes(tmp_catalog, fake_conn) -> None:
    """An absent role raises before the lock or any DDL."""
    fake_conn.respond("pg_roles", False)
    with pytest.raises(MigrationError):
        await upgrade(fake_conn, runtime_role=ROLE)
    assert not fake_conn.writes()
    assert not any("advisory" in q for q in _sqls(fake_conn))


from ._live import provision_base_tables, runtime_role, throwaway_database  # noqa: E402


@pytest.mark.asyncio
async def test_upgrade_twice_is_noop_live() -> None:
    """A live upgrade records every migration, then a second run is a no-op."""
    async with throwaway_database() as dsn:
        admin_conn = await asyncpg.connect(dsn)
        try:
            await provision_base_tables(admin_conn)
            async with runtime_role(admin_conn) as (role, _password):
                first = await upgrade(admin_conn, runtime_role=role)
                assert not first.failed
                assert not first.access_errors

                second = await upgrade(admin_conn, runtime_role=role)
                assert not second.applied
                assert not second.failed
                assert not second.access_errors
                statuses = await get_status(admin_conn)
                assert statuses
                assert all(status.state is MigrationState.APPLIED for status in statuses)
        finally:
            await admin_conn.close()


@pytest.mark.asyncio
async def test_runtime_access_live() -> None:
    """A runtime role receives, loses, and regains vault table and sequence access."""
    async with throwaway_database() as dsn:
        admin_conn = await asyncpg.connect(dsn)
        try:
            await provision_base_tables(admin_conn, with_oauth_base=False)
            async with runtime_role(admin_conn) as (role, password):
                first = await upgrade(admin_conn, sets=["vault"], runtime_role=role)
                assert not first.failed

                timestamps_before = {
                    row["filename"]: row["applied_at"]
                    for row in await admin_conn.fetch(
                        'SELECT filename, applied_at FROM "auth"."schema_migrations" ' "WHERE migration_set = 'vault'"
                    )
                }
                runtime_conn = await asyncpg.connect(dsn, user=role, password=password)
                try:
                    audit_id = await runtime_conn.fetchval(
                        'INSERT INTO "auth"."user_vault_audit" '
                        "(user_id, key, operation) VALUES (1, 'live-key', 'set') RETURNING id"
                    )
                    await runtime_conn.execute(
                        'UPDATE "auth"."user_vault_audit" SET key = $1 WHERE id = $2',
                        "updated-key",
                        audit_id,
                    )
                    assert (
                        await runtime_conn.fetchval('SELECT key FROM "auth"."user_vault_audit" WHERE id = $1', audit_id)
                        == "updated-key"
                    )
                finally:
                    await runtime_conn.close()

                await admin_conn.execute(f'REVOKE INSERT ON TABLE "auth"."user_vault_audit" FROM "{role}"')
                missing = await missing_runtime_access(admin_conn, "vault", role)
                assert any("lacks INSERT on auth.user_vault_audit" in item for item in missing)

                repaired = await upgrade(admin_conn, sets=["vault"], runtime_role=role)
                assert not repaired.applied
                assert not repaired.failed
                assert not repaired.access_errors
                assert not await missing_runtime_access(admin_conn, "vault", role)
                timestamps_after = {
                    row["filename"]: row["applied_at"]
                    for row in await admin_conn.fetch(
                        'SELECT filename, applied_at FROM "auth"."schema_migrations" ' "WHERE migration_set = 'vault'"
                    )
                }
                assert timestamps_after == timestamps_before

                runtime_conn = await asyncpg.connect(dsn, user=role, password=password)
                try:
                    assert await runtime_conn.fetchval(
                        'INSERT INTO "auth"."user_vault_audit" '
                        "(user_id, key, operation) VALUES (1, 'repaired-key', 'set') RETURNING id"
                    )
                finally:
                    await runtime_conn.close()
        finally:
            await admin_conn.close()


@pytest.mark.asyncio
async def test_guarded_skip_retry_live() -> None:
    """Identity 006 stays pending behind a view, then applies after the view is removed."""
    async with throwaway_database() as dsn:
        admin_conn = await asyncpg.connect(dsn)
        try:
            await provision_base_tables(admin_conn, legacy_identity=True, with_oauth_base=False)
            async with runtime_role(admin_conn) as (role, _password):
                await admin_conn.execute(
                    'CREATE VIEW "auth"."identity_uid_blocker" AS ' 'SELECT uid FROM "auth"."user_identities"'
                )
                blocked = await upgrade(admin_conn, sets=["identity"], runtime_role=role)
                assert [result.file.filename for result in blocked.failed] == ["006_identity_drop_legacy_uid.sql"]
                assert not await admin_conn.fetchval(
                    'SELECT EXISTS (SELECT 1 FROM "auth"."schema_migrations" '
                    "WHERE migration_set = 'identity' AND filename = '006_identity_drop_legacy_uid.sql')"
                )

                await admin_conn.execute('DROP VIEW "auth"."identity_uid_blocker"')
                retried = await upgrade(admin_conn, sets=["identity"], runtime_role=role)
                assert [result.file.filename for result in retried.applied] == ["006_identity_drop_legacy_uid.sql"]
                assert not retried.failed
                assert not await admin_conn.fetchval(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.columns "
                    "WHERE table_schema = 'auth' AND table_name = 'user_identities' AND column_name = 'uid')"
                )
        finally:
            await admin_conn.close()
