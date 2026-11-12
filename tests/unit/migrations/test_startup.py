"""Tests for read-only migration checks during application startup."""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from navigator_auth.exceptions import ConfigError
from navigator_auth.migrations import catalog
from navigator_auth.migrations.startup import tables_present, warn_pending_migrations


class ConnectionPool:
    """Pool adapter that yields one fake connection."""

    def __init__(self, connection: object) -> None:
        """Store the connection to return from ``acquire``.

        Args:
            connection: Fake connection used by the migration fixtures.
        """
        self.connection = connection

    @asynccontextmanager
    async def acquire(self):
        """Yield the configured fake connection."""
        yield self.connection


class FailingPool:
    """Pool adapter whose acquire operation raises an error."""

    def acquire(self) -> object:
        """Raise the configured connection failure."""
        raise RuntimeError("unavailable")


@pytest.mark.asyncio
async def test_warn_pending_logs_and_never_raises(caplog, fake_conn, tmp_catalog) -> None:
    """Pending, inaccessible, and fully applied migration states log safely."""
    pool = ConnectionPool(fake_conn)
    with caplog.at_level(logging.WARNING, logger="navigator.migrations"):
        await warn_pending_migrations(pool)
    warnings = [record.getMessage() for record in caplog.records if record.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "vault/001_first.sql (pending)" in warnings[0]
    assert "vault/002_second.sql (pending)" in warnings[0]
    assert "identity/001_third.sql (pending)" in warnings[0]
    assert "navauth self upgrade" in warnings[0]
    assert not fake_conn.writes()

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="navigator.migrations"):
        await warn_pending_migrations(FailingPool())
    warnings = [record.getMessage() for record in caplog.records if record.levelno == logging.WARNING]
    assert warnings == ["Could not verify database migration state (RuntimeError); run `navauth self upgrade --check`"]

    files = catalog.discover()
    fake_conn.ledger_present = True
    for file in files:
        fake_conn.ledger[(file.migration_set, file.filename)] = {
            "migration_set": file.migration_set,
            "filename": file.filename,
            "checksum": file.checksum,
            "applied_at": datetime.now(timezone.utc),
        }
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="navigator.migrations"):
        await warn_pending_migrations(pool)
    assert [record.getMessage() for record in caplog.records] == ["All database migrations are applied."]


@pytest.mark.asyncio
async def test_auth_startup_runs_no_ddl(monkeypatch) -> None:
    """Auth startup loads its keyring then uses only the migration warning check."""
    import navigator_auth.auth as auth_module

    pool = object()
    keyring = MagicMock()
    warn_pending = AsyncMock()
    monkeypatch.setattr(auth_module, "setup_vault_keyring", keyring)
    monkeypatch.setattr(auth_module, "warn_pending_migrations", warn_pending)
    stub = SimpleNamespace(
        backends={},
        _exclude_providers=[],
        logger=MagicMock(),
        register_exclusions=MagicMock(),
        _load_subnet_service_tags=AsyncMock(),
        _backend_list=("navigator_auth.backends.BasicAuth",),
    )

    await auth_module.AuthHandler.auth_startup(stub, {"authdb": pool})

    keyring.assert_called_once_with({"authdb": pool})
    warn_pending.assert_awaited_once_with(pool, stub._backend_list)
    assert not hasattr(auth_module, "setup_vault_tables")
    assert not hasattr(auth_module, "setup_identity_columns")


@pytest.mark.asyncio
async def test_passkey_startup_raises_when_tables_missing(monkeypatch) -> None:
    """Passkey startup fails clearly when its managed tables are absent."""
    import navigator_auth.backends.passkey as passkey_module

    monkeypatch.setattr(passkey_module.BasicAuth, "on_startup", AsyncMock())
    monkeypatch.setattr(passkey_module.aioredis.ConnectionPool, "from_url", MagicMock())
    monkeypatch.setitem(sys.modules, "webauthn", MagicMock())
    present = AsyncMock(return_value=False)
    monkeypatch.setattr(passkey_module, "tables_present", present)
    backend = passkey_module.PasskeyAuth(user_model=MagicMock(), identity=MagicMock())
    app = {"authdb": object()}

    with pytest.raises(ConfigError, match="navauth self upgrade"):
        await backend.on_startup(app)
    present.assert_awaited_once()

    present.reset_mock(return_value=True)
    await backend.on_startup(app)
    present.assert_awaited_once()


@pytest.mark.asyncio
async def test_tables_present(fake_conn) -> None:
    """Relation probes return false at the first missing table without DDL."""
    fake_conn.relations = {"auth.user_credentials", "auth.user_passkey_handles"}
    pool = ConnectionPool(fake_conn)

    assert await tables_present(pool, "auth.user_credentials", "auth.user_passkey_handles")
    fake_conn.relations.remove("auth.user_passkey_handles")
    assert not await tables_present(pool, "auth.user_credentials", "auth.user_passkey_handles")
    assert not fake_conn.writes()


def test_enabled_migration_sets_follow_backends_and_mfa(monkeypatch) -> None:
    """Optional sets are enabled only by a backend that uses them (or 2FA for mfa)."""
    from navigator_auth import conf
    from navigator_auth.migrations.startup import enabled_migration_sets

    monkeypatch.setattr(conf, "AUTHENTICATION_BACKENDS", ())
    monkeypatch.setattr(conf, "AUTH_BASIC_2FA_ENABLED", False)
    assert enabled_migration_sets() == ["vault", "identity"]
    assert enabled_migration_sets(("navigator_auth.backends.PasskeyAuth",)) == ["vault", "identity", "passkey"]
    assert enabled_migration_sets(("navigator_auth.backends.oauth2.Oauth2Provider",)) == [
        "vault",
        "identity",
        "oauth2",
    ]

    class PasskeyAuth:
        __module__ = "navigator_auth.backends.passkey"

    assert "passkey" in enabled_migration_sets((PasskeyAuth,))

    monkeypatch.setattr(conf, "AUTH_BASIC_2FA_ENABLED", True)
    assert enabled_migration_sets() == ["vault", "identity", "mfa"]


@pytest.mark.asyncio
async def test_warn_pending_ignores_disabled_sets(caplog, fake_conn, tmp_catalog) -> None:
    """Pending files of a set no backend uses are not named in the startup warning."""
    (tmp_catalog / "passkey").mkdir(exist_ok=True)
    (tmp_catalog / "passkey" / "001_pk.sql").write_text("SELECT 3;")
    pool = ConnectionPool(fake_conn)
    with caplog.at_level(logging.WARNING, logger="navigator.migrations"):
        await warn_pending_migrations(pool, ("navigator_auth.backends.BasicAuth",))
    assert "passkey/" not in caplog.text and "vault/001_first.sql" in caplog.text
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="navigator.migrations"):
        await warn_pending_migrations(pool, ("navigator_auth.backends.PasskeyAuth",))
    assert "passkey/001_pk.sql (pending)" in caplog.text
