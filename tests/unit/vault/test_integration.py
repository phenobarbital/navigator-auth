"""Unit tests for navigator_auth.vault.integration module."""
import warnings
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Suppress pre-existing Pydantic deprecation from oauth2/models.py
warnings.filterwarnings("ignore", message=".*extra keyword arguments on.*Field.*")

from navigator_auth.vault.integration import (
    load_vault_for_session,
    setup_vault_tables,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_session():
    """Mock session with session_id."""
    session = MagicMock()
    session.session_id = "550e8400-e29b-41d4-a716-446655440000"
    return session


@pytest.fixture
def mock_pool():
    """Mock asyncpg pool."""
    conn = AsyncMock()
    pool_ctx = AsyncMock()
    pool_ctx.__aenter__ = AsyncMock(return_value=conn)
    pool_ctx.__aexit__ = AsyncMock(return_value=False)
    pool = MagicMock()
    pool.acquire = MagicMock(return_value=pool_ctx)
    return pool


@pytest.fixture
def mock_redis():
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.setex = AsyncMock()
    redis.delete = AsyncMock()
    return redis


# ---------------------------------------------------------------------------
# load_vault_for_session
# ---------------------------------------------------------------------------

class TestLoadVaultForSession:
    @pytest.mark.asyncio
    async def test_returns_vault_on_success(self, mock_session, mock_pool):
        """Returns a SessionVault instance on successful load."""
        with patch("navigator_auth.vault.integration.SessionVault") as MockVault:
            mock_vault_instance = MagicMock()
            MockVault.load_for_session = AsyncMock(return_value=mock_vault_instance)
            vault = await load_vault_for_session(
                mock_session, user_id=1, db_pool=mock_pool
            )
            assert vault is mock_vault_instance

    @pytest.mark.asyncio
    async def test_calls_load_for_session_with_correct_params(
        self, mock_session, mock_pool, mock_redis
    ):
        """Passes correct parameters to SessionVault.load_for_session."""
        with patch("navigator_auth.vault.integration.SessionVault") as MockVault:
            MockVault.load_for_session = AsyncMock(return_value=MagicMock())
            await load_vault_for_session(
                mock_session, user_id=42, db_pool=mock_pool,
                redis=mock_redis, session_ttl=7200,
            )
            MockVault.load_for_session.assert_called_once_with(
                session_uuid="550e8400-e29b-41d4-a716-446655440000",
                user_id=42,
                db_pool=mock_pool,
                redis=mock_redis,
                session_ttl=7200,
            )

    @pytest.mark.asyncio
    async def test_returns_none_on_failure(self, mock_session, mock_pool):
        """Returns None when vault loading fails (non-blocking)."""
        with patch("navigator_auth.vault.integration.SessionVault") as MockVault:
            MockVault.load_for_session = AsyncMock(
                side_effect=RuntimeError("DB down")
            )
            vault = await load_vault_for_session(
                mock_session, user_id=1, db_pool=mock_pool
            )
            assert vault is None

    @pytest.mark.asyncio
    async def test_returns_none_on_config_error(self, mock_session, mock_pool):
        """Returns None when vault config is missing (e.g. no env vars)."""
        with patch("navigator_auth.vault.integration.SessionVault") as MockVault:
            MockVault.load_for_session = AsyncMock(
                side_effect=RuntimeError("No vault master keys found")
            )
            vault = await load_vault_for_session(
                mock_session, user_id=1, db_pool=mock_pool
            )
            assert vault is None

    @pytest.mark.asyncio
    async def test_logs_error_on_failure(self, mock_session, mock_pool):
        """Logs error when vault loading fails."""
        with patch("navigator_auth.vault.integration.SessionVault") as MockVault:
            MockVault.load_for_session = AsyncMock(
                side_effect=RuntimeError("DB down")
            )
            with patch("navigator_auth.vault.integration.logger") as mock_logger:
                await load_vault_for_session(
                    mock_session, user_id=1, db_pool=mock_pool
                )
                mock_logger.error.assert_called_once()
                assert "Failed to load vault" in mock_logger.error.call_args[0][0]

    @pytest.mark.asyncio
    async def test_logs_success(self, mock_session, mock_pool):
        """Logs info on successful vault load."""
        with patch("navigator_auth.vault.integration.SessionVault") as MockVault:
            MockVault.load_for_session = AsyncMock(return_value=MagicMock())
            with patch("navigator_auth.vault.integration.logger") as mock_logger:
                await load_vault_for_session(
                    mock_session, user_id=1, db_pool=mock_pool
                )
                mock_logger.info.assert_called_once()
                assert "Vault loaded" in mock_logger.info.call_args[0][0]

    @pytest.mark.asyncio
    async def test_works_without_redis(self, mock_session, mock_pool):
        """Works when redis=None (default)."""
        with patch("navigator_auth.vault.integration.SessionVault") as MockVault:
            MockVault.load_for_session = AsyncMock(return_value=MagicMock())
            vault = await load_vault_for_session(
                mock_session, user_id=1, db_pool=mock_pool
            )
            assert vault is not None
            # redis should have been passed as None
            call_kwargs = MockVault.load_for_session.call_args.kwargs
            assert call_kwargs.get("redis") is None

    @pytest.mark.asyncio
    async def test_is_async_function(self):
        """load_vault_for_session is an async function."""
        import asyncio
        assert asyncio.iscoroutinefunction(load_vault_for_session)


# ---------------------------------------------------------------------------
# setup_vault_tables
# ---------------------------------------------------------------------------

class TestSetupVaultTables:
    @pytest.mark.asyncio
    async def test_calls_ensure_vault_tables(self, mock_pool):
        """setup_vault_tables delegates to ensure_vault_tables."""
        with patch(
            "navigator_auth.vault.integration.ensure_vault_tables"
        ) as mock_ensure:
            mock_ensure.return_value = None
            # Make it a coroutine
            mock_ensure.side_effect = None
            mock_ensure.__wrapped__ = None
            # Use AsyncMock
            with patch(
                "navigator_auth.vault.integration.ensure_vault_tables",
                new_callable=AsyncMock,
            ) as mock_ensure_async:
                await setup_vault_tables(mock_pool)
                mock_ensure_async.assert_called_once_with(mock_pool)

    @pytest.mark.asyncio
    async def test_non_blocking_on_failure(self, mock_pool):
        """setup_vault_tables does not raise on failure."""
        with patch(
            "navigator_auth.vault.integration.ensure_vault_tables",
            new_callable=AsyncMock,
            side_effect=Exception("DB unavailable"),
        ):
            with patch("navigator_auth.vault.integration.logger") as mock_logger:
                await setup_vault_tables(mock_pool)
                mock_logger.error.assert_called_once()
                assert "Failed to create vault tables" in mock_logger.error.call_args[0][0]

    @pytest.mark.asyncio
    async def test_is_async_function(self):
        """setup_vault_tables is an async function."""
        import asyncio
        assert asyncio.iscoroutinefunction(setup_vault_tables)


# ---------------------------------------------------------------------------
# Decorator extension: _attach_vault_to_request
# ---------------------------------------------------------------------------

class TestAttachVaultToRequest:
    def test_attaches_vault_from_session(self):
        """Vault from session is attached to request."""
        from navigator_auth.vault.integration import _attach_vault_to_request

        mock_vault = MagicMock()
        session = MagicMock()
        session.get = MagicMock(return_value=mock_vault)
        request = MagicMock(spec=[])  # no pre-existing attributes

        _attach_vault_to_request(request, session)
        assert request.vault is mock_vault

    def test_no_vault_in_session(self):
        """When no vault in session, request.vault is not set."""
        from navigator_auth.vault.integration import _attach_vault_to_request

        session = MagicMock()
        session.get = MagicMock(return_value=None)
        request = MagicMock(spec=[])

        _attach_vault_to_request(request, session)
        assert not hasattr(request, "vault")

    def test_does_not_raise_on_error(self):
        """Gracefully handles errors during vault attachment."""
        from navigator_auth.vault.integration import _attach_vault_to_request

        session = MagicMock()
        session.get = MagicMock(side_effect=Exception("broken"))
        request = MagicMock(spec=[])

        _attach_vault_to_request(request, session)  # should not raise
        assert not hasattr(request, "vault")


# ---------------------------------------------------------------------------
# user_session decorator vault wiring
# ---------------------------------------------------------------------------

class TestUserSessionVaultWiring:
    """Verify that @user_session calls _attach_vault_to_request."""

    @pytest.mark.asyncio
    async def test_user_session_calls_attach_vault(self):
        """@user_session decorator attaches vault to request."""
        from navigator_auth.decorators import user_session

        mock_vault = MagicMock()
        mock_session = MagicMock()
        mock_session.decode = MagicMock(return_value=MagicMock())
        mock_session.get = MagicMock(return_value=mock_vault)

        request = MagicMock()
        request.method = "GET"

        with patch(
            "navigator_auth.decorators.get_session",
            new_callable=AsyncMock,
            return_value=mock_session,
        ):
            with patch(
                "navigator_auth.decorators._attach_vault_to_request"
            ) as mock_attach:

                @user_session()
                async def handler(request, session=None, user=None):
                    return "ok"

                await handler(request)
                mock_attach.assert_called_once_with(request, mock_session)

    @pytest.mark.asyncio
    async def test_user_session_backward_compatible(self):
        """@user_session still passes session and user kwargs."""
        from navigator_auth.decorators import user_session

        mock_user = MagicMock()
        mock_session = MagicMock()
        mock_session.decode = MagicMock(return_value=mock_user)

        request = MagicMock()
        request.method = "GET"

        received = {}

        with patch(
            "navigator_auth.decorators.get_session",
            new_callable=AsyncMock,
            return_value=mock_session,
        ):
            with patch(
                "navigator_auth.decorators._attach_vault_to_request"
            ):

                @user_session()
                async def handler(request, session=None, user=None):
                    received["session"] = session
                    received["user"] = user
                    return "ok"

                await handler(request)
                assert received["session"] is mock_session
                assert received["user"] is mock_user
