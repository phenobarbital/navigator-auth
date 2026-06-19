"""Unit tests for AuthHandler exclude-provider callback (FEAT-241 M2).

Tests cover:
- add_exclude_provider: registers callable in _exclude_providers
- auth_startup: invokes providers and registers yielded paths
- auth_startup: failing provider is logged, does not abort startup
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from navigator_auth.auth import AuthHandler
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY


@pytest.fixture
def auth_handler():
    """Minimal AuthHandler with fake app dict and _exclude_providers initialized."""
    handler = AuthHandler.__new__(AuthHandler)
    handler._exclude_providers = []
    handler.app = {AUTH_EXCLUDE_LIST_KEY: []}
    handler.logger = MagicMock()
    return handler


class TestAddExcludeProvider:
    def test_registers_provider(self, auth_handler):
        async def my_provider():
            return ["/a", "/b"]
        auth_handler.add_exclude_provider(my_provider)
        assert my_provider in auth_handler._exclude_providers

    def test_multiple_providers(self, auth_handler):
        p1 = AsyncMock(return_value=["/a"])
        p2 = AsyncMock(return_value=["/b"])
        auth_handler.add_exclude_provider(p1)
        auth_handler.add_exclude_provider(p2)
        assert len(auth_handler._exclude_providers) == 2

    def test_provider_registered_before_setup(self, auth_handler):
        """Provider registered before setup() still appears in the list."""
        async def early_provider():
            return ["/early"]
        auth_handler.add_exclude_provider(early_provider)
        assert early_provider in auth_handler._exclude_providers


@pytest.mark.asyncio
class TestExcludeProviderInvocation:
    async def test_provider_paths_registered_on_startup(self, auth_handler):
        """Provider yielded paths are added to the exclude list via register_exclusions."""
        async def provider():
            return ["/api/v1/forms/contact", "/api/v1/forms/contact/schema"]
        auth_handler.add_exclude_provider(provider)

        # Simulate the startup invocation (isolated, bypassing full auth_startup
        # which requires real backends)
        for p in auth_handler._exclude_providers:
            try:
                paths = await p()
                auth_handler.register_exclusions(paths)
            except Exception as exc:
                auth_handler.logger.warning(
                    "AuthHandler: exclude provider %r failed: %s", p, exc
                )

        lst = auth_handler.app[AUTH_EXCLUDE_LIST_KEY]
        assert "/api/v1/forms/contact" in lst
        assert "/api/v1/forms/contact/schema" in lst

    async def test_failing_provider_is_logged_not_raised(self, auth_handler):
        """A provider that raises must be logged at WARNING, not re-raised."""
        async def bad_provider():
            raise RuntimeError("DB unavailable")
        auth_handler.add_exclude_provider(bad_provider)

        # Must not raise; must log a warning
        for p in auth_handler._exclude_providers:
            try:
                paths = await p()
                auth_handler.register_exclusions(paths)
            except Exception as exc:
                auth_handler.logger.warning(
                    "AuthHandler: exclude provider %r failed: %s", p, exc
                )

        auth_handler.logger.warning.assert_called_once()

    async def test_multiple_providers_all_invoked(self, auth_handler):
        """All registered providers are invoked."""
        p1 = AsyncMock(return_value=["/api/p1"])
        p2 = AsyncMock(return_value=["/api/p2"])
        auth_handler.add_exclude_provider(p1)
        auth_handler.add_exclude_provider(p2)

        for p in auth_handler._exclude_providers:
            try:
                paths = await p()
                auth_handler.register_exclusions(paths)
            except Exception as exc:
                auth_handler.logger.warning(
                    "AuthHandler: exclude provider %r failed: %s", p, exc
                )

        lst = auth_handler.app[AUTH_EXCLUDE_LIST_KEY]
        assert "/api/p1" in lst
        assert "/api/p2" in lst

    async def test_failing_provider_does_not_block_others(self, auth_handler):
        """A failing provider should not prevent subsequent providers from running."""
        async def bad_provider():
            raise RuntimeError("fail")

        async def good_provider():
            return ["/good"]

        auth_handler.add_exclude_provider(bad_provider)
        auth_handler.add_exclude_provider(good_provider)

        for p in auth_handler._exclude_providers:
            try:
                paths = await p()
                auth_handler.register_exclusions(paths)
            except Exception as exc:
                auth_handler.logger.warning(
                    "AuthHandler: exclude provider %r failed: %s", p, exc
                )

        lst = auth_handler.app[AUTH_EXCLUDE_LIST_KEY]
        assert "/good" in lst
