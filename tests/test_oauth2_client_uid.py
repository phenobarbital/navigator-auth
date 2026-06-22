"""Tests for TASK-023 — client_uid disambiguation.

Verifies that:
  - OAuthClient.client_id holds the PUBLIC opaque string uid.
  - OAuthClient.client_pk holds the optional integer surrogate PK.
  - MemoryClientStorage and RedisClientStorage key by the public uid.
  - Non-numeric client_uid no longer raises ValueError.
"""

import pytest
from navigator_auth.backends.oauth2.models import OAuthClient
from navigator_auth.backends.oauth2.client_backend import MemoryClientStorage


# ---------------------------------------------------------------------------
# Unit tests — no external dependencies
# ---------------------------------------------------------------------------

class TestClientUid:
    def test_public_id_is_string(self):
        """client_id must always be the opaque string uid."""
        c = OAuthClient(
            client_id="abc123uid",
            client_name="Test App",
            client_pk=7,
        )
        assert c.client_id == "abc123uid"
        assert c.client_pk == 7

    def test_client_pk_is_optional(self):
        """client_pk defaults to None for in-memory / Redis clients."""
        c = OAuthClient(client_id="my-opaque-uid", client_name="App")
        assert c.client_pk is None

    def test_non_numeric_uid_accepted(self):
        """client_id accepts non-numeric strings without ValueError."""
        c = OAuthClient(
            client_id="nav_test_client",
            client_name="Navigator",
        )
        assert c.client_id == "nav_test_client"

    def test_integer_passed_as_uid_becomes_string(self):
        """Passing an integer is coerced to str (backward-compat validator)."""
        c = OAuthClient(client_id=42, client_name="LegacyApp")
        assert c.client_id == "42"
        assert isinstance(c.client_id, str)

    def test_client_pk_int_mapping(self):
        """client_pk stores the integer DB primary key."""
        c = OAuthClient(client_id="uid-abc", client_name="Foo", client_pk=99)
        assert isinstance(c.client_pk, int)
        assert c.client_pk == 99

    def test_default_scopes_parsed_from_list(self):
        """default_scopes accepts a list directly."""
        c = OAuthClient(
            client_id="uid",
            client_name="A",
            default_scopes=["default", "offline_access"],
        )
        assert "offline_access" in c.default_scopes

    def test_default_scopes_parsed_from_json_string(self):
        """default_scopes parses a JSON array string."""
        c = OAuthClient(
            client_id="uid",
            client_name="A",
            default_scopes='["read", "write"]',
        )
        assert c.default_scopes == ["read", "write"]


# ---------------------------------------------------------------------------
# Integration tests — MemoryClientStorage (no Redis/DB required)
# ---------------------------------------------------------------------------

class TestMemoryClientStorageLookup:
    @pytest.fixture
    def storage(self):
        return MemoryClientStorage()

    @pytest.fixture
    def test_client(self):
        return OAuthClient(
            client_id="nav_test_client",
            client_name="Test App",
            client_type="public",
            redirect_uris=["http://localhost/callback"],
            default_scopes=["default", "offline_access"],
            allowed_grant_types=["authorization_code"],
        )

    @pytest.mark.asyncio
    async def test_save_and_get_by_uid(self, storage, test_client):
        """save then get by opaque uid must succeed."""
        await storage.save_client(test_client)
        result = await storage.get_client("nav_test_client")
        assert result is not None
        assert result.client_id == "nav_test_client"

    @pytest.mark.asyncio
    async def test_get_unknown_uid_returns_none(self, storage):
        """Unknown uid returns None (not ValueError)."""
        result = await storage.get_client("does-not-exist")
        assert result is None

    @pytest.mark.asyncio
    async def test_non_numeric_uid_no_error(self, storage, test_client):
        """Non-numeric uid must not raise ValueError."""
        await storage.save_client(test_client)
        # Should not raise regardless of whether the uid looks like an int.
        result = await storage.get_client("nav_test_client")
        assert result is not None

    @pytest.mark.asyncio
    async def test_multiple_clients_independent(self, storage):
        """Multiple clients stored under different uids are independent."""
        c1 = OAuthClient(client_id="uid_one", client_name="One")
        c2 = OAuthClient(client_id="uid_two", client_name="Two")
        await storage.save_client(c1)
        await storage.save_client(c2)

        r1 = await storage.get_client("uid_one")
        r2 = await storage.get_client("uid_two")
        assert r1.client_name == "One"
        assert r2.client_name == "Two"
