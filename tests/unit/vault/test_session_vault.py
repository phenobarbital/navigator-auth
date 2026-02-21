"""Unit tests for navigator_session.vault.session_vault module."""
import os
import base64
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from navigator_session.vault.session_vault import SessionVault
from navigator_session.vault.crypto import (
    encrypt_for_session,
    decrypt_for_session,
    serialize_value,
    deserialize_value,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def master_key_v1() -> bytes:
    return b"\x00" * 32


@pytest.fixture
def master_key_v2() -> bytes:
    return b"\x01" * 32


@pytest.fixture(autouse=True)
def vault_env(master_key_v1, master_key_v2):
    """Set up vault environment variables for tests."""
    os.environ["VAULT_MASTER_KEY_v1"] = base64.b64encode(master_key_v1).decode()
    os.environ["VAULT_MASTER_KEY_v2"] = base64.b64encode(master_key_v2).decode()
    os.environ["VAULT_ACTIVE_KEY_ID"] = "2"
    yield
    for key in ["VAULT_MASTER_KEY_v1", "VAULT_MASTER_KEY_v2", "VAULT_ACTIVE_KEY_ID"]:
        os.environ.pop(key, None)


@pytest.fixture
def session_uuid() -> str:
    return "550e8400-e29b-41d4-a716-446655440000"


def _make_mock_conn():
    """Create a mock asyncpg connection."""
    conn = AsyncMock()
    conn.execute = AsyncMock()
    conn.fetch = AsyncMock(return_value=[])
    conn.fetchrow = AsyncMock(return_value=None)
    conn.fetchval = AsyncMock(return_value=0)
    return conn


def _make_mock_pool(conn=None):
    """Create a mock pool that yields a connection via acquire()."""
    if conn is None:
        conn = _make_mock_conn()
    pool = MagicMock()
    pool_ctx = AsyncMock()
    pool_ctx.__aenter__ = AsyncMock(return_value=conn)
    pool_ctx.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=pool_ctx)
    return pool, conn


def _make_mock_redis():
    """Create a mock Redis client."""
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.setex = AsyncMock()
    redis.delete = AsyncMock()
    return redis


def _make_vault(session_uuid, pool=None, redis=None):
    """Create a SessionVault with mocked dependencies."""
    if pool is None:
        pool, _ = _make_mock_pool()
    return SessionVault(
        session_uuid=session_uuid,
        user_id=42,
        db_pool=pool,
        redis=redis,
        session_ttl=3600,
    )


# ---------------------------------------------------------------------------
# Key validation
# ---------------------------------------------------------------------------

class TestKeyValidation:
    def test_rejects_empty_key(self, session_uuid):
        """Empty key name is rejected."""
        vault = _make_vault(session_uuid)
        with pytest.raises(ValueError, match="empty"):
            vault._validate_key("")

    def test_rejects_colon(self, session_uuid):
        """Key containing ':' is rejected."""
        vault = _make_vault(session_uuid)
        with pytest.raises(ValueError, match=":"):
            vault._validate_key("bad:key")

    def test_rejects_long_key(self, session_uuid):
        """Key exceeding 255 chars is rejected."""
        vault = _make_vault(session_uuid)
        with pytest.raises(ValueError, match="255"):
            vault._validate_key("x" * 256)

    def test_accepts_valid_key(self, session_uuid):
        """Valid key name passes validation."""
        vault = _make_vault(session_uuid)
        vault._validate_key("my_api_key")  # should not raise

    def test_accepts_max_length_key(self, session_uuid):
        """Key of exactly 255 chars passes."""
        vault = _make_vault(session_uuid)
        vault._validate_key("a" * 255)  # should not raise


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestInitialization:
    def test_creates_with_valid_params(self, session_uuid):
        """SessionVault initializes with valid parameters."""
        vault = _make_vault(session_uuid)
        assert vault is not None
        assert vault._session_uuid == session_uuid
        assert vault._user_id == 42

    def test_cache_starts_empty(self, session_uuid):
        """Internal cache is empty on initialization."""
        vault = _make_vault(session_uuid)
        assert vault._cache == {}

    def test_loads_master_keys_from_env(self, session_uuid):
        """Master keys are loaded from environment on init."""
        vault = _make_vault(session_uuid)
        assert 1 in vault._master_keys
        assert 2 in vault._master_keys

    def test_active_key_id_from_env(self, session_uuid):
        """Active key ID read from environment."""
        vault = _make_vault(session_uuid)
        assert vault._active_key_id == 2


# ---------------------------------------------------------------------------
# set() + get() round-trip
# ---------------------------------------------------------------------------

class TestSetGet:
    @pytest.mark.asyncio
    async def test_roundtrip_string(self, session_uuid):
        """set() then get() returns original string value."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        await vault.set("api_key", "sk-secret-123")
        result = await vault.get("api_key")
        assert result == "sk-secret-123"

    @pytest.mark.asyncio
    async def test_roundtrip_int(self, session_uuid):
        """Round-trip works for int."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        await vault.set("count", 42)
        assert await vault.get("count") == 42

    @pytest.mark.asyncio
    async def test_roundtrip_float(self, session_uuid):
        """Round-trip works for float."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        await vault.set("rate", 3.14)
        result = await vault.get("rate")
        assert abs(result - 3.14) < 1e-10

    @pytest.mark.asyncio
    async def test_roundtrip_dict(self, session_uuid):
        """Round-trip works for dict."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        data = {"token": "abc", "nested": {"x": 1}}
        await vault.set("config", data)
        assert await vault.get("config") == data

    @pytest.mark.asyncio
    async def test_roundtrip_list(self, session_uuid):
        """Round-trip works for list."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        await vault.set("items", [1, 2, 3])
        assert await vault.get("items") == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_roundtrip_bytes(self, session_uuid):
        """Round-trip works for bytes."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        await vault.set("binary", b"\x00\x01\xff")
        assert await vault.get("binary") == b"\x00\x01\xff"

    @pytest.mark.asyncio
    async def test_roundtrip_bool(self, session_uuid):
        """Round-trip works for bool."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        await vault.set("flag", True)
        assert await vault.get("flag") is True

    @pytest.mark.asyncio
    async def test_roundtrip_none(self, session_uuid):
        """Round-trip works for None."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        await vault.set("empty", None)
        assert await vault.get("empty") is None

    @pytest.mark.asyncio
    async def test_set_validates_key(self, session_uuid):
        """set() validates key before proceeding."""
        vault = _make_vault(session_uuid)
        with pytest.raises(ValueError, match="empty"):
            await vault.set("", "value")

    @pytest.mark.asyncio
    async def test_set_overwrites_existing(self, session_uuid):
        """set() overwrites existing value for same key."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        await vault.set("key", "old")
        await vault.set("key", "new")
        assert await vault.get("key") == "new"


# ---------------------------------------------------------------------------
# get() behavior
# ---------------------------------------------------------------------------

class TestGet:
    @pytest.mark.asyncio
    async def test_returns_default_on_miss(self, session_uuid):
        """get() returns default when key not found."""
        vault = _make_vault(session_uuid)
        assert await vault.get("missing") is None
        assert await vault.get("missing", "fallback") == "fallback"

    @pytest.mark.asyncio
    async def test_reads_from_cache_first(self, session_uuid):
        """get() reads from in-memory cache, not Redis/DB."""
        pool, conn = _make_mock_pool()
        redis = _make_mock_redis()
        vault = _make_vault(session_uuid, pool=pool, redis=redis)
        await vault.set("key", "cached-value")

        # Reset redis.get to ensure it's not called for cache hit
        redis.get.reset_mock()
        result = await vault.get("key")
        assert result == "cached-value"

    @pytest.mark.asyncio
    async def test_falls_back_to_redis(self, session_uuid):
        """get() falls back to Redis when key not in memory cache."""
        pool, conn = _make_mock_pool()
        redis = _make_mock_redis()
        vault = _make_vault(session_uuid, pool=pool, redis=redis)

        # Manually encrypt a value and put it in Redis mock
        plaintext_bytes = serialize_value("redis-value")
        ct_mem = encrypt_for_session(plaintext_bytes, session_uuid)
        redis.get = AsyncMock(return_value=ct_mem)

        result = await vault.get("from_redis")
        assert result == "redis-value"
        redis.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_validates_key(self, session_uuid):
        """get() validates key."""
        vault = _make_vault(session_uuid)
        with pytest.raises(ValueError, match="empty"):
            await vault.get("")


# ---------------------------------------------------------------------------
# delete()
# ---------------------------------------------------------------------------

class TestDelete:
    @pytest.mark.asyncio
    async def test_removes_from_cache(self, session_uuid):
        """delete() removes key from in-memory cache."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        await vault.set("to_delete", "value")
        assert await vault.exists("to_delete")

        await vault.delete("to_delete")
        assert not await vault.exists("to_delete")

    @pytest.mark.asyncio
    async def test_executes_soft_delete_sql(self, session_uuid):
        """delete() executes UPDATE SET deleted_at on DB."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        vault._cache["mykey"] = b"dummy"

        await vault.delete("mykey")

        # Verify UPDATE with deleted_at was called
        update_calls = [
            c for c in conn.execute.call_args_list
            if c.args and "deleted_at" in str(c.args[0]).lower()
        ]
        assert len(update_calls) >= 1

    @pytest.mark.asyncio
    async def test_removes_from_redis(self, session_uuid):
        """delete() removes key from Redis cache."""
        pool, conn = _make_mock_pool()
        redis = _make_mock_redis()
        vault = _make_vault(session_uuid, pool=pool, redis=redis)
        vault._cache["mykey"] = b"dummy"

        await vault.delete("mykey")
        redis.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_audit_log_on_delete(self, session_uuid):
        """delete() creates audit log entry."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        vault._cache["mykey"] = b"dummy"

        await vault.delete("mykey")

        audit_calls = [
            c for c in conn.execute.call_args_list
            if c.args and "vault_audit" in str(c.args[0]).lower()
        ]
        assert len(audit_calls) >= 1
        assert any(a == "delete" for c in audit_calls for a in c.args)

    @pytest.mark.asyncio
    async def test_validates_key(self, session_uuid):
        """delete() validates key."""
        vault = _make_vault(session_uuid)
        with pytest.raises(ValueError, match=":"):
            await vault.delete("bad:key")


# ---------------------------------------------------------------------------
# keys() and exists()
# ---------------------------------------------------------------------------

class TestKeysAndExists:
    @pytest.mark.asyncio
    async def test_keys_returns_cached_keys(self, session_uuid):
        """keys() returns names of all cached keys."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        await vault.set("a", 1)
        await vault.set("b", 2)
        result = await vault.keys()
        assert sorted(result) == ["a", "b"]

    @pytest.mark.asyncio
    async def test_keys_empty_vault(self, session_uuid):
        """keys() returns empty list for empty vault."""
        vault = _make_vault(session_uuid)
        assert await vault.keys() == []

    @pytest.mark.asyncio
    async def test_exists_true(self, session_uuid):
        """exists() returns True for cached key."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        await vault.set("present", "value")
        assert await vault.exists("present") is True

    @pytest.mark.asyncio
    async def test_exists_false(self, session_uuid):
        """exists() returns False for missing key."""
        vault = _make_vault(session_uuid)
        assert await vault.exists("missing") is False

    @pytest.mark.asyncio
    async def test_keys_excludes_deleted(self, session_uuid):
        """keys() does not include deleted keys."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        await vault.set("keep", "a")
        await vault.set("remove", "b")
        await vault.delete("remove")
        result = await vault.keys()
        assert result == ["keep"]


# ---------------------------------------------------------------------------
# max_keys_per_user enforcement
# ---------------------------------------------------------------------------

class TestMaxKeysLimit:
    @pytest.mark.asyncio
    async def test_enforces_max_keys(self, session_uuid):
        """set() raises when max_keys_per_user limit is reached."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        vault._max_keys_per_user = 3  # lower limit for testing

        await vault.set("k1", "v1")
        await vault.set("k2", "v2")
        await vault.set("k3", "v3")

        with pytest.raises(ValueError, match="[Mm]ax"):
            await vault.set("k4", "v4")

    @pytest.mark.asyncio
    async def test_overwrite_does_not_count(self, session_uuid):
        """Overwriting an existing key does not count toward limit."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        vault._max_keys_per_user = 2

        await vault.set("k1", "v1")
        await vault.set("k2", "v2")
        await vault.set("k1", "v1-updated")  # overwrite, should not raise


# ---------------------------------------------------------------------------
# DB persistence
# ---------------------------------------------------------------------------

class TestDbPersistence:
    @pytest.mark.asyncio
    async def test_set_executes_upsert(self, session_uuid):
        """set() executes DB upsert."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        await vault.set("secret", "value")

        # Should have executed an INSERT/upsert
        upsert_calls = [
            c for c in conn.execute.call_args_list
            if c.args and "user_vault_secrets" in str(c.args[0]).lower()
        ]
        assert len(upsert_calls) >= 1

    @pytest.mark.asyncio
    async def test_set_creates_audit_entry(self, session_uuid):
        """set() creates audit log with operation='set'."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool)
        await vault.set("key", "value")

        audit_calls = [
            c for c in conn.execute.call_args_list
            if c.args and "vault_audit" in str(c.args[0]).lower()
        ]
        assert len(audit_calls) >= 1
        assert any(a == "set" for c in audit_calls for a in c.args)


# ---------------------------------------------------------------------------
# Redis integration
# ---------------------------------------------------------------------------

class TestRedisIntegration:
    @pytest.mark.asyncio
    async def test_set_populates_redis(self, session_uuid):
        """set() writes ciphertext_mem to Redis with TTL."""
        pool, conn = _make_mock_pool()
        redis = _make_mock_redis()
        vault = _make_vault(session_uuid, pool=pool, redis=redis)
        await vault.set("key", "value")

        redis.setex.assert_called_once()
        call_args = redis.setex.call_args
        redis_key = call_args.args[0] if call_args.args else call_args[0][0]
        assert f"vault:{session_uuid}:key" == redis_key

    @pytest.mark.asyncio
    async def test_set_redis_ttl(self, session_uuid):
        """Redis cache uses session_ttl for TTL."""
        pool, conn = _make_mock_pool()
        redis = _make_mock_redis()
        vault = _make_vault(session_uuid, pool=pool, redis=redis)
        await vault.set("key", "value")

        call_args = redis.setex.call_args
        ttl = call_args.args[1] if call_args.args else call_args[0][1]
        assert ttl == 3600

    @pytest.mark.asyncio
    async def test_delete_removes_from_redis(self, session_uuid):
        """delete() removes Redis cache entry."""
        pool, conn = _make_mock_pool()
        redis = _make_mock_redis()
        vault = _make_vault(session_uuid, pool=pool, redis=redis)
        vault._cache["key"] = b"dummy"

        await vault.delete("key")
        redis.delete.assert_called_once()


# ---------------------------------------------------------------------------
# Works without Redis
# ---------------------------------------------------------------------------

class TestWithoutRedis:
    @pytest.mark.asyncio
    async def test_set_get_without_redis(self, session_uuid):
        """set()/get() works when redis=None."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool, redis=None)
        await vault.set("key", "value")
        assert await vault.get("key") == "value"

    @pytest.mark.asyncio
    async def test_delete_without_redis(self, session_uuid):
        """delete() works when redis=None."""
        pool, conn = _make_mock_pool()
        vault = _make_vault(session_uuid, pool=pool, redis=None)
        await vault.set("key", "value")
        await vault.delete("key")  # should not raise
        assert not await vault.exists("key")

    @pytest.mark.asyncio
    async def test_get_no_redis_fallback_returns_default(self, session_uuid):
        """Without Redis, cache miss returns default."""
        vault = _make_vault(session_uuid, redis=None)
        assert await vault.get("missing", "fallback") == "fallback"


# ---------------------------------------------------------------------------
# load_for_session() factory
# ---------------------------------------------------------------------------

class TestLoadForSession:
    @pytest.mark.asyncio
    async def test_returns_session_vault(self, session_uuid, master_key_v2):
        """load_for_session returns a SessionVault instance."""
        from navigator_session.vault.crypto import encrypt_for_db, serialize_value

        plaintext = serialize_value("loaded-secret")
        ct_db = encrypt_for_db(plaintext, key_id=2, master_key=master_key_v2)

        row = MagicMock()
        row.__getitem__ = lambda self, k: {
            "key": "my_secret",
            "ciphertext_db": ct_db,
            "key_version": 2,
        }[k]

        conn = _make_mock_conn()
        conn.fetch = AsyncMock(return_value=[row])
        pool, _ = _make_mock_pool(conn)

        vault = await SessionVault.load_for_session(
            session_uuid=session_uuid,
            user_id=42,
            db_pool=pool,
        )
        assert isinstance(vault, SessionVault)

    @pytest.mark.asyncio
    async def test_loads_secrets_into_cache(self, session_uuid, master_key_v2):
        """load_for_session populates cache with re-encrypted secrets."""
        from navigator_session.vault.crypto import encrypt_for_db, serialize_value

        plaintext = serialize_value("loaded-value")
        ct_db = encrypt_for_db(plaintext, key_id=2, master_key=master_key_v2)

        row = MagicMock()
        row.__getitem__ = lambda self, k: {
            "key": "secret_key",
            "ciphertext_db": ct_db,
            "key_version": 2,
        }[k]

        conn = _make_mock_conn()
        conn.fetch = AsyncMock(return_value=[row])
        pool, _ = _make_mock_pool(conn)

        vault = await SessionVault.load_for_session(
            session_uuid=session_uuid,
            user_id=42,
            db_pool=pool,
        )
        assert "secret_key" in vault._cache
        result = await vault.get("secret_key")
        assert result == "loaded-value"

    @pytest.mark.asyncio
    async def test_populates_redis_on_load(self, session_uuid, master_key_v2):
        """load_for_session writes re-encrypted secrets to Redis."""
        from navigator_session.vault.crypto import encrypt_for_db, serialize_value

        plaintext = serialize_value("redis-loaded")
        ct_db = encrypt_for_db(plaintext, key_id=2, master_key=master_key_v2)

        row = MagicMock()
        row.__getitem__ = lambda self, k: {
            "key": "redis_key",
            "ciphertext_db": ct_db,
            "key_version": 2,
        }[k]

        conn = _make_mock_conn()
        conn.fetch = AsyncMock(return_value=[row])
        pool, _ = _make_mock_pool(conn)
        redis = _make_mock_redis()

        vault = await SessionVault.load_for_session(
            session_uuid=session_uuid,
            user_id=42,
            db_pool=pool,
            redis=redis,
        )
        redis.setex.assert_called_once()

    @pytest.mark.asyncio
    async def test_empty_db_returns_empty_vault(self, session_uuid):
        """load_for_session with no DB rows returns vault with empty cache."""
        conn = _make_mock_conn()
        conn.fetch = AsyncMock(return_value=[])
        pool, _ = _make_mock_pool(conn)

        vault = await SessionVault.load_for_session(
            session_uuid=session_uuid,
            user_id=42,
            db_pool=pool,
        )
        assert vault._cache == {}
        assert await vault.keys() == []
