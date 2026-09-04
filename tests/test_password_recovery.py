from types import SimpleNamespace

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from navigator_auth.conf import REDIS_AUTH_URL
from navigator_auth.handlers.users.passwd import set_basic_password
from navigator_auth.handlers.recovery.policy import PasswordPolicy
from navigator_auth.handlers.recovery.store import (
    RecoveryTokenStore,
    RECOVERY_KEY_PREFIX,
    CONFIRM_KEY_PREFIX,
    _hash_token,
)
from navigator_auth.handlers.recovery.limiter import RateLimiter
from navigator_auth.libs.json import json_encoder, json_decoder
from navigator_auth.models import User

TEST_SECRET = b"test-secret-key"


class TestRecoveryConfig:
    def test_defaults(self):
        from navigator_auth import conf
        assert conf.AUTH_RECOVERY_TTL == 3600
        assert conf.AUTH_RECOVERY_CONFIRM_TTL == 900
        assert conf.AUTH_RECOVERY_RATE_EMAIL == "3/hour"
        assert conf.AUTH_RECOVERY_RATE_IP == "10/hour"
        assert conf.AUTH_RECOVERY_PWD_MIN_LENGTH == 8

    def test_secret_falls_back_to_secret_key(self):
        from navigator_auth import conf
        assert conf.AUTH_RECOVERY_SECRET
        assert isinstance(conf.AUTH_RECOVERY_SECRET, bytes)


class TestUserPasswordWidth:
    def test_user_password_column_fits_hash(self):
        """A real PBKDF2 hash (77 chars) must fit the declared max."""
        h = set_basic_password("correct horse battery staple")
        assert len(h) == 77
        col = User.get_columns()["password"]
        assert col.metadata.get("max", 0) >= len(h)

    def test_hash_roundtrips_through_model(self):
        h = set_basic_password("correct horse battery staple")
        u = User(user_id=1, username="t", password=h)
        assert u.password == h
        assert u.is_valid()


class TestPasswordPolicy:
    def test_policy_accepts_valid(self):
        assert PasswordPolicy().validate("abc12345") == []

    def test_policy_min_length(self):
        v = PasswordPolicy().validate("abc1234")      # 7 chars
        assert [x.rule for x in v] == ["min_length"]

    def test_policy_requires_letter_and_digit(self):
        assert "needs_letter" in [x.rule for x in PasswordPolicy().validate("12345678")]
        assert "needs_digit" in [x.rule for x in PasswordPolicy().validate("abcdefgh")]

    def test_policy_returns_all_violations(self):
        rules = {x.rule for x in PasswordPolicy().validate("abc")}
        assert rules == {"min_length", "needs_digit"}

    def test_policy_rejects_current_password(self):
        h = set_basic_password("abc12345")
        v = PasswordPolicy().validate("abc12345", current_hash=h)
        assert [x.rule for x in v] == ["same_as_current"]

    def test_policy_no_current_hash_is_fine(self):
        assert PasswordPolicy().validate("abc12345", current_hash=None) == []

    def test_policy_malformed_current_hash_does_not_raise(self):
        assert PasswordPolicy().validate("abc12345", current_hash="garbage") == []

    def test_policy_message_never_echoes_password(self):
        for v in PasswordPolicy().validate("a"):
            assert "a" not in v.message.replace("at least", "")  # no echo of the input


@pytest_asyncio.fixture
async def redis_pool():
    pool = aioredis.ConnectionPool.from_url(
        REDIS_AUTH_URL, decode_responses=True, encoding="utf-8"
    )
    yield pool
    await pool.disconnect()


@pytest_asyncio.fixture
async def redis(redis_pool):
    async with aioredis.Redis(connection_pool=redis_pool) as r:
        yield r


@pytest.fixture
def recovery_user():
    return SimpleNamespace(
        user_id=424242,
        username="recovery_test_user",
        email="recovery_test@example.com",
    )


@pytest_asyncio.fixture
async def broken_redis_pool():
    """A pool pointing nowhere, so every command raises a connection error.

    Used to exercise RateLimiter's fail-open behaviour without mocking.
    """
    pool = aioredis.ConnectionPool.from_url(
        "redis://recovery-test-unreachable-host.invalid:6379/0",
        decode_responses=True,
        encoding="utf-8",
        socket_connect_timeout=1,
    )
    yield pool
    await pool.disconnect()


@pytest.fixture
def recovery_store(redis_pool):
    return RecoveryTokenStore(redis_pool, secret=TEST_SECRET)


class TestRecoveryTokenStore:
    """Module 3 — RecoveryTokenStore, against a real Redis instance."""

    @pytest_asyncio.fixture(autouse=True)
    async def _clean(self, redis_pool):
        async def _purge():
            async with aioredis.Redis(connection_pool=redis_pool) as r:
                keys = await r.keys(f"{RECOVERY_KEY_PREFIX}*")
                if keys:
                    await r.delete(*keys)
        await _purge()
        yield
        await _purge()

    @pytest.mark.asyncio
    async def test_store_key_is_hashed(self, recovery_store, redis, recovery_user):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        await recovery_store.issue_confirmation(token)
        keys = await redis.keys(f"{RECOVERY_KEY_PREFIX}*")
        assert not any(token in k for k in keys)
        for k in keys:
            value = await redis.get(k)
            assert token not in (value or "")

    @pytest.mark.asyncio
    async def test_store_recovery_survives_validate(self, recovery_store, recovery_user):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        assert await recovery_store.validate_recovery(token) is not None
        assert await recovery_store.validate_recovery(token) is not None   # D4

    @pytest.mark.asyncio
    async def test_store_confirmation_rotates(self, recovery_store, recovery_user):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        c1, _ = await recovery_store.issue_confirmation(token)
        c2, _ = await recovery_store.issue_confirmation(token)
        assert await recovery_store.consume_confirmation(c1) is None
        assert await recovery_store.consume_confirmation(c2) is not None

    @pytest.mark.asyncio
    async def test_rotation_preserves_stage1_ttl(self, recovery_store, redis, recovery_user):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        key = f"{RECOVERY_KEY_PREFIX}{_hash_token(token)}"
        before = await redis.ttl(key)
        await recovery_store.issue_confirmation(token)
        after = await redis.ttl(key)
        assert after <= before

    @pytest.mark.asyncio
    async def test_store_confirmation_single_use(self, recovery_store, recovery_user):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        c, _ = await recovery_store.issue_confirmation(token)
        assert await recovery_store.consume_confirmation(c) is not None
        assert await recovery_store.consume_confirmation(c) is None

    @pytest.mark.asyncio
    async def test_store_signature_roundtrip(self, recovery_store, redis, recovery_user):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        assert await recovery_store.validate_recovery(token) is not None
        # Tamper with the payload directly in Redis.
        key = f"{RECOVERY_KEY_PREFIX}{_hash_token(token)}"
        raw = await redis.get(key)
        data = json_decoder(raw)
        data["username"] = "tampered"
        await redis.set(key, json_encoder(data), keepttl=True)
        assert await recovery_store.validate_recovery(token) is None

    @pytest.mark.asyncio
    async def test_store_wrong_secret_rejected(self, redis_pool, recovery_user):
        store_a = RecoveryTokenStore(redis_pool, secret=b"secret-a")
        store_b = RecoveryTokenStore(redis_pool, secret=b"secret-b")
        token, _ = await store_a.issue_recovery(recovery_user)
        assert await store_b.validate_recovery(token) is None

    @pytest.mark.asyncio
    async def test_store_ttls(self, recovery_store, redis, recovery_user):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        key = f"{RECOVERY_KEY_PREFIX}{_hash_token(token)}"
        ttl = await redis.ttl(key)
        assert 0 < ttl <= 3600

        c, _ = await recovery_store.issue_confirmation(token)
        ckey = f"{CONFIRM_KEY_PREFIX}{_hash_token(c)}"
        cttl = await redis.ttl(ckey)
        assert 0 < cttl <= 900

    @pytest.mark.asyncio
    async def test_store_expired_returns_none(self, redis_pool, recovery_user):
        store = RecoveryTokenStore(redis_pool, secret=TEST_SECRET)
        token, _ = await store.issue_recovery(recovery_user)
        key = f"{RECOVERY_KEY_PREFIX}{_hash_token(token)}"
        async with aioredis.Redis(connection_pool=redis_pool) as r:
            await r.delete(key)  # simulate expiry
        assert await store.validate_recovery(token) is None

    @pytest.mark.asyncio
    async def test_drop_pair_deletes_both_records(
        self, recovery_store, redis, recovery_user
    ):
        token, _ = await recovery_store.issue_recovery(recovery_user)
        c, confirmation = await recovery_store.issue_confirmation(token)
        recovery_key_hash = confirmation.recovery_key
        confirm_key_hash = _hash_token(c)
        await recovery_store.drop_pair(recovery_key_hash, confirm_key_hash)
        assert await redis.get(f"{RECOVERY_KEY_PREFIX}{recovery_key_hash}") is None
        assert await redis.get(f"{CONFIRM_KEY_PREFIX}{confirm_key_hash}") is None


class TestRateLimiter:
    """Module 4 — RateLimiter, against a real Redis instance."""

    @pytest_asyncio.fixture(autouse=True)
    async def _clean(self, redis_pool):
        from navigator_auth.handlers.recovery.limiter import RATE_KEY_PREFIX

        async def _purge():
            async with aioredis.Redis(connection_pool=redis_pool) as r:
                keys = await r.keys(f"{RATE_KEY_PREFIX}*")
                if keys:
                    await r.delete(*keys)
        await _purge()
        yield
        await _purge()

    @pytest.mark.asyncio
    async def test_limiter_allows_under_limit(self, redis_pool):
        rl = RateLimiter(redis_pool, "3/hour", "email")
        assert all([await rl.check("a@b.c") for _ in range(3)])

    @pytest.mark.asyncio
    async def test_limiter_blocks_over_limit(self, redis_pool):
        rl = RateLimiter(redis_pool, "3/hour", "email")
        for _ in range(3):
            await rl.check("a@b.c")
        assert await rl.check("a@b.c") is False

    @pytest.mark.asyncio
    async def test_limiter_fails_open(self, broken_redis_pool, caplog):
        import logging
        caplog.set_level(logging.WARNING)
        rl = RateLimiter(broken_redis_pool, "3/hour", "email")
        assert await rl.check("a@b.c") is True
        assert "WARNING" in caplog.text

    @pytest.mark.asyncio
    async def test_limiter_malformed_spec_disables(self, redis_pool):
        rl = RateLimiter(redis_pool, "garbage", "email")
        assert all([await rl.check("a@b.c") for _ in range(50)])

    @pytest.mark.asyncio
    async def test_limiter_prefixes_independent(self, redis_pool):
        e = RateLimiter(redis_pool, "3/hour", "email")
        i = RateLimiter(redis_pool, "3/hour", "ip")
        for _ in range(3):
            await e.check("x")
        assert await i.check("x") is True

    @pytest.mark.asyncio
    async def test_no_raw_email_in_keys(self, redis_pool, redis):
        rl = RateLimiter(redis_pool, "3/hour", "email")
        await rl.check("user@example.com")
        assert not any("user@example.com" in k for k in await redis.keys("*"))

    @pytest.mark.asyncio
    async def test_window_expires_and_reallows(self, redis_pool):
        rl = RateLimiter(redis_pool, "1/second", "email")
        assert await rl.check("expiring@b.c") is True
        assert await rl.check("expiring@b.c") is False
        import asyncio
        await asyncio.sleep(1.1)
        assert await rl.check("expiring@b.c") is True


class TestNotificationPayloadSecrecy:
    def test_repr_hides_token(self):
        from navigator_auth.handlers.recovery.types import NotificationPayload
        import datetime
        p = NotificationPayload(
            email="a@b.c", display_name="A", username="a",
            token="SUPERSECRETTOKEN", url="https://x/?token=SUPERSECRETTOKEN",
            expires_at=datetime.datetime.now(), found=True,
        )
        assert "SUPERSECRETTOKEN" not in repr(p)
