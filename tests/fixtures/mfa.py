"""Shared FEAT-106 MFA test fixtures."""

import secrets
import warnings
from datetime import datetime, timezone

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE, REDIS_AUTH_URL, default_dsn
from navigator_auth.handlers.users.passwd import set_basic_password
from navigator_auth.mfa.migrations import ensure_mfa_tables
from navigator_auth.mfa.types import MfaMode, OtpNotificationPayload, TenantMfaPolicy

MFA_TEST_SECRET = b"test-mfa-secret-feat106-not-for-production"
USERS = f"{AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE}"
FROZEN_EPOCH = 1_700_000_010
TEST_PASSWORD = "correct-horse-battery-9"


@pytest.fixture
def mfa_secret() -> bytes:
    """Return the deterministic test-only MFA secret."""
    return MFA_TEST_SECRET


async def _purge_mfa_keys(pool) -> None:
    """Remove MFA-related Redis keys from a fixture pool."""
    async with aioredis.Redis(connection_pool=pool) as redis_client:
        keys = [key async for key in redis_client.scan_iter(match="auth:mfa:*")]
        if keys:
            await redis_client.delete(*keys)


@pytest_asyncio.fixture
async def mfa_redis_pool():
    """Provide real Redis with MFA keys removed before and after use."""
    pool = aioredis.ConnectionPool.from_url(REDIS_AUTH_URL, decode_responses=True, encoding="utf-8")
    await _purge_mfa_keys(pool)
    yield pool
    await _purge_mfa_keys(pool)
    await pool.disconnect()


@pytest_asyncio.fixture
async def broken_redis_pool():
    """Provide a pool whose commands fail due to an unreachable host."""
    pool = aioredis.ConnectionPool.from_url(
        "redis://mfa-test-unreachable-host.invalid:6379/0",
        decode_responses=True,
        encoding="utf-8",
        socket_connect_timeout=1,
    )
    yield pool
    await pool.disconnect()


@pytest_asyncio.fixture
async def mfa_db():
    """Provide a live MFA-ready Postgres pool or skip if unavailable."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            import asyncdb  # pylint: disable=import-outside-toplevel

            pool = asyncdb.AsyncPool("pg", dsn=default_dsn)
        await pool.connect()
        await ensure_mfa_tables(pool)
    except Exception as err:  # pylint: disable=W0703
        pytest.skip(f"Postgres unavailable: {type(err).__name__}: {err}")
    yield pool
    await pool.close()


@pytest_asyncio.fixture
async def mfa_user_factory(mfa_db):
    """Create temporary users and remove them after the consuming test."""
    created: list[str] = []

    async def _make(
        *,
        superuser: bool = False,
        email: str | None = "default",
        active: bool = True,
        password: str = TEST_PASSWORD,
    ) -> dict:
        username = f"mfa_test_{secrets.token_hex(4)}"
        address = f"{username}@example.com" if email == "default" else email
        password_hash = set_basic_password(password)
        async with await mfa_db.acquire() as conn:
            row = await conn.fetch_one(
                f"INSERT INTO {USERS} "
                "(username, email, password, is_superuser, is_active, is_new, first_name, last_name) "
                "VALUES ($1, $2, $3, $4, $5, false, '', '') RETURNING user_id",
                username,
                address,
                password_hash,
                superuser,
                active,
            )
        created.append(username)
        return {
            "user_id": row["user_id"],
            "username": username,
            "email": address,
            "password": password_hash,
            "password_plain": password,
            "is_superuser": superuser,
            "is_active": active,
        }

    yield _make
    if created:
        async with await mfa_db.acquire() as conn:
            await conn.fetchval(
                f"WITH d AS (DELETE FROM {USERS} WHERE username = ANY($1::text[]) RETURNING 1) "
                "SELECT count(*) FROM d",
                created,
            )


@pytest.fixture
def mfa_policy_enforced() -> TenantMfaPolicy:
    """Return a deterministic enforced MFA policy."""
    return TenantMfaPolicy(
        org_id=5,
        mode=MfaMode.ENFORCED,
        remember_days=30,
        enforced_at=datetime(2026, 11, 1, tzinfo=timezone.utc),
        enforced_by="fixture",
    )


class FrozenClock:
    """Deterministic epoch for TOTP skew tests."""

    def __init__(self, epoch: float = FROZEN_EPOCH) -> None:
        self.now = float(epoch)

    def __call__(self) -> float:
        """Return the current frozen epoch."""
        return self.now

    def advance(self, seconds: float) -> None:
        """Advance the frozen epoch by a number of seconds."""
        self.now += seconds


@pytest.fixture
def frozen_totp_clock() -> FrozenClock:
    """Return a fresh deterministic TOTP clock."""
    return FrozenClock()


CAPTURED_OTP: list[OtpNotificationPayload] = []


def capture_otp(payload: OtpNotificationPayload) -> None:
    """Capture an OTP callback payload while asserting its code is redacted."""
    assert payload.code not in repr(payload)
    CAPTURED_OTP.append(payload)


class _OtpSpy:
    """Expose the callback dotted path and its captured payloads."""

    path = "tests.fixtures.mfa.capture_otp"

    @property
    def payloads(self) -> list[OtpNotificationPayload]:
        """Return captured notification payloads."""
        return CAPTURED_OTP


@pytest.fixture
def otp_callback_spy():
    """Provide an isolated OTP callback spy."""
    CAPTURED_OTP.clear()
    yield _OtpSpy()
    CAPTURED_OTP.clear()
