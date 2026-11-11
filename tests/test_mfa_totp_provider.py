"""Unit coverage for the TOTP provider's deterministic security primitives."""

import os

import pytest
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor.totp import TOTP

from navigator_auth.mfa.totp import TOTPProvider, mfa_seed_context, pending_seed_context
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.vault.integration import VAULT_KEYRING_APP_KEY
from navigator_session.vault import KeyRing, seal_value

def _provider() -> TOTPProvider:
    return TOTPProvider(app={}, db_pool=None, store=None, clock=lambda: 1_700_000_010)


def test_totp_accepts_exact_skew_window() -> None:
    provider = _provider()
    seed = os.urandom(20)
    for offset in (-30, 0, 30):
        code = TOTP(seed, 6, SHA1(), 30).generate(1_700_000_010 + offset).decode()
        assert provider.match_step(seed, code, 1_700_000_010) is not None


def test_totp_rejects_outside_window_and_malformed_codes() -> None:
    provider = _provider()
    seed = os.urandom(20)
    totp = TOTP(seed, 6, SHA1(), 30)
    for offset in (-60, 60):
        assert provider.match_step(seed, totp.generate(1_700_000_010 + offset).decode(), 1_700_000_010) is None
    for code in ("", "12345", "1234567", "abcdef", None):
        assert provider.match_step(seed, code, 1_700_000_010) is None


def test_mfa_contexts_bind_expected_fields() -> None:
    active = mfa_seed_context(7)
    pending = pending_seed_context(user_id=7, session_hash="session", security_version=2, enrollment_hash="token")
    assert active.purpose == "mfa"
    assert active.fields == (("user_id", 7), ("provider", "totp"), ("key", "mfa:totp"))
    assert pending.purpose == "mfa-pending"
    assert ("version", 2) in pending.fields


class _NoPool:
    """A pool that must never be used when a caller connection is supplied."""

    def acquire(self):
        raise AssertionError("pool acquired although conn= was given")


class _Conn:
    """Fake caller connection returning a sealed seed and recording statements."""

    def __init__(self, ciphertext: bytes, *, fail_touch: bool = False) -> None:
        self.ciphertext = ciphertext
        self.fail_touch = fail_touch
        self.calls = []

    async def fetch_one(self, sql, *args):
        self.calls.append(("fetch_one", sql, args))
        return {"ciphertext_db": self.ciphertext}

    async def fetchval(self, sql, *args):
        self.calls.append(("fetchval", sql, args))
        if self.fail_touch:
            raise RuntimeError("touch failed")
        return 1


class _Store:
    async def mark_totp_step(self, user_id, step, ttl):
        return True


def _conn_provider(*, fail_touch: bool = False):
    keyring = KeyRing({1: os.urandom(32)}, 1)
    seed = os.urandom(20)
    ciphertext = seal_value(seed, mfa_seed_context(7), keyring)
    conn = _Conn(ciphertext, fail_touch=fail_touch)
    provider = TOTPProvider(
        app={VAULT_KEYRING_APP_KEY: keyring},
        db_pool=_NoPool(),
        store=_Store(),
        clock=lambda: 1_700_000_010,
    )
    code = TOTP(seed, 6, SHA1(), 30).generate(1_700_000_010).decode()
    return provider, conn, code


@pytest.mark.asyncio
async def test_verify_on_caller_conn_never_acquires() -> None:
    """verify(conn=) reads and touches only the supplied connection."""
    provider, conn, code = _conn_provider()

    assert await provider.verify(None, {"user_id": 7}, code, conn=conn)
    assert [kind for kind, _sql, _args in conn.calls] == ["fetch_one", "fetchval"]


@pytest.mark.asyncio
async def test_verify_on_caller_conn_touch_failure_raises() -> None:
    """A failed caller-connection touch fails closed."""
    provider, conn, code = _conn_provider(fail_touch=True)

    with pytest.raises(MfaStorageError, match="totp last-used touch failed: RuntimeError"):
        await provider.verify(None, {"user_id": 7}, code, conn=conn)
