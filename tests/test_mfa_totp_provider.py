"""Unit coverage for the TOTP provider's deterministic security primitives."""

import os

from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor.totp import TOTP

from navigator_auth.mfa.totp import TOTPProvider, mfa_seed_context, pending_seed_context


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
