"""Focused security checks for the MFA enrolment management surface."""

from types import SimpleNamespace

import pytest

from navigator_auth.handlers.mfa import MfaHandler
from navigator_auth.mfa.types import MfaMode, MfaState


def _record(password: str = "hash") -> SimpleNamespace:
    return SimpleNamespace(user_id=7, username="alice", password=password, email="alice@example.test")


def test_fresh_password_is_required_and_malformed_hash_fails() -> None:
    checker = SimpleNamespace(
        backend=SimpleNamespace(_idp=SimpleNamespace(check_password=lambda *args, **kwargs: True))
    )
    assert not MfaHandler._fresh_password_ok(checker, _record(), None)
    assert MfaHandler._fresh_password_ok(checker, _record(), "password")

    def malformed(*args, **kwargs):
        raise ValueError("bad hash")

    checker.backend._idp.check_password = malformed
    assert not MfaHandler._fresh_password_ok(checker, _record(), "password")


@pytest.mark.asyncio
async def test_strong_factor_proof_rejects_email() -> None:
    class Provider:
        async def verify(self, *args):
            return False

    async def consume(*args):
        return False

    services = SimpleNamespace(providers={"totp": Provider()}, backup_codes=SimpleNamespace(consume=consume))

    class Session(dict):
        created = 0

    session = Session(auth_method="email")
    assert not await MfaHandler()._strong_factor_proof(SimpleNamespace(), services, session, _record(), {})


def test_security_state_values_are_stable() -> None:
    assert MfaState.EMAIL.value == "email"
    assert MfaMode.ENFORCED.value == "enforced"
