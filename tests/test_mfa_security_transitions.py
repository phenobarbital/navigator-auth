"""Security-transition semantics for FEAT-106 credential changes."""

import pytest

from navigator_auth.mfa.events import SECURITY_EVENTS, security_transition


@pytest.mark.asyncio
async def test_security_transition_is_noop_without_services():
    """A disabled MFA installation does not block the protected operation."""
    seen = []
    async with security_transition({}, 42, "password_change") as connection:
        seen.append(connection)
    assert seen == [None]


@pytest.mark.asyncio
async def test_security_transition_rejects_unknown_event():
    """Only the contract's event names are accepted."""
    with pytest.raises(ValueError):
        async with security_transition({}, 42, "unknown"):
            pass


def test_security_events_are_complete():
    """The exported event set includes wired and future global logout transitions."""
    assert SECURITY_EVENTS == frozenset(
        {
            "password_change",
            "password_reset",
            "recovery_completion",
            "passkey_registered",
            "passkey_removed",
            "global_logout",
        }
    )
