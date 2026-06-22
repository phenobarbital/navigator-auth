"""Pure helpers for RFC 8628 Device Authorization Grant — FEAT-094 TASK-032.

These functions are **pure** (synchronous, no I/O, no server dependencies) so
they can be unit-tested without a running server, Redis, or database.

Functions:
  generate_user_code(length, alphabet) — secrets-based human-legible code.
  poll_decision(dc, now)               — state machine returning RFC 8628 error
                                         strings or 'approved'.
"""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import OauthDeviceCode


# ---------------------------------------------------------------------------
# Default alphabet — unambiguous characters only.
# Excludes vowels (A E I O U) and visually confusable characters
# (0/O, 1/I/L) per RFC 8628 §6.1 recommendations.
# ---------------------------------------------------------------------------

DEFAULT_USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"
DEFAULT_USER_CODE_LENGTH = 8


def generate_user_code(
    length: int = DEFAULT_USER_CODE_LENGTH,
    alphabet: str = DEFAULT_USER_CODE_ALPHABET,
) -> str:
    """Generate a human-legible, unambiguous user code.

    Uses ``secrets.choice`` for cryptographic-quality randomness.
    Applies no formatting (hyphens etc.) — callers add presentation
    formatting if desired.

    Args:
        length:   Number of characters in the returned code.  Defaults to 8.
        alphabet: Character pool to draw from.  Defaults to the
                  unambiguous uppercase consonant-only alphabet
                  ``BCDFGHJKLMNPQRSTVWXZ``.

    Returns:
        A randomly generated string of ``length`` characters from ``alphabet``.
    """
    if not alphabet:
        raise ValueError("alphabet must not be empty")
    if length < 1:
        raise ValueError("length must be >= 1")
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ---------------------------------------------------------------------------
# Poll decision state machine
# ---------------------------------------------------------------------------

# RFC 8628 §3.5 error codes returned by the polling branch.
SLOW_DOWN = "slow_down"
AUTHORIZATION_PENDING = "authorization_pending"
ACCESS_DENIED = "access_denied"
EXPIRED_TOKEN = "expired_token"
APPROVED = "approved"


def poll_decision(dc: "OauthDeviceCode", now: datetime) -> str:
    """Evaluate the current state of a device code for a polling request.

    Implements the RFC 8628 §3.5 server-side decision table:

    1. Too soon (elapsed < interval) → ``slow_down``
       The caller must also increase ``dc.interval`` by
       ``OAUTH_DEVICE_SLOW_DOWN_INCREMENT`` before persisting.
    2. Expired → ``expired_token``
    3. Status = DENIED → ``access_denied``
    4. Status = APPROVED → ``approved``
    5. Status = CONSUMED → ``expired_token`` (single-use already exchanged)
    6. Status = PENDING → ``authorization_pending``

    Args:
        dc:  The ``OauthDeviceCode`` record loaded from storage.
        now: The current datetime (caller-provided for testability).

    Returns:
        One of: 'slow_down', 'authorization_pending', 'access_denied',
        'expired_token', 'approved'.
    """
    from .models import DeviceCodeStatus

    # 1. Expiry check (before interval: a code expired whilst polling → expired).
    if now >= dc.expires_at:
        return EXPIRED_TOKEN

    # 2. Terminal status checks (CONSUMED/DENIED) before rate-limit —
    #    these states are irreversible; returning slow_down would be misleading.
    if dc.status == DeviceCodeStatus.CONSUMED:
        # Already exchanged — treat as expired to avoid revealing state.
        return EXPIRED_TOKEN

    if dc.status == DeviceCodeStatus.DENIED:
        return ACCESS_DENIED

    # 3. Polling-rate check (too soon since last poll → slow_down).
    #    Only applicable to PENDING/APPROVED (non-terminal) states.
    if dc.last_polled_at is not None:
        elapsed = (now - dc.last_polled_at).total_seconds()
        if elapsed < dc.interval:
            return SLOW_DOWN

    # 4. Non-terminal status-based decisions.
    if dc.status == DeviceCodeStatus.APPROVED:
        return APPROVED

    # Default: DeviceCodeStatus.PENDING
    return AUTHORIZATION_PENDING
