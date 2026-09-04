"""Data models for the backend-based password recovery flow (FEAT-098).

These are plain, frozen dataclasses used as the Redis-persisted payloads for
the two token stages, the hand-off to the notification callback, and a
single policy-violation entry. None of them do I/O; they are pure data.
"""
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class RecoveryPayload:
    """Redis-persisted body of a stage-1 recovery record."""
    user_id: int
    username: str
    email: str
    issued_at: float          # epoch seconds
    nonce: str                # 16 bytes urlsafe, makes each token unique
    signature: str            # HMAC-SHA256 over the four fields above


@dataclass(frozen=True)
class ConfirmationPayload:
    """Redis-persisted body of a stage-2 confirmation record."""
    user_id: int
    username: str
    recovery_key: str         # sha256 of the stage-1 token; links the pair
    issued_at: float
    signature: str


@dataclass(frozen=True)
class NotificationPayload:
    """Hand-off to AUTH_RECOVERY_CALLBACK. The only place a raw token appears."""
    email: str
    display_name: str
    username: str
    token: str                # raw stage-1 token — never in an HTTP response
    url: str                  # AUTH_RECOVERY_URL_TEMPLATE.format(token=token)
    expires_at: datetime
    found: bool                # False => no such account; callback decides what to send

    def __repr__(self) -> str:
        # The raw token must never reach a log line via a stray repr()/str()
        # of this object (see spec "Known Risks / Gotchas — Log leakage").
        return (
            f"{self.__class__.__name__}(email={self.email!r}, "
            f"display_name={self.display_name!r}, username={self.username!r}, "
            f"token='***', url='***', expires_at={self.expires_at!r}, "
            f"found={self.found!r})"
        )


@dataclass(frozen=True)
class PolicyViolation:
    rule: str                 # "min_length" | "needs_letter" | "needs_digit" | "same_as_current"
    message: str
