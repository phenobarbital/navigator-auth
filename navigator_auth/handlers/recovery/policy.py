"""Password strength policy for the recovery flow (FEAT-098, Module 2).

Pure validator: no I/O, no Redis, no HTTP, no framework imports. Trivially
unit-testable and safe to reuse from any future "change password" screen.
"""
import re

from navigator_auth.handlers.users.passwd import check_password
from navigator_auth.exceptions import AuthException
from navigator_auth.handlers.recovery.types import PolicyViolation

_LETTER_RE = re.compile(r"[A-Za-z]")
_DIGIT_RE = re.compile(r"[0-9]")


class PasswordPolicy:
    """Validates a candidate password against a set of configurable rules.

    ``validate()`` returns every applicable violation (not just the first)
    so a front-end can render the full checklist at once.
    """

    def __init__(
        self,
        min_length: int = 8,
        require_letter: bool = True,
        require_digit: bool = True,
        reject_current: bool = True,
    ):
        self.min_length = min_length
        self.require_letter = require_letter
        self.require_digit = require_digit
        self.reject_current = reject_current

    def validate(
        self, password: str, current_hash: str = None
    ) -> list[PolicyViolation]:
        """Empty list == valid."""
        violations: list[PolicyViolation] = []

        if len(password) < self.min_length:
            violations.append(
                PolicyViolation(
                    rule="min_length",
                    message=f"Requires minimum length of {self.min_length}.",
                )
            )

        if self.require_letter and not _LETTER_RE.search(password):
            violations.append(
                PolicyViolation(
                    rule="needs_letter",
                    message="Must include letters.",
                )
            )

        if self.require_digit and not _DIGIT_RE.search(password):
            violations.append(
                PolicyViolation(
                    rule="needs_digit",
                    message="Must include digits.",
                )
            )

        if self.reject_current and current_hash:
            try:
                is_same = check_password(current_hash, password)
            except AuthException:
                # A corrupt/unrecognized existing hash must not block the
                # user from setting a new password — treat as not violated.
                is_same = False
            if is_same:
                violations.append(
                    PolicyViolation(
                        rule="same_as_current",
                        message="Must differ from current setting.",
                    )
                )

        return violations
