"""Durable credential-change state: recovery markers and OAuth credential generation (FEAT-106)."""

from .migrations import (
    SECURITY_STATE_TABLES,
    ensure_security_state_tables,
    security_state_tables_present,
    setup_security_state_tables,
)
from .store import (
    GENERATION_CLAIM,
    SecurityStateError,
    confirmation_recorded,
    current_generation,
    generation_matches,
    generation_of,
    increment_generation,
    record_confirmation,
    stamp_generation,
)

__all__ = (
    "SECURITY_STATE_TABLES",
    "ensure_security_state_tables",
    "security_state_tables_present",
    "setup_security_state_tables",
    "GENERATION_CLAIM",
    "SecurityStateError",
    "confirmation_recorded",
    "current_generation",
    "generation_matches",
    "generation_of",
    "increment_generation",
    "record_confirmation",
    "stamp_generation",
)
