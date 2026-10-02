"""Passkey (WebAuthn) support for navigator-auth (FEAT-101).

Importing this package never imports ``webauthn`` (optional extra ``passkey``).
"""

from .rp import RelyingPartyResolver
from .store import PasskeyStore
from .types import ChallengeState, RelyingParty, StoredCredential

__all__ = (
    "ChallengeState",
    "PasskeyStore",
    "RelyingParty",
    "RelyingPartyResolver",
    "StoredCredential",
)
