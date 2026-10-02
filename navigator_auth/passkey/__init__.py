"""Passkey (WebAuthn) support for navigator-auth (FEAT-101).

Importing this package never imports ``webauthn`` (optional extra ``passkey``).
"""
from .types import ChallengeState, RelyingParty, StoredCredential

__all__ = ("ChallengeState", "RelyingParty", "StoredCredential")
