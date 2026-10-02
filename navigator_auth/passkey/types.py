"""Pydantic data models for the passkey (WebAuthn) backend (FEAT-101)."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class RelyingParty(BaseModel):
    """One allow-listed WebAuthn relying party (one tenant site)."""

    origin: str = Field(..., description="Exact origin, e.g. https://app.tenant-a.com")
    rp_id: str = Field(..., description="Registrable domain, e.g. tenant-a.com")
    rp_name: str = "Navigator"
    org_id: Optional[int] = None
    client_id: Optional[int] = None


class StoredCredential(BaseModel):
    """A row of ``{schema}.user_credentials``."""

    credential_id: bytes
    user_id: int
    rp_id: str
    public_key: bytes
    sign_count: int = 0
    transports: Optional[list[str]] = None
    aaguid: Optional[str] = None
    device_type: Optional[str] = None
    backed_up: bool = False
    label: Optional[str] = None
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None


class ChallengeState(BaseModel):
    """Redis payload for a pending registration or login ceremony."""

    challenge: str  # base64url
    rp_id: str
    origin: str
    expected_user_id: Optional[int] = None  # username-first, known user
    decoy: bool = False  # username-first, unknown user
