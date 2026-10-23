"""Normalized token payload returned by every backend's identity flow."""

import base64
import json
from typing import Any, Optional
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field


def jwt_issued_at(token: Optional[str]) -> Optional[datetime]:
    """Best-effort ``iat`` of a JWT, as an aware UTC datetime.

    The claim is read WITHOUT verifying the signature, and is used only as an
    observability signal: how old a provider grant already was by the time it
    reached us (issue:3fd80396c685). Never gate a security decision on it —
    the verified path is ``AzureAuth.verify_external_token``.

    Args:
        token: A compact-serialization JWT, or any other string.

    Returns:
        The ``iat`` claim as an aware UTC datetime, or ``None`` when the value
        is not a JWT, carries no usable ``iat``, or cannot be decoded. An
        opaque provider access token is the common ``None`` case.
    """
    if not token or not isinstance(token, str):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        iat = claims.get("iat")
        if iat is None:
            return None
        return datetime.fromtimestamp(int(iat), tz=timezone.utc)
    except Exception:  # pylint: disable=W0703
        return None


@dataclass
class TokenResponse:
    """TokenResponse.

    Provider-agnostic representation of an OAuth2 token grant, used by the
    identity-link flow (authorization) and by credential refresh. Backends
    normalize whatever their provider returns into this shape.
    """

    access_token: str
    token_type: str = "Bearer"
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    expires_in: Optional[int] = None
    expires_at: Optional[datetime] = None
    #: When the provider ISSUED this token, read from the access token's own
    #: ``iat`` claim. Observability only: a provider that serves a cached
    #: token on a silent re-login (Entra does) hands back a grant whose
    #: ``issued_at`` predates this login — see ``age_seconds``.
    issued_at: Optional[datetime] = None
    scopes: list = field(default_factory=list)
    provider_user_id: Optional[str] = None
    raw: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.expires_at is None and self.expires_in is not None:
            self.expires_at = datetime.now(timezone.utc) + timedelta(
                seconds=int(self.expires_in)
            )
        if self.issued_at is None:
            self.issued_at = jwt_issued_at(self.access_token)

    def age_seconds(self) -> Optional[float]:
        """Seconds since the provider issued this token, when knowable.

        ``None`` for an opaque access token (no ``iat`` to read). A value well
        above the time this login took means the provider served a token it
        had already issued, rather than a new one.
        """
        if self.issued_at is None:
            return None
        return (datetime.now(timezone.utc) - self.issued_at).total_seconds()

    def is_expiring(self, leeway: int = 0) -> bool:
        """True when the token is expired or expires within *leeway* seconds."""
        if self.expires_at is None:
            return False
        deadline = datetime.now(timezone.utc) + timedelta(seconds=leeway)
        return self.expires_at <= deadline

    def credential(self) -> dict:
        """Serializable credential payload stored in the vault cache
        and returned by the credential endpoint. Never includes ``raw``.
        """
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "refresh_token": self.refresh_token,
            "id_token": self.id_token,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "scopes": list(self.scopes or []),
            "provider_user_id": self.provider_user_id,
        }

    @classmethod
    def from_credential(cls, data: dict) -> "TokenResponse":
        """Rebuild a TokenResponse from a ``credential()`` dict."""
        expires_at = data.get("expires_at")
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        return cls(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            refresh_token=data.get("refresh_token"),
            id_token=data.get("id_token"),
            expires_at=expires_at,
            scopes=list(data.get("scopes") or []),
            provider_user_id=data.get("provider_user_id"),
        )

    @classmethod
    def from_oauth_response(
        cls, payload: dict, scopes: Optional[list] = None
    ) -> "TokenResponse":
        """Build from a standard OAuth2 token-endpoint JSON response."""
        scope = payload.get("scope")
        if scopes is None:
            scopes = scope.split() if isinstance(scope, str) and scope else []
        expires_in = payload.get("expires_in")
        try:
            expires_in = int(expires_in) if expires_in is not None else None
        except (TypeError, ValueError):
            expires_in = None
        return cls(
            access_token=payload["access_token"],
            token_type=payload.get("token_type") or "Bearer",
            refresh_token=payload.get("refresh_token"),
            id_token=payload.get("id_token"),
            expires_in=expires_in,
            scopes=list(scopes),
            raw=dict(payload),
        )


def mask_value(value: Any) -> Optional[str]:
    """Redact a secret for API/UI output; keeps only a length hint."""
    if not value:
        return None
    return f"***{len(str(value))}"
