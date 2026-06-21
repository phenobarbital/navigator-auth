"""OAuth2 Pydantic models for navigator-auth.

FEAT-093:
  TASK-023 — OAuthClient.client_id is now the PUBLIC opaque uid (str).
             OAuthClient.client_pk carries the internal integer PK.
  TASK-024 — user_id added to OauthAuthorizationCode and OauthRefreshToken;
             nested OAuthClient field renamed client_id -> client.
  TASK-026 — parent_token, absolute_expires_at, revoked_reason on OauthRefreshToken.
  TASK-027 — OauthGrant (consent) and OauthAccessTokenRecord (jti tracking).
"""

from typing import Optional, Union
from datetime import datetime, timedelta
import json
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, field_validator

from ...conf import OAUTH_DEFAULT_TOKEN_EXPIRATION_DAYS


# ---------------------------------------------------------------------------
# Resource Owner representation (lightweight, no DB dependency)
# ---------------------------------------------------------------------------

class OauthUser(BaseModel):
    user_id: int = Field()
    username: str = Field()
    given_name: str = Field()
    family_name: str = Field()
    email: Optional[str] = Field(default=None)

    @property
    def first_name(self):
        return self.given_name

    @property
    def last_name(self):
        return self.family_name

    @classmethod
    def from_user(cls, user):
        """Convert a navigator_auth User object to OauthUser."""
        return cls(
            user_id=user.user_id,
            username=user.username,
            given_name=getattr(user, 'first_name', '') or "",
            family_name=getattr(user, 'last_name', '') or "",
            email=getattr(user, 'email', None),
        )


def default_expiration():
    return datetime.now() + timedelta(days=365)


# ---------------------------------------------------------------------------
# OAuth2 Client (TASK-023: client_id = public uid; client_pk = int PK)
# ---------------------------------------------------------------------------

class OAuthClient(BaseModel):
    """OAuthClient.

    Application making requests to the OAuth2 Server on behalf of
    the Resource Owner.

    client_id  : str  — the PUBLIC opaque identifier (= auth.clients.client_uid).
                        This is the value that appears on the wire and in JWT claims.
    client_pk  : int  — internal surrogate PK (auth.clients.client_id bigserial).
                        Used only as FK target in new token/grant tables.
                        Never returned to clients.
    """

    # Public wire identifier (opaque, non-enumerable).
    client_id: str = Field()
    # Internal integer PK — None for in-memory / Redis clients.
    client_pk: Optional[int] = Field(default=None)
    client_name: str = Field()
    client_secret: Optional[str] = Field(default=None)
    client_type: str = Field(default="public")
    redirect_uris: list = Field(default_factory=list)
    policy_uri: Optional[str] = Field(default=None)
    client_logo_uri: Optional[str] = Field(default=None)
    # `user` is kept for reference only; MUST NOT be used to derive token owners.
    user: Optional[OauthUser] = Field(default=None)
    default_scopes: Union[str, list] = Field(default_factory=list)
    allowed_grant_types: list = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    expiration_date: datetime = Field(default_factory=default_expiration)

    @field_validator("client_id", mode="before")
    @classmethod
    def parse_client_id(cls, v):
        # Ensure it is always stored as a string (uid).
        return str(v)

    @field_validator("redirect_uris", "allowed_grant_types", mode="before")
    @classmethod
    def parse_list(cls, v):
        if v is None:
            return []
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return [v]
        return v

    @field_validator("default_scopes", mode="before")
    @classmethod
    def parse_default_scopes(cls, v):
        if v is None:
            return []
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return parsed
            except Exception:
                pass
            return [v]
        return v

    @property
    def client(self):
        return self.client_name


# ---------------------------------------------------------------------------
# Auth code TTL helper
# ---------------------------------------------------------------------------

def code_expiration():
    return datetime.now() + timedelta(minutes=2)


# ---------------------------------------------------------------------------
# Authorization Code (TASK-024: user_id required; nested field = client)
# ---------------------------------------------------------------------------

class OauthAuthorizationCode(BaseModel):
    """Authorization code issued during consent.

    TASK-023: nested OAuthClient field is ``client`` (was ``client_id``).
    TASK-024: ``user_id`` (int, required) — the authenticated resource owner.
              ``used`` / ``used_at`` enforce single-use (B5).
    """

    # Renamed from client_id to avoid confusion with the wire client_id string.
    client: OAuthClient = Field()
    # Authenticated resource owner — must originate from session, never client.user.
    user_id: int = Field()
    code: str = Field()
    nonce: Optional[str] = Field(default=None)
    redirect_uri: str = Field()
    response_type: str = Field(default="code")
    scope: str = Field()
    state: str = Field()
    expires_at: datetime = Field(default_factory=code_expiration)
    code_challenge: Optional[str] = Field(default=None)
    code_challenge_method: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.now)
    # Single-use enforcement (B5).
    used: bool = Field(default=False)
    used_at: Optional[datetime] = Field(default=None)


# ---------------------------------------------------------------------------
# Refresh Token (TASK-024: user_id + renamed client; TASK-026: rotation fields)
# ---------------------------------------------------------------------------

class OauthRefreshToken(BaseModel):
    """Refresh token with rotation/reuse-detection support.

    TASK-023: nested OAuthClient field is ``client``.
    TASK-024: ``user_id`` (int, required).
    TASK-026: ``parent_token``, ``absolute_expires_at``, ``revoked_reason``.
    """

    client: OAuthClient = Field()
    user_id: int = Field()
    refresh_token: str = Field()
    scope: str = Field()
    # Rotation chain: new token sets parent_token = old token's refresh_token.
    parent_token: Optional[str] = Field(default=None)
    issued_at: datetime = Field(default_factory=datetime.now)
    # Sliding expiry (renewed on each rotation within absolute limit).
    expires_at: datetime = Field(default_factory=default_expiration)
    # Hard-stop: copied from the chain root; never extended.
    absolute_expires_at: datetime = Field(default_factory=default_expiration)
    revoked: bool = Field(default=False)
    revoked_at: Optional[datetime] = Field(default=None)
    # 'rotated' | 'revoked' | 'reuse_detected' | 'cascade'
    revoked_reason: Optional[str] = Field(default=None)


# ---------------------------------------------------------------------------
# OauthGrant — durable consent record (TASK-027)
# ---------------------------------------------------------------------------

class OauthGrant(BaseModel):
    """Durable consent grant record.

    Persists the user's decision to authorise a client for a set of scopes.
    Powers consent-skip and per-app revocation.

    ``client_id`` here is the PUBLIC ``client_uid`` string (not the int PK).
    """

    grant_id: UUID = Field(default_factory=uuid4)
    user_id: int = Field()
    client_id: str = Field()  # public client_uid
    scopes: list = Field(default_factory=list)
    granted_at: datetime = Field(default_factory=datetime.now)
    revoked: bool = Field(default=False)
    revoked_at: Optional[datetime] = Field(default=None)


# ---------------------------------------------------------------------------
# OauthAccessTokenRecord — jti tracking (TASK-027)
# ---------------------------------------------------------------------------

class OauthAccessTokenRecord(BaseModel):
    """Per-access-token jti record for revocation checking.

    ``client_id`` here is the PUBLIC ``client_uid`` string.
    ``client_pk`` is the integer FK for DB joins.
    """

    jti: UUID = Field(default_factory=uuid4)
    user_id: int = Field()
    client_id: str = Field()   # public client_uid (wire/claim value)
    client_pk: Optional[int] = Field(default=None)  # int FK for DB
    scope: str = Field(default="")
    issued_at: datetime = Field(default_factory=datetime.now)
    expires_at: datetime = Field(default_factory=default_expiration)
    revoked: bool = Field(default=False)


# ---------------------------------------------------------------------------
# OauthToken (composite; kept for backward compat, uses renamed fields)
# ---------------------------------------------------------------------------

def token_uid():
    return uuid4()


def token_expiration():
    return datetime.now() + timedelta(days=OAUTH_DEFAULT_TOKEN_EXPIRATION_DAYS)


class OauthToken(BaseModel):
    token_id: UUID = Field(default_factory=token_uid, json_schema_extra={"primary_key": True})
    token_type: str = Field(default="Bearer")
    code: OauthAuthorizationCode = Field()
    # client field mirrors code.client (the OAuthClient object).
    client: OAuthClient = Field()
    refresh_token: OauthRefreshToken = Field()
    access_token: str = Field()
    scope: str = Field()
    expires_at: datetime = Field(default_factory=token_expiration)
    issued_at: datetime = Field(default_factory=datetime.now)
