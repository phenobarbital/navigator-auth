from typing import Optional, Union
from datetime import datetime, timedelta
import json
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, field_validator
# from asyncdb.models import Model, Field
from ...identities import AuthUser
from ...conf import (
    OAUTH_DEFAULT_TOKEN_EXPIRATION_DAYS
)

# Resource Owner:
class OauthUser(BaseModel):
    user_id: int = Field()
    username: str = Field()
    given_name: str = Field()
    family_name: str = Field()
    email: Optional[str] = Field(default=None)
    # Replicate required fields or add extra
    
    # We can add a validator or constructor if needed later.
    
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
            given_name=user.first_name or '',
            family_name=user.last_name or '',
            email=user.email
        )


def default_expiration():
    return datetime.now() + timedelta(days=365)

class OAuthClient(BaseModel):
    """OAuthClient.

    Application making requests to the OAuth2 Server on behalf of
    the Resource Owner.
    """
    client_id: str = Field()
    client_name: str = Field()
    client_secret: Optional[str] = Field(default=None)
    # Consider adding a field to distinguish between public and confidential clients.
    client_type: str = Field(default='public')
    redirect_uris: list = Field(default_factory=list)
    policy_uri: Optional[str] = Field(default=None)
    client_logo_uri: Optional[str] = Field(default=None)
    user: Optional[OauthUser] = Field(default=None) # Make optional for now or handle via validator
    default_scopes: Union[str, list] = Field(default='default') # Can be list in DB
    allowed_grant_types: list = Field(default_factory=list)
    created_at: datetime = Field(
        default_factory=datetime.now
    )
    updated_at: datetime = Field(
        default_factory=datetime.now
    )
    expiration_date: datetime = Field(
        default_factory=default_expiration
    )

    @field_validator('client_id', mode='before')
    def parse_client_id(cls, v):
        return str(v)

    @field_validator('redirect_uris', 'allowed_grant_types', mode='before')
    def parse_list(cls, v):
        if v is None:
            return []
        if isinstance(v, str):
             # Try JSON load if it looks like a list? Or split?
             try:
                 return json.loads(v)
             except:
                 return [v]
        return v

    @property
    def client(self):
        return self.client_name


def code_expiration():
    return datetime.now() + timedelta(minutes=2)

class OauthAuthorizationCode(BaseModel):
    client_id: OAuthClient = Field()
    code: str = Field()
    nonce: Optional[str] = Field(default=None)
    redirect_uri: str = Field()
    response_type: str = Field(default='code')
    scope: str = Field()
    state: str = Field()
    expires_at: datetime = Field(default_factory=code_expiration)
    code_challenge: Optional[str] = Field(default=None)
    code_challenge_method: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.now)
    used: bool = Field(default=False)
    used_at: datetime = Field(default_factory=datetime.now)

class OauthRefreshToken(BaseModel):
    client_id: OAuthClient = Field()
    refresh_token: str = Field()
    scope: str = Field()
    expires_at: datetime = Field(default_factory=default_expiration)
    issued_at: datetime = Field(default_factory=datetime.now)
    revoked: bool = Field(default=False)
    revoked_at: Optional[datetime] = Field(default=None)
    revoked_reason: Optional[str] = Field(default=None)


def token_uid():
    return uuid4()

def token_expiration():
    return datetime.now() + timedelta(days=OAUTH_DEFAULT_TOKEN_EXPIRATION_DAYS)

class OauthToken(BaseModel):
    token_id: UUID = Field(primary_key=True, default_factory=token_uid)
    token_type: str = Field(default='Bearer')
    code: OauthAuthorizationCode = Field()
    client_id: OAuthClient = Field()
    refresh_token: OauthRefreshToken = Field()
    access_token: str = Field()
    scope: str = Field()
    expires_at: datetime = Field(default_factory=token_expiration)
    issued_at: datetime = Field(default_factory=datetime.now)
