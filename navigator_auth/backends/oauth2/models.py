from datetime import datetime, timedelta
from uuid import UUID, uuid4
from datamodel import BaseModel, Field
# from asyncdb.models import Model, Field
from ...identities import AuthUser
from ...conf import (
    OAUTH_DEFAULT_TOKEN_EXPIRATION_DAYS
)

# Resource Owner:
class OauthUser(AuthUser):
    given_name: str
    family_name: str
    # Any other column required

    def __post_init__(self, data):
        super(OauthUser, self).__post_init__(data)
        self.first_name = self.given_name
        self.last_name = self.family_name


def default_expiration(*args, **kwargs):
    return datetime.now() + timedelta(days=365)

class OAuthClient(BaseModel):
    """OAuthClient.

    Application making requests to the OAuth2 Server on behalf of
    the Resource Owner.
    """
    client_id: str = Field()
    client_name: str = Field()
    client_secret: str = Field(
        required=False, default=None
    )
    # Consider adding a field to distinguish between public and confidential clients.
    client_type: str = Field()
    redirect_uris: list = Field()
    policy_uri: str = Field()
    client_logo_uri: str = Field()
    user: OauthUser = Field(required=True)
    default_scopes = Field(default='default')
    allowed_grant_types: list = Field()
    created_at: datetime = Field(
        default=datetime.now()
    )
    updated_at: datetime = Field(
        default=datetime.now()
    )
    expiration_date: datetime = Field(
        default=default_expiration
    )


def code_expiration(*args, **kwargs):
    return datetime.now() + timedelta(minutes=2)

class OauthAuthorizationCode(BaseModel):
    client_id: OAuthClient = Field(required=True)
    code: str = Field()
    nonce: str = Field()
    redirect_uri: str = Field()
    response_type: str = Field(default='code')
    scope: str = Field()
    state: str = Field()
    expires_at: datetime = Field(default=code_expiration)
    code_challenge: str = Field()
    code_challenge_method: str = Field()
    created_at: datetime = Field(default=datetime.now())
    used: bool = Field(default=False)
    used_at: datetime = Field(default=datetime.now())

class OauthRefreshToken(BaseModel):
    client_id: OAuthClient = Field(required=True)
    refresh_token: str = Field(required=True)
    scope: str = Field()
    expires_at: datetime = Field(default=default_expiration)
    issued_at: datetime = Field(default=datetime.now())
    revoked: bool = Field(default=False)
    revoked_at: datetime = Field()
    revoked_reason: str = Field()


def token_uid(*args, **kwargs):
    return uuid4()

def token_expiration(*args, **kwargs):
    return datetime.now() + timedelta(days=OAUTH_DEFAULT_TOKEN_EXPIRATION_DAYS)

class OauthToken(BaseModel):
    token_id: UUID = Field(primary_key=True, default=token_uid)
    token_type: str = Field(default='Bearer')
    code: OauthAuthorizationCode = Field(required=True)
    client_id: OAuthClient = Field(required=True)
    refresh_token: OauthRefreshToken = Field(required=True)
    access_token: str = Field()
    scope: str = Field()
    expires_at: datetime = Field(default=token_expiration)
    issued_at: datetime = Field(default=datetime.now())
