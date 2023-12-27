from datetime import datetime
from asyncdb.models import Model, Field


class OAuth2Client(Model):
    client_id: str = Field()
    client_name: str = Field()
    client_secret: str = Field()
    client_type: str = Field()  # Consider adding a field to distinguish between public and confidential clients.
    redirect_uris: list = Field()
    policy_uri: str = Field()
    client_logo_uri: str = Field()
    default_scopes = Field()
    allowed_grant_types: list = Field()
    user_id: int
    created_at: datetime = Field(default=datetime.now())
    updated_at: datetime = Field(default=datetime.now())

class Oauth2AuthorizationCode(Model):
    client_id: OAuth2Client = Field()
    code: str = Field()
    nonce: str = Field()
    redirect_uri: str = Field()
    response_type: str = Field()
    scope: str = Field()
    state: str = Field()
    user_id: str = Field()
    user_consent: str = Field()
    expires_at: datetime = Field(default=datetime.now())
    code_challenge: str = Field()
    code_challenge_method: str = Field()
    created_at: datetime = Field(default=datetime.now())
    used: bool = Field(default=False)
    used_at: datetime = Field(default=datetime.now())

class Oauth2RefreshToken(Model):
    client_id: OAuth2Client = Field()
    refresh_token: str = Field()
    scope: str = Field()
    expires_at: datetime = Field(default=datetime.now())
    user_id: int = Field()
    issued_at: datetime = Field(default=datetime.now())
    revoked: bool = Field(default=False)
    revoked_at: datetime = Field(default=datetime.now())
    revoked_reason: str = Field()


class Oauth2AccessToken(Model):
    token_id: int = Field(primary_key=True)
    token_type: str = Field(default='Bearer')
    code: Oauth2AuthorizationCode = Field()
    client_id: Oauth2AuthorizationCode = Field()
    refresh_token: Oauth2RefreshToken = Field()
    access_token: str = Field()
    scope: str = Field()
    expires_at: datetime = Field(default=datetime.now())
    user_id: int = Field()
    issued_at: datetime = Field(default=datetime.now())
    revoked: bool = Field(default=False)
    revoked_at: datetime = Field(default=datetime.now())
    revoked_reason: str = Field()
