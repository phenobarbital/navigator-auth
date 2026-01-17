from typing import Optional
import json
import logging
from navigator_auth.libs.json import json_encoder, json_decoder
from ...conf import REDIS_URL
from .models import OauthAuthorizationCode

try:
    import redis.asyncio as redis
except ImportError:
    # Fallback to sync redis wrapped or error? 
    # The project seems to use redis-py, which has asyncio support since 4.2.0
    import redis

class AuthorizationCodeStorage:
    def __init__(self, dsn: str = None):
        if not dsn:
            dsn = REDIS_URL
        self.redis = redis.from_url(dsn, decode_responses=True)
        self.prefix = "oauth2:code:"

    async def save_code(self, code: OauthAuthorizationCode):
        key = f"{self.prefix}{code.code}"
        
        if not code.expires_at:
             return False
        
        # Calculate TTL
        # code.expires_at and code.created_at are datetime objects
        # We need to make sure they are aware or naive consistently.
        # Assuming Pydantic models return consistent datetime.
        
        # Simple TTL calculation:
        now = code.created_at
        if code.expires_at > now:
             remaining = code.expires_at - now
             ttl = int(remaining.total_seconds())
        else:
             ttl = 10 # Expired?

        data = code.model_dump_json()
        await self.redis.set(key, data, ex=ttl)
        return True

    async def get_code(self, code: str) -> Optional[OauthAuthorizationCode]:
        key = f"{self.prefix}{code}"
        data = await self.redis.get(key)
        if data:
            try:
                code_data = json.loads(data)
                return OauthAuthorizationCode(**code_data)
            except Exception as e:
                logging.error(f"Error decoding auth code from Redis: {e}")
                return None
        return None
    
    async def delete_code(self, code: str):
         key = f"{self.prefix}{code}"
         await self.redis.delete(key)


from .models import OauthRefreshToken

class RefreshTokenStorage:
    def __init__(self, dsn: str = None):
        if not dsn:
            dsn = REDIS_URL
        self.redis = redis.from_url(dsn, decode_responses=True)
        self.prefix = "oauth2:refresh:"

    async def save_token(self, token: OauthRefreshToken):
        key = f"{self.prefix}{token.refresh_token}"
        # Expiration in seconds
        # code.expires_at is datetime
        if not token.expires_at:
             return False
             
        now = token.issued_at # or datetime.now
        if token.expires_at > now:
             remaining = token.expires_at - now
             ttl = int(remaining.total_seconds())
        else:
             ttl = 10 
             
        data = token.model_dump_json()
        await self.redis.set(key, data, ex=ttl)
        return True
        
    async def get_token(self, refresh_token: str) -> Optional[OauthRefreshToken]:
        key = f"{self.prefix}{refresh_token}"
        data = await self.redis.get(key)
        if data:
            try:
                token_data = json.loads(data)
                return OauthRefreshToken(**token_data)
            except Exception as e:
                logging.error(f"Error decoding refresh token from Redis: {e}")
                return None
        return None

    async def delete_token(self, refresh_token: str):
         key = f"{self.prefix}{refresh_token}"
         await self.redis.delete(key)
