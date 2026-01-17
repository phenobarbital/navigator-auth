from abc import ABC, abstractmethod
from typing import Optional, Union
import json
import logging
from aiohttp import web
from .models import OAuthClient
from navigator_auth.models import Client as ClientModel  # The DB Model
from navigator_auth.libs.json import json_encoder, json_decoder

try:
    import redis.asyncio as redis
except ImportError:
    import redis

class ClientStorage(ABC):
    @abstractmethod
    async def get_client(self, client_id: str, request: Optional[web.Request] = None) -> Optional[OAuthClient]:
        pass

    @abstractmethod
    async def save_client(self, client: OAuthClient, request: Optional[web.Request] = None) -> bool:
        pass


class MemoryClientStorage(ClientStorage):
    def __init__(self):
        self._clients = {}

    async def get_client(self, client_id: str, request: Optional[web.Request] = None) -> Optional[OAuthClient]:
        return self._clients.get(client_id)

    async def save_client(self, client: OAuthClient, request: Optional[web.Request] = None) -> bool:
        self._clients[client.client_id] = client
        return True


class RedisClientStorage(ClientStorage):
    def __init__(self, dsn: str):
        self.redis = redis.from_url(dsn, decode_responses=True)

    async def get_client(self, client_id: str, request: Optional[web.Request] = None) -> Optional[OAuthClient]:
        key = f"oauth2:client:{client_id}"
        data = await self.redis.get(key)
        if data:
            try:
                client_data = json.loads(data)
                return OAuthClient(**client_data)
            except Exception as e:
                logging.error(f"Error decoding client data from Redis: {e}")
                return None
        return None

    async def save_client(self, client: OAuthClient, request: Optional[web.Request] = None) -> bool:
        key = f"oauth2:client:{client.client_id}"
        data = client.model_dump_json() # Pydantic v2
        await self.redis.set(key, data)
        return True


class PostgresClientStorage(ClientStorage):
    """Storage using the Client Model in Postgres (via asyncdb)."""
    
    async def get_client(self, client_id: str, request: Optional[web.Request] = None) -> Optional[OAuthClient]:
        db = None
        if request:
            db = request.app.get('authdb')
        
        if not db:
             # Fallback if no request or db in app (unit tests?)
             logging.warning("PostgresClientStorage: No DB connection found (request missing associated DB).")
             # Try without explicit connection (global pool rely?)
             # return await self._get_client_db(client_id)
             return None

        async with await db.acquire() as conn:
             ClientModel.Meta.connection = conn
             return await self._get_client_db(client_id)

    async def _get_client_db(self, client_id: str):
        try:
            # Note: client_id is int in DB now, but str in OAuthClient.
            try:
                cid = int(client_id)
            except ValueError:
                return None
                
            client_db = await ClientModel.get(client_id=cid)
            if client_db:
                data = client_db.to_dict()
                
                # Manual User Mapping if not present or just ID
                if 'user' not in data:
                    # check user_id
                    user_val = data.get('user_id')
                    if user_val:
                         # If it's an integer, we might need to fetch the User or mock OauthUser.
                         # Since OAuthClient expects OauthUser, lets construct it.
                         # CAUTION: We don't have full user info if we just have ID.
                         # But for Client Credentials flow, we mainly need the ID.
                         if isinstance(user_val, int):
                              # Mocking standard user details to satisfy Pydantic if we can't fetch.
                              # Ideally we should fetch User.
                              data['user'] = {
                                  "user_id": user_val,
                                  "username": f"user_{user_val}",
                                  "given_name": "Unknown",
                                  "family_name": "Unknown"
                              }
                         elif hasattr(user_val, 'to_dict'):
                              # it is a model
                              user_dict = user_val.to_dict()
                              data['user'] = {
                                  "user_id": user_dict.get('user_id'),
                                  "username": user_dict.get('username'),
                                  "given_name": user_dict.get('first_name', ''),
                                  "family_name": user_dict.get('last_name', ''),
                                  "email": user_dict.get('email')
                              }
                    else:
                         # No user attached?
                         pass
                
                # Cleanup nulls for fields that allow defaults in Pydantic
                keys_to_check = ['policy_uri', 'client_logo_uri', 'default_scopes', 'redirect_uris', 'allowed_grant_types']
                for k in keys_to_check:
                     if data.get(k) is None:
                          del data[k] # Let Pydantic use defaults

                return OAuthClient(**data)
        except Exception as e:
            logging.error(f"Error fetching client from DB: {e}")
            return None
        return None

    async def save_client(self, client: OAuthClient, request: Optional[web.Request] = None) -> bool:
        db = None
        if request:
            db = request.app.get('authdb')
        
        if db:
             async with await db.acquire() as conn:
                  ClientModel.Meta.connection = conn
                  return await self._save_client_db(client)
        else:
             return await self._save_client_db(client)

    async def _save_client_db(self, client: OAuthClient) -> bool:
        try:
            # Create a dictionary from the pydantic model
            data = client.model_dump()
            
            # Separate keys that match the model
            # user -> user_id
            
            user = data.pop('user', None)
            if user:
                 if isinstance(user, dict):
                      data['user_id'] = int(user.get('user_id'))
                 else:
                      data['user_id'] = user.user_id # Assuming object
            
            # Handle client_id
            if 'client_id' in data:
                 try:
                     data['client_id'] = int(data['client_id'])
                 except ValueError:
                     del data['client_id'] # Let DB assign or fail

            # Check if exists
            exists = False
            if 'client_id' in data:
                 try:
                      obj = await ClientModel.get(client_id=data['client_id'])
                      if obj:
                           exists = True
                 except Exception:
                      pass
                      
            if not exists:
                 c = ClientModel(**data)
                 await c.insert()
            else:
                 # Update?
                 pass

            return True
        except Exception as e:
            logging.error(f"Error saving Client to DB: {e}")
            return False
