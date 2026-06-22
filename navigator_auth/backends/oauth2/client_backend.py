"""OAuth2 client storage backends.

FEAT-093 TASK-023:
  - OAuthClient.client_id is now the PUBLIC opaque uid (str).
  - OAuthClient.client_pk carries the internal integer surrogate PK.
  - PostgresClientStorage looks up by client_uid column (DROP the int() cast).
  - Memory/Redis storages already key by string — they store by client_uid.
"""

from abc import ABC, abstractmethod
from typing import Optional
import json
import logging
import secrets
from aiohttp import web
from .models import OAuthClient
from navigator_auth.models import Client as ClientModel

try:
    import redis.asyncio as redis
except ImportError:
    import redis


class ClientStorage(ABC):
    @abstractmethod
    async def get_client(
        self, client_id: str, request: Optional[web.Request] = None
    ) -> Optional[OAuthClient]:
        """Retrieve a client by its PUBLIC client_uid (str)."""
        pass

    @abstractmethod
    async def save_client(
        self, client: OAuthClient, request: Optional[web.Request] = None
    ) -> bool:
        pass


class MemoryClientStorage(ClientStorage):
    """In-memory client store, keyed by client_uid (str)."""

    def __init__(self):
        # Keys are public client_uid strings.
        self._clients: dict = {}

    async def get_client(
        self, client_id: str, request: Optional[web.Request] = None
    ) -> Optional[OAuthClient]:
        return self._clients.get(client_id)

    async def save_client(
        self, client: OAuthClient, request: Optional[web.Request] = None
    ) -> bool:
        # Store by public uid.
        self._clients[client.client_id] = client
        return True


class RedisClientStorage(ClientStorage):
    """Redis-backed client store, keyed by client_uid (str)."""

    def __init__(self, dsn: str):
        self.redis = redis.from_url(dsn, decode_responses=True)

    async def get_client(
        self, client_id: str, request: Optional[web.Request] = None
    ) -> Optional[OAuthClient]:
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

    async def save_client(
        self, client: OAuthClient, request: Optional[web.Request] = None
    ) -> bool:
        key = f"oauth2:client:{client.client_id}"
        data = client.model_dump_json()
        await self.redis.set(key, data)
        return True


class PostgresClientStorage(ClientStorage):
    """Storage using the Client Model in Postgres (via asyncdb).

    TASK-023: Looks up by auth.clients.client_uid (NOT the int PK).
    Maps DB row: client_uid -> OAuthClient.client_id,
                 client_id  -> OAuthClient.client_pk.
    """

    async def get_client(
        self, client_id: str, request: Optional[web.Request] = None
    ) -> Optional[OAuthClient]:
        db = None
        if request:
            db = request.app.get("authdb")

        if not db:
            logging.warning(
                "PostgresClientStorage: No DB connection found."
            )
            return None

        async with await db.acquire() as conn:
            ClientModel.Meta.connection = conn
            return await self._get_client_db(client_id)

    async def _get_client_db(self, client_uid: str) -> Optional[OAuthClient]:
        """Fetch client by the PUBLIC client_uid column (no int cast)."""
        try:
            # Look up by the opaque public identifier (str column).
            client_db = await ClientModel.get(client_uid=client_uid)
            if client_db:
                data = client_db.to_dict()

                # Map DB columns to OAuthClient fields:
                #   DB client_id (int PK)  -> client_pk
                #   DB client_uid (str)    -> client_id
                db_pk = data.pop("client_id", None)     # integer PK
                db_uid = data.pop("client_uid", None)   # opaque string
                data["client_pk"] = db_pk
                data["client_id"] = db_uid or client_uid

                # Build OauthUser if user_id is present.
                if "user" not in data:
                    user_val = data.get("user_id")
                    if user_val:
                        if isinstance(user_val, int):
                            data["user"] = {
                                "user_id": user_val,
                                "username": f"user_{user_val}",
                                "given_name": "Unknown",
                                "family_name": "Unknown",
                            }
                        elif hasattr(user_val, "to_dict"):
                            user_dict = user_val.to_dict()
                            data["user"] = {
                                "user_id": user_dict.get("user_id"),
                                "username": user_dict.get("username"),
                                "given_name": user_dict.get("first_name", ""),
                                "family_name": user_dict.get("last_name", ""),
                                "email": user_dict.get("email"),
                            }

                # Drop None values for fields that have Pydantic defaults.
                for k in [
                    "policy_uri", "client_logo_uri", "default_scopes",
                    "redirect_uris", "allowed_grant_types",
                ]:
                    if data.get(k) is None:
                        data.pop(k, None)

                return OAuthClient(**data)
        except Exception as e:
            logging.error(f"Error fetching client from DB: {e}")
            return None
        return None

    async def save_client(
        self, client: OAuthClient, request: Optional[web.Request] = None
    ) -> bool:
        db = None
        if request:
            db = request.app.get("authdb")

        if db:
            async with await db.acquire() as conn:
                ClientModel.Meta.connection = conn
                return await self._save_client_db(client)
        else:
            return await self._save_client_db(client)

    async def _save_client_db(self, client: OAuthClient) -> bool:
        try:
            data = client.model_dump()

            # Separate OauthUser -> user_id FK.
            user = data.pop("user", None)
            if user:
                if isinstance(user, dict):
                    data["user_id"] = int(user.get("user_id"))
                else:
                    data["user_id"] = user.user_id

            # Map OAuthClient.client_id (public uid) -> client_uid column.
            # Map OAuthClient.client_pk (int PK)     -> client_id column (if set).
            public_uid = data.pop("client_id", None)     # str uid
            int_pk = data.pop("client_pk", None)         # int PK

            if public_uid:
                data["client_uid"] = public_uid

            if int_pk:
                data["client_id"] = int(int_pk)

            # Generate a uid if not provided.
            if not data.get("client_uid"):
                data["client_uid"] = secrets.token_urlsafe(18)

            # Check existence by uid if we have one.
            exists = False
            if data.get("client_uid"):
                try:
                    obj = await ClientModel.get(client_uid=data["client_uid"])
                    if obj:
                        exists = True
                except Exception:
                    pass

            # Fallback: check by int PK.
            if not exists and data.get("client_id"):
                try:
                    obj = await ClientModel.get(client_id=data["client_id"])
                    if obj:
                        exists = True
                except Exception:
                    pass

            if not exists:
                c = ClientModel(**data)
                await c.insert()

            return True
        except Exception as e:
            logging.error(f"Error saving Client to DB: {e}")
            return False
