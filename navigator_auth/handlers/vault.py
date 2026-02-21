import logging
from aiohttp import web
from aiohttp_cors import CorsViewMixin
from navigator_session import get_session
from navigator_auth.vault import VAULT_SESSION_KEY, load_vault_for_session
from navigator_auth.responses import JSONResponse
from navigator_auth.decorators import user_session

logger = logging.getLogger("navigator.vault")

@user_session()
class VaultView(web.View, CorsViewMixin):
    """
    HTTP Endpoint for interacting with the user's Session Vault.
    Requires user to be authenticated.
    """

    async def _get_vault(self, session):
        """Helper to get the vault from session, or load it on demand."""
        vault = session.get(VAULT_SESSION_KEY)
        if vault is not None:
            return vault

        # If not present, try to load it
        user_id = getattr(session, "user_id", None)
        if not user_id:
            raise web.HTTPUnauthorized(
                reason="User ID not found for vault access."
            )

        db_pool = self.request.app.get("authdb")
        redis = self.request.app.get("redis")
        if not db_pool:
            raise web.HTTPInternalServerError(
                reason="Database pool not configured."
            )

        try:
            vault = await load_vault_for_session(
                session, user_id=user_id, db_pool=db_pool, redis=redis
            )
            if vault:
                session[VAULT_SESSION_KEY] = vault
                return vault
        except Exception:
            logger.exception(
                "Failed to load vault dynamically"
            )
        
        raise web.HTTPInternalServerError(
            reason="Failed to load user vault."
        )

    async def _get_session_and_vault(self):
        """Ensure authenticated user and get their vault."""
        if not self.request.get("authenticated", False):
            raise web.HTTPUnauthorized(reason="Authentication required")

        session = await get_session(self.request, new=False)
        if not session:
            raise web.HTTPUnauthorized(reason="Valid session required")

        vault = await self._get_vault(session)
        return vault

    async def get(self):
        """
        GET /api/v1/user/vault : Returns list of stored keys.
        GET /api/v1/user/vault/{key} : Returns the decrypted value of 'key'.
        """
        vault = await self._get_session_and_vault()
        
        if key := self.request.match_info.get("key"):
            # Get specific key
            if not await vault.exists(key):
                raise web.HTTPNotFound(
                    reason=f"Secret '{key}' not found."
                )
            value = await vault.get(key)
            return JSONResponse({"key": key, "value": value})
        else:
            # List all keys
            keys = await vault.keys()
            return JSONResponse({"keys": keys})

    async def post(self):
        """
        POST /api/v1/user/vault
        Body: {"key": "name", "value": "secret"}
        """
        vault = await self._get_session_and_vault()
        
        try:
            data = await self.request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(reason=f"Invalid JSON Payload: {exc}") from exc

        key = data.get("key")
        value = data.get("value")
        
        if not key:
            raise web.HTTPBadRequest(
                reason="'key' is required"
            )
        if value is None:
            raise web.HTTPBadRequest(
                reason="'value' is required"
            )

        try:
            await vault.set(key, value)
            return JSONResponse(
                {
                    "message": f"Secret '{key}' saved successfully.", "key": key
                },
                status=201
            )
        except ValueError as e:
            raise web.HTTPBadRequest(reason=str(e))
        except Exception as e:
            logger.exception("Error saving vault secret")
            raise web.HTTPInternalServerError(
                reason="Error saving vault secret"
            ) from e

    async def delete(self):
        """
        DELETE /api/v1/user/vault/{key}
        Soft deletes the specified key.
        """
        vault = await self._get_session_and_vault()
        
        key = self.request.match_info.get("key")
        if not key:
             raise web.HTTPBadRequest(reason="Key parameter is required for deletion.")

        if not await vault.exists(key):
            raise web.HTTPNotFound(reason=f"Secret '{key}' not found.")

        try:
            await vault.delete(key)
            return JSONResponse({"message": f"Secret '{key}' deleted successfully.", "key": key}, status=200)
        except Exception as e:
            logger.exception(
                "Error deleting vault secret"
            )
            raise web.HTTPInternalServerError(
                reason="Error deleting vault secret"
            ) from e
