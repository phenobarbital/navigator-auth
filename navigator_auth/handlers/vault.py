import logging
from aiohttp import web
from aiohttp_cors import CorsViewMixin
from navigator_session import get_session
from navigator_auth.vault import VAULT_SESSION_KEY, load_vault_for_session
from navigator_auth.responses import JSONResponse
from navigator_auth.decorators import user_session
from navigator_auth.libs.json import json_encoder

logger = logging.getLogger("navigator.vault")


def _json_error(status: int, message: str):
    """Raise an HTTP exception with a JSON body."""
    raise web.HTTPException(
        text=json_encoder({"error": message}),
        status=status,
        content_type="application/json",
    )


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

        # Extract user_id from the user object set by @user_session decorator
        user = getattr(self, "user", None)
        if isinstance(user, dict):
            user_id = user.get("user_id")
        else:
            user_id = getattr(user, "user_id", None)
        if not user_id:
            _json_error(401, "User ID not found for vault access.")

        db_pool = self.request.app.get("authdb")
        redis = self.request.app.get("redis")
        if not db_pool:
            _json_error(500, "Database pool not configured.")

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

        _json_error(500, "Failed to load user vault.")

    async def _get_session_and_vault(self):
        """Ensure authenticated user and get their vault."""
        if not self.request.get("authenticated", False):
            _json_error(401, "Authentication required")

        session = await get_session(self.request, new=False)
        if not session:
            _json_error(401, "Valid session required")

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
                _json_error(404, f"Secret '{key}' not found.")
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
            _json_error(400, f"Invalid JSON Payload: {exc}")

        key = data.get("key")
        value = data.get("value")

        if not key:
            _json_error(400, "'key' is required")
        if value is None:
            _json_error(400, "'value' is required")

        try:
            await vault.set(key, value)
            return JSONResponse(
                {
                    "message": f"Secret '{key}' saved successfully.", "key": key
                },
                status=201
            )
        except ValueError as e:
            _json_error(400, str(e))
        except Exception as e:
            logger.exception("Error saving vault secret")
            _json_error(500, "Error saving vault secret")

    async def delete(self):
        """
        DELETE /api/v1/user/vault/{key}
        Soft deletes the specified key.
        """
        vault = await self._get_session_and_vault()

        key = self.request.match_info.get("key")
        if not key:
            _json_error(400, "Key parameter is required for deletion.")

        if not await vault.exists(key):
            _json_error(404, f"Secret '{key}' not found.")

        try:
            await vault.delete(key)
            return JSONResponse({"message": f"Secret '{key}' deleted successfully.", "key": key}, status=200)
        except Exception as e:
            logger.exception(
                "Error deleting vault secret"
            )
            _json_error(500, "Error deleting vault secret")
