"""
Session Vault HTTP API (v2, FEAT-099).

Secret values never leave the server: every response carries metadata only
(``key``, ``updated_at``, ``key_version``). Values are written through ``POST``
and consumed server-side (agents, integrations).

Errors:
    - ``503 {"error": "vault_unavailable"}`` — the vault cannot be loaded.
    - ``409 {"error": "vault_integrity_error"}`` — the requested secret exists
      but its ciphertext fails integrity checks (tampered, moved, unknown key
      version, legacy format).
"""
import logging
from typing import Any

from aiohttp import web
from aiohttp_cors import CorsViewMixin
from navigator_session import get_session
from navigator_session.vault import VaultCryptoError, VaultSecretMetadata
from navigator_auth.vault import VAULT_SESSION_KEY, get_session_vault
from navigator_auth.responses import JSONResponse, json_error as _json_error
from navigator_auth.decorators import user_session

logger = logging.getLogger("navigator.vault")

VAULT_UNAVAILABLE = "vault_unavailable"
VAULT_INTEGRITY_ERROR = "vault_integrity_error"


def _metadata_dict(metadata: Any, key: str) -> dict:
    """JSON-safe metadata for a secret (never includes the value)."""
    if isinstance(metadata, VaultSecretMetadata):
        return metadata.model_dump(mode="json")
    return {"key": key, "updated_at": None, "key_version": None}


@user_session()
class VaultView(web.View, CorsViewMixin):
    """
    HTTP Endpoint for interacting with the user's Session Vault.
    Requires user to be authenticated.
    """

    async def _get_vault(self, session):
        """Helper to get the vault from session, or load it on demand."""
        # Extract user_id from the user object set by @user_session decorator
        user = getattr(self, "user", None)
        if isinstance(user, dict):
            user_id = user.get("user_id")
        else:
            user_id = getattr(user, "user_id", None)
        if not user_id and session.get(VAULT_SESSION_KEY) is None:
            _json_error(401, "User ID not found for vault access.")
        if not self.request.app.get("authdb") and session.get(VAULT_SESSION_KEY) is None:
            _json_error(503, VAULT_UNAVAILABLE)

        try:
            vault = await get_session_vault(
                self.request, session, user_id=user_id
            )
            if vault:
                return vault
        except Exception:
            logger.exception(
                "Failed to load vault dynamically"
            )

        _json_error(503, VAULT_UNAVAILABLE)

    async def _get_session_and_vault(self):
        """Ensure authenticated user and get their vault."""
        if not self.request.get("authenticated", False):
            _json_error(401, "Authentication required")

        session = await get_session(self.request, new=False)
        if not session:
            _json_error(401, "Valid session required")

        vault = await self._get_vault(session)
        return vault

    async def _metadata_for(self, vault, key: str) -> dict:
        for metadata in await vault.list_metadata():
            if getattr(metadata, "key", None) == key:
                return _metadata_dict(metadata, key)
        return _metadata_dict(None, key)

    async def get(self):
        """
        GET /api/v1/user/vault : ``{"secrets": [metadata, ...]}``.
        GET /api/v1/user/vault/{key} : metadata of ``key`` (never its value).
        """
        vault = await self._get_session_and_vault()

        if key := self.request.match_info.get("key"):
            if not await vault.exists(key):
                _json_error(404, f"Secret '{key}' not found.")
            try:
                # Verify the secret still opens; the value is discarded.
                await vault.get(key)
            except VaultCryptoError as err:
                logger.error(
                    "Vault secret integrity failure on read: key=%s error=%s",
                    key,
                    type(err).__name__,
                )
                _json_error(409, VAULT_INTEGRITY_ERROR)
            return JSONResponse(await self._metadata_for(vault, key))

        secrets = [_metadata_dict(metadata, getattr(metadata, "key", "")) for metadata in await vault.list_metadata()]
        return JSONResponse({"secrets": secrets})

    async def post(self):
        """
        POST /api/v1/user/vault
        Body: {"key": "name", "value": "secret"}
        Response 201: {"key", "updated_at", "key_version", "message"}
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
            metadata = await vault.set(key, value)
        except ValueError as e:
            _json_error(400, str(e))
        except Exception:
            logger.exception("Error saving vault secret")
            _json_error(500, "Error saving vault secret")
        body = _metadata_dict(metadata, key)
        body["message"] = f"Secret '{key}' saved successfully."
        return JSONResponse(body, status=201)

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
        except Exception:
            logger.exception(
                "Error deleting vault secret"
            )
            _json_error(500, "Error deleting vault secret")
