"""OAuth2 per-client access gate — management API.

FEAT-095 TASK-042 (decisions D3 + D7).

    GET    /api/v1/oauth2/clients/{client_uid}/access   list rows (any status)
    GET    ...?status=pending                           the approval queue
    POST   /api/v1/oauth2/clients/{client_uid}/access   grant / approve / reject
    DELETE /api/v1/oauth2/clients/{client_uid}/access   revoke (+ cascade)

Administrative surface: every endpoint requires an authenticated **superuser**
session.  It sits behind the normal auth middleware, so ABAC policies apply on
top in the usual way.

Revocation deliberately goes through ``Oauth2Provider.cascade_access_revocation``
rather than touching token storage here: withdrawing access must also kill the
consent grant, the refresh-token chain and the live ``jti``s for that pair.
"""

from aiohttp import web
from aiohttp_cors import CorsViewMixin
from navconfig.logging import logging
from navigator_session import get_session

from ..decorators import user_session
from ..libs.json import json_encoder
from ..responses import JSONResponse

logger = logging.getLogger("navigator.oauth2.access")


def _json_error(status: int, message: str):
    """Raise an HTTP exception with a JSON body."""
    exc_class = type(
        "JSONHTTPError", (web.HTTPException,), {"status_code": status}
    )
    raise exc_class(
        text=json_encoder({"error": message}),
        content_type="application/json",
    )


def _serialize(access) -> dict:
    """Render a ClientAccess row for the API (no internal PKs leak)."""
    user_id = access.user_id
    if not isinstance(user_id, int):
        user_id = getattr(user_id, "user_id", user_id)
    return {
        "user_id": user_id,
        "client_uid": access.client_uid,
        "status": access.status,
        "granted_by": access.granted_by,
        "granted_at": (
            access.granted_at.isoformat() if access.granted_at else None
        ),
        "revoked_at": (
            access.revoked_at.isoformat() if access.revoked_at else None
        ),
    }


@user_session()
class ClientAccessHandler(web.View, CorsViewMixin):
    """Admin-only management of the OAuth2 per-client access gate."""

    # --- helpers ---------------------------------------------------

    def _require_superuser(self) -> int:
        """Return the acting admin's user_id, or refuse the request."""
        user = getattr(self, "user", None)
        if user is None:
            _json_error(401, "Authentication required.")
        if isinstance(user, dict):
            is_superuser = user.get("superuser") or user.get("is_superuser")
            user_id = user.get("user_id")
        else:
            is_superuser = getattr(user, "superuser", None)
            if is_superuser is None:
                is_superuser = getattr(user, "is_superuser", False)
            user_id = getattr(user, "user_id", None)
        if not is_superuser:
            _json_error(
                403, "Managing client access requires superuser privileges."
            )
        return user_id

    def _storage(self):
        storage = self.request.app.get("oauth2_client_access_storage")
        if storage is None:
            _json_error(503, "The OAuth2 access gate is not configured.")
        return storage

    def _provider(self):
        """The Oauth2Provider, used for the revocation cascade."""
        auth = self.request.app.get("auth")
        if auth is None:
            return None
        for backend in getattr(auth, "backends", {}).values():
            if backend.__class__.__name__ == "Oauth2Provider":
                return backend
        return None

    def _client_uid(self) -> str:
        client_uid = self.request.match_info.get("client_uid")
        if not client_uid:
            _json_error(400, "client_uid is required.")
        return client_uid

    async def _body(self) -> dict:
        try:
            data = await self.request.json()
        except Exception:
            _json_error(400, "A JSON body is required.")
        if not isinstance(data, dict):
            _json_error(400, "The request body must be a JSON object.")
        return data

    @staticmethod
    def _target_user(data: dict) -> int:
        user_id = data.get("user_id")
        if user_id is None:
            _json_error(400, "user_id is required.")
        try:
            return int(user_id)
        except (TypeError, ValueError):
            _json_error(400, "user_id must be an integer.")

    # --- endpoints -------------------------------------------------

    async def get(self):
        """List access rows for a client; ``?status=`` filters."""
        self._require_superuser()
        client_uid = self._client_uid()
        storage = self._storage()

        status = self.request.query.get("status")
        if status == "pending":
            rows = await storage.list_pending(client_uid, request=self.request)
        else:
            rows = await storage.list_for_client(client_uid, request=self.request)
            if status:
                rows = [r for r in rows if r.status == status]

        return JSONResponse(
            {
                "client_uid": client_uid,
                "count": len(rows),
                "access": [_serialize(r) for r in rows],
            }
        )

    async def post(self):
        """Grant, approve or reject access for a user.

        Body: ``{"user_id": 42, "action": "grant"|"approve"|"reject"}``.
        ``action`` defaults to ``grant`` (direct activation, D7's other half).
        """
        granted_by = self._require_superuser()
        client_uid = self._client_uid()
        storage = self._storage()
        data = await self._body()
        user_id = self._target_user(data)
        action = (data.get("action") or "grant").lower()

        if action in ("grant", "approve"):
            if action == "approve":
                row = await storage.approve(
                    user_id, client_uid, granted_by, request=self.request
                )
                if row is None:
                    _json_error(
                        404,
                        f"No pending access request for user {user_id} "
                        f"on client {client_uid}.",
                    )
            else:
                row = await storage.grant(
                    user_id, client_uid, granted_by, request=self.request
                )
                if row is None:
                    _json_error(500, "Could not grant access.")
            logger.info(
                f"OAuth2 gate: user {user_id} activated on {client_uid} "
                f"by {granted_by}"
            )
            return JSONResponse(_serialize(row), status=200)

        if action == "reject":
            rejected = await storage.reject(
                user_id, client_uid, request=self.request
            )
            if not rejected:
                _json_error(
                    404,
                    f"No pending access request for user {user_id} "
                    f"on client {client_uid}.",
                )
            # A rejected user holds nothing, but cascade anyway: the request
            # may have been queued after a previously active period.
            await self._cascade(user_id, client_uid)
            return JSONResponse(
                {"user_id": user_id, "client_uid": client_uid, "status": "revoked"}
            )

        _json_error(
            400, f"Unknown action '{action}'; use grant, approve or reject."
        )

    async def delete(self):
        """Revoke access and cascade token revocation."""
        self._require_superuser()
        client_uid = self._client_uid()
        storage = self._storage()

        user_id = self.request.query.get("user_id")
        if user_id is None:
            data = await self._body()
            user_id = self._target_user(data)
        else:
            try:
                user_id = int(user_id)
            except (TypeError, ValueError):
                _json_error(400, "user_id must be an integer.")

        revoked = await storage.revoke(user_id, client_uid, request=self.request)
        if not revoked:
            _json_error(
                404,
                f"No access record for user {user_id} on client {client_uid}.",
            )

        cascade = await self._cascade(user_id, client_uid)
        logger.info(f"OAuth2 gate: revoked user {user_id} on {client_uid}")
        return JSONResponse(
            {
                "user_id": user_id,
                "client_uid": client_uid,
                "status": "revoked",
                "cascade": cascade,
            }
        )

    async def _cascade(self, user_id: int, client_uid: str) -> dict:
        """Revoke grants, refresh chains and live jtis for the pair."""
        provider = self._provider()
        if provider is None:
            logger.warning(
                "OAuth2 gate: no Oauth2Provider available; "
                "tokens were not cascaded."
            )
            return {}
        try:
            return await provider.cascade_access_revocation(
                user_id, client_uid, request=self.request
            )
        except Exception as e:  # pylint: disable=W0703
            logger.error(f"OAuth2 gate: cascade failed: {e}")
            return {}
