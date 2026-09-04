"""
Identity Vault HTTP API.

Endpoints for linking external provider credentials to the current
session user, managing them (list / retrieve / renew / delete) and
serving the decrypted credential to authorized consumers.

All endpoints operate strictly on the authenticated session user's own
identities. Access to other users' credentials (service accounts,
admin tooling) is out of scope here — compose it via the ABAC layer.
"""
from datetime import datetime, timezone

from aiohttp import web
from aiohttp_cors import CorsViewMixin
from navconfig.logging import logging
from navigator_session import get_session

from ..decorators import user_session
from ..exceptions import AuthException, ConfigError
from ..identity.crypto import IdentityCipher
from ..identity.store import (
    IdentityStore,
    cache_credential,
    cached_credential,
    invalidate_cached,
)
from ..identity.types import TokenResponse
from ..responses import JSONResponse, json_error as _json_error
from ..conf import IDENTITY_REFRESH_LEEWAY

logger = logging.getLogger("navigator.identity")




class BaseIdentityView(web.View, CorsViewMixin):
    """Shared helpers for the Identity Vault endpoints."""

    def _user_id(self):
        user = getattr(self, "user", None)
        if isinstance(user, dict):
            user_id = user.get("user_id")
        else:
            user_id = getattr(user, "user_id", None)
        if not user_id:
            session = getattr(self, "session", None)
            if session:
                try:
                    if "session" in session:
                        user_id = session["session"].get("user_id")
                    else:
                        user_id = session.get("user_id")
                except (TypeError, KeyError):
                    user_id = None
        if not user_id:
            _json_error(401, "User ID not found in session.")
        return user_id

    def _auth(self):
        auth = self.request.app.get("auth")
        if not auth:
            _json_error(500, "Auth system not configured.")
        return auth

    def _backend(self, provider: str):
        backend = self._auth().get_external_backend(provider)
        if not backend:
            _json_error(404, f"Unknown or disabled provider: {provider}")
        return backend

    def _store(self) -> IdentityStore:
        db_pool = self.request.app.get("authdb")
        if not db_pool:
            _json_error(500, "Database pool not configured.")
        try:
            return IdentityStore(db_pool, cipher=IdentityCipher())
        except ConfigError as err:
            _json_error(501, str(err))

    async def _session(self):
        try:
            return await get_session(self.request, new=False)
        except Exception:  # pylint: disable=W0703
            return None


@user_session()
class UserIdentitiesHandler(BaseIdentityView):
    """
    /api/v1/user/identities            GET: list linked identities (masked)
    /api/v1/user/identities/{id}       GET: one identity (masked)
                                       PUT: renew via the refresh token
                                       DELETE: remove the identity
    """

    async def get(self):
        user_id = self._user_id()
        store = self._store()
        if identity_id := self.request.match_info.get("identity_id"):
            identity = await store.get_one(user_id, identity_id)
            if not identity:
                _json_error(404, f"Identity {identity_id} not found.")
            return JSONResponse(store.masked(identity))
        identities = await store.list_for_user(user_id)
        return JSONResponse({"identities": identities})

    async def put(self):
        """Renew the stored credential using its refresh token."""
        user_id = self._user_id()
        identity_id = self.request.match_info.get("identity_id")
        if not identity_id:
            _json_error(400, "Identity ID is required.")
        store = self._store()
        identity = await store.get_one(user_id, identity_id)
        if not identity:
            _json_error(404, f"Identity {identity_id} not found.")
        current = store.decrypt_credential(identity)
        if not current.refresh_token:
            _json_error(
                409,
                f"{identity.auth_provider}: no refresh token stored; "
                "re-link the identity instead.",
            )
        backend = self._backend(identity.auth_provider)
        try:
            token = await backend.refresh_identity_tokens(
                current.refresh_token
            )
        except AuthException as err:
            _json_error(502, f"Provider refresh failed: {err}")
        identity = await store.update_tokens(identity, token)
        session = await self._session()
        if session:
            await cache_credential(
                session, identity.auth_provider, token.credential()
            )
        return JSONResponse(store.masked(identity))

    async def delete(self):
        user_id = self._user_id()
        identity_id = self.request.match_info.get("identity_id")
        if not identity_id:
            _json_error(400, "Identity ID is required.")
        store = self._store()
        identity = await store.get_one(user_id, identity_id)
        if not identity:
            _json_error(404, f"Identity {identity_id} not found.")
        provider = identity.auth_provider
        await store.delete(user_id, identity_id)
        session = await self._session()
        if session:
            await invalidate_cached(session, provider)
        return JSONResponse(
            {"message": f"Identity {identity_id} deleted.", "provider": provider}
        )


@user_session()
class IdentityCredentialHandler(BaseIdentityView):
    """
    /api/v1/user/identities/{provider}/credential
    GET: serve the decrypted credential for a provider, auto-refreshing
    when it is expired/expiring. Session Vault caching avoids the
    database round-trip on repeated calls.
    """

    async def get(self):
        user_id = self._user_id()
        provider = self.request.match_info.get("provider")
        session = await self._session()
        # 1) session-vault cache
        if session:
            cached = await cached_credential(session, provider)
            if cached:
                token = TokenResponse.from_credential(cached)
                if not token.is_expiring(leeway=IDENTITY_REFRESH_LEEWAY):
                    return JSONResponse(cached)
        # 2) database (source of truth)
        store = self._store()
        identity = await store.get_by_provider(user_id, provider)
        if not identity:
            _json_error(404, f"No linked identity for provider: {provider}")
        token = store.decrypt_credential(identity)
        # 3) auto-refresh when expiring
        if token.is_expiring(leeway=IDENTITY_REFRESH_LEEWAY):
            if not token.refresh_token:
                _json_error(
                    409,
                    f"{provider}: credential expired and no refresh token "
                    "stored; re-link the identity.",
                )
            backend = self._backend(provider)
            try:
                token = await backend.refresh_identity_tokens(
                    token.refresh_token
                )
            except AuthException as err:
                _json_error(502, f"Provider refresh failed: {err}")
            identity = await store.update_tokens(identity, token)
        credential = token.credential()
        if session:
            await cache_credential(session, provider, credential)
        return JSONResponse(credential)


@user_session()
class IdentityLinkHandler(BaseIdentityView):
    """
    /api/v1/user/identities/link/{provider}
    GET: start the identity-link authorization flow (302 to provider).
    """

    async def get(self):
        user_id = self._user_id()
        provider = self.request.match_info.get("provider")
        backend = self._backend(provider)
        finish_redirect = self.request.query.get(
            "redirect_uri", "/api/v1/user/identities/manage"
        )
        # ensure crypto is configured before sending the user away:
        try:
            IdentityCipher()
        except ConfigError as err:
            _json_error(501, str(err))
        return await backend.authorize_identity(
            self.request, user_id, finish_redirect
        )


@user_session()
class IdentitiesManageView(BaseIdentityView):
    """
    /api/v1/user/identities/manage
    GET: HTML page for managing the identities vault.
    """

    async def get(self):
        user_id = self._user_id()
        auth = self._auth()
        providers = [
            {
                "service": backend._service_name,
                "description": getattr(backend, "_description", ""),
            }
            for backend in auth.external_backends()
        ]
        store = self._store()
        identities = await store.list_for_user(user_id)
        parser = getattr(auth, "_parser", None)
        if not parser:
            _json_error(500, "Template parser not configured.")
        return await parser.view(
            "identity/manage.html",
            params={
                "providers": providers,
                "identities": identities,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
        )
