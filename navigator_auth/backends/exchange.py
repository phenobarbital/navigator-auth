"""TokenExchangeAuth.

FEAT-096: exchange an already-issued provider bearer token (Azure, Google,
GitHub) for a Navigator session "as if Basic" — no password, no browser
redirect. See sdd/specs/external-token-exchange.spec.md.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from aiohttp import web
from navigator_session import SESSION_TIMEOUT

from ..exceptions import AuthException, InvalidAuth, UserNotFound
from ..identity.store import IdentityStore
from ..identity.types import TokenResponse
from ..conf import TOKEN_EXCHANGE_MAX_TTL, TOKEN_EXCHANGE_PROVIDERS
from .basic import BasicAuth


@dataclass
class ExchangeRequest:
    """Validated POST /api/v1/login body for X-Auth-Method: TokenExchangeAuth."""

    provider: str
    token: str
    token_type: str = "Bearer"
    id_token: Optional[str] = None


class TokenExchangeAuth(BasicAuth):
    """TokenExchangeAuth.

    Verifies the provider token through the matching provider backend's
    ``verify_external_token``, resolves an **existing** ``auth.users`` row
    (never provisions one — D4), vaults the credential, and opens a Basic
    session (``BasicAuth.open_session``, TASK-046) capped at the external
    token's own lifetime (D2, D6).
    """

    _service_name: str = "token_exchange"
    _description: str = "Exchange an external provider bearer for a Basic session"
    _external_auth: bool = False

    def _resolve_provider_backend(self, request: web.Request, provider: str):
        """The loaded backend whose `_service_name` matches `provider`
        (e.g. 'azure' -> AzureAuth instance), or None when not loaded."""
        auth = request.app.get("auth")
        backends = getattr(auth, "backends", None) or {}
        for backend in backends.values():
            if getattr(backend, "_service_name", None) == provider:
                return backend
        return None

    def _identity_store(self, request: web.Request) -> IdentityStore:
        return IdentityStore(request.app["authdb"])

    async def get_payload(self, request: web.Request) -> ExchangeRequest:
        """JSON body only: `{"provider", "token", "token_type"?, "id_token"?}`.

        Missing `provider`/`token`, an unsupported `provider`, or a
        `provider` that isn't a loaded backend all raise
        `AuthException(status=400)` (distinct from a 401 "bad token").
        """
        if request.content_type != "application/json":
            raise AuthException(
                "TokenExchange: JSON body required", status=400
            )
        try:
            data = await request.json()
        except Exception as err:
            raise AuthException(
                f"TokenExchange: invalid JSON payload: {err}", status=400
            ) from err
        if not isinstance(data, dict):
            raise AuthException("TokenExchange: invalid JSON payload", status=400)
        provider = data.get("provider")
        token = data.get("token")
        if not provider or not token:
            raise AuthException(
                "TokenExchange: missing 'provider' or 'token'", status=400
            )
        if provider not in TOKEN_EXCHANGE_PROVIDERS:
            raise AuthException(
                f"TokenExchange: unsupported provider '{provider}'", status=400
            )
        if self._resolve_provider_backend(request, provider) is None:
            raise AuthException(
                f"TokenExchange: provider '{provider}' is not a loaded backend",
                status=400,
            )
        return ExchangeRequest(
            provider=provider,
            token=token,
            token_type=data.get("token_type") or "Bearer",
            id_token=data.get("id_token"),
        )

    def _verified_email(self, userinfo: dict) -> Optional[str]:
        """Belt-and-braces re-check (provider verifiers already enforce
        this for Google/GitHub). Only rejects when `email_verified` is
        *explicitly* present and falsy — Azure's Graph profile has neither
        key (AD accounts are enterprise-managed; its verifier doesn't gate
        on this), so it is trusted and its own e-mail field is used."""
        email = (
            userinfo.get("email")
            or userinfo.get("mail")
            or userinfo.get("userPrincipalName")
        )
        if "email_verified" in userinfo and not userinfo.get("email_verified"):
            return None
        return email

    def _cap_expiration(self, token: TokenResponse) -> int:
        """`min(SESSION_TIMEOUT, expires_at - now)` when the provider
        reports an expiry; else `TOKEN_EXCHANGE_MAX_TTL` (D2, D6)."""
        if token.expires_at is not None:
            expires_at = token.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            remaining = int((expires_at - datetime.now(timezone.utc)).total_seconds())
            return min(int(SESSION_TIMEOUT), remaining)
        return int(TOKEN_EXCHANGE_MAX_TTL)

    async def authenticate(self, request: web.Request) -> Any:
        """Verify -> resolve existing user -> vault -> open_session."""
        req = await self.get_payload(request)
        provider_backend = self._resolve_provider_backend(request, req.provider)
        # get_payload() already checked this, but backends are re-resolved
        # here rather than cached on `self` (process-wide singleton).
        if provider_backend is None:
            raise AuthException(
                f"TokenExchange: provider '{req.provider}' is not a loaded backend",
                status=400,
            )

        try:
            userinfo, ext = await provider_backend.verify_external_token(
                req.token, token_type=req.token_type, id_token=req.id_token
            )
        except NotImplementedError as err:
            raise AuthException(
                f"TokenExchange: provider '{req.provider}' does not support "
                "token exchange",
                status=400,
            ) from err
        except InvalidAuth as err:
            self.logger.warning(
                f"TokenExchange: provider={req.provider} verification failed: {err}"
            )
            raise InvalidAuth("Invalid Credentials") from err

        email = self._verified_email(userinfo)
        if not email:
            self.logger.warning(
                f"TokenExchange: provider={req.provider} reason=email_unverified"
            )
            raise InvalidAuth("Invalid Credentials")

        store = self._identity_store(request)
        user = None
        if ext.provider_user_id:
            user_id = await store.find_user_by_provider_account(
                req.provider, ext.provider_user_id
            )
            if user_id is not None:
                try:
                    user = await self._idp.user_from_id(user_id)
                except UserNotFound:
                    user = None
        if user is None:
            # Never create_external_user here, regardless of
            # AUTH_MISSING_ACCOUNT (D4) — this flow requires a pre-existing
            # auth.users row, matched by verified e-mail as a fallback to
            # the stable provider_user_id link above.
            try:
                user = await self._idp.get_user(email)
            except UserNotFound as err:
                self.logger.warning(
                    f"TokenExchange: provider={req.provider} reason=user_not_found "
                    f"email={email}"
                )
                raise UserNotFound("Invalid Credentials") from err

        uid = user[self.userid_attribute]

        # Best-effort vault write (D3, D7, D10) — a failure here must
        # never fail the login, only be logged.
        try:
            await store.save_linked_identity(uid, req.provider, ext, userinfo)
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(
                f"TokenExchange: vault write failed provider={req.provider} "
                f"user_id={uid}: {err}"
            )

        cap = self._cap_expiration(ext)
        if cap < 60:
            self.logger.warning(
                f"TokenExchange: provider={req.provider} user_id={uid} "
                f"reason=expired cap={cap}"
            )
            raise InvalidAuth("Invalid Credentials")

        extra = {
            "auth_method": "basic",
            "auth_origin": req.provider,
            "external_expires_at": (
                ext.expires_at.isoformat() if ext.expires_at else None
            ),
            "provider_user_id": ext.provider_user_id,
        }
        self.logger.info(
            f"TokenExchange: success provider={req.provider} user_id={uid} cap={cap}"
        )
        return await self.open_session(request, user, extra=extra, expiration=cap)
