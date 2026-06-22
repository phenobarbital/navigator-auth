"""Oauth2 Provider.

Navigator as a Oauth2 Provider.

FEAT-093 changes (in task order):
  TASK-023 — Nested model field renamed client_id -> client throughout.
  TASK-024 — P0 Correctness:
      * user_id always comes from session['user'], never from client.user.
      * B1: expires_in is seconds (int).
      * B2: confidential clients verified with hmac.compare_digest.
      * B3: redirect_uri exact-match; render error, never redirect on mismatch.
      * B4: response_type validated (must be "code").
      * B5: auth codes single-use; used+deleted on exchange.
  TASK-025 — PKCE (S256): capture at authorize, verify at token.
  TASK-026 — Refresh rotation/reuse/absolute-expiry + offline_access gate.
  TASK-027 — OauthGrant + consent-skip + jti mint + /revoke + grants API.
  TASK-028 — userinfo / logout / finish_logout implemented (no stubs).
  TASK-029 — audience kwarg on create_token ('user'/'app').
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Any
from collections.abc import Awaitable
import hmac
import importlib
import secrets
from urllib.parse import urlencode, urlparse, urlunparse
from uuid import uuid4

from aiohttp import web
from datamodel.exceptions import ValidationError
from navconfig import config
import jsonpickle

from ...identities import AuthUser
from ...conf import (
    AUTH_LOGIN_FAILED_URI,
    AUTH_LOGOUT_REDIRECT_URI,
    AUTH_MISSING_ACCOUNT,
    AUTH_SUCCESSFUL_CALLBACKS,
    PREFERRED_AUTH_SCHEME,
    AUTH_EXCLUDE_LIST_KEY,
    REDIS_URL,
    OAUTH_ACCESS_TOKEN_TTL,
    OAUTH_REQUIRE_PKCE_PUBLIC,
    OAUTH_REFRESH_TOKEN_TTL,
    OAUTH_REFRESH_ABSOLUTE_TTL,
    OAUTH_REFRESH_ROTATION,
    OAUTH_SCOPES,
)
from navigator_session import get_session
from ...exceptions import (
    FailedAuth,
    UserNotFound,
    InvalidAuth,
)
from ...responses import JSONResponse
from ..abstract import BaseAuthBackend
from .models import (
    OauthUser,
    OauthRefreshToken,
    OauthGrant,
    OauthAccessTokenRecord,
)
from .client_backend import PostgresClientStorage, RedisClientStorage, MemoryClientStorage
from .code_backend import (
    AuthorizationCodeStorage,
    get_refresh_token_storage,
    get_grant_storage,
    get_access_token_storage,
)
from .pkce import verify as pkce_verify


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _now() -> datetime:
    return datetime.now()


class Oauth2Provider(BaseAuthBackend):
    """Oauth2Provider.

    Navigator-Auth as a Oauth2 provider.
    """

    user_attribute: str = "user"
    username_attribute: str = "username"
    pwd_atrribute: str = "password"
    user_mapping: dict = {}
    _ident: AuthUser = OauthUser
    _success_callbacks: Optional[list[str]] = AUTH_SUCCESSFUL_CALLBACKS
    _callbacks: Optional[list[Any]] = None

    def __init__(
        self,
        user_attribute: str = None,
        userid_attribute: str = None,
        password_attribute: str = None,
        **kwargs,
    ):
        super().__init__(user_attribute, userid_attribute, password_attribute, **kwargs)
        self.base_url: str = ""
        self.login_uri: str = "/oauth2/login"
        self.authorize_uri: str = "/oauth2/authorize"
        self.token_uri: str = "/oauth2/token"
        self.userinfo_uri: str = "/oauth2/userinfo"
        self.logout_uri: str = "/oauth2/logout"
        self.finish_logout_uri: str = "/oauth2/logout/complete"
        self.consent_uri: str = "/oauth2/consent"
        self.revoke_uri: str = "/oauth2/revoke"
        self.grants_uri: str = "/api/v1/oauth2/grants"
        self.login_failed_uri = AUTH_LOGIN_FAILED_URI
        self.logout_redirect_uri = AUTH_LOGOUT_REDIRECT_URI or "/oauth2/logout/complete"
        self.redirect_uri = None
        self.client_storage = None
        self.code_storage = None
        self.refresh_token_storage = None
        self.grant_storage = None
        self.access_token_storage = None

    def configure(self, app):
        router = app.router
        router.add_route(
            "*", self.authorize_uri, self.authorize, name="nav_oauth2_authorize"
        )
        router.add_route(
            "*", "/oauth2/authorize/", self.authorize, name="nav_oauth2_authorize_alt"
        )
        app[AUTH_EXCLUDE_LIST_KEY].append(self.authorize_uri)
        app[AUTH_EXCLUDE_LIST_KEY].append("/oauth2/authorize/")

        router.add_route(
            "*", self.login_uri, self.auth_login, name="nav_oauth2_login"
        )
        app[AUTH_EXCLUDE_LIST_KEY].append(self.login_uri)

        router.add_route(
            "*", self.consent_uri, self.consent, name="nav_oauth2_consent"
        )

        router.add_route(
            "*", self.token_uri, self.token_request, name="nav_oauth2_token_request"
        )
        app[AUTH_EXCLUDE_LIST_KEY].append(self.token_uri)

        router.add_route(
            "GET", self.userinfo_uri, self.userinfo, name="nav_oauth2_userinfo"
        )
        router.add_route(
            "GET", self.logout_uri, self.logout, name="nav_oauth2_api_logout"
        )
        router.add_route(
            "GET",
            self.logout_redirect_uri,
            self.finish_logout,
            name="nav_oauth2_complete_logout",
        )
        app[AUTH_EXCLUDE_LIST_KEY].append(self.logout_redirect_uri)

        # RFC 7009 revocation
        router.add_route(
            "POST", self.revoke_uri, self.revoke, name="nav_oauth2_revoke"
        )
        app[AUTH_EXCLUDE_LIST_KEY].append(self.revoke_uri)

        # Grants API
        router.add_route(
            "GET", self.grants_uri, self.list_grants, name="nav_oauth2_grants_list"
        )
        router.add_route(
            "DELETE",
            f"{self.grants_uri}/{{client_id}}",
            self.revoke_grant,
            name="nav_oauth2_grants_revoke",
        )

        super(Oauth2Provider, self).configure(app)

    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements."""
        if AUTH_MISSING_ACCOUNT == "create":
            self._user_model = self._idp.user_model
        else:
            self._user_model = None
        if self._success_callbacks:
            self.get_successful_callbacks()

        storage_type = config.get("OAUTH2_CLIENT_STORAGE", fallback="postgres")
        if storage_type == "redis":
            self.client_storage = RedisClientStorage(REDIS_URL)
        elif storage_type == "memory":
            self.client_storage = MemoryClientStorage()
        else:
            self.client_storage = PostgresClientStorage()

        self.code_storage = AuthorizationCodeStorage(REDIS_URL)
        self.refresh_token_storage = get_refresh_token_storage(storage_type, REDIS_URL)
        self.grant_storage = get_grant_storage(storage_type, REDIS_URL)
        self.access_token_storage = get_access_token_storage(storage_type, REDIS_URL)
        app["oauth2_access_token_storage"] = self.access_token_storage

    async def on_cleanup(self, app: web.Application):
        pass

    def get_successful_callbacks(self) -> list[Awaitable]:
        fns = []
        for fn in self._success_callbacks:
            try:
                pkg, module = fn.rsplit(".", 1)
                mod = importlib.import_module(pkg)
                obj = getattr(mod, module)
                fns.append(obj)
            except ImportError as e:
                raise RuntimeError(
                    f"Auth Callback: Error getting Callback Function: {fn}, {e!s}"
                ) from e
        self._callbacks = fns

    def get_domain(self, request: web.Request) -> str:
        uri = urlparse(str(request.url))
        domain_url = f"{PREFERRED_AUTH_SCHEME}://{uri.netloc}"
        return domain_url

    def prepare_url(self, url: str, params: dict = None) -> str:
        if not params:
            return url
        parsed = urlparse(url)
        query = urlencode(params)
        return urlunparse(parsed._replace(query=query))

    def redirect(self, uri: str, location: bool = False):
        self.logger.debug(f"Redirect URI: {uri}")
        if location is True:
            raise web.HTTPFound(location=uri)
        raise web.HTTPFound(uri)

    def _error_response(self, error: str, description: str, status: int = 400):
        """Return a JSON error response following RFC 6749."""
        return JSONResponse(
            {"error": error, "error_description": description},
            status=status,
        )

    async def get_payload(self, request):
        ctype = request.content_type
        if request.method == "POST":
            if ctype in (
                "multipart/mixed",
                "multipart/form-data",
                "application/x-www-form-urlencoded",
            ):
                data = await request.post()
            elif ctype == "application/json":
                try:
                    data = await request.json()
                except Exception:
                    self.logger.error("Oauth2: Error getting JSON data from request")
                    data = {}
            else:
                data = {}
        else:
            data = {key: val for (key, val) in request.query.items()}
        return data

    async def check_session(self, request):
        """Return the jsonpickle-encoded user string from the session, or None."""
        try:
            session = request.get("session")
            if not session:
                try:
                    session = await get_session(request, None, new=False, ignore_cookie=False)
                except Exception:
                    pass
            if session and "user" in session:
                return session["user"]
        except Exception as e:
            self.logger.warning(f"Error checking session: {e}")
        return None

    def _decode_session_user(self, encoded_user) -> Optional[OauthUser]:
        """Decode the jsonpickle-encoded user from session and extract user_id."""
        try:
            user_obj = jsonpickle.decode(encoded_user)
            if hasattr(user_obj, "user_id"):
                return user_obj
            # If it's a dict
            if isinstance(user_obj, dict) and "user_id" in user_obj:
                return OauthUser(
                    user_id=int(user_obj["user_id"]),
                    username=user_obj.get("username", ""),
                    given_name=user_obj.get("first_name", user_obj.get("given_name", "")),
                    family_name=user_obj.get("last_name", user_obj.get("family_name", "")),
                    email=user_obj.get("email"),
                )
        except Exception as e:
            self.logger.warning(f"Could not decode session user: {e}")
        return None

    async def validate_client(self, client_id, redirect_uri=None, request=None):
        """Fetch client by public uid; optionally validate redirect_uri (exact match)."""
        client = await self.client_storage.get_client(client_id, request=request)
        if not client:
            return None
        if redirect_uri:
            # B3: exact match against allow-list
            if redirect_uri not in client.redirect_uris:
                return None
        return client

    # ------------------------------------------------------------------
    # authorize
    # ------------------------------------------------------------------

    async def authorize(self, request: web.Request):
        """Start a Oauth2 Authorization Code Flow.

        B4: validates response_type == "code".
        """
        data = await self.get_payload(request)

        # B4: validate response_type
        response_type = data.get("response_type", "code")
        if response_type != "code":
            return self._error_response(
                "unsupported_response_type",
                f"response_type '{response_type}' is not supported; use 'code'.",
            )

        client_id = data.get("client_id")
        if not client_id:
            raise web.HTTPBadRequest(reason="Missing client_id")

        redirect_uri = data.get("redirect_uri")

        # B3: validate client and redirect_uri (exact match).
        # On mismatch, render an error page — never redirect.
        client = await self.client_storage.get_client(client_id, request=request)
        if not client:
            raise web.HTTPBadRequest(reason="Invalid client_id")
        if redirect_uri and redirect_uri not in client.redirect_uris:
            # B3: do NOT redirect — render error page.
            return self._error_response(
                "invalid_request",
                "redirect_uri does not match registered URIs.",
                status=400,
            )

        # Validate requested scope against client allow-list
        requested_scope = data.get("scope", "default")
        scopes = requested_scope.split()
        allowed = client.default_scopes if isinstance(client.default_scopes, list) else [client.default_scopes]
        invalid_scopes = [s for s in scopes if s not in allowed]
        if invalid_scopes and allowed:
            return self._error_response(
                "invalid_scope",
                f"Scope(s) not allowed: {', '.join(invalid_scopes)}",
            )

        # Validate requested scope against the global OAUTH_SCOPES registry.
        # When configured, granted scopes must be a subset of the known scopes.
        if OAUTH_SCOPES:
            unknown_scopes = [s for s in scopes if s not in OAUTH_SCOPES]
            if unknown_scopes:
                return self._error_response(
                    "invalid_scope",
                    f"Unknown scope(s): {', '.join(unknown_scopes)}",
                )

        # Check user session.
        session = await self.check_session(request)
        if not session:
            location = request.app.router["nav_oauth2_login"].url_for()
            payload = {"action_url": str(location), **data}
            url = location.with_query(**payload)
            self.redirect(url, location=True)

        # TASK-027: Consent-skip — if unrevoked grant exists for these scopes.
        prompt = data.get("prompt", "")
        if prompt != "consent" and self.grant_storage:
            user_obj = self._decode_session_user(session)
            if user_obj:
                existing_grant = await self.grant_storage.get_grant(
                    user_obj.user_id, client_id
                )
                if existing_grant and not existing_grant.revoked:
                    granted = set(existing_grant.scopes)
                    requested = set(scopes)
                    if requested.issubset(granted):
                        # Skip consent — issue code directly.
                        return await self._issue_code(
                            request, client, user_obj, redirect_uri,
                            requested_scope, data.get("state", ""),
                            data.get("code_challenge"),
                            data.get("code_challenge_method"),
                        )

        # Show Consent page.
        location = request.app.router["nav_oauth2_consent"].url_for()
        payload = {
            **data,
            "scope": requested_scope,
            "client_name": client.client_name,
        }
        url = location.with_query(**payload)
        self.redirect(url, location=True)

    async def _issue_code(
        self,
        request,
        client,
        user_obj: OauthUser,
        redirect_uri: str,
        scope: str,
        state: str,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
    ):
        """Issue an authorization code and redirect to the client."""
        from .models import OauthAuthorizationCode

        auth_code = secrets.token_urlsafe(32)
        code_obj = OauthAuthorizationCode(
            client=client,
            user_id=user_obj.user_id,
            code=auth_code,
            redirect_uri=redirect_uri or (client.redirect_uris[0] if client.redirect_uris else ""),
            scope=scope,
            state=state,
            response_type="code",
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        await self.code_storage.save_code(code_obj)
        payload = {"code": auth_code, "state": state}
        uri = self.prepare_url(code_obj.redirect_uri, params=payload)
        self.redirect(uri)

    # ------------------------------------------------------------------
    # consent
    # ------------------------------------------------------------------

    async def consent(self, request: web.Request):
        data = await self.get_payload(request)
        if request.method == "GET":
            return await self._parser.view(filename="oauth/consent.html", params=data)

        elif request.method == "POST":
            action = data.get("action")
            if action == "approve":
                client_id = data.get("client_id")
                redirect_uri = data.get("redirect_uri")
                scope = data.get("scope", "default")
                state = data.get("state", "")
                code_challenge = data.get("code_challenge")
                code_challenge_method = data.get("code_challenge_method")

                # Resolve authenticated user from session — NEVER from client.user.
                session_user = await self.check_session(request)
                if not session_user:
                    return self._error_response(
                        "access_denied", "User not authenticated.", status=401
                    )
                user_obj = self._decode_session_user(session_user)
                if not user_obj:
                    return self._error_response(
                        "access_denied", "Cannot resolve user from session.", status=401
                    )

                client = await self.client_storage.get_client(client_id, request=request)
                if not client:
                    return self._error_response("invalid_client", "Unknown client.", status=400)

                # TASK-027: upsert grant record.
                if self.grant_storage:
                    grant = OauthGrant(
                        user_id=user_obj.user_id,
                        client_id=client.client_id,
                        scopes=scope.split(),
                    )
                    await self.grant_storage.save_grant(grant)

                return await self._issue_code(
                    request, client, user_obj, redirect_uri, scope, state,
                    code_challenge, code_challenge_method
                )

            else:
                redirect_uri = data.get("redirect_uri")
                uri = self.prepare_url(redirect_uri, params={"error": "access_denied"})
                self.redirect(uri)

    # ------------------------------------------------------------------
    # auth_login
    # ------------------------------------------------------------------

    async def get_login_form(self, request: web.Request):
        ctype = request.content_type
        if request.method == "POST":
            if ctype in (
                "multipart/mixed",
                "multipart/form-data",
                "application/x-www-form-urlencoded",
            ):
                data = await request.post()
            elif ctype == "application/json":
                try:
                    data = await request.json()
                except Exception as err:
                    self.logger.error(f"Oauth2: Error getting JSON data: {err}")
                    data = {}
            else:
                data = {}
            username = data.get("username")
            password = data.get("password")
            if not username or not password:
                self.logger.error("Oauth2: Invalid username or password")
                raise self.auth_error(reason="Oauth2: Invalid username or password", status=400)
            return (username, password, data)
        else:
            raise self.auth_error(reason=f"Invalid HTTP Form Data: {request.method}", status=400)

    async def auth_login(self, request: web.Request):
        """Login page for OAuth2 resource owner authentication."""
        if request.method == "GET":
            data = {key: val for (key, val) in request.query.items()}
            return await self._parser.view(filename="oauth/login.html", params=data)
        elif request.method == "POST":
            username, password, data = await self.get_login_form(request)
            try:
                user = await self._idp.authenticate_credentials(login=username, password=password)
            except (FailedAuth, UserNotFound) as exc:
                raise web.HTTPBadRequest(reason=f"Auth: User not Found {exc}")
            except (ValidationError, InvalidAuth) as exc:
                raise web.HTTPBadRequest(reason=f"Auth: User Invalid {exc}")
            except Exception as exc:
                raise web.HTTPBadRequest(reason=f"Auth: Exception {exc}")

            redirect_uri = data.get("redirect_uri")
            client_id = data.get("client_id")
            state = data.get("state")
            scope = data.get("scope")

            location = request.app.router["nav_oauth2_authorize"].url_for()
            payload = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "scope": scope,
                "response_type": "code",
            }
            url = location.with_query(**payload)
            response = web.HTTPFound(url)

            try:
                auth_handler = request.app.get("auth")
                if auth_handler:
                    encoded_user = jsonpickle.encode(user)
                    session_data = {"user": encoded_user}
                    session = await auth_handler.session.storage.load_session(
                        request, session_data, response=response, new=True
                    )
                    if session:
                        session["user"] = encoded_user
            except Exception as e:
                self.logger.error(f"Error creating session: {e}")

            return response
        else:
            return self.auth_error(reason=f"Invalid HTTP Login Method: {request.method}", status=400)

    # ------------------------------------------------------------------
    # token_request
    # ------------------------------------------------------------------

    async def token_request(self, request):
        """Token endpoint (authorization_code / client_credentials / refresh_token)."""
        payload = await self.get_payload(request)
        grant_type = payload.get("grant_type")

        if grant_type == "authorization_code":
            return await self._handle_authorization_code(payload, request)
        elif grant_type == "client_credentials":
            return await self._handle_client_credentials(payload, request)
        elif grant_type == "refresh_token":
            return await self._handle_refresh_token(payload, request)
        else:
            return self._error_response(
                "unsupported_grant_type",
                f"grant_type '{grant_type}' is not supported.",
                status=400,
            )

    async def _handle_authorization_code(self, payload, request):
        """Handle authorization_code grant.

        B1: expires_in is int seconds.
        B2: confidential client verified with hmac.compare_digest.
        B3: redirect_uri exact-match (already checked at authorize; recheck here).
        B5: single-use code enforcement.
        TASK-025 PKCE: verify code_verifier.
        TASK-027: jti mint + AccessTokenRecord persist.
        """
        code = payload.get("code")
        if not code:
            return self._error_response("invalid_request", "Missing code.", status=400)

        redirect_uri = payload.get("redirect_uri")
        client_id = payload.get("client_id")

        # B5: fetch and validate code.
        auth_code = await self.code_storage.get_code(code)
        if not auth_code:
            return self._error_response("invalid_grant", "Invalid or expired authorization code.")

        # B5: reject if already used.
        if auth_code.used:
            # Delete the compromised code.
            await self.code_storage.delete_code(code)
            return self._error_response("invalid_grant", "Authorization code already used.")

        # B5: reject if expired.
        if _now() > auth_code.expires_at:
            await self.code_storage.delete_code(code)
            return self._error_response("invalid_grant", "Authorization code expired.")

        # Validate client_id matches what was stored.
        if auth_code.client.client_id != client_id:
            return self._error_response("invalid_client", "client_id mismatch.")

        # B3: exact-match redirect_uri.
        if redirect_uri and auth_code.redirect_uri != redirect_uri:
            return self._error_response(
                "invalid_grant", "redirect_uri does not match the authorization request."
            )

        # Fetch the live client.
        client = await self.client_storage.get_client(client_id, request=request)
        if not client:
            return self._error_response("invalid_client", "Unknown client.")

        # B2: for confidential clients, verify client_secret.
        if client.client_type != "public":
            client_secret = payload.get("client_secret", "")
            stored_secret = client.client_secret or ""
            if not hmac.compare_digest(stored_secret, client_secret):
                return self._error_response("invalid_client", "Invalid client_secret.")

        # TASK-025 PKCE: verify if a challenge was stored.
        if auth_code.code_challenge:
            code_verifier = payload.get("code_verifier", "")
            if not code_verifier:
                return self._error_response(
                    "invalid_grant", "code_verifier required."
                )
            method = auth_code.code_challenge_method or "S256"
            if not pkce_verify(code_verifier, auth_code.code_challenge, method):
                return self._error_response("invalid_grant", "PKCE verification failed.")
        elif client.client_type == "public" and OAUTH_REQUIRE_PKCE_PUBLIC:
            # Public client must have used PKCE — reject if no challenge stored.
            return self._error_response(
                "invalid_grant", "PKCE required for public clients."
            )

        # B5: mark code as used + delete from storage.
        await self.code_storage.mark_used(code)
        await self.code_storage.delete_code(code)

        # TASK-024: user_id comes from the auth code, never from client.user.
        user_id = auth_code.user_id
        scope = auth_code.scope

        # TASK-027: mint jti.
        jti = str(uuid4())

        token_data = {
            "user_id": user_id,
            "client_id": client.client_id,   # public uid in JWT claim
            "scope": scope,
            "jti": jti,
        }

        # TASK-029: audience = 'user' for 3LO tokens.
        access_token, _, exp_abs, scheme = self._idp.create_token(
            token_data,
            expiration=OAUTH_ACCESS_TOKEN_TTL,
            audience="user",
        )

        # B1: expires_in is seconds (not an absolute timestamp).
        now_utc = _now_utc()
        expires_in = int(exp_abs - now_utc.timestamp())

        # Save refresh token (only when offline_access granted).
        refresh_token_str = None
        scopes_list = scope.split()
        if "offline_access" in scopes_list:
            refresh_token_str = secrets.token_urlsafe(48)
            now = _now()
            sliding_ttl = timedelta(seconds=OAUTH_REFRESH_TOKEN_TTL)
            absolute_ttl = timedelta(seconds=OAUTH_REFRESH_ABSOLUTE_TTL)
            rt = OauthRefreshToken(
                client=client,
                user_id=user_id,
                refresh_token=refresh_token_str,
                scope=scope,
                issued_at=now,
                expires_at=now + sliding_ttl,
                absolute_expires_at=now + absolute_ttl,
            )
            await self.refresh_token_storage.save_token(rt)

        # TASK-027: persist access token jti.
        if self.access_token_storage:
            rec = OauthAccessTokenRecord(
                jti=jti,
                user_id=user_id,
                client_id=client.client_id,
                client_pk=client.client_pk,
                scope=scope,
                issued_at=_now(),
                expires_at=_now() + timedelta(seconds=OAUTH_ACCESS_TOKEN_TTL),
            )
            await self.access_token_storage.save(rec)

        response = {
            "access_token": access_token,
            "token_type": scheme,
            "expires_in": expires_in,
            "scope": scope,
        }
        if refresh_token_str:
            response["refresh_token"] = refresh_token_str

        return JSONResponse(response, status=200)

    async def _handle_client_credentials(self, payload, request):
        """Handle client_credentials grant (2LO).

        B2: client_secret verified via hmac.compare_digest.
        TASK-029: audience = 'app'.
        """
        client_id = payload.get("client_id")
        client_secret = payload.get("client_secret", "")

        client = await self.client_storage.get_client(client_id, request=request)
        if not client:
            return self._error_response("invalid_client", "Unknown client.")

        stored_secret = client.client_secret or ""
        if not hmac.compare_digest(stored_secret, client_secret):
            return self._error_response("invalid_client", "Invalid client_secret.")

        scope = payload.get("scope", " ".join(
            client.default_scopes if isinstance(client.default_scopes, list) else ["default"]
        ))

        jti = str(uuid4())
        token_data = {
            "client_id": client.client_id,
            "scope": scope,
            "jti": jti,
        }

        # TASK-029: audience = 'app' for 2LO tokens.
        access_token, _, exp_abs, scheme = self._idp.create_token(
            token_data,
            expiration=OAUTH_ACCESS_TOKEN_TTL,
            audience="app",
        )

        now_utc = _now_utc()
        expires_in = int(exp_abs - now_utc.timestamp())

        # TASK-027: persist jti record (user_id = None for machine-to-machine).
        if self.access_token_storage:
            rec = OauthAccessTokenRecord(
                jti=jti,
                user_id=None,
                client_id=client.client_id,
                client_pk=client.client_pk,
                scope=scope,
                issued_at=_now(),
                expires_at=_now() + timedelta(seconds=OAUTH_ACCESS_TOKEN_TTL),
            )
            await self.access_token_storage.save(rec)

        return JSONResponse(
            {"access_token": access_token, "token_type": scheme, "expires_in": expires_in, "scope": scope},
            status=200,
        )

    async def _handle_refresh_token(self, payload, request):
        """Handle refresh_token grant.

        TASK-024: user_id read from refresh token, not from client.user.
        TASK-026: rotation + reuse detection + absolute expiry + offline_access.
        """
        refresh_token = payload.get("refresh_token")
        client_id = payload.get("client_id")
        client_secret = payload.get("client_secret", "")

        if not refresh_token:
            return self._error_response("invalid_request", "Missing refresh_token.")

        client = await self.client_storage.get_client(client_id, request=request)
        if not client:
            return self._error_response("invalid_client", "Unknown client.")

        # B2: confidential client must verify secret.
        if client.client_type != "public":
            stored_secret = client.client_secret or ""
            if not hmac.compare_digest(stored_secret, client_secret):
                return self._error_response("invalid_client", "Invalid client_secret.")

        rt = await self.refresh_token_storage.get_token(refresh_token)
        if not rt:
            return self._error_response("invalid_grant", "Invalid refresh token.")

        if rt.client.client_id != client_id:
            return self._error_response("invalid_grant", "Token does not belong to this client.")

        # TASK-026: Reuse detection — if already rotated, revoke chain.
        if rt.revoked:
            if rt.revoked_reason == "rotated" and OAUTH_REFRESH_ROTATION:
                await self.refresh_token_storage.revoke_chain(refresh_token)
            return self._error_response("invalid_grant", "Refresh token has been revoked.")

        now = _now()

        # TASK-026: sliding expiry check.
        if rt.expires_at < now:
            return self._error_response("invalid_grant", "Refresh token expired.")

        # TASK-026: absolute expiry check.
        if rt.absolute_expires_at < now:
            await self.refresh_token_storage.revoke_token(refresh_token, "expired")
            return self._error_response("invalid_grant", "Refresh token absolute lifetime exceeded.")

        # TASK-024: user_id always from the refresh token.
        user_id = rt.user_id
        scope = payload.get("scope", rt.scope)
        # Scope narrowing only.
        if set(scope.split()) - set(rt.scope.split()):
            return self._error_response("invalid_scope", "Cannot widen scope during refresh.")

        jti = str(uuid4())
        token_data = {
            "user_id": user_id,
            "client_id": client.client_id,
            "scope": scope,
            "jti": jti,
        }

        # TASK-029: audience = 'user'.
        access_token, _, exp_abs, scheme = self._idp.create_token(
            token_data,
            expiration=OAUTH_ACCESS_TOKEN_TTL,
            audience="user",
        )
        now_utc = _now_utc()
        expires_in = int(exp_abs - now_utc.timestamp())

        # TASK-027: persist new jti.
        if self.access_token_storage:
            rec = OauthAccessTokenRecord(
                jti=jti,
                user_id=user_id,
                client_id=client.client_id,
                client_pk=client.client_pk,
                scope=scope,
                issued_at=now,
                expires_at=now + timedelta(seconds=OAUTH_ACCESS_TOKEN_TTL),
            )
            await self.access_token_storage.save(rec)

        response = {
            "access_token": access_token,
            "token_type": scheme,
            "expires_in": expires_in,
            "scope": scope,
        }

        # TASK-026: rotation.
        if OAUTH_REFRESH_ROTATION:
            new_refresh_token = secrets.token_urlsafe(48)
            sliding_ttl = timedelta(seconds=OAUTH_REFRESH_TOKEN_TTL)
            new_rt = OauthRefreshToken(
                client=client,
                user_id=user_id,
                refresh_token=new_refresh_token,
                scope=scope,
                parent_token=refresh_token,
                issued_at=now,
                expires_at=now + sliding_ttl,
                absolute_expires_at=rt.absolute_expires_at,   # copy from chain root
            )
            await self.refresh_token_storage.save_token(new_rt)
            # Mark old token as rotated.
            await self.refresh_token_storage.revoke_token(refresh_token, "rotated")
            response["refresh_token"] = new_refresh_token
        else:
            response["refresh_token"] = refresh_token

        return JSONResponse(response, status=200)

    # ------------------------------------------------------------------
    # userinfo (TASK-028)
    # ------------------------------------------------------------------

    async def userinfo(self, request):
        """Return scope-gated userinfo claims.

        Returns 401 on invalid/expired/revoked token.
        """
        # Extract bearer token.
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return self._error_response("invalid_token", "Bearer token required.", status=401)
        token = auth_header[7:]

        try:
            _, payload = self._idp.decode_token(token)
        except Exception:
            return self._error_response("invalid_token", "Invalid or expired token.", status=401)

        if not payload:
            return self._error_response("invalid_token", "Invalid token.", status=401)

        # TASK-027: check jti revocation.
        jti = payload.get("jti")
        if jti and self.access_token_storage:
            if await self.access_token_storage.is_revoked(jti):
                return self._error_response("invalid_token", "Token has been revoked.", status=401)

        scope = payload.get("scope", "")
        scopes = scope.split()
        user_id = payload.get("user_id", "")
        claims = {"sub": str(user_id)}

        # Look up the user record for profile claims not present in the JWT.
        # Profile attributes (name, email) are not embedded in the access token,
        # so we resolve them from the user storage backend.
        user = None
        if user_id and ("profile" in scopes or "email" in scopes):
            try:
                user = await self._idp.user_from_id(user_id)
            except Exception as e:  # noqa: BLE001
                self.logger.warning(f"userinfo: could not load user {user_id}: {e}")

        def _claim(name: str, default: str = "") -> str:
            # Prefer the JWT payload, then the user record attribute.
            if payload.get(name) not in (None, ""):
                return payload.get(name)
            if user is not None:
                val = getattr(user, name, None)
                if val not in (None, ""):
                    return val
            return default

        # Scope-gated claims.
        if "profile" in scopes:
            claims["username"] = str(_claim("username"))
            claims["given_name"] = str(_claim("given_name") or _claim("first_name"))
            claims["family_name"] = str(_claim("family_name") or _claim("last_name"))
        if "email" in scopes:
            claims["email"] = str(_claim("email"))

        return JSONResponse(claims, status=200)

    # ------------------------------------------------------------------
    # logout / finish_logout (TASK-028)
    # ------------------------------------------------------------------

    async def logout(self, request):
        """Tear down session and redirect to AUTH_LOGOUT_REDIRECT_URI."""
        try:
            session = await get_session(request, None, new=False)
            if session:
                await session.invalidate(request)
        except Exception as e:
            self.logger.warning(f"logout: could not invalidate session: {e}")
        raise web.HTTPFound(self.logout_redirect_uri)

    async def finish_logout(self, request):
        """Handle the OAuth2 post-logout redirect."""
        return web.Response(status=200, text="Logged out successfully.")

    # ------------------------------------------------------------------
    # revoke (TASK-027, RFC 7009)
    # ------------------------------------------------------------------

    async def revoke(self, request):
        """POST /oauth2/revoke — RFC 7009 revocation endpoint.

        Always returns 200 regardless of token validity.
        """
        payload = await self.get_payload(request)
        token = payload.get("token", "")
        hint = payload.get("token_type_hint", "")

        if token:
            # Try refresh token first if hint says so, or try both.
            if hint != "access_token":
                try:
                    await self.refresh_token_storage.revoke_chain(token)
                except Exception:
                    pass
            if hint != "refresh_token":
                if self.access_token_storage:
                    try:
                        _, payload_tok = self._idp.decode_token(token)
                        jti = payload_tok.get("jti") if payload_tok else None
                        if jti:
                            await self.access_token_storage.revoke(jti)
                    except Exception:
                        pass  # RFC 7009: always return 200

        return web.Response(status=200, text="")

    # ------------------------------------------------------------------
    # grants API (TASK-027)
    # ------------------------------------------------------------------

    async def list_grants(self, request):
        """GET /api/v1/oauth2/grants — list current user's authorized apps."""
        user_id = self._get_request_user_id(request)
        if not user_id:
            return self._error_response("unauthorized", "Not authenticated.", status=401)

        grants = await self.grant_storage.list_grants(user_id)
        return JSONResponse(
            [
                {
                    "client_id": g.client_id,
                    "scopes": g.scopes,
                    "granted_at": g.granted_at.isoformat(),
                    "revoked": g.revoked,
                }
                for g in grants
                if not g.revoked
            ],
            status=200,
        )

    async def revoke_grant(self, request):
        """DELETE /api/v1/oauth2/grants/{client_id} — revoke grant + cascade."""
        user_id = self._get_request_user_id(request)
        if not user_id:
            return self._error_response("unauthorized", "Not authenticated.", status=401)

        client_id = request.match_info.get("client_id")
        if not client_id:
            return self._error_response("invalid_request", "client_id required.", status=400)

        # Revoke the grant.
        if self.grant_storage:
            await self.grant_storage.revoke_grant(user_id, client_id)

        # Cascade: revoke all live refresh tokens for (user_id, client_id).
        if self.refresh_token_storage:
            tokens = await self.refresh_token_storage.list_tokens(user_id)
            for rt in tokens:
                if rt.client.client_id == client_id and not rt.revoked:
                    await self.refresh_token_storage.revoke_chain(rt.refresh_token)

        return web.Response(status=204)

    def _get_request_user_id(self, request) -> Optional[int]:
        """Extract user_id from the authenticated request."""
        try:
            userinfo = request.get("userinfo", {})
            if isinstance(userinfo, dict):
                uid = userinfo.get("user_id")
                if uid:
                    return int(uid)
        except Exception:
            pass
        return None

    async def check_credentials(self, request):
        """Authentication and create a session."""
        return True
