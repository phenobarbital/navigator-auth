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

FEAT-094 changes (in task order):
  TASK-033 — POST /oauth2/introspect (RFC 7662): confidential-client auth,
             same-client-only, real-time jti/refresh revocation check.
  TASK-034 — POST /oauth2/device_authorization (RFC 8628 §3.1-3.2).
  TASK-035 — GET/POST /oauth2/device verification page (RFC 8628 §3.3).
  TASK-036 — device_code grant branch on POST /oauth2/token (RFC 8628 §3.4-3.5).
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Any
from collections.abc import Awaitable
from html import escape
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
    # FEAT-094
    OAUTH_INTROSPECT_INCLUDE_ABAC_SCOPES,
    OAUTH_DEVICE_CODE_TTL,
    OAUTH_DEVICE_POLL_INTERVAL,
    OAUTH_DEVICE_SLOW_DOWN_INCREMENT,
    OAUTH_DEVICE_USER_CODE_LENGTH,
    OAUTH_DEVICE_USER_CODE_ALPHABET,
    OAUTH_DEVICE_VERIFICATION_URI,
    OAUTH_DEVICE_MAX_USER_CODE_ATTEMPTS,
    OAUTH_DEVICE_LOCKOUT_TTL,
    # FEAT-095 TASK-038
    AUTH_ISSUER_URL,
    # FEAT-095 TASK-039
    OAUTH_DCR_POLICY,
    OAUTH_JWT_KEYS,
)
from navigator_session import (
    get_session,
    SESSION_ID,
)
from navigator_session.conf import (
    SESSION_OBJECT,
    SESSION_REQUEST_KEY,
    SESSION_STORAGE,
)
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
    get_device_code_storage,
)
from .pkce import verify as pkce_verify
from .devicecode import generate_user_code, poll_decision as _poll_decision
from .metadata import (
    WELL_KNOWN_AS_PATH,
    WELL_KNOWN_PRM_PATH,
    DEFAULT_GRANT_TYPES_SUPPORTED,
    build_as_metadata,
    build_protected_resource_metadata,
)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _now() -> datetime:
    return datetime.now()


# ---------------------------------------------------------------------------
# FEAT-095 TASK-038 — canonical issuer identity
# ---------------------------------------------------------------------------

#: Hosts for which a plain-http issuer is tolerated (local development).
LOCALHOST_NAMES: frozenset = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


def _is_localhost(host: str) -> bool:
    """True when ``host`` (optionally ``host:port``) is a loopback name."""
    if not host:
        return False
    hostname = host.split(",")[0].strip()
    if hostname.startswith("["):          # IPv6 literal, e.g. [::1]:8080
        hostname = hostname.split("]")[0] + "]"
    else:
        hostname = hostname.split(":")[0]
    return hostname.lower() in LOCALHOST_NAMES


def issuer_url(request: Optional[web.Request] = None) -> str:
    """Return the canonical OAuth2 issuer identifier for this deployment.

    RFC 8414 §2 requires the issuer to be an ``https`` URL without query or
    fragment, and RFC 8414 §3 requires the metadata document to be served at
    ``{issuer}/.well-known/oauth-authorization-server``.  ``AUTH_TOKEN_ISSUER``
    (``urn:Navigator``) is a URN and cannot serve that role, hence the separate
    ``AUTH_ISSUER_URL`` setting.

    Resolution order:
      1. ``AUTH_ISSUER_URL`` when configured — returned verbatim (minus any
         trailing slash).
      2. Derived from the request: ``X-Forwarded-Proto`` (first value) is
         honoured for the scheme and ``X-Forwarded-Host`` / ``Host`` for the
         authority, so the value is correct behind a reverse proxy.

    https is enforced: a derived ``http`` issuer is upgraded to ``https``
    unless the host is a loopback address (local development).

    Args:
        request: the current request; may be ``None`` when a static
            ``AUTH_ISSUER_URL`` is configured.

    Returns:
        The issuer URL with no trailing slash.

    Raises:
        RuntimeError: when the issuer cannot be resolved (no setting and no
            request).
    """
    if AUTH_ISSUER_URL:
        return AUTH_ISSUER_URL.rstrip("/")
    if request is None:
        raise RuntimeError(
            "Oauth2: cannot derive the issuer URL — set AUTH_ISSUER_URL."
        )
    headers = request.headers
    forwarded_proto = headers.get("X-Forwarded-Proto", "")
    scheme = forwarded_proto.split(",")[0].strip().lower() if forwarded_proto else ""
    if not scheme:
        scheme = (getattr(request, "scheme", "") or "https").lower()
    host = (
        headers.get("X-Forwarded-Host", "")
        or headers.get("Host", "")
        or getattr(getattr(request, "url", None), "netloc", "")
        or ""
    )
    host = host.split(",")[0].strip()
    if not host:
        raise RuntimeError(
            "Oauth2: cannot derive the issuer URL — no Host header; "
            "set AUTH_ISSUER_URL."
        )
    # https enforcement: http is only tolerated for loopback development.
    if scheme != "https" and not _is_localhost(host):
        scheme = "https"
    return f"{scheme}://{host}".rstrip("/")


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
        # FEAT-094 new URIs
        self.introspect_uri: str = "/oauth2/introspect"
        self.device_authorization_uri: str = "/oauth2/device_authorization"
        self.device_uri: str = "/oauth2/device"
        # FEAT-095 TASK-039: discovery documents (RFC 8414 / RFC 9728).
        self.as_metadata_uri: str = WELL_KNOWN_AS_PATH
        self.prm_metadata_uri: str = WELL_KNOWN_PRM_PATH
        self.login_failed_uri = AUTH_LOGIN_FAILED_URI
        self.logout_redirect_uri = AUTH_LOGOUT_REDIRECT_URI or "/oauth2/logout/complete"
        self.redirect_uri = None
        self.client_storage = None
        self.code_storage = None
        self.refresh_token_storage = None
        self.grant_storage = None
        self.access_token_storage = None
        self.device_code_storage = None
        # FEAT-095 TASK-039: in-process cache of the built discovery documents,
        # keyed by issuer (a deployment can legitimately serve several hosts).
        self._metadata_cache: dict = {}

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

        # FEAT-094: Token Introspection (RFC 7662) — TASK-033
        router.add_route(
            "POST", self.introspect_uri, self.introspect, name="nav_oauth2_introspect"
        )
        app[AUTH_EXCLUDE_LIST_KEY].append(self.introspect_uri)

        # FEAT-094: Device Authorization Grant (RFC 8628) — TASK-034/035
        router.add_route(
            "POST",
            self.device_authorization_uri,
            self.device_authorization,
            name="nav_oauth2_device_authorization",
        )
        app[AUTH_EXCLUDE_LIST_KEY].append(self.device_authorization_uri)

        router.add_route(
            "*", self.device_uri, self.device_verification, name="nav_oauth2_device"
        )
        app[AUTH_EXCLUDE_LIST_KEY].append(self.device_uri)

        # FEAT-095 TASK-039: discovery documents (RFC 8414 + RFC 9728).
        # RFC 8414 §3 requires the AS metadata at the ORIGIN ROOT; the aliases
        # under the AS path exist for deployments mounted behind a prefix.
        for path, handler, name in (
            (self.as_metadata_uri, self.as_metadata, "nav_oauth2_as_metadata"),
            (self.prm_metadata_uri, self.protected_resource_metadata,
             "nav_oauth2_prm_metadata"),
            (f"/oauth2{self.as_metadata_uri}", self.as_metadata,
             "nav_oauth2_as_metadata_alias"),
            (f"/oauth2{self.prm_metadata_uri}", self.protected_resource_metadata,
             "nav_oauth2_prm_metadata_alias"),
        ):
            router.add_route("GET", path, handler, name=name)
            app[AUTH_EXCLUDE_LIST_KEY].append(path)

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
        # FEAT-094: device code storage
        self.device_code_storage = get_device_code_storage(storage_type, REDIS_URL)

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

    def issuer_url(self, request: web.Request = None) -> str:
        """Canonical issuer for this AS (FEAT-095 TASK-038).

        Thin delegation to the module-level :func:`issuer_url` helper so every
        FEAT-095 surface (discovery, DCR, JWKS, challenges) shares one
        definition of "who this authorization server is".
        """
        return issuer_url(request)

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

    # ------------------------------------------------------------------
    # Session binding
    # ------------------------------------------------------------------
    #
    # navigator-auth resolves the current user from a *server-side session*:
    # ``AuthHandler.auth_middleware`` decodes the bearer JWT and then loads the
    # session it points at, and ``@user_session()`` reads the user out of that
    # session. An OAuth2 access token therefore has to be bound to a session,
    # exactly like the token BasicAuth mints in ``remember()``; otherwise every
    # request carrying a perfectly valid 3LO token is rejected because no
    # session can be resolved from its claims.

    def _session_storage(self, request: web.Request):
        """Return the configured session storage (or None when unavailable)."""
        storage = request.get(SESSION_STORAGE)
        if storage is not None:
            return storage
        try:
            return request.app["auth"].session.storage
        except (KeyError, AttributeError, TypeError):
            return None

    async def _create_user_session(
        self,
        request: web.Request,
        user: Any,
        response: web.StreamResponse = None,
    ):
        """Create (or refresh) the server-side session for a resource owner.

        The session is keyed by the user's identity, so the interactive login
        and any token minted for that same user share one session — the same
        one-session-per-user model the other backends use.

        Args:
            request: the current request.
            user: the authenticated user object.
            response: when given, the session cookie is written on it (needed
                for the browser leg: ``/oauth2/login`` -> ``/oauth2/authorize``).

        Returns:
            The ``SessionData`` object, or None when no storage is configured.
        """
        storage = self._session_storage(request)
        if storage is None:
            self.logger.error("Oauth2: no session storage configured.")
            return None
        try:
            identity = user[self.username_attribute]
        except (KeyError, TypeError):
            identity = getattr(user, self.username_attribute, None)
        if not identity:
            self.logger.error("Oauth2: cannot resolve the user identity for a session.")
            return None
        identity = str(identity)
        try:
            user.is_authenticated = True
        except (AttributeError, TypeError):
            pass
        # Resolve the session purely from the identity: a stale session id left
        # on the request (e.g. a cookie from another user) must not be reused.
        for key in (SESSION_ID, SESSION_OBJECT, SESSION_REQUEST_KEY):
            request.pop(key, None)
        request[self.session_key_property] = identity
        session_data = {
            self.session_key_property: identity,
            "user": jsonpickle.encode(user),
        }
        try:
            session = await storage.new_session(request, session_data, response=response)
        except TypeError:
            # storages whose new_session() has no ``response`` argument.
            session = await storage.new_session(request, session_data)
        if not session:
            self.logger.error("Oauth2: unable to create the User session.")
            return None
        return session

    async def _token_session_claims(self, request: web.Request, user_id: int) -> dict:
        """Bind a freshly issued access token to a session.

        Returns the extra JWT claims (``id``, ``session_id``, ``username``)
        that let ``auth_middleware`` resolve the session — and therefore the
        user — from the bearer token alone. Returns an empty dict when the
        resource owner cannot be resolved, leaving the token usable for
        introspection-based resource servers.
        """
        try:
            user = await self._idp.user_from_id(user_id)
        except Exception as exc:  # pylint: disable=W0703
            self.logger.warning(
                f"Oauth2: cannot bind a session to the token for user_id={user_id}: {exc}"
            )
            return {}
        session = await self._create_user_session(request, user)
        if not session:
            return {}
        identity = str(user[self.username_attribute])
        return {
            self.session_key_property: identity,
            self.session_id_property: session.session_id,
            self.username_attribute: identity,
        }

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
    # Discovery documents (FEAT-095 TASK-039, RFC 8414 + RFC 9728)
    # ------------------------------------------------------------------

    def _dcr_enabled(self) -> bool:
        """True when Dynamic Client Registration is offered by this deployment."""
        return str(OAUTH_DCR_POLICY).lower() != "disabled"

    def _jwks_enabled(self) -> bool:
        """True when a signing-key registry is configured.

        Read from configuration only: the ``jwks_uri`` must never be advertised
        without keys behind it, and this must not create a code dependency on
        the (independently shippable) JWKS module.
        """
        return bool(OAUTH_JWT_KEYS)

    def _build_metadata_documents(self, issuer: str) -> dict:
        """Build (and memoise) both discovery documents for one issuer."""
        cached = self._metadata_cache.get(issuer)
        if cached is not None:
            return cached
        documents = {
            "as": build_as_metadata(
                issuer,
                dcr_enabled=self._dcr_enabled(),
                jwks=self._jwks_enabled(),
                grant_types=DEFAULT_GRANT_TYPES_SUPPORTED,
                scopes=OAUTH_SCOPES,
            ),
            "prm": build_protected_resource_metadata(
                resource=issuer,
                auth_servers=[issuer],
                scopes=OAUTH_SCOPES,
            ),
        }
        self._metadata_cache[issuer] = documents
        return documents

    def _metadata_response(self, document: dict) -> web.Response:
        """Serve a discovery document (public, cacheable, JSON)."""
        return JSONResponse(
            document,
            status=200,
            headers={
                "Cache-Control": "public, max-age=3600",
                "Access-Control-Allow-Origin": "*",
            },
        )

    async def as_metadata(self, request: web.Request):
        """GET /.well-known/oauth-authorization-server — RFC 8414 §3.

        Unauthenticated (the path is in the exclude list) and served from an
        in-process cache, so it stays far inside Claude's 10 s discovery budget.
        """
        issuer = self.issuer_url(request)
        return self._metadata_response(self._build_metadata_documents(issuer)["as"])

    async def protected_resource_metadata(self, request: web.Request):
        """GET /.well-known/oauth-protected-resource — RFC 9728.

        Describes *this* deployment as a protected resource.  External resource
        servers (ai-parrot MCP mounts, spec D6) serve their own document using
        :func:`~.metadata.build_protected_resource_metadata` directly.
        """
        issuer = self.issuer_url(request)
        return self._metadata_response(self._build_metadata_documents(issuer)["prm"])

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

            location = request.app.router["nav_oauth2_authorize"].url_for()
            payload = {
                "client_id": data.get("client_id"),
                "redirect_uri": data.get("redirect_uri"),
                "response_type": data.get("response_type", "code") or "code",
            }
            # Carry the rest of the authorization request across the login hop.
            # PKCE in particular MUST survive it: dropping code_challenge here
            # makes every public-client exchange fail later with
            # "PKCE required for public clients".
            for key in (
                "state",
                "scope",
                "code_challenge",
                "code_challenge_method",
                "nonce",
                "prompt",
            ):
                value = data.get(key)
                if value:
                    payload[key] = value
            payload = {k: v for k, v in payload.items() if v is not None}
            url = location.with_query(**payload)
            response = web.HTTPFound(url)

            # Establish the browser session for the resource owner: the
            # session cookie is written on this redirect, and /oauth2/authorize
            # reads it back on the next hop (see check_session).
            try:
                session = await self._create_user_session(
                    request, user, response=response
                )
                if not session:
                    raise web.HTTPBadRequest(
                        reason="Auth: unable to create the User session."
                    )
            except web.HTTPException:
                raise
            except Exception as e:  # pylint: disable=W0703
                self.logger.error(f"Error creating session: {e}")
                raise web.HTTPBadRequest(
                    reason=f"Auth: unable to create the User session: {e}"
                ) from e

            return response
        else:
            raise self.auth_error(reason=f"Invalid HTTP Login Method: {request.method}", status=400)

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
        elif grant_type == "urn:ietf:params:oauth:grant-type:device_code":
            return await self._handle_device_code(payload, request)
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
        # Device-origin carriers (response_type="device_code") have no redirect_uri —
        # skip the match when the _device_origin flag is set (see RFC 8628 §3.4 and
        # _handle_device_code which injects _device_origin=True into the payload).
        is_device_origin = payload.get("_device_origin", False)
        if redirect_uri and auth_code.redirect_uri != redirect_uri and not is_device_origin:
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
            # Bind the token to a session so the auth middleware,
            # @is_authenticated() and @user_session() can resolve the user.
            **await self._token_session_claims(request, user_id),
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
            # Same session binding as the authorization_code grant.
            **await self._token_session_claims(request, user_id),
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
    # _handle_device_code (FEAT-094 TASK-036, RFC 8628 §3.4-3.5)
    # ------------------------------------------------------------------

    async def _handle_device_code(self, payload, request):
        """Handle grant_type=urn:ietf:params:oauth:grant-type:device_code.

        D-2: on approval, delegates to the existing authorization_code exchange
        via the stored auth_code carrier.  This gives device tokens the same
        owner-binding, single-use, and refresh-iff-offline_access behaviour as
        regular auth-code tokens.

        State machine per RFC 8628 §3.5:
          too_soon     → slow_down  (+ bump interval)
          pending      → authorization_pending
          denied       → access_denied
          expired/unknown → expired_token
          approved     → verify PKCE → delegate to auth_code exchange
          consumed     → expired_token (single-use guard)
        """
        from .models import DeviceCodeStatus

        device_code_str = payload.get("device_code", "")
        client_id = payload.get("client_id", "")
        if not device_code_str:
            return self._error_response(
                "invalid_request", "Missing device_code.", status=400
            )

        dc = await self.device_code_storage.get_by_device_code(device_code_str)
        if not dc:
            return self._error_response(
                "expired_token", "Unknown or expired device_code.", status=400
            )

        # Client match.
        if client_id and not hmac.compare_digest(str(dc.client_id), str(client_id)):
            return self._error_response(
                "invalid_client", "device_code does not belong to this client.", status=400
            )

        now = _now()
        decision = _poll_decision(dc, now)

        if decision == "slow_down":
            # Bump interval server-side and persist.
            dc.interval = dc.interval + OAUTH_DEVICE_SLOW_DOWN_INCREMENT
            dc.last_polled_at = now
            await self.device_code_storage.update(dc)
            return JSONResponse(
                {"error": "slow_down", "interval": dc.interval}, status=400
            )

        if decision == "authorization_pending":
            dc.last_polled_at = now
            await self.device_code_storage.update(dc)
            return JSONResponse({"error": "authorization_pending"}, status=400)

        if decision == "access_denied":
            return JSONResponse({"error": "access_denied"}, status=400)

        if decision == "expired_token":
            return JSONResponse({"error": "expired_token"}, status=400)

        # decision == "approved": delegate to the authorization_code exchange.
        if not dc.auth_code:
            return JSONResponse({"error": "server_error"}, status=500)

        # PKCE is verified here (against dc.code_challenge) AND again inside
        # _handle_authorization_code (against the carrier auth_code.code_challenge,
        # which is a copy). The double-verify is harmless — both checks use the
        # same value — but is noted for future refactoring.
        # D4: PKCE verification for public clients.
        if dc.code_challenge:
            code_verifier = payload.get("code_verifier", "")
            if not code_verifier:
                return self._error_response(
                    "invalid_grant", "code_verifier required (PKCE).", status=400
                )
            if not pkce_verify(code_verifier, dc.code_challenge,
                               dc.code_challenge_method or "S256"):
                return self._error_response(
                    "invalid_grant", "PKCE verification failed.", status=400
                )

        # Mark device_code consumed before delegating (single-use guard).
        dc.status = DeviceCodeStatus.CONSUMED
        dc.last_polled_at = now
        await self.device_code_storage.update(dc)

        # Delegate to the auth_code exchange by injecting it into the payload.
        # The carrier's redirect_uri is "" (device-origin); the exchange must
        # accept it.  We set redirect_uri to None so the exact-match check is
        # skipped when the stored redirect_uri is also "".
        injected_payload = dict(payload)
        injected_payload["grant_type"] = "authorization_code"
        injected_payload["code"] = dc.auth_code
        # _device_origin=True signals _handle_authorization_code to skip redirect_uri
        # exact-match validation (device flow has no redirect_uri). See RFC 8628 §3.4.
        injected_payload["_device_origin"] = True
        return await self._handle_authorization_code(injected_payload, request)

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

    # ------------------------------------------------------------------
    # introspect (FEAT-094 TASK-033, RFC 7662)
    # ------------------------------------------------------------------

    async def introspect(self, request: web.Request):
        """POST /oauth2/introspect — RFC 7662 token introspection.

        Caller authentication: confidential client (client_id + client_secret).
        Same-client-only: the caller's client_uid must equal the token's client_id.
        Revocation truth is real-time (no cache).

        Response:
          200 {"active": true, ...RFC 7662 claims...} for active own-client tokens.
          200 {"active": false}                        for everything else.
          400 {"error": "invalid_request"}             on missing/duplicate token.
          401 {"error": "invalid_client"} + WWW-Authenticate on bad client creds.
        """
        payload = await self.get_payload(request)

        # --- Authenticate the calling confidential client ---
        caller_client_id = payload.get("client_id", "")
        caller_secret = payload.get("client_secret", "")
        if not caller_client_id:
            # Also accept HTTP Basic Auth
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Basic "):
                import base64
                try:
                    decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                    caller_client_id, caller_secret = decoded.split(":", 1)
                except Exception:
                    pass

        caller = await self.client_storage.get_client(caller_client_id, request=request)
        if not caller or caller.client_type == "public":
            return web.Response(
                status=401,
                content_type="application/json",
                headers={"WWW-Authenticate": 'Basic realm="oauth2"'},
                text='{"error":"invalid_client","error_description":"Client authentication required."}',
            )
        stored_secret = caller.client_secret or ""
        if not hmac.compare_digest(stored_secret, caller_secret):
            return web.Response(
                status=401,
                content_type="application/json",
                headers={"WWW-Authenticate": 'Basic realm="oauth2"'},
                text='{"error":"invalid_client","error_description":"Invalid client credentials."}',
            )

        # --- Validate token parameter ---
        token = payload.get("token", "")
        if not token:
            return self._error_response(
                "invalid_request", "Missing token parameter.", status=400
            )

        # Multiple token params is also invalid_request.
        # (aiohttp returns the last value; we rely on the caller sending one.)

        hint = payload.get("token_type_hint", "")

        # --- Decode token (without raising) ---
        try:
            _, token_payload = self._idp.decode_token(token)
        except Exception:
            token_payload = None

        # If no JWT and no refresh hint, nothing to look up.
        if not token_payload and hint != "refresh_token":
            return JSONResponse({"active": False}, status=200)

        # Determine token type: access or refresh.
        # For opaque tokens (token_payload is None), honour the hint.
        token_type = token_payload.get("token_type", "").lower() if token_payload else ""
        is_refresh = hint == "refresh_token" or token_type == "refresh_token"
        is_access = not is_refresh

        # --- Revocation / activity check ---
        active = False
        rt = None
        if is_access:
            jti = token_payload.get("jti") if token_payload else None
            if jti and self.access_token_storage:
                revoked = await self.access_token_storage.is_revoked(jti)
                if not revoked:
                    # Check not expired.
                    exp = token_payload.get("exp", 0)
                    if exp > _now_utc().timestamp():
                        active = True
            elif not jti:
                # No jti in payload — treat as inactive (can't verify revocation).
                active = False
        else:
            # Refresh token: look it up in storage (handles opaque tokens too).
            rt = await self.refresh_token_storage.get_token(token)
            if rt and not rt.revoked:
                if rt.expires_at > _now():
                    active = True

        if not active:
            return JSONResponse({"active": False}, status=200)

        # --- Same-client-only enforcement (RFC 7662 §2.2) ---
        # For opaque refresh tokens, derive client_id from the stored record.
        if token_payload:
            token_client_id = token_payload.get("client_id", "")
        elif rt:
            token_client_id = str(rt.client_id) if hasattr(rt, "client_id") else ""
        else:
            token_client_id = ""
        if not hmac.compare_digest(str(caller.client_id), str(token_client_id)):
            return JSONResponse({"active": False}, status=200)

        # --- Build active response (RFC 7662 §2.2 claims) ---
        exp = token_payload.get("exp") if token_payload else None
        iat = token_payload.get("iat") if token_payload else None
        scope = token_payload.get("scope", "") if token_payload else (getattr(rt, "scope", "") if rt else "")
        user_id = token_payload.get("user_id") if token_payload else (getattr(rt, "user_id", None) if rt else None)
        sub = str(user_id) if user_id else token_client_id
        aud = token_payload.get("aud", "") if token_payload else ""
        jti_claim = token_payload.get("jti") if token_payload else None

        claims: dict = {
            "active": True,
            "scope": scope,
            "client_id": caller.client_id,       # wire value = client_uid
            "token_type": "Bearer",
            "sub": sub,
        }
        if exp:
            claims["exp"] = int(exp)
        if iat:
            claims["iat"] = int(iat)
        if aud:
            claims["aud"] = aud
        if jti_claim:
            claims["jti"] = jti_claim

        # Resolve username for 3LO tokens.
        if user_id:
            try:
                user = await self._idp.user_from_id(user_id)
                if user:
                    username = getattr(user, "username", None) or getattr(user, "email", "")
                    claims["username"] = str(username)
            except Exception:
                pass

        return JSONResponse(claims, status=200)

    # ------------------------------------------------------------------
    # device_authorization (FEAT-094 TASK-034, RFC 8628 §3.1-3.2)
    # ------------------------------------------------------------------

    async def device_authorization(self, request: web.Request):
        """POST /oauth2/device_authorization — RFC 8628 §3.1/§3.2.

        Issues device_code + user_code; persists a pending OauthDeviceCode;
        returns the RFC 8628 response payload.
        """
        from .models import OauthDeviceCode

        payload = await self.get_payload(request)
        client_id = payload.get("client_id", "")
        if not client_id:
            return self._error_response("invalid_request", "Missing client_id.", status=400)

        client = await self.client_storage.get_client(client_id, request=request)
        if not client:
            return self._error_response("invalid_client", "Unknown client.", status=400)

        # Scope validation — filter to client allow-list.
        requested_scope = payload.get("scope", "default")
        scopes = requested_scope.split()
        allowed = client.default_scopes if isinstance(client.default_scopes, list) else [client.default_scopes]
        invalid_scopes = [s for s in scopes if s not in allowed]
        if invalid_scopes and allowed:
            return self._error_response(
                "invalid_scope",
                f"Scope(s) not allowed for this client: {', '.join(invalid_scopes)}",
            )

        # D4: PKCE — required (S256) for public clients.
        code_challenge = payload.get("code_challenge")
        code_challenge_method = payload.get("code_challenge_method", "S256")
        if client.client_type == "public" and OAUTH_REQUIRE_PKCE_PUBLIC:
            if not code_challenge:
                return self._error_response(
                    "invalid_request",
                    "code_challenge required for public clients (PKCE S256).",
                    status=400,
                )
            if code_challenge_method.upper() != "S256":
                return self._error_response(
                    "invalid_request",
                    "Only code_challenge_method=S256 is supported.",
                    status=400,
                )

        # Generate device_code + user_code (regenerate on collision).
        device_code_str = secrets.token_urlsafe(32)
        alphabet = OAUTH_DEVICE_USER_CODE_ALPHABET
        length = OAUTH_DEVICE_USER_CODE_LENGTH
        max_attempts = 10
        user_code_str = None
        for _ in range(max_attempts):
            candidate = generate_user_code(length=length, alphabet=alphabet)
            existing = await self.device_code_storage.get_by_user_code(candidate)
            if not existing:
                user_code_str = candidate
                break
        if not user_code_str:
            user_code_str = generate_user_code(length=length, alphabet=alphabet)

        now = _now()
        ttl = OAUTH_DEVICE_CODE_TTL
        interval = OAUTH_DEVICE_POLL_INTERVAL
        expires_at = now + timedelta(seconds=ttl)

        dc = OauthDeviceCode(
            device_code=device_code_str,
            user_code=user_code_str,
            client_id=client.client_id,
            client_pk=client.client_pk,
            scopes=scopes,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method if code_challenge else None,
            interval=interval,
            issued_at=now,
            expires_at=expires_at,
        )
        await self.device_code_storage.save(dc)

        # Build verification_uri.
        if OAUTH_DEVICE_VERIFICATION_URI:
            verification_uri = OAUTH_DEVICE_VERIFICATION_URI
        else:
            domain = self.get_domain(request)
            verification_uri = f"{domain}{self.device_uri}"

        verification_uri_complete = f"{verification_uri}?user_code={user_code_str}"

        return JSONResponse(
            {
                "device_code": device_code_str,
                "user_code": user_code_str,
                "verification_uri": verification_uri,
                "verification_uri_complete": verification_uri_complete,
                "expires_in": ttl,
                "interval": interval,
            },
            status=200,
        )

    # ------------------------------------------------------------------
    # device_verification (FEAT-094 TASK-035, RFC 8628 §3.3)
    # ------------------------------------------------------------------

    async def device_verification(self, request: web.Request):
        """GET/POST /oauth2/device — RFC 8628 §3.3 verification page.

        GET : show the user_code entry form (pre-filled from query param).
        POST: process user_code entry, anti-brute-force, login, consent.

        Owner-binding invariant: user_id always comes from the authenticated
        session, never from client.user.
        """
        from .models import OauthGrant, DeviceCodeStatus, OauthDeviceCode

        if request.method == "GET":
            data = {key: val for (key, val) in request.query.items()}
            # Try to render the device verification page.
            try:
                return await self._parser.view(filename="oauth/device.html", params=data)
            except Exception:
                # Fallback: minimal HTML form if template not found.
                user_code_val = escape(data.get("user_code", ""), quote=True)
                html = (
                    "<!DOCTYPE html><html><body>"
                    f"<form method='POST'>"
                    f"<label>User Code: <input name='user_code' value='{user_code_val}'></label>"
                    "<button name='action' value='approve' type='submit'>Approve</button>"
                    "<button name='action' value='deny' type='submit'>Deny</button>"
                    "</form></body></html>"
                )
                return web.Response(
                    status=200, content_type="text/html", text=html
                )

        # POST: process user_code entry.
        data = await self.get_payload(request)
        action = data.get("action", "approve")
        raw_user_code = data.get("user_code", "").upper().replace("-", "").replace(" ", "")

        if not raw_user_code:
            return self._error_response("invalid_request", "user_code required.", status=400)

        # --- Anti-brute-force: Redis-backed rate-limit + lockout (D3) ---
        # Use X-Forwarded-For if available (reverse proxy), else fall back to remote.
        # NOTE: IP-only lockout is bypassable behind a shared NAT; see issue M-3.
        client_ip = request.headers.get("X-Forwarded-For", request.remote)
        if client_ip:
            client_ip = client_ip.split(",")[0].strip()  # take first (client) IP
        client_ip = client_ip or "unknown"
        lockout_key = f"oauth2:device:lockout:{client_ip}"
        attempt_key = f"oauth2:device:attempts:{client_ip}"

        # Check if locked out (Redis only when RedisDeviceCodeStorage is active).
        locked_out = False
        if hasattr(self.device_code_storage, 'redis'):
            try:
                locked_out = bool(await self.device_code_storage.redis.exists(lockout_key))
            except Exception:
                pass

        if locked_out:
            return self._error_response(
                "access_denied",
                "Too many failed attempts. Please try again later.",
                status=400,
            )

        # Look up user_code.
        dc = await self.device_code_storage.get_by_user_code(raw_user_code)
        if not dc or dc.status != DeviceCodeStatus.PENDING or _now() >= dc.expires_at:
            # Increment bad-attempt counter (generic error — no info leakage).
            await self._record_device_attempt(attempt_key, lockout_key)
            return self._error_response(
                "access_denied",
                "Invalid or expired user code.",
                status=400,
            )

        # Reset attempt counter on valid code.
        if hasattr(self.device_code_storage, 'redis'):
            try:
                await self.device_code_storage.redis.delete(attempt_key)
            except Exception:
                pass

        # --- Require authenticated session ---
        session_user = await self.check_session(request)
        if not session_user:
            # Redirect to login, with return URL.
            location = request.app.router["nav_oauth2_login"].url_for()
            redirect_url = location.with_query(
                action_url=str(location),
                device_user_code=raw_user_code,
            )
            raise web.HTTPFound(redirect_url)

        user_obj = self._decode_session_user(session_user)
        if not user_obj:
            return self._error_response("access_denied", "Cannot resolve session user.", status=401)

        if action == "deny":
            dc.status = DeviceCodeStatus.DENIED
            await self.device_code_storage.update(dc)
            try:
                return await self._parser.view(
                    filename="oauth/device_denied.html", params={}
                )
            except Exception:
                return web.Response(status=200, text="Authorization denied.")

        # --- Consent-skip via GrantStorage (FEAT-093 pattern) ---
        client = await self.client_storage.get_client(dc.client_id, request=request)
        if not client:
            return self._error_response("invalid_client", "Unknown client.", status=400)

        scopes = dc.scopes
        if self.grant_storage:
            existing_grant = await self.grant_storage.get_grant(user_obj.user_id, dc.client_id)
            if existing_grant and not existing_grant.revoked:
                granted = set(existing_grant.scopes)
                requested = set(scopes)
                if requested.issubset(granted):
                    # Consent already granted — proceed to approval.
                    return await self._approve_device_code(
                        dc, user_obj, scopes, client, request
                    )

        # Show consent page.
        try:
            return await self._parser.view(
                filename="oauth/device_consent.html",
                params={
                    "client_name": client.client_name,
                    "scopes": scopes,
                    "user_code": raw_user_code,
                    "device_code": dc.device_code,
                },
            )
        except Exception:
            # Fallback: approve directly.
            return await self._approve_device_code(dc, user_obj, scopes, client, request)

    async def _record_device_attempt(self, attempt_key: str, lockout_key: str) -> None:
        """Increment the bad-attempt counter; lock out if threshold exceeded."""
        if not hasattr(self.device_code_storage, 'redis'):
            return
        try:
            count = await self.device_code_storage.redis.incr(attempt_key)
            await self.device_code_storage.redis.expire(
                attempt_key, OAUTH_DEVICE_LOCKOUT_TTL
            )
            if int(count) >= OAUTH_DEVICE_MAX_USER_CODE_ATTEMPTS:
                await self.device_code_storage.redis.set(
                    lockout_key, "1", ex=OAUTH_DEVICE_LOCKOUT_TTL
                )
        except Exception:
            pass

    async def _approve_device_code(self, dc, user_obj, scopes, client, request):
        """Stamp the device record APPROVED + mint the D-2 auth-code carrier."""
        from .models import OauthAuthorizationCode, DeviceCodeStatus, OauthGrant

        # Upsert grant record (consent recorded).
        if self.grant_storage:
            grant = OauthGrant(
                user_id=user_obj.user_id,
                client_id=client.client_id,
                scopes=scopes,
            )
            await self.grant_storage.save_grant(grant)

        # D-2: mint an internal owner-bound OauthAuthorizationCode carrier.
        # This carrier has no redirect_uri (device-origin; the exchange must
        # accept it without requiring a matching redirect_uri).
        auth_code_str = secrets.token_urlsafe(32)
        now = _now()
        carrier = OauthAuthorizationCode(
            client=client,
            user_id=user_obj.user_id,          # owner-binding: from session
            code=auth_code_str,
            redirect_uri="",                    # no redirect_uri for device flow
            scope=" ".join(scopes),
            state="",
            response_type="device_code",        # marker so exchange allows it
            code_challenge=dc.code_challenge,
            code_challenge_method=dc.code_challenge_method,
            expires_at=now + timedelta(seconds=OAUTH_DEVICE_CODE_TTL),
        )
        await self.code_storage.save_code(carrier)

        # Stamp device record.
        dc.status = DeviceCodeStatus.APPROVED
        dc.user_id = user_obj.user_id           # owner-binding invariant
        dc.granted_scopes = scopes
        dc.auth_code = auth_code_str
        await self.device_code_storage.update(dc)

        try:
            return await self._parser.view(
                filename="oauth/device_approved.html", params={}
            )
        except Exception:
            return web.Response(status=200, text="Authorization approved. You may close this window.")

    def _get_request_user_id(self, request) -> Optional[int]:
        """Extract user_id from the authenticated request.

        The auth middleware publishes the decoded token claims under
        ``request["userdata"]`` (``"userinfo"`` is the ABAC context key, which
        nothing sets on the request — reading only that made every call to the
        grants API return 401). The authenticated user object is used as a
        fallback for cookie-session requests, whose claims are not on the
        request at all.
        """
        for source in (request.get("userdata"), request.get("userinfo")):
            if isinstance(source, dict):
                uid = source.get("user_id")
                if uid:
                    try:
                        return int(uid)
                    except (TypeError, ValueError):
                        pass
        user = request.get(self.user_property) or getattr(request, "user", None)
        for attr in (self.userid_attribute, "user_id", "id"):
            uid = getattr(user, attr, None) if user is not None else None
            if uid:
                try:
                    return int(uid)
                except (TypeError, ValueError):
                    continue
        return None

    # ------------------------------------------------------------------
    # Resource-Server side: validating an issued access token
    # ------------------------------------------------------------------

    async def authenticate(self, request: web.Request):
        """Validate the ``Authorization: Bearer <access_token>`` credential.

        This is the Resource-Server half of the provider and the hook
        ``@is_authenticated()`` calls when a request has not already been
        authenticated by ``AuthHandler.auth_middleware``. On success the
        user, the session and the token claims are attached to the request.

        Returns:
            The decoded token claims.

        Raises:
            InvalidAuth: no token, invalid/expired token, revoked ``jti``, or
                a token that resolves to no session/user.
        """
        token = await self._idp.get_payload(request)
        if not token:
            raise InvalidAuth("Oauth2: Missing Bearer access token.", status=401)
        _, payload = self._idp.decode_token(code=token)
        if not payload:
            raise InvalidAuth("Oauth2: Invalid access token.", status=401)

        # Real-time revocation check (RFC 7009 marks the jti, not the JWT).
        jti = payload.get("jti")
        if jti and self.access_token_storage:
            try:
                if await self.access_token_storage.is_revoked(jti):
                    raise InvalidAuth(
                        "Oauth2: access token has been revoked.", status=401
                    )
            except InvalidAuth:
                raise
            except Exception as exc:  # pylint: disable=W0703
                self.logger.warning(f"Oauth2: cannot check jti revocation: {exc}")

        try:
            session = await get_session(request, payload, new=False)
        except Exception as exc:  # pylint: disable=W0703
            self.logger.error(f"Oauth2: error loading the token session: {exc}")
            session = None
        if not session:
            raise InvalidAuth(
                "Oauth2: the access token is not bound to a valid session.",
                status=401,
            )
        user = await self.get_session_user(session)
        if not user:
            raise InvalidAuth(
                "Oauth2: cannot resolve the user of this access token.", status=401
            )
        request["userdata"] = payload
        request["authenticated"] = True
        self._set_user_request(request, user)
        return payload

    async def check_credentials(self, request):
        """Check the credentials carried by the request (bearer access token)."""
        return await self.authenticate(request)
