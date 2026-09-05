"""ExternalAuth Backend.

Abstract Model to any Oauth2 or external Auth Support.
"""

import asyncio
import secrets
from typing import Any, Optional
from collections.abc import Callable
import importlib
from abc import abstractmethod
from urllib.parse import urlparse, parse_qs, quote
from requests.models import PreparedRequest
import aiohttp
import jwt
from aiohttp import web, hdrs
from aiohttp.client import ClientTimeout, ClientSession
import redis.asyncio as aioredis
from datamodel.exceptions import ValidationError
from navconfig.logging import logging
from navigator_session import AUTH_SESSION_OBJECT
from ..identities import AuthUser
from ..libs.json import json_decoder
from ..libs.redirect import safe_redirect_url
from ..exceptions import UserNotFound, AuthException, InvalidAuth
from ..identity.flow_store import IdentityFlowStore
from ..identity.types import TokenResponse
from ..conf import (
    AUTH_LOGIN_FAILED_URI,
    AUTH_REDIRECT_URI,
    AUTH_FAILED_REDIRECT_URI,
    AUTH_MISSING_ACCOUNT,
    AUTH_SUCCESSFUL_CALLBACKS,
    PREFERRED_AUTH_SCHEME,
    AUTH_OAUTH2_REDIRECT_URL,
    AUTH_EXCLUDE_LIST_KEY,
    USER_MAPPING,
    REDIS_AUTH_URL,
)
from .abstract import BaseAuthBackend
from . import jwksutils

#: FEAT-096 TASK-048 — reason codes surfaced in InvalidAuth messages/logs
#: for token-exchange verification failures. Shared by the abstract
#: `_verify_jwt`/`_require_verified_email` helpers below and by the
#: per-provider verifiers (Azure/Google/GitHub) and the exchange backend.
EXCHANGE_REASONS = frozenset(
    {
        "bad_signature",
        "wrong_audience",
        "wrong_issuer",
        "expired",
        "email_unverified",
        "invalid_token",
        "user_not_found",
    }
)

#: FEAT-095 TASK-041 — upstream IdP proxy login for the OAuth2 AS.
#: Short-lived, HttpOnly cookie carrying the opaque id of the parked
#: authorize request across the provider round-trip.  Only the handle
#: travels in the browser; the request itself stays in IdentityFlowStore.
OAUTH2_RESUME_COOKIE: str = "nav_oauth2_flow"

#: IdentityFlowStore key holding the parked authorize request.
OAUTH2_PENDING_FLOW_KEY: str = "oauth2_pending_{flow_id}"


class OauthUser(AuthUser):
    token: str
    given_name: str
    family_name: str

    def __post_init__(self, data):
        super(OauthUser, self).__post_init__(data)
        self.first_name = self.given_name
        self.last_name = self.family_name


class ExternalAuth(BaseAuthBackend):
    """ExternalAuth.

    is an abstract base to any External Auth backend, as Oauth2 or OpenId.
    """

    user_attribute: str = "user"
    username_attribute: str = "username"
    pwd_atrribute: str = "password"
    _service_name: str = "service"
    _ident: AuthUser = OauthUser
    _success_callbacks: Optional[list[str]] = AUTH_SUCCESSFUL_CALLBACKS
    _callbacks: Optional[list[Callable]] = None
    _external_auth: bool = True

    def __init__(
        self,
        user_attribute: str = None,
        userid_attribute: str = None,
        password_attribute: str = None,
        **kwargs,
    ):
        super().__init__(user_attribute, userid_attribute, password_attribute, **kwargs)
        self.base_url: str = ""
        self.authorize_uri: str = ""
        self.userinfo_uri: str = ""
        self._token_uri: str = ""
        self.login_failed_uri = AUTH_LOGIN_FAILED_URI
        self.redirect_uri = "{domain}/auth/{service}/callback/"
        self.finish_redirect_url = None
        self._issuer: str = None
        self.users_info: str = None
        self.authority: str = None

    def configure(self, app):
        # add the callback url
        router = app.router
        # TODO: know the host we already are running
        # start login
        router.add_route(
            "*",
            f"/api/v1/auth/{self._service_name}/",
            self.authenticate,
            name=f"{self._service_name}_api_login",
        )
        self._info.uri = f"/api/v1/auth/{self._service_name}/"
        ## added to excluded list:
        app[AUTH_EXCLUDE_LIST_KEY].append(f"/api/v1/auth/{self._service_name}/")
        self.finish_redirect_url: str = None
        self.failed_redirect_url: str = AUTH_FAILED_REDIRECT_URI
        ## alt login
        router.add_route(
            "GET",
            f"/auth/{self._service_name}/login",
            self.authenticate,
            name=f"{self._service_name}_alt_login",
        )
        app[AUTH_EXCLUDE_LIST_KEY].append(f"/auth/{self._service_name}/login")
        # finish login (callback); dispatches identity-link flows first
        router.add_route(
            "GET",
            f"/auth/{self._service_name}/callback/",
            self._auth_callback_dispatch,
            name=f"{self._service_name}_complete_login",
        )
        app[AUTH_EXCLUDE_LIST_KEY].append(f"/auth/{self._service_name}/callback/")
        # logout process
        router.add_route(
            "GET",
            f"/api/v1/auth/{self._service_name}/logout",
            self.logout,
            name=f"{self._service_name}_api_logout",
        )
        router.add_route(
            "GET",
            f"/auth/{self._service_name}/logout",
            self.finish_logout,
            name=f"{self._service_name}_complete_logout",
        )
        # Check Credentials:
        check_credentials = f"/auth/{self._service_name}/check_credentials"
        router.add_route(
            "GET",
            check_credentials,
            self.check_credentials,
            name=f"{self._service_name}_check_credentials",
        )
        app[AUTH_EXCLUDE_LIST_KEY].append(check_credentials)
        super(ExternalAuth, self).configure(app)

    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements."""
        ## geting User Model for saving users:
        ## TODO: Migrate Code to IdP
        if AUTH_MISSING_ACCOUNT == "create":
            self._user_model = self._idp.user_model
        else:
            self._user_model = None
        ## Using Startup for detecting and loading functions.
        if self._success_callbacks:
            self.get_successful_callbacks()
        # Redis pool for per-request OAuth2 flow state (login and
        # identity-link); backends are singletons, so per-flow data
        # must live here instead of on the instance.
        self._pool = aioredis.ConnectionPool.from_url(
            REDIS_AUTH_URL, decode_responses=True, encoding="utf-8"
        )
        self._flow_store = IdentityFlowStore(self._pool)

    async def on_cleanup(self, app: web.Application):
        try:
            await self._pool.disconnect(inuse_connections=True)
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(err)

    def get_successful_callbacks(self) -> list[Callable]:
        fns = []
        for fn in self._success_callbacks:
            try:
                pkg, module = fn.rsplit(".", 1)
                mod = importlib.import_module(pkg)
                obj = getattr(mod, module)
                fns.append(obj)
            except ImportError as e:
                raise RuntimeError(f"Auth Callback: Error getting Callback Function: {fn}, {e!s}") from e
        self._callbacks = fns

    async def get_payload(self, request):
        ctype = request.content_type
        if request.method == "POST":
            if ctype in (
                "multipart/mixed",
                "multipart/form-data",
                "application/x-www-form-urlencoded",
            ):
                data = await request.post()
                if len(data) > 0:
                    user = data.get(self.user_attribute, None)
                    password = data.get(self.pwd_atrribute, None)
                    return [user, password]
                else:
                    return [None, None]
            elif ctype == "application/json":
                try:
                    data = await request.json()
                    user = data[self.user_attribute]
                    password = data[self.pwd_atrribute]
                    return [user, password]
                except Exception:
                    return [None, None]
        else:
            return [None, None]

    def get_domain(self, request: web.Request) -> str:
        uri = urlparse(str(request.url))
        domain_url = f"{PREFERRED_AUTH_SCHEME}://{uri.netloc}"
        logging.debug(f"DOMAIN: {domain_url}")
        return domain_url

    def get_redirect_uri(self, request: web.Request) -> str:
        """Compute this backend's callback URL for the current host.

        Unlike the legacy ``self.redirect_uri`` template mutation, this is
        a pure function: safe under concurrency and multi-host deployments.
        """
        domain_url = self.get_domain(request)
        return f"{domain_url}/auth/{self._service_name}/callback/"

    def get_finish_redirect_url(self, request: web.Request) -> str:
        """Resolve where to send the browser once authentication finishes.

        ``?redirect_uri=`` is frontend-supplied and therefore untrusted: it
        is passed through :func:`safe_redirect_url`, which only honours
        relative paths, hosts under ``AUTH_TRUSTED_DOMAINS`` and mobile
        deep-link schemes, falling back to ``AUTH_REDIRECT_URI`` otherwise.
        """
        domain_url = self.get_domain(request)
        fallback = AUTH_REDIRECT_URI if AUTH_REDIRECT_URI else "/"
        try:
            redirect_url = request.query["redirect_uri"]
        except (TypeError, KeyError):
            redirect_url = fallback
        redirect_url = safe_redirect_url(
            request, redirect_url, fallback=fallback, domain_url=domain_url
        )
        self.logger.notice(f"Redirect URL: {redirect_url}")
        self.finish_redirect_url = redirect_url
        return redirect_url

    def redirect(self, uri: str):
        """redirect.
        Making the redirection to External Auth Page.
        """
        logging.debug(f"{self.__class__.__name__} URI: {uri}")
        return web.HTTPFound(uri)

    def prepare_url(self, url: str, params: dict = None):
        """Construct a URL with query parameters.

        Note: PreparedRequest doesn't handle custom URL schemes (navigator://, myapp://, etc.)
        so we manually construct URLs for non-HTTP schemes to support mobile deep links.
        """
        parsed = urlparse(url)
        if parsed.scheme and parsed.scheme not in ("http", "https", ""):
            # Custom scheme - manually append params
            if params:
                from urllib.parse import urlencode

                query_string = urlencode(params)
                separator = "&" if "?" in url else "?"
                return f"{url}{separator}{query_string}"
            return url
        # Standard HTTP(S) URL - use PreparedRequest
        req = PreparedRequest()
        req.prepare_url(url, params)
        return req.url

    def home_redirect(
        self,
        request: web.Request,
        token: str = None,
        token_type: str = "Bearer",
        uri: str = None,
        queryparams: Optional[dict] = None,
    ):
        headers = {"x-authenticated": "true"}
        self.get_finish_redirect_url(request)
        params = {}
        if queryparams:
            params = queryparams
        if token:
            headers["x-auth-token-type"] = token_type
            _auth = {"token": token, "type": token_type}
            params = {**params, **_auth}
        if uri:
            self.logger.notice(f"Redirect to: {uri}")
            # ``uri`` comes from the client (RelayState, internal_redirect,
            # ?redirect_uri=) and must pass the trusted-domain gate.
            redirect_url = safe_redirect_url(
                request,
                uri,
                fallback=self.finish_redirect_url,
                domain_url=self.get_domain(request),
            )
        elif AUTH_OAUTH2_REDIRECT_URL is not None:
            # TODO: relative URL and calculate based on Domain
            redirect_url = AUTH_OAUTH2_REDIRECT_URL
        else:
            redirect_url = self.finish_redirect_url
        self.logger.notice(f"Redirect URL: {redirect_url}, Params: {params}, Headers: {headers}")
        url = self.prepare_url(redirect_url, params)
        return web.HTTPFound(url, headers=headers)

    def get_failed_redirect_url(self, request: web.Request) -> str:
        domain_url = self.get_domain(request)
        redirect_url = AUTH_FAILED_REDIRECT_URI if AUTH_FAILED_REDIRECT_URI else "/"
        if not bool(urlparse(redirect_url).netloc):
            # if redirect is not an absolute resource
            redirect_url = f"{domain_url}{redirect_url}"
        self.logger.warning(f"Failed Redirect URI: {redirect_url}")
        return redirect_url

    def failed_redirect(self, request: web.Request, error: str = "ERROR_UNKNOWN", message: str = "ERROR_UNKNOWN"):
        url = self.get_failed_redirect_url(request)
        headers = {"x-message": message, "x-error": str(error)}
        params = {"error": error, "message": message}
        url = self.prepare_url(url, params)
        return web.HTTPFound(url, headers=headers)

    @abstractmethod
    async def authenticate(self, request: web.Request):
        """Authenticate, refresh or return the user credentials."""

    @abstractmethod
    async def auth_callback(self, request: web.Request):
        """auth_callback, Finish method for authentication."""

    async def get_callback_state(self, request: web.Request) -> Optional[str]:
        """Return the OAuth2 ``state`` (or SAML ``RelayState``) identifying
        an in-flight identity-link flow for this callback request.

        Default: the query ``state`` param, unchanged for every OIDC/OAuth2
        backend. FEAT-097's `AbstractSAMLBackend` overrides this — its ACS
        callback is a POST and the flow key (``RelayState``) arrives in the
        form body instead of the query string.
        """
        return request.rel_url.query.get("state")

    async def _auth_callback_dispatch(self, request: web.Request):
        """Route the provider callback to the right flow.

        The identity-link flow shares the provider's registered callback
        URL with the login flow; a single-use Redis record keyed by the
        OAuth2 ``state`` (or SAML ``RelayState``, via `get_callback_state`)
        distinguishes them.

        FEAT-095 TASK-041 adds a third outcome: when this login was a detour
        taken on behalf of the OAuth2 authorization server, the browser is
        sent back to ``/oauth2/authorize`` to resume the parked request
        instead of to ``home_redirect``.
        """
        state = await self.get_callback_state(request)
        if state:
            flow = await self._flow_store.consume_link(state)
            if flow:
                return await self.finish_identity_link(request, flow)
        # Read the AS marker BEFORE auth_callback: the backend consumes its
        # own state-keyed record in there, and the marker must not depend on
        # any particular backend's flow-record shape.
        resume_flow_id = self._pending_oauth2_flow(request)
        response = await self.auth_callback(request)
        if resume_flow_id:
            return await self._resume_oauth2_authorize(
                request, resume_flow_id, response
            )
        return response

    # ------------------------------------------------------------------
    # OAuth2 AS proxy login (FEAT-095 TASK-041, decision D2)
    # ------------------------------------------------------------------

    def _pending_oauth2_flow(self, request: web.Request) -> Optional[str]:
        """Return the parked authorize-flow id, if this login is an AS detour.

        The id travels in a short-lived, HttpOnly cookie set by
        ``Oauth2Provider.auth_login`` when it hands the browser to an upstream
        provider.  It is an opaque handle only — the authorize request itself
        (state, PKCE challenge, scope, redirect_uri) never leaves the server;
        it lives in ``IdentityFlowStore`` under ``oauth2_pending_{flow_id}``.

        A backend that carries ``oauth2_flow`` in its own state-keyed record
        may set ``request['oauth2_flow']``; that takes precedence.
        """
        try:
            carried = request.get("oauth2_flow")
        except (AttributeError, TypeError):
            carried = None
        return carried or request.cookies.get(OAUTH2_RESUME_COOKIE) or None

    async def _resume_oauth2_authorize(
        self, request: web.Request, flow_id: str, response
    ):
        """Send a freshly authenticated browser back into ``/oauth2/authorize``.

        The session cookie was already written by ``remember()`` during
        ``auth_callback``; only the redirect target changes, so the response
        object is edited in place rather than rebuilt — rebuilding it would
        drop whatever cookies/headers the backend attached.
        """
        # A failed login must keep the backend's own error response.
        status = getattr(response, "status", 500)
        if status not in (301, 302, 303, 307, 308):
            self.logger.warning(
                f"{self._service_name}: upstream login failed; "
                "not resuming the OAuth2 authorize request."
            )
            return response

        # Best-effort: persist the upstream credential in the Identity Vault,
        # exactly as the identity-link flow does.
        await self._vault_upstream_token(request)

        domain_url = self.get_domain(request)
        resume_url = f"{domain_url}/oauth2/authorize?flow={quote(flow_id)}"
        try:
            response.headers["Location"] = resume_url
        except Exception as err:  # pylint: disable=W0703
            self.logger.error(f"{self._service_name}: cannot resume OAuth2: {err}")
            return response
        # The marker is single-use.
        response.del_cookie(OAUTH2_RESUME_COOKIE)
        self.logger.notice(f"OAuth2 AS: resuming authorize flow {flow_id}")
        return response

    async def _vault_upstream_token(self, request: web.Request) -> None:
        """Store the upstream provider token in ``auth.user_identities``.

        The AS-initiated login is the same kind of event as an explicit
        identity link — the user has just authorised this deployment against
        Google/Microsoft — so the credential is ciphered into the vault
        through the same ``IdentityStore`` path.  Best-effort: a vault failure
        must never break the login or the authorize resume.
        """
        try:
            from navigator_session import get_session
            from ..identity.store import IdentityStore
            from ..identity.types import TokenResponse

            session = await get_session(request, new=False)
            if not session:
                return
            access_token = session.get("auth_token")
            if not access_token:
                return
            user_id = session.get("user_id")
            if user_id is None:
                session_obj = session.get(AUTH_SESSION_OBJECT) or {}
                user_id = session_obj.get("user_id")
            if user_id is None:
                return
            token = TokenResponse(
                access_token=access_token,
                token_type=session.get("token_type") or self.scheme,
                provider_user_id=str(session.get(self.userid_attribute) or ""),
            )
            store = IdentityStore(request.app["authdb"])
            await store.save_linked_identity(
                user_id, self._service_name, token, {}
            )
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(
                f"{self._service_name}: could not vault the upstream token: {err}"
            )

    # ------------------------------------------------------------------
    # Identity-link flow: a logged-in user authorizes this backend's
    # provider once more, purely to capture a credential (bearer +
    # refresh token) that is stored ciphered in auth.user_identities.
    # ------------------------------------------------------------------

    def identity_scopes(self) -> list:
        """Scopes requested when linking an identity. Per-backend."""
        return []

    def identity_authorize_params(self) -> dict:
        """Extra authorize-endpoint params for the identity flow
        (e.g. Google's access_type=offline&prompt=consent)."""
        return {}

    def get_identity_client(self) -> tuple:
        """(client_id, client_secret) used by the generic identity flow."""
        raise AuthException(
            f"{self._service_name}: identity flow is not supported"
        )

    def get_identity_userid(self, userinfo: dict) -> Optional[str]:
        """Stable external account id from the provider's userinfo."""
        for key in (self.userid_attribute, "sub", "id"):
            value = userinfo.get(key)
            if value is not None:
                return str(value)
        return None

    async def authorize_identity(
        self, request: web.Request, user_id: Any, finish_redirect: str
    ):
        """Start the identity-link authorization flow (302 to provider)."""
        from ..conf import IDENTITY_LINK_TTL

        state = secrets.token_urlsafe(32)
        redirect_uri = self.get_redirect_uri(request)
        client_id, _ = self.get_identity_client()
        scopes = self.identity_scopes()
        payload = {
            "user_id": user_id,
            "provider": self._service_name,
            "flow": "identity_link",
            "finish_redirect": finish_redirect,
            "redirect_uri": redirect_uri,
            "extra": {},
        }
        await self._flow_store.start_link(state, payload, ttl=IDENTITY_LINK_TTL)
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "response_type": "code",
            **self.identity_authorize_params(),
        }
        return self.redirect(self.prepare_url(self.authorize_uri, params))

    async def exchange_code_for_tokens(
        self, request: web.Request, flow: dict
    ) -> "TokenResponse":
        """Generic authorization_code exchange for the identity flow."""
        code = request.rel_url.query.get("code")
        if not code:
            raise AuthException(
                f"{self._service_name}: no authorization code in callback"
            )
        client_id, client_secret = self.get_identity_client()
        payload = await self.token_request(
            self._token_uri,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": flow["redirect_uri"],
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        return TokenResponse.from_oauth_response(
            payload, scopes=self.identity_scopes()
        )

    async def refresh_identity_tokens(
        self, refresh_token: str
    ) -> "TokenResponse":
        """Generic refresh_token grant; providers may rotate the token."""
        client_id, client_secret = self.get_identity_client()
        payload = await self.token_request(
            self._token_uri,
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        token = TokenResponse.from_oauth_response(payload)
        if not token.refresh_token:
            # provider did not rotate: keep using the current one
            token.refresh_token = refresh_token
        return token

    async def get_identity_userinfo(self, token: "TokenResponse") -> dict:
        """Provider userinfo for the linked account (best-effort)."""
        try:
            data = await self.get(
                self.userinfo_uri,
                token=token.access_token,
                token_type=token.token_type or "Bearer",
            )
            return data or {}
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(
                f"{self._service_name}: cannot fetch identity userinfo: {err}"
            )
            return {}

    async def finish_identity_link(self, request: web.Request, flow: dict):
        """Provider callback for an identity-link flow: exchange the code,
        cipher and store the credential, cache it in the Session Vault."""
        from ..identity.store import IdentityStore, cache_credential

        if error := request.rel_url.query.get("error"):
            desc = request.rel_url.query.get("error_description", "")
            return self.failed_redirect(
                request, error="IDENTITY_LINK_DENIED", message=f"{error}: {desc}"
            )
        try:
            token = await self.exchange_code_for_tokens(request, flow)
            userinfo = await self.get_identity_userinfo(token)
            if not token.provider_user_id:
                token.provider_user_id = self.get_identity_userid(userinfo)
            store = IdentityStore(request.app["authdb"])
            await store.save_linked_identity(
                flow["user_id"], self._service_name, token, userinfo
            )
        except Exception as err:  # pylint: disable=W0703
            self.logger.exception(
                f"{self._service_name}: identity link failed: {err}"
            )
            return self.failed_redirect(
                request,
                error="IDENTITY_LINK_FAILED",
                message=f"Identity link failed: {err}",
            )
        # best-effort: cache the decrypted credential in the session vault
        try:
            from navigator_session import get_session

            session = await get_session(request, new=False)
            if session:
                await cache_credential(
                    session, self._service_name, token.credential()
                )
        except Exception:  # pylint: disable=W0703
            pass
        # ``finish_redirect`` was captured from the query string when the
        # link flow started: untrusted, so it goes through the same gate.
        redirect_to = safe_redirect_url(
            request,
            flow.get("finish_redirect") or "/",
            fallback="/",
            domain_url=self.get_domain(request),
        )
        return web.HTTPFound(redirect_to)

    @abstractmethod
    async def logout(self, request: web.Request):
        """logout, forgot credentials and remove the user session."""

    @abstractmethod
    async def finish_logout(self, request: web.Request):
        """finish_logout, Finish Logout Method."""

    def build_user_info(self, userdata: dict, token: str, mapping: dict) -> tuple:
        """build_user_info.
            Get user or validate user from User Model.
        Args:
            userdata (Dict): User data gets from Auth Backend.
            token (str): User token gets from Auth Backend.
            mapping (dict): User mapping gets from Auth Backend.
        Returns:
            Tuple: user_id and user_data.
        Raises:
            UserNotFound: when user doesn't exists on Backend.
            ValueError: User doesn't have username attributes.
        """
        # Get data for user mapping:
        userdata = self.get_user_mapping(user=userdata, mapping=mapping)
        # User ID:
        try:
            userid = userdata[self.userid_attribute]
            userdata["id"] = userid
        except KeyError:
            try:
                userid = userdata[self.username_attribute]
                userdata["id"] = userid
            except (TypeError, KeyError) as exc:
                raise ValueError(f"User cannot have username attribute: {self.userid_attribute}") from exc
        userdata[self.session_key_property] = userid
        userdata["auth_method"] = self._service_name
        # set original token in userdata
        userdata["auth_token"] = token
        userdata["token_type"] = self.scheme
        return (userdata, userid)

    async def validate_user_info(self, request: web.Request, user_id: Any, userdata: Any, token: str) -> dict:
        user = None
        # then, if everything is ok with user data, can we validate from model:
        try:
            login = userdata[self.username_attribute]
        except KeyError:
            try:
                login = userdata[self.user_attribute]
            except KeyError:
                login = userdata[self.userid_attribute]
        try:
            user = await self._idp.get_user(login)
        except UserNotFound as err:
            if AUTH_MISSING_ACCOUNT == "raise":
                raise UserNotFound(f"Invalid Credentials for {login}") from err
            elif AUTH_MISSING_ACCOUNT == "create":
                # can create an user using userdata:
                await self.create_external_user(userdata)
                self.logger.info(f"Created new User: {login}")
                try:
                    user = await self._idp.get_user(login)
                except UserNotFound as ex:
                    raise UserNotFound(f"Invalid Credentials for {login}") from ex
            else:
                raise RuntimeError(
                    f"Auth: Invalid config for AUTH_MISSING_ACCOUNT: \
                    {AUTH_MISSING_ACCOUNT}"
                ) from err
        if user and self._callbacks:
            try:
                # construir e invocar callbacks para actualizar data de usuario
                args = {
                    "username_attribute": self.username_attribute,
                    "userid_attribute": self.userid_attribute,
                    "userdata": userdata,
                }
                await self.auth_successful_callback(request, user, **args)
            except Exception as exc:
                self.logger.warning(exc)
        try:
            userinfo = self.get_userdata(user=user, mapping=USER_MAPPING)
            ### merging userdata and userinfo:
            userinfo = {**userinfo, **userdata}
            user = await self.create_user(userinfo)
            try:
                user.username = userdata[self.username_attribute]
            except KeyError:
                user.username = user_id
            user.token = token  # issued token:
            uid = userinfo[AUTH_SESSION_OBJECT].get("user_id", user_id)
            username = userdata.get("username")
            userinfo["user_id"] = uid
            # saving Auth data.
            session = await self.remember(request, user_id, userinfo, user)
            payload = {
                "user_id": uid,
                self.user_property: uid,
                self.username_attribute: username,
                "email": userdata.get("email", username),
                self.session_key_property: user_id,
                self.session_id_property: session.session_id,
                "auth_method": userdata.get("auth_method", self._service_name),
                "token_type": userdata.get("token_type", self.scheme),
            }
            # Create the User Token.
            token, refresh_token, exp, scheme = self._idp.create_token(data=payload)
            return {"token": token, "refresh_token": refresh_token, "type": scheme, "expires_in": exp, **userdata}
        except Exception as err:
            logging.exception(str(err))
            raise

    @abstractmethod
    async def check_credentials(self, request: web.Request):
        """Check the validity of the current issued credentials."""

    # ------------------------------------------------------------------
    # FEAT-096: Token-exchange verification contract.
    #
    # A client that already holds a provider bearer token (mobile app,
    # desktop tool, partner front-end that ran the provider login itself)
    # can exchange it for a Navigator session through
    # `backends/exchange.py::TokenExchangeAuth`, without replaying the
    # browser redirect flow. That backend calls `verify_external_token` on
    # the matching provider backend (Azure/Google/GitHub); backends that
    # don't participate simply inherit the default below.
    # ------------------------------------------------------------------

    async def verify_external_token(
        self,
        token: str,
        token_type: str = "Bearer",
        id_token: Optional[str] = None,
    ) -> tuple[dict, TokenResponse]:
        """Verify a provider-issued token was minted for THIS client and is
        live; return (raw userinfo, normalized TokenResponse with
        provider_user_id, expires_at, id_token).

        Args:
            token: the provider access token (or, for id_token-only
                clients, the id_token itself).
            token_type: bearer scheme reported by the caller (informational
                only; verification always requires a live/valid token).
            id_token: optional provider id_token (OIDC JWT), when the
                client separately holds one alongside the access token.

        Returns:
            ``(userinfo, TokenResponse)`` — ``userinfo`` is the raw
            provider profile/claims used to resolve the internal user (by
            verified e-mail) and audit logging; ``TokenResponse`` carries
            ``provider_user_id``, ``expires_at`` and ``id_token`` for
            vaulting.

        Raises:
            InvalidAuth: the token is invalid — bad signature, wrong
                audience/issuer, expired, or the identity's e-mail is not
                verified. The message carries a reason code from
                ``EXCHANGE_REASONS`` for logging; the HTTP response never
                reveals it (mapped to a generic 401 by the caller).
            NotImplementedError: this backend does not support token
                exchange (the default for every ``ExternalAuth`` subclass
                that doesn't override this method) — callers map this to a
                400 "unsupported provider" rather than a 401.
        """
        raise NotImplementedError(
            f"{self._service_name}: token exchange not supported"
        )

    async def _verify_jwt(
        self,
        token: str,
        *,
        audience: Any,
        issuer: Any,
        jwks_url: Optional[str] = None,
        tenant_id: Optional[str] = None,
        leeway: int = 30,
    ) -> dict:
        """Decode and verify a provider JWT (id_token or JWT-shaped access
        token) against its JWKS, enforcing signature, ``exp`` and ``aud``.

        ``audience``/``issuer`` each accept a single value or a list of
        accepted values. The signing key is resolved via
        ``jwksutils.get_public_key`` — a static ``jwks_url`` (e.g. Google's
        published certs) when given, otherwise tenant/discovery-based
        resolution (Azure/ADFS) — off the event loop via this backend's
        executor, and cached per-process by ``jwksutils``.

        Raises ``InvalidAuth`` with a reason code from ``EXCHANGE_REASONS``
        in the message on any failure (``bad_signature``,
        ``wrong_audience``, ``wrong_issuer``, ``expired``). Never logs the
        token; only ``kid``, ``iss`` and ``aud`` are logged on failure.
        """
        loop = asyncio.get_running_loop()
        try:
            public_key = await loop.run_in_executor(
                self.executor,
                jwksutils.get_public_key,
                token,
                tenant_id,
                None,
                jwks_url,
            )
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(
                f"{self._service_name}: JWKS/public-key lookup failed: {err}"
            )
            raise InvalidAuth("bad_signature") from err
        issuers = issuer if isinstance(issuer, (list, tuple, set, frozenset)) else [issuer]
        try:
            claims = jwt.decode(
                token,
                key=public_key,
                algorithms=["RS256", "RS384", "RS512"],
                audience=audience,
                # `iss` is verified manually right below: PyJWT's built-in
                # `issuer=` check only accepts a single value, but Azure
                # tokens may be valid under either of two issuer forms.
                options={"verify_iss": False},
                leeway=leeway,
            )
        except jwt.ExpiredSignatureError as err:
            raise InvalidAuth("expired") from err
        except jwt.InvalidAudienceError as err:
            self.logger.warning(
                f"{self._service_name}: JWT wrong audience (expected {audience})"
            )
            raise InvalidAuth("wrong_audience") from err
        except jwt.PyJWTError as err:
            self.logger.warning(f"{self._service_name}: JWT rejected: {err}")
            raise InvalidAuth("bad_signature") from err
        token_iss = claims.get("iss")
        if token_iss not in issuers:
            self.logger.warning(
                f"{self._service_name}: JWT wrong issuer iss={token_iss!r} "
                f"expected={list(issuers)!r}"
            )
            raise InvalidAuth("wrong_issuer")
        return claims

    def _require_verified_email(
        self,
        userinfo: dict,
        *,
        key: str = "email",
        verified_key: str = "email_verified",
    ) -> str:
        """Return ``userinfo[key]`` when ``userinfo[verified_key]`` is
        truthy; raise ``InvalidAuth("email_unverified")`` otherwise
        (missing e-mail, missing verification flag, or explicitly false).
        Accepts both boolean and string ("true"/"false") verified flags,
        as providers are inconsistent about this.
        """
        email = userinfo.get(key)
        verified = userinfo.get(verified_key)
        if isinstance(verified, str):
            verified = verified.strip().lower() == "true"
        if not email or not verified:
            raise InvalidAuth("email_unverified")
        return email

    def get(self, url, **kwargs) -> web.Response:
        """Perform an HTTP GET request."""
        return self.request(url, method=hdrs.METH_GET, **kwargs)

    def post(self, url, **kwargs) -> web.Response:
        """Perform an HTTP POST request."""
        return self.request(url, method=hdrs.METH_POST, **kwargs)

    async def request(
        self,
        url: str,
        method: str = "get",
        token: str = None,
        token_type: str = "Bearer",
        **kwargs,
    ) -> web.Response:
        """
        request.
            connect to an http source using aiohttp
        """
        timeout = ClientTimeout(total=120)
        if "headers" in kwargs:
            headers = kwargs["headers"].copy()
            del kwargs["headers"]
        else:
            headers = {}
        if token:
            headers["Authorization"] = f"{token_type} {token}"
        if "content-type" not in headers:
            headers["content-type"] = "application/json"
            headers["Accept"] = "application/json"
        response = None
        async with ClientSession(trust_env=True) as client:
            async with client.request(
                method,
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                **kwargs,
            ) as response:
                logging.debug(f"{url} with response: {response.status}, {response!s}")
                if response.status == 200:
                    try:
                        return await response.json()
                    except aiohttp.client_exceptions.ContentTypeError:
                        resp = await response.read()
                        return parse_qs(resp.decode("utf-8"))
                else:
                    resp = await response.read()
                    try:
                        response = json_decoder(resp)
                    except ValueError:
                        response = resp
                    raise AuthException(f"{response}")

    async def token_request(
        self,
        url: str,
        data: dict,
        headers: Optional[dict] = None,
        auth: Optional[aiohttp.BasicAuth] = None,
    ) -> dict:
        """POST to an OAuth2 token endpoint and return the parsed response.

        Sends a form-encoded body with ``Accept: application/json`` (GitHub
        replies form-encoded without it) and normalizes a form-encoded reply
        into a flat dict. Raises AuthException with the provider's error
        payload on HTTP errors or an ``error`` key in the body.
        """
        _headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if headers:
            _headers.update(headers)
        timeout = ClientTimeout(total=120)
        async with ClientSession(trust_env=True) as client:
            async with client.post(
                url,
                data=data,
                headers=_headers,
                auth=auth,
                timeout=timeout,
            ) as response:
                raw = await response.read()
                try:
                    payload = json_decoder(raw)
                except (ValueError, AuthException):
                    parsed = parse_qs(raw.decode("utf-8"))
                    payload = {
                        k: v[0] if len(v) == 1 else v
                        for k, v in parsed.items()
                    }
                if not isinstance(payload, dict):
                    payload = {"response": payload}
                if response.status >= 400 or "error" in payload:
                    raise AuthException(
                        f"{self._service_name}: Token request failed: {payload}"
                    )
                return payload

    async def create_external_user(self, userdata: dict) -> Callable:
        """create_external_user.

        if an user doesn't exists, is created automatically.
        Args:
            userdata (dict): user attributes
        """
        db = self._app["authdb"]
        try:
            login = userdata[self.username_attribute]
        except KeyError:
            login = userdata[self.user_attribute]
        async with await db.acquire() as conn:
            self._user_model.Meta.connection = conn
            # generate userdata:
            data = {}
            columns = self._user_model.columns(self._user_model)
            for col in columns:
                try:
                    data[col] = userdata[col]
                except KeyError:
                    pass
            try:
                user = self._user_model(**data)
                if user:
                    user = await user.insert()
                    return user
                else:
                    raise UserNotFound(f"Cannot create User {login}")
            except ValueError as ex:
                self.logger.error(f"Wrong Payload for {login!s}: {data!s}")
            except TypeError as ex:
                self.logger.error(f"Payload error for {login!s}")
            except ValidationError as ex:
                self.logger.error(f"Invalid User Information {login!s}")
                self.logger.warning(f"{ex.payload!r}")
                raise UserNotFound(f"Cannot create User {login}: {ex}") from ex
            except Exception as e:
                self.logger.error(f"Error getting User {login}")
                raise UserNotFound(f"Error getting User {login}: {e!s}") from e
