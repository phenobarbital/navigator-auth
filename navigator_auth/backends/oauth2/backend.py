"""Oauth2 Provider.


Navigator as a Oauth2 Provider.
"""
from typing import Optional, Any
from collections.abc import Awaitable
import importlib
from urllib.parse import urlparse
from requests.models import PreparedRequest
from aiohttp import web
from datamodel.exceptions import ValidationError
from ...identities import AuthUser
from ...conf import (
    AUTH_LOGIN_FAILED_URI,
    AUTH_LOGOUT_REDIRECT_URI,
    AUTH_MISSING_ACCOUNT,
    AUTH_SUCCESSFUL_CALLBACKS,
    PREFERRED_AUTH_SCHEME,
    exclude_list,
)
from ...exceptions import (
    FailedAuth,
    UserNotFound,
    InvalidAuth,
)
from ...responses import JSONResponse
from ..abstract import BaseAuthBackend


class OauthUser(AuthUser):
    access_token: str
    refresh_token: str
    given_name: str
    family_name: str

    def __post_init__(self, data):
        super(OauthUser, self).__post_init__(data)
        self.first_name = self.given_name
        self.last_name = self.family_name


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
        super().__init__(
            user_attribute,
            userid_attribute,
            password_attribute,
            **kwargs
        )
        self.base_url: str = ""
        ## TODO: customize URLs
        self.login_uri: str = "/oauth2/login"
        self.authorize_uri: str = "/oauth2/authorize"
        self.token_uri: str = "/oauth2/token"
        self.userinfo_uri: str = "/oauth2/userinfo"
        self.logout_uri: str = "/oauth2/logout"
        self.login_failed_uri = AUTH_LOGIN_FAILED_URI
        self.logout_redirect_uri = AUTH_LOGOUT_REDIRECT_URI
        if not self.logout_redirect_uri:
            self.logout_redirect_uri = '/oauth2/login'
        self.redirect_uri = None

    def configure(self, app):
        router = app.router
        # start login (Authorize)
        router.add_route(
            "*",
            self.authorize_uri,
            self.authorize,
            name="nav_oauth2_authorize",
        )
        router.add_route(
            "*",
            "/oauth2/authorize/",
            self.authorize,
            name="nav_oauth2_authorize_alt",
        )
        ## added to excluded list:
        exclude_list.append(self.authorize_uri)
        exclude_list.append(
            "/oauth2/authorize/"
        )
        ## login
        router.add_route(
            "*",
            self.login_uri,
            self.auth_login,
            name="nav_oauth2_login",
        )
        exclude_list.append(self.login_uri)
        # Token Request
        router.add_route(
            "*",
            self.token_uri,
            self.token_request,
            name="nav_oauth2_token_request",
        )
        exclude_list.append(self.token_uri)
        # User Info
        router.add_route(
            "GET",
            self.userinfo_uri,
            self.userinfo,
            name="nav_oauth2_userinfo",
        )
        # logout process
        router.add_route(
            "GET",
            self.logout_uri,
            self.logout,
            name="nav_oauth2_api_logout",
        )
        # Logout redirection
        router.add_route(
            "GET",
            self.logout_redirect_uri,
            self.finish_logout,
            name="nav_oauth2_complete_logout",
        )
        exclude_list.append(self.logout_redirect_uri)
        super(Oauth2Provider, self).configure(app)

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
        self.logger.debug(
            f"OAUTH2 DOMAIN URL: {domain_url}"
        )
        return domain_url

    def prepare_url(self, url: str, params: dict = None):
        req = PreparedRequest()
        req.prepare_url(url, params)
        return req.url

    def redirect(self, uri: str, location: bool = False):
        """redirect.
        Making the redirection Any External Page.
        """
        self.logger.debug(f"Redirect URI: {uri}")
        if location is True:
            raise web.HTTPFound(location=uri)
        raise web.HTTPFound(uri)

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
                    self.logger.error(
                        "Oauth2: Error getting JSON data from request"
                    )
        else:
            ## getting data from query string.
            data = {
                key: val for (key, val) in request.query.items()
            }
        ## validate payload before returning
        if 'client_id' not in data:
            raise web.HTTPBadRequest(
                reason="Missing Client ID in request"
            )
        if 'redirect_uri' not in data:
            raise web.HTTPBadRequest(
                reason="Missing redirect URI in request"
            )
        if 'response_type' not in data:
            raise web.HTTPBadRequest(
                reason="Invalid Auth Request: Missing response_type"
            )
        return data

    async def authorize(self, request: web.Request):
        """Starts a Oauth2 Code Flow."""
        data = await self.get_payload(request)
        # TODO: Check if user is already authorized
        ## Redirect to Login Page.
        location = request.app.router['nav_oauth2_login'].url_for()
        payload = {
            "action_url": str(location),
            **data,
        }
        url = location.with_query(**payload)
        self.redirect(url, location=True)

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
                    self.logger.error(
                        f"Oauth2: Error getting JSON data from request: {err}"
                    )
            # TODO: configurable username and password attributes
            username = data.get('username', None)
            password = data.get('password', None)
            if None in [username, password]:
                self.logger.error(
                    "Oauth2: Invalid username or password"
                )
                raise self.auth_error(
                    reason="Oauth2: Invalid username or password",
                    status=400
                )
            return (username, password, data)
        else:
            raise self.auth_error(
                reason=f'Invalid HTTP Form Data: {request.method}',
                status=400
            )

    async def return_token(self, data, redirect_uri):
        ## Implicit Flow, return in callback Access Token
        access_token, exp, scheme = self._idp.create_token(data)
        refresh_token = self._idp.create_refresh_token()
        payload = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": scheme,
            "expires_in": exp
        }
        uri = self.prepare_url(redirect_uri, params=payload)
        self.redirect(uri)

    async def auth_login(self, request: web.Request):
        """auth_login.
            Login Page for User Authentication.
        """
        if request.method == "GET":
            ## Render Login Page:
            data = {key: val for (key, val) in request.query.items()}
            return await self._parser.view(
                filename='oauth/login.html',
                params=data
            )
        elif request.method == "POST":
            ## User Authentication.
            username, password, data = await self.get_login_form(request)
            if not password and not username:
                raise web.HTTPBadRequest(
                    reason="Auth: Invalid Credentials"
                )
            try:
                user = await self._idp.authenticate_credentials(
                    login=username,
                    password=password
                )
            except (FailedAuth, UserNotFound) as exc:  # pylint: disable=W0706
                raise web.HTTPBadRequest(
                    reason=f"Auth: User not Found {exc}"
                )
            except (ValidationError, InvalidAuth) as exc:
                raise web.HTTPBadRequest(
                    reason=f"Auth: User Invalid {exc}"
                )
            except Exception as exc:
                raise web.HTTPBadRequest(
                    reason=f"Auth: Exception {exc}"
                )
            ## Authorization:
            # Build the Authorization Code and returns
            redirect_uri = data.get('redirect_uri')
            client_id = data.get('client_id')
            response_type = data.get('response_type')
            if response_type == 'code':
                # Authorization code Flow
                code = self._idp.generate_authorization_code(
                    client_id, redirect_uri
                )
                payload = {
                    "code": code,
                    "client_id": client_id,
                    "state": data['state']
                }
                uri = self.prepare_url(redirect_uri, params=payload)
                self.redirect(uri)
            elif response_type == 'token':
                await self.return_token(data, redirect_uri)
        else:
            return self.auth_error(
                reason=f'Invalid HTTP Login Method: {request.method}',
                status=400
            )

    async def token_request(self, request):
        payload = await self.get_payload(request)
        code = payload.get('code', None)
        if not code:
            return self.auth_error(
                reason='Access Denied',
                status=403
            )
        redirect_uri = payload.get('redirect_uri')
        client_id = payload.get('client_id')
        if self._idp.check_authorization_code(
            code, client_id, redirect_uri
        ):
            # authorization accepted.
            access_token, exp, scheme = self._idp.create_token(payload)
            payload = {
                "access_token": access_token,
                "token_type": scheme,
                "expires_in": exp
            }
            return JSONResponse(payload, status=200)
        else:
            # authorization denied.
            return self.auth_error(
                reason='Invalid Authorization Code, Access Denied',
                status=403
            )

    async def userinfo(self, request):
        pass

    async def logout(self, request):
        pass

    async def finish_logout(self, request):
        pass

    async def check_credentials(self, request):
        """Authentication and create a session."""
        return True
