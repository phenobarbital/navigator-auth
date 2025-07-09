"""ExternalAuth Backend.

Abstract Model to any Oauth2 or external Auth Support.
"""
import asyncio
from typing import Any, Optional
from collections.abc import Callable
import importlib
from abc import abstractmethod
from urllib.parse import urlparse, parse_qs
from requests.models import PreparedRequest
import aiohttp
from aiohttp import web, hdrs
from aiohttp.client import ClientTimeout, ClientSession
from datamodel.exceptions import ValidationError
from navconfig.logging import logging
from navigator_session import AUTH_SESSION_OBJECT
from ..identities import AuthUser
from ..libs.json import json_decoder
from ..exceptions import UserNotFound, AuthException
from ..conf import (
    AUTH_LOGIN_FAILED_URI,
    AUTH_REDIRECT_URI,
    AUTH_FAILED_REDIRECT_URI,
    AUTH_MISSING_ACCOUNT,
    AUTH_SUCCESSFUL_CALLBACKS,
    PREFERRED_AUTH_SCHEME,
    AUTH_OAUTH2_REDIRECT_URL,
    exclude_list,
    USER_MAPPING
)
from .abstract import BaseAuthBackend


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
        super().__init__(
            user_attribute,
            userid_attribute,
            password_attribute,
            **kwargs
        )
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
        exclude_list.append(f"/api/v1/auth/{self._service_name}/")
        self.finish_redirect_url: str = None
        self.failed_redirect_url: str = AUTH_FAILED_REDIRECT_URI
        ## alt login
        router.add_route(
            "GET",
            f"/auth/{self._service_name}/login",
            self.authenticate,
            name=f"{self._service_name}_alt_login",
        )
        exclude_list.append(f"/auth/{self._service_name}/login")
        # finish login (callback)
        router.add_route(
            "GET",
            f"/auth/{self._service_name}/callback/",
            self.auth_callback,
            name=f"{self._service_name}_complete_login",
        )
        exclude_list.append(f"/auth/{self._service_name}/callback/")
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
        exclude_list.append(check_credentials)
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

    async def on_cleanup(self, app: web.Application):
        pass

    def get_successful_callbacks(self) -> list[Callable]:
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

    def get_finish_redirect_url(self, request: web.Request) -> str:
        domain_url = self.get_domain(request)
        try:
            redirect_url = request.query['redirect_uri']
        except (TypeError, KeyError):
            redirect_url = AUTH_REDIRECT_URI if AUTH_REDIRECT_URI else '/'
        if not bool(urlparse(redirect_url).netloc):
            redirect_url = f"{domain_url}{redirect_url}"
        self.logger.notice(
            f"Redirect URL: {redirect_url}"
        )
        self.finish_redirect_url = redirect_url

    def redirect(self, uri: str):
        """redirect.
        Making the redirection to External Auth Page.
        """
        logging.debug(f"{self.__class__.__name__} URI: {uri}")
        return web.HTTPFound(uri)

    def prepare_url(self, url: str, params: dict = None):
        req = PreparedRequest()
        req.prepare_url(url, params)
        return req.url

    def home_redirect(
        self,
        request: web.Request,
        token: str = None,
        token_type: str = "Bearer",
        uri: str = None,
        queryparams: Optional[dict] = None
    ):
        headers = {"x-authenticated": "true"}
        self.get_finish_redirect_url(request)
        params = {}
        if queryparams:
            params = queryparams
        if token:
            headers["x-auth-token-type"] = token_type
            _auth = {
                "token": token,
                "type": token_type
            }
            params = {**params, **_auth}
        if uri:
            self.logger.notice(
                f"Redirect to: {uri}"
            )
            if not bool(urlparse(uri).netloc):
                domain_url = self.get_domain(request)
                redirect_url = f"{domain_url}{uri}"
            else:
                redirect_url = uri
        elif AUTH_OAUTH2_REDIRECT_URL is not None:
            # TODO: relative URL and calculate based on Domain
            redirect_url = AUTH_OAUTH2_REDIRECT_URL
        else:
            redirect_url = self.finish_redirect_url
        self.logger.notice(
            f"Redirect URL: {redirect_url}, Params: {params}, Headers: {headers}"
        )
        url = self.prepare_url(redirect_url, params)
        return web.HTTPFound(url, headers=headers)

    def get_failed_redirect_url(self, request: web.Request) -> str:
        domain_url = self.get_domain(request)
        redirect_url = AUTH_FAILED_REDIRECT_URI if AUTH_FAILED_REDIRECT_URI else '/'
        if not bool(urlparse(redirect_url).netloc):
            # if redirect is not an absolute resource
            redirect_url = f"{domain_url}{redirect_url}"
        self.logger.warning(
            f"Failed Redirect URI: {redirect_url}"
        )
        return redirect_url

    def failed_redirect(
        self,
        request: web.Request,
        error: str = "ERROR_UNKNOWN",
        message: str = "ERROR_UNKNOWN"
    ):
        url = self.get_failed_redirect_url(request)
        headers = {"x-message": message, "x-error": str(error)}
        params = {
            "error": error,
            "message": message
        }
        url = self.prepare_url(url, params)
        return web.HTTPFound(url, headers=headers)

    @abstractmethod
    async def authenticate(self, request: web.Request):
        """Authenticate, refresh or return the user credentials."""

    @abstractmethod
    async def auth_callback(self, request: web.Request):
        """auth_callback, Finish method for authentication."""

    @abstractmethod
    async def logout(self, request: web.Request):
        """logout, forgot credentials and remove the user session."""

    @abstractmethod
    async def finish_logout(self, request: web.Request):
        """finish_logout, Finish Logout Method."""

    def build_user_info(
        self,
        userdata: dict,
        token: str,
        mapping: dict
    ) -> tuple:
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
        userdata = self.get_user_mapping(
            user=userdata, mapping=mapping
        )
        # User ID:
        try:
            userid = userdata[self.userid_attribute]
            userdata["id"] = userid
        except KeyError:
            try:
                userid = userdata[self.username_attribute]
                userdata["id"] = userid
            except (TypeError, KeyError) as exc:
                raise ValueError(
                    f"User cannot have username attribute: {self.userid_attribute}"
                ) from exc
        userdata[self.session_key_property] = userid
        userdata["auth_method"] = self._service_name
        # set original token in userdata
        userdata['auth_token'] = token
        userdata["token_type"] = self.scheme
        return (userdata, userid)

    async def validate_user_info(
        self, request: web.Request, user_id: Any, userdata: Any, token: str
    ) -> dict:
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
                raise UserNotFound(
                    f"Invalid Credentials for {login}"
                ) from err
            elif AUTH_MISSING_ACCOUNT == "create":
                # can create an user using userdata:
                await self.create_external_user(userdata)
                self.logger.info(
                    f"Created new User: {login}"
                )
                try:
                    user = await self._idp.get_user(login)
                except UserNotFound as ex:
                    raise UserNotFound(
                        f"Invalid Credentials for {login}"
                    ) from ex
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
                    "userdata": userdata
                }
                await self.auth_successful_callback(request, user, **args)
            except Exception as exc:
                self.logger.warning(exc)
        try:
            userinfo = self.get_userdata(
                user=user,
                mapping=USER_MAPPING
            )
            ### merging userdata and userinfo:
            userinfo = {**userinfo, **userdata}
            user = await self.create_user(userinfo)
            try:
                user.username = userdata[self.username_attribute]
            except KeyError:
                user.username = user_id
            user.token = token  # issued token:
            uid = userinfo[AUTH_SESSION_OBJECT].get('user_id', user_id)
            username = userdata.get('username')
            userinfo['user_id'] = uid
            # saving Auth data.
            session = await self.remember(request, user_id, userinfo, user)
            payload = {
                "user_id": uid,
                self.user_property: uid,
                self.username_attribute: username,
                "email": userdata.get('email', username),
                self.session_key_property: user_id,
                self.session_id_property: session.session_id,
                "auth_method": userdata.get('auth_method', self._service_name),
                "token_type": userdata.get('token_type', self.scheme)
            }
            # Create the User Token.
            token, exp, scheme = self._idp.create_token(
                data=payload
            )
            return {
                "token": token,
                "type": scheme,
                "expires_in": exp,
                **userdata
            }
        except Exception as err:
            logging.exception(str(err))
            raise

    @abstractmethod
    async def check_credentials(self, request: web.Request):
        """Check the validity of the current issued credentials."""

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
                logging.debug(
                    f"{url} with response: {response.status}, {response!s}"
                )
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
                    raise AuthException(
                        f"{response}"
                    )

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
                    raise UserNotFound(
                        f"Cannot create User {login}"
                    )
            except ValueError as ex:
                self.logger.error(
                    f"Wrong Payload for {login!s}: {data!s}"
                )
            except TypeError as ex:
                self.logger.error(
                    f"Payload error for {login!s}"
                )
            except ValidationError as ex:
                self.logger.error(
                    f"Invalid User Information {login!s}"
                )
                self.logger.warning(
                    f"{ex.payload!r}"
                )
                raise UserNotFound(
                    f"Cannot create User {login}: {ex}"
                ) from ex
            except Exception as e:
                self.logger.error(
                    f"Error getting User {login}"
                )
                raise UserNotFound(
                    f"Error getting User {login}: {e!s}"
                ) from e
