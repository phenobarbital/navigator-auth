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
from navigator_auth.identities import AuthUser
from navigator_auth.exceptions import UserNotFound
from navigator_auth.conf import (
    AUTH_USER_MODEL,
    AUTH_LOGIN_FAILED_URI,
    AUTH_REDIRECT_URI,
    AUTH_MISSING_ACCOUNT,
    AUTH_SUCCESSFUL_CALLBACKS,
    PREFERRED_AUTH_SCHEME,
    exclude_list,
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
    _user_mapping: dict = {}
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

    def configure(self, app, router):
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
        self.finish_redirect_url = AUTH_REDIRECT_URI
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
        super(ExternalAuth, self).configure(app, router)

    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements."""
        ## geting User Model for saving users:
        if AUTH_MISSING_ACCOUNT == "create":
            self._user_model = self.get_authmodel(AUTH_USER_MODEL)
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

    def get_domain(self, request: web.Request) -> str:
        uri = urlparse(str(request.url))
        domain_url = f"{PREFERRED_AUTH_SCHEME}://{uri.netloc}"
        logging.debug(f"DOMAIN: {domain_url}")
        return domain_url

    def get_finish_redirect_url(self, request: web.Request) -> str:
        domain_url = self.get_domain(request)
        print(request.query.items())
        try:
            redirect_url = request.query["redirect_url"]
        except (TypeError, KeyError):
            redirect_url = AUTH_REDIRECT_URI
        if not bool(urlparse(redirect_url).netloc):
            redirect_url = f"{domain_url}{redirect_url}"
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
        self, request: web.Request, token: str = None, token_type: str = "Bearer"
    ):
        headers = {"x-authenticated": "true"}
        params = {}
        if token:
            headers["x-auth-token"] = token
            headers["x-auth-token-type"] = token_type
            params = {"token": token, "type": token_type}
        url = self.prepare_url(self.finish_redirect_url, params)
        return web.HTTPFound(url, headers=headers)

    def failed_redirect(self, request: web.Request, error: str = "ERROR_UNKNOWN", message: str = "ERROR_UNKNOWN"):
        headers = {"x-message": message}
        params = {"error": error}
        url = self.prepare_url(self.finish_redirect_url, params)

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

    def build_user_info(self, userdata: dict) -> tuple:
        """build_user_info.
            Get user or validate user from User Model.
        Args:
            userdata (Dict): User data gets from Auth Backend.

        Returns:
            Tuple: user_id and user_data.
        Raises:
            UserNotFound: when user doesn't exists on Backend.
        """
        # User ID:
        userid = userdata[self.userid_attribute]
        userdata["id"] = userid
        userdata[self.session_key_property] = userid
        userdata["auth_method"] = self._service_name
        for key, val in self._user_mapping.items():
            try:
                userdata[key] = userdata[val]
            except KeyError:
                pass
        return (userdata, userid)

    async def validate_user_info(
        self, request: web.Request, user_id: Any, userdata: Any, token: str
    ) -> dict:
        data = None
        user = None
        # then, if everything is ok with user data, can we validate from model:
        try:
            login = userdata[self.username_attribute]
        except KeyError:
            login = userdata[self.user_attribute]
        try:
            search = {self.username_attribute: login}
            self.logger.debug(f'USER SEARCH > {search}')
            user = await self.get_user(**search)
        except UserNotFound as err:
            if AUTH_MISSING_ACCOUNT == "ignore":
                pass
            elif AUTH_MISSING_ACCOUNT == "raise":
                raise UserNotFound(f"User {login} doesn't exists: {err}") from err
            elif AUTH_MISSING_ACCOUNT == "create":
                # can create an user using userdata:
                self.logger.info(f"Creating new User: {login}")
                await self.create_external_user(userdata)
                try:
                    user = await self.get_user(**search)
                except UserNotFound as ex:
                    raise UserNotFound(
                        f"User {login} doesn't exists: {ex}"
                    ) from ex
            else:
                raise RuntimeError(
                    f"Auth: Invalid config for AUTH_MISSING_ACCOUNT: {AUTH_MISSING_ACCOUNT}"
                ) from err
        if user and self._callbacks:
            # construir e invocar callbacks para actualizar data de usuario
            args = {
                "username_attribute": self.username_attribute,
                "userid_attribute": self.userid_attribute,
                "userdata": userdata
            }
            await self.auth_successful_callback(request, user, **args)
        try:
            userinfo = self.get_userdata(user)
            ### merging userdata and userinfo:
            userinfo = {**userinfo, **userdata}
            user = await self.create_user(userinfo)
            try:
                user.username = userdata[self.username_attribute]
            except KeyError:
                user.username = user_id
            user.token = token  # issued token:
            payload = {"user_id": user_id, **userdata}
            # saving Auth data.
            await self.remember(request, user_id, userinfo, user)
            # Create the User session.
            jwt_token = self.create_jwt(data=payload)
            data = {"token": jwt_token, "access_token": token, **userdata}
            return data
        except Exception as err:
            logging.exception(err)

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
                logging.debug(f"{url} with response: {response.status}, {response!s}")
                if response.status == 200:
                    try:
                        return await response.json()
                    except aiohttp.client_exceptions.ContentTypeError:
                        resp = await response.read()
                        return parse_qs(resp.decode("utf-8"))
                else:
                    resp = await response.read()
                    raise Exception(f"Error getting Session Information: {resp}")

    async def auth_successful_callback(
        self, request: web.Request, user: Callable, **kwargs
    ) -> None:
        coro = []
        for fn in self._callbacks:
            func = self.call_successful_callbacks(request, fn, user, **kwargs)
            coro.append(asyncio.create_task(func))
        try:
            await asyncio.gather(*coro, return_exceptions=True)
        except Exception as ex:
            self.logger.exception(f"Auth Callback Error: {ex}")

    async def call_successful_callbacks(
        self, request: web.Request, fn: Callable, user: Callable, **kwargs
    ) -> None:
        # start here:
        print(":: Calling the Successful Callback :: ", fn)
        try:
            await fn(request, user, self._user_model, **kwargs)
        except Exception as e:
            self.logger.exception(
                f"Auth Callback: Error callig Callback Function: {fn}, {e!s}",
                stack_info=False,
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
        try:
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
                        await user.insert()
                        return user
                    else:
                        raise UserNotFound(f"Cannot create User {login}")
                except ValidationError as ex:
                    self.logger.error(f"Invalid User Information {login!s}")
                    print(ex.payload)
                    raise UserNotFound(f"Cannot create User {login}: {ex}") from ex
        except Exception as e:
            self.logger.error(f"Error getting User {login}")
            raise UserNotFound(f"Error getting User {login}: {e!s}") from e
