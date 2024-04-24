import asyncio
from typing import Union, Optional
from collections.abc import Callable, Iterable
from abc import ABC, abstractmethod
from functools import partial, wraps
from concurrent.futures import ThreadPoolExecutor
import importlib
from urllib.parse import urlparse
from requests.models import PreparedRequest
from aiohttp import web, hdrs
from aiohttp.web_urldispatcher import SystemRoute
from navconfig.logging import logging
from asyncdb.models import Model
from navigator_session import (
    new_session,
    AUTH_SESSION_OBJECT,
    SESSION_TIMEOUT,
    SESSION_KEY,
    SESSION_USER_PROPERTY,
)
from ..exceptions import (
    AuthException,
    InvalidAuth,
    UserNotFound
)
from ..conf import (
    AUTH_DEFAULT_SCHEME,
    AUTH_USERNAME_ATTRIBUTE,
    USER_MAPPING,
    AUTH_CREDENTIALS_REQUIRED,
    AUTH_SUCCESSFUL_CALLBACKS,
    exclude_list,
    PREFERRED_AUTH_SCHEME,
    AUTH_REDIRECT_URI
)
from ..libs.json import json_encoder
# Authenticated Identity
from ..identities import Identity, AuthBackend


class BaseAuthBackend(ABC):
    """Abstract Base for Authentication."""

    user_attribute: str = "user"
    password_attribute: str = "password"
    userid_attribute: str = "user_id"
    username_attribute: str = AUTH_USERNAME_ATTRIBUTE
    session_key_property: str = SESSION_KEY
    session_timeout: int = int(SESSION_TIMEOUT)
    _service: str = None
    _ident: Identity = Identity
    _info: AuthBackend = None
    _description: str = "Abstract Backend"
    _service_name: str = "abstract"
    _external_auth: bool = False
    _success_callbacks: Optional[list[str]] = AUTH_SUCCESSFUL_CALLBACKS
    _callbacks: Optional[list[Callable]] = None
    # User Mapping:
    user_mapping: dict = USER_MAPPING

    def __init__(
        self,
        user_attribute: str = None,
        userid_attribute: str = None,
        password_attribute: str = None,
        template_parser: Callable = None,
        identity: Callable = None,
        **kwargs,
    ):
        self._service = self.__class__.__name__
        self._session = None
        self._app: web.Application = None  # reference for Application
        # force using of credentials
        self.credentials_required: bool = AUTH_CREDENTIALS_REQUIRED
        self._credentials = None
        self.user_property = SESSION_USER_PROPERTY
        if user_attribute:
            self.user_attribute = user_attribute
        if password_attribute:
            self.password_attribute = password_attribute
        if userid_attribute:
            self.userid_attribute = userid_attribute
        if not self.username_attribute:
            self.username_attribute = AUTH_USERNAME_ATTRIBUTE
        # authentication scheme
        self.scheme = kwargs.pop('scheme', AUTH_DEFAULT_SCHEME)
        # user and group models
        # getting User and Group Models
        self.user_model: Model = kwargs["user_model"]
        # starts the Executor
        self.executor = ThreadPoolExecutor(max_workers=2)
        # logger
        self.logger = logging.getLogger(
            f"Auth.{self._service}"
        )
        ## Backend Info:
        self._info = AuthBackend()
        self._info.name = self._service
        self._info.uri = "/api/v1/login"
        self._info.description = self._description
        self._info.icon = f"/static/auth/icons/{self._service_name}.png"
        self._info.external = self._external_auth
        self._info.headers = {"x-auth-method": self._service}
        ## Custom User Attributes:
        self._user_attributes = kwargs.get("user_attributes", {})
        ## Identity Provider:
        self._idp = identity
        ## Template Parser:
        self._parser = template_parser

    def get_backend_info(self):
        return self._info

    @classmethod
    def authz_backends(cls):
        return cls._authz_backends

    @abstractmethod
    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements."""

    @abstractmethod
    async def on_cleanup(self, app: web.Application):
        """Used to cleanup and shutdown any db connection."""

    async def get_payload(self, request: web.Request):
        token = None
        if "Authorization" in request.headers:
            try:
                scheme, token = request.headers.get(
                    hdrs.AUTHORIZATION
                ).strip().split(" ", 1)
            except ValueError as e:
                raise AuthException(
                    "Invalid Authentication Header",
                    status=400
                ) from e
            if scheme != self.scheme:
                raise AuthException(
                    "Invalid Authentication Scheme",
                    status=400
                )
        return token

    def queryparams(self, request: web.Request) -> dict:
        return {key: val for (key, val) in request.query.items()}

    async def create_user(self, userdata) -> Identity:
        try:
            usr = self._ident(data=userdata)
            self.logger.debug(
                f"User Created > {usr.username}"
            )
            return usr
        except Exception as err:
            raise InvalidAuth(
                f"Unable to created Session User: {err}"
            ) from err

    def get_user_mapping(
        self,
        user: dict,
        mapping: dict
    ) -> dict:
        udata = {}
        for key, val in mapping.items():
            if key != self.password_attribute:
                try:
                    udata[key] = user[val]
                except (KeyError, AttributeError):
                    self.logger.warning(
                        f"Error UserData: asking for a non existing attribute: {key}"
                    )
        return udata

    def get_userdata(self, user: dict, **kwargs) -> dict:
        userdata = self.get_user_mapping(
            user=user, mapping=USER_MAPPING
        )
        ### getting custom user attributes.
        for obj in self._user_attributes:
            try:
                attr = obj()
                key, value = attr(user=user, userdata=userdata, **kwargs)
                if key:
                    userdata[key] = value
            except (KeyError, AttributeError):
                self.logger.warning(
                    f"Error UserData: asking for a non-existing attribute: {key}"
                )
        if AUTH_SESSION_OBJECT:
            return {AUTH_SESSION_OBJECT: userdata}
        return userdata

    def configure(self, app):
        """Base configuration for Auth Backends, need to be extended
        to create Session Object."""
        self._app = app

    def default_headers(self, message: str, exception: BaseException = None) -> dict:
        headers = {
            "X-AUTH": message,
        }
        if exception:
            headers['X-ERROR'] = str(exception)
        return headers

    def auth_error(
        self,
        reason: dict = None,
        exception: Exception = None,
        status: int = 400,
        headers: dict = None,
        content_type: str = 'application/json',
        **kwargs,
    ) -> web.HTTPError:
        if headers:
            headers = {
                **self.default_headers(message=str(reason), exception=exception),
                **headers
            }
        else:
            headers = self.default_headers(message=str(reason), exception=exception)
        # TODO: process the exception object
        response_obj = {}
        if exception:
            response_obj["error"] = str(exception)
        args = {
            "content_type": content_type,
            "headers": headers,
            **kwargs
        }
        if isinstance(reason, dict):
            response_obj = {**response_obj, **reason}
            args["content_type"] = "application/json"
            args["body"] = json_encoder(response_obj)
        else:
            response_obj['reason'] = reason
            args["reason"] = json_encoder(response_obj)
        # defining the error
        if args["content_type"] == "application/json":
            args['body'] = args['reason']
            del args['reason']
        if status == 400:  # bad request
            obj = web.HTTPBadRequest(**args)
        elif status == 401:  # unauthorized
            obj = web.HTTPUnauthorized(**args)
        elif status == 403:  # forbidden
            obj = web.HTTPForbidden(**args)
        elif status == 404:  # not found
            obj = web.HTTPNotFound(**args)
        elif status == 406:  # Not acceptable
            obj = web.HTTPNotAcceptable(**args)
        elif status == 412:
            obj = web.HTTPPreconditionFailed(**args)
        elif status == 428:
            obj = web.HTTPPreconditionRequired(**args)
        else:
            obj = web.HTTPBadRequest(**args)
        return obj

    def ForbiddenAccess(self, reason: Union[str, dict], **kwargs) -> web.HTTPError:
        return self.auth_error(
            reason=reason, status=403, **kwargs
        )

    def Unauthorized(self, reason: Union[str, dict], **kwargs) -> web.HTTPError:
        return self.auth_error(
            reason=reason, status=401, **kwargs
        )

    async def validate_user(self, login: str = None, userid: int = None):
        # get the user based on Model
        try:
            if login is not None:
                user = await self._idp.get_user(login)
            if userid is not None:
                user = await self._idp.user_from_id(userid)
            else:
                raise UserNotFound(
                    "User Not Found"
                )
            return user
        except UserNotFound:
            raise
        except Exception as err:
            self.logger.exception(err)
            raise

    async def remember(
        self, request: web.Request, identity: str, userdata: dict, user: Identity
    ):
        """
        Saves User Identity into request Object and session.
        """
        try:
            request[self.session_key_property] = identity
            # saving the user
            request.user = user
            try:
                session = await new_session(request, userdata)
                user.is_authenticated = True  # if session, then, user is authenticated.
                session[self.session_key_property] = identity
                try:
                    await session.save_encoded_data(request, 'user', user)
                except RuntimeError as ex:
                    print('Error Saving User ', ex)
            except Exception as err:
                raise web.HTTPForbidden(
                    reason=f"Error Creating User Session: {err!s}"
                )
            # to allowing request.user.is_authenticated
        except Exception as err:  # pylint: disable=W0703
            self.logger.exception(err)

    @abstractmethod
    async def check_credentials(self, request):
        """Authenticate against user credentials (token, user/password)."""

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

    async def auth_successful_callback(
        self, request: web.Request, user: Callable, **kwargs
    ) -> None:
        try:
            for fn in self._callbacks:
                await self.call_successful_callbacks(request, fn, user, **kwargs)
        #     coro.append(asyncio.create_task(func))
        # try:
        #     await asyncio.gather(*coro, return_exceptions=True)
        except Exception as ex:  # pylint: disable=W0718
            self.logger.exception(
                f"Auth Callback Error: {ex}", stack_info=True
            )

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

    def threaded_function(
        self,
        func: Callable,
        evt: asyncio.AbstractEventLoop = None,
        threaded: bool = True,
    ):
        """Wraps a Function into an Executor Thread."""

        @wraps(func)
        async def _wrap(*args, loop: asyncio.AbstractEventLoop = None, **kwargs):
            result = None
            if evt is None:
                loop = asyncio.get_event_loop()
            else:
                loop = evt
            try:
                if threaded:
                    fn = partial(func, *args, **kwargs)
                    result = await loop.run_in_executor(self.executor, fn)
                else:
                    result = await func(*args, **kwargs)
                return result
            except Exception as err:  # pylint: disable=W0703
                self.logger.exception(err)

        return _wrap

    async def get_session_user(self, session: Iterable, name: str = "user") -> Iterable:
        try:
            user = None
            if session:
                user = session.decode(name)
                if user:
                    user.is_authenticated = True
            return user
        except (AttributeError, RuntimeError) as ex:
            self.logger.warning(
                f"NAV: Unable to decode User session: {ex}"
            )

    async def verify_exceptions(self, request: web.Request) -> bool:
        # avoid authorization backend on excluded methods:
        if request.method == hdrs.METH_OPTIONS or request.path in exclude_list:
            return True
        # avoid check system routes
        try:
            if isinstance(request.match_info.route, SystemRoute):  # eg. 404
                return True
        except Exception:  # pylint: disable=W0703
            pass
        ## Already Authenticated
        if request.get("authenticated", False) is True:
            return True

    def get_domain(self, request: web.Request) -> str:
        uri = urlparse(str(request.url))
        domain_url = f"{PREFERRED_AUTH_SCHEME}://{uri.netloc}"
        logging.debug(f"DOMAIN: {domain_url}")
        return domain_url

    def get_finish_redirect_url(self, request: web.Request) -> str:
        domain_url = self.get_domain(request)
        try:
            redirect_url = request.query["redirect_uri"]
        except (TypeError, KeyError):
            redirect_url = AUTH_REDIRECT_URI
        if not bool(urlparse(redirect_url).netloc):
            redirect_url = f"{domain_url}{redirect_url}"
        self.finish_redirect_url = redirect_url

    def prepare_url(self, url: str, params: dict = None):
        req = PreparedRequest()
        req.prepare_url(url, params)
        return req.url

    def uri_redirect(
        self,
        request: web.Request,
        token: str = None,
        token_type: str = "Bearer",
        uri: str = None
    ):
        headers = {
            "x-authenticated": "true"
        }
        self.get_finish_redirect_url(request)
        params = {}
        if token:
            headers["x-auth-token-type"] = token_type
            params = {"token": token, "type": token_type}
        if uri is not None:
            if not bool(urlparse(uri).netloc):
                domain_url = self.get_domain(request)
                redirect_url = f"{domain_url}{uri}"
            else:
                redirect_url = uri
        else:
            redirect_url = self.finish_redirect_url
        url = self.prepare_url(redirect_url, params)
        return web.HTTPFound(url, headers=headers)
