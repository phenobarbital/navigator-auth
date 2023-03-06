import asyncio
from typing import Union, Optional
from collections.abc import Callable, Iterable
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from functools import partial, wraps
from concurrent.futures import ThreadPoolExecutor
import importlib
import jwt
from aiohttp import web, hdrs
from navconfig.logging import logging
from datamodel.exceptions import ValidationError
from asyncdb.models import Model
from navigator_session import (
    new_session,
    AUTH_SESSION_OBJECT,
    SESSION_TIMEOUT,
    SESSION_KEY,
    SESSION_USER_PROPERTY,
)
from navigator_auth.exceptions import (
    AuthException,
    UserNotFound,
    InvalidAuth,
    FailedAuth,
    AuthExpired,
)
from navigator_auth.conf import (
    AUTH_DEFAULT_ISSUER,
    AUTH_DEFAULT_SCHEME,
    AUTH_USERNAME_ATTRIBUTE,
    AUTH_JWT_ALGORITHM,
    USER_MAPPING,
    AUTH_CREDENTIALS_REQUIRED,
    SECRET_KEY,
    AUTH_SUCCESSFUL_CALLBACKS
)
from navigator_auth.libs.json import json_encoder
# Authenticated Identity
from navigator_auth.identities import Identity, AuthBackend


class BaseAuthBackend(ABC):
    """Abstract Base for Authentication."""

    user_attribute: str = "user"
    password_attribute: str = "password"
    userid_attribute: str = "user_id"
    username_attribute: str = AUTH_USERNAME_ATTRIBUTE
    session_key_property: str = SESSION_KEY
    scheme: str = "Bearer"
    session_timeout: int = int(SESSION_TIMEOUT)
    _service: str = None
    _ident: Identity = Identity
    _info: AuthBackend = None
    _description: str = "Abstract Backend"
    _service_name: str = "abstract"
    _external_auth: bool = False
    _success_callbacks: Optional[list[str]] = AUTH_SUCCESSFUL_CALLBACKS
    _callbacks: Optional[list[Callable]] = None

    def __init__(
        self,
        user_attribute: str = None,
        userid_attribute: str = None,
        password_attribute: str = None,
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
        try:
            self.scheme = kwargs["scheme"]
        except KeyError:
            pass
        # user and group models
        # getting User and Group Models
        self.user_model: Model = kwargs["user_model"]
        # user mapping
        self.user_mapping = USER_MAPPING
        # starts the Executor
        self.executor = ThreadPoolExecutor(max_workers=1)
        # logger
        self.logger = logging.getLogger(f"Auth.{self._service}")
        ## Backend Info:
        self._info = AuthBackend()
        self._info.name = self._service
        self._info.uri = "/api/v1/login"
        self._info.description = self._description
        self._info.icon = f"/static/auth/icons/{self._service_name}.png"
        self._info.external = self._external_auth
        self._info.headers = {"x-auth-method": self._service}

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

    def get_authmodel(self, model: str):
        try:
            parts = model.split(".")
            name = parts[-1]
            classpath = ".".join(parts[:-1])
            module = importlib.import_module(classpath, package=name)
            obj = getattr(module, name)
            return obj
        except ImportError as err:
            ## Using fallback Model
            raise RuntimeError(
                f"Auth Model: Cannot import model {model}: {err}"
            ) from err

    async def get_user(self, **search):
        """Getting User Object."""
        user = None
        error = None
        try:
            db = self._app["authdb"]
            async with await db.acquire() as conn:
                self.user_model.Meta.connection = conn
                user = await self.user_model.get(**search)
        except ValidationError as ex:
            self.logger.error(f"Invalid User Information {search!s}")
            print(ex.payload)
            error = ex
        except Exception as e:
            error = e
            self.logger.error(f"Error getting User {search!s}")
            raise UserNotFound(f"Error getting User {search!s}: {e!s}") from e
        # if not exists, return error of missing
        if not user:
            raise UserNotFound(f"User {search!s} doesn't exists: {error}")
        return user

    async def create_user(self, userdata) -> Identity:
        try:
            usr = self._ident(data=userdata)
            self.logger.debug(f"User Created > {usr.username}")
            return usr
        except Exception as err:
            raise InvalidAuth(
                f"Unable to created Session User: {err}"
            ) from err

    def get_userdata(self, user=None):
        userdata = {}
        for name, item in self.user_mapping.items():
            if name != self.password_attribute:
                try:
                    userdata[name] = user[item]
                except AttributeError:
                    self.logger.warning(
                        f"Error on User Data: asking for a non existing attribute: {item}"
                    )
        if AUTH_SESSION_OBJECT:
            return {AUTH_SESSION_OBJECT: userdata}
        return userdata

    def configure(self, app, router):
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
            headers = {**self.default_headers(message=str(reason), exception=exception), **headers}
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
            # args["content_type"] = "application/json"
            args["reason"] = json_encoder(response_obj)
        else:
            response_obj['reason'] = reason
            args["reason"] = json_encoder(response_obj)
        # defining the error
        if status == 400:  # bad request
            obj = web.HTTPBadRequest(**args)
        elif status == 401:  # unauthorized
            obj = web.HTTPUnauthorized(**args)
        elif status == 403:  # forbidden
            obj = web.HTTPForbidden(**args)
        elif status == 404:  # not found
            obj = web.HTTPNotFound(**args)
        elif status == 406: # Not acceptable
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
            reason=reason, **kwargs, status=403
        )

    def Unauthorized(self, reason: Union[str, dict], **kwargs) -> web.HTTPError:
        return self.auth_error(
            reason=reason, **kwargs, status=401
        )

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
                    # session["user"] = session.encode(user)
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

    def create_jwt(
        self, issuer: str = None, expiration: int = None, data: dict = None
    ) -> str:
        """Creation of JWT tokens based on basic parameters.
        issuer: for default, urn:Navigator
        expiration: in seconds
        **kwargs: data to put in payload
        """
        if not expiration:
            expiration = self.session_timeout
        if not issuer:
            issuer = AUTH_DEFAULT_ISSUER
        payload = {
            "exp": datetime.utcnow() + timedelta(seconds=expiration),
            "iat": datetime.utcnow(),
            "iss": issuer,
            **data,
        }
        try:
            jwt_token = jwt.encode(
                payload,
                SECRET_KEY,
                AUTH_JWT_ALGORITHM,
            )
        except (TypeError, ValueError) as ex:
            raise web.HTTPForbidden(
                reason=f"Cannot Create Session Token: {ex!s}"
            ) from ex
        return jwt_token

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
        coro = []
        for fn in self._callbacks:
            func = self.call_successful_callbacks(request, fn, user, **kwargs)
            coro.append(asyncio.create_task(func))
        try:
            await asyncio.gather(*coro, return_exceptions=True)
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
            if session:
                user = session.decode(name)
                if user:
                    user.is_authenticated = True
            return user
        except (AttributeError, RuntimeError) as ex:
            logging.warning(f"NAV: Unable to decode User session: {ex}")


def decode_token(request, issuer: str = None):
    jwt_token = None
    tenant = None
    _id = None
    payload = None
    if not issuer:
        issuer = AUTH_DEFAULT_ISSUER
    if "Authorization" in request.headers:
        try:
            scheme, _id = request.headers.get(hdrs.AUTHORIZATION).strip().split(" ", 1)
        except ValueError as e:
            raise AuthException("Invalid Authentication Header", status=400) from e
        if scheme != AUTH_DEFAULT_SCHEME:
            raise AuthException("Invalid Authentication Scheme", status=400)
        try:
            tenant, jwt_token = _id.split(":")
        except (TypeError, ValueError, AttributeError):
            # normal Token:
            jwt_token = _id
        try:
            payload = jwt.decode(
                jwt_token,
                SECRET_KEY,
                algorithms=[AUTH_JWT_ALGORITHM],
                iss=issuer,
                leeway=30,
            )
            logging.debug(f"Decoded Token: {payload!s}")
            return [tenant, payload]
        except jwt.exceptions.ExpiredSignatureError as err:
            raise AuthExpired(f"Credentials Expired: {err!s}") from err
        except jwt.exceptions.InvalidSignatureError as err:
            raise AuthExpired(f"Signature Failed or Expired: {err!s}") from err
        except jwt.exceptions.DecodeError as err:
            raise FailedAuth(f"Token Decoding Error: {err}") from err
        except jwt.exceptions.InvalidTokenError as err:
            raise InvalidAuth(f"Invalid authorization token {err!s}") from err
        except Exception as err:
            raise AuthException(str(err), status=501) from err
    else:
        return [tenant, payload]
