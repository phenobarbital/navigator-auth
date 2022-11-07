import asyncio
from collections.abc import Callable
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from functools import partial, wraps
from concurrent.futures import ThreadPoolExecutor
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
    SESSION_USER_PROPERTY
)
from navigator_auth.exceptions import (
    AuthException,
    UserNotFound,
    InvalidAuth,
    FailedAuth,
    AuthExpired
)
from navigator_auth.conf import (
    AUTH_DEFAULT_ISSUER,
    AUTH_DEFAULT_SCHEME,
    AUTH_USERNAME_ATTRIBUTE,
    AUTH_JWT_ALGORITHM,
    USER_MAPPING,
    CREDENTIALS_REQUIRED,
    SECRET_KEY
)

# Authenticated Identity
from navigator_auth.identities import Identity


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

    def __init__(
        self,
        user_attribute: str = None,
        userid_attribute: str = None,
        password_attribute: str = None,
        **kwargs,
    ):
        self._service = self.__class__.__name__
        self._session = None
        self._app: web.Application = None # reference for Application
        # force using of credentials
        self.credentials_required: bool = CREDENTIALS_REQUIRED
        self._credentials = None
        self.user_property = SESSION_USER_PROPERTY
        if user_attribute:
            self.user_attribute = user_attribute
        if password_attribute:
            self.password_attribute = password_attribute
        if userid_attribute:
            self.userid_attribute = userid_attribute
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
        self.logger = logging.getLogger('Nav-auth.backends')

    @classmethod
    def authz_backends(cls):
        return cls._authz_backends

    @abstractmethod
    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements.
        """

    @abstractmethod
    async def on_cleanup(self, app: web.Application):
        """Used to cleanup and shutdown any db connection.
        """

    async def get_user(self, **search):
        """Getting User Object."""
        user = None
        try:
            db = self._app['authdb']
            async with await db.acquire() as conn:
                self.user_model.Meta.connection = conn
                user = await self.user_model.get(**search)
        except ValidationError as ex:
            self.logger.error(f"Invalid User Information {search!s}")
            print(ex.payload)
        except Exception as e:
            self.logger.error(f"Error getting User {search!s}")
            raise UserNotFound(
                f"Error getting User {search!s}: {e!s}"
            ) from e
        # if not exists, return error of missing
        if not user:
            raise UserNotFound(
                f"User {search!s} doesn't exists"
            )
        return user

    async def create_user(self, userdata) -> Identity:
        try:
            usr = self._ident(
                data=userdata
            )
            self.logger.debug(f'User Created > {usr}')
            return usr
        except Exception as err:
            raise Exception(err) from err

    def get_userdata(self, user = None):
        userdata = {}
        for name, item in self.user_mapping.items():
            if name != self.password_attribute:
                try:
                    userdata[name] = user[item]
                except AttributeError:
                    self.logger.warning(
                        f'Error on User Data: asking for a non existing attribute: {item}'
                    )
        if AUTH_SESSION_OBJECT:
            return {
                AUTH_SESSION_OBJECT: userdata
            }
        return userdata

    def configure(self, app, router):
        """Base configuration for Auth Backends, need to be extended
        to create Session Object."""
        self._app = app

    async def remember(
            self,
            request: web.Request,
            identity: str,
            userdata: dict,
            user: Identity
        ):
        """
        Saves User Identity into request Object.
        """
        try:
            request[self.session_key_property] = identity
            # saving the user
            request.user = user
            try:
                session = await new_session(request, userdata)
                user.is_authenticated = True # if session, then, user is authenticated.
                session[self.session_key_property] = identity
                session['user'] = session.encode(user)
                request['session'] = session
            except Exception as err:
                raise web.HTTPForbidden(
                    reason=f"Error Creating User Session: {err!s}"
                )
            # to allowing request.user.is_authenticated
        except Exception as err: # pylint: disable=W0703
            self.logger.exception(err)

    def create_jwt(
        self,
        issuer: str = None,
        expiration: int = None,
        data: dict = None
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
        """ Authenticate against user credentials (token, user/password)."""

    def threaded_function(self, func: Callable, evt: asyncio.AbstractEventLoop = None, threaded: bool = True):
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
                    result = await loop.run_in_executor(
                        self.executor, fn
                    )
                else:
                    result = await func(*args, **kwargs)
                return result
            except Exception as err: # pylint: disable=W0703
                self.logger.exception(err)
        return _wrap


def decode_token(request, issuer: str = None):
    jwt_token = None
    tenant = None
    _id = None
    payload = None
    if not issuer:
        issuer = AUTH_DEFAULT_ISSUER
    if "Authorization" in request.headers:
        try:
            scheme, _id = (
                request.headers.get(hdrs.AUTHORIZATION).strip().split(" ", 1)
            )
        except ValueError as e:
            raise AuthException(
                "Invalid Authentication Header",
                status=400
            ) from e
        if scheme != AUTH_DEFAULT_SCHEME:
            raise AuthException(
                "Invalid Authentication Scheme",
                status=400
            )
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
            raise AuthExpired(
                f"Credentials Expired: {err!s}"
            ) from err
        except jwt.exceptions.InvalidSignatureError as err:
            raise AuthExpired(
                f"Signature Failed or Expired: {err!s}"
            ) from err
        except jwt.exceptions.DecodeError as err:
            raise FailedAuth(
                f"Token Decoding Error: {err}"
            ) from err
        except jwt.exceptions.InvalidTokenError as err:
            raise InvalidAuth(
                f"Invalid authorization token {err!s}"
            ) from err
        except Exception as err:
            raise AuthException(
                str(err),
                status=501
            ) from err
    else:
        return [tenant, payload]
