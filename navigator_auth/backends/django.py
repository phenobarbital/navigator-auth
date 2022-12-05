"""Django Session Backend.

Navigator Authentication using Django Session Backend
description: read the Django session from Redis Backend
and decrypt, after that, a session will be created.
"""
import base64
import logging
from collections.abc import Callable, Awaitable
import aioredis
import orjson
from aiohttp import web, hdrs
from aiohttp.web_urldispatcher import SystemRoute
from navigator_session import (
    get_session,
    AUTH_SESSION_OBJECT
)
from navigator_auth.exceptions import (
    AuthException,
    AuthExpired,
    FailedAuth,
    Forbidden,
    InvalidAuth,
    UserNotFound,
)
from navigator_auth.identities import AuthUser, Column
from navigator_auth.conf import (
    AUTH_CREDENTIALS_REQUIRED,
    DJANGO_USER_MAPPING,
    DJANGO_SESSION_URL,
    DJANGO_SESSION_PREFIX,
    exclude_list
)
# User Identity
from .abstract import BaseAuthBackend, decode_token

class DjangoUser(AuthUser):
    """DjangoUser.

    user authenticated with Django Session (sessionid bearer).
    """
    sessionid: str = Column(required=True)



class DjangoAuth(BaseAuthBackend):
    """Django SessionID Authentication Handler."""
    _user_object: str = 'user'
    _user_id_key: str = '_auth_user_id'
    _ident: AuthUser = DjangoUser

    def __init__(
        self,
        user_attribute: str = None,
        userid_attribute: str = None,
        password_attribute: str = None,
        **kwargs,
    ):
        self._pool: Callable = None
        super(
            DjangoAuth, self
        ).__init__(
            user_attribute,
            userid_attribute,
            password_attribute,
            **kwargs
        )

    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements.
        """
        self._pool = aioredis.ConnectionPool.from_url(
            DJANGO_SESSION_URL,
            decode_responses=True,
            encoding='utf-8'
        )

    async def on_cleanup(self, app: web.Application):
        """Used to cleanup and shutdown any db connection.
        """
        try:
            await self._pool.disconnect(inuse_connections=True)
        except Exception as e: # pylint: disable=W0703
            logging.warning(e)

    async def check_credentials(self, request):
        """ Authentication and create a session."""
        return True

    async def get_payload(self, request):
        _id = None
        try:
            if "Authorization" in request.headers:
                try:
                    scheme, _id = request.headers.get("Authorization").strip().split(" ")
                except ValueError as ex:
                    raise web.HTTPForbidden(
                        reason="Invalid authorization Header",
                    ) from ex
                if scheme != self.scheme:
                    raise web.HTTPForbidden(
                        reason="Invalid Session scheme",
                    )
            elif "x-sessionid" in request.headers:
                _id = request.headers.get("x-sessionid", None)
        except Exception: # pylint: disable=W0703
            return None
        return _id

    async def validate_session(self, key: str = None):
        try:
            async with aioredis.Redis(connection_pool=self._pool) as redis:
                result = await redis.get(f"{DJANGO_SESSION_PREFIX}:{key}")
            if not result:
                raise Exception(
                    'Django Auth: non-existing Session'
                )
            data = base64.b64decode(result)
            session_data = data.decode("utf-8").split(":", 1)
            user = orjson.loads(session_data[1])
            try:
                if not 'user_id' in user:
                    user['user_id'] = user[self._user_id_key]
            except KeyError:
                logging.error(
                    'DjangoAuth: Current User Data missing User ID'
                )
            session = {
                "key": key,
                "session_id": session_data[0],
                self.user_property: user,
            }
            return session
        except Exception as err:
            logging.debug(
                f"Django Decoding Error: {err}"
            )
            raise UserNotFound(
                f"{err}"
            ) from err

    async def validate_user(self, login: str = None):
        # get the user based on Model
        search = {self.userid_attribute: login}
        try:
            user = await self.get_user(**search)
            return user
        except UserNotFound as err:
            raise UserNotFound(
                f"User {login} doesn\'t exists: {err}"
            ) from err
        except Exception as e:
            raise Exception(e) from e

    async def authenticate(self, request):
        """ Authenticate against user credentials (django session id)."""
        try:
            sessionid = await self.get_payload(request)
            logging.debug(f"Session ID: {sessionid}")
        except Exception as err:
            raise AuthException(
                err, status=400
            ) from err
        if not sessionid:
            raise InvalidAuth(
                "Django Auth: Missing Credentials",
                status=401
            )
        else:
            try:
                data = await self.validate_session(
                    key=sessionid
                )
            except UserNotFound:
                raise
            except Exception as err:
                raise InvalidAuth(
                    f"{err!s}",
                    status=401
                ) from err
            if not data:
                raise InvalidAuth(
                    "Django Auth: Missing User Info",
                    status=403
                )
            try:
                u = data[self.user_property]
                username = u[self.userid_attribute]
            except KeyError as err:
                raise InvalidAuth(
                    f"Missing {self.userid_attribute} attribute: {err!s}",
                    status=401
                ) from err
            try:
                user = await self.validate_user(
                    login=username
                )
            except UserNotFound as err:
                raise UserNotFound(str(err)) from err
            except Exception as err:
                raise AuthException(str(err), status=500) from err
            try:
                userdata = self.get_userdata(user)
                # extract data from Django Session to Session Object:
                udata = {}
                for k, v in data[self._user_object].items():
                    if k in DJANGO_USER_MAPPING:
                        if k in userdata:
                            if isinstance(userdata[k], list):
                                # if userdata of k is a list, we need to mix with data:
                                udata[k] = v + userdata[k]
                            elif isinstance(userdata[k], dict):
                                udata[k] = {**v, ** userdata[k]}
                            else:
                                # data override current employee data.
                                udata[k] = v
                        else:
                            udata[k] = v
                try:
                    # merging both session objects
                    userdata[AUTH_SESSION_OBJECT] = {
                        **userdata[AUTH_SESSION_OBJECT],
                        **data,
                        **udata
                    }
                    usr = await self.create_user(
                        userdata[AUTH_SESSION_OBJECT]
                    )
                    usr.id = sessionid
                    usr.sessionid = sessionid
                    usr.set(self.username_attribute, user[self.username_attribute])
                except Exception as err: # pylint: disable=W0703
                    logging.exception(err)
                userdata[self.session_key_property] = sessionid
                # saving user-data into request:
                await self.remember(
                    request, sessionid, userdata, usr
                )
                payload = {
                    self.user_property: user[self.userid_attribute],
                    self.username_attribute: user[self.username_attribute],
                    self.userid_attribute: user[self.userid_attribute],
                    self.session_key_property: sessionid
                }
                token = self.create_jwt(
                    data=payload
                )
                return {
                    "token": token,
                    **userdata
                }
            except Exception as err: # pylint: disable=W0703
                logging.exception(
                    f'DjangoAuth: Authentication Error: {err}'
                )
                return False

    async def auth_middleware(
            self,
            app: web.Application,
            handler: Callable[[web.Request], Awaitable[web.StreamResponse]]
        ) -> web.StreamResponse:
            """
                Basic Auth Middleware.
                Description: Basic Authentication for NoAuth, Basic, Token and Django.
            """
            @web.middleware
            async def middleware(request: web.Request) -> web.StreamResponse:
                # avoid authorization backend on excluded methods:
                if request.method == hdrs.METH_OPTIONS:
                    return await handler(request)
                # avoid authorization on exclude list
                if request.path in exclude_list:
                    return await handler(request)
                # avoid check system routes
                try:
                    if isinstance(request.match_info.route, SystemRoute):  # eg. 404
                        return await handler(request)
                except Exception as err: # pylint: disable=W0703
                    self.logger.error(err)
                ## Already Authenticated
                try:
                    if request.get('authenticated', False) is True:
                        return await handler(request)
                except KeyError:
                    pass
                self.logger.debug(':: DJANGO MIDDLEWARE ::')
                try:
                    _, payload = decode_token(request)
                    if payload:
                        ## check if user has a session:
                        # load session information
                        session = await get_session(request, payload, new=False, ignore_cookie=True)
                        if not session and AUTH_CREDENTIALS_REQUIRED is True:
                            raise web.HTTPUnauthorized(
                                reason="There is no Session for User or Authentication is missing"
                            )
                        try:
                            request.user = await self.get_session_user(session)
                            request['authenticated'] = True
                        except Exception as ex: # pylint: disable=W0703
                            self.logger.error(
                                f'Missing User Object from Session: {ex}'
                            )
                    else:
                        if AUTH_CREDENTIALS_REQUIRED is True:
                            raise web.HTTPUnauthorized(
                                reason="There is no Session for User or Authentication is missing"
                            )
                except (Forbidden) as err:
                    self.logger.error('Auth Middleware: Access Denied')
                    raise web.HTTPUnauthorized(
                        reason=err.message
                    )
                except (AuthExpired, FailedAuth) as err:
                    self.logger.error('Django Auth: Auth Credentials were expired')
                    raise web.HTTPUnauthorized(
                        reason=err.message
                    )
                except AuthException as err:
                    self.logger.error('Django Auth: Invalid Signature or secret')
                    raise web.HTTPForbidden(
                        reason=err.message
                    )
                except Exception as err: # pylint: disable=W0703
                    self.logger.error(f"Bad Request: {err!s}")
                    if AUTH_CREDENTIALS_REQUIRED is True:
                        raise web.HTTPBadRequest(
                            reason=f"Auth Error: {err!s}"
                        )
                return await handler(request)
            return middleware
