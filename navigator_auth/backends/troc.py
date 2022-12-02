"""TROC Backend.

Troc Authentication using RNC algorithm.
"""
from collections.abc import Awaitable, Callable
from aiohttp import web, hdrs
from aiohttp.web_urldispatcher import SystemRoute
import orjson
from navigator_session import get_session, AUTH_SESSION_OBJECT
from navigator_auth.libs.cipher import Cipher
from navigator_auth.exceptions import (
    AuthException,
    AuthExpired,
    FailedAuth,
    Forbidden,
    InvalidAuth,
    UserNotFound,
)
from navigator_auth.conf import (
    AUTH_CREDENTIALS_REQUIRED,
    PARTNER_KEY,
    CYPHER_TYPE,
    exclude_list
)
from .abstract import BaseAuthBackend, decode_token
from .basic import BasicUser

class TrocToken(BaseAuthBackend):
    """TROC authentication Header."""

    user_attribute: str = "user"
    username_attribute: str = "email"
    _ident: BasicUser = BasicUser

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
            **kwargs,
        )
        # forcing to use Email as Username Attribute
        self.username_attribute = "email"
        self.cypher: Cipher = None

    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements.
        """
        self.cypher = Cipher(PARTNER_KEY, type=CYPHER_TYPE)

    async def on_cleanup(self, app: web.Application):
        """Used to cleanup and shutdown any db connection.
        """

    async def validate_user(self, login: str = None):
        # get the user based on Model
        search = {self.username_attribute: login}
        try:
            user = await self.get_user(**search)
            return user
        except UserNotFound as err:
            raise UserNotFound(
                f"User {login} doesn't exists"
            ) from err
        except Exception as err:
            self.logger.exception(err)
            raise

    async def get_payload(self, request):
        try:
            if "Authorization" in request.headers:
                try:
                    scheme, token = (
                        request.headers.get("Authorization").strip().split(" ")
                    )
                except ValueError as ex:
                    raise web.HTTPForbidden(
                        reason="Invalid authorization Header",
                    ) from ex
                if scheme != self.scheme:
                    raise web.HTTPForbidden(
                        reason="Invalid Session scheme",
                    )
            else:
                try:
                    token = request.query.get("auth", None)
                except Exception as e: # pylint: disable=W0703
                    print(e)
                    return None
        except Exception as err: # pylint: disable=W0703
            self.logger.exception(f"TrocAuth: Error getting payload: {err}")
            return None
        return token

    async def authenticate(self, request):
        """ Authenticate, refresh or return the user credentials."""
        try:
            token = await self.get_payload(request)
        except Exception as err:
            raise AuthException(
                str(err), status=400
            ) from err
        if not token:
            raise InvalidAuth(
                "Missing Credentials",
                status=401
            )
        else:
            # getting user information
            # TODO: making the validation of token and expiration
            try:
                data = orjson.loads(
                    self.cypher.decode(token)
                )
                self.logger.debug(
                    f'TrocToken: Decoded User data: {data!r}'
                )
            except Exception as err:
                raise InvalidAuth(
                    f"Invalid Token: {err!s}", status=401
                ) from err
            # making validation
            try:
                username = data[self.username_attribute]
            except KeyError as err:
                raise InvalidAuth(
                    f"Missing Email attribute: {err!s}", status=401
                ) from err
            try:
                user = await self.validate_user(login=username)
            except UserNotFound as err:
                raise UserNotFound(str(err)) from err
            except Exception as err:
                raise AuthException(err, status=500) from err
            try:
                userdata = self.get_userdata(user)
                try:
                    # merging both session objects
                    userdata[AUTH_SESSION_OBJECT] = {
                        **userdata[AUTH_SESSION_OBJECT], **data
                    }
                except Exception as err: # pylint: disable=W0703
                    self.logger.exception(err)
                uid = user[self.username_attribute]
                username = user[self.username_attribute]
                userdata[self.session_key_property] = uid
                usr = await self.create_user(
                    userdata[AUTH_SESSION_OBJECT]
                )
                usr.id = uid
                usr.set(self.username_attribute, username)
                payload = {
                    self.user_property: user[self.userid_attribute],
                    self.username_attribute: username,
                    "user_id": user[self.userid_attribute],
                }
                token = self.create_jwt(data=payload)
                usr.access_token = token
                # saving user-data into request:
                await self.remember(
                    request, uid, userdata, usr
                )
                return {
                    "token": token,
                    **userdata
                }
            except Exception as err: # pylint: disable=W0703
                self.logger.exception(f'TROC Auth: Authentication Error: {err}')
                return False

    async def check_credentials(self, request):
        """ Authentication and create a session."""
        return True


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
                self.logger.debug(f'MIDDLEWARE: {self.__class__.__name__}')
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
                    self.logger.error('TROC Auth: Access Denied')
                    raise web.HTTPUnauthorized(
                        reason=err.message
                    )
                except (AuthExpired, FailedAuth) as err:
                    self.logger.error('TROC Auth: Auth Credentials were expired')
                    raise web.HTTPUnauthorized(
                        reason=err.message
                    )
                except AuthException as err:
                    self.logger.error('Auth Middleware: Invalid Signature or secret')
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
