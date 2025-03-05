"""TROC Backend.

Troc Authentication using RNC algorithm.
"""
from typing import Optional
from collections.abc import Awaitable, Callable
from aiohttp import web
import orjson
from navigator_session import get_session, AUTH_SESSION_OBJECT
from ..libs.cipher import Cipher
from ..exceptions import (
    AuthException,
    AuthExpired,
    FailedAuth,
    Forbidden,
    InvalidAuth,
    UserNotFound,
)
from ..conf import (
    AUTH_CREDENTIALS_REQUIRED,
    PARTNER_KEY,
    CYPHER_TYPE,
    AUTH_SUCCESSFUL_CALLBACKS,
    TROCTOKEN_REDIRECT_URI
)
from .abstract import BaseAuthBackend
from .basic import BasicUser


class TrocToken(BaseAuthBackend):
    """TROC authentication Header."""

    user_attribute: str = "user"
    username_attribute: str = "email"
    _ident: BasicUser = BasicUser
    _description: str = "Partnership Token authentication"
    _service_name: str = "troctoken"
    _success_callbacks: Optional[list[str]] = AUTH_SUCCESSFUL_CALLBACKS
    _callbacks: Optional[list[Callable]] = None

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
        """Used to initialize Backend requirements."""
        self.cypher = Cipher(PARTNER_KEY, type=CYPHER_TYPE)
        ## Using Startup for detecting and loading functions.
        if self._success_callbacks:
            self._user_model = self._idp.user_model
            self.get_successful_callbacks()

    async def on_cleanup(self, app: web.Application):
        """Used to cleanup and shutdown any db connection."""

    async def get_payload(self, request: web.Request):
        try:
            try:
                token = request.query.get("auth", None)
            except Exception as e:  # pylint: disable=W0703
                print(e)
                return None
        except Exception as err:  # pylint: disable=W0703
            self.logger.exception(
                f"TrocAuth: Error getting payload: {err}"
            )
            raise
        return token

    async def get_token(self, token: str):
        # TODO: making the validation of token and expiration
        try:
            data = orjson.loads(self.cypher.decode(token))
            # making validation
            try:
                username = data[self.username_attribute]
            except KeyError as err:
                raise InvalidAuth(
                    f"Missing Username: {err!s}", status=412
                ) from err
            return data, username
        except Exception as err:
            raise InvalidAuth(
                f"Invalid Token: {err!s}",
                status=401
            ) from err

    async def authenticate(self, request):
        """Authenticate, refresh or return the user credentials."""
        qs = dict(request.query.items())
        try:
            token = await self.get_payload(request)
        except Exception as err:
            raise AuthException(
                str(err),
                status=400
            ) from err
        if not token:
            raise InvalidAuth(
                "Token: Missing Token",
                status=401
            )
        else:
            # getting user information
            try:
                data, username = await self.get_token(token)
            except InvalidAuth:
                raise
            try:
                user = await self.validate_user(login=username)
            except UserNotFound:
                raise
            except Exception as err:
                raise AuthException(
                    err,
                    status=500
                ) from err
            try:
                userdata = self.get_userdata(user)
                try:
                    # merging both session objects
                    userdata[AUTH_SESSION_OBJECT] = {
                        **userdata[AUTH_SESSION_OBJECT],
                        **data,
                    }
                except Exception as err:  # pylint: disable=W0703
                    self.logger.exception(err)
                uid = user[self.username_attribute]
                username = user[self.username_attribute]
                userdata[self.session_key_property] = uid
                usr = await self.create_user(userdata[AUTH_SESSION_OBJECT])
                usr.id = uid
                usr.set(self.username_attribute, username)
                # saving user-data into request:
                session = await self.remember(request, uid, userdata, usr)
                payload = {
                    self.user_property: user[self.userid_attribute],
                    self.username_attribute: username,
                    "user_id": uid,
                    self.session_key_property: username,
                    self.session_id_property: session.session_id
                }
                token, exp, scheme = self._idp.create_token(data=payload)
                usr.access_token = token
                usr.token_type = scheme
                usr.expires_in = exp
                userdata['expires_in'] = exp
                userdata['token_type'] = scheme
                ### check if any callbacks exists:
                try:
                    if user and self._callbacks:
                        # construir e invocar callbacks para actualizar data de usuario
                        args = {
                            "username_attribute": self.username_attribute,
                            "userid_attribute": self.userid_attribute,
                            "userdata": userdata
                        }
                        await self.auth_successful_callback(request, user, **args)
                except Exception as err:
                    self.logger.error(str(err))
                # If redirect_uri is set:
                if 'redirect_uri' in qs:
                    # redirect:
                    redirect = qs.pop('redirect_uri', TROCTOKEN_REDIRECT_URI)
                    return self.uri_redirect(
                        request,
                        token=token,
                        uri=redirect
                    )
                return {"token": token, **userdata}
            except Exception as err:  # pylint: disable=W0703
                self.logger.exception(
                    f"TROC Auth: Authentication Error: {err}"
                )
                return False

    async def check_credentials(self, request: web.Request, username: str, data: dict):
        """Authentication and create a session."""
        try:
            user = await self.validate_user(login=username)
        except UserNotFound:
            return False
        except Exception as err:
            raise AuthException(
                err,
                status=500
            ) from err
        userdata = self.get_userdata(user)
        try:
            # merging both session objects
            userdata[AUTH_SESSION_OBJECT] = {
                **userdata[AUTH_SESSION_OBJECT],
                **data,
            }
            return userdata
        except Exception as err:  # pylint: disable=W0703
            self.logger.exception(err)
            return False

    @web.middleware
    async def auth_middleware(
        self,
        request: web.Request,
        handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
    ) -> web.StreamResponse:
        """
        Partner Auth Middleware.
        Description: Basic Authentication for Partner Token Auth.
        """
        # avoid check system routes
        if await self.verify_exceptions(request):
            return await handler(request)
        self.logger.debug(
            f"MIDDLEWARE: {self.__class__.__name__}"
        )
        try:
            payload = None
            token = await self.get_payload(request)
            if not token:
                return await handler(request)
            try:
                data, username = await self.get_token(token)
                magic = data.pop('magic', None)
                # TODO: evaluate the Magic attribute in payload
                if userdata := await self.check_credentials(request, username, data):
                    usr = await self.create_user(userdata[AUTH_SESSION_OBJECT])
                    usr.id = username
                    usr.set(self.username_attribute, username)
                    self._set_user_request(request, usr)
                    return await handler(request)
            except InvalidAuth:
                _, payload = self._idp.decode_token(code=token)
            if not payload and AUTH_CREDENTIALS_REQUIRED is True:
                raise self.Unauthorized(
                    reason="There is no Session or Authentication is missing"
                )
            ## check if user has a session:
            # load session information
            session = await get_session(
                request, payload, new=False, ignore_cookie=True
            )
            if not session and AUTH_CREDENTIALS_REQUIRED is True:
                raise self.Unauthorized(
                    reason="There is no Session or Authentication is missing"
                )
            try:
                request.user = await self.get_session_user(session)
                request["authenticated"] = True
            except UnboundLocalError:
                pass
            except Exception as ex:  # pylint: disable=W0703
                self.logger.error(
                    f"Missing User Object from Session: {ex}"
                )
        except web.HTTPError:
            raise
        except Forbidden as err:
            self.logger.error("TROC Auth: Access Denied")
            raise self.ForbiddenAccess(
                reason=err.message
            ) from err
        except AuthExpired as err:
            self.logger.error("TROC Auth: Credentials expired")
            raise self.Unauthorized(
                reason=err.message
            ) from err
        except FailedAuth as err:
            raise self.ForbiddenAccess(
                reason=err.message
            ) from err
        except AuthException as err:
            self.logger.error("Invalid Signature or Authentication Failed")
            raise self.ForbiddenAccess(
                reason=err.message
            ) from err
        return await handler(request)
