"""Token Auth Backend.

Navigator Authentication using an API Token.
description: Single API Token Authentication
"""
from collections.abc import Callable, Awaitable
import orjson
from aiohttp import web
from navigator_session import get_session
from ..libs.cipher import Cipher
from ..exceptions import (
    AuthException,
    InvalidAuth,
    FailedAuth,
    AuthExpired,
    UserNotFound
)
from ..conf import (
    AUTH_CREDENTIALS_REQUIRED,
    AUTH_USERID_ATTRIBUTE,
    AUTH_TOKEN_SECRET,
    AUTH_SESSION_OBJECT,
)
# Authenticated Entity
from ..identities import AuthUser
from .abstract import BaseAuthBackend

class APIKeyUser(AuthUser):
    token: str
    api_key: str


class APIKeyAuth(BaseAuthBackend):
    """API Token Authentication Handler."""

    _pool = None
    _ident: AuthUser = APIKeyUser
    _description: str = "API Key authentication"

    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements."""
        self.cipher = Cipher(AUTH_TOKEN_SECRET, type="AES")

    async def on_cleanup(self, app: web.Application):
        """Used to cleanup and shutdown any db connection."""

    async def get_payload(self, request):
        token = None
        mech = None
        try:
            if "Authorization" in request.headers:
                # Bearer Token (jwt)
                try:
                    scheme, token = (
                        request.headers.get("Authorization").strip().split(" ", 1)
                    )
                    mech = "bearer"
                except ValueError as ex:
                    raise AuthException(
                        "Invalid authorization Header",
                        status=400
                    ) from ex
                if scheme != self.scheme:
                    raise AuthException(
                        "Invalid Authorization Scheme",
                        status=400
                    )
                if ":" in token:
                    # is an Partner Token, not API
                    return [None, None]
            elif 'X-API-KEY' in request.headers:
                token = request.headers.get('X-API-KEY')
                mech = "api"
            elif "apikey" in request.rel_url.query:
                token = request.rel_url.query["apikey"]
                mech = "api"
            else:
                return [None, None]
        except Exception as err:  # pylint: disable=W0703
            self.logger.exception(
                f"API Key Auth: Error getting payload: {err}"
            )
            return None
        return [mech, token]

    async def reconnect(self):
        if not self.connection or not self.connection.is_connected():
            await self.connection.connection()

    async def get_token_info(self, request: web.Request, mech: str, token: str) -> dict:
        payload = None
        if mech == "bearer":
            try:
                _, payload = self._idp.decode_token(token)
            except (FailedAuth, AuthExpired, InvalidAuth):
                raise
        elif mech == "api":
            try:
                payload = orjson.loads(self.cipher.decode(token))
            except (TypeError, ValueError):
                raise InvalidAuth(
                    "Invalid Token",
                    status=401
                )
        # getting user information
        return await self.check_token_info(request, payload)

    async def authenticate(self, request):
        """Authenticate, refresh or return the user credentials."""
        try:
            mech, token = await self.get_payload(request)
        except Exception as err:
            raise AuthException(str(err), status=400) from err
        if not token or not mech:
            return None
        else:
            data = await self.get_token_info(request, mech, token)
            try:
                device_id = str(data["device_id"])
                user_id = data["user_id"]
            except KeyError as err:
                raise InvalidAuth(
                    f"Missing attributes for API Key: {err!s}",
                    status=401
                ) from err
            try:
                user = await self.validate_user(userid=user_id)
            except UserNotFound:
                raise
            except Exception as err:  # pylint: disable=W0703
                self.logger.exception(err)
                raise AuthException(
                    "Error on User Validation",
                    status=401
                ) from err
            userdata = self.get_userdata(user)
            # merging both session objects
            userdata[AUTH_SESSION_OBJECT] = {
                **userdata[AUTH_SESSION_OBJECT],
                **data,
            }
            try:
                userdata[AUTH_USERID_ATTRIBUTE] = user_id
                userdata[self.session_key_property] = device_id
                userdata[self.username_attribute] = data.get('name', user_id)
                userdata['auth_method'] = 'apikey'
                userdata['token'] = token
                usr = await self.create_user(userdata)
                # saving user-data into request:
                await self.remember(request, device_id, userdata, usr)
                return {"token": token, **userdata}
            except Exception as err:  # pylint: disable=W0703
                self.logger.exception(
                    f"API Key Auth: Authentication Error: {err}"
                )
                return False

    async def check_token_info(self, request, payload):
        try:
            user_id = payload["user_id"]
            device_id = payload["device_id"]
        except KeyError:
            return False
            ##
        sql = """
         SELECT user_id, name, device_id, token FROM auth.api_keys
         WHERE user_id=$1 AND device_id=$2
         AND revoked = FALSE
        """
        app = request.app
        pool = app["authdb"]
        try:
            result = None
            async with await pool.acquire() as conn:
                result, error = await conn.queryrow(sql, user_id, device_id)
                if error or not result:
                    return False
                else:
                    return result
        except Exception as err:  # pylint: disable=W0703
            self.logger.exception(err)
            return False

    async def check_credentials(self, request: web.Request):
        """Check if Current credentials are valid."""
        mech, token = await self.get_payload(request)
        if not token or not mech:
            return False
        try:
            data = await self.get_token_info(request, mech, token)
            if not data:
                return False
            userid = data.get(AUTH_USERID_ATTRIBUTE, None)
            user = await self.validate_user(userid=userid)
        except AuthExpired:
            raise
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
            userdata[AUTH_USERID_ATTRIBUTE] = userid
            userdata[self.session_key_property] = str(data["device_id"])
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
        request.user = None
        # avoid check system routes
        if await self.verify_exceptions(request):
            return await handler(request)
        try:
            if request.get("authenticated", False) is True:
                # already authenticated
                return await handler(request)
        except KeyError:
            pass
        try:
            if (userdata := await self.check_credentials(request)):
                try:
                    userid = userdata.get('user_id')
                    request[self.session_key_property] = userdata.get(
                        self.session_key_property,
                        userid
                    )
                    session = await get_session(
                        request, userdata, new=True, ignore_cookie=True
                    )
                    request.user = await self.get_session_user(session)
                    request["authenticated"] = True
                except Exception as ex:  # pylint: disable=W0703
                    self.logger.error(
                        f"Missing User Object from Session: {ex}"
                    )
        except (FailedAuth, InvalidAuth) as err:
            raise self.Unauthorized(
                reason=f"API Key: {err.message!s}",
                exception=err
            )
        except AuthExpired as err:
            raise self.Unauthorized(
                reason=f"API Key Expired: {err.message!s}",
                exception=err
            )
        except AuthException as err:
            if AUTH_CREDENTIALS_REQUIRED is True:
                self.logger.error(
                    f"Invalid authorization token: {err!r}"
                )
                raise self.Unauthorized(
                    reason=f"API Key: Invalid authorization Key: {err!r}",
                    exception=err
                )
        except Exception as err:
            if AUTH_CREDENTIALS_REQUIRED is True:
                self.logger.exception(f"Error on API Key Middleware: {err}")
                raise self.auth_error(
                    reason="API Auth Error",
                    exception=err
                ) from err
        return await handler(request)
