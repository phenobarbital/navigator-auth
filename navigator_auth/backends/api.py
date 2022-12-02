"""Token Auth Backend.

Navigator Authentication using an API Token for partners.
description: Single API Token Authentication
"""
import jwt
import orjson
from aiohttp import web
from aiohttp.web_urldispatcher import SystemRoute
from navigator_auth.libs.cipher import Cipher
from navigator_auth.exceptions import AuthException, InvalidAuth
from navigator_auth.conf import (
    AUTH_CREDENTIALS_REQUIRED,
    AUTH_JWT_ALGORITHM,
    AUTH_TOKEN_ISSUER,
    AUTH_TOKEN_SECRET,
    SECRET_KEY
)
# Authenticated Entity
from navigator_auth.identities import AuthUser
from .abstract import BaseAuthBackend

class APIKeyUser(AuthUser):
    token: str
    api_key: str

class APIKeyAuth(BaseAuthBackend):
    """API Token Authentication Handler."""

    _pool = None
    _ident: AuthUser = APIKeyUser

    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements.
        """
        self.cipher = Cipher(AUTH_TOKEN_SECRET, type='AES')

    async def on_cleanup(self, app: web.Application):
        """Used to cleanup and shutdown any db connection.
        """

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
                    mech = 'bearer'
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
                if ':' in token:
                    # is an Partner Token, not API
                    return [None, None]
            elif 'apikey' in request.rel_url.query:
                token = request.rel_url.query['apikey']
                mech = 'api'
            else:
                return [None, None]
        except Exception as err: # pylint: disable=W0703
            self.logger.exception(f"API Key Auth: Error getting payload: {err}")
            return None
        return [mech, token]

    async def reconnect(self):
        if not self.connection or not self.connection.is_connected():
            await self.connection.connection()

    async def authenticate(self, request):
        """ Authenticate, refresh or return the user credentials."""
        try:
            mech, token = await self.get_payload(request)
        except Exception as err:
            raise AuthException(
                str(err), status=400
            ) from err
        if not token or not mech:
            return None
        else:
            if mech == 'bearer':
                payload = jwt.decode(
                    token,
                    SECRET_KEY,
                    algorithms=[AUTH_JWT_ALGORITHM],
                    leeway=30
                )
            elif mech == 'api':
                payload = orjson.loads(
                    self.cipher.decode(token)
                )
            # getting user information
            data = await self.check_token_info(request, mech, payload)
            if not data:
                return None
            try:
                device = data["name"]
                device_id = str(data["device_id"])
                user_id = data["user_id"]
            except KeyError as err:
                raise InvalidAuth(
                    f"Missing attributes for API Key: {err!s}",
                    status=401
                ) from err
            # TODO: Validate that partner (tenants table):
            try:
                user = {
                    "name": device,
                    "username": user_id,
                    "issuer": AUTH_TOKEN_ISSUER,
                    "id": device_id,
                    "user_id": user_id,
                }
                user[self.session_key_property] = user_id
                usr = await self.create_user(user)
                usr.set(self.username_attribute, user_id)
                self.logger.debug(f'User Created: {usr}')
                # usr.access_token = data['token']
                # saving user-data into request:
                await self.remember(
                    request, device_id, user, usr
                )
                return {
                    "token": token,
                    **user
                }
            except Exception as err: # pylint: disable=W0703
                self.logger.exception(
                    f'API Key Auth: Authentication Error: {err}'
                )
                return False

    async def check_token_info(self, request, mech, payload):
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
        pool = app['authdb']
        try:
            result = None
            async with await pool.acquire() as conn:
                result, error = await conn.queryrow(sql, user_id, device_id)
                if error or not result:
                    return False
                else:
                    return result
        except Exception as err: # pylint: disable=W0703
            self.logger.exception(err)
            return False

    async def check_credentials(self, request):
        pass

    async def auth_middleware(self, app, handler):
        async def middleware(request):
            request.user = None
            # avoid check system routes
            try:
                if isinstance(request.match_info.route, SystemRoute):  # eg. 404
                    return await handler(request)
            except Exception as err: # pylint: disable=W0703
                self.logger.error(err)
            try:
                if request.get('authenticated', False) is True:
                    # already authenticated
                    return await handler(request)
            except KeyError:
                pass
            self.logger.debug(f'MIDDLEWARE: {self.__class__.__name__}')
            try:
                userdata = await self.authenticate(request)
                if userdata:
                    request['authenticated'] = True
                    request[self.session_key_property] = userdata['user_id']
            except (InvalidAuth) as err:
                raise web.HTTPForbidden(
                    reason=f"API Key: {err.message!s}"
                )
            except AuthException as err:
                if AUTH_CREDENTIALS_REQUIRED is True:
                    self.logger.error(
                        f"Invalid authorization token: {err!r}"
                    )
                    raise web.HTTPForbidden(
                        reason=f"API Key: Invalid authorization Key: {err!r}"
                    )
            except Exception as err:
                if AUTH_CREDENTIALS_REQUIRED is True:
                    self.logger.exception(f"Error on API Key Middleware: {err}")
                    raise web.HTTPBadRequest(
                        reason=f"API Auth Error: {err}"
                    )
            return await handler(request)

        return middleware
