"""Token Auth Backend.

Navigator Authentication using an API Token for partners.
description: Single API Token Authentication
"""
from collections.abc import Callable, Awaitable
import jwt
from aiohttp import web
from navigator_session import get_session
from ..exceptions import AuthException, InvalidAuth
from ..conf import (
    AUTH_JWT_ALGORITHM,
    AUTH_TOKEN_ISSUER,
    AUTH_TOKEN_SECRET,
)


# Authenticated Entity
from ..identities import AuthUser, Program
from .abstract import BaseAuthBackend


class TokenUser(AuthUser):
    tenant: str
    programs: list[Program]


class TokenAuth(BaseAuthBackend):
    """API Token Authentication Handler."""

    _pool = None
    _ident: AuthUser = TokenUser
    _description: str = "Partner Token authentication"

    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements."""

    async def on_cleanup(self, app: web.Application):
        """Used to cleanup and shutdown any db connection."""

    async def get_payload(self, request):
        token = None
        tenant = None
        try:
            if "Authorization" in request.headers:
                try:
                    scheme, token = (
                        request.headers.get("Authorization").strip().split(" ", 1)
                    )
                except ValueError as ex:
                    raise AuthException(
                        "Invalid authorization Header", status=400
                    ) from ex
                if scheme != self.scheme:
                    raise AuthException("Invalid Authorization Scheme", status=400)
                try:
                    tenant, token = token.split(":")
                except ValueError:
                    pass
        except Exception as err:  # pylint: disable=W0703
            self.logger.error(
                f"TokenAuth: Error getting payload: {err}"
            )
            return [None, None]
        return [tenant, token]

    async def reconnect(self):
        if not self.connection or not self.connection.is_connected():
            await self.connection.connection()

    async def authenticate(self, request):
        """Authenticate, refresh or return the user credentials."""
        try:
            tenant, token = await self.get_payload(request)
            self.logger.debug(
                f"Tenant ID: {tenant}"
            )
        except Exception as err:
            raise AuthException(err, status=400) from err
        if not tenant:
            # is another authorization backend
            return False
        if not token:
            raise InvalidAuth(
                "Invalid Credentials",
                status=401
            )
        else:
            payload = jwt.decode(
                token, AUTH_TOKEN_SECRET, algorithms=[AUTH_JWT_ALGORITHM], leeway=30
            )
            self.logger.debug(
                f"Decoded Token: {payload!s}"
            )
            data = await self.check_token_info(request, tenant, payload)
            if not data:
                raise InvalidAuth(
                    f"Invalid Session: {token!s}", status=401
                )
            # getting user information
            # making validation
            try:
                username = data["partner"]
                grants = data["grants"]
                programs = data["programs"]
            except KeyError as err:
                raise InvalidAuth(
                    f"Missing attributes for Partner Token: {err!s}", status=401
                ) from err
            # TODO: Validate that partner (tenants table):
            try:
                userdata = dict(data)
                uid = data["name"]
                userdata[self.session_key_property] = uid
                usr = await self.create_user(userdata)
                usr.id = uid
                usr.set(self.username_attribute, uid)
                usr.programs = programs
                usr.tenant = tenant
                # saving user-data into request:
                session = await self.remember(request, uid, userdata, usr)
                user = {
                    "name": data["name"],
                    "partner": username,
                    "issuer": AUTH_TOKEN_ISSUER,
                    "programs": programs,
                    "grants": grants,
                    "tenant": tenant,
                    "id": data["name"],
                    "user_id": uid,
                    self.session_id_property: session.session_id
                }
                token, exp, scheme = self._idp.create_token(data=user)
                usr.access_token = token
                usr.token_type = scheme
                usr.expires_in = exp
                return {"token": f"{tenant}:{token}", **user}
            except Exception as err:  # pylint: disable=W0703
                self.logger.exception(f"TokenAuth: Authentication Error: {err}")
                return False

    async def check_credentials(self, request):
        pass

    async def check_token_info(self, request, tenant, payload):
        try:
            name = payload["name"]
            partner = payload["partner"]
        except KeyError:
            return False
        sql = """
        SELECT name, partner, grants, programs FROM auth.partner_keys
        WHERE name=$1 AND partner=$2
        AND enabled = TRUE AND revoked = FALSE AND $3= ANY(programs)
        """
        app = request.app
        pool = app["authdb"]
        try:
            result = None
            async with await pool.acquire() as conn:
                result, error = await conn.queryrow(sql, name, partner, tenant)
                if error or not result:
                    return False
                else:
                    return result
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
        Token Auth Middleware.
        Description: Token Middleware.
        """
        # avoid check system routes
        if await self.verify_exceptions(request):
            return await handler(request)
        # self.logger.debug(f'MIDDLEWARE: {self.__class__.__name__}')
        tenant, jwt_token = await self.get_payload(request)
        if not tenant:
            return await handler(request)
        if jwt_token:
            try:
                payload = jwt.decode(
                    jwt_token,
                    AUTH_TOKEN_SECRET,
                    algorithms=[AUTH_JWT_ALGORITHM],
                    leeway=30,
                )
                self.logger.debug(f"Decoded Token: {payload!s}")
                result = await self.check_token_info(request, tenant, payload)
                if result:
                    request["authenticated"] = True
                    try:
                        request[self.session_key_property] = payload["name"]
                        # TRUE because if data doesnt exists, returned
                        session = await get_session(
                            request, payload, new=True, ignore_cookie=True
                        )
                        session["grants"] = result["grants"]
                        session["partner"] = result["partner"]
                        session["tenant"] = tenant
                    except (AttributeError, KeyError, TypeError) as err:
                        self.logger.warning(f"Error loading Token Session {err}")
                    try:
                        request.user = session.decode("user")
                        request.user.is_authenticated = True
                    except (AttributeError, KeyError):
                        pass
            except web.HTTPError:
                raise
            except jwt.exceptions.ExpiredSignatureError as err:
                self.logger.error(f"TokenAuth: token expired: {err!s}")
                raise web.HTTPForbidden(
                    reason=f"TokenAuth: token expired: {err!s}"
                ) from err
            except jwt.exceptions.InvalidSignatureError as err:
                self.logger.error(f"Invalid Credentials: {err!r}")
                raise web.HTTPForbidden(
                    reason=f"TokenAuth: Invalid or missing Credentials: {err!r}"
                ) from err
            except jwt.exceptions.DecodeError as err:
                self.logger.error(f"Invalid authorization token: {err!r}")
                raise web.HTTPForbidden(
                    reason=f"TokenAuth: Invalid authorization token: {err!r}"
                ) from err
            except AuthException as err:
                self.logger.error("TokenAuth: Authentication failed.")
                raise self.Unauthorized(
                    reason="TokenAuth: Authentication failed.",
                    exception=err
                ) from err
        return await handler(request)
