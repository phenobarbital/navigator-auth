"""JWT Backend.

Navigator Authentication using JSON Web Tokens.
"""
import logging
from aiohttp import web
from navigator_session import AUTH_SESSION_OBJECT
from navigator_session import SESSION_KEY, SESSION_ID, SessionHandler, get_session
from datamodel.exceptions import ValidationError
# Authenticated Entity
from ..conf import (
    BASIC_USER_MAPPING,
    exclude_list
)
from .abstract import BaseAuthBackend
from ..exceptions import (
    AuthException,
    FailedAuth,
    UserNotFound,
    InvalidAuth,
)
from ..responses import JSONResponse
from ..identities import AuthUser

class BasicUser(AuthUser):
    """BasicAuth.

    Basic authenticated user.
    """


# "%s$%d$%s$%s" % (algorithm, iterations, salt, hash)
class BasicAuth(BaseAuthBackend):
    """Basic User/password Authentication."""

    user_attribute: str = "user"
    pwd_atrribute: str = "password"
    _ident: AuthUser = BasicUser
    _description: str = "Basic User/Password authentication"
    _service_name: str = "basic"

    def configure(self, app):
        router = app.router
        check_credentials = f"/auth/{self._service_name}/check_credentials"
        router.add_route(
            "GET",
            check_credentials,
            self.check_credentials,
            name=f"{self._service_name}_check_credentials",
        )
        exclude_list.append(check_credentials)
        super().configure(app)

    async def on_startup(self, app: web.Application):
        """Used to initialize Backend requirements."""
        ## Using Startup for detecting and loading functions.
        if self._success_callbacks:
            # self._user_model = self.get_authmodel(AUTH_USER_MODEL)
            self._user_model = self._idp.user_model
            self.get_successful_callbacks()

    async def on_cleanup(self, app: web.Application):
        """Used to cleanup and shutdown any db connection."""

    async def validate_user(self, login: str = None, password: str = None):
        # get the user based on Model
        try:
            # search = {self.username_attribute: }
            user = await self._idp.get_user(login)
        except ValidationError as ex:
            raise InvalidAuth(
                f"Invalid User Information: {ex.payload}"
            ) from ex
        except (InvalidAuth, FailedAuth, UserNotFound):
            raise
        except Exception as err:
            raise InvalidAuth(
                f"{err}"
            ) from err
        try:
            # later, check the password
            pwd = user[self.pwd_atrribute]
        except KeyError as ex:
            raise InvalidAuth(
                f"Missing Password attribute on User {login}"
            ) from ex
        except (ValidationError, TypeError, ValueError) as ex:
            raise InvalidAuth(
                f"Invalid credentials on User {login}"
            ) from ex
        try:
            if self._idp.check_password(pwd, password):
                # return the user Object
                return user
            else:
                raise FailedAuth(
                    f"User {login}: Invalid Credentials"
                )
        except FailedAuth as err:
            self.logger.error(err)
            raise
        except InvalidAuth as err:
            self.logger.error(err)
            raise
        except Exception as err:
            raise InvalidAuth(
                f"Unknown Password Error: {err}"
            ) from err

    async def get_payload(self, request):
        ctype = request.content_type
        if request.method == "GET":
            try:
                user = request.query.get(self.username_attribute, None)
                password = request.query.get(self.pwd_atrribute, None)
                return [user, password]
            except Exception:  # pylint: disable=W0703
                return [None, None]
        elif ctype in (
            "multipart/mixed",
            "multipart/form-data",
            "application/x-www-form-urlencoded",
        ):
            data = await request.post()
            if len(data) <= 0:
                return [None, None]
            user = data.get(self.username_attribute, None)
            password = data.get(self.pwd_atrribute, None)
            return [user, password]
        elif ctype == "application/json":
            try:
                data = await request.json()
                user = data[self.username_attribute]
                password = data[self.pwd_atrribute]
                return [user, password]
            except Exception:  # pylint: disable=W0703
                return [None, None]
        else:
            return [None, None]

    async def authenticate(self, request):
        """Authenticate, refresh or return the user credentials."""
        try:
            user, pwd = await self.get_payload(request)
        except Exception as err:
            raise AuthException(
                str(err),
                status=400
            ) from err
        if not pwd and not user:
            raise InvalidAuth(
                "Basic Auth: Missing Credentials",
                status=401
            )
        else:
            # making validations
            try:
                user = await self.validate_user(
                    login=user, password=pwd
                )
            except (FailedAuth, UserNotFound, InvalidAuth):  # pylint: disable=W0706
                raise
            except (ValidationError) as err:
                raise InvalidAuth(str(err), status=401) from err
            except Exception as err:
                raise AuthException(
                    str(err),
                    status=500
                ) from err
            try:
                userdata = self.get_userdata(user=user)
                username = user[self.username_attribute]
                uid = user[self.userid_attribute]
                userdata[self.username_attribute] = username
                userdata[self.session_key_property] = username
                usr = await self.create_user(userdata[AUTH_SESSION_OBJECT])
                usr.id = uid
                usr.set(self.username_attribute, username)
                for key, val in BASIC_USER_MAPPING.items():
                    userdata[key] = user[val]
                ### saving User data into session:
                session = await self.remember(request, username, userdata, usr)
                payload = {
                    self.user_property: user[self.userid_attribute],
                    self.username_attribute: username,
                    "user_id": uid,
                    self.session_key_property: username,
                    self.session_id_property: session.session_id
                }
                # Create the User session and returned.
                token, exp, scheme = self._idp.create_token(data=payload)
                usr.access_token = token
                usr.token_type = scheme
                usr.expires_in = exp
                userdata['expires_in'] = exp
                userdata['token_type'] = scheme
                userdata['auth_method'] = "basic"
                # invoke callbacks to update user data:
                if user and self._callbacks:
                    # construir e invocar callbacks para actualizar data de usuario
                    args = {
                        "username_attribute": self.username_attribute,
                        "userid_attribute": self.userid_attribute,
                        "userdata": userdata
                    }
                    await self.auth_successful_callback(request, user, **args)
                ### check if any callbacks exists:
                return {"token": token, **userdata}
            except Exception as err:  # pylint: disable=W0703
                self.logger.exception(
                    f"BasicAuth: Authentication Error: {err}"
                )
                return False

    async def check_credentials(self, request):
        """Using for check the user credentials to the backend."""
        try:
            token = await self._idp.get_payload(request)
            _, payload = self._idp.decode_token(code=token)
            username = payload.get(self.username_attribute)
            user = await self._idp.get_user(username)
            if not user:
                raise UserNotFound(
                    f"User {username} not found"
                )
        except UserNotFound as err:
            self.logger.error(
                f"User Not Found: {err}"
            )
            raise self.Unauthorized(
                reason="User Not Found"
            ) from err
        except Exception as err:
            self.logger.error(
                f"Auth Middleware: Access Denied: {err}"
            )
            raise self.Unauthorized(
                reason=err.message
            ) from err
        # User information:
        session_id = payload.get(SESSION_ID, None)
        userdata = self.get_userdata(user=user)
        if session_id:
            userdata[SESSION_ID] = session_id
        if not userdata:
            raise InvalidAuth(
                "Invalid User Information"
            )
        uid = user[self.userid_attribute]
        usr = await self.create_user(userdata[AUTH_SESSION_OBJECT])
        usr.id = uid
        usr.set(self.username_attribute, username)
        # load session information
        try:
            session = await self.remember(request, username, userdata, usr)
            try:
                request.user = await self.get_session_user(session)
                self._set_user_request(request, usr)
                sessioninfo = {
                    "status": "success",
                    "message": "User Authenticated",
                    "username": username,
                    "session": userdata
                }
                return JSONResponse(sessioninfo, status=200)
            except Exception as ex:  # pylint: disable=W0703
                self.logger.error(
                    f"Missing User Object from Session: {ex}"
                )
        except Exception as err:
            raise self.Unauthorized(
                reason=err.message
            ) from err
