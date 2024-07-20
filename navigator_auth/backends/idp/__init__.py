import time
from datetime import datetime, timedelta
import hashlib
import base64
import secrets
import importlib
import jwt
from aiohttp import web, hdrs
from asyncdb.exceptions import NoDataFound
from datamodel.exceptions import ValidationError
from navconfig.logging import logging
from navigator_session import (
    SESSION_TIMEOUT
)
from ...identities import Identity
from ...conf import (
    AUTH_TOKEN_ISSUER,
    AUTH_USERID_ATTRIBUTE,
    AUTH_USERNAME_ATTRIBUTE,
    AUTH_PASSWORD_ATTRIBUTE,
    USER_MAPPING,
    AUTH_USER_VIEW,
    AUTH_USER_MODEL,
    AUTH_PWD_ALGORITHM,
    AUTH_PWD_SALT_LENGTH,
    AUTH_PWD_DIGEST,
    AUTH_PWD_LENGTH,
    AUTH_CODE_EXPIRATION,
    AUTH_JWT_ALGORITHM,
    SECRET_KEY,
    AUTH_DEFAULT_SCHEME
)
from ...exceptions import (
    UserNotFound,
    ConfigError,
    InvalidAuth,
    FailedAuth,
    AuthExpired,
    AuthException
)
from ...libs import DefaultEncoder

class IdentityProvider:
    """IdP.

    Identity Provider for Navigator.
    """
    userid_attribute: str = AUTH_USERID_ATTRIBUTE
    username_attribute: str = AUTH_USERNAME_ATTRIBUTE
    pwd_atrribute: str = AUTH_PASSWORD_ATTRIBUTE
    scheme: str = AUTH_DEFAULT_SCHEME
    session_timeout: int = int(SESSION_TIMEOUT)
    user_mapping = USER_MAPPING

    def __init__(self):
        ## List of Authorization codes emmited:
        self.authorization_codes: dict = {}
        # Application
        self.app: web.Application = None
        # logger
        self.logger = logging.getLogger(
            "Auth.IdP"
        )
        # get search model:
        try:
            self.user_search = self.get_usermodel(
                AUTH_USER_VIEW
            )
            self.logger.debug(
                f"User Model: {self.user_search}"
            )
            # Get User Model:
            self.user_model = self.get_usermodel(
                AUTH_USER_MODEL
            )
        except Exception as ex:
            raise ConfigError(
                f"Error Getting Auth User Model: {ex}"
            ) from ex

    def setup(self, app: web.Application):
        self.app = app
        self.logger.notice(
            ":: Initializing Identity Provider ::"
        )
        # Code Management

    def get_usermodel(self, model: str):
        try:
            parts = model.split(".")
            name = parts[-1]
            classpath = ".".join(parts[:-1])
            module = importlib.import_module(classpath, package=name)
            obj = getattr(module, name)
            return obj
        except ImportError as ex:
            raise ConfigError(
                f"Auth: Error loading Auth User Model {model}: {ex}"
            ) from ex

    async def user_from_id(self, uid: int) -> Identity:
        """Getting User Object."""
        user = None
        try:
            db = self.app["authdb"]
            async with await db.acquire() as conn:
                search = {self.userid_attribute: uid}
                self.user_search.Meta.connection = conn
                user = await self.user_search.get(**search)
        except NoDataFound as ex:
            raise UserNotFound(
                f"Invalid credentials for User {search!s}"
            ) from ex
        except ValidationError as ex:
            self.logger.error(
                f"Invalid User Information {search!s}: {ex}"
            )
            self.logger.warning(
                f"Error on User Model = {ex.payload!r}"
            )
            raise
        except Exception as e:
            raise UserNotFound(
                f"Error getting User {search!s}: {e!s}"
            ) from e
        # if not exists, return error of missing
        if not user:
            raise UserNotFound(
                f"Invalid credentials for User {search!s}"
            )
        return user

    async def get_user(self, login: str) -> Identity:
        """Getting User Object."""
        user = None
        try:
            db = self.app["authdb"]
            async with await db.acquire() as conn:
                search = {self.username_attribute: login}
                self.user_search.Meta.connection = conn
                user = await self.user_search.get(**search)
                if user:
                    return user
                raise UserNotFound(
                    f"Invalid Credentials for {search!s}"
                )
        except UserNotFound:
            raise
        except NoDataFound as ex:
            self.logger.error(
                f"User {search!s} not found: {ex}"
            )
            raise UserNotFound(
                f"Invalid Credentials for {search!s}"
            ) from ex
        except TypeError as ex:
            self.logger.error(
                f"Error on User Data {search!s}: {ex}"
            )
            raise
        except ValidationError as ex:
            self.logger.error(
                f"Invalid User Information {search!s}: {ex}"
            )
            self.logger.warning(
                f"{ex.payload!r}"
            )
            raise
        except Exception as e:
            self.logger.error(
                f"Error getting User {search!s}: {e!s}"
            )
            raise UserNotFound(
                f"Invalid User credentials for: {search!s}: {e!s}"
            ) from e

    async def authenticate_credentials(self, login: str = None, password: str = None):
        try:
            user = await self.get_user(login)
        except ValidationError as ex:
            raise InvalidAuth(
                f"User: Invalid {ex.payload}"
            ) from ex
        except UserNotFound:
            raise
        except Exception as err:
            raise InvalidAuth(
                f"User: Auth Exception: {err}"
            ) from err
        try:
            # later, check the password
            pwd = user[self.pwd_atrribute]
        except (KeyError, ValidationError, TypeError, ValueError) as ex:
            raise InvalidAuth(
                "Invalid credentials for User"
            ) from ex
        try:
            if self.check_password(pwd, password):
                # return the user Object
                return user
            else:
                raise FailedAuth(
                    "Basic Auth: Invalid Credentials"
                )
        except (InvalidAuth, FailedAuth, UserNotFound) as err:
            self.logger.error(err)
            raise
        except Exception as err:
            raise InvalidAuth(
                f"Unknown Error: {err}"
            ) from err

    def check_password(self, current_password, password):
        try:
            if current_password is None:
                raise InvalidAuth(
                    "User: Password cannot be null.",
                    status=412
                )
            algorithm, iterations, salt, _ = current_password.split("$", 3)
        except ValueError as ex:
            if str(ex).startswith('not enough values to unpack'):
                raise InvalidAuth(
                    "Invalid Password: user password doesn't match \
                    algorithm requirements"
                ) from ex
            raise InvalidAuth(
                f"Basic Auth: Invalid Credentials: {ex}"
            ) from ex
        assert algorithm == AUTH_PWD_ALGORITHM
        compare_hash = self.set_password(
            password,
            iterations=int(iterations),
            salt=salt,
            token_num=AUTH_PWD_SALT_LENGTH,
        )
        return secrets.compare_digest(current_password, compare_hash)

    def set_password(
        self,
        password: str,
        token_num: int = 6,
        iterations: int = 80000,
        salt: str = None,
    ):
        if not salt:
            salt = secrets.token_hex(token_num)
        key = hashlib.pbkdf2_hmac(
            AUTH_PWD_DIGEST,
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
            dklen=AUTH_PWD_LENGTH,
        )
        hst = base64.b64encode(key).decode("utf-8").strip()
        return f"{AUTH_PWD_ALGORITHM}${iterations}${salt}${hst}"

    def generate_authorization_code(self, client_id, redirect_uri):
        ## TODO: add Client and Redirect URI Validation
        expiration_date = time.time() + AUTH_CODE_EXPIRATION
        payload = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "issuer": AUTH_TOKEN_ISSUER,
            "exp": expiration_date
        }
        authzcode = jwt.encode(payload, SECRET_KEY, algorithm=AUTH_JWT_ALGORITHM)
        self.authorization_codes[authzcode] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "exp": expiration_date
        }
        return authzcode

    def check_authorization_code(self, code, client_id, redirect_uri):
        # First check if code exists in the dictionary
        # TODO: migrate to Redis
        if code not in self.authorization_codes:
            return False

        # Now let's validate the token
        try:
            # Decode the token, this will also automatically verify the token expiration
            payload = jwt.decode(code, SECRET_KEY, algorithms=[AUTH_JWT_ALGORITHM])

            if payload['issuer'] != AUTH_TOKEN_ISSUER:
                self.logger.error(
                    'User: Invalid Authorization Code Issuer'
                )
                return False

            # Now let's check that the client_id and redirect_uri in
            # the payload match what we expect
            if payload['client_id'] != client_id:
                self.logger.error(
                    'User: Client ID mismatch'
                )
                return False

            if payload['redirect_uri'] != redirect_uri:
                return False

        except jwt.ExpiredSignatureError:
            # Token is expired. Remove it from the dictionary and return False
            del self.authorization_codes[code]
            return False

        except jwt.InvalidTokenError:
            # Token is invalid. Remove it from the dictionary and return False
            del self.authorization_codes[code]
            return False

        # If we made it here, the token is valid!
        return True

    def create_refresh_token(self) -> str:
        # Generate a refresh token
        return secrets.token_urlsafe(32)

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

    def create_token(
        self,
        data: dict = None,
        issuer: str = None,
        expiration: int = None
    ) -> str:
        """Creation of JWT tokens based on basic parameters.
        issuer: for default, urn:Navigator
        expiration: in seconds
        **kwargs: data to put in payload
        """
        try:
            del data['exp']
            del data['iat']
            del data['iss']
            del data['aud']
        except KeyError:
            pass
        if not expiration:
            expiration = self.session_timeout
        if not issuer:
            issuer = AUTH_TOKEN_ISSUER
        if not data:
            data = {}
        iat = datetime.utcnow()
        exp = (iat + timedelta(seconds=expiration)).timestamp()
        payload = {
            "exp": exp,
            "iat": iat,
            "iss": issuer,
            **data,
        }
        try:
            jwt_token = jwt.encode(
                payload,
                SECRET_KEY,
                AUTH_JWT_ALGORITHM,
                json_encoder=DefaultEncoder
            )
        except (TypeError, ValueError) as ex:
            raise AuthException(
                f"Cannot Create Session Token: {ex!s}"
            ) from ex
        return jwt_token, exp, self.scheme

    def decode_token(
        self,
        code: str,
        issuer: str = None
    ):
        payload = None
        tenant = None
        if not code:
            return [None, None]
        if not issuer:
            issuer = AUTH_TOKEN_ISSUER
        try:
            tenant, jwt_token = code.split(":")
        except (TypeError, ValueError, AttributeError):
            # normal Token:
            jwt_token = code
        if not jwt_token:
            return [None, None]
        try:
            payload = jwt.decode(
                jwt_token,
                SECRET_KEY,
                algorithms=[AUTH_JWT_ALGORITHM],
                iss=issuer,
                leeway=30,
            )
            self.logger.debug(
                f"Decoded Token: {payload!s}"
            )
            return [tenant, payload]
        except jwt.exceptions.ExpiredSignatureError as exc:
            raise AuthExpired(
                f"Credentials Expired: {exc!s}"
            ) from exc
        except jwt.exceptions.InvalidSignatureError as exc:
            raise AuthExpired(
                f"Signature Failed or Expired: {exc!s}"
            ) from exc
        except jwt.exceptions.DecodeError as exc:
            raise FailedAuth(
                f"Token Decoding Error: {exc}"
            ) from exc
        except jwt.exceptions.InvalidTokenError as exc:
            raise InvalidAuth(
                f"Invalid authorization token {exc!s}"
            ) from exc
        except Exception as err:
            raise AuthException(
                str(err),
                status=501
            ) from err
