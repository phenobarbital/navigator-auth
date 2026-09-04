import time
from typing import Union
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import hashlib
import base64
import secrets
import importlib
import jwt
from aiohttp import web, hdrs
from asyncdb.exceptions import NoDataFound
from datamodel.exceptions import ValidationError
from navconfig.logging import logging
from navigator_session import SESSION_TIMEOUT
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
    OAUTH_JWT_SIGNING_ALG,
    OAUTH_JWT_KEYS,
    AUTH_DEFAULT_SCHEME,
)
from ...exceptions import UserNotFound, ConfigError, InvalidAuth, FailedAuth, AuthExpired, AuthException
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
        self.logger = logging.getLogger("Auth.IdP")
        # get search model:
        try:
            self.user_search = self.get_usermodel(AUTH_USER_VIEW)
            self.logger.debug(f"User Model: {self.user_search}")
            # Get User Model:
            self.user_model = self.get_usermodel(AUTH_USER_MODEL)
        except Exception as ex:
            raise ConfigError(f"Error Getting Auth User Model: {ex}") from ex

    def setup(self, app: web.Application):
        self.app = app
        self.logger.notice(":: Initializing Identity Provider ::")
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
            raise ConfigError(f"Auth: Error loading Auth User Model {model}: {ex}") from ex

    async def get_user_identity_credential(
        self, user_id, provider: str, *, auto_refresh: bool = True
    ) -> dict:
        """Serve a user's linked-identity credential to in-process consumers.

        Decrypts the stored credential for (user, provider) from
        auth.user_identities; when it is expired/expiring and a refresh
        token is stored, refreshes it against the provider first.

        Raises UserNotFound when no identity is linked; ConfigError when
        the identity cipher is not configured.
        """
        from ...identity.crypto import IdentityCipher
        from ...identity.store import IdentityStore
        from ...conf import IDENTITY_REFRESH_LEEWAY

        db = self.app["authdb"]
        store = IdentityStore(db, cipher=IdentityCipher())
        identity = await store.get_by_provider(user_id, provider)
        if not identity:
            raise UserNotFound(
                f"No linked identity for user {user_id} on {provider}"
            )
        token = store.decrypt_credential(identity)
        if auto_refresh and token.is_expiring(leeway=IDENTITY_REFRESH_LEEWAY):
            if not token.refresh_token:
                raise ConfigError(
                    f"{provider}: credential expired and no refresh token "
                    "stored; the identity must be re-linked."
                )
            auth = self.app.get("auth")
            backend = auth.get_external_backend(provider) if auth else None
            if backend is None:
                raise ConfigError(
                    f"{provider}: backend not enabled; cannot refresh."
                )
            token = await backend.refresh_identity_tokens(token.refresh_token)
            await store.update_tokens(identity, token)
        return token.credential()

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
            raise UserNotFound(f"Invalid credentials for User {search!s}") from ex
        except ValidationError as ex:
            self.logger.error(f"Invalid User Information {search!s}: {ex}")
            self.logger.warning(f"Error on User Model = {ex.payload!r}")
            raise
        except Exception as e:
            raise UserNotFound(f"Error getting User {search!s}: {e!s}") from e
        # if not exists, return error of missing
        if not user:
            raise UserNotFound(f"Invalid credentials for User {search!s}")
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
                raise UserNotFound(f"Invalid Credentials for {search!s}")
        except UserNotFound:
            raise
        except NoDataFound as ex:
            self.logger.error(f"User {search!s} not found: {ex}")
            raise UserNotFound(f"Invalid Credentials for {search!s}") from ex
        except TypeError as ex:
            self.logger.error(f"Error on User Data {search!s}: {ex}")
            raise
        except ValidationError as ex:
            self.logger.error(f"Invalid User Information {search!s}: {ex}")
            self.logger.warning(f"{ex.payload!r}")
            raise
        except Exception as e:
            self.logger.error(f"Error getting User {search!s}: {e!s}")
            raise UserNotFound(f"Invalid User credentials for: {search!s}: {e!s}") from e

    async def authenticate_credentials(self, login: str = None, password: str = None):
        try:
            user = await self.get_user(login)
        except ValidationError as ex:
            raise InvalidAuth(f"User: Invalid {ex.payload}") from ex
        except UserNotFound:
            raise
        except Exception as err:
            raise InvalidAuth(f"User: Auth Exception: {err}") from err
        try:
            # later, check the password
            pwd = user[self.pwd_atrribute]
        except (KeyError, ValidationError, TypeError, ValueError) as ex:
            raise InvalidAuth("Invalid credentials for User") from ex
        try:
            if self.check_password(pwd, password, login=login):
                # return the user Object
                return user
            else:
                raise FailedAuth(f"Basic Auth: Invalid Credentials for user {login}")
        except (InvalidAuth, FailedAuth, UserNotFound) as err:
            self.logger.error(err)
            raise
        except Exception as err:
            raise InvalidAuth(f"Unknown Error: {err}") from err

    def check_password(self, current_password, password, login: str = None):
        who = f" for user {login}" if login else ""
        try:
            if current_password is None:
                raise InvalidAuth(f"User: Password cannot be null{who}.", status=412)
            algorithm, iterations, salt, _ = current_password.split("$", 3)
        except ValueError as ex:
            if str(ex).startswith("not enough values to unpack"):
                raise InvalidAuth(
                    f"Invalid Password{who}: stored password doesn't match "
                    "algorithm requirements"
                ) from ex
            raise InvalidAuth(f"Basic Auth: Invalid Credentials{who}: {ex}") from ex
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
            "exp": expiration_date,
        }
        authzcode = jwt.encode(payload, SECRET_KEY, algorithm=AUTH_JWT_ALGORITHM)
        self.authorization_codes[authzcode] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "exp": expiration_date,
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

            if payload["issuer"] != AUTH_TOKEN_ISSUER:
                self.logger.error("User: Invalid Authorization Code Issuer")
                return False

            # Now let's check that the client_id and redirect_uri in
            # the payload match what we expect
            if payload["client_id"] != client_id:
                self.logger.error("User: Client ID mismatch")
                return False

            if payload["redirect_uri"] != redirect_uri:
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
                scheme, token = request.headers.get(hdrs.AUTHORIZATION).strip().split(" ", 1)
            except ValueError as e:
                raise AuthException("Invalid Authentication Header", status=400) from e
            if scheme != self.scheme:
                raise AuthException("Invalid Authentication Scheme", status=400)
        return token

    def create_ephemeral_token(self, data: dict = None, expiration: int = 1800) -> tuple:
        """Create an Ephemeral Token (short-lived) for accessing resources.
        default expiration: 30 minutes.
        """
        return self.create_token(data=data, expiration=expiration)

    # ------------------------------------------------------------------
    # Signing keys (FEAT-095 TASK-043, decision D4)
    # ------------------------------------------------------------------

    @property
    def key_registry(self):
        """Lazily-loaded signing-key registry.

        Empty unless ``OAUTH_JWT_KEYS`` is configured, in which case every
        signing/verification decision below stays on the legacy HS256 path.
        """
        registry = getattr(self.__class__, "_key_registry", None)
        if registry is None:
            from .keys import load_registry

            registry = load_registry(OAUTH_JWT_KEYS)
            self.__class__._key_registry = registry
            if registry:
                self.logger.notice(
                    f"Loaded {len(registry)} JWT signing key(s); "
                    f"algorithm: {OAUTH_JWT_SIGNING_ALG}"
                )
        return registry

    def signing_key(self):
        """The active asymmetric signer, or None to keep the HS256 path.

        Returns None unless ``OAUTH_JWT_SIGNING_ALG`` selects an asymmetric
        algorithm *and* a usable active key is loaded — the default config
        must never change token output.
        """
        from .keys import ASYMMETRIC_ALGORITHMS

        if OAUTH_JWT_SIGNING_ALG not in ASYMMETRIC_ALGORITHMS:
            return None
        return self.key_registry.signing_key()

    def _verification_key(self, jwt_token: str) -> tuple:
        """Pick the verification key for a token: ``(key, algorithms)``.

        Selection is driven by the token's own ``kid`` header, so tokens
        signed before a rotation keep verifying against the retired key.
        Anything without a known ``kid`` falls back to ``SECRET_KEY``/HS256,
        which is what makes a mixed-token migration window work.
        """
        registry = self.key_registry
        if not registry:
            return SECRET_KEY, [AUTH_JWT_ALGORITHM]
        try:
            kid = jwt.get_unverified_header(jwt_token).get("kid")
        except Exception:  # pylint: disable=W0703
            kid = None
        if not kid:
            return SECRET_KEY, [AUTH_JWT_ALGORITHM]
        key = registry.get(kid)
        if key is None or not key.public_key:
            self.logger.warning(
                f"Token references unknown signing key '{kid}'; "
                "falling back to the symmetric key."
            )
            return SECRET_KEY, [AUTH_JWT_ALGORITHM]
        return key.public_key, [key.algorithm]

    def create_token(
        self,
        data: dict = None,
        issuer: str = None,
        expiration: int = None,
        audience: str = None,
    ) -> tuple:
        """Creation of JWT tokens based on basic parameters.

        issuer:    default urn:Navigator
        expiration: in seconds
        audience:  optional ``aud`` claim value ('user' for 3LO, 'app' for 2LO).
                   When omitted the ``aud`` claim is NOT included (backward-compatible).
                   FEAT-093 TASK-029 — additive kwarg; existing callers unaffected.

        Returns: (jwt_token, refresh_token, exp, scheme) — 4-tuple; signature unchanged.
        """
        # Operate on a local copy to avoid mutating the caller's dict.
        data = dict(data) if data else {}
        for reserved in ("exp", "iat", "iss", "aud", "jti"):
            data.pop(reserved, None)
        if not expiration:
            expiration = self.session_timeout
        if not issuer:
            issuer = AUTH_TOKEN_ISSUER
        if not data:
            data = {}
        iat = datetime.now(timezone.utc)
        exp = (iat + timedelta(seconds=expiration)).timestamp()
        payload = {
            "exp": exp,
            "iat": iat,
            "iss": issuer,
            "jti": str(uuid4()),  # FEAT-098 — unique per token, enables revocation
            **data,
        }
        # TASK-029: only include aud when the caller explicitly requests it.
        if audience is not None:
            payload["aud"] = audience
        # FEAT-095 TASK-043 (D4): asymmetric signing when configured.
        # With no key registry this is skipped entirely and the HS256 call
        # below is byte-identical to pre-feature behaviour.
        signing_key = self.signing_key()
        try:
            if signing_key is not None:
                jwt_token = jwt.encode(
                    payload,
                    signing_key.private_pem(),
                    algorithm=signing_key.algorithm,
                    headers={"kid": signing_key.kid},
                    json_encoder=DefaultEncoder,
                )
            else:
                jwt_token = jwt.encode(payload, SECRET_KEY, AUTH_JWT_ALGORITHM, json_encoder=DefaultEncoder)
        except (TypeError, ValueError) as ex:
            raise AuthException(f"Cannot Create Session Token: {ex!s}") from ex
        refresh_token = self.create_refresh_token()
        return jwt_token, refresh_token, exp, self.scheme

    def decode_token(
        self,
        code: str,
        issuer: str = None,
        audience: Union[str, list[str], None] = None,
    ):
        """Decode a Navigator JWT.

        Args:
            code: the raw token (optionally prefixed with ``<tenant>:``).
            issuer: expected ``iss`` claim. When omitted, the issuer is *not*
                verified (this used to be passed to PyJWT as an unsupported
                ``iss=`` kwarg, which PyJWT silently ignored — and warns about
                since 2.10, fatally under ``-W error``).
            audience: expected ``aud`` claim. When omitted, the ``aud`` claim
                is *not* verified.

        Note:
            ``create_token(audience=...)`` mints tokens carrying an ``aud``
            claim (FEAT-093 TASK-029 uses ``'user'`` for 3LO access tokens and
            ``'app'`` for client-credentials tokens). PyJWT rejects any token
            with an ``aud`` claim when ``decode()`` is called without an
            ``audience`` argument, which made every OAuth2 access token
            undecodable by the auth middleware, ``/oauth2/userinfo``,
            ``/oauth2/revoke`` and ``/oauth2/introspect``. Audience is a
            token-class marker here, not a resource identifier, so validation
            is opt-in: callers that care pass ``audience`` explicitly.
        """
        payload = None
        tenant = None
        if not code:
            return [None, None]
        try:
            tenant, jwt_token = code.split(":")
        except (TypeError, ValueError, AttributeError):
            # normal Token:
            jwt_token = code
        if not jwt_token:
            return [None, None]
        # FEAT-095 TASK-043: dispatch on the `kid` header when the token was
        # signed asymmetrically; otherwise fall back to the SECRET_KEY HS256
        # path.  Both must work at once during an HS256→RS256 migration.
        verify_key, verify_algorithms = self._verification_key(jwt_token)
        try:
            payload = jwt.decode(
                jwt_token,
                verify_key,
                algorithms=verify_algorithms,
                issuer=issuer,
                audience=audience,
                options={
                    "verify_aud": audience is not None,
                    "verify_iss": issuer is not None,
                },
                leeway=30,
            )
            self.logger.debug(f"Decoded Token: {payload!s}")
            return [tenant, payload]
        except jwt.exceptions.ExpiredSignatureError as exc:
            raise AuthExpired(f"Credentials Expired: {exc!s}") from exc
        except jwt.exceptions.InvalidSignatureError as exc:
            raise AuthExpired(f"Signature Failed or Expired: {exc!s}") from exc
        except jwt.exceptions.DecodeError as exc:
            raise FailedAuth(f"Token Decoding Error: {exc}") from exc
        except jwt.exceptions.InvalidTokenError as exc:
            raise InvalidAuth(f"Invalid authorization token {exc!s}") from exc
        except Exception as err:
            raise AuthException(str(err), status=501) from err
