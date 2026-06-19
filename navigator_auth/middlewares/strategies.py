"""Pluggable token strategies for the unified auth middleware."""
import base64
import json
from abc import ABC, abstractmethod
from typing import Any

import jwt
from aiohttp import web

from navigator_auth.conf import AUTH_CREDENTIALS_REQUIRED, SECRET_KEY


class TokenStrategy(ABC):
    """Base class for authentication token strategies.

    Each strategy encapsulates three concerns:
    - How to extract a token from the request
    - How to validate/decode the token
    - When to enforce authentication
    """

    @abstractmethod
    def extract(self, request: web.Request) -> tuple[str | None, str | None]:
        """Extract token and scheme from the request.

        Returns:
            (token, scheme) tuple. Both None if no credentials found.
        """

    @abstractmethod
    async def validate(self, token: str, scheme: str | None, app: web.Application) -> Any:
        """Validate/decode a token and return the payload.

        Raises:
            web.HTTPForbidden or web.HTTPUnauthorized on invalid token.
        """

    def should_enforce(self, request: web.Request, protected_routes: tuple) -> bool:
        """Whether auth is required for this request."""
        return request.path in protected_routes


class APIKeyStrategy(TokenStrategy):
    """Extract from x-api-key header or api_key query param. Validate against DB.

    Extracts the API key from the ``x-api-key`` request header first, then
    falls back to the ``api_key`` query parameter. Validation queries the
    ``authdb`` connection pool stored on the application for a matching row in
    ``public.api_keys``.
    """

    def extract(self, request: web.Request) -> tuple[str | None, str | None]:
        """Extract the API key and return scheme ``"api"``."""
        if "x-api-key" in request.headers:
            return request.headers["x-api-key"].strip(), "api"
        api_key = request.query.get("api_key")
        if api_key:
            return api_key.strip(), "api"
        return None, None

    async def validate(self, token: str, scheme: str | None, app: web.Application) -> Any:
        """Query the DB for a valid API key row and return it.

        Args:
            token: The raw API key value.
            scheme: Always ``"api"`` for this strategy.
            app: The aiohttp application (must have ``app["authdb"]`` pool).

        Returns:
            A dict-like row with at least ``user_id`` and ``name``.

        Raises:
            web.HTTPForbidden: When the key is not found or expired.
            web.HTTPBadRequest: On unexpected database errors.
        """
        try:
            db = app["authdb"]
            async with await db.acquire() as conn:
                payload = await conn.fetch_one(
                    "SELECT user_id, name from public.api_keys "
                    "WHERE token = $1 "
                    "AND (expiration >= extract(epoch from now()) or expiration = 0)",
                    token,
                )
            if not payload:
                raise web.HTTPForbidden(reason="Access is Restricted")
            return payload
        except web.HTTPError:
            raise
        except Exception as err:
            raise web.HTTPBadRequest(
                reason=f"API Key Decryption Error: {err}"
            ) from err


class PlainTokenStrategy(TokenStrategy):
    """Extract from Authorization header, auth query, or X-Token header. No validation.

    The raw token and scheme are returned to the caller as-is; no signature
    checking is performed. This is useful when a downstream user function
    handles validation.
    """

    def extract(self, request: web.Request) -> tuple[str | None, str | None]:
        """Extract token from ``Authorization`` header, ``auth`` query, or ``X-Token`` header."""
        if "Authorization" in request.headers:
            try:
                scheme, token = request.headers["Authorization"].strip().split(" ", 1)
                return token, scheme
            except ValueError:
                return None, None
        token = request.query.get("auth", request.headers.get("X-Token"))
        return (token, None) if token else (None, None)

    async def validate(self, token: str, scheme: str | None, app: web.Application) -> Any:
        """Return the token and scheme as a dict (no cryptographic validation).

        Args:
            token: The extracted token string.
            scheme: The HTTP auth scheme (e.g. ``"Bearer"``), or ``None``.
            app: The aiohttp application (unused).

        Returns:
            ``{"token": token, "scheme": scheme}``
        """
        return {"token": token, "scheme": scheme}

    def should_enforce(self, request: web.Request, protected_routes: tuple) -> bool:
        """Return ``True`` when ``AUTH_CREDENTIALS_REQUIRED`` is ``True``."""
        return AUTH_CREDENTIALS_REQUIRED is True


class TrocTokenStrategy(TokenStrategy):
    """Extract like PlainToken, validate via Cipher.decode().

    Wraps a ``Cipher`` instance (from ``navigator_auth.libs.cipher``) to
    decrypt proprietary Troc tokens.
    """

    def __init__(self, cipher: Any) -> None:
        """Initialise the strategy with a cipher instance.

        Args:
            cipher: An object exposing a ``decode(passphrase=...)`` method,
                typically ``navigator_auth.libs.cipher.Cipher``.
        """
        self._cipher = cipher
        self._plain = PlainTokenStrategy()

    def extract(self, request: web.Request) -> tuple[str | None, str | None]:
        """Delegate extraction to :class:`PlainTokenStrategy`."""
        return self._plain.extract(request)

    async def validate(self, token: str, scheme: str | None, app: web.Application) -> Any:
        """Decode the token with the cipher and return the payload.

        Args:
            token: The encrypted token passphrase.
            scheme: Unused.
            app: Unused.

        Returns:
            The decoded payload returned by ``cipher.decode()``.

        Raises:
            web.HTTPForbidden: When the decoded payload is empty.
            web.HTTPUnauthorized: On a :exc:`ValueError` during decryption.
            web.HTTPBadRequest: On any other decryption error.
        """
        try:
            payload = self._cipher.decode(passphrase=token)
            if not payload:
                raise web.HTTPForbidden(reason="Invalid authorization Token")
            return payload
        except web.HTTPError:
            raise
        except ValueError as err:
            raise web.HTTPUnauthorized(
                reason="Token Decryption Error"
            ) from err
        except Exception as err:
            raise web.HTTPBadRequest(
                reason=f"Token Decryption Error: {err}"
            ) from err


class JWTStrategy(TokenStrategy):
    """Extract Bearer token, validate via jwt.decode().

    Only accepts ``Authorization: Bearer <token>`` headers or an ``auth``
    query parameter. The ``secret_key`` defaults to ``SECRET_KEY`` from
    ``navigator_auth.conf``.
    """

    def __init__(self, secret_key: str | None = None, algorithm: str = "HS256") -> None:
        """Initialise the JWT strategy.

        Args:
            secret_key: HMAC secret (or RSA public key). Defaults to
                ``SECRET_KEY`` from ``navigator_auth.conf``.
            algorithm: JWT algorithm identifier, e.g. ``"HS256"``.
        """
        self._secret = secret_key or SECRET_KEY
        self._algorithm = algorithm

    def extract(self, request: web.Request) -> tuple[str | None, str | None]:
        """Extract a Bearer token from the ``Authorization`` header or ``auth`` query param."""
        if "Authorization" in request.headers:
            try:
                scheme, token = request.headers["Authorization"].strip().split(" ", 1)
            except ValueError:
                return None, None
            if scheme != "Bearer":
                return None, None
            return token, scheme
        token = request.query.get("auth")
        return (token, None) if token else (None, None)

    async def validate(self, token: str, scheme: str | None, app: web.Application) -> Any:
        """Decode and verify the JWT, returning the claims payload.

        Args:
            token: The encoded JWT string.
            scheme: Expected to be ``"Bearer"``; unused inside validation.
            app: Unused.

        Returns:
            The decoded JWT claims dict.

        Raises:
            web.HTTPBadRequest: On expired or malformed tokens.
            web.HTTPForbidden: When the decoded payload is falsy.
        """
        try:
            payload = jwt.decode(token, self._secret, algorithms=[self._algorithm])
            if not payload:
                raise web.HTTPForbidden(reason="Invalid authorization Token")
            return payload
        except jwt.DecodeError as err:
            raise web.HTTPBadRequest(
                reason=f"JWT: Invalid Token: {err}"
            ) from err
        except jwt.ExpiredSignatureError as err:
            raise web.HTTPBadRequest(
                reason=f"JWT: Expired Token or bad signature: {err}"
            ) from err
        except web.HTTPError:
            raise
        except Exception as err:
            raise web.HTTPBadRequest(
                reason=f"JWT Token Decryption Error: {err}"
            ) from err

    def should_enforce(self, request: web.Request, protected_routes: tuple) -> bool:
        """Return ``True`` when ``AUTH_CREDENTIALS_REQUIRED`` is ``True``."""
        return AUTH_CREDENTIALS_REQUIRED is True


class DjangoSessionStrategy(TokenStrategy):
    """Extract x-sessionid header, validate via Redis session lookup.

    Looks up the session key in Redis using ``app["redis"]`` and decodes the
    base64-encoded Django session payload.
    """

    def __init__(self, session_prefix: str = "navigator_session") -> None:
        """Initialise the Django session strategy.

        Args:
            session_prefix: Redis key prefix used to look up the session,
                e.g. ``"nav_session"`` → key ``"nav_session:<sessionid>"``.
        """
        self._prefix = session_prefix

    def extract(self, request: web.Request) -> tuple[str | None, str | None]:
        """Extract the Django session ID from the ``x-sessionid`` header."""
        sessionid = request.headers.get("x-sessionid")
        return (sessionid, "django") if sessionid else (None, None)

    async def validate(self, token: str, scheme: str | None, app: web.Application) -> Any:
        """Look up the session in Redis and decode the Django session payload.

        Args:
            token: The Django session ID string.
            scheme: Always ``"django"`` for this strategy.
            app: The aiohttp application (must have ``app["redis"]``).

        Returns:
            A dict with ``key``, ``session_id``, and the session user data.

        Raises:
            web.HTTPBadRequest: When the session is not found or cannot be decoded.
        """
        try:
            redis = app["redis"]
            payload = await redis.get(f"{self._prefix}:{token}")
            if not payload:
                raise web.HTTPBadRequest(
                    reason="Django Middleware: Invalid Django Session"
                )
            data = base64.b64decode(payload)
            session_data = data.decode("utf-8").split(":", 1)
            user = json.loads(session_data[1])
            return {"key": token, "session_id": session_data[0], **user}
        except web.HTTPError:
            raise
        except Exception as err:
            raise web.HTTPBadRequest(
                reason=f"Django Middleware: Error decoding: {err!s}"
            ) from err
