"""PasskeyAuth — WebAuthn passkey authentication backend (FEAT-101).

`webauthn` (optional extra ``navigator-auth[passkey]``) is imported lazily in
``on_startup``; importing this module never requires it.
"""
import hashlib
import hmac
from typing import Any

import redis.asyncio as aioredis
from aiohttp import web

from .. import conf as auth_conf
from ..conf import AUTH_EXCLUDE_LIST_KEY
from ..exceptions import AuthException, ConfigError, InvalidAuth
from ..identities import AuthUser
from ..passkey import ChallengeState, PasskeyStore, RelyingParty, RelyingPartyResolver
from ..passkey.migrations import setup_passkey_tables
from .basic import BasicAuth

PASSKEY_PREFIX = "/api/v1/auth/passkey"


class PasskeyUser(AuthUser):
    """User authenticated with a WebAuthn passkey."""


class PasskeyAuth(BasicAuth):
    """Passkey (WebAuthn) authentication; sign-in goes through POST /api/v1/login."""

    _ident: AuthUser = PasskeyUser
    _description: str = "Passkey (WebAuthn) authentication"
    _service_name: str = "passkey"

    def configure(self, app: web.Application) -> None:
        """Register ceremony routes and build the RP resolver (ConfigError if the map is empty)."""
        self._resolver = RelyingPartyResolver(auth_conf.PASSKEY_RELYING_PARTIES)
        router = app.router
        router.add_route("POST", f"{PASSKEY_PREFIX}/register/options", self.register_options,
                         name="passkey_register_options")
        router.add_route("POST", f"{PASSKEY_PREFIX}/register/verify", self.register_verify,
                         name="passkey_register_verify")
        router.add_route("POST", f"{PASSKEY_PREFIX}/login/options", self.login_options,
                         name="passkey_login_options")
        app[AUTH_EXCLUDE_LIST_KEY].append(f"{PASSKEY_PREFIX}/login/options")
        super().configure(app)

    async def on_startup(self, app: web.Application) -> None:
        """BasicAuth startup, lazy webauthn import, Redis pool, store and migration."""
        await super().on_startup(app)
        try:
            import webauthn  # pylint: disable=C0415
        except ImportError as err:
            raise ConfigError(
                "PasskeyAuth requires the optional extra: pip install navigator-auth[passkey]"
            ) from err
        self._webauthn = webauthn
        self._pool = aioredis.ConnectionPool.from_url(
            auth_conf.REDIS_AUTH_URL, decode_responses=True, encoding="utf-8"
        )
        self._store = PasskeyStore(app["authdb"])
        await setup_passkey_tables(app["authdb"])

    async def on_cleanup(self, app: web.Application) -> None:
        """Disconnect the Redis pool, then BasicAuth cleanup."""
        pool = getattr(self, "_pool", None)
        if pool is not None:
            try:
                await pool.disconnect(inuse_connections=True)
            except Exception as err:  # pylint: disable=W0703
                self.logger.warning(f"PasskeyAuth: error closing Redis pool: {err}")
        await super().on_cleanup(app)

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    def _challenge_key(self, kind: str, key: str) -> str:
        return f"passkey_{kind}_{key}"

    async def _save_challenge(self, kind: str, key: str, state: ChallengeState) -> None:
        """SETEX the ceremony state for PASSKEY_CHALLENGE_TTL seconds."""
        try:
            async with aioredis.Redis(connection_pool=self._pool) as redis:
                await redis.setex(
                    self._challenge_key(kind, key),
                    auth_conf.PASSKEY_CHALLENGE_TTL,
                    state.model_dump_json(),
                )
        except Exception as err:  # pylint: disable=W0703
            raise AuthException(f"Passkey: challenge store error: {err}", status=500) from err

    async def _pop_challenge(self, kind: str, key: str) -> ChallengeState:
        """GETDEL; missing ⇒ InvalidAuth('Passkey: ceremony expired', status=401)."""
        try:
            async with aioredis.Redis(connection_pool=self._pool) as redis:
                raw = await redis.getdel(self._challenge_key(kind, key))
        except Exception as err:  # pylint: disable=W0703
            raise AuthException(f"Passkey: challenge store error: {err}", status=500) from err
        if raw is None:
            raise InvalidAuth("Passkey: ceremony expired", status=401)
        try:
            return ChallengeState.model_validate_json(raw)
        except ValueError as err:
            raise InvalidAuth("Passkey: ceremony expired", status=401) from err

    def _decoy_ids(self, rp: RelyingParty, username: str) -> list[bytes]:
        """Deterministic fake credential ids for unknown users (E5)."""
        secret = auth_conf.SECRET_KEY
        key = secret if isinstance(secret, bytes) else str(secret).encode()
        return [
            hmac.new(
                key,
                f"{rp.rp_id}\x00{username.casefold()}\x00{i}".encode(),
                hashlib.sha256,
            ).digest()
            for i in range(auth_conf.PASSKEY_DECOY_CREDENTIALS)
        ]

    def _session_user(self, request: web.Request) -> Any:
        """Return ``request.user`` for a live session, else raise 401 (E12)."""
        if not request.get("authenticated", False):
            raise self.Unauthorized(reason="Passkey: a session is required")
        return request.user

    async def get_payload(self, request: web.Request) -> tuple[str, dict]:
        """Return ``(challenge_id, credential)``; InvalidAuth(401) with no I/O when absent (E11)."""
        missing = InvalidAuth("Passkey: missing assertion", status=401)
        if not (request.content_type or "").startswith("application/json"):
            raise missing
        try:
            body = await request.json()
        except ValueError as err:
            raise missing from err
        if not isinstance(body, dict):
            raise missing
        challenge_id = body.get("challenge_id")
        credential = body.get("credential")
        if (
            not isinstance(challenge_id, str)
            or not challenge_id
            or not isinstance(credential, dict)
            or not credential
        ):
            raise missing
        return challenge_id, credential

    # ------------------------------------------------------------------
    # Ceremony handlers (TASK-94 / TASK-95)
    # ------------------------------------------------------------------
    async def register_options(self, request: web.Request) -> web.Response:
        raise web.HTTPNotImplemented(reason="TASK-94")

    async def register_verify(self, request: web.Request) -> web.Response:
        raise web.HTTPNotImplemented(reason="TASK-94")

    async def login_options(self, request: web.Request) -> web.Response:
        raise web.HTTPNotImplemented(reason="TASK-95")

    async def authenticate(self, request: web.Request) -> dict:
        """Sign-in (TASK-95). Until then: fail fast so the api_login fallback loop continues."""
        await self.get_payload(request)
        raise InvalidAuth("Passkey: not implemented", status=401)
