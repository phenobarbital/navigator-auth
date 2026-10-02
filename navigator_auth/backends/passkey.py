"""PasskeyAuth — WebAuthn passkey authentication backend (FEAT-101).

`webauthn` (optional extra ``navigator-auth[passkey]``) is imported lazily in
``on_startup``; importing this module never requires it.
"""

import functools
import hashlib
import hmac
import json
import secrets
from collections.abc import Mapping
from typing import Any

import redis.asyncio as aioredis
from aiohttp import web

from .. import conf as auth_conf
from ..conf import AUTH_EXCLUDE_LIST_KEY
from ..exceptions import AuthException, ConfigError, InvalidAuth, UserNotFound
from ..identities import AuthUser
from ..identity.store import IdentityStore
from ..passkey import (
    ChallengeState,
    PasskeyStore,
    RelyingParty,
    RelyingPartyResolver,
    StoredCredential,
)
from ..passkey.migrations import setup_passkey_tables
from ..responses import JSONResponse
from .basic import BasicAuth

PASSKEY_PREFIX = "/api/v1/auth/passkey"


def _json_errors(handler):
    """Map ``AuthException`` raised by a ceremony handler to a JSON error response.

    Route handlers sit outside ``AuthHandler``'s error mapping, so an uncaught
    ``InvalidAuth`` would surface as a 500. 5xx details are never echoed.
    """

    @functools.wraps(handler)
    async def wrapper(self, request: web.Request) -> web.StreamResponse:
        try:
            return await handler(self, request)
        except AuthException as err:
            status = err.status if 400 <= err.status < 500 else 500
            if status == 500:
                self.logger.error(f"Passkey: {handler.__name__}: {err}")
            message = str(err) if status < 500 else "Passkey: internal error"
            return JSONResponse({"reason": message}, status=status)

    return wrapper


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
        router.add_route(
            "POST", f"{PASSKEY_PREFIX}/register/options", self.register_options, name="passkey_register_options"
        )
        router.add_route(
            "POST", f"{PASSKEY_PREFIX}/register/verify", self.register_verify, name="passkey_register_verify"
        )
        router.add_route("POST", f"{PASSKEY_PREFIX}/login/options", self.login_options, name="passkey_login_options")
        router.add_route("GET", f"{PASSKEY_PREFIX}/credentials", self.list_credentials, name="passkey_credentials")
        router.add_route(
            "PATCH", f"{PASSKEY_PREFIX}/credentials/{{id}}", self.rename_credential, name="passkey_credential_rename"
        )
        router.add_route(
            "DELETE", f"{PASSKEY_PREFIX}/credentials/{{id}}", self.delete_credential, name="passkey_credential_delete"
        )
        app[AUTH_EXCLUDE_LIST_KEY].append(f"{PASSKEY_PREFIX}/login/options")
        super().configure(app)

    async def on_startup(self, app: web.Application) -> None:
        """BasicAuth startup, lazy webauthn import, Redis pool, store and migration."""
        await super().on_startup(app)
        try:
            import webauthn  # pylint: disable=C0415
        except ImportError as err:
            raise ConfigError("PasskeyAuth requires the optional extra: pip install navigator-auth[passkey]") from err
        self._webauthn = webauthn
        self._pool = aioredis.ConnectionPool.from_url(auth_conf.REDIS_AUTH_URL, decode_responses=True, encoding="utf-8")
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
        if not isinstance(challenge_id, str) or not challenge_id or not isinstance(credential, dict) or not credential:
            raise missing
        return challenge_id, credential

    # ------------------------------------------------------------------
    # Ceremony handlers (TASK-94 / TASK-95)
    # ------------------------------------------------------------------
    @_json_errors
    async def register_options(self, request: web.Request) -> web.Response:
        """Creation options for the session user on the resolved RP (C3, E10, E12, E15)."""
        user = self._session_user(request)
        rp = self._resolver.resolve(request)
        from webauthn.helpers import bytes_to_base64url  # pylint: disable=C0415
        from webauthn.helpers.structs import (  # pylint: disable=C0415
            AttestationConveyancePreference,
            AuthenticatorSelectionCriteria,
            PublicKeyCredentialDescriptor,
            ResidentKeyRequirement,
            UserVerificationRequirement,
        )

        handle = await self._store.get_or_create_handle(user.user_id, rp.rp_id)
        existing = await self._store.list_credentials(user.user_id, rp.rp_id)
        options = self._webauthn.generate_registration_options(
            rp_id=rp.rp_id,
            rp_name=rp.rp_name,
            user_id=handle,
            user_name=user.username,
            user_display_name=getattr(user, "display_name", None) or user.username,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement(auth_conf.PASSKEY_USER_VERIFICATION),
            ),
            exclude_credentials=[PublicKeyCredentialDescriptor(id=c.credential_id) for c in existing],
        )
        await self._save_challenge(
            "register",
            str(user.user_id),
            ChallengeState(
                challenge=bytes_to_base64url(options.challenge),
                rp_id=rp.rp_id,
                origin=rp.origin,
                expected_user_id=user.user_id,
            ),
        )
        return web.Response(
            text=self._webauthn.options_to_json(options),
            content_type="application/json",
        )

    @_json_errors
    async def register_verify(self, request: web.Request) -> web.Response:
        """Verify the attestation and store the credential with its rp_id (C3)."""
        user = self._session_user(request)
        rp = self._resolver.resolve(request)
        from webauthn.helpers import base64url_to_bytes, bytes_to_base64url  # pylint: disable=C0415
        from webauthn.helpers.exceptions import InvalidRegistrationResponse  # pylint: disable=C0415

        try:
            body = await request.json()
        except ValueError as err:
            raise web.HTTPBadRequest(reason="Passkey: invalid request body") from err
        credential = body.get("credential") if isinstance(body, dict) else None
        if not isinstance(credential, dict) or not credential:
            raise web.HTTPBadRequest(reason="Passkey: invalid request body")
        label = body.get("label")
        if label is not None and (not isinstance(label, str) or len(label) > 128):
            raise web.HTTPBadRequest(reason="Passkey: label must be a string of at most 128 characters")
        state = await self._pop_challenge("register", str(user.user_id))
        if state.rp_id != rp.rp_id or state.expected_user_id != user.user_id:
            raise InvalidAuth("Passkey: registration failed", status=401)
        try:
            verified = self._webauthn.verify_registration_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(state.challenge),
                expected_rp_id=state.rp_id,
                expected_origin=state.origin,
                require_user_verification=(auth_conf.PASSKEY_USER_VERIFICATION == "required"),
            )
        except (InvalidRegistrationResponse, ValueError, KeyError, TypeError) as err:
            self.logger.warning(
                f"Passkey: registration verification failed for user {user.user_id}: " f"{type(err).__name__}"
            )
            raise web.HTTPBadRequest(reason="Passkey: registration failed") from err
        transports = (credential.get("response") or {}).get("transports")
        if not isinstance(transports, list):
            transports = None
        device_type = getattr(verified.credential_device_type, "value", None) or str(verified.credential_device_type)
        stored = StoredCredential(
            credential_id=verified.credential_id,
            user_id=user.user_id,
            rp_id=rp.rp_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            transports=[str(t) for t in transports] if transports else None,
            aaguid=str(verified.aaguid) if verified.aaguid else None,
            device_type=device_type,
            backed_up=bool(verified.credential_backed_up),
            label=label,
        )
        try:
            if await self._store.get_credential(stored.credential_id) is not None:
                raise web.HTTPConflict(reason="Passkey: credential already registered")
            await self._store.save_credential(stored)
        except web.HTTPException:
            raise
        except Exception as err:  # pylint: disable=W0703
            if "duplicate key" in str(err).lower() or "unique" in str(err).lower():
                raise web.HTTPConflict(reason="Passkey: credential already registered") from err
            raise AuthException(f"Passkey: could not store credential: {err}", status=500) from err
        self.logger.info(f"Passkey: registered credential for user {user.user_id} on {rp.rp_id}")
        return JSONResponse(
            {"status": "registered", "id": bytes_to_base64url(stored.credential_id)},
            status=201,
        )

    def _fail(self, log_reason: str, *, warning: bool = False) -> InvalidAuth:
        """Log the specific reason, return the uniform 401 (E4)."""
        (self.logger.warning if warning else self.logger.info)(f"Passkey: {log_reason}")
        return InvalidAuth("Passkey: invalid credential", status=401)

    @_json_errors
    async def login_options(self, request: web.Request) -> web.Response:
        """Start a sign-in ceremony: username-first (default) or usernameless (C4, E5)."""
        rp = self._resolver.resolve(request)
        from webauthn.helpers import bytes_to_base64url  # pylint: disable=C0415
        from webauthn.helpers.structs import (  # pylint: disable=C0415
            PublicKeyCredentialDescriptor,
            UserVerificationRequirement,
        )

        username = ""
        if request.can_read_body:
            try:
                body = await request.json()
            except ValueError as err:
                raise InvalidAuth("Passkey: invalid request body", status=400) from err
            if isinstance(body, dict) and isinstance(body.get("username"), str):
                username = body["username"].strip()
        allow: list = []
        expected_user_id = None
        decoy = False
        if username:
            user_id = None
            try:
                user = await self._idp.get_user(username)
                user_id = user.user_id if hasattr(user, "user_id") else user["user_id"]
            except UserNotFound:
                user_id = None
            except Exception as err:  # pylint: disable=W0703
                raise AuthException(f"Passkey: user lookup error: {err}", status=500) from err
            # Always hit the store, known or not, to keep timing comparable (R4).
            creds = await self._store.list_credentials(user_id if user_id is not None else -1, rp.rp_id)
            if user_id is not None and creds:
                allow = [PublicKeyCredentialDescriptor(id=c.credential_id) for c in creds]
                expected_user_id = user_id
            else:
                allow = [PublicKeyCredentialDescriptor(id=i) for i in self._decoy_ids(rp, username)]
                decoy = True
        options = self._webauthn.generate_authentication_options(
            rp_id=rp.rp_id,
            allow_credentials=allow,
            user_verification=UserVerificationRequirement(auth_conf.PASSKEY_USER_VERIFICATION),
        )
        challenge_id = secrets.token_urlsafe(32)
        await self._save_challenge(
            "login",
            challenge_id,
            ChallengeState(
                challenge=bytes_to_base64url(options.challenge),
                rp_id=rp.rp_id,
                origin=rp.origin,
                expected_user_id=expected_user_id,
                decoy=decoy,
            ),
        )
        return JSONResponse(
            {
                "challenge_id": challenge_id,
                "publicKey": json.loads(self._webauthn.options_to_json(options)),
            }
        )

    async def authenticate(self, request: web.Request) -> dict:
        """Verify a WebAuthn assertion, then open a Basic-style session (spec §2.5 steps 1–10)."""
        from webauthn.helpers import base64url_to_bytes, bytes_to_base64url  # pylint: disable=C0415
        from webauthn.helpers.exceptions import InvalidAuthenticationResponse  # pylint: disable=C0415

        challenge_id, credential = await self.get_payload(request)  # 1 (no I/O)
        state = await self._pop_challenge("login", challenge_id)  # 2
        try:
            raw_id = base64url_to_bytes(str(credential.get("rawId") or credential.get("id")))
        except Exception as err:  # pylint: disable=W0703
            raise self._fail("malformed credential id") from err
        try:
            cred = await self._store.get_credential(raw_id)  # 3
            if cred is None or state.decoy:
                raise self._fail("unknown credential or decoy ceremony")
            if cred.rp_id != state.rp_id:
                raise self._fail(f"credential rp_id {cred.rp_id!r} != challenge rp_id")
            if state.expected_user_id is not None and cred.user_id != state.expected_user_id:
                raise self._fail("credential belongs to another user")  # 4
            handle_b64 = (credential.get("response") or {}).get("userHandle")
            if handle_b64:  # 5
                try:
                    given = base64url_to_bytes(str(handle_b64))
                except Exception as err:  # pylint: disable=W0703
                    raise self._fail("malformed userHandle") from err
                if given != await self._store.get_handle(cred.user_id, cred.rp_id):
                    raise self._fail("userHandle mismatch")
        except InvalidAuth:
            raise
        except Exception as err:  # pylint: disable=W0703
            raise AuthException(f"Passkey: store error: {err}", status=500) from err
        try:  # 6
            verified = self._webauthn.verify_authentication_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(state.challenge),
                expected_rp_id=state.rp_id,
                expected_origin=state.origin,
                credential_public_key=cred.public_key,
                credential_current_sign_count=cred.sign_count,
                require_user_verification=(auth_conf.PASSKEY_USER_VERIFICATION == "required"),
            )
        except InvalidAuthenticationResponse as err:
            if "sign count" in str(err).lower():
                raise self._fail(
                    "sign-count regression (possible cloned authenticator) for credential "
                    f"{bytes_to_base64url(cred.credential_id)} user {cred.user_id}",
                    warning=True,
                ) from err
            raise self._fail(f"assertion verification failed: {err}") from err
        except (ValueError, KeyError, TypeError) as err:
            raise self._fail(f"malformed assertion: {type(err).__name__}") from err
        try:
            await self._store.update_usage(  # 7
                cred.credential_id,
                sign_count=verified.new_sign_count,
                backed_up=bool(verified.credential_backed_up),
            )
        except Exception as err:  # pylint: disable=W0703
            raise AuthException(f"Passkey: store error: {err}", status=500) from err
        try:  # 8
            user = await self._idp.user_from_id(cred.user_id)
        except UserNotFound as err:
            raise self._fail(f"user {cred.user_id} no longer exists") from err
        rp = self._resolver.by_rp_id(state.rp_id)  # 9
        if rp is None:
            raise self._fail(f"relying party {state.rp_id!r} no longer configured")
        self._check_tenant(user, rp)
        uv = bool(verified.user_verified)
        extra = {
            "auth_method": "passkey",
            "mfa": uv,
            "amr": ["hwk", "user"] if uv else ["hwk"],
            "org_id": rp.org_id,
            "client_id": rp.client_id,
            "passkey_rp_id": rp.rp_id,
        }
        return await self.open_session(request, user, extra=extra)  # 10 (E9 propagates)

    def _check_tenant(self, user: Any, rp: RelyingParty) -> None:
        """When PASSKEY_TENANT_ATTRIBUTE is set and present on user, require == rp.org_id (Q-T)."""
        attr = auth_conf.PASSKEY_TENANT_ATTRIBUTE
        if not attr:
            return
        if isinstance(user, Mapping):
            value = user.get(attr)
        else:
            value = getattr(user, attr, None)
        if value is None:
            return
        if str(value) != str(rp.org_id):
            uid = user.get("user_id") if isinstance(user, Mapping) else getattr(user, "user_id", None)
            raise self._fail(f"tenant mismatch for user {uid}")

    # ------------------------------------------------------------------
    # Credential management (TASK-96)
    # ------------------------------------------------------------------
    @staticmethod
    def _credential_id(request: web.Request) -> bytes:
        """Decode the ``{id}`` path segment; anything not base64url ⇒ 404."""
        from webauthn.helpers import base64url_to_bytes  # pylint: disable=C0415

        try:
            raw = base64url_to_bytes(request.match_info["id"])
        except Exception as err:  # pylint: disable=W0703
            raise web.HTTPNotFound(reason="Passkey: credential not found") from err
        if not raw:
            raise web.HTTPNotFound(reason="Passkey: credential not found")
        return raw

    @_json_errors
    async def list_credentials(self, request: web.Request) -> web.Response:
        """The caller's passkeys across all RPs (no key material)."""
        from webauthn.helpers import bytes_to_base64url  # pylint: disable=C0415

        user = self._session_user(request)
        creds = await self._store.list_credentials(user.user_id)
        return JSONResponse(
            [
                {
                    "id": bytes_to_base64url(c.credential_id),
                    "label": c.label,
                    "created_at": c.created_at.isoformat() if c.created_at else None,
                    "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
                    "device_type": c.device_type,
                    "backed_up": c.backed_up,
                    "rp_id": c.rp_id,
                }
                for c in creds
            ]
        )

    @_json_errors
    async def rename_credential(self, request: web.Request) -> web.Response:
        """Rename one of the caller's passkeys."""
        user = self._session_user(request)
        credential_id = self._credential_id(request)
        try:
            body = await request.json()
        except ValueError as err:
            raise web.HTTPBadRequest(reason="Passkey: invalid request body") from err
        label = body.get("label") if isinstance(body, dict) else None
        label = label.strip() if isinstance(label, str) else ""
        if not 1 <= len(label) <= 128:
            raise web.HTTPBadRequest(reason="Passkey: label must be 1 to 128 characters")
        if not await self._store.rename_credential(user.user_id, credential_id, label):
            raise web.HTTPNotFound(reason="Passkey: credential not found")
        return JSONResponse({"status": "renamed"})

    @_json_errors
    async def delete_credential(self, request: web.Request) -> web.Response:
        """Delete one of the caller's passkeys; 409 when it would lock the user out (E13)."""
        user = self._session_user(request)
        credential_id = self._credential_id(request)
        owned = await self._store.list_credentials(user.user_id)
        if credential_id not in {c.credential_id for c in owned}:
            raise web.HTTPNotFound(reason="Passkey: credential not found")
        guard_last = not await self._has_other_login_method(user.user_id)
        # With no other login method the store deletes only if another passkey remains,
        # atomically (two concurrent deletes cannot both succeed).
        if not await self._store.delete_credential(user.user_id, credential_id, keep_last=guard_last):
            if guard_last:
                raise web.HTTPConflict(reason="Passkey: cannot delete the last login method")
            raise web.HTTPNotFound(reason="Passkey: credential not found")
        return web.Response(status=204)

    async def _has_other_login_method(self, user_id: int) -> bool:
        """True when the user has a password or at least one linked external identity."""
        user = await self._idp.user_from_id(user_id)
        password = (
            user.get(self.pwd_atrribute) if isinstance(user, Mapping) else getattr(user, self.pwd_atrribute, None)
        )
        if password:
            return True
        try:
            identities = await IdentityStore(self._app["authdb"]).list_for_user(user_id)
        except ConfigError as err:
            self.logger.warning(f"Passkey: cannot check linked identities: {err}")
            return False
        return bool(identities)
