"""TOTP second factor for BasicAuth."""

import base64
import logging
import os
import secrets
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from aiohttp import web
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor import InvalidToken
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from navigator_session.vault import KeyRing, VaultContext, VaultCryptoError, open_value, seal_value

from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_TOTP_ISSUER
from navigator_auth.vault.integration import VAULT_KEYRING_APP_KEY

from .abstract import AbstractOTPProvider
from .exceptions import MfaStorageError
from .state import _field
from .store import ENROLLMENT_TTL, MfaChallengeStore, _hash_token, new_opaque_token
from .types import PROVIDER_TOTP, EnrollmentAuthorization, EnrollmentConfirmation, MfaChallenge, PendingEnrollment

logger = logging.getLogger("navigator.mfa")
TOTP_VAULT_KEY = "mfa:totp"
TOTP_DIGITS, TOTP_PERIOD, TOTP_SKEW_STEPS = 6, 30, 1
TOTP_SEED_BYTES = 20
MFA_SEED_PURPOSE, MFA_PENDING_PURPOSE = "mfa", "mfa-pending"
REPLAY_TTL = TOTP_PERIOD * (2 * TOTP_SKEW_STEPS + 2)
MFA_SECRETS_TABLE = f"{AUTH_DB_SCHEMA}.user_mfa_secrets"
USER_MFA_TABLE = f"{AUTH_DB_SCHEMA}.user_mfa"
SECURITY_TABLE = f"{AUTH_DB_SCHEMA}.user_mfa_security"


def mfa_seed_context(user_id: int, provider: str = PROVIDER_TOTP, key: str = TOTP_VAULT_KEY) -> VaultContext:
    """Build the AAD context for an active seed."""
    return VaultContext(
        purpose=MFA_SEED_PURPOSE, layer="db", fields=(("user_id", int(user_id)), ("provider", provider), ("key", key))
    )


def pending_seed_context(
    *, user_id: int, session_hash: str, security_version: int, enrollment_hash: str
) -> VaultContext:
    """Build the AAD context for a pending seed."""
    return VaultContext(
        purpose=MFA_PENDING_PURPOSE,
        layer="db",
        fields=(
            ("user_id", int(user_id)),
            ("session", session_hash),
            ("version", int(security_version)),
            ("enrollment", enrollment_hash),
        ),
    )


class TOTPProvider(AbstractOTPProvider):
    """Google-Authenticator-compatible TOTP factor."""

    _provider_name = PROVIDER_TOTP
    _is_strong = True

    def __init__(
        self,
        *,
        app: Any,
        db_pool: Any,
        store: MfaChallengeStore,
        issuer: str = AUTH_TOTP_ISSUER,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._app, self._db, self._store = app, db_pool, store
        self._issuer, self._clock = issuer, clock
        self.logger = logger

    def _keyring(self) -> KeyRing:
        """Resolve the current vault keyring."""
        keyring = self._app.get(VAULT_KEYRING_APP_KEY) if self._app is not None else None
        if keyring is None:
            raise MfaStorageError("vault keyring unavailable")
        return keyring

    @staticmethod
    def _totp(seed: bytes) -> TOTP:
        return TOTP(seed, TOTP_DIGITS, SHA1(), TOTP_PERIOD)

    def match_step(self, seed: bytes, code: str, now: float) -> Optional[int]:
        """Return the matching counter in the configured skew window."""
        if not isinstance(code, str) or len(code.strip()) != TOTP_DIGITS or not code.strip().isdigit():
            return None
        counter = int(now) // TOTP_PERIOD
        for step in range(counter - TOTP_SKEW_STEPS, counter + TOTP_SKEW_STEPS + 1):
            try:
                self._totp(seed).verify(code.strip().encode("ascii"), step * TOTP_PERIOD)
            except InvalidToken:
                continue
            return step
        return None

    async def _load_seed(self, user_id: int, *, conn: Any = None) -> Optional[bytes]:
        sql = f"SELECT ciphertext_db FROM {MFA_SECRETS_TABLE} WHERE user_id = $1 AND provider = $2 AND key = $3 AND deleted_at IS NULL"
        try:
            if conn is not None:
                row = await conn.fetch_one(sql, user_id, PROVIDER_TOTP, TOTP_VAULT_KEY)
            else:
                async with await self._db.acquire() as own:
                    row = await own.fetch_one(sql, user_id, PROVIDER_TOTP, TOTP_VAULT_KEY)
        except Exception as err:
            raise MfaStorageError(f"totp seed read failed: {type(err).__name__}") from err
        if not row:
            return None
        try:
            seed = open_value(bytes(row["ciphertext_db"]), mfa_seed_context(user_id), self._keyring())
        except (VaultCryptoError, TypeError, ValueError) as err:
            raise MfaStorageError(f"totp seed unusable: {type(err).__name__}") from err
        if not isinstance(seed, bytes) or len(seed) != TOTP_SEED_BYTES:
            raise MfaStorageError("totp seed unusable: invalid plaintext")
        return seed

    async def _current_version(self, conn: Any, user_id: int) -> int:
        return int((await conn.fetchval(f"SELECT version FROM {SECURITY_TABLE} WHERE user_id = $1", user_id)) or 0)

    async def is_enrolled(self, user: Mapping) -> bool:
        """Return whether the confirmed factor and active seed both exist."""
        user_id = int(_field(user, "user_id"))
        try:
            async with await self._db.acquire() as conn:
                row = await conn.fetch_one(
                    f"SELECT m.enabled, m.confirmed_at FROM {USER_MFA_TABLE} m WHERE m.user_id=$1 AND m.provider=$2 AND EXISTS (SELECT 1 FROM {MFA_SECRETS_TABLE} v WHERE v.user_id=$1 AND v.provider=$2 AND v.key=$3 AND v.deleted_at IS NULL)",
                    user_id,
                    PROVIDER_TOTP,
                    TOTP_VAULT_KEY,
                )
        except Exception as err:
            raise MfaStorageError(f"totp enrollment read failed: {type(err).__name__}") from err
        return bool(row and row["enabled"] and row["confirmed_at"] is not None)

    async def start_enrollment(self, user: Mapping, authorization: EnrollmentAuthorization) -> dict:
        """Create and persist a sealed pending seed."""
        user_id = int(_field(user, "user_id"))
        if authorization.user_id != user_id or authorization.expires_at <= datetime.now(timezone.utc):
            raise ValueError("invalid enrollment authorization")
        seed, token = os.urandom(TOTP_SEED_BYTES), new_opaque_token()
        context = pending_seed_context(
            user_id=user_id,
            session_hash=_hash_token(authorization.session_id),
            security_version=authorization.security_version,
            enrollment_hash=_hash_token(token),
        )
        sealed = seal_value(seed, context, self._keyring())
        await self._store.put_enrollment(
            token,
            user_id=user_id,
            session_id=authorization.session_id,
            security_version=authorization.security_version,
            context_digest=authorization.context_digest,
            sealed_seed=sealed,
        )
        account = str(_field(user, "username") or user_id)
        return {
            "enrollment_token": token,
            "uri": self._totp(seed).get_provisioning_uri(account, self._issuer),
            "secret_b32": base64.b32encode(seed).decode("ascii").rstrip("="),
            "expires_in": ENROLLMENT_TTL,
        }

    async def challenge(self, request: web.Request, user: Mapping) -> dict:
        """Return no challenge because the authenticator app is the channel."""
        return {}

    async def confirm_enrollment(
        self,
        user: Mapping,
        code: str,
        enrollment_token: str,
        session_id: str,
        *,
        conn: Any = None,
        context_digest: Optional[str] = None,
    ) -> bool:
        """Return a boolean confirmation; callers must supply the current security context."""
        result = await self.confirm_enrollment_result(
            user, code, enrollment_token, session_id, conn=conn, context_digest=context_digest
        )
        return result.confirmed

    async def confirm_enrollment_result(
        self,
        user: Mapping,
        code: str,
        enrollment_token: str,
        session_id: str,
        *,
        conn: Any = None,
        context_digest: Optional[str] = None,
    ) -> EnrollmentConfirmation:
        """Confirm and install a seed, preserving the atomic failure budget for the caller."""
        if conn is None:
            raise ValueError("confirm_enrollment requires conn")
        if not context_digest:
            return EnrollmentConfirmation(confirmed=False)
        user_id = int(_field(user, "user_id"))
        pending = await self._store.peek_enrollment(enrollment_token)
        if pending is None:
            return EnrollmentConfirmation(confirmed=False)
        if pending.user_id != user_id or pending.session_hash != _hash_token(session_id):
            remaining = await self._store.register_enrollment_failure(enrollment_token)
            return EnrollmentConfirmation(confirmed=False, attempts_remaining=remaining)
        if not secrets.compare_digest(context_digest, pending.context_digest) or (
            await self._current_version(conn, user_id) != pending.security_version
        ):
            await self._store.consume_enrollment(enrollment_token)
            return EnrollmentConfirmation(confirmed=False)
        seed = self._open_pending(pending, enrollment_token)
        step = self.match_step(seed, code, self._clock())
        if step is None or not await self._store.mark_totp_step(user_id, step, REPLAY_TTL):
            remaining = await self._store.register_enrollment_failure(enrollment_token)
            return EnrollmentConfirmation(confirmed=False, attempts_remaining=remaining)
        consumed = await self._store.consume_enrollment(enrollment_token)
        if consumed is None or consumed != pending:
            return EnrollmentConfirmation(confirmed=False)
        await self._install_seed(conn, user_id, seed)
        return EnrollmentConfirmation(confirmed=True)

    async def verify(
        self,
        request: web.Request,
        user: Mapping,
        code: str,
        challenge: Optional[MfaChallenge] = None,
        *,
        conn: Any = None,
    ) -> bool:
        """Verify a code against the active seed, failing closed on storage errors."""
        user_id = int(_field(user, "user_id"))
        seed = await self._load_seed(user_id, conn=conn)
        if seed is None:
            return False
        step = self.match_step(seed, code, self._clock())
        if step is None or not await self._store.mark_totp_step(user_id, step, REPLAY_TTL):
            return False
        touch = f"UPDATE {USER_MFA_TABLE} SET last_used_at = now() WHERE user_id=$1 AND provider=$2 RETURNING 1"
        if conn is not None:
            try:
                await conn.fetchval(touch, user_id, PROVIDER_TOTP)
            except Exception as err:
                raise MfaStorageError(f"totp last-used touch failed: {type(err).__name__}") from err
            return True
        try:
            async with await self._db.acquire() as own:
                await own.fetchval(touch, user_id, PROVIDER_TOTP)
        except Exception as err:
            self.logger.warning("MFA last-used touch failed: %s", type(err).__name__)
        return True

    async def disenroll(self, user: Mapping, *, conn: Any = None) -> None:
        """Soft-delete the seed and disable its MFA row."""
        user_id = int(_field(user, "user_id"))
        if conn is None:
            async with await self._db.acquire() as pooled:
                await self._disenroll_on(pooled, user_id)
        else:
            await self._disenroll_on(conn, user_id)

    async def _disenroll_on(self, conn: Any, user_id: int) -> None:
        await conn.fetchval(
            f"UPDATE {MFA_SECRETS_TABLE} SET deleted_at = now() WHERE user_id=$1 AND provider=$2 AND key=$3 AND deleted_at IS NULL RETURNING 1",
            user_id,
            PROVIDER_TOTP,
            TOTP_VAULT_KEY,
        )
        await conn.fetchval(
            f"UPDATE {USER_MFA_TABLE} SET enabled=false, confirmed_at=NULL WHERE user_id=$1 AND provider=$2 RETURNING 1",
            user_id,
            PROVIDER_TOTP,
        )

    def _open_pending(self, pending: PendingEnrollment, token: str) -> bytes:
        context = pending_seed_context(
            user_id=pending.user_id,
            session_hash=pending.session_hash,
            security_version=pending.security_version,
            enrollment_hash=_hash_token(token),
        )
        try:
            seed = open_value(base64.b64decode(pending.sealed_seed), context, self._keyring())
        except (VaultCryptoError, ValueError) as err:
            raise MfaStorageError(f"pending seed unusable: {type(err).__name__}") from err
        if not isinstance(seed, bytes) or len(seed) != TOTP_SEED_BYTES:
            raise MfaStorageError("pending seed unusable: invalid plaintext")
        return seed

    async def _install_seed(self, conn: Any, user_id: int, seed: bytes) -> None:
        keyring = self._keyring()
        ciphertext = seal_value(seed, mfa_seed_context(user_id), keyring)
        await conn.fetchval(
            f"INSERT INTO {MFA_SECRETS_TABLE} (user_id,provider,key,ciphertext_db,key_version) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (user_id,provider,key) WHERE deleted_at IS NULL DO UPDATE SET ciphertext_db=EXCLUDED.ciphertext_db,key_version=EXCLUDED.key_version,updated_at=NOW() RETURNING 1",
            user_id,
            PROVIDER_TOTP,
            TOTP_VAULT_KEY,
            ciphertext,
            keyring.active_key_id,
        )
        await conn.fetchval(
            f"INSERT INTO {USER_MFA_TABLE} (user_id,provider,enabled,confirmed_at) VALUES ($1,$2,true,now()) ON CONFLICT (user_id,provider) DO UPDATE SET enabled=true,confirmed_at=now() RETURNING 1",
            user_id,
            PROVIDER_TOTP,
        )
