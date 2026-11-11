"""Fail-closed Redis state for MFA challenges, enrolments, and replay guards."""

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections.abc import Mapping
from math import ceil
from typing import Optional, TypeVar

import redis.asyncio as aioredis
from redis.exceptions import RedisError

from navigator_auth.conf import (
    AUTH_OTP_CHALLENGE_TTL,
    AUTH_OTP_MAX_ATTEMPTS,
    AUTH_USERID_ATTRIBUTE,
    AUTH_USERNAME_ATTRIBUTE,
)
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.types import MfaChallenge, PendingEnrollment

logger = logging.getLogger("navigator.mfa")
RecordT = TypeVar("RecordT", MfaChallenge, PendingEnrollment)

CHALLENGE_KEY_PREFIX = "auth:mfa:challenge:"
ATTEMPTS_KEY_PREFIX = "auth:mfa:attempts:"
TOTP_REPLAY_PREFIX = "auth:mfa:totp:used:"
ENROLL_KEY_PREFIX = "auth:mfa:enroll:"
ENROLL_ATTEMPTS_PREFIX = "auth:mfa:enroll-attempts:"
ENROLLMENT_TTL = 300

_REGISTER_FAILURE_LUA = """
if redis.call('EXISTS', KEYS[1]) == 0 then return -1 end
local n = redis.call('INCR', KEYS[2])
if n == 1 then
  local pttl = redis.call('PTTL', KEYS[1])
  if pttl > 0 then redis.call('PEXPIRE', KEYS[2], pttl) end
end
if n >= tonumber(ARGV[1]) then
  redis.call('DEL', KEYS[1], KEYS[2])
  return 0
end
return tonumber(ARGV[1]) - n
"""

_CONSUME_LUA = """
local v = redis.call('GETDEL', KEYS[1])
redis.call('DEL', KEYS[2])
return v
"""


def _hash_token(token: str) -> str:
    """Return the SHA-256 digest used for Redis keys."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def canonical_json(fields: dict) -> bytes:
    """Serialize signed fields canonically."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def new_opaque_token() -> str:
    """Create a fresh opaque token."""
    return secrets.token_urlsafe(32)


def _user_field(user: Mapping, name: str):
    """Read a field from a mapping or model-like user object."""
    try:
        value = user[name]
    except (KeyError, TypeError):
        value = getattr(user, name, None)
    if value is None:
        raise ValueError(f"user record lacks {name}")
    return value


class MfaChallengeStore:
    """HMAC-signed, TTL-bound, single-use MFA state store."""

    def __init__(
        self,
        pool: aioredis.ConnectionPool,
        secret: bytes,
        ttl: int = AUTH_OTP_CHALLENGE_TTL,
        max_attempts: int = AUTH_OTP_MAX_ATTEMPTS,
    ) -> None:
        """Bind the shared Redis pool, signing secret, lifetime and attempt budget."""
        if not secret:
            raise ValueError("MfaChallengeStore requires a non-empty secret")
        self._pool, self._secret = pool, secret
        self._ttl, self._max_attempts = int(ttl), int(max_attempts)

    def _redis(self) -> aioredis.Redis:
        """Return a client backed by the shared pool."""
        return aioredis.Redis(connection_pool=self._pool)

    async def check_capabilities(self) -> None:
        """Require Redis 6.2+ for GETDEL inside Lua and SET KEEPTTL, without writing keys."""
        try:
            async with self._redis() as redis:
                info = await redis.info("server")
            version = tuple(int(part) for part in info["redis_version"].split(".")[:2])
            if len(version) != 2 or version < (6, 2):
                raise ValueError("unsupported Redis version")
        except (RedisError, KeyError, TypeError, ValueError) as err:
            raise MfaStorageError("MFA requires Redis 6.2 or newer with readable server information") from err

    def _sign(self, fields: dict) -> str:
        """Authenticate the canonical representation of record fields."""
        return hmac.new(self._secret, canonical_json(fields), hashlib.sha256).hexdigest()

    def _decode(self, raw: str | bytes, model: type[RecordT]) -> Optional[RecordT]:
        """Verify a stored record's signature and validate its immutable schema."""
        try:
            data = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
            signature = data.pop("signature")
            if not secrets.compare_digest(self._sign(data), signature):
                logger.warning("MFA record HMAC verification failed")
                return None
            return model.model_validate({**data, "signature": signature})
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("MFA record decode failed: %s", type(exc).__name__)
            return None

    async def issue(
        self,
        user: Mapping,
        providers: list[str],
        preferred: str,
        *,
        security_version: int,
        context_digest: str,
        email_code_hash: Optional[str] = None,
    ) -> tuple[str, MfaChallenge]:
        """Create a signed challenge without overwriting any existing token."""
        token = new_opaque_token()
        fields = {
            "user_id": int(_user_field(user, AUTH_USERID_ATTRIBUTE)),
            "username": str(_user_field(user, AUTH_USERNAME_ATTRIBUTE)),
            "providers": list(providers),
            "preferred": preferred,
            "issued_at": time.time(),
            "security_version": int(security_version),
            "context_digest": context_digest,
            "email_code_hash": email_code_hash,
        }
        record = MfaChallenge(**fields, signature=self._sign(fields))
        try:
            async with self._redis() as redis:
                ok = await redis.set(
                    f"{CHALLENGE_KEY_PREFIX}{_hash_token(token)}",
                    json.dumps(record.model_dump(mode="json")),
                    nx=True,
                    ex=self._ttl,
                )
            if not ok:
                raise MfaStorageError("MFA challenge key collision")
        except RedisError as exc:
            raise MfaStorageError("MFA challenge storage unavailable") from exc
        return token, record

    async def peek(self, token: str) -> Optional[MfaChallenge]:
        """Read and authenticate a live challenge without consuming it."""
        try:
            async with self._redis() as redis:
                raw = await redis.get(f"{CHALLENGE_KEY_PREFIX}{_hash_token(token)}")
            return None if raw is None else self._decode(raw, MfaChallenge)
        except RedisError as exc:
            raise MfaStorageError("MFA challenge storage unavailable") from exc

    async def consume(self, token: str) -> Optional[MfaChallenge]:
        """Atomically consume a challenge and remove its failure counter."""
        return await self._consume(token, CHALLENGE_KEY_PREFIX, ATTEMPTS_KEY_PREFIX, MfaChallenge)

    async def _consume(
        self, token: str, record_prefix: str, counter_prefix: str, model: type[RecordT]
    ) -> Optional[RecordT]:
        """Consume and authenticate one record using its configured key namespaces."""
        h = _hash_token(token)
        try:
            async with self._redis() as redis:
                raw = await redis.eval(_CONSUME_LUA, 2, f"{record_prefix}{h}", f"{counter_prefix}{h}")
            return None if raw is None else self._decode(raw, model)
        except RedisError as exc:
            raise MfaStorageError("MFA storage unavailable") from exc

    async def discard(self, token: str) -> None:
        """Delete a challenge and its attempt counter."""
        h = _hash_token(token)
        try:
            async with self._redis() as redis:
                await redis.delete(f"{CHALLENGE_KEY_PREFIX}{h}", f"{ATTEMPTS_KEY_PREFIX}{h}")
        except RedisError as exc:
            raise MfaStorageError("MFA storage unavailable") from exc

    async def remaining_ttl(self, token: str) -> int:
        """Return the challenge's remaining lifetime in whole seconds."""
        try:
            async with self._redis() as redis:
                pttl = await redis.pttl(f"{CHALLENGE_KEY_PREFIX}{_hash_token(token)}")
            return 0 if pttl <= 0 else ceil(pttl / 1000)
        except RedisError as exc:
            raise MfaStorageError("MFA storage unavailable") from exc

    async def _register_failure(self, token: str, record_prefix: str, counter_prefix: str) -> int:
        """Atomically decrement retries, preserving expiry; return -1 for an absent record."""
        h = _hash_token(token)
        try:
            async with self._redis() as redis:
                result = await redis.eval(
                    _REGISTER_FAILURE_LUA, 2, f"{record_prefix}{h}", f"{counter_prefix}{h}", self._max_attempts
                )
            return int(result)
        except RedisError as exc:
            raise MfaStorageError("MFA storage unavailable") from exc

    async def register_failure(self, token: str) -> int:
        """Record a challenge failure and return the exact remaining attempts."""
        return await self._register_failure(token, CHALLENGE_KEY_PREFIX, ATTEMPTS_KEY_PREFIX)

    async def replace_email_code(self, token: str, new_code_hash: str) -> Optional[MfaChallenge]:
        """Replace the signed email-code hash while preserving challenge expiry."""
        key = f"{CHALLENGE_KEY_PREFIX}{_hash_token(token)}"
        try:
            async with self._redis() as redis:
                raw = await redis.get(key)
                if raw is None:
                    return None
                record = self._decode(raw, MfaChallenge)
                if record is None:
                    return None
                fields = record.model_dump(mode="json")
                fields.pop("signature")
                fields["email_code_hash"] = new_code_hash
                replacement = MfaChallenge(**fields, signature=self._sign(fields))
                if not await redis.set(key, json.dumps(replacement.model_dump(mode="json")), xx=True, keepttl=True):
                    return None
                return replacement
        except RedisError as exc:
            raise MfaStorageError("MFA storage unavailable") from exc

    async def mark_totp_step(self, user_id: int, step: int, ttl: int) -> bool:
        """Claim a TOTP time step once across all requests for this user."""
        try:
            async with self._redis() as redis:
                return bool(await redis.set(f"{TOTP_REPLAY_PREFIX}{int(user_id)}:{int(step)}", "1", nx=True, ex=ttl))
        except RedisError as exc:
            raise MfaStorageError("MFA storage unavailable") from exc

    async def put_enrollment(
        self,
        token: str,
        *,
        user_id: int,
        session_id: str,
        security_version: int,
        context_digest: str,
        sealed_seed: bytes,
    ) -> PendingEnrollment:
        """Persist a signed, session- and context-bound pending seed with fixed expiry."""
        fields = {
            "user_id": int(user_id),
            "session_hash": hashlib.sha256(session_id.encode()).hexdigest(),
            "security_version": int(security_version),
            "context_digest": context_digest,
            "sealed_seed": base64.b64encode(sealed_seed).decode("ascii"),
            "issued_at": time.time(),
        }
        record = PendingEnrollment(**fields, signature=self._sign(fields))
        try:
            async with self._redis() as redis:
                ok = await redis.set(
                    f"{ENROLL_KEY_PREFIX}{_hash_token(token)}",
                    json.dumps(record.model_dump(mode="json")),
                    nx=True,
                    ex=ENROLLMENT_TTL,
                )
            if not ok:
                raise MfaStorageError("MFA enrollment key collision")
            return record
        except RedisError as exc:
            raise MfaStorageError("MFA storage unavailable") from exc

    async def peek_enrollment(self, token: str) -> Optional[PendingEnrollment]:
        """Read and authenticate a pending enrollment without consuming it."""
        try:
            async with self._redis() as redis:
                raw = await redis.get(f"{ENROLL_KEY_PREFIX}{_hash_token(token)}")
            return None if raw is None else self._decode(raw, PendingEnrollment)
        except RedisError as exc:
            raise MfaStorageError("MFA storage unavailable") from exc

    async def consume_enrollment(self, token: str) -> Optional[PendingEnrollment]:
        """Atomically consume a pending enrollment and its attempt counter."""
        return await self._consume(token, ENROLL_KEY_PREFIX, ENROLL_ATTEMPTS_PREFIX, PendingEnrollment)

    async def register_enrollment_failure(self, token: str) -> int:
        """Record an enrollment failure and return the exact remaining attempts."""
        return await self._register_failure(token, ENROLL_KEY_PREFIX, ENROLL_ATTEMPTS_PREFIX)
