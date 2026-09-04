"""RecoveryTokenStore — two-stage, HMAC-signed, TTL'd Redis token store
(FEAT-098, Module 3).

Replaces the broken ``RecoveryTokenStorage`` in the legacy
``handlers/recovery_legacy.py`` (encodes with a *decoder*, opens a fresh
Redis client per request and never closes it, keys Redis by the raw
token). This store follows the shape of
``navigator_auth/identity/flow_store.py`` — a pooled connection, ``setex``
to write, ``getdel`` for single-use consumption — but is not a subclass of
it: the key namespace and the HMAC-signing concern are different.

Security property (D12): Redis is keyed by ``sha256(token)``, never by the
token itself, and every payload carries an HMAC-SHA256 signature over its
own fields. A dump of the Redis database yields hashed keys and signed
payloads — no usable token can be reconstructed from it.
"""
import hashlib
import hmac
import secrets
import time
from dataclasses import asdict
from typing import Optional

import redis.asyncio as aioredis

from navigator_auth.conf import AUTH_RECOVERY_TTL, AUTH_RECOVERY_CONFIRM_TTL
from navigator_auth.libs.json import json_encoder, json_decoder
from navigator_auth.handlers.recovery.types import (
    RecoveryPayload,
    ConfirmationPayload,
)

RECOVERY_KEY_PREFIX = "auth:recovery:"
CONFIRM_KEY_PREFIX = "auth:recovery:confirm:"


def _hash_token(token: str) -> str:
    """sha256(token) hex digest — the only thing ever used as a Redis key."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class RecoveryTokenStore:
    """Two-stage, HMAC-signed, TTL'd token store.

    Redis is keyed by ``sha256(token)`` and never by the token itself, so a
    dump of the database yields no usable credential (D12).
    """

    def __init__(self, pool: aioredis.ConnectionPool, secret: bytes):
        self._pool = pool
        self._secret = secret

    # --- signing -----------------------------------------------------
    def _sign(self, *parts: str) -> str:
        message = ":".join(parts).encode("utf-8")
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()

    def _sign_recovery(self, user_id, username: str, issued_at, nonce: str) -> str:
        return self._sign(str(user_id), username, str(issued_at), nonce)

    def _sign_confirmation(
        self, user_id, username: str, recovery_key: str, issued_at
    ) -> str:
        return self._sign(str(user_id), username, recovery_key, str(issued_at))

    # --- stage 1: recovery token --------------------------------------
    async def issue_recovery(self, user) -> tuple[str, RecoveryPayload]:
        """Mint the stage-1 token; SETEX for AUTH_RECOVERY_TTL."""
        token = secrets.token_urlsafe(32)
        issued_at = time.time()
        nonce = secrets.token_urlsafe(16)
        signature = self._sign_recovery(user.user_id, user.username, issued_at, nonce)
        payload = RecoveryPayload(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            issued_at=issued_at,
            nonce=nonce,
            signature=signature,
        )
        raw = asdict(payload)
        # Back-pointer to the currently-live stage-2 token's key hash, used
        # by issue_confirmation() to implement rotation. None until step 2
        # is first called.
        raw["confirm_key"] = None
        key = f"{RECOVERY_KEY_PREFIX}{_hash_token(token)}"
        async with aioredis.Redis(connection_pool=self._pool) as redis:
            await redis.setex(key, AUTH_RECOVERY_TTL, json_encoder(raw))
        return token, payload

    async def validate_recovery(self, token: str) -> Optional[RecoveryPayload]:
        """Read + verify signature. Does NOT consume the record (D4)."""
        key = f"{RECOVERY_KEY_PREFIX}{_hash_token(token)}"
        async with aioredis.Redis(connection_pool=self._pool) as redis:
            raw = await redis.get(key)
        if not raw:
            return None
        return self._decode_recovery(raw)

    def _decode_recovery(self, raw) -> Optional[RecoveryPayload]:
        data = json_decoder(raw)
        expected = self._sign_recovery(
            data["user_id"], data["username"], data["issued_at"], data["nonce"]
        )
        if not secrets.compare_digest(expected, data["signature"]):
            return None
        return RecoveryPayload(
            user_id=data["user_id"],
            username=data["username"],
            email=data["email"],
            issued_at=data["issued_at"],
            nonce=data["nonce"],
            signature=data["signature"],
        )

    # --- stage 2: confirmation token -----------------------------------
    async def issue_confirmation(
        self, token: str
    ) -> tuple[str, ConfirmationPayload]:
        """Mint stage-2 and invalidate any previous stage-2 for this
        recovery (rotation, D4). Stage-1 is left intact."""
        recovery_hash = _hash_token(token)
        recovery_key = f"{RECOVERY_KEY_PREFIX}{recovery_hash}"
        async with aioredis.Redis(connection_pool=self._pool) as redis:
            raw = await redis.get(recovery_key)
            if not raw:
                raise LookupError("Recovery token not found or expired.")
            data = json_decoder(raw)
            expected = self._sign_recovery(
                data["user_id"], data["username"], data["issued_at"], data["nonce"]
            )
            if not secrets.compare_digest(expected, data["signature"]):
                raise LookupError("Recovery token failed signature check.")

            # Rotation: drop the previously-issued confirmation, if any.
            old_confirm_hash = data.get("confirm_key")
            if old_confirm_hash:
                await redis.delete(f"{CONFIRM_KEY_PREFIX}{old_confirm_hash}")

            confirm_token = secrets.token_urlsafe(32)
            confirm_hash = _hash_token(confirm_token)
            issued_at = time.time()
            signature = self._sign_confirmation(
                data["user_id"], data["username"], recovery_hash, issued_at
            )
            confirmation = ConfirmationPayload(
                user_id=data["user_id"],
                username=data["username"],
                recovery_key=recovery_hash,
                issued_at=issued_at,
                signature=signature,
            )
            confirm_key = f"{CONFIRM_KEY_PREFIX}{confirm_hash}"
            await redis.setex(
                confirm_key, AUTH_RECOVERY_CONFIRM_TTL, json_encoder(asdict(confirmation))
            )

            # Update the stage-1 back-pointer in place, preserving its
            # remaining TTL rather than extending it.
            data["confirm_key"] = confirm_hash
            await redis.set(recovery_key, json_encoder(data), keepttl=True)

        return confirm_token, confirmation

    def _decode_confirmation(self, raw) -> Optional[ConfirmationPayload]:
        data = json_decoder(raw)
        expected = self._sign_confirmation(
            data["user_id"], data["username"], data["recovery_key"], data["issued_at"]
        )
        if not secrets.compare_digest(expected, data["signature"]):
            return None
        return ConfirmationPayload(
            user_id=data["user_id"],
            username=data["username"],
            recovery_key=data["recovery_key"],
            issued_at=data["issued_at"],
            signature=data["signature"],
        )

    async def peek_confirmation(self, token: str) -> Optional[ConfirmationPayload]:
        """Read + verify signature WITHOUT consuming (unlike
        ``consume_confirmation``, this is GET not GETDEL).

        FEAT-098 TASK-067 — lets the handler resolve the user behind a
        confirmation token (to run the password policy check against their
        current hash) *before* deciding whether to burn the single-use
        record, so a policy failure at step 3 leaves both tokens intact
        (D4/D5 apply to the read; the write path is still single-use via
        ``consume_confirmation``).
        """
        key = f"{CONFIRM_KEY_PREFIX}{_hash_token(token)}"
        async with aioredis.Redis(connection_pool=self._pool) as redis:
            raw = await redis.get(key)
        if not raw:
            return None
        return self._decode_confirmation(raw)

    async def consume_confirmation(self, token: str) -> Optional[ConfirmationPayload]:
        """GETDEL — single use."""
        key = f"{CONFIRM_KEY_PREFIX}{_hash_token(token)}"
        async with aioredis.Redis(connection_pool=self._pool) as redis:
            raw = await redis.getdel(key)
        if not raw:
            return None
        return self._decode_confirmation(raw)

    async def drop_pair(self, recovery_key: str, confirm_key: str) -> None:
        """Delete both records so the link cannot be replayed (step 3).

        ``recovery_key``/``confirm_key`` are the bare sha256 hex digests of
        the two tokens (as carried in ``ConfirmationPayload.recovery_key``),
        not the prefixed Redis keys.
        """
        async with aioredis.Redis(connection_pool=self._pool) as redis:
            await redis.delete(
                f"{RECOVERY_KEY_PREFIX}{recovery_key}",
                f"{CONFIRM_KEY_PREFIX}{confirm_key}",
            )
