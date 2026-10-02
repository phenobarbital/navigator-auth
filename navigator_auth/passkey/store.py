"""Persistence for WebAuthn credentials and per-(user, RP) user handles (FEAT-101)."""

import secrets
from typing import Any, Optional

from navconfig.logging import logging

from ..conf import AUTH_DB_SCHEMA
from .types import StoredCredential

logger = logging.getLogger("navigator.passkey")

_CREDENTIALS = f"{AUTH_DB_SCHEMA}.user_credentials"
_HANDLES = f"{AUTH_DB_SCHEMA}.user_passkey_handles"


class PasskeyStore:
    """CRUD over ``user_credentials`` and ``user_passkey_handles``."""

    def __init__(self, db_pool: Any) -> None:
        """Bind the store to ``app["authdb"]``.

        Args:
            db_pool: asyncdb/asyncpg pool exposing ``acquire()``.
        """
        self._pool = db_pool

    @staticmethod
    def _row_to_credential(row: Any) -> StoredCredential:
        """Map a DB row to ``StoredCredential`` (aaguid UUID → str, transports → list)."""
        data = dict(row)
        if data.get("aaguid") is not None:
            data["aaguid"] = str(data["aaguid"])
        if data.get("transports") is not None:
            data["transports"] = list(data["transports"])
        for key in ("credential_id", "public_key"):
            if data.get(key) is not None:
                data[key] = bytes(data[key])
        return StoredCredential(**data)

    async def get_credential(self, credential_id: bytes) -> Optional[StoredCredential]:
        """Return one credential by id, or ``None``."""
        async with await self._pool.acquire() as conn:
            row = await conn.fetch_one(
                f"SELECT * FROM {_CREDENTIALS} WHERE credential_id = $1",
                credential_id,
            )
        return self._row_to_credential(row) if row else None

    async def list_credentials(self, user_id: int, rp_id: Optional[str] = None) -> list[StoredCredential]:
        """All credentials of a user, optionally limited to one RP, oldest first."""
        async with await self._pool.acquire() as conn:
            if rp_id is None:
                rows = await conn.fetch_all(
                    f"SELECT * FROM {_CREDENTIALS} WHERE user_id = $1 " "ORDER BY created_at",
                    user_id,
                )
            else:
                rows = await conn.fetch_all(
                    f"SELECT * FROM {_CREDENTIALS} WHERE user_id = $1 AND rp_id = $2 " "ORDER BY created_at",
                    user_id,
                    rp_id,
                )
        return [self._row_to_credential(r) for r in rows or []]

    async def save_credential(self, credential: StoredCredential) -> None:
        """Insert a newly registered credential."""
        async with await self._pool.acquire() as conn:
            await conn.execute(
                f"INSERT INTO {_CREDENTIALS} "
                "(credential_id, user_id, rp_id, public_key, sign_count, transports, "
                "aaguid, device_type, backed_up, label) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7::uuid, $8, $9, $10)",
                credential.credential_id,
                credential.user_id,
                credential.rp_id,
                credential.public_key,
                credential.sign_count,
                credential.transports,
                credential.aaguid,
                credential.device_type,
                credential.backed_up,
                credential.label,
            )

    async def update_usage(self, credential_id: bytes, *, sign_count: int, backed_up: bool) -> None:
        """Raise ``sign_count`` (never lower it), set ``backed_up`` and ``last_used_at = now()``."""
        async with await self._pool.acquire() as conn:
            await conn.execute(
                f"UPDATE {_CREDENTIALS} SET sign_count = GREATEST(sign_count, $2), backed_up = $3, "
                "last_used_at = now() WHERE credential_id = $1",
                credential_id,
                sign_count,
                backed_up,
            )

    async def rename_credential(self, user_id: int, credential_id: bytes, label: str) -> bool:
        """Rename a credential owned by ``user_id``; True when a row changed."""
        async with await self._pool.acquire() as conn:
            changed = await conn.fetchval(
                f"WITH u AS (UPDATE {_CREDENTIALS} SET label = $3 "
                "WHERE user_id = $1 AND credential_id = $2 RETURNING 1) "
                "SELECT count(*) FROM u",
                user_id,
                credential_id,
                label,
            )
        return bool(changed)

    async def delete_credential(self, user_id: int, credential_id: bytes, *, keep_last: bool = False) -> bool:
        """Delete a credential owned by ``user_id``; True when a row was removed.

        Args:
            user_id: Owner of the credential.
            credential_id: Credential to delete.
            keep_last: When True the row is only deleted if the user has another
                credential, checked atomically in the same statement (no
                check-then-act race).
        """
        guard = f" AND (SELECT count(*) FROM {_CREDENTIALS} WHERE user_id = $1) > 1" if keep_last else ""
        async with await self._pool.acquire() as conn:
            removed = await conn.fetchval(
                f"WITH d AS (DELETE FROM {_CREDENTIALS} "
                f"WHERE user_id = $1 AND credential_id = $2{guard} RETURNING 1) "
                "SELECT count(*) FROM d",
                user_id,
                credential_id,
            )
        return bool(removed)

    async def count_credentials(self, user_id: int) -> int:
        """Number of credentials of a user across all RPs."""
        async with await self._pool.acquire() as conn:
            count = await conn.fetchval(
                f"SELECT count(*) FROM {_CREDENTIALS} WHERE user_id = $1",
                user_id,
            )
        return int(count or 0)

    async def get_handle(self, user_id: int, rp_id: str) -> Optional[bytes]:
        """The user's WebAuthn user handle for ``rp_id``, or ``None``."""
        async with await self._pool.acquire() as conn:
            handle = await conn.fetchval(
                f"SELECT user_handle FROM {_HANDLES} WHERE user_id = $1 AND rp_id = $2",
                user_id,
                rp_id,
            )
        return bytes(handle) if handle is not None else None

    async def get_or_create_handle(self, user_id: int, rp_id: str) -> bytes:
        """Return the user's handle for ``rp_id``, creating ``secrets.token_bytes(32)`` if absent.

        Race-safe: the ``(user_id, rp_id)`` primary key serialises concurrent
        inserts, and the handle is random (never derived from PII, E15).
        """
        candidate = secrets.token_bytes(32)
        async with await self._pool.acquire() as conn:
            await conn.execute(
                f"INSERT INTO {_HANDLES} (user_id, rp_id, user_handle) "
                "VALUES ($1, $2, $3) ON CONFLICT (user_id, rp_id) DO NOTHING",
                user_id,
                rp_id,
                candidate,
            )
        handle = await self.get_handle(user_id, rp_id)
        if handle is None:  # pragma: no cover - defensive
            raise RuntimeError("could not create passkey user handle")
        return handle
