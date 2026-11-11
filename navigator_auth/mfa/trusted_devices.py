"""Trusted devices for the BasicAuth second factor."""

import hashlib
import logging
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Optional

from navigator_auth.conf import AUTH_DB_SCHEMA
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.types import TrustedDevice

logger = logging.getLogger("navigator.mfa.trusted_devices")

_TABLE = f"{AUTH_DB_SCHEMA}.user_trusted_devices"
_ORG_MEMBERSHIP_TABLE = "organization_users"
_MEMBERSHIP = f"{AUTH_DB_SCHEMA}.{_ORG_MEMBERSHIP_TABLE}"


def _hash_token(raw_token: str) -> str:
    """Return the only form of a cookie token stored by this module."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def may_offer_trusted_device(*, has_strong_factor: bool, remember_days: int) -> bool:
    """Return whether a strong-factor user may receive a trusted-device cookie."""
    return has_strong_factor and remember_days > 0


class TrustedDeviceStore:
    """Rotating bearer second factor with replay detection, bound to a user."""

    def __init__(self, db_pool: Any) -> None:
        """Bind the store to an asyncdb/asyncpg pool."""
        self._pool = db_pool

    @asynccontextmanager
    async def _scope(self, conn: Any = None) -> AsyncIterator[Any]:
        """Yield a caller transaction connection or acquire one from the pool."""
        if conn is not None:
            yield conn
            return
        async with await self._pool.acquire() as own:
            yield own

    async def issue(self, user_id: int, days: int, label: str, *, conn: Any = None) -> str:
        """Create a trusted-device family and return its raw cookie token."""
        if days <= 0:
            raise ValueError("Trusted devices require remember_days > 0")
        raw = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(days=days)
        try:
            async with self._scope(conn) as db:
                row_id = await db.fetchval(
                    f"INSERT INTO {_TABLE} (user_id, token_hash, family_id, label, expires_at) "
                    "VALUES ($1, $2, $3, $4, $5) RETURNING id",
                    int(user_id),
                    _hash_token(raw),
                    uuid.uuid4(),
                    (label or "")[:128],
                    expires_at,
                )
        except Exception as err:
            raise MfaStorageError(f"trusted device issue failed: {type(err).__name__}") from err
        if not row_id:
            raise MfaStorageError("trusted device issue returned no row")
        return raw

    async def consume_and_rotate(self, raw_token: str, user_id: int) -> Optional[tuple[int, str]]:
        """Validate and atomically rotate a live token, or revoke on replay."""
        if not raw_token:
            return None
        try:
            async with await self._pool.acquire() as conn:
                await conn.transaction()
                try:
                    row = await conn.fetch_one(
                        f"SELECT id, user_id, family_id, label, expires_at, rotated_at, revoked_at "
                        f"FROM {_TABLE} WHERE token_hash = $1 FOR UPDATE",
                        _hash_token(raw_token),
                    )
                    if row is None or int(row["user_id"]) != int(user_id) or row["revoked_at"] is not None:
                        await conn.rollback()
                        return None
                    if row["rotated_at"] is not None:
                        await conn.fetchval(
                            f"WITH r AS (UPDATE {_TABLE} SET revoked_at = now(), revoke_reason = 'replay' "
                            "WHERE family_id = $1 AND revoked_at IS NULL RETURNING 1) SELECT count(*) FROM r",
                            row["family_id"],
                        )
                        await conn.commit()
                        logger.warning("trusted device replay: family revoked user_id=%s", user_id)
                        return None
                    now = datetime.now(timezone.utc)
                    if row["expires_at"] <= now:
                        await conn.rollback()
                        return None
                    new_raw = secrets.token_urlsafe(32)
                    await conn.fetchval(
                        f"UPDATE {_TABLE} SET rotated_at = now(), last_used_at = now() "
                        "WHERE id = $1 RETURNING id",
                        row["id"],
                    )
                    new_id = await conn.fetchval(
                        f"INSERT INTO {_TABLE} (user_id, token_hash, family_id, label, expires_at) "
                        "VALUES ($1, $2, $3, $4, $5) RETURNING id",
                        int(row["user_id"]),
                        _hash_token(new_raw),
                        row["family_id"],
                        row["label"],
                        row["expires_at"],
                    )
                    if not new_id:
                        raise MfaStorageError("trusted device rotation returned no row")
                    await conn.commit()
                    return int(row["user_id"]), new_raw
                except BaseException:
                    await conn.rollback()
                    raise
        except MfaStorageError:
            raise
        except Exception as err:
            raise MfaStorageError(f"trusted device rotation failed: {type(err).__name__}") from err

    async def revoke_all(self, user_id: int, reason: str, *, conn: Any = None) -> int:
        """Revoke every live device of a user and return the count."""
        try:
            async with self._scope(conn) as db:
                count = await db.fetchval(
                    f"WITH r AS (UPDATE {_TABLE} SET revoked_at = now(), revoke_reason = $2 "
                    "WHERE user_id = $1 AND revoked_at IS NULL RETURNING 1) SELECT count(*) FROM r",
                    int(user_id),
                    (reason or "")[:64],
                )
        except Exception as err:
            raise MfaStorageError(f"trusted device revoke_all failed: {type(err).__name__}") from err
        return int(count or 0)

    async def revoke_tenant(self, org_id: int, reason: str, *, conn: Any = None) -> int:
        """Revoke every live device belonging to members of a tenant."""
        try:
            async with self._scope(conn) as db:
                if await db.fetchval("SELECT to_regclass($1)", _MEMBERSHIP) is None:
                    return 0
                count = await db.fetchval(
                    f"WITH r AS (UPDATE {_TABLE} SET revoked_at = now(), revoke_reason = $2 "
                    f"WHERE revoked_at IS NULL AND user_id IN "
                    f"(SELECT user_id FROM {_MEMBERSHIP} WHERE org_id = $1) RETURNING 1) SELECT count(*) FROM r",
                    int(org_id),
                    (reason or "")[:64],
                )
        except Exception as err:
            raise MfaStorageError(f"trusted device revoke_tenant failed: {type(err).__name__}") from err
        return int(count or 0)

    async def list_active(self, user_id: int) -> list[TrustedDevice]:
        """Return a user's live, unrotated devices, oldest first."""
        try:
            async with await self._pool.acquire() as conn:
                rows = await conn.fetch_all(
                    f"SELECT user_id, token_hash, label, family_id, expires_at, last_used_at, revoked_at "
                    f"FROM {_TABLE} WHERE user_id = $1 AND revoked_at IS NULL AND rotated_at IS NULL "
                    "AND expires_at > now() ORDER BY created_at",
                    int(user_id),
                )
        except Exception as err:
            raise MfaStorageError(f"trusted device list_active failed: {type(err).__name__}") from err
        devices = []
        for row in rows or []:
            data = dict(row)
            data["family_id"] = str(data["family_id"])
            devices.append(TrustedDevice(**data))
        return devices
