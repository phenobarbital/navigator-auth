"""Per-client access gate storage — FEAT-095 TASK-042 (decisions D3 + D7).

Registration confers nothing (DCR is open, D1); *this* is the access control.
A user must hold an ``active`` row for a client before ``/oauth2/authorize``
(or device verification) will let them reach consent.  A denied attempt on a
gated client records a single ``pending`` row so an administrator can see who
asked and approve or reject them (D7).

Storage follows the FEAT-093 pattern: an ABC plus memory / redis / postgres
tiers and a factory.  The record type is the asyncdb
:class:`~navigator_auth.models.ClientAccess` model, so all three tiers speak
the same shape as the ``auth.client_access`` table.

Status values:
  ``active``  — may authorize.
  ``pending`` — denied, awaiting approval.
  ``revoked`` — withdrawn; the caller cascades token revocation.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional
import json
import logging

from aiohttp import web

from navigator_auth.models import ClientAccess

try:
    import redis.asyncio as redis
except ImportError:  # pragma: no cover
    import redis


__all__ = (
    "STATUS_ACTIVE",
    "STATUS_PENDING",
    "STATUS_REVOKED",
    "ClientAccessStorage",
    "MemoryClientAccessStorage",
    "PostgresClientAccessStorage",
    "RedisClientAccessStorage",
    "get_client_access_storage",
)


STATUS_ACTIVE: str = "active"
STATUS_PENDING: str = "pending"
STATUS_REVOKED: str = "revoked"


def _now() -> datetime:
    return datetime.now()


def _record(
    user_id: int,
    client_uid: str,
    status: str,
    *,
    client_pk: Optional[int] = None,
    granted_by: Optional[int] = None,
) -> ClientAccess:
    """Build a ClientAccess row object (not persisted)."""
    return ClientAccess(
        user_id=user_id,
        client_id=client_pk,
        client_uid=client_uid,
        status=status,
        granted_by=granted_by,
        granted_at=_now(),
    )


def _to_payload(access: ClientAccess) -> dict:
    """Serialise a record for the Redis tier."""
    return {
        "access_id": str(getattr(access, "access_id", "") or ""),
        "user_id": int(_user_id_of(access)),
        "client_id": access.client_id,
        "client_uid": access.client_uid,
        "status": access.status,
        "granted_by": access.granted_by,
        "granted_at": (
            access.granted_at.isoformat() if access.granted_at else None
        ),
        "revoked_at": (
            access.revoked_at.isoformat() if access.revoked_at else None
        ),
    }


def _from_payload(data: dict) -> ClientAccess:
    """Rebuild a record from its Redis representation."""
    access = ClientAccess(
        user_id=data["user_id"],
        client_id=data.get("client_id"),
        client_uid=data["client_uid"],
        status=data.get("status", STATUS_ACTIVE),
        granted_by=data.get("granted_by"),
    )
    for field in ("granted_at", "revoked_at"):
        raw = data.get(field)
        if raw:
            try:
                setattr(access, field, datetime.fromisoformat(raw))
            except (TypeError, ValueError):
                pass
    return access


def _user_id_of(access: ClientAccess) -> int:
    """Read the integer user id off a record.

    ``ClientAccess.user_id`` is declared as an FK to ``User``, so asyncdb may
    hand back either the raw integer or a hydrated model object.
    """
    value = access.user_id
    if isinstance(value, int):
        return value
    return int(getattr(value, "user_id", value))


class ClientAccessStorage(ABC):
    """Access-gate storage contract (spec §2)."""

    @abstractmethod
    async def get(
        self, user_id: int, client_uid: str, request: Optional[web.Request] = None
    ) -> Optional[ClientAccess]:
        """Return the row for (user, client), whatever its status."""

    @abstractmethod
    async def check(
        self, user_id: int, client_uid: str, request: Optional[web.Request] = None
    ) -> bool:
        """True only when an ``active`` row exists — fail closed."""

    @abstractmethod
    async def grant(
        self,
        user_id: int,
        client_uid: str,
        granted_by: Optional[int] = None,
        *,
        client_pk: Optional[int] = None,
        request: Optional[web.Request] = None,
    ) -> ClientAccess:
        """Activate access for (user, client). Idempotent upsert."""

    @abstractmethod
    async def revoke(
        self, user_id: int, client_uid: str, request: Optional[web.Request] = None
    ) -> bool:
        """Mark access revoked. The caller cascades token revocation."""

    @abstractmethod
    async def list_for_client(
        self, client_uid: str, request: Optional[web.Request] = None
    ) -> list:
        """Every row for a client, any status (management API)."""

    @abstractmethod
    async def request_access(
        self,
        user_id: int,
        client_uid: str,
        *,
        client_pk: Optional[int] = None,
        request: Optional[web.Request] = None,
    ) -> Optional[ClientAccess]:
        """Record a denied attempt as a single ``pending`` row (D7).

        Upsert: repeated denied attempts must not accumulate duplicates, and
        an existing ``active`` or ``revoked`` row is never downgraded.
        """

    async def list_pending(
        self, client_uid: str, request: Optional[web.Request] = None
    ) -> list:
        """The approval queue for a client."""
        rows = await self.list_for_client(client_uid, request=request)
        return [r for r in rows if r.status == STATUS_PENDING]

    async def approve(
        self,
        user_id: int,
        client_uid: str,
        granted_by: Optional[int] = None,
        request: Optional[web.Request] = None,
    ) -> Optional[ClientAccess]:
        """Approve a pending request (``pending`` → ``active``)."""
        existing = await self.get(user_id, client_uid, request=request)
        if not existing or existing.status != STATUS_PENDING:
            return None
        return await self.grant(
            user_id,
            client_uid,
            granted_by,
            client_pk=existing.client_id,
            request=request,
        )

    async def reject(
        self, user_id: int, client_uid: str, request: Optional[web.Request] = None
    ) -> bool:
        """Reject a pending request (``pending`` → ``revoked``)."""
        existing = await self.get(user_id, client_uid, request=request)
        if not existing or existing.status != STATUS_PENDING:
            return False
        return await self.revoke(user_id, client_uid, request=request)


class MemoryClientAccessStorage(ClientAccessStorage):
    """In-process gate storage (tests / single-process deployments)."""

    def __init__(self):
        # (user_id, client_uid) -> ClientAccess
        self._rows: dict = {}

    async def get(self, user_id, client_uid, request=None):
        return self._rows.get((int(user_id), client_uid))

    async def check(self, user_id, client_uid, request=None):
        row = self._rows.get((int(user_id), client_uid))
        return bool(row and row.status == STATUS_ACTIVE)

    async def grant(
        self, user_id, client_uid, granted_by=None, *, client_pk=None, request=None
    ):
        key = (int(user_id), client_uid)
        row = self._rows.get(key)
        if row:
            row.status = STATUS_ACTIVE
            row.granted_by = granted_by
            row.granted_at = _now()
            row.revoked_at = None
            if client_pk is not None:
                row.client_id = client_pk
        else:
            row = _record(
                user_id,
                client_uid,
                STATUS_ACTIVE,
                client_pk=client_pk,
                granted_by=granted_by,
            )
            self._rows[key] = row
        return row

    async def revoke(self, user_id, client_uid, request=None):
        row = self._rows.get((int(user_id), client_uid))
        if not row:
            return False
        row.status = STATUS_REVOKED
        row.revoked_at = _now()
        return True

    async def list_for_client(self, client_uid, request=None):
        return [r for r in self._rows.values() if r.client_uid == client_uid]

    async def request_access(self, user_id, client_uid, *, client_pk=None, request=None):
        key = (int(user_id), client_uid)
        existing = self._rows.get(key)
        if existing:
            # Never downgrade an active or revoked decision.
            return existing if existing.status == STATUS_PENDING else None
        row = _record(user_id, client_uid, STATUS_PENDING, client_pk=client_pk)
        self._rows[key] = row
        return row


class RedisClientAccessStorage(ClientAccessStorage):
    """Redis-backed gate storage (shared across workers)."""

    def __init__(self, dsn: str):
        self.redis = redis.from_url(dsn, decode_responses=True)
        self.prefix = "oauth2:client_access:"
        self.client_index_prefix = "oauth2:client_access:client:"

    def _key(self, user_id, client_uid) -> str:
        return f"{self.prefix}{int(user_id)}:{client_uid}"

    async def _save(self, access: ClientAccess) -> ClientAccess:
        uid = _user_id_of(access)
        await self.redis.set(
            self._key(uid, access.client_uid), json.dumps(_to_payload(access))
        )
        await self.redis.sadd(
            f"{self.client_index_prefix}{access.client_uid}", str(uid)
        )
        return access

    async def get(self, user_id, client_uid, request=None):
        data = await self.redis.get(self._key(user_id, client_uid))
        if not data:
            return None
        try:
            return _from_payload(json.loads(data))
        except Exception as e:  # pragma: no cover — defensive
            logging.error(f"Error decoding client_access from Redis: {e}")
            return None

    async def check(self, user_id, client_uid, request=None):
        row = await self.get(user_id, client_uid)
        return bool(row and row.status == STATUS_ACTIVE)

    async def grant(
        self, user_id, client_uid, granted_by=None, *, client_pk=None, request=None
    ):
        row = await self.get(user_id, client_uid)
        if row:
            row.status = STATUS_ACTIVE
            row.granted_by = granted_by
            row.granted_at = _now()
            row.revoked_at = None
            if client_pk is not None:
                row.client_id = client_pk
        else:
            row = _record(
                user_id,
                client_uid,
                STATUS_ACTIVE,
                client_pk=client_pk,
                granted_by=granted_by,
            )
        return await self._save(row)

    async def revoke(self, user_id, client_uid, request=None):
        row = await self.get(user_id, client_uid)
        if not row:
            return False
        row.status = STATUS_REVOKED
        row.revoked_at = _now()
        await self._save(row)
        return True

    async def list_for_client(self, client_uid, request=None):
        user_ids = await self.redis.smembers(
            f"{self.client_index_prefix}{client_uid}"
        )
        rows = []
        for uid in user_ids:
            row = await self.get(uid, client_uid)
            if row:
                rows.append(row)
        return rows

    async def request_access(self, user_id, client_uid, *, client_pk=None, request=None):
        existing = await self.get(user_id, client_uid)
        if existing:
            return existing if existing.status == STATUS_PENDING else None
        row = _record(user_id, client_uid, STATUS_PENDING, client_pk=client_pk)
        return await self._save(row)


class PostgresClientAccessStorage(ClientAccessStorage):
    """Durable gate storage over ``auth.client_access``."""

    def _connection(self, request: Optional[web.Request]):
        if request:
            return request.app.get("authdb")
        return None

    async def get(self, user_id, client_uid, request=None):
        db = self._connection(request)
        if not db:
            logging.warning("PostgresClientAccessStorage: no DB connection.")
            return None
        try:
            async with await db.acquire() as conn:
                ClientAccess.Meta.connection = conn
                rows = await ClientAccess.filter(
                    user_id=int(user_id), client_uid=client_uid
                )
                return rows[0] if rows else None
        except Exception as e:
            logging.error(f"Error fetching client_access: {e}")
            return None

    async def check(self, user_id, client_uid, request=None):
        row = await self.get(user_id, client_uid, request=request)
        return bool(row and row.status == STATUS_ACTIVE)

    async def grant(
        self, user_id, client_uid, granted_by=None, *, client_pk=None, request=None
    ):
        db = self._connection(request)
        if not db:
            logging.warning("PostgresClientAccessStorage: no DB connection.")
            return None
        try:
            async with await db.acquire() as conn:
                ClientAccess.Meta.connection = conn
                rows = await ClientAccess.filter(
                    user_id=int(user_id), client_uid=client_uid
                )
                if rows:
                    row = rows[0]
                    row.status = STATUS_ACTIVE
                    row.granted_by = granted_by
                    row.granted_at = _now()
                    row.revoked_at = None
                    if client_pk is not None:
                        row.client_id = client_pk
                    await row.update()
                    return row
                row = _record(
                    user_id,
                    client_uid,
                    STATUS_ACTIVE,
                    client_pk=client_pk,
                    granted_by=granted_by,
                )
                await row.insert()
                return row
        except Exception as e:
            logging.error(f"Error granting client_access: {e}")
            return None

    async def revoke(self, user_id, client_uid, request=None):
        db = self._connection(request)
        if not db:
            return False
        try:
            async with await db.acquire() as conn:
                ClientAccess.Meta.connection = conn
                rows = await ClientAccess.filter(
                    user_id=int(user_id), client_uid=client_uid
                )
                if not rows:
                    return False
                row = rows[0]
                row.status = STATUS_REVOKED
                row.revoked_at = _now()
                await row.update()
                return True
        except Exception as e:
            logging.error(f"Error revoking client_access: {e}")
            return False

    async def list_for_client(self, client_uid, request=None):
        db = self._connection(request)
        if not db:
            return []
        try:
            async with await db.acquire() as conn:
                ClientAccess.Meta.connection = conn
                return await ClientAccess.filter(client_uid=client_uid) or []
        except Exception as e:
            logging.error(f"Error listing client_access: {e}")
            return []

    async def request_access(self, user_id, client_uid, *, client_pk=None, request=None):
        db = self._connection(request)
        if not db:
            return None
        try:
            async with await db.acquire() as conn:
                ClientAccess.Meta.connection = conn
                rows = await ClientAccess.filter(
                    user_id=int(user_id), client_uid=client_uid
                )
                if rows:
                    row = rows[0]
                    return row if row.status == STATUS_PENDING else None
                row = _record(
                    user_id, client_uid, STATUS_PENDING, client_pk=client_pk
                )
                await row.insert()
                return row
        except Exception as e:
            # A unique-constraint violation means a concurrent denied attempt
            # already queued this pair — exactly the desired end state.
            logging.warning(f"Could not queue access request: {e}")
            return None


def get_client_access_storage(
    storage_type: str = "postgres", dsn: str = None
) -> ClientAccessStorage:
    """Return the ClientAccessStorage matching the configured tier."""
    if storage_type == "memory":
        return MemoryClientAccessStorage()
    if storage_type == "redis":
        return RedisClientAccessStorage(dsn)
    return PostgresClientAccessStorage()
