"""MFA security primitives (FEAT-106, spec section 3 security contracts)."""

import hashlib
import hmac
import json
import logging
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Any

from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_PASSWORD_ATTRIBUTE, AUTH_USERID_ATTRIBUTE
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.types import MfaAuditEntry, MfaState, TenantMfaPolicy

logger = logging.getLogger("navigator.mfa")

LOCK_NAMESPACE = 0x4D464131
_INT4_MAX = 2**31 - 1
_DIGEST_DOMAIN = b"navigator-auth/mfa/context/v1|"


def _canonical_bytes(fields: dict) -> bytes:
    """Serialize digest fields deterministically."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _user_field(user: Mapping, name: str, default: Any = None) -> Any:
    """Read a field from either a mapping or an attribute-based user model."""
    try:
        value = user[name]
    except (KeyError, TypeError, AttributeError):
        value = getattr(user, name, default)
    return default if value is None else value


def _lock_key(user_id: int) -> int:
    """Return the bounded advisory-lock key for a non-negative user id."""
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id < 0:
        raise ValueError("user_id must be a non-negative integer")
    return user_id if user_id <= _INT4_MAX else user_id % _INT4_MAX


class MfaSecurity:
    """Per-user lock, security version, durable audit and context digest."""

    def __init__(self, db_pool: Any, secret: bytes):
        """Bind security operations to a database pool and HMAC secret."""
        if not secret:
            raise ValueError("MfaSecurity requires a non-empty secret")
        self._pool = db_pool
        self._secret = secret
        self._schema = AUTH_DB_SCHEMA

    @asynccontextmanager
    async def user_lock(self, user_id: int) -> AsyncIterator[Any]:
        """Yield a transaction holding a PostgreSQL advisory lock for one user."""
        key = _lock_key(user_id)
        async with await self._pool.acquire() as conn:
            try:
                await conn.transaction()
                await conn.fetchval(
                    "SELECT pg_advisory_xact_lock($1::int4, $2::int4)", LOCK_NAMESPACE, key
                )
            except Exception as err:
                try:
                    await conn.rollback()
                except Exception:
                    pass
                raise MfaStorageError(f"MFA user lock failed: {type(err).__name__}") from err
            try:
                yield conn
            except BaseException:
                await conn.rollback()
                raise
            try:
                await conn.commit()
            except Exception as err:
                raise MfaStorageError(f"MFA user lock commit failed: {type(err).__name__}") from err

    async def current_version(self, conn: Any, user_id: int) -> int:
        """Return the user's security version, atomically creating it at zero."""
        sql = (
            f"WITH ins AS (INSERT INTO {self._schema}.user_mfa_security (user_id) VALUES ($1) "
            f"ON CONFLICT (user_id) DO NOTHING RETURNING version) "
            f"SELECT version FROM ins UNION ALL "
            f"SELECT version FROM {self._schema}.user_mfa_security WHERE user_id = $1 LIMIT 1"
        )
        try:
            version = await conn.fetchval(sql, int(user_id))
            if version is None:
                raise ValueError("security version was not returned")
            return int(version)
        except Exception as err:
            raise MfaStorageError(f"MFA security version read failed: {type(err).__name__}") from err

    async def bump_version(self, conn: Any, user_id: int) -> int:
        """Increment and return the user's monotonic security version."""
        sql = (
            f"INSERT INTO {self._schema}.user_mfa_security (user_id, version) VALUES ($1, 1) "
            f"ON CONFLICT (user_id) DO UPDATE SET "
            f"version = {self._schema}.user_mfa_security.version + 1, updated_at = now() "
            f"RETURNING version"
        )
        try:
            version = await conn.fetchval(sql, int(user_id))
            if version is None:
                raise ValueError("security version was not returned")
            return int(version)
        except Exception as err:
            raise MfaStorageError(f"MFA security version bump failed: {type(err).__name__}") from err

    async def write_audit(self, conn: Any, entry: MfaAuditEntry) -> None:
        """Insert a durable MFA audit record in the caller's transaction."""
        sql = (
            f"INSERT INTO {self._schema}.user_mfa_audit (actor_user_id, target_user_id, org_id, "
            f"action, old_state, new_state, method, request_id, outcome, detail) "
            f"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id"
        )
        try:
            audit_id = await conn.fetchval(
                sql,
                entry.actor_user_id,
                entry.target_user_id,
                entry.org_id,
                entry.action,
                entry.old_state,
                entry.new_state,
                entry.method,
                entry.request_id,
                entry.outcome,
                dict(entry.detail),
            )
            if audit_id is None:
                raise ValueError("audit id was not returned")
        except Exception as err:
            raise MfaStorageError(f"MFA audit write failed: {type(err).__name__}") from err

    def context_digest(
        self,
        *,
        user: Mapping,
        memberships: tuple[int, ...],
        policy: TenantMfaPolicy,
        state: MfaState,
        has_strong_factor: bool,
    ) -> str:
        """Return an HMAC digest of the challenge's canonical security context."""
        fields = {
            "v": 1,
            "uid": int(_user_field(user, AUTH_USERID_ATTRIBUTE)),
            "pwd": str(_user_field(user, AUTH_PASSWORD_ATTRIBUTE, "") or ""),
            "active": bool(_user_field(user, "is_active", True)),
            "su": bool(_user_field(user, "is_superuser", False)),
            "email": str(_user_field(user, "email", "") or "").strip().lower(),
            "orgs": sorted({int(org) for org in memberships}),
            "policy_org": int(policy.org_id),
            "mode": policy.mode.value,
            "remember_days": int(policy.remember_days),
            "state": state.value,
            "strong": bool(has_strong_factor),
        }
        return hmac.new(self._secret, _DIGEST_DOMAIN + _canonical_bytes(fields), hashlib.sha256).hexdigest()
