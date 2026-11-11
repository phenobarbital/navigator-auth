"""Effective per-tenant MFA policy (FEAT-106, spec §3 Module 7).

The policy table is mutable operational data: it is read on EVERY login and
never cached. Membership comes from the authenticated user id, never from
request headers and never from the ABAC tenant helper (spec R14).
"""
import logging
from collections.abc import Sequence
from typing import Any, Optional

from navigator_auth.conf import AUTH_DB_SCHEMA
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.security import MfaSecurity
from navigator_auth.mfa.state import _scope, _user_id
from navigator_auth.mfa.trusted_devices import TrustedDeviceStore
from navigator_auth.mfa.types import (
    MfaAuditEntry,
    MfaMode,
    TenantMfaPolicy,
    MODE_STRICTNESS,
    NO_TENANT_ORG_ID,
)

logger = logging.getLogger("navigator.mfa.policy")

ORG_MEMBERSHIP_TABLE = "organization_users"
_MEMBERSHIP = f"{AUTH_DB_SCHEMA}.{ORG_MEMBERSHIP_TABLE}"
_POLICY = f"{AUTH_DB_SCHEMA}.tenant_mfa_policy"
_SECURITY = f"{AUTH_DB_SCHEMA}.user_mfa_security"
_COLUMNS = "org_id, mode, remember_days, enforced_at, enforced_by"

NO_TENANT_POLICY = TenantMfaPolicy(
    org_id=NO_TENANT_ORG_ID, mode=MfaMode.OFF, remember_days=0, enforced_at=None, enforced_by=None
)


def combine_policies(rows: Sequence[TenantMfaPolicy]) -> TenantMfaPolicy:
    """Strictest mode wins; smallest remember_days among non-OFF orgs wins (D9).

    Empty input -> NO_TENANT_POLICY (D8). Effective org_id/enforced_* come from the
    strictest org (tie -> smallest org_id, for determinism).
    """
    if not rows:
        return NO_TENANT_POLICY
    top = min(rows, key=lambda p: (-MODE_STRICTNESS[p.mode], p.org_id))
    days = [p.remember_days for p in rows if p.mode != MfaMode.OFF]
    return TenantMfaPolicy(
        org_id=top.org_id,
        mode=top.mode,
        remember_days=min(days) if days else 0,
        enforced_at=top.enforced_at,
        enforced_by=top.enforced_by,
    )


def is_hardening(old: TenantMfaPolicy, new: TenantMfaPolicy) -> bool:
    """D18: strictness increases, or remember_days decreases while new mode != OFF."""
    if MODE_STRICTNESS[new.mode] > MODE_STRICTNESS[old.mode]:
        return True
    return new.mode != MfaMode.OFF and new.remember_days < old.remember_days


def _row_to_policy(row: Any) -> TenantMfaPolicy:
    """Map a tenant_mfa_policy row; an unknown mode string is ambiguity -> MfaStorageError."""
    try:
        return TenantMfaPolicy(
            org_id=int(row["org_id"]),
            mode=MfaMode(row["mode"]),
            remember_days=int(row["remember_days"]),
            enforced_at=row["enforced_at"],
            enforced_by=row["enforced_by"],
        )
    except (ValueError, KeyError, TypeError) as err:
        raise MfaStorageError("unreadable tenant policy row") from err


class MfaPolicyResolver:
    """Process-lifetime object holding NO policy: every call is a fresh read (AC22)."""

    def __init__(self, db_pool: Any) -> None:
        self._pool = db_pool

    async def memberships(self, user_id: int, *, conn: Any = None) -> tuple[int, ...]:
        """Org ids of the authenticated user, from organization_users (D7). () when absent."""
        try:
            async with _scope(self._pool, conn) as db:
                if await db.fetchval("SELECT to_regclass($1)", _MEMBERSHIP) is None:
                    return ()
                rows = await db.fetch_all(
                    f"SELECT DISTINCT org_id FROM {_MEMBERSHIP} WHERE user_id = $1 ORDER BY org_id",
                    int(user_id),
                )
        except Exception as err:  # pylint: disable=W0703
            raise MfaStorageError(f"membership read failed: {type(err).__name__}") from err
        return tuple(int(r["org_id"]) for r in (rows or []))

    async def effective(
        self, user: Any, *, conn: Any = None, memberships: Optional[tuple[int, ...]] = None
    ) -> TenantMfaPolicy:
        """Fresh effective policy. Raises MfaStorageError on storage errors —
        never degrades to OFF (spec M7, AC22, test_policy_read_failure_fails_closed).
        """
        uid = _user_id(user)
        orgs = memberships if memberships is not None else await self.memberships(uid, conn=conn)
        if not orgs:
            return NO_TENANT_POLICY
        try:
            async with _scope(self._pool, conn) as db:
                rows = (
                    await db.fetch_all(
                        f"SELECT {_COLUMNS} FROM {_POLICY} WHERE org_id = ANY($1::bigint[])",
                        list(orgs),
                    )
                    or []
                )
        except Exception as err:  # pylint: disable=W0703
            raise MfaStorageError(f"policy read failed: {type(err).__name__}") from err
        return combine_policies([_row_to_policy(r) for r in rows])


async def apply_tenant_policy(
    *,
    db_pool: Any,
    security: MfaSecurity,
    trusted_devices: TrustedDeviceStore,
    org_id: int,
    mode: MfaMode,
    remember_days: int,
    actor: str,
    actor_user_id: Optional[int] = None,
) -> TenantMfaPolicy:
    """Change a tenant's MFA policy in ONE transaction (the v1 administration recipe).

    Hardening (D18) additionally: bumps auth.user_mfa_security.version for every
    member in one statement (outstanding challenges die), revokes the tenant's
    trusted devices, and audits. Relaxing only audits. Run the pre-flight
    (scripts/preflight_mfa.py) BEFORE switching a tenant to ENFORCED.

    Raises:
        ValueError: remember_days < 0 or org_id <= 0.
        MfaStorageError: the transaction failed (nothing was changed).
    """
    if remember_days < 0 or int(org_id) <= 0:
        raise ValueError("org_id must be positive and remember_days >= 0")
    mode = MfaMode(mode)
    try:
        async with await db_pool.acquire() as conn:
            await conn.transaction()
            try:
                old_row = await conn.fetch_one(
                    f"SELECT {_COLUMNS} FROM {_POLICY} WHERE org_id = $1 FOR UPDATE",
                    int(org_id),
                )
                old = (
                    _row_to_policy(old_row)
                    if old_row
                    else TenantMfaPolicy(
                        org_id=int(org_id),
                        mode=MfaMode.OFF,
                        remember_days=0,
                        enforced_at=None,
                        enforced_by=None,
                    )
                )
                new_row = await conn.fetch_one(
                    f"INSERT INTO {_POLICY} AS t (org_id, mode, remember_days, enforced_at, "
                    "enforced_by, updated_at) VALUES ($1, $2::varchar, $3, "
                    "CASE WHEN $2::varchar = 'enforced' THEN now() ELSE NULL END, $4, now()) "
                    "ON CONFLICT (org_id) DO UPDATE SET mode = EXCLUDED.mode, "
                    "remember_days = EXCLUDED.remember_days, "
                    "enforced_at = CASE WHEN EXCLUDED.mode = 'enforced' "
                    "THEN COALESCE(CASE WHEN t.mode = 'enforced' THEN t.enforced_at END, now()) "
                    "ELSE NULL END, "
                    "enforced_by = EXCLUDED.enforced_by, updated_at = now() "
                    f"RETURNING {_COLUMNS}",
                    int(org_id),
                    mode.value,
                    int(remember_days),
                    actor,
                )
                new = _row_to_policy(new_row)
                hardening = is_hardening(old, new)
                bumped = 0
                revoked = 0
                if hardening:
                    if await conn.fetchval("SELECT to_regclass($1)", _MEMBERSHIP) is not None:
                        bumped = int(
                            await conn.fetchval(
                                f"WITH m AS (SELECT DISTINCT user_id FROM {_MEMBERSHIP} "
                                "WHERE org_id = $1), "
                                f"up AS (INSERT INTO {_SECURITY} (user_id, version) "
                                "SELECT user_id, 1 FROM m "
                                "ON CONFLICT (user_id) DO UPDATE SET version = user_mfa_security.version + 1, "
                                "updated_at = now() RETURNING 1) SELECT count(*) FROM up",
                                int(org_id),
                            )
                            or 0
                        )
                    revoked = await trusted_devices.revoke_tenant(
                        int(org_id), "tenant_hardening", conn=conn
                    )
                await security.write_audit(
                    conn,
                    MfaAuditEntry(
                        actor_user_id=actor_user_id,
                        target_user_id=None,
                        org_id=int(org_id),
                        action="policy_change",
                        old_state=old.mode.value,
                        new_state=new.mode.value,
                        method="apply_tenant_policy",
                        outcome="success",
                        detail={
                            "actor": actor,
                            "hardening": hardening,
                            "remember_days": [old.remember_days, new.remember_days],
                            "bumped_users": bumped,
                            "revoked_devices": revoked,
                        },
                    ),
                )
                await conn.commit()
                return new
            except BaseException:
                await conn.rollback()
                raise
    except (ValueError, MfaStorageError):
        raise
    except Exception as err:  # pylint: disable=W0703
        raise MfaStorageError(f"apply_tenant_policy failed: {type(err).__name__}") from err
