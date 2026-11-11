"""Security-transition hooks shared by non-MFA credential changes."""

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from navigator_auth.mfa.exceptions import MfaStorageError, MfaUnavailable
from navigator_auth.mfa.security import advisory_user_lock
from navigator_auth.mfa.services import mfa_services_lease
from navigator_auth.mfa.types import MfaAuditEntry

logger = logging.getLogger("navigator.mfa.events")

SECURITY_EVENTS = frozenset(
    {
        "password_change",
        "password_reset",
        "recovery_completion",
        "passkey_registered",
        "passkey_removed",
        "global_logout",
    }
)


class TransitionAborted(Exception):
    """Raised by a transition body to roll back with a client-facing reason (logged at info)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@asynccontextmanager
async def security_transition(
    app: Any,
    user_id: int,
    event: str,
    *,
    actor_user_id: Optional[int] = None,
    revoke_devices: bool = True,
    detail: Optional[dict] = None,
    request_id: Optional[str] = None,
) -> AsyncIterator[Any]:
    """Yield one live connection inside one transaction for a credential change.

    No configured MFA service takes an advisory-locked ``authdb`` transaction without
    bookkeeping. Available MFA services use their security lock and perform version,
    device, and audit bookkeeping after the body on the yielded connection.
    """
    if event not in SECURITY_EVENTS:
        raise ValueError(f"unknown MFA security event {event!r}")
    uid = int(user_id)
    async with mfa_services_lease(app) as services:
        if services is None:
            db_pool = app.get("authdb") if app is not None else None
            if db_pool is None:
                raise MfaStorageError("security transition requires app['authdb']")
            async with advisory_user_lock(db_pool, uid) as conn:
                try:
                    yield conn
                except BaseException as exc:
                    _log_failure(event, uid, exc)
                    raise
            return
        if not services.available:
            logger.error("MFA security transition unavailable: event=%s user_id=%s", event, uid)
            raise MfaUnavailable("MFA services unavailable")
        async with services.security.user_lock(uid) as conn:
            try:
                yield conn
                await services.security.bump_version(conn, uid)
                if revoke_devices:
                    await services.trusted_devices.revoke_all(uid, event, conn=conn)
                await services.security.write_audit(
                    conn,
                    MfaAuditEntry(
                        actor_user_id=actor_user_id,
                        target_user_id=uid,
                        org_id=None,
                        action=event,
                        method=None,
                        request_id=request_id,
                        outcome="success",
                        detail=dict(detail or {}),
                    ),
                )
            except BaseException as exc:
                _log_failure(event, uid, exc)
                raise


def _log_failure(event: str, user_id: int, exc: BaseException) -> None:
    """Log a rolled-back transition without exposing exception details."""
    if isinstance(exc, TransitionAborted):
        logger.info("MFA security transition aborted: event=%s user_id=%s reason=%s", event, user_id, exc.reason)
        return
    logger.error("MFA security transition failed: event=%s user_id=%s error=%s", event, user_id, type(exc).__name__)
