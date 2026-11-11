"""Security-transition hooks shared by non-MFA credential changes."""

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from navigator_auth.mfa.services import get_mfa_services
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
) -> AsyncIterator[Optional[Any]]:
    """Run a credential change under the user's MFA security lock."""
    if event not in SECURITY_EVENTS:
        raise ValueError(f"unknown MFA security event {event!r}")
    services = get_mfa_services(app)
    if services is None:
        yield None
        return
    if not services.available:
        logger.error("MFA security transition unavailable: event=%s user_id=%s", event, user_id)
        yield None
        return

    lock_cm = services.security.user_lock(int(user_id))
    try:
        conn = await lock_cm.__aenter__()
    except BaseException as exc:
        # Fail closed: never run the credential change without the lock, version bump and audit.
        logger.error(
            "MFA security transition lock failed: event=%s user_id=%s error=%s", event, user_id, type(exc).__name__
        )
        raise

    try:
        yield conn
        await services.security.bump_version(conn, int(user_id))
        if revoke_devices:
            await services.trusted_devices.revoke_all(int(user_id), event, conn=conn)
        await services.security.write_audit(
            conn,
            MfaAuditEntry(
                actor_user_id=actor_user_id,
                target_user_id=int(user_id),
                org_id=None,
                action=event,
                method=None,
                request_id=request_id,
                outcome="success",
                detail=dict(detail or {}),
            ),
        )
    except BaseException as exc:
        try:
            await lock_cm.__aexit__(type(exc), exc, exc.__traceback__)
        except BaseException:
            pass
        logger.error("MFA security transition failed: event=%s user_id=%s error=%s", event, user_id, type(exc).__name__)
        # Propagate: a failing body (or failing bump/revoke/audit) must never look like success.
        raise
    try:
        await lock_cm.__aexit__(None, None, None)
    except BaseException as exc:
        logger.error(
            "MFA security transition commit failed: event=%s user_id=%s error=%s", event, user_id, type(exc).__name__
        )
        raise
