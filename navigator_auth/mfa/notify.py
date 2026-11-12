"""Callback hand-offs for FEAT-106 (OTP delivery and security notices)."""

import asyncio
import importlib
import inspect
import logging
from typing import Optional

from navigator_auth import conf as auth_conf

from .types import MfaModel, MfaSecurityNotice

logger = logging.getLogger("navigator.mfa")


async def invoke_callback(path: Optional[str], payload: MfaModel, *, label: str) -> bool:
    """Invoke callbacks without blocking the loop; cancellation propagates to the caller.

    Synchronous I/O runs in a worker thread. Cancelling its await cannot stop that
    thread, so a timed-out callback may still finish its external delivery later.
    """
    if not path:
        logger.warning("MFA: no %s callback configured; dropping hand-off", label)
        return False
    try:
        package, name = path.rsplit(".", 1)
        callback = getattr(importlib.import_module(package), name)
        if asyncio.iscoroutinefunction(callback):
            await callback(payload)
        else:
            result = await asyncio.to_thread(callback, payload)
            if inspect.isawaitable(result):
                await result
        return True
    except Exception as ex:  # noqa: BLE001 - callback failures must be contained
        logger.warning("MFA: %s callback failed: %s", label, type(ex).__name__)
        return False


async def notify_security_event(notice: MfaSecurityNotice) -> None:
    """Hand off a factor-state change notification; never raise."""
    path = auth_conf.AUTH_MFA_NOTIFY_CALLBACK
    if not path:
        logger.info(
            "MFA: security event %s for user %s (no AUTH_MFA_NOTIFY_CALLBACK configured)",
            notice.event,
            notice.username,
        )
        return
    await invoke_callback(path, notice, label="security-notice")
