"""Per-user second-factor state for the BasicAuth hook (FEAT-106, spec §3 Module 7).

none -> email -> totp, plus the strong-factor predicate: a confirmed TOTP OR at
least one registered passkey. A strong factor CLOSES the e-mail path. The
passkey half is derived from the credentials table on every login, so deleting
the last passkey reopens e-mail for an ordinary user without TOTP.
"""

import logging
from collections.abc import Mapping
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from navigator_auth.conf import AUTH_DB_SCHEMA
from navigator_auth.exceptions import MFARefused
from navigator_auth.mfa.backup_codes import BackupCodeStore
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.types import (
    MfaMode,
    MfaState,
    TenantMfaPolicy,
    PROVIDER_BACKUP,
    PROVIDER_EMAIL,
    PROVIDER_TOTP,
)

logger = logging.getLogger("navigator.mfa.state")

_USER_MFA = f"{AUTH_DB_SCHEMA}.user_mfa"
_CREDENTIALS = f"{AUTH_DB_SCHEMA}.user_credentials"


def _field(user: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` from a dict or a datamodel ``Model`` user record."""
    if isinstance(user, Mapping):
        return user.get(name, default)
    try:
        return user[name]
    except (KeyError, TypeError, AttributeError, IndexError):
        return getattr(user, name, default)


def _user_id(user: Any) -> int:
    """Authenticated user id; a missing or non-integer id is ambiguity -> fail closed."""
    try:
        return int(_field(user, "user_id"))
    except (TypeError, ValueError) as err:
        raise MfaStorageError("ambiguous user identity") from err


def usable_email(user: Any) -> Optional[str]:
    """The address the e-mail floor would use, or None (spec R3).

    Shared with the pre-flight (TASK-146) so B1 and the login path agree.
    """
    value = _field(user, "email")
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or value.count("@") != 1:
        return None
    local, domain = value.split("@")
    if not local or not domain:
        return None
    return value


@asynccontextmanager
async def _scope(pool: Any, conn: Any = None) -> AsyncIterator[Any]:
    """Caller's connection (e.g. the per-user lock transaction) or a pooled one."""
    if conn is not None:
        yield conn
        return
    async with await pool.acquire() as own:
        yield own


class MfaStateMachine:
    """none -> email -> totp, the strong-factor predicate and the provider allowlist."""

    def __init__(self, db_pool: Any, backup_codes: Optional[BackupCodeStore] = None) -> None:
        self._pool = db_pool
        self._backup = backup_codes

    async def totp_confirmed(self, user_id: int, *, conn: Any = None) -> bool:
        """A confirmed, enabled TOTP enrolment exists (``user_mfa`` row)."""
        try:
            async with _scope(self._pool, conn) as db:
                found = await db.fetchval(
                    f"SELECT EXISTS (SELECT 1 FROM {_USER_MFA} WHERE user_id = $1 "
                    "AND provider = $2 AND enabled AND confirmed_at IS NOT NULL)",
                    int(user_id),
                    PROVIDER_TOTP,
                )
        except Exception as err:  # pylint: disable=W0703
            raise MfaStorageError(f"user_mfa read failed: {type(err).__name__}") from err
        return bool(found)

    async def passkey_count(self, user_id: int, *, conn: Any = None) -> int:
        """Registered passkeys. 0 when the passkey table does not exist (backend never ran).

        Reads the table directly — never imports the passkey backend (R10).
        """
        try:
            async with _scope(self._pool, conn) as db:
                regclass = await db.fetchval("SELECT to_regclass($1)", _CREDENTIALS)
                if regclass is None:
                    return 0
                count = await db.fetchval(f"SELECT count(*) FROM {_CREDENTIALS} WHERE user_id = $1", int(user_id))
        except Exception as err:  # pylint: disable=W0703
            raise MfaStorageError(f"passkey count failed: {type(err).__name__}") from err
        return int(count or 0)

    async def has_strong_factor(self, user: Any, *, conn: Any = None) -> bool:
        """Confirmed TOTP OR >= 1 passkey. Evaluated fresh every call (spec M7)."""
        uid = _user_id(user)
        if await self.totp_confirmed(uid, conn=conn):
            return True
        return await self.passkey_count(uid, conn=conn) > 0

    async def requires_strong_factor(self, user: Any, policy: TenantMfaPolicy) -> bool:
        """True for ``is_superuser`` under ENFORCED (D10; models.py:54)."""
        return policy.mode == MfaMode.ENFORCED and bool(_field(user, "is_superuser", False))

    async def state_of(self, user: Any, policy: TenantMfaPolicy, *, conn: Any = None) -> MfaState:
        """D10 — in this order:

        1. requires_strong and not strong -> raise MFARefused("strong_factor_required", status=403)
           (before ANY e-mail fallback or trusted-device use — AC33)
        2. totp_confirmed                 -> MfaState.TOTP
        3. mode in (OFF, OPTIONAL)        -> MfaState.NONE
        4. ENFORCED                       -> MfaState.EMAIL
        """
        uid = _user_id(user)
        totp = await self.totp_confirmed(uid, conn=conn)
        if await self.requires_strong_factor(user, policy):
            strong = totp or await self.passkey_count(uid, conn=conn) > 0
            if not strong:
                raise MFARefused(MFARefused.STRONG_FACTOR_REQUIRED, status=403)
        if totp:
            return MfaState.TOTP
        if policy.mode in (MfaMode.OFF, MfaMode.OPTIONAL):
            return MfaState.NONE
        return MfaState.EMAIL

    async def available_providers(
        self, user: Any, policy: TenantMfaPolicy, *, conn: Any = None
    ) -> tuple[list[str], Optional[str]]:
        """``(providers, preferred)`` per D10.

        - ``totp``   iff TOTP confirmed
        - ``email``  iff mode == ENFORCED and NOT strong and usable_email(user)
        - ``backup`` iff remaining backup codes > 0 (0 when no BackupCodeStore)
        preferred = first present of totp, email, backup; else None.
        A strong factor CLOSES e-mail: the mailbox stops being the ceiling (AC9).
        """
        uid = _user_id(user)
        totp = await self.totp_confirmed(uid, conn=conn)
        strong = totp or await self.passkey_count(uid, conn=conn) > 0
        providers: list[str] = []
        if totp:
            providers.append(PROVIDER_TOTP)
        if policy.mode == MfaMode.ENFORCED and not strong and usable_email(user):
            providers.append(PROVIDER_EMAIL)
        if self._backup is not None and await self._backup.remaining(uid, conn=conn) > 0:
            providers.append(PROVIDER_BACKUP)
        return providers, (providers[0] if providers else None)
