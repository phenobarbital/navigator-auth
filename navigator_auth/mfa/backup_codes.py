"""Backup codes for the BasicAuth second factor (FEAT-106, spec §3 Module 5).

Ten single-use codes, shown exactly once, stored as a keyed hash
(HMAC-SHA256 under AUTH_OTP_SECRET, bound to the user id). Consumption commits
on its own connection so a downstream failure can never restore a used code.
"""

import hashlib
import hmac
import logging
import secrets
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Mapping, Optional

from aiohttp import web

from navigator_auth.conf import (
    AUTH_DB_SCHEMA,
    AUTH_MFA_BACKUP_CODE_COUNT,
    AUTH_MFA_BACKUP_CODE_LENGTH,
)
from navigator_auth.mfa.abstract import AbstractOTPProvider
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.types import EnrollmentAuthorization, MfaChallenge, PROVIDER_BACKUP

logger = logging.getLogger("navigator.mfa.backup_codes")

BACKUP_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_TABLE = f"{AUTH_DB_SCHEMA}.user_mfa_backup_codes"


def normalize_code(code: str) -> str:
    """Upper-case and drop spaces/hyphens so "abcd-2345" == "ABCD2345"."""
    if not isinstance(code, str):
        return ""
    return code.strip().replace(" ", "").replace("-", "").upper()


def _user_id(user: Any) -> int:
    """``user_id`` of a dict or datamodel Model record."""
    value = None
    try:
        value = user["user_id"]
    except (KeyError, TypeError, IndexError, AttributeError):
        value = getattr(user, "user_id", None)
    if value is None:
        raise MfaStorageError("missing user_id")
    try:
        return int(value)
    except (TypeError, ValueError) as err:
        raise MfaStorageError("invalid user_id") from err


class BackupCodeStore:
    """10 x 8-char codes, shown once, stored as HMAC(secret, "user_id:code")."""

    def __init__(
        self,
        db_pool: Any,
        secret: bytes,
        count: int = AUTH_MFA_BACKUP_CODE_COUNT,
        length: int = AUTH_MFA_BACKUP_CODE_LENGTH,
    ) -> None:
        """Bind the store.

        Args:
            db_pool: ``app["authdb"]``.
            secret: ``AUTH_OTP_SECRET`` bytes (the pepper; D16).
            count: Codes per set (spec: 10).
            length: Characters per code (spec: 8).
        """
        if not secret:
            raise ValueError("BackupCodeStore requires AUTH_OTP_SECRET")
        self._pool = db_pool
        self._secret = secret
        self._count = count
        self._length = length

    def _hash(self, user_id: int, normalized: str) -> str:
        """Keyed, user-bound digest — the only stored form of a code."""
        message = f"{int(user_id)}:{normalized}".encode("utf-8")
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()

    @asynccontextmanager
    async def _scope(self, conn: Any = None) -> AsyncIterator[Any]:
        """Caller's connection (lock transaction) or a pooled one."""
        if conn is not None:
            yield conn
            return
        async with await self._pool.acquire() as own:
            yield own

    def _draw_codes(self) -> list[str]:
        """Draw ``count`` unique random codes."""
        codes: set[str] = set()
        ordered: list[str] = []
        while len(ordered) < self._count:
            candidate = "".join(secrets.choice(BACKUP_CODE_ALPHABET) for _ in range(self._length))
            if candidate in codes:
                continue
            codes.add(candidate)
            ordered.append(candidate)
        return ordered

    async def generate(self, user_id: int, *, conn: Any = None) -> list[str]:
        """Invalidate the user's unused codes and return a NEW plaintext set.

        The returned list is the only time the codes exist unhashed. The caller
        (TASK-141) must have re-checked the password (spec M5, D21).

        Raises:
            MfaStorageError: the set could not be replaced atomically.
        """
        codes = self._draw_codes()
        hashes = [self._hash(user_id, code) for code in codes]
        # One data-modifying statement: delete + insert are atomic together.
        sql = (
            f"WITH d AS (DELETE FROM {_TABLE} WHERE user_id = $1 AND used_at IS NULL RETURNING 1), "
            f"ins AS (INSERT INTO {_TABLE} (user_id, code_hash) "
            "SELECT $1, unnest($2::varchar[]) RETURNING 1) "
            "SELECT count(*) FROM ins"
        )
        try:
            async with self._scope(conn) as db:
                inserted = await db.fetchval(sql, int(user_id), hashes)
        except Exception as err:  # pylint: disable=W0703
            raise MfaStorageError(f"backup code generation failed: {type(err).__name__}") from err
        if inserted != self._count:
            raise MfaStorageError("backup code set was not stored completely")
        return codes

    async def consume(self, user_id: int, code: str) -> bool:
        """Single-use check of a code, on the store's OWN connection (D16).

        Compares against every unused hash with ``hmac.compare_digest`` and no
        early exit, then marks one row used with
        ``UPDATE … SET used_at = now() WHERE id = $1 AND used_at IS NULL RETURNING id``
        so two concurrent submissions of the same code consume it once.

        Returns:
            True only when a row was marked used by THIS call.

        Raises:
            MfaStorageError: storage failure (the caller refuses the login).
        """
        normalized = normalize_code(code)
        valid_shape = len(normalized) == self._length
        candidate = self._hash(user_id, normalized if valid_shape else "")
        try:
            async with await self._pool.acquire() as db:
                rows = (
                    await db.fetch_all(
                        f"SELECT id, code_hash FROM {_TABLE} WHERE user_id = $1 AND used_at IS NULL",
                        int(user_id),
                    )
                    or []
                )
                matched_id = None
                for row in rows:
                    if hmac.compare_digest(str(row["code_hash"]), candidate):
                        matched_id = row["id"]
                if matched_id is None or not valid_shape:
                    return False
                used = await db.fetchval(
                    f"UPDATE {_TABLE} SET used_at = now() WHERE id = $1 AND used_at IS NULL RETURNING id",
                    matched_id,
                )
        except Exception as err:  # pylint: disable=W0703
            raise MfaStorageError(f"backup code consume failed: {type(err).__name__}") from err
        return used is not None

    async def remaining(self, user_id: int, *, conn: Any = None) -> int:
        """Number of unused codes."""
        try:
            async with self._scope(conn) as db:
                value = await db.fetchval(
                    f"SELECT count(*) FROM {_TABLE} WHERE user_id = $1 AND used_at IS NULL",
                    int(user_id),
                )
        except Exception as err:  # pylint: disable=W0703
            raise MfaStorageError(f"backup code count failed: {type(err).__name__}") from err
        return int(value or 0)

    async def invalidate_all(self, user_id: int, *, conn: Any = None) -> int:
        """Delete every unused code (admin disenrolment, D21); returns the count."""
        try:
            async with self._scope(conn) as db:
                value = await db.fetchval(
                    f"WITH d AS (DELETE FROM {_TABLE} WHERE user_id = $1 AND used_at IS NULL RETURNING 1) "
                    "SELECT count(*) FROM d",
                    int(user_id),
                )
        except Exception as err:  # pylint: disable=W0703
            raise MfaStorageError(f"backup code invalidation failed: {type(err).__name__}") from err
        return int(value or 0)


class BackupCodeProvider(AbstractOTPProvider):
    """The ``"backup"`` provider: verification by single-use code. Not strong."""

    _provider_name = PROVIDER_BACKUP
    _is_strong = False

    def __init__(self, store: BackupCodeStore) -> None:
        self._store = store

    async def is_enrolled(self, user: Mapping) -> bool:
        return await self._store.remaining(_user_id(user)) > 0

    async def start_enrollment(self, user: Mapping, authorization: EnrollmentAuthorization) -> dict:
        """No codes here: generation needs the handler's fresh password check (D21)."""
        return {"remaining": await self._store.remaining(_user_id(user))}

    async def confirm_enrollment(
        self, user: Mapping, code: str, enrollment_token: str, session_id: str, *, conn: Any = None
    ) -> bool:
        return False  # nothing to confirm for backup codes

    async def challenge(self, request: web.Request, user: Mapping) -> dict:
        return {}  # nothing to deliver

    async def verify(
        self, request: web.Request, user: Mapping, code: str, challenge: Optional[MfaChallenge] = None
    ) -> bool:
        """Consume a code on the store's own connection; ``challenge`` is unused."""
        return await self._store.consume(_user_id(user), code)

    async def disenroll(self, user: Mapping, *, conn: Any = None) -> None:
        await self._store.invalidate_all(_user_id(user), conn=conn)
