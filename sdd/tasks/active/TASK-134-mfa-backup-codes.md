# TASK-134: Backup codes — keyed-hash store and `BackupCodeProvider`

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-129, TASK-130
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 5**: ten single-use recovery codes, the way back in
when a TOTP device is lost, so that administrative disenrolment stays
exceptional (spec G6). Backup codes are also one of the recovery routes for an
enforced superuser whose strong factor is gone (spec §3 "Superuser invariant and
recovery").

Two layers in one module:

- `BackupCodeStore` — generate / consume / count / invalidate, over
  `{schema}.user_mfa_backup_codes` (DDL from TASK-130).
- `BackupCodeProvider(AbstractOTPProvider)` — the provider named `"backup"` that
  the verify handler (TASK-140) dispatches to, exactly like `"totp"` and
  `"email"`. Its `_is_strong` is `False`: holding backup codes never closes the
  e-mail path; only a confirmed TOTP or a passkey does (spec M7).

Decomposition decisions applied (contract `feat106_contract.md`):

- **D16 — keyed hash.** A code is 8 characters from
  `BACKUP_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"` (32 symbols ⇒ 40
  bits). An unkeyed `sha256` of a 40-bit code is brute-forceable from a database
  dump in minutes, so the stored form is
  `HMAC-SHA256(AUTH_OTP_SECRET, f"{user_id}:{normalized}")` hex. Binding
  `user_id` into the MAC also means a code row copied to another user never
  verifies.
- **D16 — own connection for consumption.** The verify handler holds the
  per-user lock transaction while it checks a code. If consumption ran on that
  connection, a later failure (e.g. session creation) would roll back and
  **restore** the consumed code — the spec forbids it ("Do not restore challenges
  or consumed backup codes after downstream failures"). So `consume()` has **no
  `conn` parameter** and always commits on its own pooled connection.
- **D21** — regeneration is driven by the handler (TASK-141) after fresh password
  re-authentication; admin disenrolment (TASK-142) calls `invalidate_all`.
  This store never checks a password.

---

## Scope

- Create `navigator_auth/mfa/backup_codes.py` with `normalize_code`,
  `BackupCodeStore` and `BackupCodeProvider` per contract §3 TASK-134.
- `generate` invalidates the previous unused set and inserts the new hashes
  atomically; returns plaintext codes (the only time they exist unhashed).
- `consume` compares in constant time against **all** of the user's unused
  hashes (no early exit), then marks one row used with a single-use
  `UPDATE … WHERE used_at IS NULL RETURNING id`.
- All storage errors raise `MfaStorageError` (fail closed).
- Write `tests/test_mfa_backup_codes.py`.

**NOT in scope**: the HTTP endpoint and password re-auth (TASK-141); showing
codes in the TOTP-confirm response (TASK-141, D21); admin disenrolment
(TASK-142); counting codes into `available_providers` (TASK-135 calls
`remaining()`).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/backup_codes.py` | CREATE | `normalize_code`, `BackupCodeStore`, `BackupCodeProvider` |
| `tests/test_mfa_backup_codes.py` | CREATE | Unit + live-Postgres tests |

---

## Codebase Contract

> Re-verified on `dev` @ `b10a3a3` (2026-11-11).

### Verified Imports

```python
import hashlib, hmac, logging, secrets                       # stdlib
from contextlib import asynccontextmanager                   # stdlib
from typing import Any, AsyncIterator, Mapping, Optional     # stdlib
from aiohttp import web                                      # used by the ABC signatures (navigator_auth/auth.py:19)
from navigator_auth.conf import (
    AUTH_DB_SCHEMA,                                          # verified: conf.py:33
    AUTH_MFA_BACKUP_CODE_COUNT,                              # TASK-129 (spec M1, fallback 10)
    AUTH_MFA_BACKUP_CODE_LENGTH,                             # TASK-129 (spec M1, fallback 8)
)
from navigator_auth.mfa.abstract import AbstractOTPProvider  # TASK-129
from navigator_auth.mfa.exceptions import MfaStorageError    # TASK-129
from navigator_auth.mfa.types import (                       # TASK-129
    EnrollmentAuthorization, MfaChallenge, PROVIDER_BACKUP,
)
```

### `AbstractOTPProvider` (TASK-129, contract §3 — D4 extensions)

```python
class AbstractOTPProvider(ABC):
    _provider_name: str; _is_strong: bool
    async def is_enrolled(self, user: Mapping) -> bool
    async def start_enrollment(self, user: Mapping, authorization: EnrollmentAuthorization) -> dict
    async def confirm_enrollment(self, user: Mapping, code: str, enrollment_token: str, session_id: str, *, conn: Any = None) -> bool
    async def challenge(self, request: web.Request, user: Mapping) -> dict
    async def verify(self, request: web.Request, user: Mapping, code: str, challenge: Optional[MfaChallenge] = None) -> bool
    async def disenroll(self, user: Mapping, *, conn: Any = None) -> None
```

### Table `{schema}.user_mfa_backup_codes` (TASK-130)

```
id bigserial PK, user_id bigint NOT NULL FK users ON DELETE CASCADE,
code_hash varchar(64) NOT NULL, used_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
partial index (user_id) WHERE used_at IS NULL
```

### asyncdb connection API (verified `.venv/.../asyncdb/drivers/pg.py`)

`fetchval` (:1052) / `fetch_one` (:1036) / `fetch_all` (:1000, returns **None** on
no rows) **raise** on error. `transaction()` :1069, `commit()` :1076,
`rollback()` :1083. Pool pattern `async with await pool.acquire() as conn:`
(verified `navigator_auth/passkey/store.py:43`).

> **Gotcha — `conn.execute()` swallows errors** (`pg.py:937-972` returns
> `[result, error]`). Never use it here; use `fetchval` with `RETURNING` or the
> CTE idiom `WITH d AS (DELETE … RETURNING 1) SELECT count(*) FROM d`
> (as `PasskeyStore.delete_credential`, `passkey/store.py:121-127`).

### User records

The idp returns a datamodel `Model` (`AUTH_USER_VIEW`) **or** a dict. Read
`user_id` through a small local accessor (`user["user_id"]` / `user.get` /
`getattr`) — TASK-135's `_field()` is not importable here (it lands later).

### Does NOT Exist (Anti-Hallucination)

- ~~unkeyed `sha256(code)` storage~~ — rejected by D16.
- ~~`BackupCodeStore.consume(..., conn=...)`~~ — no `conn` on purpose (D16).
- ~~password checking in this module~~ — the handler re-authenticates (TASK-141).
- ~~`pyotp`, `qrcode`~~ — not installed, not to be added (spec §6).

---

## Implementation Blueprint

### `navigator_auth/mfa/backup_codes.py` — CREATE (two blocks, one file)

**Block 1 — header, helpers, store core:**

```python
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
    # FILL IN: return "" for non-str; strip, remove " " and "-", upper() — bounded by D16.


def _user_id(user: Any) -> int:
    """``user_id`` of a dict or datamodel Model record."""
    # FILL IN: try user["user_id"], then getattr(user, "user_id"); int(); raise
    #          MfaStorageError("missing user_id") when absent — never guess an id.


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
```

**Why HMAC instead of a slow KDF.** The codes are 40-bit random values, so a
per-code KDF would cost ten KDF runs at every consumption for no gain over a
secret pepper: without `AUTH_OTP_SECRET` an attacker holding the table cannot
start guessing at all. The MAC input includes `user_id`, so the same plaintext
for two users produces two digests and a moved row is inert.

**Block 2 — store operations and the provider:**

```python
    async def generate(self, user_id: int, *, conn: Any = None) -> list[str]:
        """Invalidate the user's unused codes and return a NEW plaintext set.

        The returned list is the only time the codes exist unhashed. The caller
        (TASK-141) must have re-checked the password (spec M5, D21).

        Raises:
            MfaStorageError: the set could not be replaced atomically.
        """
        # FILL IN — bounded by spec M5, AC14, D16:
        #  1. Draw self._count codes, each "".join(secrets.choice(BACKUP_CODE_ALPHABET)
        #     for _ in range(self._length)); redraw duplicates within the set.
        #  2. Atomically (caller conn => it is already in a tx; own conn => conn.transaction()
        #     + commit/rollback): DELETE unused rows of user_id (CTE count idiom), then
        #     insert all hashes in ONE statement:
        #       WITH ins AS (INSERT INTO _TABLE (user_id, code_hash)
        #         SELECT $1, unnest($2::varchar[]) RETURNING 1) SELECT count(*) FROM ins
        #     and assert the count equals self._count (else MfaStorageError).
        #  3. Wrap any exception in MfaStorageError; never log a code.
        #  4. Return the plaintext codes in the drawn (unnormalized == normalized) form.

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
        # FILL IN — bounded by D16, spec M5 "constant-time compare", AC31:
        #  normalized = normalize_code(code); wrong length -> still run the comparison
        #  loop against a dummy digest, then return False (no length-based shortcut timing);
        #  rows = await conn.fetch_all("SELECT id, code_hash FROM _TABLE WHERE user_id=$1
        #         AND used_at IS NULL", uid) or [];
        #  loop ALL rows, matched_id = row id when compare_digest(row hash, candidate);
        #  no break; then the single-use UPDATE … RETURNING id via fetchval.

    async def remaining(self, user_id: int, *, conn: Any = None) -> int:
        """Number of unused codes."""
        # FILL IN: SELECT count(*) … WHERE user_id=$1 AND used_at IS NULL; errors -> MfaStorageError.

    async def invalidate_all(self, user_id: int, *, conn: Any = None) -> int:
        """Delete every unused code (admin disenrolment, D21); returns the count."""
        # FILL IN: CTE-count DELETE … WHERE user_id=$1 AND used_at IS NULL; errors -> MfaStorageError.


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
```

**Why `verify` ignores the lock connection.** It is called inside the verify
handler's lock transaction (TASK-140), and that is deliberate: the *decision* is
serialized per user, but the *consumption* must survive a rollback (D16). The
single-use `UPDATE … WHERE used_at IS NULL RETURNING id` is what makes two
concurrent requests consume a code once, independently of the advisory lock.

### `tests/test_mfa_backup_codes.py` — CREATE

```python
"""BackupCodeStore / BackupCodeProvider — FEAT-106 spec §3 Module 5 (TASK-134)."""
import hashlib
import inspect
import re

import pytest

from navigator_auth.mfa.backup_codes import (
    BACKUP_CODE_ALPHABET, BackupCodeProvider, BackupCodeStore, normalize_code,
)
from navigator_auth.mfa.exceptions import MfaStorageError
from tests.fixtures.mfa import mfa_db, mfa_secret, mfa_user_factory  # noqa: F401


def test_normalize_code_accepts_spacing_and_case():
    assert normalize_code(" abcd-2345 ") == "ABCD2345"


def test_consume_has_no_conn_parameter():
    """D16: consumption can never join a caller's (rollback-able) transaction."""
    assert "conn" not in inspect.signature(BackupCodeStore.consume).parameters


@pytest.mark.asyncio
async def test_backup_codes_generate_count_and_shape(mfa_db, mfa_user_factory, mfa_secret):
    """10 codes, 8 chars, all from BACKUP_CODE_ALPHABET, unique."""
    # FILL IN


@pytest.mark.asyncio
async def test_backup_code_single_use(mfa_db, mfa_user_factory, mfa_secret):
    """A consumed code fails on reuse; remaining() drops by one."""
    # FILL IN


@pytest.mark.asyncio
async def test_backup_code_regeneration_invalidates_previous(mfa_db, mfa_user_factory, mfa_secret):
    """The old set stops working after generate() runs again."""
    # FILL IN


@pytest.mark.asyncio
async def test_codes_stored_as_keyed_hash_only(mfa_db, mfa_user_factory, mfa_secret):
    """No plaintext and no unkeyed sha256(code) in the table (D16, AC14)."""
    # FILL IN: compare every stored code_hash against sha256(code) and the plaintext.


@pytest.mark.asyncio
async def test_code_bound_to_user(mfa_db, mfa_user_factory, mfa_secret):
    """User B cannot consume user A's code."""
    # FILL IN


@pytest.mark.asyncio
async def test_concurrent_consume_succeeds_once(mfa_db, mfa_user_factory, mfa_secret):
    """asyncio.gather of two consume() of the same code -> exactly one True."""
    # FILL IN


@pytest.mark.asyncio
async def test_provider_contract(mfa_db, mfa_user_factory, mfa_secret):
    """name == 'backup', is_strong is False, verify() consumes, disenroll() invalidates."""
    # FILL IN


@pytest.mark.asyncio
async def test_storage_error_fails_closed(mfa_secret):
    """A pool that raises on acquire() surfaces MfaStorageError from every method."""
    # FILL IN: tiny _BrokenPool fake (acquire() raises ConnectionError).
```

### Steps (in order)

1. Confirm TASK-129 (settings `AUTH_MFA_BACKUP_CODE_*`, ABC, `PROVIDER_BACKUP`) and
   TASK-130 (`user_mfa_backup_codes` table, fixtures) landed.
2. Create Block 1; fill `normalize_code` and `_user_id`.
3. Add Block 2; fill `generate` (atomic replace), then `consume` (constant-time
   loop, single-use UPDATE), then `remaining` / `invalidate_all`.
4. Write the tests and fill them; run the concurrency test several times.
5. Run **Test Specification**, including the D5 grep.

### FILL IN checklist

- [ ] `normalize_code`, `_user_id` — D16
- [ ] `generate` — atomic delete+insert, count check — spec M5, AC14
- [ ] `consume` — full-loop compare_digest, single-use UPDATE, own connection — D16, AC31
- [ ] `remaining`, `invalidate_all` — CTE count idiom
- [ ] 7 test bodies

---

## Acceptance Criteria

- [ ] **AC-1** `generate` returns `AUTH_MFA_BACKUP_CODE_COUNT` unique codes of `AUTH_MFA_BACKUP_CODE_LENGTH` chars drawn from `BACKUP_CODE_ALPHABET`, and invalidates every previously unused code.
- [ ] **AC-2** Stored values are `HMAC-SHA256(secret, "user_id:code")`; no plaintext or unkeyed sha256 is persisted or logged (spec AC14).
- [ ] **AC-3** A code verifies once; reuse, another user's code, or a code from a replaced set returns `False`.
- [ ] **AC-4** Two concurrent `consume` calls of the same code yield exactly one `True` (spec AC31).
- [ ] **AC-5** `consume` has no `conn` parameter and commits on its own connection (D16).
- [ ] **AC-6** `BackupCodeProvider.name == "backup"` and `is_strong is False`.
- [ ] **AC-7** Every storage failure raises `MfaStorageError` (spec G7, R5); no `conn.execute()` in the module.
- [ ] **AC-8** `grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/` prints nothing (D5).
- [ ] Contributes to spec **AC14, AC31** and the backup-code recovery route of **AC33**.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_backup_codes.py -v
ruff check navigator_auth/mfa/backup_codes.py tests/test_mfa_backup_codes.py
grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/ ; test $? -eq 1
grep -n "execute(" navigator_auth/mfa/backup_codes.py ; test $? -eq 1
```

Spec §4 rows owned here: `test_backup_codes_generate_count_and_shape`,
`test_backup_code_single_use`, `test_backup_code_regeneration_invalidates_previous`.

---

## Agent Instructions

1. **Read the spec** — §3 Module 5, §3 "Retry accounting and concurrency"
   (the no-restore rule), §3 "Superuser invariant and recovery", AC14, AC31;
   contract D16, D21.
2. **Check dependencies** — TASK-129, TASK-130 in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint.
5. **Verify** every acceptance criterion.
6. **Move this file** to `sdd/tasks/completed/TASK-134-mfa-backup-codes.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**:
**Date**:
**Notes**:

**Deviations from spec**: none | describe if any
