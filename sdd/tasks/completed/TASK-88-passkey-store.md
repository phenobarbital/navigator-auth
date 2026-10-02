# TASK-88: `PasskeyStore` — credential and user-handle CRUD

**Feature**: FEAT-101 — Passkey (WebAuthn) Authentication Backend
**Spec**: `sdd/specs/passkey-support-backend.spec.md` (Module 2, §2.3, AC3)
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-87
**Assigned-to**: unassigned

---

## Context

Part of serial stage S0. `PasskeyStore` is the only code that touches `{schema}.user_credentials`
and `{schema}.user_passkey_handles`. Enrollment, sign-in and management (TASKS 94 to 96) all go
through it.

Q3 is resolved: storage lives in this dedicated store class, following `IdentityStore`. It does
**not** live on the IdP.

---

## Scope

- Implement `navigator_auth/passkey/store.py` with the exact method set in the spec Module 2
  skeleton, using raw parameterised SQL over `app["authdb"]`.
- Return `StoredCredential` models. Map `aaguid` (`uuid.UUID`) to `str` and `transports` (array) to `list[str]`.
- `get_or_create_handle` must be race-safe: two concurrent first enrollments must end up with the same handle.
- Export `PasskeyStore` from `navigator_auth/passkey/__init__.py`.
- Write `tests/test_passkey_store.py` (`test_store_crud`, live, skipped without Postgres).

**NOT in scope**: the E13 "has another login method" rule (TASK-96), and the Redis challenges (TASK-93).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/passkey/store.py` | CREATE | `PasskeyStore` |
| `navigator_auth/passkey/__init__.py` | MODIFY | Export `PasskeyStore` |
| `tests/test_passkey_store.py` | CREATE | Live CRUD test |

---

## Codebase Contract (Anti-Hallucination)

> Verified 2026-10-02 against `dev` @ `564c440`.

### Verified Imports
```python
from navigator_auth.conf import AUTH_DB_SCHEMA                 # conf.py:32
from navigator_auth.passkey.types import StoredCredential      # created by TASK-87
from navconfig.logging import logging                          # identity/store.py:10
```

### Existing Signatures to Use
```python
# identity/store.py — the pattern to follow
class IdentityStore:                                           # :49
    def __init__(self, db_pool: Any, cipher=None):             # :52  → self._pool = db_pool
    async def list_for_user(self, user_id: Any) -> list[dict]: # :199
        async with await self._pool.acquire() as conn:         # ← acquire pattern used across the repo
# Raw SQL on an asyncdb pg connection, as used in this repo:
#   payload = await conn.fetch_one(sql, *args)    middlewares/strategies.py:87
#   rows    = await conn.fetch_all(sql, *args)    abac/audit.py:451
#   await conn.execute(sql, *args)                abac/audit.py:348
#   value   = await conn.fetchval(sql, ...)       handlers/userattrs.py:46
```
- Placeholders are asyncpg-style `$1, $2, …` (see `strategies.py:87-91`).
- Table names come from `AUTH_DB_SCHEMA`; the tables come from TASK-87's DDL.

### Does NOT Exist
- `IdentityProvider.get_credential`, `list_credentials`, `save_credential` and
  `update_credential_usage`. Do **not** add them to the IdP.
- An asyncdb `Model` for these tables. Use raw SQL and return Pydantic models (spec §2 note).
- `PasskeyStore.has_other_login_method`. That logic is TASK-96's, in the backend.

---

## Implementation Blueprint

### Steps (in order)
1. Implement the methods in the order of the skeleton. Every query must be parameterised. Only
   the schema name is interpolated, and it comes from config, never from the request.
2. For `get_or_create_handle`, use
   `INSERT ... ON CONFLICT (user_id, rp_id) DO NOTHING`, then `SELECT`. This is race-safe
   without an explicit transaction, because the PK serialises concurrent inserts.
3. Make `rename_credential` and `delete_credential` filter by **both** `user_id` and
   `credential_id`, so a user can never touch someone else's credential. Return `bool` (whether a
   row changed).
4. Wire the export and write the live test.

### `navigator_auth/passkey/store.py` — CREATE
```python
"""Persistence for WebAuthn credentials and per-(user, RP) user handles (FEAT-101)."""
import secrets
from typing import Any, Optional

from navconfig.logging import logging

from ..conf import AUTH_DB_SCHEMA
from .types import StoredCredential

logger = logging.getLogger("navigator.passkey")

_CREDENTIALS = f"{AUTH_DB_SCHEMA}.user_credentials"
_HANDLES = f"{AUTH_DB_SCHEMA}.user_passkey_handles"


class PasskeyStore:
    """CRUD over ``user_credentials`` and ``user_passkey_handles``."""

    def __init__(self, db_pool: Any) -> None:
        """Bind the store to ``app["authdb"]``.

        Args:
            db_pool: asyncdb/asyncpg pool exposing ``acquire()``.
        """
        self._pool = db_pool

    @staticmethod
    def _row_to_credential(row: Any) -> StoredCredential:
        """Map a DB row to ``StoredCredential`` (aaguid UUID → str, transports → list)."""
        # FILL IN: dict(row) → convert aaguid with str() when not None; transports list or None.
        raise NotImplementedError

    async def get_credential(self, credential_id: bytes) -> Optional[StoredCredential]:
        """Return one credential by id, or ``None``."""
        # FILL IN: SELECT * FROM {_CREDENTIALS} WHERE credential_id = $1 (fetch_one).

    async def list_credentials(
        self, user_id: int, rp_id: Optional[str] = None
    ) -> list[StoredCredential]:
        """All credentials of a user, optionally limited to one RP, oldest first."""
        # FILL IN: two query variants; ORDER BY created_at.

    async def save_credential(self, credential: StoredCredential) -> None:
        """Insert a newly registered credential."""
        # FILL IN: INSERT all columns except created_at/last_used_at (DB defaults).

    async def update_usage(
        self, credential_id: bytes, *, sign_count: int, backed_up: bool
    ) -> None:
        """Set ``sign_count``, ``backed_up`` and ``last_used_at = now()``."""

    async def rename_credential(self, user_id: int, credential_id: bytes, label: str) -> bool:
        """Rename a credential owned by ``user_id``; True when a row changed."""

    async def delete_credential(self, user_id: int, credential_id: bytes) -> bool:
        """Delete a credential owned by ``user_id``; True when a row was removed."""

    async def count_credentials(self, user_id: int) -> int:
        """Number of credentials of a user across all RPs."""

    async def get_handle(self, user_id: int, rp_id: str) -> Optional[bytes]:
        """The user's WebAuthn user handle for ``rp_id``, or ``None``."""

    async def get_or_create_handle(self, user_id: int, rp_id: str) -> bytes:
        """Return the user's handle for ``rp_id``, creating ``secrets.token_bytes(32)`` if absent."""
        candidate = secrets.token_bytes(32)
        # FILL IN: INSERT (user_id, rp_id, candidate) ON CONFLICT (user_id, rp_id) DO NOTHING,
        #          then return get_handle(); bounded by: race-safe, handle never derived from user_id (E15).
```
**Why**: The method set is frozen by the spec skeleton. Owner-scoped mutations are the
authorization boundary for TASK-96. A random handle is G4/E15: the WebAuthn `user.id` must never
carry PII.

### `navigator_auth/passkey/__init__.py` — MODIFY
```python
# AFTER — insert below `from .types import ChallengeState, RelyingParty, StoredCredential`
#   (created by TASK-87; occurrences: 1)
from .store import PasskeyStore
# and add "PasskeyStore" to __all__
```

### `tests/test_passkey_store.py` — CREATE
```python
"""FEAT-101 TASK-88 — PasskeyStore against live Postgres (skipped when unavailable)."""
import pytest

pytestmark = pytest.mark.asyncio


async def test_store_crud():
    """Insert, get, list by user and RP, update_usage, rename, delete; handles stable and unique."""
    # FILL IN: pool + ensure_passkey_tables (TASK-87); seed a throwaway auth.users row like
    #          tests/test_basic_auth.py:100-113; exercise every method; clean up the rows.
```

### FILL IN checklist
- [ ] `_row_to_credential` conversions.
- [ ] All query bodies, parameterised.
- [ ] Race-safe `get_or_create_handle`.
- [ ] Live test with cleanup.

---

## Acceptance Criteria

- [ ] `test_store_crud` passes against live Postgres (AC3).
- [ ] `rename_credential` and `delete_credential` return `False` for a credential owned by another user.
- [ ] Two calls to `get_or_create_handle(user, rp)` return the same 32-byte value, and different RPs get different handles.
- [ ] `ruff check navigator_auth/passkey tests/test_passkey_store.py` is clean.

---

## Test Specification

See the blueprint above (spec §4: `test_store_crud`).

---

## Agent Instructions

1. Read the spec (Module 2, §2.3, §2 Data Models).
2. Confirm TASK-87 is in `sdd/tasks/completed/`.
3. Set this task to `"in-progress"` in `sdd/tasks/index/passkey-support-backend.json`.
4. Implement inside `.worktrees/feat-FEAT-101-passkey-support-backend`.
5. Verify the acceptance criteria.
6. Move this file to `sdd/tasks/completed/`, set the index entry to `"done"`, and fill in the Completion Note.

---

## Completion Note

**Completed by**: sdd-worker (Sonnet 5.5, sequential fallback)
**Date**: 2026-10-02
**Notes**: Raw-SQL store over asyncdb pool; live tests (2) pass. Pool usage: async with await pool.acquire() as conn; fetch_all returns None on no rows.
**Deviations from spec**: none
