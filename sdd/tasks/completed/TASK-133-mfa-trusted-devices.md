# TASK-133: Trusted-device store — rotating "remember me" cookie with replay → family revocation

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: done
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-129, TASK-130
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 6** ("remember me for N days"). A trusted device lets a
strong-factor user skip **only the OTP challenge — never the password** — for a
bounded window. The cookie is a *bearer second factor*: a stolen cookie is a 2FA
bypass for its lifetime (spec §7 R8). The defence is the standard
rotation-with-replay-detection pattern:

- every successful use **rotates** the token (new raw value, old row retired);
- re-presenting an already-rotated token proves the chain was copied, so the
  **whole family** is revoked;
- an enumerated list of security events revokes every device of a user
  (`revoke_all`) or of a tenant (`revoke_tenant`).

This task builds the store only. *Who* may be offered remember-me (strong-factor
users, tenant `remember_days > 0`, spec AC17) is decided by the BasicAuth hook
(TASK-138) and the verify handler (TASK-140); *when* revocation fires is wired by
TASK-135 (`apply_tenant_policy`), TASK-141/142 (enrol/disenrol) and TASK-144
(password change, recovery, passkey removal). Those callers pass their own
lock-transaction connection through the `conn=` parameter so revocation commits
atomically with the factor-state change (contract **D17**).

Decomposition decisions applied here (see contract `feat106_contract.md`):

- **D14** — the raw token never travels through `open_session(extra=…)`; this
  store only returns it. Delivery is TASK-138/139/140's job.
- **D15** — `consume_and_rotate(raw_token, user_id)` takes the *authenticated*
  user id: a cookie belonging to another user is ignored (returns `None`, **no
  mutation**). Rotation keeps the family's **original** `expires_at` — the window
  is bounded and never extended by use. Superseded rows are kept with
  `rotated_at` set so a replay is detectable (the DDL from TASK-130 carries
  `rotated_at` and `revoke_reason` for exactly this).
- **D7** — `revoke_tenant` finds members through
  `{schema}.organization_users` keyed by `org_id`; when that table does not
  exist the tenant has no members ⇒ `0`.

---

## Scope

- Create `navigator_auth/mfa/trusted_devices.py` with `TrustedDeviceStore`
  exactly as the contract signature block (§3 TASK-133).
- Implement `issue`, `consume_and_rotate`, `revoke_all`, `revoke_tenant`,
  `list_active`, all **fail closed**: any storage error raises
  `MfaStorageError` (never returns a value that could be read as "valid").
- Add the pure helper `may_offer_trusted_device(*, has_strong_factor: bool,
  remember_days: int) -> bool` (spec AC17 predicate, one place for TASK-138 and
  TASK-140 to call).
- Store only `sha256(raw_token)`; never log a raw token or its hash prefix.
- Write `tests/test_mfa_trusted_devices.py`.

**NOT in scope**: setting/reading the cookie on HTTP requests (TASK-138,
TASK-139, TASK-140); deciding which events revoke (TASK-135/141/142/144); the
DDL (TASK-130); a User-Agent or IP binding (rejected by the spec as security
theatre — bind to `user_id` only).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/trusted_devices.py` | CREATE | `TrustedDeviceStore`, `may_offer_trusted_device`, `_hash_token` |
| `tests/test_mfa_trusted_devices.py` | CREATE | Unit + live-Postgres tests |

---

## Codebase Contract

> Re-verified on `dev` @ `b10a3a3` (2026-11-11).

### Verified Imports

```python
import hashlib, logging, secrets, uuid                      # stdlib
from contextlib import asynccontextmanager                  # stdlib
from datetime import datetime, timedelta, timezone          # stdlib
from typing import Any, AsyncIterator, Optional             # stdlib
from navigator_auth.conf import AUTH_DB_SCHEMA              # verified: conf.py:33  (fallback "auth")
from navigator_auth.mfa.types import TrustedDevice          # TASK-129 (spec §2 Data Models)
from navigator_auth.mfa.exceptions import MfaStorageError   # TASK-129
```

Tests additionally use (TASK-130 fixtures, imported explicitly like
`tests/fixtures/passkey.py` is):

```python
from tests.fixtures.mfa import mfa_db, mfa_user_factory  # noqa: F401
```

### `TrustedDevice` (TASK-129, spec §2 — frozen Pydantic v2)

```python
class TrustedDevice(MfaModel):
    user_id: int
    token_hash: str               # sha256 of the cookie value
    label: str
    family_id: str                # rotation chain; replay revokes the family
    expires_at: datetime
    last_used_at: Optional[datetime]
    revoked_at: Optional[datetime]
```

### Table `{schema}.user_trusted_devices` (TASK-130 DDL, contract §3)

```
id bigserial PK, user_id bigint NOT NULL FK users ON DELETE CASCADE,
token_hash varchar(64) NOT NULL UNIQUE, family_id uuid NOT NULL,
label varchar(128) NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(),
expires_at timestamptz NOT NULL, last_used_at timestamptz,
rotated_at timestamptz, revoked_at timestamptz, revoke_reason varchar(64)
```

### Membership table (D7 — verified live 2026-11-11)

`auth.organization_users(user_id bigint, org_id bigint, properties jsonb, created_at, updated_at, created_by)`.
Not created by navigator-auth; guard with `SELECT to_regclass($1)`.

### asyncdb connection API (verified `.venv/.../asyncdb/drivers/pg.py`, asyncdb 2.16.3)

```python
async with await pool.acquire() as conn:      # pattern verified: navigator_auth/passkey/store.py:43
    row  = await conn.fetch_one(sql, *args)    # :1036 — asyncpg fetchrow; RAISES on error
    val  = await conn.fetchval(sql, *args)     # :1052 — RAISES on error
    rows = await conn.fetch_all(sql, *args)    # :1000 — RAISES; returns **None** (not []) when no rows
    await conn.transaction()                   # :1069 — starts a tx, returns self
    await conn.commit(); await conn.rollback() # :1076 / :1083
```

> **Gotcha — `conn.execute()` swallows errors.** `pg.execute` (:937-972)
> catches `PostgresError`/`Exception`, stores it in `error` and **returns**
> `[result, error]` instead of raising. A fail-closed store must never depend on
> `execute()`. Use `fetchval`/`fetch_one` with `RETURNING`, and the CTE counting
> idiom already used by `PasskeyStore.delete_credential`
> (`navigator_auth/passkey/store.py:121-127`):
> `WITH d AS (UPDATE … RETURNING 1) SELECT count(*) FROM d`.

### Does NOT Exist (Anti-Hallucination)

- ~~`UserDevices` as a trusted-device store~~ — `navigator_auth/models.py:143`
  exists but is referenced nowhere and is built for 1460-day device JWTs. Do
  **not** import or reuse it (spec §6).
- ~~a User-Agent / IP binding column~~ — deliberately absent.
- ~~`TrustedDeviceStore.consume_and_rotate(raw_token)`~~ with one argument — the
  contract signature takes `user_id` too (D15).
- ~~an HTTP cookie helper in this module~~ — `TRUSTED_COOKIE` and
  `trusted_cookie_kwargs()` live in `navigator_auth/mfa/types.py` (TASK-129).
- ~~`ORG_MEMBERSHIP_TABLE` importable from `navigator_auth.mfa.policy`~~ here —
  `policy.py` (TASK-135) imports **this** module, so importing it back would be
  a cycle. Use the module-private `_ORG_MEMBERSHIP_TABLE` below; TASK-135's test
  asserts the two constants are equal.

---

## Implementation Blueprint

### `navigator_auth/mfa/trusted_devices.py` — CREATE (three blocks, one file)

**Block 1 — module header, helpers, constructor:**

```python
"""Trusted devices ("remember me for N days") for the BasicAuth second factor.

A trusted device skips ONLY the OTP challenge, never the password, for a bounded
window, and only for strong-factor users (TOTP confirmed or a registered passkey)
in a tenant whose ``remember_days`` is greater than zero.

The cookie is a bearer second factor, so the token rotates on every use and
re-presenting an already-rotated token revokes the whole family (the chain was
copied). Only ``sha256(token)`` is stored. Every storage error raises
``MfaStorageError``: a device that cannot be checked is not trusted.
"""
import hashlib
import logging
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Optional

from navigator_auth.conf import AUTH_DB_SCHEMA
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.types import TrustedDevice

logger = logging.getLogger("navigator.mfa.trusted_devices")

_TABLE = f"{AUTH_DB_SCHEMA}.user_trusted_devices"
# Must equal navigator_auth.mfa.policy.ORG_MEMBERSHIP_TABLE (TASK-135 asserts it).
_ORG_MEMBERSHIP_TABLE = "organization_users"
_MEMBERSHIP = f"{AUTH_DB_SCHEMA}.{_ORG_MEMBERSHIP_TABLE}"


def _hash_token(raw_token: str) -> str:
    """sha256 hex digest of the raw cookie value — the only stored form."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def may_offer_trusted_device(*, has_strong_factor: bool, remember_days: int) -> bool:
    """Spec AC17: remember-me only for strong-factor users and only when the
    tenant's ``remember_days`` is positive. Never a password skip.

    Named ``…_trusted_device`` and not ``…_remember``: any identifier ending in
    ``remember(`` would trip the refined AC5 grep (contract D5).
    """
    # FILL IN: return the conjunction — bounded by AC17 (no other inputs).


class TrustedDeviceStore:
    """Rotating bearer second factor with replay detection, bound to user_id."""

    def __init__(self, db_pool: Any) -> None:
        """Bind the store to ``app["authdb"]``.

        Args:
            db_pool: asyncdb/asyncpg pool exposing ``acquire()``.
        """
        self._pool = db_pool

    @asynccontextmanager
    async def _scope(self, conn: Any = None) -> AsyncIterator[Any]:
        """Yield the caller's connection, or acquire one from the pool.

        A caller holding the per-user lock transaction passes ``conn`` so the
        write commits (or rolls back) with its factor-state change (D17).
        """
        if conn is not None:
            yield conn
            return
        async with await self._pool.acquire() as own:
            yield own
```

**Why `_scope` instead of always acquiring.** Every revocation event except the
login-time rotation runs inside the per-user advisory-lock transaction owned by
the handler (D17). If this store opened its own connection there, a rollback of
the factor change would leave devices revoked — harmless — but the reverse
(factor change committed, revocation on a connection that failed) would leave a
stolen cookie alive after an admin disenrolment, which is exactly spec R8's
"admin disenrolment that does not revoke devices does nothing".

**Block 2 — `issue` and `consume_and_rotate`:**

```python
    async def issue(self, user_id: int, days: int, label: str, *, conn: Any = None) -> str:
        """Create a new family and return the raw cookie value (only sha256 is stored).

        Args:
            user_id: Authenticated owner.
            days: Window length; must be > 0 (caller already applied AC17).
            label: Human label ("Chrome on macOS"); truncated to 128 chars.
            conn: Optional lock-transaction connection.

        Raises:
            ValueError: ``days <= 0``.
            MfaStorageError: the row could not be written.
        """
        if days <= 0:
            raise ValueError("Trusted devices require remember_days > 0")
        raw = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(days=days)
        try:
            async with self._scope(conn) as db:
                row_id = await db.fetchval(
                    f"INSERT INTO {_TABLE} (user_id, token_hash, family_id, label, expires_at) "
                    "VALUES ($1, $2, $3, $4, $5) RETURNING id",
                    int(user_id), _hash_token(raw), uuid.uuid4(), (label or "")[:128], expires_at,
                )
        except Exception as err:  # pylint: disable=W0703
            raise MfaStorageError(f"trusted device issue failed: {type(err).__name__}") from err
        if not row_id:
            raise MfaStorageError("trusted device issue returned no row")
        return raw

    async def consume_and_rotate(self, raw_token: str, user_id: int) -> Optional[tuple[int, str]]:
        """Validate and rotate a presented cookie in ONE transaction.

        Returns ``(user_id, new_raw_token)`` when the token is live, belongs to
        ``user_id`` and has not been rotated before. Returns ``None`` (and
        changes nothing) when it is unknown, expired, revoked or another user's.
        A token that was ALREADY rotated is a replay: the whole family is
        revoked (committed) and ``None`` is returned.

        Raises:
            MfaStorageError: on any storage error (fail closed — never trusted).
        """
        if not raw_token:
            return None
        token_hash = _hash_token(raw_token)
        try:
            async with await self._pool.acquire() as conn:
                await conn.transaction()
                try:
                    row = await conn.fetch_one(
                        f"SELECT id, user_id, family_id, label, expires_at, rotated_at, revoked_at "
                        f"FROM {_TABLE} WHERE token_hash = $1 FOR UPDATE",
                        token_hash,
                    )
                    # FILL IN: the decision ladder, in THIS order — bounded by D15, spec M6, AC18:
                    #  1. row is None                       -> rollback, return None
                    #  2. int(row["user_id"]) != int(user_id) -> rollback, return None (NO mutation)
                    #  3. row["revoked_at"] is not None     -> rollback, return None
                    #  4. row["rotated_at"] is not None     -> REPLAY: revoke every non-revoked row of
                    #       row["family_id"] with revoke_reason='replay' (CTE count idiom), commit,
                    #       logger.warning("trusted device replay: family revoked user_id=%s", user_id)
                    #       (never log the token or its hash), return None
                    #  5. row["expires_at"] <= now(utc)     -> rollback, return None
                    #  6. otherwise: UPDATE this row SET rotated_at=now(), last_used_at=now();
                    #       INSERT a new row: same user_id, family_id, label and the SAME expires_at
                    #       (D15 — never extend the window), token_hash=_hash_token(new_raw);
                    #       commit; return (int(row["user_id"]), new_raw)
                    #  Every write uses fetchval/fetch_one with RETURNING — never conn.execute().
                    ...
                except BaseException:
                    await conn.rollback()
                    raise
        except MfaStorageError:
            raise
        except Exception as err:  # pylint: disable=W0703
            raise MfaStorageError(f"trusted device rotation failed: {type(err).__name__}") from err
```

**Why the ladder order matters.** The user-mismatch check (2) must precede the
replay check (4): otherwise user A could present user B's *already rotated*
token and get B's whole family revoked — a cross-user denial-of-service. And the
replay branch must **commit** even though it returns `None`, because the
revocation is the point of detecting the replay. Note the `except BaseException:
rollback` will not undo a committed replay revocation — commit first, then return.

**Why keep `expires_at` on rotation.** If every use extended the window, a
cookie used daily would never expire and "remember me for N days" would mean
"forever". The family's first `expires_at` is the hard bound (D15).

**Block 3 — revocation and listing:**

```python
    async def revoke_all(self, user_id: int, reason: str, *, conn: Any = None) -> int:
        """Revoke every live device of a user; returns the number revoked.

        Invalidation events (spec M6): password change, recovery completion,
        TOTP enrol, TOTP disenrol, ADMIN disenrol, tenant hardening, passkey
        removal (D23), global logout (D22, unwired).
        """
        try:
            async with self._scope(conn) as db:
                count = await db.fetchval(
                    f"WITH r AS (UPDATE {_TABLE} SET revoked_at = now(), revoke_reason = $2 "
                    "WHERE user_id = $1 AND revoked_at IS NULL RETURNING 1) SELECT count(*) FROM r",
                    int(user_id), (reason or "")[:64],
                )
        except Exception as err:  # pylint: disable=W0703
            raise MfaStorageError(f"trusted device revoke_all failed: {type(err).__name__}") from err
        return int(count or 0)

    async def revoke_tenant(self, org_id: int, reason: str, *, conn: Any = None) -> int:
        """Revoke every live device of every member of ``org_id`` (tenant hardening).

        Membership comes from ``{schema}.organization_users`` (D7). When that
        table does not exist the tenant has no members and nothing is revoked.
        Relaxing a tenant never calls this (spec: hardening revokes, relaxing
        does not).
        """
        # FILL IN: inside self._scope(conn):
        #   1. regclass = await db.fetchval("SELECT to_regclass($1)", _MEMBERSHIP); None -> return 0
        #   2. CTE-count UPDATE ... SET revoked_at=now(), revoke_reason=$2
        #      WHERE revoked_at IS NULL AND user_id IN (SELECT user_id FROM {_MEMBERSHIP} WHERE org_id = $1)
        #   Wrap errors in MfaStorageError exactly like revoke_all — bounded by D7, AC18.

    async def list_active(self, user_id: int) -> list[TrustedDevice]:
        """Live (not revoked, not rotated, not expired) devices of a user, oldest first."""
        # FILL IN: SELECT user_id, token_hash, label, family_id, expires_at, last_used_at, revoked_at
        #   FROM _TABLE WHERE user_id=$1 AND revoked_at IS NULL AND rotated_at IS NULL
        #   AND expires_at > now() ORDER BY created_at; fetch_all may return None -> [].
        #   Map family_id (uuid) -> str. Errors -> MfaStorageError. — bounded by spec §2 TrustedDevice.
```

**Why `to_regclass` in `revoke_tenant`.** navigator-auth does not create
`organization_users`; a deployment without tenants must not see tenant hardening
crash. An absent table is a structural fact ("no members"), not a transient
error, so it maps to `0` rather than `MfaStorageError` (D7).

### `tests/test_mfa_trusted_devices.py` — CREATE

```python
"""TrustedDeviceStore — FEAT-106 spec §3 Module 6 (TASK-133)."""
import hashlib
from datetime import datetime, timezone

import pytest

from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.trusted_devices import TrustedDeviceStore, may_offer_trusted_device
from tests.fixtures.mfa import mfa_db, mfa_user_factory  # noqa: F401


class _BrokenPool:
    """acquire() raises — every method must surface MfaStorageError."""

    def acquire(self):
        raise ConnectionError("pool down")


def test_trusted_device_not_offered_to_email_state():
    """AC17: only strong-factor users, only when remember_days > 0."""
    # FILL IN: keyword-only calls — (has_strong_factor=True, remember_days=30) -> True;
    #          (False, 30) -> False; (True, 0) -> False.


@pytest.mark.asyncio
async def test_trusted_device_stored_as_hash_only(mfa_db, mfa_user_factory):
    """No raw cookie value in the table; token_hash == sha256(raw)."""
    # FILL IN: issue(); SELECT token_hash FROM auth.user_trusted_devices WHERE user_id=…;
    #          assert row == sha256(raw) and raw not in any column value.


@pytest.mark.asyncio
async def test_trusted_device_rotates_on_use(mfa_db, mfa_user_factory):
    """The returned token differs and the old hash is retired (rotated_at set)."""
    # FILL IN


@pytest.mark.asyncio
async def test_rotation_keeps_original_expiry(mfa_db, mfa_user_factory):
    """D15: the rotated row's expires_at equals the family's first expires_at."""
    # FILL IN


@pytest.mark.asyncio
async def test_trusted_device_replay_revokes_family(mfa_db, mfa_user_factory):
    """Re-presenting a rotated token returns None and revokes the WHOLE family,
    including the newest token."""
    # FILL IN


@pytest.mark.asyncio
async def test_cookie_of_other_user_ignored(mfa_db, mfa_user_factory):
    """D15: user B presenting A's live token gets None and A's row is untouched."""
    # FILL IN


@pytest.mark.asyncio
async def test_expired_token_rejected(mfa_db, mfa_user_factory):
    # FILL IN: UPDATE expires_at into the past, then consume_and_rotate -> None.


@pytest.mark.asyncio
async def test_revoke_all_revokes_every_device(mfa_db, mfa_user_factory):
    # FILL IN: two issues, revoke_all returns 2, both now rejected.


@pytest.mark.asyncio
async def test_revoke_tenant_only_members(mfa_db, mfa_user_factory):
    """Hardening revokes members of the org only."""
    # FILL IN: needs an org + organization_users rows. Inspect FKs first
    #   (information_schema.table_constraints for auth.organization_users); create and
    #   clean up an auth.organizations row if a FK requires it. Bounded by D7.


@pytest.mark.asyncio
async def test_storage_error_fails_closed():
    """Every method raises MfaStorageError when the pool is down (G7)."""
    store = TrustedDeviceStore(_BrokenPool())
    with pytest.raises(MfaStorageError):
        await store.consume_and_rotate("any-token", 1)
    # FILL IN: same for issue, revoke_all, revoke_tenant, list_active.
```

**Why live Postgres.** `FOR UPDATE`, the CTE counting idiom and the unique
`token_hash` constraint are exactly what makes rotation atomic; a fake pool would
test the fake. Postgres is live at `conf.default_dsn` (verified 2026-11-11) and
the `mfa_db` fixture skips cleanly when it is not.

### Steps (in order)

1. Confirm TASK-129 and TASK-130 landed: `from navigator_auth.mfa.types import TrustedDevice`
   imports, and `auth.user_trusted_devices` has `rotated_at` and `revoke_reason`.
2. Create the module with Block 1; fill `may_offer_trusted_device`.
3. Add Block 2. Fill the ladder **in the listed order**; commit before returning
   from the replay branch.
4. Add Block 3; fill `revoke_tenant` and `list_active`.
5. Write the tests; fill bodies one class of behaviour at a time.
6. Run the commands in **Test Specification**.
7. Run the AC5 guard (D5): `grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/`
   must print nothing.

### FILL IN checklist

- [ ] `may_offer_trusted_device` body — AC17
- [ ] `consume_and_rotate` ladder (6 branches, ordered; replay commits) — D15, AC18, R8
- [ ] `revoke_tenant` with `to_regclass` guard — D7, AC18
- [ ] `list_active` mapping — spec §2
- [ ] 10 test bodies (org fixture for `revoke_tenant`)

---

## Acceptance Criteria

- [ ] **AC-1** Only `sha256(raw)` is persisted; no raw token appears in any column or log line (spec AC14).
- [ ] **AC-2** `consume_and_rotate` returns a *different* raw token and the presented row gets `rotated_at`.
- [ ] **AC-3** Re-presenting a rotated token returns `None` and revokes every row of its family (`revoke_reason='replay'`).
- [ ] **AC-4** A token belonging to another user returns `None` and leaves every row unchanged.
- [ ] **AC-5** Rotation preserves the family's original `expires_at`; an expired token is rejected.
- [ ] **AC-6** `revoke_all` / `revoke_tenant` return the number revoked; `revoke_tenant` touches only members of the org and returns `0` when `organization_users` is absent.
- [ ] **AC-7** Every method raises `MfaStorageError` when storage fails (fail closed, spec G7/R5).
- [ ] **AC-8** `may_offer_trusted_device` is true only for `has_strong_factor and remember_days > 0` (spec AC17).
- [ ] **AC-9** `UserDevices` is not referenced; no `conn.execute()` call in the module.
- [ ] **AC-10** `grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/` prints nothing (D5).
- [ ] Contributes to spec **AC14, AC17, AC18** (revocation primitives), **AC19** (via TASK-138's use).

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_trusted_devices.py -v
ruff check navigator_auth/mfa/trusted_devices.py tests/test_mfa_trusted_devices.py
grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/ ; test $? -eq 1
grep -n "execute(" navigator_auth/mfa/trusted_devices.py ; test $? -eq 1
```

Spec §4 rows owned here: `test_trusted_device_rotates_on_use`,
`test_trusted_device_replay_revokes_family`, `test_trusted_device_stored_as_hash_only`,
`test_trusted_device_not_offered_to_email_state`.

---

## Agent Instructions

1. **Read the spec** `sdd/specs/basicauth-otp-2fa.spec.md` — §3 Module 6, §7 R8,
   AC17–AC19, and the contract decisions D7, D14, D15, D17.
2. **Check dependencies** — TASK-129 and TASK-130 must be in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint. Do not invent extra columns or bindings.
5. **Verify** every acceptance criterion.
6. **Move this file** to `sdd/tasks/completed/TASK-133-mfa-trusted-devices.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: gpt-5.6-luna (codex), 1 attempt
**Date**: 2026-11-11
**Notes**: MFA trusted devices delivered; merge-tier green.

**Deviations from spec**: none | describe if any
