# TASK-171: Bounded user_lock, LOCK_CONNECTION and a standalone advisory_user_lock

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

PR #633 review finding **#3** (spec §1): code running inside `MfaSecurity.user_lock` acquires more
connections from the same `authdb` pool, while password handlers acquire in the opposite order, so at
about `max_size` concurrent requests the pool deadlocks. Spec goal **G3** says that inside a `user_lock`
scope no code may acquire a second pool connection, and **AC11** says every lock wait is bounded by
`AUTH_MFA_LOCK_TIMEOUT` (a timeout surfaces as 503 `mfa_unavailable`, never as a hang).

This task implements the **lock core** of spec §3 Module 2:

- the per-user lock gets a bounded acquire and a bounded advisory-lock wait;
- its connection is published in a `ContextVar` (`LOCK_CONNECTION`) for the scope;
- the lock is also available as a standalone `advisory_user_lock(db_pool, user_id)`. Spec M3 needs the
  *same* per-user advisory lock when MFA is not configured (no `MfaSecurity`, no secret), and the
  recovery/OAuth tasks need it with MFA off.

It also adds the shared `single_connection_authdb` test fixture that every later task uses to prove AC10
("no `acquire()` while `LOCK_CONNECTION` is set").

The `conn=` parameters on the stores (spec M2's second half) are TASK-172. The 503 mapping of a timeout
is done by the callers (TASK-177, TASK-181).

---

## Scope

- Add `LOCK_CONNECTION` (`ContextVar`) and `advisory_user_lock(db_pool, user_id, *, timeout=None)` to
  `navigator_auth/mfa/security.py`, with:
  - the pool acquire bounded by `asyncio.wait_for`;
  - the lock wait bounded by a transaction-local `lock_timeout` set via `fetchval`;
  - either timeout raising `MfaStorageError`;
  - the connection published in `LOCK_CONNECTION` for the scope.
- Rewrite `MfaSecurity.user_lock` to delegate to `advisory_user_lock(self._pool, user_id)`. Its
  observable behaviour is unchanged except for the new bounds and the `ContextVar`.
- Add `AUTH_MFA_LOCK_TIMEOUT` (float seconds, fallback `5.0`) to `navigator_auth/conf.py`.
- Add the `single_connection_authdb` fixture (and its `_LockAwarePool` wrapper) to `tests/fixtures/mfa.py`.
- Create `tests/test_mfa_review_fixes_transitions.py` with the lock-core tests.

**NOT in scope**:
- `conn=` kwargs on `user_from_id`, TOTP, trusted devices or passkey store (TASK-172).
- `AUTH_MFA_RETRY_INTERVAL` and self-healing services (TASK-173).
- Any change to `security_transition` (TASK-177).
- Mapping `MfaStorageError` to 503 in handlers (TASK-177, TASK-181/182).
- Any production code branching on `LOCK_CONNECTION`. Only `advisory_user_lock` sets and resets it
  (spec §7 Known Risks: the guard is a test aid).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/security.py` | MODIFY | `LOCK_CONNECTION`, `advisory_user_lock`, `user_lock` delegates |
| `navigator_auth/conf.py` | MODIFY | `AUTH_MFA_LOCK_TIMEOUT` |
| `tests/fixtures/mfa.py` | MODIFY | `_LockAwarePool` + `single_connection_authdb` fixture |
| `tests/test_mfa_review_fixes_transitions.py` | CREATE | Lock-core tests (timeout, publication, guard self-test) |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `0b80d88` (branch `feat-FEAT-106-basicauth-otp-2fa`, worktree
> `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa`). The code is identical to the spec's `3f14b3c`.

### Verified Imports
```python
from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_PASSWORD_ATTRIBUTE, AUTH_USERID_ATTRIBUTE  # verified: navigator_auth/mfa/security.py:11
from navigator_auth.mfa.exceptions import MfaStorageError                 # verified: navigator_auth/mfa/security.py:12 (class at exceptions.py:8)
from navigator_auth.mfa.security import LOCK_NAMESPACE, MfaSecurity, _lock_key  # verified: tests/test_mfa_security_core.py:10
from navigator_auth.mfa.migrations import ensure_mfa_tables                # verified: tests/fixtures/mfa.py:13
from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE, REDIS_AUTH_URL, default_dsn  # verified: tests/fixtures/mfa.py:11
from tests.fixtures.mfa import mfa_db, mfa_secret, mfa_user_factory  # noqa: F401  — verified: tests/test_mfa_security_core.py:12
from navconfig import config                                               # verified: navigator_auth/conf.py:11
import asyncdb  # inside the fixture, as tests/fixtures/mfa.py:65 does; AsyncPool("pg", **kw) forwards kw to pgPool
# stdlib, new in security.py: import asyncio ; from contextvars import ContextVar ; from typing import Any, Optional
```

### Existing Signatures to Use
```python
# navigator_auth/mfa/security.py
from collections.abc import AsyncIterator, Mapping                      # line 7
from contextlib import asynccontextmanager                               # line 8
from typing import Any                                                   # line 9 (Optional must be added)
LOCK_NAMESPACE = 0x4D464131                                              # line 17
def _lock_key(user_id: int) -> int:                                      # line 36 (ValueError on bool/negative/non-int)
class MfaSecurity:                                                       # line 43
    def __init__(self, db_pool: Any, secret: bytes):                     # line 46 — sets self._pool, self._secret, self._schema
    @asynccontextmanager
    async def user_lock(self, user_id: int) -> AsyncIterator[Any]:       # line 55 — today: `async with await self._pool.acquire() as conn`,
                                                                         #   conn.transaction(); fetchval pg_advisory_xact_lock; yield; commit/rollback
    async def current_version(self, conn: Any, user_id: int) -> int:     # line 78
    async def bump_version(self, conn: Any, user_id: int) -> int:        # line 94

# navigator_auth/conf.py
AUTH_OTP_EMAIL_CALLBACK = config.get("AUTH_OTP_EMAIL_CALLBACK")          # line 671 (anchor; FEAT-106 2FA block at 657-675)

# tests/fixtures/mfa.py
@pytest_asyncio.fixture
async def mfa_db():                                                      # line 60 — AsyncPool("pg", dsn=default_dsn); connect; ensure_mfa_tables; skip if down
@pytest_asyncio.fixture
async def mfa_user_factory(mfa_db):                                      # line 77 — returns dict with user_id, password, ...

# asyncdb (site-packages, installed version)
# asyncdb/drivers/pg.py:233-236  pgPool kwargs `max_clients` (pool max size) and `min_size`
# asyncdb/drivers/pg.py:443      pgPool.acquire() -> _pgAcquireContext; supports `await pool.acquire()` and
#                                `async with await pool.acquire() as conn` (the pattern used by user_lock today)
```

### Does NOT Exist
- ~~`config.getfloat(...)`~~ — navconfig's `config` exposes only `get`, `getboolean`, `getdict`, `getint`,
  `getlist` (verified in the venv). Use `float(config.get("AUTH_MFA_LOCK_TIMEOUT", fallback=5.0))`.
  This deviates from the spec's `config.getfloat` wording; the value and fallback are the same.
- ~~`pool.acquire(timeout=...)`~~ — the asyncdb wrapper takes no timeout. Bound it with `asyncio.wait_for`.
- ~~`LOCK_CONNECTION`~~, ~~`advisory_user_lock`~~, ~~`AUTH_MFA_LOCK_TIMEOUT`~~, ~~`single_connection_authdb`~~,
  ~~`_LockAwarePool`~~ — created by THIS task.
- ~~`AUTH_MFA_RETRY_INTERVAL`~~, ~~`mfa_services_lease`~~ — TASK-173. ~~`MfaUnavailable`~~,
  ~~`TransitionAborted`~~ — TASK-177.
- ~~a `tests/conftest.py` plugin that loads `tests/fixtures/mfa.py`~~ — none. Tests import fixtures
  explicitly (`from tests.fixtures.mfa import ...  # noqa: F401`), so a new fixture is purely additive.
- ~~`MfaSecurity.lock_timeout`~~ or any per-instance timeout attribute — the bound is the module-level
  `AUTH_MFA_LOCK_TIMEOUT`, or the `timeout=` kwarg of `advisory_user_lock`.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/mfa/security.py", "action": "MODIFY"},
    {"path": "navigator_auth/conf.py", "action": "MODIFY"},
    {"path": "tests/fixtures/mfa.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_review_fixes_transitions.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/mfa/security.py#MfaSecurity",
    "sym:navigator_auth/mfa/security.py#MfaSecurity.user_lock",
    "sym:navigator_auth/mfa/security.py#_lock_key",
    "sym:navigator_auth/mfa/security.py#LOCK_NAMESPACE",
    "sym:navigator_auth/mfa/exceptions.py#MfaStorageError",
    "sym:navigator_auth/mfa/migrations.py#ensure_mfa_tables",
    "sym:tests/fixtures/mfa.py#mfa_db",
    "sym:tests/fixtures/mfa.py#mfa_user_factory"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
```python
# The current MfaSecurity.user_lock (security.py:54-76) is the transaction shape to keep:
async with await self._pool.acquire() as conn:
    await conn.transaction()
    await conn.fetchval("SELECT pg_advisory_xact_lock($1::int4, $2::int4)", LOCK_NAMESPACE, key)
    try:
        yield conn
    except BaseException:
        await conn.rollback()
        raise
    await conn.commit()
```

### Key Constraints
- asyncdb `conn.execute` swallows DB errors (project memory `asyncdb-execute-never-raises`). Set
  `lock_timeout` with `fetchval("SELECT set_config('lock_timeout', $1, true)", "<ms>ms")`, never with
  `execute("SET LOCAL ...")`. A silent failure would leave the lock wait unbounded.
- `is_local=true` makes the setting transaction-scoped. It also bounds row locks taken later in the
  same lock scope (e.g. `FOR UPDATE` in trusted-device rotation). That is intended.
- `LOCK_CONNECTION` must be reset with the token from `set()` in a `finally`, so it is `None` after the
  scope on every exit path (success, body exception, commit failure).
- Keep `advisory_user_lock` free of MFA services: it must work with only a pool. Spec M3 uses it when MFA
  is not configured, and recovery/OAuth use it with 2FA off.
- Read `AUTH_MFA_LOCK_TIMEOUT` as a module global at call time, so tests can
  `monkeypatch.setattr("navigator_auth.mfa.security.AUTH_MFA_LOCK_TIMEOUT", 0.3)`.
- Error messages carry only exception type names: no SQL, no secrets (FEAT-106 `test_no_secret_in_logs`).
- Google-style docstrings and strict type hints on every new function and class.

### References in Codebase
- `navigator_auth/mfa/security.py:54-76` — the lock being refactored.
- `tests/test_mfa_security_core.py:112-176` — existing `user_lock` tests (rollback, same-user
  serialization, independent users). They must keep passing unchanged.
- `tests/fixtures/mfa.py:59-73` — the `mfa_db` fixture to mirror for `single_connection_authdb`.

---

## Implementation Blueprint

### Steps (in order)
1. Add `AUTH_MFA_LOCK_TIMEOUT` to `conf.py` — *why*: `security.py` imports it at module import time.
2. Extend the imports in `security.py` (`asyncio`, `ContextVar`, `Optional`, `AUTH_MFA_LOCK_TIMEOUT`) —
   *why*: the new lock code needs them; nothing else may be imported.
3. Insert `LOCK_CONNECTION` and `advisory_user_lock` above `class MfaSecurity:` — *why*: a module-level
   function is usable without `MfaSecurity` (no secret needed). That is what spec M3's "MFA not
   configured" branch requires.
4. Replace the body of `MfaSecurity.user_lock` with a delegation — *why*: one lock implementation, so
   the bounds and the `ContextVar` apply to every caller.
5. Add `_LockAwarePool` and `single_connection_authdb` to `tests/fixtures/mfa.py` — *why*: later tasks
   prove AC10 per flow with it.
6. Write `tests/test_mfa_review_fixes_transitions.py` and run the Validation Commands — *why*: AC11 and
   the G3 guard must be proven on a live database.

### `navigator_auth/conf.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'AUTH_OTP_EMAIL_CALLBACK = config.get("AUTH_OTP_EMAIL_CALLBACK")' navigator_auth/conf.py)
# AFTER — insert below `AUTH_OTP_EMAIL_CALLBACK = config.get("AUTH_OTP_EMAIL_CALLBACK")` (verified: navigator_auth/conf.py:671)
# Bound (seconds) on the MFA per-user lock: pool acquire AND advisory-lock wait (FEAT-106 review fixes, M2).
# navconfig has no getfloat(): parse explicitly.
AUTH_MFA_LOCK_TIMEOUT = float(config.get("AUTH_MFA_LOCK_TIMEOUT", fallback=5.0))
```
**Why**: Spec Q1 fixed the default at 5 s. TASK-173 later adds `AUTH_MFA_RETRY_INTERVAL` right below
this line, so keep the two settings adjacent.

### `navigator_auth/mfa/security.py` (MODIFY — imports)
```python
# occurrences: 1 (verified: grep -c 'import hashlib' navigator_auth/mfa/security.py)
# BEFORE — insert above `import hashlib` (verified: navigator_auth/mfa/security.py:3)
import asyncio

# occurrences: 1 (verified: grep -c 'from contextlib import asynccontextmanager' navigator_auth/mfa/security.py)
# AFTER — insert below `from contextlib import asynccontextmanager` (verified: navigator_auth/mfa/security.py:8)
from contextvars import ContextVar

# occurrences: 1 (verified: grep -c 'from typing import Any' navigator_auth/mfa/security.py)
# REPLACE — `from typing import Any` (verified: navigator_auth/mfa/security.py:9)
from typing import Any, Optional

# occurrences: 1 (verified: grep -c 'from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_PASSWORD_ATTRIBUTE, AUTH_USERID_ATTRIBUTE' navigator_auth/mfa/security.py)
# REPLACE — that line (verified: navigator_auth/mfa/security.py:11)
from navigator_auth.conf import (
    AUTH_DB_SCHEMA,
    AUTH_MFA_LOCK_TIMEOUT,
    AUTH_PASSWORD_ATTRIBUTE,
    AUTH_USERID_ATTRIBUTE,
)
```
**Why**: These are the only new names the lock needs. `AsyncIterator` is already imported from
`collections.abc` (line 7).

### `navigator_auth/mfa/security.py` (MODIFY — new module-level lock)
```python
# occurrences: 1 (verified: grep -c 'class MfaSecurity:' navigator_auth/mfa/security.py)
# BEFORE — insert above `class MfaSecurity:` (verified: navigator_auth/mfa/security.py:43), after _lock_key()
LOCK_CONNECTION: ContextVar[Optional[Any]] = ContextVar("navigator_auth_mfa_lock_connection", default=None)


async def _acquire(db_pool: Any) -> Any:
    """Await the pool's acquire so it can be bounded by ``asyncio.wait_for``."""
    return await db_pool.acquire()


@asynccontextmanager
async def advisory_user_lock(db_pool: Any, user_id: int, *, timeout: Optional[float] = None) -> AsyncIterator[Any]:
    """Yield ONE pooled connection in ONE transaction holding the user's advisory lock.

    Args:
        db_pool: asyncdb pool exposing ``acquire()``.
        user_id: Non-negative user id, folded into an int4 key by ``_lock_key``.
        timeout: Seconds bounding the pool acquire and the lock wait; ``None`` uses
            ``AUTH_MFA_LOCK_TIMEOUT``.

    Yields:
        The lock connection, published in ``LOCK_CONNECTION`` for the scope.

    Raises:
        MfaStorageError: the acquire or the lock wait timed out, the lock statements failed, or
            the commit failed. A body exception rolls back and is re-raised unchanged.
    """
    key = _lock_key(user_id)
    limit = AUTH_MFA_LOCK_TIMEOUT if timeout is None else float(timeout)
    try:
        conn_cm = await asyncio.wait_for(_acquire(db_pool), timeout=limit)
    except asyncio.TimeoutError as err:
        raise MfaStorageError("MFA user lock acquire timed out") from err
    except Exception as err:
        raise MfaStorageError(f"MFA user lock acquire failed: {type(err).__name__}") from err
    # FILL IN: guarantee a connection acquired just as the timeout fired is released, never leaked
    #          — bounded by AC10 (a leaked connection exhausts a max_size=1 pool)
    async with conn_cm as conn:
        try:
            await conn.transaction()
            await conn.fetchval("SELECT set_config('lock_timeout', $1, true)", f"{max(int(limit * 1000), 1)}ms")
            await conn.fetchval("SELECT pg_advisory_xact_lock($1::int4, $2::int4)", LOCK_NAMESPACE, key)
        except Exception as err:
            try:
                await conn.rollback()
            except Exception:  # pylint: disable=W0703
                pass
            raise MfaStorageError(f"MFA user lock failed: {type(err).__name__}") from err
        token = LOCK_CONNECTION.set(conn)
        try:
            try:
                yield conn
            except BaseException:
                await conn.rollback()
                raise
            try:
                await conn.commit()
            except Exception as err:
                raise MfaStorageError(f"MFA user lock commit failed: {type(err).__name__}") from err
        finally:
            LOCK_CONNECTION.reset(token)
```
**Why this shape**: The transaction, lock statement, rollback and commit semantics are copied from
today's `user_lock`, so `tests/test_mfa_security_core.py` keeps passing. The new parts are the
`wait_for` around the acquire, `set_config('lock_timeout', …, true)` before the advisory lock (spec M2
skeleton: "asyncio.wait_for … + SET LOCAL lock_timeout"), and the `ContextVar` publication. The lock
statements stay outside the `LOCK_CONNECTION` window because they run on the lock connection itself.

### `navigator_auth/mfa/security.py` (MODIFY — user_lock delegates)
```python
# occurrences: 1 (verified: grep -c 'async def user_lock(self, user_id: int) -> AsyncIterator[Any]:' navigator_auth/mfa/security.py)
# REPLACE — the whole method starting at that line through `raise MfaStorageError(f"MFA user lock commit failed: ...`
#           (verified: navigator_auth/mfa/security.py:54-76, decorator at :54)
    @asynccontextmanager
    async def user_lock(self, user_id: int) -> AsyncIterator[Any]:
        """Yield a transaction holding the user's advisory lock.

        Bounded by ``AUTH_MFA_LOCK_TIMEOUT`` and published in ``LOCK_CONNECTION``; see
        :func:`advisory_user_lock`.
        """
        async with advisory_user_lock(self._pool, user_id) as conn:
            yield conn
```
**Why**: There is exactly one lock implementation, so every caller (`security_transition`, the MFA
handlers, the gate) gets the bounds and the guard publication with no further change.

### `tests/fixtures/mfa.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'from navigator_auth.mfa.migrations import ensure_mfa_tables' tests/fixtures/mfa.py)
# AFTER — insert below `from navigator_auth.mfa.migrations import ensure_mfa_tables` (verified: tests/fixtures/mfa.py:13)
from navigator_auth.mfa.security import LOCK_CONNECTION

# occurrences: 1 (verified: grep -c 'async def mfa_user_factory(mfa_db):' tests/fixtures/mfa.py)
# BEFORE — insert above the `@pytest_asyncio.fixture` decorator of `async def mfa_user_factory(mfa_db):` (verified: tests/fixtures/mfa.py:76-77)
class _LockAwarePool:
    """asyncdb pool wrapper recording every ``acquire()`` with the ``LOCK_CONNECTION`` value (AC10)."""

    def __init__(self, pool) -> None:
        self._pool = pool
        self.strict = False
        self.acquires: list[bool] = []
        self.acquires_inside_lock: list[object] = []

    def acquire(self):
        """Record the call, optionally refuse it inside a lock scope, then delegate."""
        held = LOCK_CONNECTION.get()
        self.acquires.append(held is not None)
        if held is not None:
            self.acquires_inside_lock.append(held)
            if self.strict:
                raise AssertionError("pool.acquire() called inside a user_lock scope")
        return self._pool.acquire()

    def __getattr__(self, name):
        return getattr(self._pool, name)


@pytest_asyncio.fixture
async def single_connection_authdb():
    """Live authdb pool capped at ONE connection that records nested acquires, or skip."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            import asyncdb  # pylint: disable=import-outside-toplevel

            pool = asyncdb.AsyncPool("pg", dsn=default_dsn, max_clients=1, min_size=1)
        await pool.connect()
        await ensure_mfa_tables(pool)
    except Exception as err:  # pylint: disable=W0703
        pytest.skip(f"Postgres unavailable: {type(err).__name__}: {err}")
    yield _LockAwarePool(pool)
    await pool.close()
```
**Why**: Recording happens when `acquire()` is called, before anything is awaited, so a nested acquire is
caught even though it would block forever on a one-connection pool. `strict` turns the record into an
immediate `AssertionError` for the guard test. Tests assert `pool.acquires_inside_lock == []` after each
flow (AC10).

### `tests/test_mfa_review_fixes_transitions.py` (CREATE)
```python
"""FEAT-106 review fixes — lock core (M2): bounded user_lock and LOCK_CONNECTION (AC10, AC11).

Later tasks (TASK-177, TASK-179) append transition tests to this module.
"""

import asyncio

import pytest

from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.security import LOCK_CONNECTION, MfaSecurity, advisory_user_lock
from tests.fixtures.mfa import mfa_db, mfa_secret, mfa_user_factory, single_connection_authdb  # noqa: F401


@pytest.mark.asyncio
async def test_user_lock_timeout(mfa_db, mfa_user_factory, mfa_secret, monkeypatch):
    """A held advisory lock makes a second user_lock raise MfaStorageError after the timeout (AC11)."""
    monkeypatch.setattr("navigator_auth.mfa.security.AUTH_MFA_LOCK_TIMEOUT", 0.3)
    # FILL IN: hold user_lock(uid) in a task; a second user_lock(uid) raises MfaStorageError within ~1 s
    #          (assert elapsed < 2 s) — bounded by AC11


@pytest.mark.asyncio
async def test_user_lock_acquire_timeout(single_connection_authdb, mfa_user_factory):
    """With the only pool connection held, the acquire itself is bounded (AC11)."""
    # FILL IN: hold advisory_user_lock(pool, uid_a); advisory_user_lock(pool, uid_b, timeout=0.2) raises
    #          MfaStorageError — bounded by AC11


@pytest.mark.asyncio
async def test_lock_connection_published(mfa_db, mfa_user_factory, mfa_secret):
    """LOCK_CONNECTION is the lock connection inside the scope and None after, on every exit path."""
    # FILL IN: success path, body-exception path (RuntimeError re-raised, rolled back) — bounded by spec §4 M2 row


@pytest.mark.asyncio
async def test_no_acquire_inside_lock_guard(single_connection_authdb, mfa_user_factory):
    """The fixture records (and in strict mode refuses) an acquire inside a lock scope (AC10)."""
    # FILL IN: strict=True; inside advisory_user_lock, pool.acquire() raises AssertionError (do NOT await
    #          it) and acquires_inside_lock has one entry; outside the scope acquires are clean


@pytest.mark.asyncio
async def test_advisory_user_lock_serializes_without_mfa_security(mfa_db, mfa_user_factory):
    """The standalone lock serializes one user with only a pool: no MfaSecurity, no secret (spec M3)."""
    # FILL IN: mirror tests/test_mfa_security_core.py::test_user_lock_serializes_same_user with advisory_user_lock
```
**Why**: These are exactly the spec §4 unit rows owned by M2's lock half (`test_user_lock_timeout`,
`test_lock_connection_published`) plus the fixture self-test behind `test_no_acquire_inside_lock_guard`.
Later tasks append to this module, so keep the imports minimal.

### FILL IN checklist
- [ ] `security.py::advisory_user_lock` — release a connection that arrives after the timeout fired; bounded by AC10.
- [ ] `test_user_lock_timeout` — two-task hold/timeout body; bounded by AC11.
- [ ] `test_user_lock_acquire_timeout` — pool-exhaustion body; bounded by AC11.
- [ ] `test_lock_connection_published` — success and failure paths; bounded by spec §4 M2.
- [ ] `test_no_acquire_inside_lock_guard` — strict guard plus record assertion; bounded by AC10.
- [ ] `test_advisory_user_lock_serializes_without_mfa_security` — serialization with only a pool; bounded by spec §3 M3.

---

## Acceptance Criteria

- [ ] `advisory_user_lock` and `LOCK_CONNECTION` exist in `navigator_auth/mfa/security.py`.
      `MfaSecurity.user_lock` delegates to `advisory_user_lock`.
- [ ] A held lock makes a second `user_lock` for the same user raise `MfaStorageError` after
      `AUTH_MFA_LOCK_TIMEOUT` (AC11 at the lock level). An exhausted pool makes the acquire raise
      `MfaStorageError` within the bound.
- [ ] `LOCK_CONNECTION.get()` is the lock connection inside the scope and `None` after it on success,
      body exception and commit failure.
- [ ] `single_connection_authdb` records every `acquire()` with the `LOCK_CONNECTION` value. In strict
      mode it refuses an acquire inside a lock scope.
- [ ] `AUTH_MFA_LOCK_TIMEOUT` defaults to `5.0` (float).
- [ ] Every existing `tests/test_mfa_security_core.py` test passes unchanged.
- [ ] No linting errors in the touched files.

---

## Validation Commands

- `pytest tests/test_mfa_review_fixes_transitions.py -q`
- `pytest tests/test_mfa_security_core.py -q`

---

## Test Specification

```python
# tests/test_mfa_review_fixes_transitions.py — see the Implementation Blueprint block above.
# Live Postgres via tests.fixtures.mfa (mfa_db / single_connection_authdb); the tests skip when Postgres is down.
# Key assertions:
#   - test_user_lock_timeout: pytest.raises(MfaStorageError) and elapsed < 2 s with the timeout patched to 0.3
#   - test_lock_connection_published: LOCK_CONNECTION.get() is conn inside; None after success and after RuntimeError
#   - test_no_acquire_inside_lock_guard: AssertionError in strict mode; len(pool.acquires_inside_lock) == 1
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the stacked feature worktree** `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa-review-fixes`
   (branch `feat-FEAT-106-basicauth-otp-2fa-review-fixes`, stacked on `feat-FEAT-106-basicauth-otp-2fa`; ships in PR #633), never on `dev`.
2. **Read the spec** at the path listed above, §3 Module 2 and §7.
3. **Check dependencies**: none.
4. **Verify the Codebase Contract**: re-run the `grep -c` counts in the blueprint before editing.
5. **Update status** in `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json` → `"in-progress"`.
6. **Implement**: start from the blueprint blocks and complete every `# FILL IN:` marker.
7. **Verify**: run the Validation Commands.
8. **Commit the code**: stage only the files listed above.
9. **Close the task** with `parrot sdd task close TASK-171 basicauth-otp-2fa-review-fixes verified`.
10. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: `AUTH_MFA_LOCK_TIMEOUT` is parsed with `float(config.get(...))` because navconfig has no `getfloat`.
