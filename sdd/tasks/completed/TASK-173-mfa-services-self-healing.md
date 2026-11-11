# TASK-173: Self-healing MFA services with leases (M1)

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-171
**Assigned-to**: unassigned

---

## Context

Review finding **#4** (spec §1): MFA availability is decided once at startup and never retried. A
transient failure (for example, the MFA tables probe failing while Postgres restarts) refuses every
BasicAuth login for the life of the process. Goal **G5**: MFA availability self-heals without a restart.

Spec §3 **Module 1** fixes the contract:

- `MfaServicesSlot.ready(app)` returns the current services and rebuilds them when they are transiently
  unavailable, at most once per `AUTH_MFA_RETRY_INTERVAL`, single-flight under an `asyncio.Lock`.
- Permanent misconfiguration (no `AUTH_OTP_SECRET`, no `authdb`) is flagged `permanent=True` and never
  retried.
- Callers hold a **service lease** for their whole operation. Swapping retires the old object, and its
  Redis pool closes only after its last lease ends (AC34). Shutdown drains or cancels leases first.

The lease API is decided in the /sdd-task plan, so dependent tasks can use it verbatim:
`MfaServices.lease()`, `MfaServices.retire()`, `MfaServicesSlot.close()`, `get_ready_mfa_services(app)`
and `mfa_services_lease(app)`.

Every MFA decision point later switches to `async with mfa_services_lease(app) as services:`:

- `security_transition` (TASK-177);
- the gate's callers (TASK-182, TASK-184);
- the MFA handlers (TASK-182, TASK-183);
- the passkey remove guard (TASK-178).

This task builds the mechanism and switches only `BasicAuth.on_cleanup`.

---

## Scope

- Add `permanent: bool = False` to `MfaServices.__init__`, set by `build_mfa_services` for a missing
  secret or a missing `authdb`.
- Add lease tracking to `MfaServices`: `lease()` (async context manager), `retire()`, and an idempotent
  `close()`.
- Add the following to `MfaServicesSlot`:
  - `ready(app)`: rebuild-on-interval, single-flight, never raises;
  - `close()`: shutdown drain;
  - track retired-but-leased objects.
- Add module functions `get_ready_mfa_services(app)` and `mfa_services_lease(app)`. Keep
  `get_mfa_services(app)` unchanged (sync, raw) for existing callers.
- Add `AUTH_MFA_RETRY_INTERVAL` (int seconds, fallback `15`) to `navigator_auth/conf.py`, right below
  TASK-171's `AUTH_MFA_LOCK_TIMEOUT`.
- `BasicAuth.on_cleanup`: replace the direct `slot.services.close()` with `await slot.close()`.
- Create `tests/test_mfa_review_fixes_services.py`.

**NOT in scope**:
- Switching `security_transition`, `BasicAuth._second_factor`, `MfaHandler`, the passkey backend or the
  OAuth2 form to `mfa_services_lease`. Each switch belongs to its own task (177, 182, 183, 178, 184).
- Changing what `build_mfa_services` builds, or the startup path in `BasicAuth.on_startup` (it still
  assigns `slot.services = await build_mfa_services(app, self)`).
- Any HTTP-level 503 mapping.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/services.py` | MODIFY | `permanent`, leases, `ready()`, `close()`, `get_ready_mfa_services`, `mfa_services_lease` |
| `navigator_auth/conf.py` | MODIFY | `AUTH_MFA_RETRY_INTERVAL` |
| `navigator_auth/backends/basic.py` | MODIFY | `on_cleanup` → `await slot.close()` |
| `tests/test_mfa_review_fixes_services.py` | CREATE | `test_ready_*` (spec §4 M1 rows), lease/shutdown tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `0b80d88` (branch `feat-FEAT-106-basicauth-otp-2fa`, worktree
> `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa`). The code is identical to the spec's `3f14b3c`.

### Verified Imports
```python
from collections.abc import Mapping                                        # verified: navigator_auth/mfa/services.py:4 (add AsyncIterator)
from typing import Any, Optional                                           # verified: navigator_auth/mfa/services.py:5
from navigator_auth import conf as auth_conf                               # verified: navigator_auth/mfa/services.py:9 (read settings at call time)
from navigator_auth.mfa.services import MFA_APP_KEY, MfaServices, MfaServicesSlot, build_mfa_services  # verified: tests/test_mfa_basic_auth_hook.py:16
from tests.fixtures.mfa import mfa_db, mfa_secret  # noqa: F401            # verified: tests/test_mfa_security_core.py:12 (same style)
# stdlib, new in services.py: import asyncio ; import time ; from contextlib import asynccontextmanager
```

### Existing Signatures to Use
```python
# navigator_auth/mfa/services.py
MFA_APP_KEY = "navigator_auth.mfa"                                        # line 25
class MfaServices:                                                         # line 28
    def __init__(self, *, backend, available, redis_pool=None, db_pool=None, secret=b"", store=None,
                 user_limiter=None, ip_limiter=None, security=None, trusted_devices=None, backup_codes=None,
                 resolver=None, state=None, providers=None) -> None       # lines 31-62 (last kw `providers` at :47; last assignment :62)
    async def evaluate(self, user: Mapping, *, conn: Any = None) -> MfaEvaluation   # line 64
    async def close(self) -> None:                                         # line 100 — `if self.redis_pool is not None: await self.redis_pool.disconnect()`
class MfaServicesSlot:                                                     # line 106 — __init__(self, services=None): self.services = services
def get_mfa_services(app: Any) -> Optional[MfaServices]:                   # line 113 (KEEP unchanged)
async def build_mfa_services(app: Any, backend: Any) -> MfaServices:       # line 119 — never raises; returns available=False:
    #   :125-126 missing AUTH_OTP_SECRET (permanent) · :129-130 no app["authdb"] (permanent)
    #   :147-149 exception while building (transient) · :150-151 tables probe False (transient; full object incl. redis_pool)

# navigator_auth/backends/basic.py
    async def on_startup(self, app):                                       # line 81 — :92-95 builds slot.services, sets self._mfa_slot
    async def on_cleanup(self, app):                                       # line 97 — :105-111 closes slot.services directly

# navigator_auth/conf.py (after TASK-171)
AUTH_MFA_LOCK_TIMEOUT = float(config.get("AUTH_MFA_LOCK_TIMEOUT", fallback=5.0))   # created by TASK-171 (dependency), below conf.py:671

# Tests construct services directly (must keep working, positional slot arg):
#   MfaServicesSlot(services)  — tests/test_mfa_basic_auth_hook.py:84, tests/test_mfa_verify.py:142,
#   tests/test_mfa_enrollment_security.py:122, tests/test_mfa_admin_disenroll.py:55
#   MfaServices(backend=None, available=False) — tests/test_mfa_basic_auth_hook.py:73
```

### Does NOT Exist
- ~~`get_ready_mfa_services`~~, ~~`mfa_services_lease`~~, ~~`MfaServices.permanent`~~, ~~`MfaServices.lease`~~,
  ~~`MfaServices.retire`~~, ~~`MfaServicesSlot.ready`~~, ~~`MfaServicesSlot.close`~~,
  ~~`AUTH_MFA_RETRY_INTERVAL`~~ — created by THIS task.
- ~~`config.getfloat`~~ — not in navconfig (see TASK-171). `AUTH_MFA_RETRY_INTERVAL` uses `config.getint`,
  which exists.
- ~~a background retry task / timer~~ — the spec chose a lazy rebuild at decision points. Never start a
  periodic task.
- ~~`MfaServicesSlot.install()`~~ / a setter on `services` — startup keeps plain attribute assignment
  (`basic.py:94`). The rebuild clock comes from the services object's own build time.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/mfa/services.py", "action": "MODIFY"},
    {"path": "navigator_auth/conf.py", "action": "MODIFY"},
    {"path": "navigator_auth/backends/basic.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_review_fixes_services.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/mfa/services.py#MfaServices",
    "sym:navigator_auth/mfa/services.py#MfaServices.close",
    "sym:navigator_auth/mfa/services.py#MfaServicesSlot",
    "sym:navigator_auth/mfa/services.py#get_mfa_services",
    "sym:navigator_auth/mfa/services.py#build_mfa_services",
    "sym:navigator_auth/mfa/services.py#MFA_APP_KEY",
    "sym:navigator_auth/backends/basic.py#BasicAuth.on_cleanup",
    "sym:navigator_auth/backends/basic.py#BasicAuth.on_startup"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
```python
# Atomicity of "pick services + take a lease": asyncio switches tasks only at a suspending await.
# `services = await slot.ready(app)` followed by `async with services.lease():` increments the lease
# counter before any suspension, so a concurrent swap can never close the object between the two.
async with mfa_services_lease(app) as services:
    if services is None or not services.available:
        ...  # caller fails closed (503) / not-configured path
```

### Key Constraints
- `ready()` **never raises**: log and return the current (possibly unavailable) object on any rebuild
  error. `build_mfa_services` never raises today; stay defensive anyway.
- Single-flight: re-read `self.services` and re-check the interval **after** acquiring
  `_rebuild_lock`. N concurrent callers must cause exactly one `build_mfa_services` call
  (`test_ready_single_flight`, 20 callers).
- Rebuild clock: never rebuild sooner than `AUTH_MFA_RETRY_INTERVAL` seconds after the current
  object's build time, or after the slot's last attempt. A freshly started process (or a test's
  hand-built `MfaServices(available=False)`) must NOT rebuild on its first decision point.
  `tests/test_mfa_basic_auth_hook.py:141` expects the plain 503.
- Read `auth_conf.AUTH_MFA_RETRY_INTERVAL` at call time (module attribute), so tests can monkeypatch
  `navigator_auth.conf.AUTH_MFA_RETRY_INTERVAL`.
- A rebuilt object that is still unavailable is closed and discarded. Keep the old object, so nothing
  churns.
- On a successful swap: assign `self.services = fresh` first, then `await old.retire()`. The old Redis
  pool closes only when its lease count reaches 0 (AC34). Errors from `close()` are logged at WARNING
  with the exception type only. They are never raised out of `lease()`'s exit, where they would mask
  the caller's own exception.
- `asyncio.Lock()` / `asyncio.Event()` are created in `__init__`. On Python ≥ 3.10 (venv: 3.11) they
  bind no loop at creation, so creating them while `configure()` runs before the loop is fine.
- `close()` is idempotent: a second call is a no-op.
- Log messages are secret-free (FEAT-106 log sweep).

### References in Codebase
- `navigator_auth/mfa/services.py:100-167` — `close`, slot, `get_mfa_services`, `build_mfa_services`.
- `navigator_auth/backends/basic.py:81-111` — startup build and cleanup.
- `tests/test_mfa_basic_auth_hook.py:71-90` — how tests build services and slots by hand.

---

## Implementation Blueprint

### Steps (in order)
1. Add `AUTH_MFA_RETRY_INTERVAL` to `conf.py` below `AUTH_MFA_LOCK_TIMEOUT` — *why*: `ready()` reads it.
   The two settings stay adjacent (spec Q1 defaults: 5 s and 15 s).
2. Extend the `services.py` imports — *why*: leases need `asyncio`, `time` and `asynccontextmanager`.
3. Add `permanent` plus the lease state to `MfaServices.__init__`, then add `lease()` and `retire()`
   and make `close()` idempotent — *why*: the in-flight guarantee (AC34) lives on the object that owns
   the Redis pool.
4. Flag the two permanent returns in `build_mfa_services` — *why*: AC12 says permanent
   misconfiguration is never retried.
5. Rewrite `MfaServicesSlot` with `ready()` and `close()` — *why*: spec M1's interface skeleton.
6. Add `get_ready_mfa_services` and `mfa_services_lease` below `get_mfa_services` — *why*: the
   decided caller API for every later task.
7. Switch `BasicAuth.on_cleanup` to `await slot.close()` — *why*: shutdown must drain leases before
   closing pools (spec M1).
8. Write the tests and run the Validation Commands.

### `navigator_auth/conf.py` (MODIFY)
```python
# occurrences: 0 today / 1 after TASK-171 (verify: grep -c 'AUTH_MFA_LOCK_TIMEOUT = ' navigator_auth/conf.py)
# AFTER — insert below `AUTH_MFA_LOCK_TIMEOUT = float(config.get("AUTH_MFA_LOCK_TIMEOUT", fallback=5.0))`
#         (TASK-171 adds it directly below `AUTH_OTP_EMAIL_CALLBACK = config.get("AUTH_OTP_EMAIL_CALLBACK")`,
#          verified: navigator_auth/conf.py:671, occurrences 1). If the count is 0, TASK-171 has not landed: STOP.
# Minimum seconds between two rebuild attempts of transiently unavailable MFA services (FEAT-106 review fixes, M1).
AUTH_MFA_RETRY_INTERVAL = config.getint("AUTH_MFA_RETRY_INTERVAL", fallback=15)
```
**Why**: Spec M1 skeleton and Q1 fix the default (15 s, int).

### `navigator_auth/mfa/services.py` (MODIFY — imports)
```python
# occurrences: 1 (verified: grep -c 'import logging' navigator_auth/mfa/services.py)
# BEFORE — insert above `import logging` (verified: navigator_auth/mfa/services.py:3)
import asyncio

# AFTER — insert below `import logging` (verified: navigator_auth/mfa/services.py:3)
import time

# occurrences: 1 (verified: grep -c 'from collections.abc import Mapping' navigator_auth/mfa/services.py)
# REPLACE — (verified: navigator_auth/mfa/services.py:4)
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
```

### `navigator_auth/mfa/services.py` (MODIFY — MfaServices)
```python
# occurrences: 1 (verified: grep -c 'providers: Optional[dict[str, AbstractOTPProvider]] = None,' navigator_auth/mfa/services.py)
# AFTER — insert below that parameter line (verified: navigator_auth/mfa/services.py:47)
        permanent: bool = False,

# occurrences: 1 (verified: grep -c 'self.providers = providers or {}' navigator_auth/mfa/services.py)
# AFTER — insert below that line (verified: navigator_auth/mfa/services.py:62)
        self.permanent = permanent
        self._built_at = time.monotonic()
        self._leases = 0
        self._retired = False
        self._closed = False
        self._idle = asyncio.Event()
        self._idle.set()

# occurrences: 1 (verified: grep -c 'async def close(self) -> None:' navigator_auth/mfa/services.py)
# REPLACE — MfaServices.close (verified: navigator_auth/mfa/services.py:100-103)
    @asynccontextmanager
    async def lease(self) -> AsyncIterator["MfaServices"]:
        """Hold these services for one operation; a retired object closes after its last lease."""
        self._leases += 1
        self._idle.clear()
        try:
            yield self
        finally:
            self._leases -= 1
            if self._leases == 0:
                self._idle.set()
                if self._retired:
                    await self._close_quietly()

    async def retire(self) -> None:
        """Mark these services replaced; close now if unleased, else when the last lease ends."""
        self._retired = True
        if self._leases == 0:
            await self._close_quietly()

    async def close(self) -> None:
        """Disconnect the Redis pool (idempotent)."""
        if self._closed:
            return
        self._closed = True
        if self.redis_pool is not None:
            await self.redis_pool.disconnect()

    async def _close_quietly(self) -> None:
        """Close and log (type only) instead of raising — used on lease exit and retirement."""
        try:
            await self.close()
        except Exception as err:  # pylint: disable=W0703
            logger.warning("MFA: error closing retired services: %s", type(err).__name__)
```
**Why**: The lease counter and the `_idle` event let the slot (and shutdown) wait for in-flight users.
`_close_quietly` keeps a pool-close failure from replacing a caller's real exception.

### `navigator_auth/mfa/services.py` (MODIFY — slot and module API)
```python
# occurrences: 1 (verified: grep -c 'class MfaServicesSlot:' navigator_auth/mfa/services.py)
# REPLACE — the class (verified: navigator_auth/mfa/services.py:106-110)
class MfaServicesSlot:
    """Mutable holder registered on the app before it is frozen; self-heals transient failures."""

    def __init__(self, services: Optional[MfaServices] = None) -> None:
        self.services = services
        self._rebuild_lock = asyncio.Lock()
        self._last_attempt: Optional[float] = None
        self._retired: list[MfaServices] = []

    def _due(self, services: Optional[MfaServices]) -> bool:
        """Return whether ``services`` is transiently unavailable and the retry interval elapsed."""
        if services is None or services.available or services.permanent:
            return False
        last = max(services._built_at, self._last_attempt or float("-inf"))
        return time.monotonic() - last >= auth_conf.AUTH_MFA_RETRY_INTERVAL

    async def ready(self, app: Any) -> Optional[MfaServices]:
        """Return the slot's services, rebuilding them when transiently unavailable (spec M1).

        At most one rebuild per AUTH_MFA_RETRY_INTERVAL, single-flight; never raises.
        """
        if not self._due(self.services):
            return self.services
        async with self._rebuild_lock:
            current = self.services
            if not self._due(current):
                return current
            self._last_attempt = time.monotonic()
            try:
                fresh = await build_mfa_services(app, current.backend)
            except Exception as err:  # pylint: disable=W0703
                logger.error("MFA: services rebuild failed: %s", type(err).__name__)
                return current
            # FILL IN: fresh unavailable -> close it quietly, return current; available -> swap
            #          (self.services = fresh; keep `current` in self._retired until closed; await current.retire();
            #          log recovery at WARNING) and return fresh — bounded by AC12, AC34
            return current

    async def close(self) -> None:
        """Shutdown: retire every object, drain their leases (bounded), then close the pools."""
        current, self.services = self.services, None
        pending = [s for s in [current, *self._retired] if s is not None]
        self._retired = []
        # FILL IN: retire each; wait for `_idle` of the leased ones under a bounded asyncio.wait_for
        #          (decide the bound — e.g. AUTH_MFA_LOCK_TIMEOUT); on timeout log and force close() — bounded by
        #          spec M1 "Shutdown drains or cancels outstanding leases before closing pools"


# occurrences: 1 (verified: grep -c 'def get_mfa_services(app: Any) -> Optional[MfaServices]:' navigator_auth/mfa/services.py)
# AFTER — insert below the unchanged get_mfa_services body (verified: navigator_auth/mfa/services.py:113-116)
async def get_ready_mfa_services(app: Any) -> Optional[MfaServices]:
    """Async, self-healing counterpart of :func:`get_mfa_services`."""
    slot = app.get(MFA_APP_KEY) if app is not None else None
    if not isinstance(slot, MfaServicesSlot):
        return None
    return await slot.ready(app)


@asynccontextmanager
async def mfa_services_lease(app: Any) -> AsyncIterator[Optional[MfaServices]]:
    """``ready()`` plus a lease held for the whole scope; yields None when MFA is not configured.

    Callers check ``services.available`` themselves and fail closed when it is False.
    """
    services = await get_ready_mfa_services(app)
    if services is None:
        yield None
        return
    async with services.lease() as leased:
        yield leased
```
**Why**: This is spec M1's skeleton plus the lease API decided at /sdd-task time. The interval check
runs before the lock, so the hot path (services available) takes no lock at all.

### `navigator_auth/mfa/services.py` (MODIFY — permanent flags)
```python
# occurrences: 3 for `return MfaServices(backend=backend, available=False)` (lines 126, 130, 149) — disambiguated by the preceding line:
# REPLACE — the return directly below
#   `logger.critical("MFA: AUTH_BASIC_2FA_ENABLED but AUTH_OTP_SECRET is unset; BasicAuth logins will be refused")` (count 1, :125)
        return MfaServices(backend=backend, available=False, permanent=True)
# REPLACE — the return directly below
#   `logger.critical("MFA: no 'authdb' pool; BasicAuth logins will be refused")` (count 1, :129)
        return MfaServices(backend=backend, available=False, permanent=True)
# The third return (:149, inside `except Exception`) stays transient: unchanged.
```

### `navigator_auth/backends/basic.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'if slot is not None and slot.services is not None:' navigator_auth/backends/basic.py)
# REPLACE — from that line through `slot.services = None` (verified: navigator_auth/backends/basic.py:106-111)
        if slot is not None:
            try:
                await slot.close()
            except Exception as ex:  # pylint: disable=W0703
                self.logger.warning(f"BasicAuth: error closing MFA services: {type(ex).__name__}")
```
**Why**: `slot.close()` sets `slot.services = None` and drains leases, including retired objects from
earlier swaps that the old direct `close()` never saw.

### `tests/test_mfa_review_fixes_services.py` (CREATE)
```python
"""FEAT-106 review fixes — self-healing MFA services with leases (M1; AC12, AC34)."""

import asyncio

import pytest

from navigator_auth.mfa import services as services_mod
from navigator_auth.mfa.services import (
    MFA_APP_KEY,
    MfaServices,
    MfaServicesSlot,
    build_mfa_services,
    get_ready_mfa_services,
    mfa_services_lease,
)


class _Redis:
    """Fake Redis pool recording disconnect()."""

    def __init__(self) -> None:
        self.closed = False

    async def disconnect(self) -> None:
        self.closed = True


def _unavailable(backend: object = None) -> MfaServices:
    return MfaServices(backend=backend or object(), available=False, redis_pool=_Redis())


@pytest.mark.asyncio
async def test_ready_rebuilds_after_interval(monkeypatch):
    """Not before the interval; after it the slot swaps and the retired pool closes (AC12)."""
    # FILL IN: interval 60 -> no build; interval 0 -> stubbed build returns available services; old _Redis.closed


@pytest.mark.asyncio
async def test_ready_rebuild_inflight(monkeypatch):
    """A lease on the old object survives the swap; its pool closes only after release (AC34)."""


@pytest.mark.asyncio
async def test_ready_single_flight(monkeypatch):
    """20 concurrent ready() calls trigger exactly one rebuild."""


@pytest.mark.asyncio
async def test_ready_permanent_not_retried(monkeypatch):
    """Missing secret / authdb -> permanent=True and build_mfa_services is never called again."""


@pytest.mark.asyncio
async def test_lease_helper_and_shutdown():
    """mfa_services_lease yields None without a slot; slot.close() drains leases then closes pools."""
```
**Why**: These are the four spec §4 M1 rows plus the decided lease/shutdown API. Stub
`build_mfa_services` with `monkeypatch.setattr(services_mod, "build_mfa_services", stub)` and the
interval with `monkeypatch.setattr("navigator_auth.conf.AUTH_MFA_RETRY_INTERVAL", 0)`.

### FILL IN checklist
- [ ] `MfaServicesSlot.ready` — discard-or-swap branch; bounded by AC12, AC34.
- [ ] `MfaServicesSlot.close` — retire, bounded drain, force close; bounded by spec M1 shutdown rule.
- [ ] `test_ready_rebuilds_after_interval` — interval gating plus swap; bounded by AC12.
- [ ] `test_ready_rebuild_inflight` — lease across the swap; bounded by AC34.
- [ ] `test_ready_single_flight` — 20 callers, one build (stub sleeps briefly and counts); bounded by AC12.
- [ ] `test_ready_permanent_not_retried` — the real `build_mfa_services` with `auth_conf.AUTH_OTP_SECRET`
      patched to None, and with no `authdb` → `permanent`; a counting stub proves no retry; bounded by AC12.
- [ ] `test_lease_helper_and_shutdown` — None without a slot; drain on close; bounded by spec M1.

---

## Acceptance Criteria

- [ ] Services built unavailable for a transient reason become available on the first decision point
      after `AUTH_MFA_RETRY_INTERVAL`, without a restart (AC12).
- [ ] Concurrent callers trigger exactly one rebuild (AC12).
- [ ] Permanent misconfiguration (no secret, no `authdb`) is `permanent=True` and is never retried (AC12).
- [ ] An in-flight request holding the old services survives a successful rebuild. The retired Redis
      pool closes only after its last lease ends (AC34).
- [ ] `BasicAuth.on_cleanup` drains leases via `slot.close()`.
- [ ] `get_mfa_services` is unchanged. Every existing `tests/test_mfa_*.py` suite that builds slots by
      hand still passes (AC21).
- [ ] No linting errors in the touched files.

---

## Validation Commands

- `pytest tests/test_mfa_review_fixes_services.py -q`
- `pytest tests/test_mfa_basic_auth_hook.py -q`

---

## Test Specification

```python
# tests/test_mfa_review_fixes_services.py — unit tests with stubbed build_mfa_services and a fake Redis pool
# (see blueprint). Optional live variant: real build_mfa_services against tests.fixtures.mfa.mfa_db with
# services_mod.setup_mfa_tables patched False -> True to reproduce "tables probe fails, then recovers" (AC12).
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the stacked feature worktree** `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa-review-fixes`
   (branch `feat-FEAT-106-basicauth-otp-2fa-review-fixes`, stacked on `feat-FEAT-106-basicauth-otp-2fa`; ships in PR #633), never on `dev`.
2. **Read the spec** at the path listed above, §3 Module 1 and §7 (single-flight risk).
3. **Check dependencies**: TASK-171 must be `"done"` in `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json`.
4. **Verify the Codebase Contract**: re-run the `grep -c` counts in the blueprint before editing.
5. **Update status** in the index → `"in-progress"`.
6. **Implement**: start from the blueprint blocks and complete every `# FILL IN:` marker.
7. **Verify**: run the Validation Commands.
8. **Commit the code**: stage only the files listed above.
9. **Close the task** with `parrot sdd task close TASK-173 basicauth-otp-2fa-review-fixes verified`.
10. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any

---

## Completion Note

Implemented by native sonnet; orchestrator ran tests (45 passed) and committed the uncommitted delivery. Merge-tier validation: 16 passed (others cached green). File fidelity checked. Closed via `parrot sdd task close`.
