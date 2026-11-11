# TASK-177: One-connection, fail-closed security_transition (M3)

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-171, TASK-173
**Assigned-to**: unassigned

---

## Context

Review findings **#4**, **#5** and **A2** (spec §1):

- today `security_transition` yields `None` when MFA services are missing or unavailable, so the
  credential change runs with no version bump, no device revocation and no audit;
- when services are available, the credential write commits on a *different* connection than the
  bump/revoke/audit, so a failure after the write leaves a half-applied change.

Goals **G4** (one transaction, one connection) and **G5** (fail closed, 503, when MFA is configured
but down).

Spec §3 **Module 3** fixes the new contract. `security_transition` always yields **one live connection
inside one transaction**:

- MFA not configured → a pooled transaction holding the same per-user advisory lock, with no MFA
  bookkeeping;
- MFA available → the user-lock connection, followed by bump, revoke and audit on that same connection,
  then commit;
- MFA configured but unavailable (after the M1 self-heal) → raise `MfaUnavailable` **before** yielding.

A body that raises `TransitionAborted` rolls back without being logged as an error.

The callers move to "write on the yielded connection" in TASK-178 (passkey), TASK-179 (password) and
TASK-180 (recovery). Until they land, the existing callers keep working, writing on their own
connection.

---

## Scope

- Add `MfaUnavailable(MfaStorageError)` to `navigator_auth/mfa/exceptions.py` and export it in `__all__`.
- Add `TransitionAborted(reason)` (attribute `.reason`) to `navigator_auth/mfa/events.py`.
- Rewrite `security_transition` per spec §3 M3. It holds `mfa_services_lease(app)` for the whole scope
  and uses `advisory_user_lock(app["authdb"], user_id)` when MFA is not configured.
- Raise `MfaStorageError` when there are no services and no `app["authdb"]`. The function can no
  longer yield `None`.
- Update `tests/test_mfa_security_transitions.py` for the intended behaviour change: patch target
  `mfa_services_lease`, and the old "no-op without services" test now expects `MfaStorageError` when
  there is no `authdb`. Docstrings must say so (AC21).
- Append the M3 tests to `tests/test_mfa_review_fixes_transitions.py` (created by TASK-171).

**NOT in scope**:
- Changing any caller (`handlers/users/session.py`, `handlers/recovery/handler.py`,
  `backends/passkey.py`): TASK-178, TASK-179 and TASK-180.
- HTTP mapping of `MfaUnavailable` → 503 `mfa_unavailable` (done by the callers).
- Generation increments or session revocation inside transitions (TASK-179, TASK-180).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/events.py` | MODIFY | `TransitionAborted`; one-connection `security_transition` |
| `navigator_auth/mfa/exceptions.py` | MODIFY | `MfaUnavailable(MfaStorageError)` |
| `tests/test_mfa_review_fixes_transitions.py` | MODIFY | M3 tests (fail closed, not-configured tx, abort rollback, one connection) |
| `tests/test_mfa_security_transitions.py` | MODIFY | patch `mfa_services_lease`; updated no-services test |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `0b80d88` (branch `feat-FEAT-106-basicauth-otp-2fa`, worktree
> `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa`). The code is identical to the spec's `3f14b3c`.

### Verified Imports
```python
from navigator_auth.mfa.types import MfaAuditEntry                         # verified: navigator_auth/mfa/events.py:8
from navigator_auth.mfa.exceptions import MfaStorageError                  # verified: navigator_auth/mfa/exceptions.py:8
from navigator_auth.mfa.events import SECURITY_EVENTS, security_transition # verified: tests/test_mfa_security_transitions.py:5
from navigator_auth.mfa.security import MfaSecurity                        # verified: tests/test_mfa_security_core.py:10
from navigator_auth.mfa.services import MFA_APP_KEY, MfaServices, MfaServicesSlot  # verified: tests/test_mfa_verify.py:17
from navigator_auth.mfa.trusted_devices import TrustedDeviceStore          # verified: navigator_auth/mfa/trusted_devices.py:32
from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE           # verified: tests/fixtures/mfa.py:11
from tests.fixtures.mfa import mfa_db, mfa_secret, mfa_user_factory  # noqa: F401  — verified: tests/test_mfa_security_core.py:12

# Created by dependencies (fixed signatures from the /sdd-task plan):
from navigator_auth.mfa.security import LOCK_CONNECTION, advisory_user_lock     # TASK-171
from navigator_auth.mfa.services import mfa_services_lease                      # TASK-173
from tests.fixtures.mfa import single_connection_authdb  # noqa: F401           # TASK-171
```

### Existing Signatures to Use
```python
# navigator_auth/mfa/events.py
from navigator_auth.mfa.services import get_mfa_services                  # line 7 (to be replaced)
SECURITY_EVENTS = frozenset({...6 events...})                              # line 12
@asynccontextmanager
async def security_transition(app, user_id, event, *, actor_user_id=None, revoke_devices=True,
                              detail=None, request_id=None) -> AsyncIterator[Optional[Any]]   # lines 24-89

# navigator_auth/mfa/security.py
class MfaSecurity:                                                        # line 43
    async def user_lock(self, user_id: int) -> AsyncIterator[Any]        # line 55 (after TASK-171: delegates to advisory_user_lock)
    async def current_version(self, conn: Any, user_id: int) -> int      # line 78
    async def bump_version(self, conn: Any, user_id: int) -> int         # line 94
    async def write_audit(self, conn: Any, entry: MfaAuditEntry) -> None # line 110 — INSERT {schema}.user_mfa_audit ... RETURNING id

# navigator_auth/mfa/trusted_devices.py
class TrustedDeviceStore:
    async def revoke_all(self, user_id, reason, *, conn=None) -> int     # line 126

# navigator_auth/mfa/exceptions.py
__all__ = ("MfaSignal", "MFARequired", "MFARefused", "MfaStorageError")   # line 5
class MfaStorageError(Exception):                                          # line 8

# Created by dependencies:
# TASK-171  advisory_user_lock(db_pool, user_id, *, timeout=None) -> async CM yielding ONE conn in ONE tx (MfaStorageError on timeout)
# TASK-173  mfa_services_lease(app) -> async CM yielding Optional[MfaServices] (None when no slot); lease held for the scope
```

### Does NOT Exist
- ~~`MfaUnavailable`~~, ~~`TransitionAborted`~~ — created by THIS task.
- ~~`security_transition` yielding `None`~~ — removed by this task. No caller may rely on it after this.
- ~~`get_mfa_services` inside `events.py`~~ after this task — the import is replaced by `mfa_services_lease`.
  Tests that monkeypatched `navigator_auth.mfa.events.get_mfa_services` must patch
  `navigator_auth.mfa.events.mfa_services_lease`.
- ~~`increment_generation`~~ / ~~`SessionRevoker` strict mode~~ — TASK-175 / TASK-176, not used here.
- ~~a `conn=` argument on `security_transition`~~ — the transition owns its connection. Callers receive it
  from `async with ... as conn`.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/mfa/events.py", "action": "MODIFY"},
    {"path": "navigator_auth/mfa/exceptions.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_review_fixes_transitions.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_security_transitions.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/mfa/events.py#security_transition",
    "sym:navigator_auth/mfa/events.py#SECURITY_EVENTS",
    "sym:navigator_auth/mfa/exceptions.py#MfaStorageError",
    "sym:navigator_auth/mfa/security.py#MfaSecurity.user_lock",
    "sym:navigator_auth/mfa/security.py#MfaSecurity.bump_version",
    "sym:navigator_auth/mfa/security.py#MfaSecurity.write_audit",
    "sym:navigator_auth/mfa/security.py#MfaSecurity.current_version",
    "sym:navigator_auth/mfa/trusted_devices.py#TrustedDeviceStore.revoke_all",
    "sym:navigator_auth/mfa/types.py#MfaAuditEntry"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
```python
# Callers after TASK-178/179/180 (for orientation only — not edited here):
async with security_transition(request.app, uid, "password_change", actor_user_id=uid) as conn:
    User.Meta.connection = conn
    ...  # write the credential on `conn`; never acquire another connection
```

### Key Constraints
- Order on the MFA path is unchanged: body, then `bump_version`, then `revoke_all` (when
  `revoke_devices`), then `write_audit`, then commit. All of it runs on the lock connection, inside the
  `user_lock` scope, so any failure rolls everything back.
- `MfaUnavailable` is raised **before** the body runs. Assert that the body never executed.
- `TransitionAborted` → log at **INFO** with the event, user id and `exc.reason` (a short code such as
  `credentials_changed`, never a secret), then re-raise. Any other exception → log at ERROR with the
  exception type name only, then re-raise.
- The lease (`mfa_services_lease`) wraps the whole scope, including the bookkeeping. A concurrent M1
  swap must not close the Redis pool this transition uses (AC34).
- No services and no `app["authdb"]` → `MfaStorageError("security transition requires app['authdb']")`.
  Callers map `MfaStorageError` (which `MfaUnavailable` subclasses) to 503 `mfa_unavailable`.
- Inside an `@asynccontextmanager`, an exception thrown at `yield` propagates through the enclosing
  `async with user_lock(...)` / `advisory_user_lock(...)`, which roll back. Do not add manual
  `__aenter__`/`__aexit__` plumbing. The current file's manual plumbing is what this task removes.
- Interim state, until TASK-178/179/180 land: current callers ignore the yielded connection and write
  on their own pooled connection. With MFA off they now also hold the transition's lock connection, so
  each takes two connections at once. That is acceptable on a normal-sized pool and is fixed by those
  tasks. Run `pytest tests/test_password_recovery.py -q` and `pytest tests/test_mfa_e2e.py -q` once as a
  regression check before committing (they are not this task's validation commands).

### References in Codebase
- `navigator_auth/mfa/events.py:24-89` — the transition being rewritten.
- `tests/test_mfa_security_transitions.py:25-117` — the fake lock/services harness to keep.
- `tests/test_mfa_security_core.py:178-233` — how audit rows are asserted on a live DB.

---

## Implementation Blueprint

### Steps (in order)
1. Add `MfaUnavailable` to `exceptions.py` — *why*: `events.py` raises it, and later tasks map it to 503.
2. Replace the `get_mfa_services` import in `events.py` and add `TransitionAborted` — *why*: the
   transition must hold a lease for its whole scope (TASK-173 API).
3. Rewrite `security_transition` per the blueprint — *why*: spec §3 M3. One connection, one
   transaction, fail closed.
4. Update `tests/test_mfa_security_transitions.py` (patch target, no-services test) — *why*: these
   are intended behaviour changes (AC21 says the docstrings must say so).
5. Append the M3 tests to `tests/test_mfa_review_fixes_transitions.py` and run the Validation
   Commands.

### `navigator_auth/mfa/exceptions.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '__all__ = ("MfaSignal", "MFARequired", "MFARefused", "MfaStorageError")' navigator_auth/mfa/exceptions.py)
# REPLACE — (verified: navigator_auth/mfa/exceptions.py:5)
__all__ = ("MfaSignal", "MFARequired", "MFARefused", "MfaStorageError", "MfaUnavailable")

# occurrences: 1 (verified: grep -c 'class MfaStorageError(Exception):' navigator_auth/mfa/exceptions.py)
# AFTER — append below the MfaStorageError class body (verified: navigator_auth/mfa/exceptions.py:8-9, end of file)


class MfaUnavailable(MfaStorageError):
    """2FA is enabled but the MFA services are unavailable; callers answer 503 mfa_unavailable."""
```

### `navigator_auth/mfa/events.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'from navigator_auth.mfa.services import get_mfa_services' navigator_auth/mfa/events.py)
# REPLACE — that import (verified: navigator_auth/mfa/events.py:7); keep `from navigator_auth.mfa.types import MfaAuditEntry` (:8)
from navigator_auth.mfa.exceptions import MfaStorageError, MfaUnavailable
from navigator_auth.mfa.security import advisory_user_lock
from navigator_auth.mfa.services import mfa_services_lease

# occurrences: 1 (verified: grep -c 'async def security_transition(' navigator_auth/mfa/events.py)
# REPLACE — from the `@asynccontextmanager` above it through the end of file (verified: navigator_auth/mfa/events.py:24-89)
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
    """Yield ONE live connection inside ONE transaction for a credential change.

    - No MFA services (2FA off / no BasicAuth slot): a pooled ``app["authdb"]`` transaction holding the
      same per-user advisory lock; no bump or audit; commit on clean exit.
    - Services unavailable: raise ``MfaUnavailable`` BEFORE yielding.
    - Otherwise: the ``user_lock`` connection; after the body, ``bump_version``, ``revoke_all`` (when
      ``revoke_devices``) and ``write_audit`` on that connection, then commit.

    The body MUST write the credential on the yielded connection and MUST NOT acquire another. Any
    exception from the body (``TransitionAborted`` included) rolls back and is re-raised.

    Raises:
        ValueError: unknown ``event``.
        MfaUnavailable: 2FA configured but its services are unavailable.
        MfaStorageError: no ``authdb`` pool, lock timeout, or a bookkeeping/commit failure.
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
    """Log a rolled-back transition: INFO for TransitionAborted, ERROR (type name only) otherwise."""
    # FILL IN: TransitionAborted -> logger.info("... aborted: event=%s user_id=%s reason=%s", ..., exc.reason);
    #          else logger.error("... failed: event=%s user_id=%s error=%s", ..., type(exc).__name__)
    #          — bounded by spec §3 M3 "rolls back without being logged as an error"; no secrets in logs
```
**Why this shape**: Spec M3's three branches map one-to-one onto the code. Rollback comes from the
lock context managers that own the transaction (TASK-171), so the old manual
`__aenter__`/`__aexit__` choreography disappears. The audit entry fields are copied unchanged from
today's code (events.py:62-74). The spec's fault-injection tests rely on the exact order:
bump → revoke → audit.

### `tests/test_mfa_security_transitions.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'import pytest' tests/test_mfa_security_transitions.py — exact line)
# BEFORE — insert above `import pytest` (verified: tests/test_mfa_security_transitions.py:3)
from contextlib import asynccontextmanager

# and below `from navigator_auth.mfa.events import SECURITY_EVENTS, security_transition` (count 1, :5):
from navigator_auth.mfa.exceptions import MfaStorageError

# occurrences: 1 (verified: grep -c 'async def test_security_transition_is_noop_without_services():' tests/test_mfa_security_transitions.py)
# REPLACE — that test (verified: tests/test_mfa_security_transitions.py:8-14, decorator at :8)
@pytest.mark.asyncio
async def test_security_transition_without_services_requires_authdb():
    """Behaviour change (FEAT-106 review fixes, M3): with no MFA services the transition no longer yields
    None — it takes a pooled advisory-locked transaction on app["authdb"], and fails closed without one."""
    ran = []
    with pytest.raises(MfaStorageError):
        async with security_transition({}, 42, "password_change"):
            ran.append(True)
    assert ran == []

# occurrences: 1 (verified: grep -c 'monkeypatch.setattr("navigator_auth.mfa.events.get_mfa_services", lambda app: services)' tests/test_mfa_security_transitions.py)
# REPLACE — that line (verified: tests/test_mfa_security_transitions.py:64)
    @asynccontextmanager
    async def _lease(app):
        yield services

    # M3: the transition now holds a services lease instead of reading get_mfa_services.
    monkeypatch.setattr("navigator_auth.mfa.events.mfa_services_lease", _lease)
```
**Why**: The four fake-lock tests keep their assertions unchanged (`calls`, `exits`). Only the patch
point moves.

### `tests/test_mfa_review_fixes_transitions.py` (MODIFY — append)
```python
# APPEND at end of file (module created by TASK-171); extend its imports with:
from contextlib import asynccontextmanager

from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE
from navigator_auth.mfa.events import TransitionAborted, security_transition
from navigator_auth.mfa.exceptions import MfaUnavailable
from navigator_auth.mfa.services import MFA_APP_KEY, MfaServices, MfaServicesSlot
from navigator_auth.mfa.trusted_devices import TrustedDeviceStore


def _app_with_services(pool, secret: bytes) -> dict:
    """App mapping with live MFA bookkeeping on ``pool`` (available, not permanent)."""
    services = MfaServices(
        backend=None, available=True, db_pool=pool, secret=secret,
        security=MfaSecurity(pool, secret), trusted_devices=TrustedDeviceStore(pool),
    )
    return {"authdb": pool, MFA_APP_KEY: MfaServicesSlot(services)}


@pytest.mark.asyncio
async def test_transition_unavailable_fails_closed():
    """2FA on + unavailable -> MfaUnavailable before the body runs (AC13 at transition level)."""
    # FILL IN: {MFA_APP_KEY: MfaServicesSlot(MfaServices(backend=None, available=False))} -> raises, body flag False


@pytest.mark.asyncio
async def test_transition_not_configured_yields_tx(mfa_db, mfa_user_factory):
    """No slot -> one advisory-locked transaction on authdb; LOCK_CONNECTION is the yielded conn;
    a body exception rolls the write back."""
    # FILL IN: update first_name via conn.fetchval(... RETURNING 1) then raise RuntimeError -> unchanged after


@pytest.mark.asyncio
async def test_transition_aborted_rolls_back(mfa_db, mfa_user_factory, mfa_secret):
    """TransitionAborted -> no bump, no audit row, no write (spec §4 M3)."""
    # FILL IN: _app_with_services(mfa_db, mfa_secret); write then raise TransitionAborted("credentials_changed");
    #          current_version stays 0; no user_mfa_audit row for target_user_id; write rolled back


@pytest.mark.asyncio
async def test_transition_commits_write_with_bookkeeping(single_connection_authdb, mfa_user_factory, mfa_secret):
    """Success on a ONE-connection pool: write + bump + audit commit together; no nested acquire (AC10, AC14 base)."""
    # FILL IN: asyncio.wait_for(..., 10); version == 1; one audit row; write visible;
    #          single_connection_authdb.acquires_inside_lock == []
```
**Why**: These are the three spec §4 M3 unit rows plus the one-connection proof that the downstream
call-site tasks build on.

### FILL IN checklist
- [ ] `events.py::_log_failure` — INFO for `TransitionAborted`, ERROR for everything else; bounded by spec §3 M3.
- [ ] `test_transition_unavailable_fails_closed` — the body never runs; bounded by AC13.
- [ ] `test_transition_not_configured_yields_tx` — lock publication and rollback; bounded by spec §3 M3.
- [ ] `test_transition_aborted_rolls_back` — no bump, no audit, no write; bounded by spec §4 M3 row.
- [ ] `test_transition_commits_write_with_bookkeeping` — one connection, 10 s bound; bounded by AC10 and AC14.

---

## Acceptance Criteria

- [ ] `security_transition` never yields `None`. It always yields one connection inside one transaction.
- [ ] 2FA configured but unavailable → `MfaUnavailable` before the body runs (AC13, transition level).
- [ ] No services → advisory-locked pooled transaction (same lock namespace as `user_lock`), no
      bookkeeping. No `authdb` → `MfaStorageError`.
- [ ] On the MFA path, a body write, the bump, the device revocation and the audit commit or roll back
      together on one connection (G4).
- [ ] `TransitionAborted` rolls back and is logged at INFO, not ERROR.
- [ ] `tests/test_mfa_security_transitions.py` passes with the updated patch target. The changed test's
      docstring states the behaviour change (AC21).
- [ ] No linting errors in the touched files.

---

## Validation Commands

- `pytest tests/test_mfa_review_fixes_transitions.py -q`
- `pytest tests/test_mfa_security_transitions.py -q`

---

## Test Specification

```python
# tests/test_mfa_security_transitions.py — fake-lock unit harness (no DB), patch target moved to mfa_services_lease.
# tests/test_mfa_review_fixes_transitions.py — live Postgres (skips when down):
#   unavailable -> MfaUnavailable; not configured -> locked tx + rollback; TransitionAborted -> nothing persisted;
#   success on single_connection_authdb -> committed together, acquires_inside_lock == [].
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the stacked feature worktree** `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa-review-fixes`
   (branch `feat-FEAT-106-basicauth-otp-2fa-review-fixes`, stacked on `feat-FEAT-106-basicauth-otp-2fa`; ships in PR #633), never on `dev`.
2. **Read the spec** at the path listed above, §3 Module 3 and §7 (D6).
3. **Check dependencies**: TASK-171 and TASK-173 must be `"done"` in
   `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json`.
4. **Verify the Codebase Contract**: re-run the `grep -c` counts. Confirm that `advisory_user_lock`
   (TASK-171) and `mfa_services_lease` (TASK-173) exist with the listed signatures.
5. **Update status** in the index → `"in-progress"`.
6. **Implement**: start from the blueprint blocks and complete every `# FILL IN:` marker.
7. **Verify**: run the Validation Commands and the one-off regression check from Key Constraints.
8. **Commit the code**: stage only the files listed above.
9. **Close the task** with `parrot sdd task close TASK-177 basicauth-otp-2fa-review-fixes verified`.
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

Implemented by seat gpt-5.6-terra (codex), 1 attempt. Merge-tier validation (chunk 5): 83 passed, 1 skipped. File fidelity checked. Closed via `parrot sdd task close`.
