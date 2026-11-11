# TASK-178: Passkey register/remove write on the transition connection

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-172, TASK-177
**Assigned-to**: unassigned

---

## Context

Review finding **A2** (spec §1): `PasskeyAuth.register_verify` and `PasskeyAuth.delete_credential` run
`PasskeyStore.save_credential` / `delete_credential` on **their own pooled connection** inside
`security_transition`, so the credential write commits independently of the MFA bookkeeping (version bump,
audit). A failure after the write leaves a stored/removed passkey without its audit row; the nested acquire
also feeds the pool deadlock of finding #3.

This task implements spec §3 **Module 4** for the passkey call sites (`passkey.py:320` register,
`passkey.py:569` remove): the credential write moves onto the connection the transition yields, so
credential change + bump + revoke + audit commit or roll back together (G4, AC16). It also switches the
remove guard from `get_mfa_services` to the leased, self-healing `mfa_services_lease` (spec M1 "every MFA
decision point") and maps `MfaUnavailable` / any `MfaStorageError` to 503 `mfa_unavailable` (AC13, AC11).

---

## Scope

- In `register_verify`: enter `security_transition(...) as conn` and call
  `self._store.save_credential(stored, conn=conn)`; map `MfaStorageError` (incl. `MfaUnavailable`) to 503
  `mfa_unavailable` before the generic `except Exception` → 500 branch.
- In `delete_credential` (the HTTP handler at `passkey.py:559`):
  - hold `async with mfa_services_lease(request.app) as services:` for the guard, the transition and the
    downgrade notification;
  - inside the transition, run the strong-factor guard and `self._store.delete_credential(..., conn=conn)`
    on the yielded connection; raise `TransitionAborted(<reason>)` (not `web.HTTPConflict`) inside the body
    so the rollback is logged at INFO, and map the reason to 409/404 after the `async with`;
  - delete the `if conn is None:` 503 branch (the transition now always yields a connection or raises
    `MfaUnavailable` before yielding — TASK-177);
  - map `MfaStorageError` (incl. `MfaUnavailable`, lock timeout, audit/commit failure) to 503
    `mfa_unavailable`.
- Replace the `get_mfa_services` import with `mfa_services_lease`.
- Add tests to `tests/test_mfa_security_transitions.py`: `test_passkey_transition_atomic` (AC16, both
  register and remove), MfaUnavailable → 503 for both endpoints (AC13), and the AC10 single-connection
  assertion for register and remove.

**NOT in scope**: `PasskeyStore` itself (`conn=` parameters are TASK-172); `security_transition` internals
(TASK-177); `_mfa_strong_factor_guard` / `_has_other_login_method` / `_notify_if_downgraded` bodies (they run
outside the lock on their own pooled connections, which is allowed — G3 only forbids acquires *inside* a
lock scope); password/recovery call sites (TASK-179, TASK-180).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/passkey.py` | MODIFY | Register/remove write on the transition connection; lease; 503 mapping |
| `tests/test_mfa_security_transitions.py` | MODIFY | AC16 atomicity, AC13 503, AC10 single-connection tests for passkey |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `0b80d88` (branch feat-FEAT-106-basicauth-otp-2fa). Line numbers are from that tree.

### Verified Imports
```python
import json                                                    # verified: navigator_auth/backends/passkey.py:10
from aiohttp import web                                        # already imported in passkey.py (used as web.HTTPConflict)
from ..mfa.events import security_transition                   # verified: navigator_auth/backends/passkey.py:35
from ..mfa.exceptions import MfaStorageError                   # verified: navigator_auth/backends/passkey.py:36
from ..mfa.services import get_mfa_services                    # verified: navigator_auth/backends/passkey.py:38 — REPLACED by this task
# Created by dependency tasks (fixed signatures from the decomposition plan):
from ..mfa.services import mfa_services_lease                  # created by TASK-173 (dependency of TASK-177)
from ..mfa.events import TransitionAborted                     # created by TASK-177 (dependency)
from ..mfa.exceptions import MfaUnavailable                    # created by TASK-177 (dependency)
```

### Existing Signatures to Use
```python
# navigator_auth/backends/passkey.py
class PasskeyAuth(BasicAuth):                                                    # line 70
    async def register_verify(self, request: web.Request) -> web.Response:      # line 268
    #   security_transition(... "passkey_registered", ..., revoke_devices=False) at 320-322
    #   await self._store.save_credential(stored)                                 line 323
    #   except web.HTTPException: raise / except Exception -> AuthException(500)  lines 324-329
    async def delete_credential(self, request: web.Request) -> web.Response:    # line 559 (@_json_errors)
    #   services = get_mfa_services(request.app)                                  line 567
    #   record, guard_strong = await self._mfa_strong_factor_guard(services, user.user_id)  line 568
    #   async with security_transition(... "passkey_removed" ...) as conn:       lines 569-571
    #   if conn is None: raise web.HTTPServiceUnavailable(...)                    lines 573-577 (REMOVE)
    async def _has_other_login_method(self, user_id: int) -> bool:              # line 599 (own pooled conns)
    async def _mfa_strong_factor_guard(self, services: Any, user_id: int) -> tuple[Any, bool]:  # line 617
    #   services None -> (None, False); not available -> 503 mfa_unavailable; MfaStorageError -> 503
    async def _notify_if_downgraded(self, services: Any, record: Any) -> None:  # line 637

# navigator_auth/mfa/state.py
class MfaStateMachine:                                                           # line 78
    async def totp_confirmed(self, user_id: int, *, conn: Any = None) -> bool:  # line 85
    async def passkey_count(self, user_id: int, *, conn: Any = None) -> int:    # line 99

# navigator_auth/passkey/store.py (TASK-172 adds conn=; today's lines)
class PasskeyStore:                                                              # line 17
    async def save_credential(self, credential: StoredCredential) -> None:       # line 66 -> (credential, *, conn=None) after TASK-172
    async def delete_credential(self, user_id: int, credential_id: bytes, *, keep_last: bool = False) -> bool:  # line 110 -> + conn=None after TASK-172

# navigator_auth/mfa/events.py (after TASK-177 — fixed contract)
@asynccontextmanager
async def security_transition(app, user_id, event, *, actor_user_id=None, revoke_devices=True,
                              detail=None, request_id=None) -> AsyncIterator[Any]:
    # ALWAYS yields ONE live connection in ONE transaction; services unavailable -> MfaUnavailable BEFORE yield;
    # body exception (TransitionAborted included) -> rollback + re-raise; TransitionAborted logged at INFO.
class TransitionAborted(Exception):
    reason: str   # TransitionAborted(reason: str)

# navigator_auth/mfa/services.py (after TASK-173 — fixed contract)
@asynccontextmanager
async def mfa_services_lease(app: Any) -> AsyncIterator[Optional[MfaServices]]  # yields None when no slot/services
```

### Does NOT Exist
- ~~`conn is None` from `security_transition`~~ — after TASK-177 the transition never yields `None`; the 503 branch at `passkey.py:573-577` is dead and must be removed.
- ~~`PasskeyStore.save_credential(..., conn=)`~~ / ~~`delete_credential(..., conn=)`~~ on today's tree — added by TASK-172 (dependency). Do NOT edit `navigator_auth/passkey/store.py` in this task.
- ~~`MfaUnavailable`~~, ~~`TransitionAborted`~~ — created by TASK-177; ~~`mfa_services_lease`~~ — created by TASK-173.
- ~~`PasskeyBackend`~~ — the class is `PasskeyAuth` (`passkey.py:70`).
- ~~`navigator_auth/handlers/auth.py`~~ — does not exist (spec M4 path list drift); irrelevant here.
- ~~`_mfa_strong_factor_guard(..., conn=)`~~ — no conn parameter; it runs pre-lock on its own connections (allowed).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {
      "path": "navigator_auth/backends/passkey.py",
      "action": "MODIFY"
    },
    {
      "path": "tests/test_mfa_security_transitions.py",
      "action": "MODIFY"
    }
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/passkey.py#PasskeyAuth.register_verify",
    "sym:navigator_auth/backends/passkey.py#PasskeyAuth.delete_credential",
    "sym:navigator_auth/backends/passkey.py#PasskeyAuth._has_other_login_method",
    "sym:navigator_auth/backends/passkey.py#PasskeyAuth._mfa_strong_factor_guard",
    "sym:navigator_auth/backends/passkey.py#PasskeyAuth._notify_if_downgraded",
    "sym:navigator_auth/mfa/state.py#MfaStateMachine.totp_confirmed",
    "sym:navigator_auth/mfa/state.py#MfaStateMachine.passkey_count",
    "sym:navigator_auth/passkey/store.py#PasskeyStore.save_credential",
    "sym:navigator_auth/passkey/store.py#PasskeyStore.delete_credential",
    "sym:navigator_auth/mfa/events.py#security_transition"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
```python
# The transition body writes ONLY on the yielded connection (spec §3 M3 docstring):
async with security_transition(request.app, user_id, "passkey_removed", actor_user_id=user_id) as conn:
    ...                                   # guard reads on conn
    await self._store.delete_credential(user_id, credential_id, keep_last=guard_last, conn=conn)
```

### Key Constraints
- **No pool acquire inside the transition** (G3, AC10): inside the `async with security_transition(...)` body
  call only `conn=`-taking methods. `_has_other_login_method`, `_mfa_strong_factor_guard`,
  `self._store.get_credential`, `self._store.list_credentials` and `_notify_if_downgraded` stay OUTSIDE the
  body (before / after), exactly as today.
- Keep the 503 JSON shape already used in this file:
  `web.HTTPServiceUnavailable(text=json.dumps({"error": "mfa_unavailable", "reason": "Passkey: MFA storage unavailable"}), content_type="application/json")`.
- Keep the existing 409 bodies verbatim (`strong_factor_required` JSON for the strong-factor guard; reason text
  `"Passkey: cannot delete the last login method"` for the last-login-method guard) and the 404 reason.
- asyncdb `conn.execute` swallows DB errors (project memory `asyncdb-execute-never-raises`).
  `PasskeyStore.save_credential` uses `conn.execute` today; after TASK-172 confirm it fails closed (raises)
  when the INSERT fails on the caller's connection. If it still swallows the error, do NOT edit `store.py`
  here (TASK-172 owns it) — record it in the Completion Note as a blocker for AC16 and stop.
- Never log credential ids or raw keys; keep log lines as they are (`type(err).__name__` only).
- Google docstrings + type hints; `self.logger`, never `print`.

### References in Codebase
- `navigator_auth/backends/passkey.py:617-635` — the 503 mapping pattern for `MfaStorageError`.
- `tests/test_mfa_security_transitions.py:42-65` — fake-services pattern (TASK-177 updates it for the lease).
- `tests/fixtures/mfa.py` — `mfa_db`, `mfa_user_factory`, and (TASK-171) `single_connection_authdb`.
- `tests/fixtures/passkey.py` / `tests/test_passkey_management.py` — live passkey app fixture (`passkey_app`, `soft_authenticator`).

---

## Implementation Blueprint

> **CRITICAL — Executor-ready starting point.** Write each block below to its declared
> path nearly verbatim, then complete every `# FILL IN:` marker. Blocks were derived
> from the spec's Interface Skeletons and re-verified against the Codebase Contract
> above when this task was written. This is NOT the full implementation:
> business-logic branches, edge cases and test bodies are `FILL IN` stubs by design.
> Never change a signature, class name, or file path the blueprint fixes.

### Steps (in order)
1. Confirm TASK-172/173/177 are merged in the worktree (`grep -n "conn: Any = None" navigator_auth/passkey/store.py`, `grep -n "def mfa_services_lease" navigator_auth/mfa/services.py`, `grep -n "class TransitionAborted" navigator_auth/mfa/events.py`) — *why*: every block below calls their symbols.
2. Replace the imports (block 1) — *why*: `get_mfa_services` is the non-healing raw accessor; the spec requires a leased, self-healing one at every decision point.
3. Rewrite the register write (block 2) — *why*: the INSERT must commit in the transition's transaction (AC16 register half).
4. Rewrite `delete_credential` (block 3) — *why*: the guard and the DELETE must run on the lock connection, and 409/404 refusals must roll back without being logged as errors.
5. Add the tests (block 4) and run the Validation Commands — *why*: AC16/AC13/AC10 are only proven by fault injection and the single-connection pool.

### `navigator_auth/backends/passkey.py` (MODIFY) — block 1: imports
```python
# occurrences: 1 (verified: grep -c 'from ..mfa.exceptions import MfaStorageError' navigator_auth/backends/passkey.py)
# occurrences: 1 (verified: grep -c 'from ..mfa.services import get_mfa_services' navigator_auth/backends/passkey.py)
# REPLACE — lines 35-38 (verified: navigator_auth/backends/passkey.py:35-38)
from ..mfa.events import TransitionAborted, security_transition
from ..mfa.exceptions import MfaStorageError, MfaUnavailable
from ..mfa.notify import notify_security_event
from ..mfa.services import mfa_services_lease
```
**Why**: `MfaUnavailable` is a subclass of `MfaStorageError`; it is imported for readability of the
`except` clauses and the tests. `get_mfa_services` has no other use in this file (verified: 1 occurrence) —
remove it so no decision point can bypass the lease.

### `navigator_auth/backends/passkey.py` (MODIFY) — block 2: register write
```python
# occurrences: 1 (verified: grep -c 'await self._store.save_credential(stored)' navigator_auth/backends/passkey.py)
# occurrences of 'async with security_transition(': 2 (lines 320, 569) — disambiguated by the next line
#   'request.app, user.user_id, "passkey_registered", actor_user_id=user.user_id, revoke_devices=False' (1 occurrence, line 321)
# REPLACE — lines 317-329 (verified: navigator_auth/backends/passkey.py:317-329)
        try:
            if await self._store.get_credential(stored.credential_id) is not None:
                raise web.HTTPConflict(reason="Passkey: credential already registered")
            async with security_transition(
                request.app, user.user_id, "passkey_registered", actor_user_id=user.user_id, revoke_devices=False
            ) as conn:
                await self._store.save_credential(stored, conn=conn)
        except web.HTTPException:
            raise
        except MfaStorageError as err:
            # MfaUnavailable (2FA on, services down), lock timeout (AC11), bump/audit/commit failure (AC16).
            self.logger.warning(f"Passkey: registration transition failed for user {user.user_id}: {type(err).__name__}")
            raise web.HTTPServiceUnavailable(
                text=json.dumps({"error": "mfa_unavailable", "reason": "Passkey: MFA storage unavailable"}),
                content_type="application/json",
            ) from err
        except Exception as err:  # pylint: disable=W0703
            if "unique" in type(err).__name__.lower() or "duplicate key" in str(err).lower():
                raise web.HTTPConflict(reason="Passkey: credential already registered") from err
            raise AuthException(f"Passkey: could not store credential: {err}", status=500) from err
```
**Why**: the `get_credential` pre-check stays OUTSIDE the transition (own pooled connection, released before
the lock is taken — G3). The `except MfaStorageError` must precede `except Exception`, otherwise a fail-closed
503 becomes a 500. Nothing else in `register_verify` changes.

### `navigator_auth/backends/passkey.py` (MODIFY) — block 3: `delete_credential` handler
```python
# occurrences: 1 (verified: grep -c 'async def delete_credential(self, request: web.Request) -> web.Response:' navigator_auth/backends/passkey.py)
# REPLACE — the whole method body, lines 558-597 (verified: navigator_auth/backends/passkey.py:558-597),
#           from '@_json_errors' above 'async def delete_credential' through 'return web.Response(status=204)'
    @_json_errors
    async def delete_credential(self, request: web.Request) -> web.Response:
        """Delete one of the caller's passkeys; 409 when it would lock the user out (E13).

        The guard and the DELETE run on the security-transition connection, so the removal
        commits or rolls back together with the MFA bump/audit (FEAT-106 review A2, AC16).
        """
        user = self._session_user(request)
        credential_id = self._credential_id(request)
        owned = await self._store.list_credentials(user.user_id)
        if credential_id not in {c.credential_id for c in owned}:
            raise web.HTTPNotFound(reason="Passkey: credential not found")
        guard_last = not await self._has_other_login_method(user.user_id)
        async with mfa_services_lease(request.app) as services:
            record, guard_strong = await self._mfa_strong_factor_guard(services, user.user_id)
            try:
                async with security_transition(
                    request.app, user.user_id, "passkey_removed", actor_user_id=user.user_id
                ) as conn:
                    if guard_strong:
                        totp = await services.state.totp_confirmed(user.user_id, conn=conn)
                        count = await services.state.passkey_count(user.user_id, conn=conn)
                        if not totp and count <= 1:
                            raise TransitionAborted("strong_factor_required")
                    # With no other login method the store deletes only if another passkey remains,
                    # atomically (two concurrent deletes cannot both succeed).
                    if not await self._store.delete_credential(
                        user.user_id, credential_id, keep_last=guard_last, conn=conn
                    ):
                        raise TransitionAborted("last_login_method" if guard_last else "not_found")
            except TransitionAborted as aborted:
                # FILL IN: map aborted.reason -> the existing responses, verbatim — bounded by AC20/E13:
                #   "strong_factor_required" -> web.HTTPConflict(text=json.dumps({"error": "strong_factor_required",
                #       "reason": "Passkey: cannot delete the last strong factor"}), content_type="application/json")
                #   "last_login_method" -> web.HTTPConflict(reason="Passkey: cannot delete the last login method")
                #   "not_found" -> web.HTTPNotFound(reason="Passkey: credential not found")
                raise
            except MfaStorageError as err:
                self.logger.warning(f"Passkey: removal transition failed for user {user.user_id}: {type(err).__name__}")
                raise web.HTTPServiceUnavailable(
                    text=json.dumps({"error": "mfa_unavailable", "reason": "Passkey: MFA storage unavailable"}),
                    content_type="application/json",
                ) from err
            await self._notify_if_downgraded(services, record)
        return web.Response(status=204)
```
**Why**: raising `TransitionAborted` inside the body rolls the transaction back and is logged at INFO
(TASK-177), whereas an `HTTPConflict` raised inside would be logged as a transition failure at ERROR. The lease
covers the guard, the transition and `_notify_if_downgraded` so the services object cannot be retired and
closed mid-request (spec M1, AC34). `services` is non-None whenever `guard_strong` is True
(`_mfa_strong_factor_guard` returns `(None, False)` for `None`). The `conn is None` branch is gone: TASK-177's
transition raises `MfaUnavailable` before yielding instead.

### `tests/test_mfa_security_transitions.py` (MODIFY) — block 4: append tests
```python
# occurrences: 1 (verified: grep -c 'def test_security_events_are_complete' tests/test_mfa_security_transitions.py)
# AFTER — append at end of file, below `def test_security_events_are_complete():` (verified: tests/test_mfa_security_transitions.py:110)
# FILL IN: imports at the top of the file — mfa_db / mfa_user_factory / single_connection_authdb from
#   tests.fixtures.mfa; PasskeyStore + StoredCredential (verified: tests/test_passkey_store.py:10-11 imports them);
#   ensure_passkey_tables (navigator_auth.passkey.migrations); MfaServicesSlot/build_mfa_services/MFA_APP_KEY
#   (navigator_auth.mfa.services); MfaUnavailable (navigator_auth.mfa.exceptions).


@pytest.mark.asyncio
async def test_passkey_transition_atomic(mfa_db, mfa_user_factory, monkeypatch):
    """AC16: an audit fault during passkey remove keeps the credential; during register nothing is stored."""
    # FILL IN: build real MFA services on app = {"authdb": mfa_db, MFA_APP_KEY: MfaServicesSlot(services)}
    #   (services = await build_mfa_services(app, backend=None) with AUTH_OTP_SECRET set via monkeypatch),
    #   monkeypatch services.security.write_audit to raise MfaStorageError; then
    #   (a) remove: seed a credential with PasskeyStore(mfa_db).save_credential(...), run
    #       `async with security_transition(app, uid, "passkey_removed") as conn:
    #            await store.delete_credential(uid, cid, conn=conn)` under pytest.raises(MfaStorageError),
    #       assert store.get_credential(cid) is not None;
    #   (b) register: same with save_credential(stored, conn=conn) -> assert get_credential(cid) is None.
    #   Bounded by AC16 + spec §4 row test_passkey_transition_atomic.
    raise NotImplementedError


@pytest.mark.asyncio
async def test_passkey_endpoints_mfa_unavailable_503(monkeypatch):
    """AC13: 2FA on + MFA unavailable -> register/remove answer 503 mfa_unavailable and change nothing."""
    # FILL IN: drive PasskeyAuth.delete_credential / register_verify (or the passkey_app routes from
    #   tests/fixtures/passkey.py) with a slot whose services have available=False and permanent=False;
    #   assert status 503 and body {"error": "mfa_unavailable", ...}; credential set unchanged. Bounded by AC13.
    raise NotImplementedError


@pytest.mark.asyncio
async def test_passkey_flows_single_connection(single_connection_authdb, mfa_user_factory):
    """AC10: passkey register and remove complete on a one-connection authdb within 10 s, no acquire under the lock."""
    # FILL IN: run the register write and the remove guard+delete through security_transition with
    #   app["authdb"] = single_connection_authdb (and MFA services built on it) under asyncio.wait_for(..., 10);
    #   assert single_connection_authdb.acquires_inside_lock == []. Bounded by AC10 / G3.
    raise NotImplementedError
```
**Why**: AC16 needs a real Postgres transaction to prove rollback (the existing `_FakeLock` yields a string,
which cannot roll anything back). Tests append to the end so they do not collide with TASK-177's edits at the
top of this file.

### FILL IN checklist
- [ ] `passkey.py::PasskeyAuth.delete_credential` — map `TransitionAborted.reason` to the existing 409/404 responses verbatim; bounded by AC20 / E13 (bodies unchanged).
- [ ] `test_mfa_security_transitions.py` imports — only fixtures/symbols verified above or created by TASK-171/172/173/177.
- [ ] `test_passkey_transition_atomic` — fault-inject `write_audit`; bounded by AC16.
- [ ] `test_passkey_endpoints_mfa_unavailable_503` — bounded by AC13.
- [ ] `test_passkey_flows_single_connection` — bounded by AC10 / G3.

---

## Acceptance Criteria

- [ ] `register_verify` calls `save_credential(stored, conn=conn)` inside `security_transition(...) as conn`; `delete_credential` (handler) calls `self._store.delete_credential(..., conn=conn)` inside it.
- [ ] No reference to `get_mfa_services` remains in `navigator_auth/backends/passkey.py`; the remove path holds `mfa_services_lease`.
- [ ] AC16 — a fault in `write_audit` during passkey remove leaves the credential present; during register the credential is not stored.
- [ ] AC13 (passkey) — 2FA on and MFA unavailable: register and remove answer 503 `mfa_unavailable` and leave credentials unchanged.
- [ ] AC10 (passkey) — register and remove complete with `authdb` capped at one connection within 10 s; no `acquire()` while `LOCK_CONNECTION` is set.
- [ ] Existing passkey suites stay green (AC21).
- [ ] No linting errors: `ruff check navigator_auth/backends/passkey.py` (if ruff is configured).

---

## Validation Commands

- `pytest tests/test_mfa_security_transitions.py -q`
- `pytest tests/test_passkey_management.py -q`
- `pytest tests/test_passkey_enrollment.py -q`

---

## Test Specification

```python
# tests/test_mfa_security_transitions.py (appended — see blueprint block 4)
@pytest.mark.asyncio
async def test_passkey_transition_atomic(mfa_db, mfa_user_factory, monkeypatch): ...      # AC16
@pytest.mark.asyncio
async def test_passkey_endpoints_mfa_unavailable_503(monkeypatch): ...                    # AC13
@pytest.mark.asyncio
async def test_passkey_flows_single_connection(single_connection_authdb, mfa_user_factory): ...  # AC10
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the stacked feature worktree** `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa-review-fixes` (branch
   `feat-FEAT-106-basicauth-otp-2fa-review-fixes`, stacked on `feat-FEAT-106-basicauth-otp-2fa`; ships in PR #633) — never on `dev`.
2. **Read the spec** at the path listed above for full context (§3 M3, M4; §5 AC10, AC13, AC16).
3. **Check dependencies** — TASK-172 and TASK-177 must be `"done"` in
   `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json`.
4. **Verify the Codebase Contract** — before writing ANY code:
   - Confirm every import in "Verified Imports" still exists (`grep` or `read` the source)
   - Confirm every class/method in "Existing Signatures" still has the listed attributes
   - If anything has changed, update the contract FIRST, then implement
   - **NEVER** reference an import, attribute, or method not in the contract without verifying it exists
5. **Update status** in `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json` → `"in-progress"`
   (set `started_at`) and commit only that index file
6. **Implement** — start from the Implementation Blueprint blocks, complete every
   `# FILL IN:` marker, and never change a signature or path the blueprint fixes
7. **Verify** all acceptance criteria are met — run the Validation Commands
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`)
9. **Close the task** with `parrot sdd task close TASK-178 basicauth-otp-2fa-review-fixes verified`
   — it moves this file to `sdd/tasks/completed/` and marks it `"done"` in the
   index; never move or copy the file by hand
10. **Fill in the Completion Note** below, then commit the staged SDD state

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any

---

## Completion Note

Implemented by seats gpt-5.6-terra x2 then gpt-5.6-luna (3 attempts; task-tier validation timed out, 0 failures). Orchestrator merged by hand after running tests: test_mfa_security_transitions 10 passed, test_mfa_review_fixes_transitions 15 passed. KNOWN ENVIRONMENT ISSUE (also on base tree): tests/test_passkey_enrollment.py and test_passkey_management.py hang, test_passkey_backend_unit has 2 pre-existing failures; the merge-tier run timed out on those. File fidelity checked. Closed via `parrot sdd task close`.
