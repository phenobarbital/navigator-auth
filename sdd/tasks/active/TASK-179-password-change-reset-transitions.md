# TASK-179: Two-phase password_change and revoking password_reset

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-175, TASK-176, TASK-177
**Assigned-to**: unassigned

---

## Context

Review findings **#3** and **#5** (spec §1): `UserSession.password_change` and `UserSession.password_reset`
acquire a pooled connection, then enter `security_transition` (which takes the MFA user-lock connection) and
write the new password through `User.update()` on the **first** connection. That is (a) a nested acquisition
that deadlocks the pool at ~`max_size` concurrent requests and (b) a credential write that commits on a
different connection from the bump/revoke/audit, so a later failure leaves the new password without its MFA
bookkeeping. Open question Q3 (spec §8) adds **G9**: an admin `password_reset` must end the target's existing
sessions and tokens.

This task implements spec §3 **Module 4** for `password_change` (`session.py:131`) and `password_reset`
(`session.py:171`): the two-phase pattern (phase 1: read + validate on a pooled connection that is released;
phase 2: re-read + compare + write on the transition connection), plus — for `password_reset` only — the OAuth
credential-generation increment and **strict** session/JTI revocation inside the same transaction (AC28).

---

## Scope

- Rewrite `password_change`:
  1. Phase 1 (pooled, released): load the user, check the old password (403 on mismatch), capture the stored hash.
  2. Phase 2: `async with security_transition(...) as conn:` re-read the hash on `conn`; drift →
     `TransitionAborted("credentials_changed")` → **409**; write the new hash on `conn` with explicit SQL.
  3. `MfaUnavailable` → **503** `mfa_unavailable`; any other `MfaStorageError` (lock timeout, audit/commit
     failure) → **503**.
- Rewrite `password_reset`:
  1. Phase 1 (pooled, released): existence check (**404**), capture the stored hash.
  2. Phase 2 on `conn`: re-read → drift → 409; write the new hash with `is_new = true`;
     `increment_generation(conn, user_id)`; `PasswordRecoveryHandler.session_revoker().revoke_user(request, user, strict=True)`
     — all before the transition commits.
  3. `MfaUnavailable`, `MfaStorageError`, `RevocationError`, `SecurityStateError` → **503**, password and
     generation unchanged (rollback).
- Extend `tests/test_mfa_review_fixes_transitions.py` with the password-flow tests listed below.

**NOT in scope**: recovery completion (TASK-180); passkey (TASK-178); `security_transition` internals
(TASK-177); OAuth token rejection by generation (TASK-185 — this task only increments the generation);
revoking other sessions on a self-service `password_change` (spec Non-Goal); `UserManager` (spec Non-Goal #11);
the pre-existing missing `return` before `self.error(...)` in the `ValidationError` branches (leave as is).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/users/session.py` | MODIFY | Two-phase `password_change` / `password_reset`; generation + strict revocation on reset |
| `tests/test_mfa_review_fixes_transitions.py` | MODIFY | AC10/AC13/AC14/AC28 + 409 drift tests for the two password flows |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `0b80d88` (branch feat-FEAT-106-basicauth-otp-2fa). Line numbers are from that tree.

### Verified Imports
```python
from ...exceptions import AuthException                     # verified: navigator_auth/handlers/users/session.py:7
from ...models import User                                  # verified: navigator_auth/handlers/users/session.py:9
from .passwd import check_password, set_basic_password      # verified: navigator_auth/handlers/users/session.py:11
from ...mfa.events import security_transition               # verified: navigator_auth/handlers/users/session.py:12
from ...conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE         # verified: navigator_auth/conf.py:33-34 (session.py already imports from ...conf at line 10)
from ...mfa.exceptions import MfaStorageError               # verified: navigator_auth/mfa/exceptions.py:8
from asyncdb.exceptions import NoDataFound                  # verified: navigator_auth/handlers/recovery/handler.py:24
import secrets                                              # stdlib (compare_digest)
# Created by dependency tasks (fixed signatures from the decomposition plan):
from ...mfa.events import TransitionAborted                 # created by TASK-177
from ...mfa.exceptions import MfaUnavailable                # created by TASK-177
from ...security_state.store import SecurityStateError, increment_generation   # created by TASK-175
from ..recovery.handler import PasswordRecoveryHandler      # exists (handler.py:115); session_revoker() added by TASK-176
from ..recovery.revoke import RevocationError               # created by TASK-176
```

### Existing Signatures to Use
```python
# navigator_auth/handlers/users/session.py
class UserSession(BaseHandler):                                      # line 15
    async def session(self, request)                                 # line 16 — returns the session or an error response
    async def password_change(self, request: web.Request):          # line 99
    #   route: POST /api/v2/user/set_password  (verified: navigator_auth/handlers/__init__.py:67)
    #   body {"password", "old_password"}; session[AUTH_SESSION_OBJECT]["user_id"]; 403 on old-password mismatch
    #   security_transition at 131-133; 202 {"action": "Password Changed", "status": "OK"}
    async def password_reset(self, request: web.Request):           # line 146
    #   route: POST /api/v2/user/password_reset/{userid}  (verified: navigator_auth/handlers/__init__.py:68)
    #   superuser-only (userinfo["superuser"]); security_transition at 171-173; sets is_new = True;
    #   202 {"action": "Password was changed successfully", "user", "username", "status": "OK"}

# navigator_auth/handlers/users/passwd.py
def set_basic_password(...)                                          # line 12 — returns the PBKDF2 hash string
def check_password(current_password, password)                      # line 28

# navigator_auth/models.py
class User(Model):                                                   # line 39; Meta.name = AUTH_USERS_TABLE, Meta.schema = AUTH_DB_SCHEMA (lines 68-70)

# navigator_auth/conf.py
AUTH_DB_SCHEMA = config.get("AUTH_DB_SCHEMA", fallback="auth")      # line 33
AUTH_USERS_TABLE = config.get("AUTH_USERS_TABLE", fallback="users") # line 34

# --- dependency contracts (fixed) ---
# navigator_auth/mfa/events.py (TASK-177): security_transition(...) ALWAYS yields ONE connection in ONE transaction;
#   MfaUnavailable before yield when 2FA is configured but down; body exception -> rollback + re-raise;
#   TransitionAborted(reason) -> rollback, logged at INFO; attribute .reason
# navigator_auth/security_state/store.py (TASK-175):
async def increment_generation(conn: Any, user_id: int) -> int      # upsert ... RETURNING generation (fetchval)
class SecurityStateError(Exception)
# navigator_auth/handlers/recovery/revoke.py (TASK-176):
class RevocationError(Exception)
class SessionRevoker:
    async def revoke_user(self, request, user, *, strict: bool = False) -> int   # strict -> raises RevocationError
# navigator_auth/handlers/recovery/handler.py (TASK-176):
class PasswordRecoveryHandler:
    @classmethod
    def session_revoker(cls) -> SessionRevoker                      # cls._ensure_resources(); return cls._revoker
```

### Does NOT Exist
- ~~`navigator_auth/handlers/auth.py`~~ — does not exist (spec M4 path list drift). Nothing in this task touches token validation.
- ~~`TransitionAborted`~~, ~~`MfaUnavailable`~~ (TASK-177), ~~`increment_generation`~~ / ~~`SecurityStateError`~~ (TASK-175), ~~`RevocationError`~~ / ~~`PasswordRecoveryHandler.session_revoker`~~ / ~~`revoke_user(..., strict=)`~~ (TASK-176) — not on today's tree; created by the dependencies.
- ~~`security_transition(...)` yielding `None`~~ — after TASK-177 it never does; do not branch on `conn is None`.
- ~~a `User.update(conn=...)` parameter~~ — asyncdb `Model.update()` only uses the class-level `User.Meta.connection`; this task does not use `Model.update()` in phase 2 at all (see Key Constraints).
- ~~`UserSession.json_error`~~ — use the existing `self.error(reason=..., status=...)` / `self.json_response(response=..., status=...)`.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {
      "path": "navigator_auth/handlers/users/session.py",
      "action": "MODIFY"
    },
    {
      "path": "tests/test_mfa_review_fixes_transitions.py",
      "action": "MODIFY"
    }
  ],
  "contract_symbols": [
    "sym:navigator_auth/handlers/users/session.py#UserSession.password_change",
    "sym:navigator_auth/handlers/users/session.py#UserSession.password_reset",
    "sym:navigator_auth/handlers/users/session.py#UserSession.session",
    "sym:navigator_auth/handlers/users/passwd.py#check_password",
    "sym:navigator_auth/handlers/users/passwd.py#set_basic_password",
    "sym:navigator_auth/models.py#User",
    "sym:navigator_auth/mfa/events.py#security_transition",
    "sym:navigator_auth/mfa/exceptions.py#MfaStorageError",
    "sym:navigator_auth/handlers/recovery/handler.py#PasswordRecoveryHandler"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
```python
# Phase 1 (pooled, released) -> Phase 2 (transition connection), spec §3 M4:
async with await db.acquire() as conn:          # released before the lock is taken
    User.Meta.connection = conn
    user = await User.get(user_id=user_id)
    captured = user.password
async with security_transition(app, user_id, event, actor_user_id=...) as conn:
    current = await conn.fetchval(f"SELECT password FROM {USERS} WHERE user_id = $1 FOR UPDATE", user_id)
    if current is None or not secrets.compare_digest(str(current), str(captured or "")):
        raise TransitionAborted("credentials_changed")
    await conn.fetchval(f"UPDATE {USERS} SET password = $2 WHERE user_id = $1 RETURNING user_id", user_id, new_hash)
```

### Key Constraints
- **Phase 2 uses explicit SQL, not `User.get`/`User.update`.** Do X — because Y:
  - asyncdb `Model.update()` has a hard-coded 2 s timeout, rewrites every column and builds its WHERE from a
    class-wide shared dict (project memory `asyncdb-model-update-pitfalls`); and `User.Meta.connection` is
    class-level shared state (spec §7 Known Risks). Reading and writing with `conn.fetchval(... RETURNING ...)`
    on the transition connection avoids both and fails closed (it raises; `conn.execute` would swallow the
    error — project memory `asyncdb-execute-never-raises`). This is the spec's "re-get, compare, update"
    contract expressed safely; record it under "Deviations from spec" in the Completion Note.
  - Phase 1 may keep `User.get` (read-only), setting `User.Meta.connection = conn` immediately before it with
    no other `await` in between.
- **No pool acquire inside the transition** (G3, AC10): inside the phase-2 body only `conn.*` calls, Redis
  calls (`revoke_user` is Redis-only) and `increment_generation(conn, ...)`.
- **Order inside `password_reset` phase 2**: re-read/compare → password UPDATE → `increment_generation` →
  strict `revoke_user` — all before the `async with` exits, so a revocation failure rolls back both DB writes
  (AC28). A partial Redis revocation before rollback is acceptable (spec M4 durable contract) but must never be
  reported as success.
- `password_change` does **not** revoke sessions and does **not** touch the generation (spec Non-Goal).
- Hash comparison: `secrets.compare_digest` on `str` values (never `==` on secrets).
- Response shapes: keep today's 202/403/404/406 bodies. New: 409 → `self.json_response(response={"error": "credentials_changed"}, status=409)`;
  503 → `self.json_response(response={"error": "mfa_unavailable"}, status=503)` for `MfaUnavailable` and any other
  `MfaStorageError`; `self.json_response(response={"error": "temporarily_unavailable"}, status=503)` for
  `RevocationError` / `SecurityStateError`. Catch these BEFORE the generic `except Exception` → `self.critical(...)` (500).
- Never log the password, hash, or token values; log `type(err).__name__` only.
- If importing `PasswordRecoveryHandler` at module level causes a circular import (`navigator_auth.handlers.users`
  is imported by `navigator_auth.handlers.__init__` before `recovery.handler`), move that one import inside
  `password_reset` and say so in the Completion Note — verify with `python -c "import navigator_auth.handlers"`.

### References in Codebase
- `navigator_auth/mfa/security.py:78-108` — `fetchval ... RETURNING` fail-closed write pattern.
- `tests/test_mfa_e2e.py:615` (`test_password_change_revokes_trusted_devices`) — live call of `/api/v2/user/set_password`.
- `tests/fixtures/mfa.py` — `mfa_db`, `mfa_user_factory`; `single_connection_authdb` (TASK-171).

---

## Implementation Blueprint

> **CRITICAL — Executor-ready starting point.** Write each block below to its declared
> path nearly verbatim, then complete every `# FILL IN:` marker. Blocks were derived
> from the spec's Interface Skeletons and re-verified against the Codebase Contract
> above when this task was written. This is NOT the full implementation:
> business-logic branches, edge cases and test bodies are `FILL IN` stubs by design.
> Never change a signature, class name, or file path the blueprint fixes.

### Steps (in order)
1. Confirm TASK-175/176/177 are merged in the worktree (`grep -n "def increment_generation" navigator_auth/security_state/store.py`, `grep -n "def session_revoker" navigator_auth/handlers/recovery/handler.py`, `grep -n "class TransitionAborted" navigator_auth/mfa/events.py`) — *why*: the blocks import their symbols.
2. Add the imports and the `_USERS` constant (block 1) — *why*: phase 2 writes with explicit, schema-qualified SQL.
3. Replace the body of `password_change` from `try:` (line 124) through its `except Exception` (line 144) (block 2) — *why*: phase 1 must release its connection before the transition takes the lock (no nested acquire, AC10), and the write must commit with the bookkeeping (AC14).
4. Replace the body of `password_reset` from `try:` (line 163) through its `except Exception` (line 188) (block 3) — *why*: G9/AC28 — generation and strict revocation commit atomically with the new hash.
5. Add the tests (block 4) and run the Validation Commands — *why*: fault injection is the only proof of atomicity.

### `navigator_auth/handlers/users/session.py` (MODIFY) — block 1: imports
```python
# occurrences: 1 (verified: grep -c 'from ...mfa.events import security_transition' navigator_auth/handlers/users/session.py)
# REPLACE — line 12 (verified: navigator_auth/handlers/users/session.py:12); also add `import secrets` after `import time` (line 1)
from asyncdb.exceptions import NoDataFound
from ...conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE
from ...mfa.events import TransitionAborted, security_transition
from ...mfa.exceptions import MfaStorageError, MfaUnavailable
from ...security_state.store import SecurityStateError, increment_generation
from ..recovery.handler import PasswordRecoveryHandler
from ..recovery.revoke import RevocationError

_USERS = f"{AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE}"
```
**Why**: `_USERS` mirrors the `User` model's `Meta.schema`/`Meta.name` (models.py:68-70) so the explicit SQL hits
the same table the ORM uses.

### `navigator_auth/handlers/users/session.py` (MODIFY) — block 2: `password_change`
```python
# occurrences of 'async with security_transition(': 2 (lines 131, 171) — disambiguated by the next line
#   'request.app, user.user_id, "password_change", actor_user_id=user.user_id' (1 occurrence, line 132)
# REPLACE — lines 124-144 of password_change (verified: navigator_auth/handlers/users/session.py:124-144)
        db = request.app["authdb"]
        try:
            # Phase 1: read + validate on a pooled connection, released before the lock (G3).
            async with await db.acquire() as conn:
                User.Meta.connection = conn
                user = await User.get(user_id=user_id)
                if not check_password(user.password, old_password):
                    return self.error(reason="Forbidden: Current Password doesn't match.", status=403)
                target_id = user.user_id
                captured = user.password
            new_hash = set_basic_password(new_password)
            # Phase 2: ONE connection, ONE transaction with the MFA bookkeeping (G4).
            async with security_transition(
                request.app, target_id, "password_change", actor_user_id=target_id
            ) as conn:
                current = await conn.fetchval(f"SELECT password FROM {_USERS} WHERE user_id = $1 FOR UPDATE", target_id)
                if current is None or not secrets.compare_digest(str(current), str(captured or "")):
                    raise TransitionAborted("credentials_changed")
                await conn.fetchval(
                    f"UPDATE {_USERS} SET password = $2 WHERE user_id = $1 RETURNING user_id", target_id, new_hash
                )
            headers = {"x-status": "OK", "x-message": "Session OK"}
            response = {"action": "Password Changed", "status": "OK"}
            return self.json_response(response=response, headers=headers, status=202)
        except TransitionAborted as aborted:
            return self.json_response(response={"error": aborted.reason}, status=409)
        except MfaStorageError:  # MfaUnavailable, lock timeout (AC11), audit/commit failure (AC14)
            return self.json_response(response={"error": "mfa_unavailable"}, status=503)
        except ValidationError as ex:
            self.error(reason="User info has errors", exception=ex.payload, status=412)
        except Exception as err:  # pylint: disable=W0703
            return self.critical(reason=f"Error getting User: {err}", exception=err)
```
**Why**: `set_basic_password` (CPU-bound hashing) runs before the lock to keep the lock window short.
`FOR UPDATE` pins the row for the rest of the transaction. `MfaUnavailable` is a subclass of `MfaStorageError`,
so one clause maps both to the spec's 503 `mfa_unavailable` (AC13). The `ValidationError` branch is kept as it
is today (pre-existing missing `return`, out of scope).

### `navigator_auth/handlers/users/session.py` (MODIFY) — block 3: `password_reset`
```python
# occurrences of 'async with security_transition(': 2 (lines 131, 171) — disambiguated by the next line
#   'request.app, user.user_id, "password_reset", actor_user_id=userinfo.get("user_id")' (1 occurrence, line 172)
# REPLACE — lines 163-188 of password_reset (verified: navigator_auth/handlers/users/session.py:163-188)
        db = request.app["authdb"]
        try:
            # Phase 1: existence check only (404), pooled and released.
            async with await db.acquire() as conn:
                User.Meta.connection = conn
                try:
                    user = await User.get(user_id=userid)
                except NoDataFound:
                    user = None
                if not user:
                    return self.error(reason="User not found", status=404)
                captured = user.password
            new_hash = set_basic_password(new_password)
            revoker = PasswordRecoveryHandler.session_revoker()
            async with security_transition(
                request.app, user.user_id, "password_reset", actor_user_id=userinfo.get("user_id")
            ) as conn:
                current = await conn.fetchval(f"SELECT password FROM {_USERS} WHERE user_id = $1 FOR UPDATE", user.user_id)
                if current is None or not secrets.compare_digest(str(current), str(captured or "")):
                    raise TransitionAborted("credentials_changed")
                await conn.fetchval(
                    f"UPDATE {_USERS} SET password = $2, is_new = true WHERE user_id = $1 RETURNING user_id",
                    user.user_id,
                    new_hash,
                )
                await increment_generation(conn, user.user_id)
                # G9 / AC28: strict — any session-Redis / JTI-index / per-token failure raises and rolls back.
                await revoker.revoke_user(request, user, strict=True)
            headers = {"x-status": "OK", "x-message": "Session OK"}
            response = {
                "action": "Password was changed successfully",
                "user": user.user_id,
                "username": user.username,
                "status": "OK",
            }
            return self.json_response(response=response, headers=headers, status=202)
        except TransitionAborted as aborted:
            return self.json_response(response={"error": aborted.reason}, status=409)
        except MfaStorageError:
            return self.json_response(response={"error": "mfa_unavailable"}, status=503)
        except (RevocationError, SecurityStateError) as err:
            self.logger.error(f"password_reset rolled back for user {user.user_id}: {type(err).__name__}")
            return self.json_response(response={"error": "temporarily_unavailable"}, status=503)
        except ValidationError as ex:
            self.error(reason="User data has errors", exception=ex.payload, status=412)
        except Exception as err:  # pylint: disable=W0703
            return self.critical(reason=f"Error getting User: {err}", exception=err)
```
**Why**: the generation increment and the strict revocation run inside the transition so that a failure of
either rolls back the password too (AC28, AC31). `session_revoker()` is fetched before the lock because it may
lazily create the recovery Redis pool (no DB work, but keep the lock window minimal). `revoke_user` receives the
phase-1 `User` instance: it reads only `username` / `user_id` (revoke.py:29-38), which phase 2 does not change.
The `except (RevocationError, SecurityStateError)` clause may reference `user`: those errors are raised only in
phase 2, after `user` is bound.

### `tests/test_mfa_review_fixes_transitions.py` (MODIFY) — block 4: append tests
```python
# AFTER — append at the end of the file (created by TASK-171, extended by TASK-177; re-check its last line
#   with `tail -5 tests/test_mfa_review_fixes_transitions.py` before appending)
# FILL IN: imports — UserSession (navigator_auth.handlers.users.session), set_basic_password,
#   mfa fixtures (mfa_db, mfa_user_factory, single_connection_authdb) from tests.fixtures.mfa, and the
#   dependency symbols listed in the Codebase Contract. Build the handler call with
#   aiohttp.test_utils.make_mocked_request + monkeypatched UserSession.session / get_json / json_data,
#   app = {"authdb": <pool>, MFA_APP_KEY: <slot>} — or reuse a live app helper if TASK-171/177 created one here.


@pytest.mark.asyncio
async def test_password_change_two_phase_success(mfa_db, mfa_user_factory):
    """password_change writes the new hash and bumps/audits in one transaction (G4)."""
    # FILL IN: bounded by spec §3 M4 password_change contract; assert 202, new hash verifies, audit row once.
    raise NotImplementedError


@pytest.mark.asyncio
async def test_password_change_hash_drift_409(mfa_db, mfa_user_factory, monkeypatch):
    """A hash change between phase 1 and phase 2 answers 409 and writes nothing."""
    # FILL IN: change the stored hash after phase 1 (e.g. patch set_basic_password to update the row first);
    #   assert 409 {"error": "credentials_changed"} and the intervening hash is still stored. Bounded by M4.
    raise NotImplementedError


@pytest.mark.asyncio
async def test_transition_atomic_on_audit_failure_password_flows(mfa_db, mfa_user_factory, monkeypatch):
    """AC14 (password_change + password_reset): a write_audit fault, and separately a commit fault, leave hash,
    security version and trusted devices unchanged; response 503."""
    # FILL IN: bounded by AC14; inject into MfaSecurity.write_audit and into the transition commit.
    raise NotImplementedError


@pytest.mark.asyncio
async def test_password_flows_mfa_unavailable_503(monkeypatch):
    """AC13: 2FA on + MFA unavailable -> both flows answer 503 mfa_unavailable; credential unchanged."""
    # FILL IN: bounded by AC13.
    raise NotImplementedError


@pytest.mark.asyncio
async def test_password_reset_revokes_sessions(mfa_db, mfa_user_factory, monkeypatch):
    """AC28: reset strictly revokes the session and indexed jtis and commits the generation increment;
    a revocation failure leaves password and generation unchanged (503)."""
    # FILL IN: bounded by AC28 / AC31 — assert generation == previous + 1 after success; make
    #   SessionRevoker.revoke_user(strict=True) raise RevocationError and assert hash + generation unchanged.
    raise NotImplementedError


@pytest.mark.asyncio
async def test_password_flows_single_connection(single_connection_authdb, mfa_user_factory):
    """AC10: password_change and password_reset complete on a one-connection authdb within 10 s."""
    # FILL IN: bounded by AC10 / G3 — asyncio.wait_for(..., 10); single_connection_authdb.acquires_inside_lock == [].
    raise NotImplementedError
```
**Why**: the spec's Validation Contract puts the M3/M4 transition tests in this file; tests are appended so they
do not collide with TASK-171/TASK-177's tests above them.

### FILL IN checklist
- [ ] Test imports and the handler-call harness — only symbols verified in the Codebase Contract or created by TASK-171/175/176/177.
- [ ] `test_password_change_hash_drift_409` — bounded by spec §3 M4 (409 on drift).
- [ ] `test_transition_atomic_on_audit_failure_password_flows` — bounded by AC14.
- [ ] `test_password_flows_mfa_unavailable_503` — bounded by AC13.
- [ ] `test_password_reset_revokes_sessions` — bounded by AC28, AC31.
- [ ] `test_password_flows_single_connection` — bounded by AC10.

---

## Acceptance Criteria

- [ ] `password_change` and `password_reset` follow the two-phase pattern: no `db.acquire()` while the transition is open; the hash write happens on the transition connection.
- [ ] Hash drift between phases answers 409 `credentials_changed` and writes nothing.
- [ ] AC13 (password flows) — 2FA on + MFA unavailable → 503 `mfa_unavailable`, credential unchanged.
- [ ] AC14 (password_change, password_reset) — fault in `write_audit` (and separately the commit) leaves hash, security version and trusted devices unchanged; response 503.
- [ ] AC28 — `password_reset` strictly revokes the target's session and indexed jtis and commits the generation increment with the password; a revocation failure leaves password and generation unchanged (503).
- [ ] AC10 (password flows) — both complete on a one-connection `authdb` within 10 s; no `acquire()` while `LOCK_CONNECTION` is set.
- [ ] `password_change` does not revoke sessions or change the generation.
- [ ] `python -c "import navigator_auth.handlers"` succeeds (no circular import).
- [ ] No linting errors: `ruff check navigator_auth/handlers/users/session.py` (if ruff is configured).

---

## Validation Commands

- `pytest tests/test_mfa_review_fixes_transitions.py -q`

---

## Test Specification

```python
# tests/test_mfa_review_fixes_transitions.py (appended — see blueprint block 4)
async def test_password_change_two_phase_success(...): ...                 # G4
async def test_password_change_hash_drift_409(...): ...                     # M4 drift
async def test_transition_atomic_on_audit_failure_password_flows(...): ...  # AC14
async def test_password_flows_mfa_unavailable_503(...): ...                 # AC13
async def test_password_reset_revokes_sessions(...): ...                    # AC28 / AC31
async def test_password_flows_single_connection(...): ...                   # AC10
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the existing feature worktree** `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa` (branch
   `feat-FEAT-106-basicauth-otp-2fa`, PR #633) — never on `dev`.
2. **Read the spec** at the path listed above for full context (§3 M3, M4 and the durable recovery/revocation contract; §5 AC10, AC13, AC14, AC28).
3. **Check dependencies** — TASK-175, TASK-176 and TASK-177 must be `"done"` in
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
9. **Close the task** with `parrot sdd task close TASK-179 basicauth-otp-2fa-review-fixes verified`
   — it moves this file to `sdd/tasks/completed/` and marks it `"done"` in the
   index; never move or copy the file by hand
10. **Fill in the Completion Note** below, then commit the staged SDD state

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any (expected: phase-2 re-read/write via explicit SQL instead of `User.get`/`User.update`, per Key Constraints)
