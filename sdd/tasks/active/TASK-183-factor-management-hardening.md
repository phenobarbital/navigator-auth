# TASK-183: Backup-code proof and lock-scoped disenroll guard (M8)

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-182
**Assigned-to**: unassigned

---

## Context

Two high-severity PR #633 review findings live in the factor-management endpoints of
`navigator_auth/handlers/mfa.py` (spec §3 **Module 8**, decision **D7**):

- **#7** — `backup_codes` (`handlers/mfa.py:436`) regenerates a standing second factor with only a session plus
  the password. A stolen session + password mints new backup codes. Fix: also require
  `_strong_factor_proof` (a current TOTP code, an unused backup code, or a fresh passkey session) → else 403
  `strong_factor_proof_required`. This amends FEAT-106 M5/AC14.
- **#12** — `disenroll_totp` (`handlers/mfa.py:385`) evaluates the "last strong factor" guard at `:394-396`
  **outside** the user lock, so it races a concurrent passkey delete (whose own guard runs under the lock,
  `backends/passkey.py:569-592`); pre-lock storage errors surface as 500. Fix: evaluate the guard inside
  `user_lock` on the lock connection, roll back on refusal (409), and map pre-lock `MfaStorageError` to 503.

TASK-182 already gave every endpoint a service lease via `@_with_mfa_services` and changed
`_session_user(request)` to `_session_user(request, services)`; this task edits only the two endpoint bodies.

---

## Scope

- `backup_codes`: after the fresh-password and `has_strong_factor` checks, require
  `await self._strong_factor_proof(request, services, session, record, body)`; wrap the pre-lock checks so
  `MfaStorageError` → 503 `mfa_unavailable`.
- `disenroll_totp`: wrap the pre-lock calls (`is_enrolled`, proof verification, backup consume) for
  `MfaStorageError` → 503; delete the pre-lock guard (`:394-396`); evaluate the guard inside `user_lock`
  before `disenroll(conn=conn)`, raising a rollback sentinel → 409 `strong_factor_required`.
- Add the `_StrongFactorRequired` sentinel next to `_EnrollmentFailed`.
- Write `tests/test_mfa_review_fixes_management.py` (AC19, AC20, AC10 for these two endpoints) and update the
  existing tests whose behaviour intentionally changes (docstrings say so — AC21).

**NOT in scope**:
- `_strong_factor_proof`'s own logic (`handlers/mfa.py:141-156`) — reused as is.
- The passkey delete path (`backends/passkey.py`, TASK-178).
- `enroll_totp` / `confirm_totp` / `admin_disenroll` bodies.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/mfa.py` | MODIFY | `backup_codes` proof; `disenroll_totp` guard under the lock; `_StrongFactorRequired` |
| `tests/test_mfa_review_fixes_management.py` | CREATE | AC19, AC20 (race + pre-lock 503), AC10 for disenroll/regeneration |
| `tests/test_mfa_enrollment_security.py` | MODIFY | regeneration calls now carry a proof; last-factor test reflects the in-lock guard |

---

## Codebase Contract (Anti-Hallucination)

> **CRITICAL**: This section contains VERIFIED code references from the actual codebase.
> The implementing agent MUST use these exact imports, class names, and method signatures.
> **DO NOT** invent, guess, or assume any import, attribute, or method not listed here.
> If you need something not listed, VERIFY it exists first with `grep` or `read`.

Verified against `0b80d88` (branch `feat-FEAT-106-basicauth-otp-2fa`). TASK-182 edits `handlers/mfa.py`
first (decorator line + `services` parameter on every endpoint) — re-run every `grep -c` below.

### Verified Imports
```python
# Already imported by navigator_auth/handlers/mfa.py — no new imports needed:
from navigator_auth.mfa.exceptions import MfaStorageError        # verified: handlers/mfa.py:20 (exceptions.py:8)
from navigator_auth.mfa.types import PROVIDER_TOTP, MfaAuditEntry  # verified: handlers/mfa.py:26-39 (types.py:10, :111)

# tests (all verified present on 0b80d88):
from tests.fixtures.mfa import (frozen_totp_clock, mfa_db, mfa_redis_pool, mfa_secret,  # noqa: F401
                                mfa_user_factory)                 # verified: tests/fixtures/mfa.py:22-151
from tests.test_mfa_enrollment_security import Env, FakeSession, env  # noqa: F401
#   verified: tests/test_mfa_enrollment_security.py:111 (Env), :77 (FakeSession), :257 (env fixture).
#   Import ONLY these names — importing a `test_*` function would collect it twice.
from navigator_auth.passkey.migrations import ensure_passkey_tables  # verified: passkey/migrations.py:43

# Created by dependencies:
#   handlers/mfa.py::_with_mfa_services, MfaHandler._session_user(request, services)  — TASK-182
#   tests/fixtures/mfa.py::single_connection_authdb (.acquires_inside_lock)           — TASK-171
```

### Existing Signatures to Use
```python
# navigator_auth/handlers/mfa.py
def _error(code: str, status: int, **extra: Any) -> web.Response                  # line 49
class MfaHandler:
    async def _session_user(self, request, services) -> tuple[Any, Any, Any]        # line 109 (services param: TASK-182)
    @staticmethod
    def _fresh_password_ok(services, record, password: Optional[str]) -> bool        # line 130 (sync)
    async def _strong_factor_proof(self, request, services, session, record, body: dict) -> bool  # line 141
    #   TOTP `code` → providers[PROVIDER_TOTP].verify(request, record, code) (own connection, pre-lock);
    #   `backup_code` → services.backup_codes.consume(uid, code) (own connection, D16); fresh passkey session.
    async def _security_context(self, services, record, conn) -> tuple[policy, MfaState, bool, str]  # line 158
    async def disenroll_totp(self, request, services) -> web.Response               # line 385 (body 386-434)
    #   pre-lock guard to DELETE (lines 394-396):
    #     policy = await services.resolver.effective(record)
    #     if await services.state.requires_strong_factor(record, policy) and await services.state.passkey_count(uid) == 0:
    #         return _error("strong_factor_required", 409)
    async def backup_codes(self, request, services) -> web.Response                 # line 436 (body 437-464)
class _EnrollmentFailed(Exception)                                                 # line 563 (rollback-sentinel pattern)

# navigator_auth/mfa/state.py — class MfaStateMachine
    async def passkey_count(self, user_id: int, *, conn: Any = None) -> int         # line 99 (0 when table absent)
    async def has_strong_factor(self, user: Any, *, conn: Any = None) -> bool       # line 114 (raises MfaStorageError)
    async def requires_strong_factor(self, user: Any, policy) -> bool               # line 121 (no DB; superuser ∧ ENFORCED)
    async def totp_confirmed(self, user_id: int, *, conn: Any = None) -> bool       # line 85

# navigator_auth/mfa/totp.py — class TOTPProvider
    async def is_enrolled(self, user: Mapping) -> bool                              # line 136 (raises MfaStorageError)
    async def verify(self, request, user, code, challenge=None, *, conn=None) -> bool  # line 210 (conn= by TASK-172)

# navigator_auth/mfa/backup_codes.py — class BackupCodeStore
    async def consume(self, user_id: int, code: str) -> bool                        # line 132 — own connection (D16)

# navigator_auth/mfa/security.py — class MfaSecurity
    async def user_lock(self, user_id: int) -> AsyncIterator[Any]                   # line 55 (rollback on exception)

# navigator_auth/backends/passkey.py:569-592 — the passkey delete guard this race test mirrors: under
#   security_transition(...) as conn: totp = state.totp_confirmed(uid, conn=conn);
#   count = state.passkey_count(uid, conn=conn); `if not totp and count <= 1` → 409 strong_factor_required.

# tests/test_mfa_enrollment_security.py
class Env:                                     # line 111
    async def call(self, method, user_id, body, session=None, authenticated=True)   # line 138
    def code(self, secret_b32) -> tuple[str, int]                                   # line 149 (advances the clock 30 s)
    async def enrolled_user(self, **kwargs) -> tuple[dict, FakeSession, str, list[str]]  # line 163
    async def enforced_org(self, *members: int) -> int                              # line 212
    async def audit(self, user_id, action=None) -> list[dict]                        # line 198
```

### Does NOT Exist
- ~~`_StrongFactorRequired`~~ — created by THIS task.
- ~~`MfaStateMachine.requires_strong_factor(..., conn=...)`~~ — no `conn` parameter (pure policy check).
- ~~`BackupCodeStore.consume(..., conn=...)`~~ — deliberately absent (D16); proof consumption stays pre-lock.
- ~~a pre-lock "last strong factor" guard in `disenroll_totp` after this task~~ — spec M8 removes it.
- ~~`strong_factor_proof_required` on `backup_codes` today~~ — it exists only on `enroll_totp` (`:305`) and
  `disenroll_totp` (`:402`) until this task.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/handlers/mfa.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_review_fixes_management.py", "action": "CREATE"},
    {"path": "tests/test_mfa_enrollment_security.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/handlers/mfa.py#_error",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler._session_user",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler._fresh_password_ok",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler._strong_factor_proof",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler._security_context",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler.disenroll_totp",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler.backup_codes",
    "sym:navigator_auth/handlers/mfa.py#_EnrollmentFailed",
    "sym:navigator_auth/mfa/state.py#MfaStateMachine.passkey_count",
    "sym:navigator_auth/mfa/state.py#MfaStateMachine.has_strong_factor",
    "sym:navigator_auth/mfa/state.py#MfaStateMachine.requires_strong_factor",
    "sym:navigator_auth/mfa/state.py#MfaStateMachine.totp_confirmed",
    "sym:navigator_auth/mfa/totp.py#TOTPProvider.is_enrolled",
    "sym:navigator_auth/mfa/totp.py#TOTPProvider.verify",
    "sym:navigator_auth/mfa/backup_codes.py#BackupCodeStore.consume",
    "sym:navigator_auth/mfa/security.py#MfaSecurity.user_lock",
    "sym:navigator_auth/mfa/exceptions.py#MfaStorageError",
    "sym:navigator_auth/passkey/migrations.py#ensure_passkey_tables",
    "sym:tests/test_mfa_enrollment_security.py#Env",
    "sym:tests/test_mfa_enrollment_security.py#FakeSession",
    "sym:tests/test_mfa_enrollment_security.py#env"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- The guard must run **inside** `user_lock`, on the lock connection (`passkey_count(uid, conn=conn)`), so it
  serializes with the passkey delete guard (`backends/passkey.py:569-592`), which takes the same per-user lock
  through `security_transition`.
- A 409 from inside the lock must **roll back** (spec "(rollback)"): raise a sentinel inside the `async with`
  and map it outside — the `_EnrollmentFailed` pattern at `handlers/mfa.py:355,378-381,563-567`.
- Proof checks stay **pre-lock**: `_strong_factor_proof`, TOTP `verify` and `backup_codes.consume` acquire their
  own connections (D16); calling them inside the lock would be a nested acquire (G3/AC10).
- Fail closed: `MfaStorageError` in any pre-lock check → `_error("mfa_unavailable", 503)` (AC20), never a 500.
- **Intended behaviour change (flag in the test docstrings, AC21):** FEAT-106 AC33 promised the superuser
  last-factor refusal "before any submitted code is consumed". With the guard moved under the lock (spec M8),
  the proof is verified first, so a valid TOTP step IS marked used before the 409. Update
  `test_disenroll_superuser_last_factor_refused` accordingly; do not keep a pre-lock fast path (the spec
  removes it).
- Never log codes, backup codes or passwords.

### References in Codebase
- `navigator_auth/handlers/mfa.py:334-383` — `confirm_totp`, the sentinel/rollback pattern to follow.
- `tests/test_mfa_enrollment_security.py:257-300` — the `env` fixture to mirror for a `single_connection_authdb` variant.

---

## Implementation Blueprint

> **CRITICAL — Executor-ready starting point.** Write each block below to its declared
> path nearly verbatim, then complete every `# FILL IN:` marker. Blocks were derived
> from the spec's Interface Skeletons and re-verified against the Codebase Contract
> above when this task was written. This is NOT the full implementation:
> business-logic branches, edge cases and test bodies are `FILL IN` stubs by design.
> Never change a signature, class name, or file path the blueprint fixes.

### Steps (in order)
1. Confirm TASK-182 landed: `grep -n "_with_mfa_services" navigator_auth/handlers/mfa.py` shows the decorator on
   `disenroll_totp` and `backup_codes` — *why*: the blueprint below assumes the `services` parameter.
2. Add `_StrongFactorRequired` next to `_EnrollmentFailed` — *why*: the in-lock refusal must roll back.
3. Rewrite the `backup_codes` pre-lock section — *why*: AC19 (D7).
4. Rewrite the `disenroll_totp` pre-lock section and add the in-lock guard — *why*: AC20 (#12).
5. Update `tests/test_mfa_enrollment_security.py`, write the new test module, run the Validation Commands.

### `navigator_auth/handlers/mfa.py` (MODIFY — sentinel)
```python
# occurrences: 1 (verified: grep -c 'class _EnrollmentFailed(Exception):' navigator_auth/handlers/mfa.py)
# AFTER — the end of `class _EnrollmentFailed` (handlers/mfa.py:563-567)


class _StrongFactorRequired(Exception):
    """Internal rollback sentinel: disenrolling TOTP would leave no strong factor (spec §3 M8, AC20)."""
```

### `navigator_auth/handlers/mfa.py` (MODIFY — `backup_codes`)
```python
# occurrences: 1 (verified: grep -c 'async def backup_codes(' navigator_auth/handlers/mfa.py)
# REPLACE — the body lines from the `_session_user` call through the strong-factor check (0b80d88 :438-444:
#   `services, _, record = await self._session_user(request)` [TASK-182 makes it `(request, services)`] …
#   `if not await services.state.has_strong_factor(record):` (occurrences: 1) … `return _error("strong_factor_required", 403)`)
        """Generate a replacement backup-code set: fresh password AND fresh strong-factor proof (D7, AC19)."""
        services, session, record = await self._session_user(request, services)
        body = await _json_body(request)
        uid = int(record["user_id"] if isinstance(record, dict) else getattr(record, "user_id"))
        if not self._fresh_password_ok(services, record, body.get("password")):
            return _error("invalid_credentials", 403)
        try:
            if not await services.state.has_strong_factor(record):
                return _error("strong_factor_required", 403)
            if not await self._strong_factor_proof(request, services, session, record, body):
                return _error("strong_factor_proof_required", 403)
        except MfaStorageError:
            return _error("mfa_unavailable", 503)
        # (unchanged from here: `try: async with services.security.user_lock(uid) as conn: …` — 0b80d88 :445-464)
```
**Why**: spec §3 M8 `backup_codes` steps 1–4, in order. The docstring line replaces the old one
(`"""Generate and return a replacement backup-code set once."""`, :437).

### `navigator_auth/handlers/mfa.py` (MODIFY — `disenroll_totp`)
```python
# occurrences: 1 (verified: grep -c 'async def disenroll_totp(' navigator_auth/handlers/mfa.py)
# REPLACE — 0b80d88 :386-405 (docstring through `policy, old_state, _, _ = await self._security_context(services, record, conn)`),
#   which includes the pre-lock guard lines (occurrences: 1 each):
#   `policy = await services.resolver.effective(record)` (:394) and
#   `if await services.state.requires_strong_factor(record, policy) and await services.state.passkey_count(uid) == 0:` (:395)
        """Disenrol TOTP after fresh password and proof; the last-factor guard runs under the lock (AC20)."""
        services, session, record = await self._session_user(request, services)
        body = await _json_body(request)
        uid = int(record["user_id"] if isinstance(record, dict) else getattr(record, "user_id"))
        if not self._fresh_password_ok(services, record, body.get("password")):
            return _error("invalid_credentials", 403)
        try:
            if not await services.providers[PROVIDER_TOTP].is_enrolled(record):
                return _error("not_enrolled", 404)
            proof = body.get("code")
            valid = bool(proof and await services.providers[PROVIDER_TOTP].verify(request, record, proof))
            if not valid and body.get("backup_code"):
                valid = await services.backup_codes.consume(uid, body["backup_code"])
        except MfaStorageError:
            return _error("mfa_unavailable", 503)
        if not valid:
            return _error("strong_factor_proof_required", 403)
        try:
            async with services.security.user_lock(uid) as conn:
                policy, old_state, _, _ = await self._security_context(services, record, conn)
                if await services.state.requires_strong_factor(record, policy) and (
                    await services.state.passkey_count(uid, conn=conn) == 0
                ):
                    raise _StrongFactorRequired()
                # (unchanged from here: disenroll(conn=conn), bump_version, revoke_all, write_audit — 0b80d88 :406-421;
                #  then notify_security_event + 200 — :422-432)
        except _StrongFactorRequired:
            return _error("strong_factor_required", 409)
        except MfaStorageError:
            return _error("mfa_unavailable", 503)
```
**Why**: spec §3 M8 `disenroll_totp`: pre-lock calls wrapped → 503; guard inside `user_lock` → conn, before
`disenroll(conn=conn)`, with rollback; pre-lock guard removed. Keep the existing `except MfaStorageError` at
:433-434 (shown last above) — add the sentinel branch before it.

### `tests/test_mfa_enrollment_security.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'response, _ = await env.call("backup_codes", uid, {"password": user["password_plain"]}, session)' tests/test_mfa_enrollment_security.py) — line 531
# occurrences: 1 (verified: grep -c 'regenerated = await env.call("backup_codes", uid, {"password": user["password_plain"]}, session)' tests/test_mfa_enrollment_security.py) — line 691
# FILL IN: add a fresh proof to both bodies — `"code": env.code(started["secret_b32"])[0]` (both tests hold
#   `started`); at 691 also append that code to `secrets_seen` — bounded by AC19.
# occurrences: 1 (verified: grep -c 'async def test_backup_codes_require_strong_factor(env):' tests/test_mfa_enrollment_security.py) — line 652
# FILL IN: password-only regeneration of an enrolled user now answers (403, {"error": "strong_factor_proof_required"});
#   the 201 path passes `"code": env.code(secret)[0]` (unpack `secret` from enrolled_user) — docstring states the
#   D7 behaviour change (AC21).
# occurrences: 1 (verified: grep -c 'async def test_disenroll_superuser_last_factor_refused(env):' tests/test_mfa_enrollment_security.py) — line 631
# FILL IN: still 409 strong_factor_required with nothing disenrolled/audited and the backup code untouched; replace
#   `assert await env.services.store.mark_totp_step(uid, step, 120)` (line 645, occurrences: 1) with the new truth
#   (the valid TOTP step WAS consumed by the pre-lock proof) — docstring cites spec M8 superseding FEAT-106 AC33.
```

### `tests/test_mfa_review_fixes_management.py` (CREATE)
```python
"""FEAT-106 review fixes — factor-management hardening (spec §3 M8; AC19, AC20, AC10)."""

import asyncio

import pytest

from navigator_auth.passkey.migrations import ensure_passkey_tables
from tests.fixtures.mfa import (  # noqa: F401
    frozen_totp_clock,
    mfa_db,
    mfa_redis_pool,
    mfa_secret,
    mfa_user_factory,
)
from tests.test_mfa_enrollment_security import Env, FakeSession, env  # noqa: F401


@pytest.mark.asyncio
async def test_backup_regeneration_requires_proof(env):
    """AC19: password only → 403 strong_factor_proof_required; TOTP code or unused backup code → 201 and the old set dies."""
    # FILL IN — bounded by AC19


@pytest.mark.asyncio
async def test_disenroll_guard_under_lock_race(env):
    """AC20: enforced superuser with TOTP + exactly one passkey; concurrent TOTP disenroll and passkey delete
    leave ≥1 strong factor — exactly one succeeds, the other answers 409."""
    # FILL IN: ensure_passkey_tables(env.db); insert one auth.user_credentials row for the user; run
    #   env.call("disenroll_totp", …) and a passkey-delete stand-in that mirrors backends/passkey.py:569-592
    #   (user_lock → totp_confirmed(conn) + passkey_count(conn) → 409 or DELETE on conn) with asyncio.gather;
    #   repeat a few times with jitter — bounded by AC20


@pytest.mark.asyncio
async def test_disenroll_prelock_storage_error_is_503(env, monkeypatch):
    """AC20: MfaStorageError from is_enrolled / proof verification → 503 mfa_unavailable, not 500."""
    # FILL IN — bounded by AC20


@pytest.mark.asyncio
async def test_management_single_connection_pool(single_connection_authdb):  # TASK-171 fixture
    """AC10: TOTP disenroll and backup-code regeneration finish within 10 s on a one-connection authdb,
    with no acquire() while LOCK_CONNECTION is set."""
    # FILL IN: mirror the `env` fixture (test_mfa_enrollment_security.py:257) over single_connection_authdb — bounded by AC10
```

### FILL IN checklist
- [ ] `handlers/mfa.py::backup_codes` — proof check wired exactly as above; bounded by AC19
- [ ] `handlers/mfa.py::disenroll_totp` — unchanged tail kept inside the new `try`; sentinel → 409; bounded by AC20
- [ ] `test_mfa_enrollment_security.py` — 2 regeneration bodies, `test_backup_codes_require_strong_factor`, `test_disenroll_superuser_last_factor_refused`
- [ ] `test_mfa_review_fixes_management.py` — four test bodies

---

## Acceptance Criteria

- [ ] **AC19** — `POST /auth/mfa/backup-codes` with password only → 403 `strong_factor_proof_required`; with a
      current TOTP code or an unused backup code → 201, and the previous set stops working.
- [ ] **AC20** — concurrent TOTP disenroll vs passkey delete for an enforced superuser with TOTP + one passkey:
      exactly one succeeds, the other answers 409; a storage error in a pre-lock disenroll check answers 503.
- [ ] **AC10** — TOTP disenroll and backup-code regeneration complete within 10 s on a one-connection `authdb`,
      no `acquire()` while `LOCK_CONNECTION` is set.
- [ ] **AC21** — `tests/test_mfa_enrollment_security.py` and `tests/test_mfa_backup_codes.py` pass; every test
      changed for the D7/M8 behaviour change says so in its docstring.
- [ ] The in-lock refusal rolls back: no audit row, TOTP still confirmed, security version unchanged.

---

## Validation Commands

- `pytest tests/test_mfa_review_fixes_management.py -q`
- `pytest tests/test_mfa_enrollment_security.py -q`
- `pytest tests/test_mfa_backup_codes.py -q`

---

## Test Specification

```python
# tests/test_mfa_review_fixes_management.py — see the blueprint block above (four tests):
#   test_backup_regeneration_requires_proof            (AC19)
#   test_disenroll_guard_under_lock_race               (AC20)
#   test_disenroll_prelock_storage_error_is_503        (AC20)
#   test_management_single_connection_pool             (AC10)
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the existing feature worktree `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa`** (branch
   `feat-FEAT-106-basicauth-otp-2fa`, PR #633) — never on `dev`. No new worktree.
2. **Read the spec** at the path listed above for full context (§3 Module 8, §7 D7).
3. **Check dependencies** — TASK-182 must be `"done"` in
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
9. **Close the task** with `parrot sdd task close TASK-183 basicauth-otp-2fa-review-fixes verified`
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
