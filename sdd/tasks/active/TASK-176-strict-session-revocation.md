# TASK-176: Strict SessionRevoker and PasswordRecoveryHandler.session_revoker()

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Spec §3 Module 4 ("Durable recovery and token revocation contract", second bullet) and G9 / AC31.
`SessionRevoker.revoke_user` (`navigator_auth/handlers/recovery/revoke.py:47`) is best-effort by design
(FEAT-098): every failure is logged and turned into a smaller count. That is fine after a password has
already changed, but this feature moves revocation **inside** the credential-change transaction of
`password_reset` (TASK-179) and recovery completion (TASK-180): a revocation failure must abort and roll back
the password write (503). A silent zero count would report a password change as successful while the old
sessions and tokens survive.

This task adds an opt-in strict mode that propagates every underlying failure (session Redis, JTI index,
per-token revocation, or a missing required backend), keeps the default behaviour byte-for-byte for existing
callers, and exposes the single process-wide revoker through a public classmethod so `password_reset` can use
the same instance recovery uses.

---

## Scope

- Add `class RevocationError(Exception)` to `navigator_auth/handlers/recovery/revoke.py`.
- Change `SessionRevoker.revoke_user(self, request, user) -> int` to
  `revoke_user(self, request, user, *, strict: bool = False) -> int`. In strict mode attempt **every** record,
  collect failures, and raise `RevocationError` at the end when any occurred. Default mode unchanged.
- Thread an optional failure collector through `_revoke_session` and `_revoke_jtis`.
- Add `PasswordRecoveryHandler.session_revoker()` (classmethod): `cls._ensure_resources()`; `return cls._revoker`.
- Extend `tests/test_password_recovery.py::TestSessionRevoker` with strict-mode tests (AC31 at unit level).

**NOT in scope**:
- Calling `revoke_user(..., strict=True)` from `password_reset` (TASK-179) or recovery completion (TASK-180).
  The existing recovery call (`handler.py:311`) stays as it is here — TASK-180 rewrites that flow.
- Durable generation / consumption tables (TASK-175).
- Any change to `AccessTokenStorage` or `BasicAuth._index_user_jti`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/recovery/revoke.py` | MODIFY | `RevocationError`; `strict` keyword; failure collection |
| `navigator_auth/handlers/recovery/handler.py` | MODIFY | `PasswordRecoveryHandler.session_revoker()` classmethod |
| `tests/test_password_recovery.py` | MODIFY | Strict-mode tests in `TestSessionRevoker` |

---

## Codebase Contract (Anti-Hallucination)

> **CRITICAL**: This section contains VERIFIED code references from the actual codebase.
> The implementing agent MUST use these exact imports, class names, and method signatures.
> **DO NOT** invent, guess, or assume any import, attribute, or method not listed here.
> If you need something not listed, VERIFY it exists first with `grep` or `read`.
>
> Verified against `0b80d88` (branch `feat-FEAT-106-basicauth-otp-2fa`).

### Verified Imports
```python
# navigator_auth/handlers/recovery/revoke.py (existing module imports)
import logging                                   # verified: revoke.py:17
from typing import Optional                      # verified: revoke.py:18
import redis.asyncio as aioredis                 # verified: revoke.py:20
# navigator_auth/handlers/recovery/handler.py
from navigator_auth.handlers.recovery.revoke import SessionRevoker   # verified: handler.py:44
# tests/test_password_recovery.py
from navigator_auth.handlers.recovery.revoke import SessionRevoker   # verified: tests/test_password_recovery.py:17
from navigator_auth.handlers.recovery.handler import PasswordRecoveryHandler  # verified: handler.py:115
```

### Existing Signatures to Use
```python
# navigator_auth/handlers/recovery/revoke.py
JTI_INDEX_PREFIX = "auth:user:jti:"                          # line 26
def _username_of(user) -> Optional[str]                      # line 29
def _user_id_of(user)                                        # line 35
class SessionRevoker:                                        # line 41
    def __init__(self, session_pool: aioredis.ConnectionPool)  # line 44
    async def revoke_user(self, request, user) -> int        # line 47 — sum of _revoke_session + _revoke_jtis
    async def _revoke_session(self, user) -> int             # line 54 — user:{username} -> session:{id}; deletes both
    async def _revoke_jtis(self, request, user) -> int       # line 86 — walks request.app["auth"].backends[*].access_token_storage;
                                                             #   smembers(index) -> storage.revoke(jti) -> storage.redis.srem(index, jti)

# navigator_auth/handlers/recovery/handler.py
class PasswordRecoveryHandler(BaseView):                     # line 115
    _pool: Optional[aioredis.ConnectionPool] = None          # line 131
    _revoker: Optional[SessionRevoker] = None                # line 136
    @classmethod
    def _ensure_resources(cls) -> None:                      # line 139 — lazily builds the class-level pool, store, policy, limiters, revoker
        cls._revoker = SessionRevoker(cls._pool)             # line 151
    revoked = await self._revoker.revoke_user(self.request, user)   # line 311 — only existing caller (best-effort)

# tests/test_password_recovery.py
@pytest_asyncio.fixture async def redis_pool()              # line 87; `redis` fixture at line 96
@pytest_asyncio.fixture async def broken_redis_pool()        # line 111 — pool to an unreachable host (every command raises)
@pytest.fixture def revoker(redis_pool) -> SessionRevoker    # line 316
@pytest_asyncio.fixture async def access_token_storage()     # line 321 — real AccessTokenStorage, closed at teardown
class TestSessionRevoker:                                    # line 367 — real Redis; fake request = SimpleNamespace(app={"auth": SimpleNamespace(backends={...})})
    async def test_revoker_partial_failure(...)              # line 431 — default mode: one failing revoke -> count == 1 (must stay green)
class TestNotificationPayloadSecrecy:                        # line 454
```

### Does NOT Exist
- ~~`RevocationError`~~, ~~`SessionRevoker.revoke_user(..., strict=...)`~~, ~~`PasswordRecoveryHandler.session_revoker`~~ — created by this task.
- ~~`navigator_auth/handlers/auth.py`~~ — does not exist (spec M4 path list); not touched here.
- ~~`AccessTokenStorage.revoke_all(user_id)`~~ — no bulk revoke; jtis are revoked one by one from the `auth:user:jti:{user_id}` index.
- ~~an OAuth refresh-token revocation in `SessionRevoker`~~ — OAuth refresh chains are invalidated by the generation check (TASK-185), not here.
- ~~`navigator_auth.security_state`~~ — TASK-175; not used here.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/handlers/recovery/revoke.py", "action": "MODIFY"},
    {"path": "navigator_auth/handlers/recovery/handler.py", "action": "MODIFY"},
    {"path": "tests/test_password_recovery.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/handlers/recovery/revoke.py#SessionRevoker",
    "sym:navigator_auth/handlers/recovery/revoke.py#SessionRevoker.revoke_user",
    "sym:navigator_auth/handlers/recovery/revoke.py#SessionRevoker._revoke_session",
    "sym:navigator_auth/handlers/recovery/revoke.py#SessionRevoker._revoke_jtis",
    "sym:navigator_auth/handlers/recovery/handler.py#PasswordRecoveryHandler",
    "sym:navigator_auth/handlers/recovery/handler.py#PasswordRecoveryHandler._ensure_resources"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
```python
# revoke.py:107-115 — today each failure is logged and skipped; strict mode keeps the same loop and ALSO records it
            for jti in jtis:
                try:
                    await storage.revoke(jti)
                    revoked += 1
                except Exception as exc:  # pylint: disable=W0703
                    logger.warning("SessionRevoker: failed to revoke jti=%s: %s", jti, exc)
                    continue
```

### Key Constraints
- **Default mode is unchanged**: same counts, same logs, never raises (existing callers and
  `test_revoker_partial_failure` depend on it).
- **Strict mode attempts everything, then raises**: revoking as much as possible before failing is safe (it may log
  users out) and makes a retry converge — `storage.revoke` is idempotent and a jti leaves the index only after a
  successful revoke. Raise once, at the end, with a secret-free summary (failure labels + counts, never a jti or token).
- Strict failures: session Redis unreachable / `get` / `delete` errors; JTI index `smembers` errors; any
  `storage.revoke` error; **missing required backends** — `request is None`, no `request.app["auth"]`, or no backend
  exposing `access_token_storage`; a user with no username or no user_id (nothing can be addressed).
- Not a strict failure: no `user:{username}` session key (nothing to revoke) and an `srem` prune failure after a
  successful revoke (the token is revoked; a stale index entry is harmless and is re-revoked on retry).
- Log lines stay secret-free; keep the module `logger`.

### References in Codebase
- `navigator_auth/handlers/recovery/revoke.py` — the whole module (123 lines)
- `navigator_auth/auth.py:1044-1065` — `_token_is_revoked` walks the same `backends[*].access_token_storage`

---

## Implementation Blueprint

> **CRITICAL — Executor-ready starting point.** Write each block below to its declared
> path nearly verbatim, then complete every `# FILL IN:` marker. Blocks were derived
> from the spec's Interface Skeletons and re-verified against the Codebase Contract
> above when this task was written. This is NOT the full implementation:
> business-logic branches, edge cases and test bodies are `FILL IN` stubs by design.
> Never change a signature, class name, or file path the blueprint fixes.

### Steps (in order)
1. Add `RevocationError` above `class SessionRevoker` — *why*: callers (TASK-179/180) catch one specific type to answer 503 and roll back.
2. Replace `revoke_user` with the strict-aware version — *why*: the public contract is fixed by the plan (`*, strict: bool = False`).
3. Add the optional `failures` collector to `_revoke_session` / `_revoke_jtis` — *why*: one code path for both modes keeps the default behaviour identical.
4. Add `PasswordRecoveryHandler.session_revoker()` — *why*: `password_reset` must reuse the single process-wide revoker (spec M4).
5. Add the strict tests and run the suite — *why*: AC31 failure injection at unit level; the existing default-mode tests must stay green.

### `navigator_auth/handlers/recovery/revoke.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'class SessionRevoker:' navigator_auth/handlers/recovery/revoke.py)
# BEFORE — insert above `class SessionRevoker:` (verified: navigator_auth/handlers/recovery/revoke.py:41)
class RevocationError(Exception):
    """Strict revocation could not prove that every session and token of a user was revoked.

    Raised only by ``SessionRevoker.revoke_user(..., strict=True)``; the message is secret-free.
    """


# occurrences: 1 (verified: grep -c '    async def revoke_user(self, request, user) -> int:' navigator_auth/handlers/recovery/revoke.py)
# REPLACE — the whole revoke_user method (verified: navigator_auth/handlers/recovery/revoke.py:47-52)
    async def revoke_user(self, request, user, *, strict: bool = False) -> int:
        """Revoke a user's live session and every indexed JWT ``jti``.

        Args:
            request: Current request (its ``app["auth"].backends`` expose ``access_token_storage``).
            user: Mapping or object with ``username`` and ``user_id``.
            strict: ``False`` (default, FEAT-098) — best-effort, failures are logged and not counted.
                ``True`` (FEAT-106 review fixes: password reset / recovery) — attempt every record, then
                raise when any session, index or token revocation failed or a required backend is missing.

        Returns:
            The count of records actually revoked.

        Raises:
            RevocationError: Only in strict mode.
        """
        failures: Optional[list[str]] = [] if strict else None
        count = 0
        count += await self._revoke_session(user, failures)
        count += await self._revoke_jtis(request, user, failures)
        if failures:
            logger.error(
                "SessionRevoker: strict revocation incomplete for user_id=%s (%d failure(s), %d revoked)",
                _user_id_of(user), len(failures), count,
            )
            raise RevocationError(f"revocation incomplete: {', '.join(sorted(set(failures)))}")
        return count

# occurrences: 1 (verified: grep -c '    async def _revoke_session(self, user) -> int:' navigator_auth/handlers/recovery/revoke.py)
# REPLACE — signature line only (verified: navigator_auth/handlers/recovery/revoke.py:54)
    async def _revoke_session(self, user, failures: Optional[list[str]] = None) -> int:
        # FILL IN: when `failures is not None`, append a label in each existing except branch and when the username is
        #          missing: "username_missing", "session_delete", "session_index_delete", "session_store_unreachable".
        #          Keep every existing logger.warning and return value unchanged — bounded by "default mode unchanged"
        #          and AC31 (session Redis errors must surface in strict mode). Thread `failures` through unchanged
#          wherever the method body passes data on; never raise inside it (revoke_user raises once, at the end).

# occurrences: 1 (verified: grep -c '    async def _revoke_jtis(self, request, user) -> int:' navigator_auth/handlers/recovery/revoke.py)
# REPLACE — signature line only (verified: navigator_auth/handlers/recovery/revoke.py:86)
    async def _revoke_jtis(self, request, user, failures: Optional[list[str]] = None) -> int:
        # FILL IN: when `failures is not None`, append: "user_id_missing" (user_id None), "jti_backend_missing"
        #          (request None, no app["auth"], or NO backend with access_token_storage — track whether any storage
        #          was seen), "jti_index_unreadable" (smembers raised), "jti_revoke" (storage.revoke raised).
        #          Do NOT record srem failures. Default-mode returns/logs unchanged — bounded by AC31 and
        #          test_revoker_partial_failure (tests/test_password_recovery.py:431).
```
**Why this shape**: a single `failures` list (None in default mode) keeps one control flow, so the FEAT-098
behaviour cannot drift; raising after the loops implements "attempt everything, then fail" for convergent retries.

### `navigator_auth/handlers/recovery/handler.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'cls._revoker = SessionRevoker(cls._pool)' navigator_auth/handlers/recovery/handler.py)
# AFTER — insert below `        cls._revoker = SessionRevoker(cls._pool)` (verified: navigator_auth/handlers/recovery/handler.py:151),
#         i.e. after the end of _ensure_resources and before `    def __init__(self, request, *args, **kwargs):` (line 153)

    @classmethod
    def session_revoker(cls) -> SessionRevoker:
        """Return the single process-wide ``SessionRevoker`` (FEAT-106 review fixes, spec M4 / G9).

        ``password_reset`` (``handlers/users/session.py``) revokes the target user's sessions and tokens
        with the same instance recovery completion uses, so both share one Redis pool.
        """
        cls._ensure_resources()
        return cls._revoker
```
**Why**: spec M4 fixes this as a classmethod over the existing lazily-created resources (verified `handler.py:139`,
`:151`); no new pool is created.

### `tests/test_password_recovery.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '^class TestNotificationPayloadSecrecy:' tests/test_password_recovery.py)
# BEFORE — insert above `class TestNotificationPayloadSecrecy:` (verified: tests/test_password_recovery.py:454),
#          as a new class right after TestSessionRevoker
class TestStrictSessionRevoker:
    """FEAT-106 review fixes (spec M4, AC31): strict revocation propagates every failure."""

    @pytest.mark.asyncio
    async def test_strict_raises_on_token_revoke_failure_after_attempting_all(self, revoker, redis_pool, access_token_storage):
        """One failing jti revoke -> RevocationError, but the other jti is still revoked (partial revocation)."""
        # FILL IN: mirror test_revoker_partial_failure with strict=True; assert RevocationError and that the
        #          successful jti is revoked and pruned while the failed one stays in the index.

    @pytest.mark.asyncio
    async def test_strict_retry_converges(self, revoker, redis_pool, access_token_storage):
        """After a partial failure, a retry with a healthy storage revokes the rest and returns normally."""
        # FILL IN

    @pytest.mark.asyncio
    async def test_strict_raises_when_jti_index_unreadable(self, revoker, access_token_storage):
        # FILL IN: storage.redis.smembers = AsyncMock(side_effect=ConnectionError("down")) -> RevocationError

    @pytest.mark.asyncio
    async def test_strict_raises_when_session_store_unreachable(self, broken_redis_pool, access_token_storage):
        # FILL IN: SessionRevoker(broken_redis_pool).revoke_user(fake_request, user, strict=True) -> RevocationError

    @pytest.mark.asyncio
    async def test_strict_raises_without_required_backend(self, revoker):
        """request None / no auth handler / no access_token_storage are failures in strict mode only."""
        # FILL IN: strict -> RevocationError for each; default mode -> returns an int, no raise

    def test_session_revoker_is_the_process_wide_instance(self):
        from navigator_auth.handlers.recovery.handler import PasswordRecoveryHandler

        revoker = PasswordRecoveryHandler.session_revoker()
        assert isinstance(revoker, SessionRevoker)
        assert revoker is PasswordRecoveryHandler.session_revoker() is PasswordRecoveryHandler._revoker
```
Add `from navigator_auth.handlers.recovery.revoke import RevocationError` next to the existing
`from navigator_auth.handlers.recovery.revoke import SessionRevoker` (verified: tests/test_password_recovery.py:17;
`grep -c` = 1) and `from unittest.mock import AsyncMock` at module level if the new tests use it.

### FILL IN checklist
- [ ] `revoke.py::SessionRevoker._revoke_session` — failure labels; bounded by default-mode parity + AC31
- [ ] `revoke.py::SessionRevoker._revoke_jtis` — failure labels incl. missing backend, no srem failures; bounded by AC31
- [ ] the five strict-mode test bodies

---

## Acceptance Criteria

- [ ] `revoke_user(request, user)` (default) behaves exactly as before: every existing `TestSessionRevoker` test passes unchanged.
- [ ] `revoke_user(..., strict=True)` raises `RevocationError` for injected session-Redis, JTI-index and per-token failures and for a missing required backend (AC31, unit level), after attempting every record.
- [ ] A retry after a partial strict failure converges (revokes the remainder, no raise).
- [ ] `PasswordRecoveryHandler.session_revoker()` returns the class-level `_revoker`, creating resources lazily.
- [ ] `RevocationError` messages and logs contain no jti, token or session id.
- [ ] All tests pass: `pytest tests/test_password_recovery.py -q`

---

## Validation Commands

- `pytest tests/test_password_recovery.py -q`

---

## Test Specification

```python
# tests/test_password_recovery.py — new class TestStrictSessionRevoker (scaffold in the Implementation Blueprint).
# Uses the existing fixtures: revoker, redis_pool, redis, broken_redis_pool, access_token_storage.
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the stacked feature worktree `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa-review-fixes`** (branch
   `feat-FEAT-106-basicauth-otp-2fa-review-fixes`, stacked on `feat-FEAT-106-basicauth-otp-2fa`; ships in PR #633) — never on `dev`.
2. **Read the spec** at the path listed above (§3 Module 4, the strict-revocation bullet; AC31).
3. **Check dependencies** — none.
4. **Verify the Codebase Contract** — re-run every `grep -c` in the blueprint; update the contract first if anything moved.
5. **Update status** in `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json` → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** — start from the Implementation Blueprint blocks, complete every `# FILL IN:` marker, and never change a signature or path the blueprint fixes.
7. **Verify** all acceptance criteria — run the Validation Commands.
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`).
9. **Close the task** with `parrot sdd task close TASK-176 basicauth-otp-2fa-review-fixes verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none
