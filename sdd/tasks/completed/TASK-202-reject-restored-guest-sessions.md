# TASK-202: `@is_authenticated` rejects restored `AnonymousUser` sessions before its shortcut

**Feature**: FEAT-108 — OAuth2 3LO examples work end-to-end — auth paths fail closed on misconfiguration and unknown users
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-198
**Assigned-to**: unassigned

---

## Context

Spec §2 (request authentication, 2nd bullet), §3 Module 4 (second responsibility), §7 "Legacy guest
sessions", AC6a. TASK-198 stops NoAuth from *creating* guest sessions inside `@is_authenticated`, but
guest sessions issued before this change still exist in Redis. The auth middleware restores them for
the cookie and the bearer paths and sets `request["authenticated"] = True`, so both wrappers would take
their `request.get("authenticated")` shortcut and admit the guest.

**Verified at task time** (dev @ `61d424b`): `NoAuth` stores the concrete `AnonymousUser`
(`noauth.py:17`, `:56`, `remember()` at `:73`) and a jsonpickle round trip — what
`SessionData.decode` does (`navigator_session/data.py:341`) — restores
`navigator_auth.backends.noauth.AnonymousUser` with `isinstance` intact; importing
`navigator_auth.backends.noauth` from `navigator_auth.decorators` creates no import cycle (both orders
tested). So the check is on the restored class; no provenance marker or migration is needed **unless
the real-session tests below disprove it** — then stop and report (spec §7).

---

## Scope

- Add `_is_restored_guest(request) -> bool` (`isinstance(getattr(request, "user", None), AnonymousUser)`).
- In both wrappers, after the exclude-list / `allow_anonymous` short-circuit and **before**
  `if request.get("authenticated", False):`, raise the same 401 the wrappers already raise.
- Add real-session tests (Redis) for cookie and bearer, function and method wrappers, plus the
  "normal session still works" and "explicit anonymous exemption still works" cases.

**NOT in scope**: the backend loop (TASK-198); session storage or `get_session_user`; the middleware.
Never infer anonymity from `is_authenticated`, the Guest group or the display name (spec §2).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/decorators.py` | MODIFY | `_is_restored_guest` + check in both wrappers |
| `tests/test_is_authenticated_backend_loop.py` | MODIFY | `test_existing_guest_sessions_rejected` (+ positives) |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `61d424b` AND `feat-FEAT-106-basicauth-otp-2fa` @ `0b80d88` (2026-11-11);
> line numbers dev / FEAT-106. TASK-198 has already replaced both loops with `_authenticate_with_backends`.

### Verified Imports
```python
from .backends.noauth import AnonymousUser             # verified: navigator_auth/backends/noauth.py:17 (no cycle with decorators.py)
from navigator_auth import AuthHandler                 # verified: tests/test_auth_middleware_mechanism.py:57
from navigator_session import SESSION_ID, SESSION_KEY  # verified: tests/test_auth_middleware_mechanism.py:25
from aiohttp.test_utils import TestClient, TestServer  # verified: tests/test_auth_middleware_mechanism.py:24
from aiohttp import DummyCookieJar, web                # verified: tests/test_auth_middleware_mechanism.py:23
```

### Existing Signatures to Use
```python
# navigator_auth/decorators.py
def is_authenticated(content_type: str = "application/json") -> Callable[[F], F]:   # :179
#   both wrappers:  if _is_path_excluded(request) or getattr(request, "allow_anonymous", False):  (dev :207, :252 / 106 :207, :256 — 3rd occurrence at :1289 is another decorator)
#                   if request.get("authenticated", False):                                   (dev :209, :254 / 106 :209, :258)
#   existing 401:   raise web.HTTPUnauthorized(reason="Access Denied",
#                       headers={hdrs.CONTENT_TYPE: content_type, hdrs.CONNECTION: "keep-alive"})

# navigator_auth/backends/noauth.py
class AnonymousUser(AuthUser):                          # :17 (display_name "Anonymous User")
class NoAuth(BaseAuthBackend):                          # :21; authenticate :54 returns {"token": …, session key, …}

# navigator_auth/auth.py
async def get_session_user(self, session, name: str = "user"):  # :748 — session.decode(name) → jsonpickle; sets user.is_authenticated = True

# tests/test_auth_middleware_mechanism.py:48-100 — real AuthHandler app over Redis:
#   AuthHandler(secure_cookies=True, enable_authdb=False, backends=("navigator_auth.backends.NoAuth",))
#   storage.new_session(request, {SESSION_KEY: identity}); session.save_encoded_data(request, "user", user)
```

### Does NOT Exist
- ~~`AuthUser.is_guest`~~, ~~`is_anonymous`~~, ~~a "provenance" session key~~ — none exists; do not add one unless the tests prove the class is lost.
- `user.is_authenticated` is forced True by `get_session_user` (`auth.py:756`) and `remember()` — useless as a guest test.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/decorators.py", "action": "MODIFY"},
    {"path": "tests/test_is_authenticated_backend_loop.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/decorators.py#is_authenticated",
    "sym:navigator_auth/backends/noauth.py#AnonymousUser",
    "sym:navigator_auth/backends/noauth.py#NoAuth",
    "sym:navigator_auth/auth.py#AuthHandler.get_session_user"
  ]
}
```

---

## Implementation Notes

- **Exclusive task** (`parallel: false`): its tests use the local Redis for real serialized sessions
  (same resource as `tests/test_auth_middleware_mechanism.py`). Skip them cleanly when Redis is down,
  using that file's conventions.
- Order inside each wrapper: OPTIONS → exclude/`allow_anonymous` → **restored guest → 401** →
  `authenticated` shortcut → backend loop. Exemptions must still admit guests (AC6a, AC9).

---

## Implementation Blueprint

### Steps (in order)
1. Add the import and `_is_restored_guest` — *why*: one definition used by both wrappers.
2. Insert the check in both wrappers — *why*: AC6a, before the shortcut that would admit the guest.
3. Add the Redis-backed tests: guest cookie / guest bearer × function / method → 401; normal user
   session → 200; guest on an excluded path / `allow_anonymous` handler → 200.

### `navigator_auth/decorators.py` (MODIFY) — import + helper
```python
# occurrences: 1 (verified: grep -c 'from .conf import AUTH_SESSION_OBJECT, AUTH_EXCLUDE_LIST_KEY' navigator_auth/decorators.py)
# AFTER — insert below `from .conf import AUTH_SESSION_OBJECT, AUTH_EXCLUDE_LIST_KEY` (verified: :11)
from .backends.noauth import AnonymousUser


# and, placed directly above `async def _authenticate_with_backends(` (added by TASK-198):
def _is_restored_guest(request: web.Request) -> bool:
    """True when the middleware restored a NoAuth guest identity onto the request (FEAT-108 AC6a).

    NoAuth stores the concrete ``AnonymousUser`` class in the session and jsonpickle restores it,
    so the class is the trusted signal — never ``is_authenticated`` (forced True on restore),
    the Guest group or the display name.
    """
    return isinstance(getattr(request, "user", None), AnonymousUser)
```

### `navigator_auth/decorators.py` (MODIFY) — both wrappers
```python
# occurrences: 2 (verified: grep -c 'if request.get("authenticated", False):' navigator_auth/decorators.py)
# FILL IN: disambiguate — insert ABOVE each occurrence (function wrapper: dev :209 / 106 :209, 12-space
# indent, inside `_wrap`; method wrapper: dev :254 / 106 :258, 12-space indent, inside `wrapped_method`).
# Function wrapper:
            if _is_restored_guest(request):
                raise web.HTTPUnauthorized(
                    reason="Access Denied",
                    headers={
                        hdrs.CONTENT_TYPE: content_type,
                        hdrs.CONNECTION: "keep-alive",
                    },
                )
# Method wrapper: the same block, same indentation.
```
**Why**: placed after the exemption checks so explicitly anonymous routes keep working (AC9).

### `tests/test_is_authenticated_backend_loop.py` (MODIFY) — append
```python
# --- FEAT-108 AC6a: restored guest sessions (real Redis sessions) -----------------------------
# FILL IN: a module-scoped pytest_asyncio fixture modelled on tests/test_auth_middleware_mechanism.py:48-100:
#   AuthHandler(secure_cookies=True, enable_authdb=False, backends=("navigator_auth.backends.NoAuth",)),
#   an excluded POST route that creates a session and saves AnonymousUser (and, for the positive case,
#   an AuthUser) with session.save_encoded_data(request, "user", user) — the real pre-change encoding —
#   plus protected routes: a function handler and a class-based web.View, both @is_authenticated(),
#   an excluded handler and an @allow_anonymous handler. Skip when Redis is unavailable.
#
# FILL IN: test_existing_guest_sessions_rejected — cookie (SESSION_ID cookie) and bearer
#   (token from auth._idp.create_token carrying the session key) × function and method handlers → 401;
#   the same calls with the AuthUser session → 200; the guest on the excluded / allow_anonymous
#   routes → 200 — bounded by AC6a and AC9.
```

### FILL IN checklist
- [ ] Wrapper insertions at both disambiguated anchors.
- [ ] Redis fixture + skip; AC6a.
- [ ] `test_existing_guest_sessions_rejected` matrix (cookie/bearer × function/method, positives); AC6a, AC9.
- [ ] If any guest session restores without its `AnonymousUser` class, STOP and report (spec §7 requires a migration then).

---

## Acceptance Criteria

- [ ] AC6a: previously issued NoAuth cookie and bearer sessions get 401 before both authenticated shortcuts, even when the middleware marks them authenticated; tested with real serialized sessions; non-guest sessions and explicit anonymous exemptions still work.
- [ ] AC9: `tests/unit/test_is_authenticated_exclude.py` passes unchanged.
- [ ] `ruff check navigator_auth/decorators.py tests/test_is_authenticated_backend_loop.py` clean.

---

## Validation Commands

- `pytest tests/test_is_authenticated_backend_loop.py -q`
- `pytest tests/unit/test_is_authenticated_exclude.py -q`

---

## Test Specification

Spec §4, M4: `test_existing_guest_sessions_rejected` (real pre-change NoAuth serialization, cookie and
bearer, function and method wrappers ⇒ 401; normal sessions and explicit anonymous exemptions still work).

---

## Agent Instructions

When you pick up this task:

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug oauth2-3lo-issues --feature-id FEAT-108`).
   The spec requires the worktree to be created from `origin/dev` **after FEAT-106 (PR #633) merges**.
2. **Read the spec** at the path listed above for full context.
3. **Check dependencies** — every `Depends-on` task must be `"done"` in `sdd/tasks/index/oauth2-3lo-issues.json`.
4. **Verify the Codebase Contract** — re-run each `grep -c` in the blueprint before editing; a changed
   count means the anchor moved (re-locate it), a `0` means drift (stop and report).
5. **Update status** in the index → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** from the Implementation Blueprint; complete every `# FILL IN:`; never change a fixed signature or path.
7. **Verify** — run the Validation Commands (Redis must be running for the AC6a tests).
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`).
9. **Close the task** with `parrot sdd task close TASK-202 oauth2-3lo-issues verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none

## Completion Note

Merged manually from attempt 3 (luna). Task-tier validation: 18 passed, 1 failed — test_existing_guest_sessions_rejected needs a live Redis (AC6a), unavailable in the sandbox (connection refused on localhost:6379). NOT verified here; must be re-run with Redis before release.
