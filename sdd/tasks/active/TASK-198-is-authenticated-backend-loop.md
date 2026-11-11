# TASK-198: `_anonymous_auth` flag and one shared `@is_authenticated` backend loop

**Feature**: FEAT-108 — OAuth2 3LO examples work end-to-end — auth paths fail closed on misconfiguration and unknown users
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Spec §1 S1–S2 / G4, §2 decisions **D1** (class flag checked *before* `authenticate()`) and **D2**
(unexpected backend errors are logged and skipped), §3 Module 4, AC6–AC9.
Today both `@is_authenticated()` wrappers duplicate a loop that accepts the first truthy backend
result: `NoAuth` (a guest for everyone) lets unauthenticated callers through with 200, and one
backend's `TypeError` turns the request into a 500. FEAT-106 (merged before this feature starts)
added `except MfaSignal: break` to both loops — that stop must survive.

The second half of Module 4 (rejecting *restored* guest sessions before the
`request["authenticated"]` shortcut, AC6a) is TASK-202.

---

## Scope

- Add `_anonymous_auth: bool = False` to `BaseAuthBackend` (next to `_external_auth`) and
  `_anonymous_auth: bool = True` to `NoAuth`.
- Add the private helper `_authenticate_with_backends(auth, request)` to `navigator_auth/decorators.py`.
- Replace the loop in **both** wrappers with a call to the helper; keep the existing 401s unchanged.
- Create `tests/test_is_authenticated_backend_loop.py`.

**NOT in scope**: the restored-guest-session check (TASK-202); `AuthHandler.api_login`'s similar
loop (spec Non-Goals); the exclude list / `allow_anonymous` short-circuits (unchanged, AC9).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/abstract.py` | MODIFY | `_anonymous_auth: bool = False` |
| `navigator_auth/backends/noauth.py` | MODIFY | `_anonymous_auth: bool = True` |
| `navigator_auth/decorators.py` | MODIFY | `_authenticate_with_backends` + both wrappers call it |
| `tests/test_is_authenticated_backend_loop.py` | CREATE | AC6–AC9 tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `61d424b` AND `feat-FEAT-106-basicauth-otp-2fa` @ `0b80d88` (2026-11-11).
> The worktree is created after FEAT-106 merges, so `decorators.py` will already carry FEAT-106's
> `MfaSignal` import and `except MfaSignal: break` (line numbers below: dev / FEAT-106).

### Verified Imports
```python
from navconfig.logging import logger                     # verified: navigator_auth/decorators.py:9
from .exceptions import AuthException, MfaSignal         # decorators.py:10 — `MfaSignal` exists only after FEAT-106 merges
                                                         #   (FEAT-106 branch: navigator_auth/exceptions.py:72, class MfaSignal(AuthException))
from navigator_auth.backends.abstract import BaseAuthBackend   # verified: abstract.py:64
from navigator_auth.backends.noauth import NoAuth              # verified: noauth.py:21
from navigator_auth.decorators import is_authenticated         # verified: decorators.py:179
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY          # verified: tests/unit/test_is_authenticated_exclude.py:15
```

### Existing Signatures to Use
```python
# navigator_auth/backends/abstract.py
class BaseAuthBackend(ABC):                       # :64
    _external_auth: bool = False                  # :79 (read with getattr at auth.py:358)

# navigator_auth/backends/noauth.py
class NoAuth(BaseAuthBackend):                    # :21
    _service_name: str = "anonymous"              # :28
    async def authenticate(self, request):        # :54 (remember() creates a session; returns a truthy dict)

# navigator_auth/decorators.py
from typing import Any, Optional, TypeVar, Union  # :4
from aiohttp import web, hdrs                     # :6
def get_auth(app) -> Awaitable:                   # :35 (app["auth"])
def is_authenticated(content_type: str = "application/json") -> Callable[[F], F]:  # :179
#   function wrapper: `userdata = None` dev :214 / 106 :214; loop `for _, backend in auth.backends.items():`
#                     dev :215 / 106 :215; 401 raised dev :234-240 / 106 :238-244
#   method wrapper:   `userdata = None` dev :258 / 106 :262; loop dev :259 / 106 :263; 401 dev :275-281 / 106 :279-285
```

### Does NOT Exist
- ~~`BaseAuthBackend._anonymous_auth`~~, ~~`is_anonymous`~~, ~~`allow_guest=`~~ — no anonymous marker or `is_authenticated` kwarg exists (it takes only `content_type`).
- ~~`_authenticate_with_backends`~~, ~~`_try_backends`~~ — no shared helper; the two loops are duplicated today.
- `request.user.is_authenticated` is NOT a guest test: `BaseAuthBackend.remember()` sets it True (`abstract.py:300`). `_service_name == "anonymous"` is overridden by tests — do not use either (D1).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/backends/abstract.py", "action": "MODIFY"},
    {"path": "navigator_auth/backends/noauth.py", "action": "MODIFY"},
    {"path": "navigator_auth/decorators.py", "action": "MODIFY"},
    {"path": "tests/test_is_authenticated_backend_loop.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/abstract.py#BaseAuthBackend",
    "sym:navigator_auth/backends/noauth.py#NoAuth",
    "sym:navigator_auth/decorators.py#is_authenticated",
    "sym:navigator_auth/decorators.py#get_auth"
  ]
}
```

---

## Implementation Notes

### Decisions fixed for this task
- **D1**: check `getattr(backend, "_anonymous_auth", False)` **before** calling `authenticate()`, so
  NoAuth never runs and never creates a guest session.
- **D2**: a non-`AuthException` is logged with `logger.exception(...)` naming the backend (never a
  token, header or credential) and the loop continues; 401 if nothing succeeds.
- **`web.HTTPException` is re-raised, not swallowed** — decided here: it is deliberate HTTP control
  flow (a backend redirecting or refusing), not a crash; today it propagates and D2 targets crashes
  such as S1's `TypeError`. Re-raising keeps that behaviour and can never grant access.
- Order of handlers inside the loop: `MfaSignal` (stop) → `AuthException` (next) → `web.HTTPException`
  (re-raise) → `Exception` (log + next). `MfaSignal` subclasses `AuthException`, so it must come first.

### Key Constraints
- Use the module `logger` (`decorators.py:9`), not `print`.
- Both wrappers must call the helper — the point is that the loops can no longer drift.

---

## Implementation Blueprint

### Steps (in order)
1. Confirm FEAT-106 is in the base: `grep -c 'MfaSignal' navigator_auth/decorators.py` must be ≥ 3.
   If it is 0, **stop** — the spec requires FEAT-106 merged first.
2. Add the two class flags — *why*: D1.
3. Add the helper above `is_authenticated` — *why*: one loop for both wrappers.
4. Replace each wrapper's loop with the helper call — *why*: AC6–AC8 for function and class-based handlers.
5. Write the tests and run them with the unchanged exclude-list tests (AC9).

### `navigator_auth/backends/abstract.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '_external_auth: bool = False' navigator_auth/backends/abstract.py)
# AFTER — insert below `_external_auth: bool = False` (verified: navigator_auth/backends/abstract.py:79)
    #: True for backends that authenticate *anyone* (a guest). @is_authenticated never
    #: calls them; anonymous access goes through the exclude list / allow_anonymous.
    _anonymous_auth: bool = False
```

### `navigator_auth/backends/noauth.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '_service_name: str = "anonymous"' navigator_auth/backends/noauth.py)
# AFTER — insert below `_service_name: str = "anonymous"` (verified: navigator_auth/backends/noauth.py:28)
    _anonymous_auth: bool = True
```

### `navigator_auth/decorators.py` (MODIFY) — helper
```python
# occurrences: 1 (verified: grep -c 'def is_authenticated(content_type: str = "application/json") -> Callable\[\[F\], F\]:' navigator_auth/decorators.py)
# BEFORE — insert above `def is_authenticated(content_type: str = "application/json") -> Callable[[F], F]:` (verified: :179)
async def _authenticate_with_backends(auth: Any, request: web.Request) -> Optional[Any]:
    """Try each configured backend in order (FEAT-108).

    - backend with ``_anonymous_auth`` → skipped, never called (D1);
    - ``MfaSignal`` (FEAT-106) → stop, return None;
    - other ``AuthException`` → next backend;
    - ``web.HTTPException`` → re-raised (deliberate HTTP control flow, unchanged);
    - any other exception → ``logger.exception`` (backend name, no credential) → next backend (D2);
    - falsy result or ``web.StreamResponse`` (IdP redirect) → next backend.

    Returns the first remaining truthy result, else None (the wrappers then raise their 401).
    """
    for name, backend in auth.backends.items():
        if getattr(backend, "_anonymous_auth", False):
            continue
        try:
            result = await backend.authenticate(request)
        except MfaSignal:
            # FEAT-106 R2: a second factor is owed — no other backend may authenticate this request.
            return None
        except AuthException:
            continue
        except web.HTTPException:
            raise
        except Exception:  # pylint: disable=W0703
            logger.exception("is_authenticated: backend %s failed; trying the next one", name)
            continue
        if not result or isinstance(result, web.StreamResponse):
            # A redirect to an external IdP is the start of an interactive login, not a credential.
            continue
        return result
    return None
```

### `navigator_auth/decorators.py` (MODIFY) — function wrapper
```python
# occurrences: 2 (verified: grep -c 'for _, backend in auth.backends.items():' navigator_auth/decorators.py)
# FILL IN: disambiguate — replace the FIRST occurrence, inside `_func_wrapper`, identified by its
# 16-space indentation and the context (dev :213-215 / FEAT-106 :213-215):
#                 auth = get_auth(app)
#                 userdata = None
#                 for _, backend in auth.backends.items():
# Replace from `userdata = None` through the loop's final `break` (dev :214-228 / FEAT-106 :214-232) WITH:
                userdata = await _authenticate_with_backends(auth, request)
# Leave the following `if userdata: ... else: raise web.HTTPUnauthorized(...)` untouched.
```

### `navigator_auth/decorators.py` (MODIFY) — method wrapper
```python
# FILL IN: disambiguate — the SECOND occurrence, inside `_method_wrapper`, 12-space indentation, context
# (dev :257-259 / FEAT-106 :261-263):
#             auth = get_auth(app)
#             userdata = None
#             for _, backend in auth.backends.items():
# Replace from `userdata = None` through the loop's final `break` (dev :258-269 / FEAT-106 :262-273) WITH:
            userdata = await _authenticate_with_backends(auth, request)
```

### `tests/test_is_authenticated_backend_loop.py` (CREATE)
```python
"""FEAT-108 M4 — @is_authenticated backend loop (D1, D2, FEAT-106 MfaSignal)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web

from navigator_auth.backends.abstract import BaseAuthBackend
from navigator_auth.backends.noauth import NoAuth
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY
from navigator_auth.decorators import is_authenticated
from navigator_auth.exceptions import MfaSignal


def _backend(*, result=None, raises=None, anonymous=False) -> MagicMock:
    backend = MagicMock()
    backend._anonymous_auth = anonymous
    backend.authenticate = AsyncMock(return_value=result, side_effect=raises)
    return backend


def _request(backends: dict) -> MagicMock:
    """Mock request (pattern: tests/unit/test_is_authenticated_exclude.py:17-31) plus app['auth']."""
    req = MagicMock(spec=web.Request)
    req.method = "GET"
    req.path = "/api/v1/me"
    req.app = {AUTH_EXCLUDE_LIST_KEY: [], "auth": MagicMock(backends=backends)}
    req.get = lambda key, default=None: default
    req.allow_anonymous = False
    return req


def test_noauth_class_flag():
    assert NoAuth._anonymous_auth is True
    assert BaseAuthBackend._anonymous_auth is False


@pytest.mark.asyncio
async def test_anonymous_backend_is_never_called():
    guest = _backend(result={"user": "guest"}, anonymous=True)
    handler = AsyncMock(return_value=web.Response(status=200))
    with pytest.raises(web.HTTPUnauthorized):
        await is_authenticated()(handler)(_request({"NoAuth": guest}))
    guest.authenticate.assert_not_awaited()
    handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_unexpected_error_is_logged_and_skipped():
    first = _backend(raises=TypeError("'bool' object is not subscriptable"))
    second = _backend(result={"user": "demo"})
    handler = AsyncMock(return_value=web.Response(status=200))
    with patch("navigator_auth.decorators.logger") as log:
        response = await is_authenticated()(handler)(_request({"A": first, "B": second}))
    assert response.status == 200
    log.exception.assert_called_once()
    # FILL IN: assert the logged args name the backend ("A") and contain no token — bounded by AC7.


@pytest.mark.asyncio
async def test_unexpected_error_only_backend_gives_401():
    only = _backend(raises=TypeError("boom"))
    with pytest.raises(web.HTTPUnauthorized):
        await is_authenticated()(AsyncMock())(_request({"A": only}))


@pytest.mark.asyncio
async def test_mfa_signal_still_stops_the_loop():
    first = _backend(raises=MfaSignal)  # FILL IN: construct MfaSignal with the args its FEAT-106 __init__ requires
    second = _backend(result={"user": "demo"})
    with pytest.raises(web.HTTPUnauthorized):
        await is_authenticated()(AsyncMock())(_request({"A": first, "B": second}))
    second.authenticate.assert_not_awaited()


@pytest.mark.asyncio
async def test_method_wrapper_same_semantics():
    """AC7/AC8 on a class-based view (pattern: tests/unit/test_is_authenticated_exclude.py:175)."""
    # FILL IN: decorate a class with an async `get(self)`; give an instance `.request = _request(...)`;
    #          repeat the anonymous-skip, error-skip and MfaSignal cases — bounded by AC6–AC8.
```

### FILL IN checklist
- [ ] Function-wrapper and method-wrapper replacements at the disambiguated anchors.
- [ ] `test_unexpected_error_is_logged_and_skipped` — log names backend, no credential; AC7.
- [ ] `MfaSignal(...)` construction per its FEAT-106 signature; AC8.
- [ ] `test_method_wrapper_same_semantics`; AC6–AC8.

---

## Acceptance Criteria

- [ ] AC6: a backend with `_anonymous_auth = True` is never called; `NoAuth` sets it; with `[Oauth2Provider-like, NoAuth]` a request without credentials gets 401.
- [ ] AC7: a non-`AuthException` from one backend is logged with `logger.exception` (backend name only) and the loop continues; 401 (never 500) when nothing succeeds — function handlers and class-based views.
- [ ] AC8: `MfaSignal` still stops the loop with 401.
- [ ] AC9: `tests/unit/test_is_authenticated_exclude.py` passes unchanged.
- [ ] `ruff check` clean on the four files.

---

## Validation Commands

- `pytest tests/test_is_authenticated_backend_loop.py -q`
- `pytest tests/unit/test_is_authenticated_exclude.py -q`

---

## Test Specification

Spec §4, M4: `test_anonymous_backend_is_never_called`, `test_noauth_class_flag`,
`test_unexpected_error_is_logged_and_skipped`, `test_unexpected_error_only_backend_gives_401`,
`test_mfa_signal_still_stops_the_loop`, `test_method_wrapper_same_semantics` (CREATE block above).
`test_existing_guest_sessions_rejected` is added to this file by TASK-202.

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
7. **Verify** — run the Validation Commands.
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`).
9. **Close the task** with `parrot sdd task close TASK-198 oauth2-3lo-issues verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none
