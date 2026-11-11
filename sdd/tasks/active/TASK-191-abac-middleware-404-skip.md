# TASK-191: `abac_middleware` 404 skip fix and DEBUG log level

**Feature**: FEAT-109 — PBAC example policy issues
**Spec**: `sdd/specs/policy-issues.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Browser probes (`/favicon.ico`, `/.well-known/...`, `/client-config`) log
`Access to <path> is not Authenticated.` at WARNING (spec §1 problem 2). The cause is a bug, not
missing exclusions: `abac_middleware` wraps the system-route skip in
`try: ... return await handler(request) except Exception: pass`, so the `HTTPNotFound` raised by
aiohttp's 404 handler is swallowed, the request falls through to the WARNING, and the 404 handler
runs a **second** time. Reproduced at task time (aiohttp 3.14.3): today the handler chain runs
twice for `/favicon.ico` and one WARNING is emitted.

This task implements spec §3 **Module 3**. `EXCLUDE_DEFAULTS` is deliberately **not** changed
(the exclude list also bypasses authentication — spec §7 Design Decisions).

---

## Scope

- Add `_is_system_route(request) -> bool` (guarded read of `request.match_info.route`; never calls the handler).
- Replace the `try/except Exception: pass` skip (middleware.py:27-32) with
  `if _is_system_route(request): return await handler(request)` — handler awaited outside any `try`.
- Log the unauthenticated pass-through at DEBUG (middleware.py:43).
- Remove the duplicated, unreachable second `except (TypeError, KeyError)` clause (middleware.py:53-57).
- Write `tests/test_abac_middleware_404.py`.

**NOT in scope**: adding `/favicon.ico` or `/.well-known/*` to `EXCLUDE_DEFAULTS`
(`navigator_auth/conf.py:63-68`) — explicitly rejected; changing the order of the skips; changing
`protected_paths` / `probes`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/middleware.py` | MODIFY | `_is_system_route` helper, 404 skip outside `try`, DEBUG level, one except clause |
| `tests/test_abac_middleware_404.py` | CREATE | 404 / log-level regression tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` HEAD `c5403d4` on 2026-11-11.

### Verified Imports
```python
# already in middleware.py (lines 1-6) — no new imports needed
from collections.abc import Awaitable, Callable
import fnmatch
from aiohttp import web, hdrs
from aiohttp.web_urldispatcher import SystemRoute        # verified: abac/middleware.py:4
from navconfig.logging import logging                    # verified: abac/middleware.py:5 (stdlib-style root logger calls)
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY    # verified: abac/middleware.py:6
# tests
from aiohttp.test_utils import TestClient, TestServer    # verified: tests/test_protected_paths.py:15
from navigator_auth.abac.middleware import abac_middleware  # verified: abac/middleware.py:16
from navigator_auth.conf import EXCLUDE_DEFAULTS          # verified: conf.py:63
```

### Existing Signatures to Use
```python
# navigator_auth/abac/middleware.py
exceptions = ("/api/v1/abac/authorize", "/api/v1/abac/is_allowed", "/api/v1/abac/reload")  # lines 9-13
@web.middleware
async def abac_middleware(request, handler) -> web.StreamResponse: ...  # lines 15-58
#   27-32: try: if isinstance(request.match_info.route, SystemRoute): return await handler(request)
#          except Exception: pass                      <-- swallows HTTPNotFound (bug)
#   43:    logging.warning(f'Access to {request.path} is not Authenticated.')
#   48-57: two identical `except (TypeError, KeyError) as ex:` clauses (48 and 53; second unreachable)
```
Edit-site anchors (re-verified): `        if isinstance(request.match_info.route, SystemRoute):  # eg. 404`
→ 1 occurrence (line 29); the `logging.warning(f'Access to ...` line → 1 (line 43);
`    except (TypeError, KeyError) as ex:` → **2** (lines 48, 53).

### Does NOT Exist
- ~~`navigator_auth.abac.middleware._is_system_route`~~ — added by this task.
- ~~`/favicon.ico`, `/.well-known/*` in `EXCLUDE_DEFAULTS`~~ — intentionally not added.
- ~~`pytest-aiohttp` `aiohttp_client` fixture usage in this repo's ABAC tests~~ — use `TestClient(TestServer(app))` + `@pytest.mark.asyncio` (pattern: `tests/test_protected_paths.py:156-160`).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/abac/middleware.py", "action": "MODIFY"},
    {"path": "tests/test_abac_middleware_404.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/abac/middleware.py#abac_middleware"
  ]
}
```

---

## Delegation Contract

The design is complete and was validated at `/sdd-task` time in a scratch copy: the test file
below fails 4/5 against the current middleware (2 handler calls + a WARNING for `/favicon.ico`,
WARNING level for `/routed`, no helper, 2 except clauses) and, with the new middleware, it passes
together with `tests/test_abac_middleware_order.py`, `tests/test_protected_paths.py` and
`tests/test_probes.py` (94 passed). The middleware was restored afterwards (hash unchanged).

```json
{
  "schema_version": 1,
  "task_id": "TASK-191",
  "spec_path": "sdd/specs/policy-issues.spec.md",
  "design_complete": true,
  "targets": [
    {
      "path": "navigator_auth/abac/middleware.py",
      "action": "modify",
      "expected_sha256": "dec8a4f6177d89baeb968c6f9149e0ab2529e25f2f6289b8d61a8ed7649920d8",
      "planned_changes": "Add _is_system_route(); await the 404 handler outside any try; log the unauthenticated pass-through at DEBUG; drop the unreachable second except (TypeError, KeyError) clause",
      "blocks": ["impl-middleware"]
    },
    {
      "path": "tests/test_abac_middleware_404.py",
      "action": "create",
      "expected_sha256": null,
      "planned_changes": "Regression tests: single 404 handler call with no WARNING, DEBUG level for unauthenticated routed requests, helper fail-safe, one except clause, EXCLUDE_DEFAULTS unchanged",
      "blocks": ["impl-test-404"]
    }
  ],
  "references": [
    {
      "path": "navigator_auth/abac/middleware.py",
      "sha256": "dec8a4f6177d89baeb968c6f9149e0ab2529e25f2f6289b8d61a8ed7649920d8",
      "start_line": 15,
      "end_line": 58,
      "purpose": "current abac_middleware with the swallowed-404 bug and duplicated except clause"
    }
  ],
  "implementation_blocks": ["impl-middleware", "impl-test-404"],
  "acceptance_criteria": [
    "GET /favicon.ico through abac_middleware returns 404, the handler chain runs once, and no WARNING is logged",
    "An unauthenticated routed request (GET /routed) logs its 'is not Authenticated.' line at DEBUG only",
    "abac_middleware contains exactly one except (TypeError, KeyError) clause",
    "EXCLUDE_DEFAULTS does not gain /favicon.ico or /.well-known entries",
    "pytest tests/test_abac_middleware_404.py tests/test_abac_middleware_order.py tests/test_protected_paths.py tests/test_probes.py passes"
  ],
  "validation_commands": [
    ["pytest", "tests/test_abac_middleware_404.py", "-q"],
    ["pytest", "tests/test_abac_middleware_order.py", "-q"],
    ["pytest", "tests/test_protected_paths.py", "-q"],
    ["pytest", "tests/test_probes.py", "-q"]
  ]
}
```

```python id=impl-middleware
# Apply to navigator_auth/abac/middleware.py: replace the whole file with the content below.
from collections.abc import Awaitable, Callable
import fnmatch
from aiohttp import web, hdrs
from aiohttp.web_urldispatcher import SystemRoute
from navconfig.logging import logging
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY


exceptions = (
    "/api/v1/abac/authorize",
    "/api/v1/abac/is_allowed",
    "/api/v1/abac/reload"
)


def _is_system_route(request: web.Request) -> bool:
    """Tell whether aiohttp resolved the request to a SystemRoute (404/405).

    Args:
        request: The incoming request.

    Returns:
        True when ``request.match_info.route`` is a ``SystemRoute``. Any error
        while reading the route returns False. Never calls the handler.
    """
    try:
        return isinstance(request.match_info.route, SystemRoute)
    except Exception:  # pylint: disable=W0703
        return False


@web.middleware
async def abac_middleware(
    request: web.Request,
    handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
) -> web.StreamResponse:
    """
    Basic AUthorizacion/Access Middleware.
    Description: Authorization/Access Middleware for ABAC
    """
    # avoid authorization backend on excluded methods:
    if request.method == hdrs.METH_OPTIONS:
        return await handler(request)
    # avoid check system routes (eg. 404). The handler runs outside any try:
    # its HTTPNotFound must propagate instead of falling through to a 2nd call.
    if _is_system_route(request):
        return await handler(request)
    # avoid authorization on exclude list (per-app, not global)
    for pattern in request.app.get(AUTH_EXCLUDE_LIST_KEY, ()):
        if fnmatch.fnmatch(request.path, pattern):
            return await handler(request)
    # avoid authorization on exceptions
    if request.path in exceptions:
        return await handler(request)
    logging.debug(' == ABAC MIDDLEWARE == ')
    ### verify if request is authenticated
    if request.get('authenticated', False) is False:
        logging.debug(f'Access to {request.path} is not Authenticated.')
        return await handler(request)
    ### get Guardian:
    try:
        response = await request.app['security'].authorize(request=request)
    except (TypeError, KeyError) as ex:
        ### there is no ABAC access backend enabled:
        logging.warning(
            f'ABAC Warning: there is no backend installed on this system: {ex}'
        )
    return await handler(request)
```

```python id=impl-test-404 path=tests/test_abac_middleware_404.py
"""abac_middleware skips unrouted (404) requests cleanly and logs at DEBUG (FEAT-109 M3)."""
import inspect
import logging

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from navigator_auth.abac import middleware as abac_mw
from navigator_auth.abac.middleware import abac_middleware
from navigator_auth.conf import EXCLUDE_DEFAULTS


def _app(calls: list) -> web.Application:
    """Build an app whose inner middleware records each pass through the handler chain."""

    @web.middleware
    async def count_calls(request, handler):
        calls.append(request.path)
        return await handler(request)

    async def ok(request):
        return web.Response(text="ok")

    app = web.Application(middlewares=[abac_middleware, count_calls])
    app.router.add_get("/routed", ok)
    return app


@pytest.mark.asyncio
async def test_unrouted_path_no_warning_single_call(caplog):
    """GET of an unrouted path: 404, no WARNING, the 404 handler runs once."""
    caplog.set_level(logging.DEBUG)
    calls: list = []
    async with TestClient(TestServer(_app(calls))) as client:
        response = await client.get("/favicon.ico")
        assert response.status == 404
    assert calls == ["/favicon.ico"]
    noisy = [
        r for r in caplog.records
        if r.levelno >= logging.WARNING and "not Authenticated" in r.getMessage()
    ]
    assert noisy == []


@pytest.mark.asyncio
async def test_unauthenticated_routed_logs_debug(caplog):
    """An unauthenticated routed request is logged once, at DEBUG."""
    caplog.set_level(logging.DEBUG)
    calls: list = []
    async with TestClient(TestServer(_app(calls))) as client:
        response = await client.get("/routed")
        assert response.status == 200
    assert calls == ["/routed"]
    levels = [
        r.levelno for r in caplog.records
        if "Access to /routed is not Authenticated." in r.getMessage()
    ]
    assert levels == [logging.DEBUG]


def test_is_system_route_false_when_route_unreadable():
    """An error while reading match_info means 'not a system route'."""

    class _Broken:
        @property
        def match_info(self):
            raise RuntimeError("no match info")

    assert abac_mw._is_system_route(_Broken()) is False


def test_single_type_key_except_clause():
    """The duplicated, unreachable except clause is gone."""
    source = inspect.getsource(abac_mw.abac_middleware)
    assert source.count("except (TypeError, KeyError)") == 1


def test_exclude_defaults_unchanged():
    """Probe paths are not added to the default auth exclude list."""
    assert "/favicon.ico" not in EXCLUDE_DEFAULTS
    assert not any(path.startswith("/.well-known") for path in EXCLUDE_DEFAULTS)
```

---

## Implementation Notes

### Key Constraints
- Keep the skip order: OPTIONS → system route → exclude list → ABAC endpoints → unauthenticated → Guardian.
- `response = await request.app['security'].authorize(...)` stays as-is (unused variable pre-exists; not this task).
- `caplog` sees the root-logger records emitted through `navconfig.logging.logging`.

### References in Codebase
- `tests/test_protected_paths.py:156-197` — `TestClient(TestServer(...))` + `caplog` pattern.

---

## Implementation Blueprint

> The Delegation Contract blocks above **are** the blueprint: `impl-middleware` is the complete new
> `navigator_auth/abac/middleware.py`, `impl-test-404` the complete test file.

### Steps (in order)
1. Confirm `sha256sum navigator_auth/abac/middleware.py` equals `expected_sha256` — *why*: the
   replacement block was derived from that exact content; if it moved, re-derive the edits below
   instead of overwriting.
2. Write `impl-middleware` over `navigator_auth/abac/middleware.py` — *why*: spec §3 M3 skeleton.
3. Write `impl-test-404` to `tests/test_abac_middleware_404.py`.
4. Run the Validation Commands.

### `navigator_auth/abac/middleware.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '        if isinstance(request.match_info.route, SystemRoute):  # eg. 404' navigator_auth/abac/middleware.py)
# occurrences: 2 (verified: grep -c '    except (TypeError, KeyError) as ex:' navigator_auth/abac/middleware.py)
#   -> disambiguated: remove the SECOND clause, i.e. the one directly after the first block's
#      `logging.warning(... {ex}' \n        )` (lines 53-57), keeping lines 48-52.
# Full replacement content: Delegation Contract block `impl-middleware`.
```
**Why**: if the hash check fails, apply the same three edits by hand at the anchors above
(helper above `@web.middleware`; lines 27-32 → `if _is_system_route(request): return await handler(request)`;
line 43 `logging.warning` → `logging.debug`; delete lines 53-57).

### `tests/test_abac_middleware_404.py` (CREATE)
Content: Delegation Contract block `impl-test-404`.

### FILL IN checklist
- [ ] none — design complete (only the hash check in Step 1 can route this to manual edits)

---

## Acceptance Criteria

- [ ] GET of an unrouted path through `abac_middleware` returns 404, emits no WARNING, and runs the 404 handler once.
- [ ] Unauthenticated routed requests log at DEBUG.
- [ ] Only one `except (TypeError, KeyError)` remains in `abac_middleware`.
- [ ] `EXCLUDE_DEFAULTS` (`navigator_auth/conf.py:63-68`) is unchanged.
- [ ] All Validation Commands pass.

---

## Validation Commands
- `pytest tests/test_abac_middleware_404.py -q`
- `pytest tests/test_abac_middleware_order.py -q`
- `pytest tests/test_protected_paths.py -q`
- `pytest tests/test_probes.py -q`

---

## Test Specification

The complete test file is the Delegation Contract block `impl-test-404` above.

---

## Agent Instructions

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug policy-issues --feature-id FEAT-109`).
2. **Read the spec** (§1 problem 2, §3 Module 3, §7 Design Decisions "No probe-path exclusions").
3. **Check dependencies** — none.
4. **Verify the Codebase Contract** and the `expected_sha256`.
5. **Update status** in `sdd/tasks/index/policy-issues.json` → `"in-progress"` (set `started_at`).
6. **Implement** from the Delegation Contract blocks.
7. **Verify** — run the Validation Commands.
8. **Commit the code** — stage only the files listed above.
9. **Close the task** with `parrot sdd task close TASK-191 policy-issues verified`.
10. **Fill in the Completion Note**, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any
