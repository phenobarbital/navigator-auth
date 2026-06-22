# TASK-014: Middleware PolicyEvaluator Integration

**Feature**: migrate-classic-policies-abac-rust
**Spec**: `sdd/specs/migrate-classic-policies-abac-rust.spec.md`
**Status**: in-progress
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-011
**Assigned-to**: session-middleware-task

---

## Context

> Spec Module 6. The ABAC middleware needs to make the PolicyEvaluator accessible to
> request handlers via `request.app['policy_evaluator']`. The middleware evaluation flow
> already goes through PDP (which now delegates to the evaluator), but handlers need
> direct access for resource-level checks (e.g., tool permissions, dataset access).

---

## Scope

- During PDP startup/setup, register the evaluator on the aiohttp app:
  `app['policy_evaluator'] = pdp.evaluator`.
- Verify middleware `authorize()` flow works end-to-end with the new PDP delegation.
- Write a simple integration test showing a handler accessing `request.app['policy_evaluator']`
  and calling `check_access()` or `filter_resources()`.

**NOT in scope**: Changing the middleware flow itself (it still calls `Guardian.authorize()`),
PDP changes (already done in TASK-011), Rust changes.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/pdp.py` | MODIFY | Register evaluator on app during setup |
| `navigator_auth/abac/middleware.py` | MODIFY | Minor: ensure evaluator is accessible (if not via app already) |
| `tests/test_middleware_integration.py` | CREATE | Integration tests |

---

## Implementation Notes

### Pattern to Follow

```python
# In PDP.setup() or on_startup callback
class PDP:
    async def on_startup(self, app):
        await self._load_policies()
        # Register evaluator for handler-level access
        app['policy_evaluator'] = self._evaluator

# Handler usage pattern (for documentation / test)
async def my_handler(request):
    evaluator = request.app['policy_evaluator']
    ctx = EvalContext(request=request, ...)
    result = evaluator.check_access(
        ctx, ResourceType.TOOL, "jira_create", "tool:execute"
    )
    if not result.allowed:
        raise web.HTTPForbidden()
    # proceed...
```

### Key Constraints
- The evaluator registration must happen after `_load_policies()` completes.
- `request.app['policy_evaluator']` must be the same instance the PDP uses (not a copy).
- The middleware flow is unchanged: `middleware -> Guardian.authorize() -> PDP.authorize()`.
  This task only adds the app-level reference for direct handler access.

### References in Codebase
- `navigator_auth/abac/middleware.py:46-47` — current `request.app['security'].authorize()`
- `navigator_auth/abac/pdp.py` — PDP setup/on_startup pattern
- `navigator_auth/abac/guardian.py:49-65` — Guardian.authorize() flow

---

## Acceptance Criteria

- [ ] `request.app['policy_evaluator']` is set during PDP startup
- [ ] The evaluator reference is the same instance used by PDP
- [ ] A handler can call `request.app['policy_evaluator'].check_access()` successfully
- [ ] A handler can call `request.app['policy_evaluator'].filter_resources()` successfully
- [ ] Middleware authorize flow works end-to-end with PDP delegation
- [ ] All tests pass: `pytest tests/test_middleware_integration.py -v`

---

## Test Specification

```python
import pytest
from navigator_auth.abac.policies.resources import ResourceType


class TestMiddlewareIntegration:
    async def test_evaluator_on_app(self, app_with_abac):
        """PolicyEvaluator is registered on app."""
        assert 'policy_evaluator' in app_with_abac

    async def test_handler_check_access(self, aiohttp_client, app_with_abac):
        """Handler can use policy_evaluator for resource checks."""
        client = await aiohttp_client(app_with_abac)
        # Make authenticated request, handler uses evaluator
        resp = await client.get("/test/protected")
        assert resp.status in (200, 403)

    async def test_middleware_authorize_flow(self, aiohttp_client, app_with_abac):
        """Full middleware -> PDP -> Evaluator -> Rust flow."""
        client = await aiohttp_client(app_with_abac)
        resp = await client.get("/api/v1/admin/")
        # Verify policy evaluation happened
```

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify `Depends-on` tasks are in `tasks/completed/`
3. **Update status** in `tasks/.index.json` -> `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `tasks/completed/TASK-014-middleware-integration.md`
7. **Update index** -> `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

**Completed by**: session-middleware-task
**Date**: 2026-04-03
**Notes**: Integrated `PolicyEvaluator` into the aiohttp middleware flow.
- Added `app['policy_evaluator'] = self._evaluator` in `PDP.on_startup` to make the evaluator accessible to all handlers.
- Fixed a bug in `Guardian.get_user` where `self._logger` was used instead of the module-level `logger`.
- Fixed a bug in `navigator_auth/abac/errors.py` where the deprecated `body` argument was used in `web.HTTPError` subclasses, causing test failures in strict mode.
- Verified that handlers can successfully access `policy_evaluator` and perform `check_access` and `filter_resources` calls.
- Verified that the main middleware authorization flow works end-to-end.

**Deviations from spec**: Also fixed a few unrelated bugs in `guardian.py` and `errors.py` that were blocking integration tests.
