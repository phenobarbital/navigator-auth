# TASK-013: Policy Hot Reload

**Feature**: migrate-classic-policies-abac-rust
**Spec**: `sdd/specs/migrate-classic-policies-abac-rust.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-011, TASK-012
**Assigned-to**: unassigned

---

## Context

> Spec Module 5. Policy changes (especially DB-stored) must take effect without server
> restart. The spec decision is to use a polling interval (every 60 seconds) for DB
> reload, plus an explicit REST endpoint trigger. This task adds `PDP.reload_policies()`
> and `PolicyEvaluator.swap_index()`.

---

## Scope

- Add `PDP.reload_policies()` async method:
  - Re-loads policy dicts from DB storage and YAML storage.
  - Re-runs `PolicyAdapter.adapt_batch()` on all loaded dicts.
  - Builds a new `PolicyIndex` from resulting ResourcePolicies.
  - Calls `PolicyEvaluator.swap_index()` to atomically swap index and clear cache.
  - Returns count of loaded policies.
- Add `PolicyEvaluator.swap_index(new_index, new_policies_json)`:
  - Replace `self._index` with new index.
  - Replace `self._policies_json` with new JSON.
  - Clear `self._cache`.
  - Thread-safe via Python's GIL (atomic reference swap).
- Add REST endpoint `POST /api/v1/abac/reload` in `PolicyHandler` that triggers reload.
- Add optional periodic reload with configurable interval (default: disabled,
  configurable via `ABAC_RELOAD_INTERVAL` setting, e.g., 60 seconds).
- Write tests for reload flow.

**NOT in scope**: PostgreSQL LISTEN/NOTIFY, filesystem watchers, Rust changes.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/pdp.py` | MODIFY | Add `reload_policies()` method |
| `navigator_auth/abac/policies/evaluator.py` | MODIFY | Add `swap_index()` method |
| `navigator_auth/abac/policyhandler.py` | MODIFY | Add `POST /api/v1/abac/reload` endpoint |
| `tests/test_hot_reload.py` | CREATE | Tests for reload flow |

---

## Implementation Notes

### Pattern to Follow

```python
# In PDP
class PDP:
    async def reload_policies(self) -> int:
        """Hot-reload policies from DB/YAML without restart."""
        policy_dicts = []

        # Re-load from DB
        if self.storage:
            db_policies = await self.storage.load_policies()
            if db_policies:
                policy_dicts.extend(db_policies)

        # Re-load from YAML
        if self.yaml_storage:
            yaml_policies = self.yaml_storage.load_policies()
            if yaml_policies:
                policy_dicts.extend(yaml_policies)

        # Convert and swap
        resource_policies, warnings = PolicyAdapter.adapt_batch(policy_dicts)
        for w in warnings:
            self.logger.warning(f"Reload warning: {w}")

        # Build new index
        new_index = PolicyIndex()
        for p in resource_policies:
            new_index.add(p)

        # Serialize for Rust
        new_json = self._evaluator._serialize_policies_from_index(new_index)

        # Atomic swap
        self._evaluator.swap_index(new_index, new_json)
        self.logger.info(f"Hot-reloaded {len(resource_policies)} policies")
        return len(resource_policies)


# In PolicyEvaluator
class PolicyEvaluator:
    def swap_index(self, new_index: PolicyIndex, new_json: str) -> None:
        """Atomically swap policy index and clear cache."""
        self._index = new_index
        self._policies_json = new_json
        self._cache.clear()
        self._stats['cache_hits'] = 0
        self._stats['cache_misses'] = 0


# In PolicyHandler
class PolicyHandler:
    async def reload(self, request):
        """POST /api/v1/abac/reload — trigger policy hot-reload."""
        pdp = request.app.get('pdp')
        if not pdp:
            raise web.HTTPServiceUnavailable(text="PDP not available")
        count = await pdp.reload_policies()
        return web.json_response({"reloaded": count})
```

### Key Constraints
- `swap_index` must be a single-assignment swap (Python GIL guarantees atomicity of
  reference assignment).
- Clear cache atomically with index swap to prevent stale evaluations.
- The periodic reload should use `asyncio.create_task` with a loop, not a separate thread.
- The reload endpoint should require authentication (existing ABAC endpoint auth pattern).

### References in Codebase
- `navigator_auth/abac/pdp.py:63-81` — current `_load_policies()` to model reload after
- `navigator_auth/abac/policies/evaluator.py:256-264` — cache invalidation pattern
- `navigator_auth/abac/policyhandler.py` — existing REST endpoints to extend

---

## Acceptance Criteria

- [ ] `PDP.reload_policies()` re-loads from DB and YAML storage
- [ ] `PDP.reload_policies()` re-adapts and swaps evaluator index atomically
- [ ] `PolicyEvaluator.swap_index()` replaces index, JSON cache, and clears LRU cache
- [ ] `POST /api/v1/abac/reload` triggers reload and returns `{"reloaded": N}`
- [ ] After reload, new policies are used for subsequent evaluations
- [ ] In-flight requests using old index complete without errors
- [ ] Periodic reload works when `ABAC_RELOAD_INTERVAL` is configured
- [ ] All tests pass: `pytest tests/test_hot_reload.py -v`

---

## Test Specification

```python
import pytest
from unittest.mock import AsyncMock, MagicMock
from navigator_auth.abac.pdp import PDP


class TestHotReload:
    async def test_reload_swaps_policies(self):
        """After reload, new policies are active."""
        storage = MagicMock()
        storage.load_policies = AsyncMock(return_value=[
            {"name": "v1", "policy_type": "resource", "effect": "allow",
             "resources": ["tool:old_*"], "subjects": {"groups": ["*"]}}
        ])
        pdp = PDP(storage=storage)
        await pdp._load_policies()

        # Verify old policy is active
        # ...

        # Reload with new policies
        storage.load_policies = AsyncMock(return_value=[
            {"name": "v2", "policy_type": "resource", "effect": "allow",
             "resources": ["tool:new_*"], "subjects": {"groups": ["*"]}}
        ])
        count = await pdp.reload_policies()
        assert count == 1

        # Verify new policy is active
        # ...

    async def test_reload_clears_cache(self):
        """Reload clears the evaluator LRU cache."""
        # ...

    async def test_reload_endpoint(self, aiohttp_client):
        """POST /api/v1/abac/reload returns reload count."""
        # ...
```

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify `Depends-on` tasks are in `tasks/completed/`
3. **Update status** in `tasks/.index.json` -> `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `tasks/completed/TASK-013-hot-reload.md`
7. **Update index** -> `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any
