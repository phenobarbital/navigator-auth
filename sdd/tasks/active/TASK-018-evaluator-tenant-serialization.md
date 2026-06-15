# TASK-018: Evaluator tenant serialization + request injection + cache key

**Feature**: per-tenant-policy-scoping (FEAT-092)
**Spec**: `sdd/specs/per-tenant-policy-scoping.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-016
**Assigned-to**: unassigned

---

## Context

The `PolicyEvaluator` serializes policies to JSON for the Rust engine and builds
the per-request `user_ctx`/cache key. This task makes both tenant-aware and
**freezes the JSON contract** that TASK-020 (Rust) consumes. Implements
**Module 3**.

---

## Scope

- `_serialize_policies_from_index`: add `"org_id"` and `"client_id"` to each
  policy JSON object (read from `policy.org_id` / `policy.client_id`).
- `check_access` and `filter_resources`: add `org_id: int = 1, client_id: int = 1`
  params; place them on the `user_ctx` dict passed to Rust
  (`user_ctx["org_id"]`, `user_ctx["client_id"]`).
- `_make_cache_key`: include `org_id`/`client_id` so two tenants never share a
  cached decision (**security requirement**, not optimization).

**NOT in scope**: who supplies the request tenant (TASK-019 resolves it from
request/headers/session); Rust matching (TASK-020).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/policies/evaluator.py` | MODIFY | JSON tenant fields, tenant params, tenant-aware cache key |

---

## Implementation Notes

### JSON contract (must match TASK-020 Rust `PolicyDef`)
```python
policies_data.append({
    "name": policy.name,
    "effect": "allow" if policy.effect == PolicyEffect.ALLOW else "deny",
    "resources": [...],
    "actions": list(policy._actions),
    "subjects": {...},
    "conditions": {...},
    "priority": policy.priority,
    "enforcing": policy.enforcing,
    "org_id": getattr(policy, "org_id", 1),       # NEW
    "client_id": getattr(policy, "client_id", 1), # NEW
})
```

### Request tenant injection
```python
def check_access(self, ctx, resource_type, resource_name, action,
                 env=None, owner_reports_to=None, org_id=1, client_id=1):
    ...
    user_ctx = self._build_user_context(ctx)
    user_ctx["action"] = action
    user_ctx["org_id"] = int(org_id)
    user_ctx["client_id"] = int(client_id)
    ...
    cache_key = self._make_cache_key(user_id, user_groups, resource_type,
                                     resource_name, action, env_dict=env_dict,
                                     org_id=org_id, client_id=client_id)
```
Do the same on `filter_resources` (no cache there today, just inject into `user_ctx`).

### Key Constraints
- `getattr(policy, "org_id", 1)` keeps the path safe if an old policy object lacks
  the attribute.
- Cache key change is mandatory for tenant isolation — add the dedicated test.

### References in Codebase
- `navigator_auth/abac/policies/evaluator.py:229-253` — serialization.
- `evaluator.py:304-318` — `_make_cache_key`.
- `evaluator.py:361-441` — `check_access`. `evaluator.py:443-494` — `filter_resources`.

---

## Acceptance Criteria

- [ ] Serialized JSON contains `org_id`/`client_id` for every policy.
- [ ] `check_access`/`filter_resources` accept and forward `org_id`/`client_id`.
- [ ] Cache keys differ when only `org_id` (or `client_id`) differs.
- [ ] Default call (no tenant args) behaves identically to today.
- [ ] `pytest tests/ -v -k "policy or evaluator"` passes.

---

## Test Specification

```python
import json
from navigator_auth.abac.policies.evaluator import PolicyEvaluator
from navigator_auth.abac.policies.resource_policy import ResourcePolicy

def test_serialize_includes_tenant():
    ev = PolicyEvaluator()
    ev.load_policies([ResourcePolicy(name="p", resources=["tool:*"], org_id=5, client_id=3)])
    data = json.loads(ev._policies_json)
    assert data[0]["org_id"] == 5 and data[0]["client_id"] == 3

def test_cache_key_tenant_isolation():
    ev = PolicyEvaluator()
    k1 = ev._make_cache_key("u", {"eng"}, "tool", "jira", "tool:execute", org_id=1, client_id=1)
    k2 = ev._make_cache_key("u", {"eng"}, "tool", "jira", "tool:execute", org_id=5, client_id=1)
    assert k1 != k2
```

---

## Agent Instructions

1. Read the spec (Module 3). 2. Verify TASK-016 in `completed/`.
3. Index → `in-progress`. 4. Implement, freezing the JSON shape for TASK-020.
5. Verify. 6. Move to `completed/`, index → `done`. 7. Fill Completion Note.

---

## Completion Note

**Completed by**:
**Date**:
**Notes**:
**Deviations from spec**: none
