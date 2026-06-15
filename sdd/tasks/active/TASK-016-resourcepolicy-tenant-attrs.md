# TASK-016: ResourcePolicy tenant attributes (org_id / client_id)

**Feature**: per-tenant-policy-scoping (FEAT-092)
**Spec**: `sdd/specs/per-tenant-policy-scoping.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Foundational data-contract change for FEAT-092. Every policy must carry a tenant
pair so downstream layers (adapter → evaluator JSON → Rust) can scope decisions.
Implements **Module 1** of the spec. `1` is the reserved global/inheritable
sentinel (matches the existing `auth.policies` column defaults).

---

## Scope

- Add `org_id: int = 1` and `client_id: int = 1` constructor params to
  `ResourcePolicy.__init__`, stored as `self.org_id` / `self.client_id`.
- Defaults preserve current behaviour: a policy created without tenant args is
  global (`1`/`1`).
- No change to pure-Python matching methods (`covers_resource`, `matches_subject`,
  `evaluate_conditions`, `evaluate`) — tenant filtering happens in the Rust engine.

**NOT in scope**: adapter wiring (TASK-017), JSON serialization (TASK-018), Rust
(TASK-020), request-side resolution (TASK-019).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/policies/resource_policy.py` | MODIFY | Add `org_id`/`client_id` params + attrs |

---

## Implementation Notes

### Pattern to Follow
`ResourcePolicy.__init__` already accepts `**kwargs` and forwards to the parent.
Add the two params before `**kwargs` and assign before `super().__init__(...)`:

```python
def __init__(self, name, effect=PolicyEffect.ALLOW, ..., enforcing=False,
             org_id: int = 1, client_id: int = 1, **kwargs):
    ...
    self.org_id = org_id
    self.client_id = client_id
    super().__init__(name=name, ..., enforcing=enforcing, **kwargs)
```

### Key Constraints
- Keep defaults at `1` (global) — never `0`/`None`.
- Do not break the existing positional/keyword call sites in `adapter.py` and
  `evaluator.py` (they pass keyword args).

### References in Codebase
- `navigator_auth/abac/policies/resource_policy.py:27-78` — constructor.
- `navigator_auth/abac/storages/pg.py:58-59` — column defaults (`org_id`/`client_id` = 1).

---

## Acceptance Criteria

- [ ] `ResourcePolicy(name="x").org_id == 1 and .client_id == 1`.
- [ ] `ResourcePolicy(name="x", org_id=5, client_id=3)` stores `5`/`3`.
- [ ] Existing policy tests still pass: `pytest tests/ -v -k policy`.
- [ ] `ruff check navigator_auth/abac/policies/resource_policy.py` clean.

---

## Test Specification

```python
from navigator_auth.abac.policies.resource_policy import ResourcePolicy

def test_resourcepolicy_tenant_defaults():
    p = ResourcePolicy(name="p")
    assert p.org_id == 1 and p.client_id == 1

def test_resourcepolicy_tenant_explicit():
    p = ResourcePolicy(name="p", org_id=5, client_id=3)
    assert (p.org_id, p.client_id) == (5, 3)
```

---

## Agent Instructions

1. Read the spec (Module 1) for full context.
2. Update index → `in-progress` with your session ID.
3. Implement per scope.
4. Verify acceptance criteria.
5. Move this file to `tasks/completed/` and update index → `done`.
6. Fill the Completion Note.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**:
**Date**:
**Notes**:
**Deviations from spec**: none
