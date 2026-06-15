# TASK-017: PolicyAdapter carries tenant onto policies

**Feature**: per-tenant-policy-scoping (FEAT-092)
**Spec**: `sdd/specs/per-tenant-policy-scoping.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-016
**Assigned-to**: unassigned

---

## Context

Policies arrive at the PDP as dicts (from `pgStorage` / YAML) and are converted to
`ResourcePolicy` by `PolicyAdapter`. The adapter currently drops `org_id`/
`client_id`. This task threads the tenant pair through every adapter path.
Implements **Module 2**.

---

## Scope

- In `_adapt_resource`, `_adapt_classic`, `_adapt_object`, `_adapt_file`, read
  `org_id` and `client_id` from the policy dict (default `1`) and pass to the
  `ResourcePolicy(...)` constructor.
- The auto-generated `_negated` DENY policy (`adapter.py:205-217`) MUST inherit
  the **same** tenant pair as its parent — otherwise a tenant-specific deny could
  leak globally (security).
- Coerce to `int` with a `1` fallback (dict values may be `str`/`None`).

**NOT in scope**: serialization to Rust JSON (TASK-018), request resolution
(TASK-019), Rust changes (TASK-020).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/policies/adapter.py` | MODIFY | Carry `org_id`/`client_id` in all `_adapt_*` paths + negated policy |

---

## Implementation Notes

### Pattern to Follow
Add a small helper and use it in each adapter branch:

```python
@staticmethod
def _tenant(policy_dict: dict) -> tuple[int, int]:
    def _coerce(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return 1
    return _coerce(policy_dict.get("org_id", 1)), _coerce(policy_dict.get("client_id", 1))
```

Then in each `ResourcePolicy(...)` call:
```python
org_id, client_id = PolicyAdapter._tenant(policy_dict)
p = ResourcePolicy(..., org_id=org_id, client_id=client_id)
```
And for the negated deny policy, pass the **same** `org_id`/`client_id`.

### Key Constraints
- Negated policy must inherit parent tenant (covered by a dedicated test).
- Do not change priority/effect logic.

### References in Codebase
- `navigator_auth/abac/policies/adapter.py:91-248` — `_adapt_*` methods.
- `navigator_auth/abac/policies/adapter.py:205-217` — negated deny policy.

---

## Acceptance Criteria

- [ ] A dict with `org_id=5, client_id=3` produces a `ResourcePolicy` with `5`/`3`.
- [ ] A dict without tenant keys produces `1`/`1`.
- [ ] Negated deny policy inherits the parent's `org_id`/`client_id`.
- [ ] Non-int/`None` tenant values coerce to `1`.
- [ ] `pytest tests/ -v -k "policy or adapter"` passes.

---

## Test Specification

```python
from navigator_auth.abac.policies.adapter import PolicyAdapter

def test_adapter_carries_tenant():
    d = {"name": "p", "effect": "ALLOW", "resource": ["tool:*"],
         "actions": ["tool:execute"], "groups": ["eng"],
         "org_id": 5, "client_id": 3}
    res = PolicyAdapter.adapt(d)
    assert (res.policy.org_id, res.policy.client_id) == (5, 3)

def test_adapter_negated_inherits_tenant():
    d = {"name": "p", "effect": "ALLOW",
         "resource": ["tool:jira_*", "!tool:jira_admin"],
         "actions": ["tool:execute"], "groups": ["eng"],
         "org_id": 7, "client_id": 2}
    res = PolicyAdapter.adapt(d)
    assert (res.policy.org_id, res.policy.client_id) == (7, 2)
    assert all((p.org_id, p.client_id) == (7, 2) for p in res.additional_policies)
```

---

## Agent Instructions

1. Read the spec (Module 2). 2. Verify TASK-016 is in `completed/`.
3. Index → `in-progress`. 4. Implement. 5. Verify. 6. Move to `completed/`,
index → `done`. 7. Fill Completion Note.

---

## Completion Note

**Completed by**:
**Date**:
**Notes**:
**Deviations from spec**: none
