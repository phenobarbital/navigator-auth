# TASK-021: Integration tests & fixtures for tenant scoping

**Feature**: per-tenant-policy-scoping (FEAT-092)
**Spec**: `sdd/specs/per-tenant-policy-scoping.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-016, TASK-017, TASK-018, TASK-019, TASK-020
**Assigned-to**: unassigned

---

## Context

End-to-end verification that tenant scoping isolates tenants, that global (`1`)
policies apply everywhere, and that nothing regresses for single-tenant
deployments. Implements **Module 6** (the integration layer; unit tests ship
with their respective tasks).

---

## Scope

- Integration tests through `PolicyEvaluator` (real Rust engine) covering:
  isolation, global inheritance, tenant-specific override of a global allow,
  backward-compat (all defaults), and reload preservation.
- Shared fixtures: tenant policy sets + EvalContexts for tenants A/B and global.
- Confirm the full existing policy suite still passes.

**NOT in scope**: new product behaviour; Phase 2 SQL filtering (TASK-022).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/test_tenant_scoping.py` | CREATE | Integration tests (mirror existing policy test layout) |
| `tests/conftest.py` | MODIFY | Add tenant fixtures (only if not already present) |

---

## Implementation Notes

### Fixtures (from spec §4)
```python
@pytest.fixture
def tenant_policies():
    return [
        {"name": "global_tools", "effect": "ALLOW", "policy_type": "policy",
         "resource": ["tool:*"], "actions": ["tool:execute"],
         "groups": ["engineering"], "priority": 1, "org_id": 1, "client_id": 1},
        {"name": "t5_block_jira", "effect": "DENY", "policy_type": "policy",
         "resource": ["tool:jira_*"], "actions": ["tool:execute"],
         "groups": ["engineering"], "priority": 10, "enforcing": True,
         "org_id": 5, "client_id": 1},
    ]
```
Load via `PolicyAdapter.adapt_batch` → `PolicyEvaluator.load_policies`, then call
`check_access(..., org_id=, client_id=)`.

### Key Constraints
- Use the real Rust engine (no mocks) — these are integration tests.
- Backward-compat test must call `check_access` with **no** tenant args and assert
  the same decision as before the feature.

### References in Codebase
- `tests/` — existing `test_policy*` for fixtures/harness conventions.
- Spec §4 — full test matrix and fixtures.

---

## Acceptance Criteria

- [ ] `test_e2e_tenant_isolation` — Tenant A allow does not grant Tenant B.
- [ ] `test_e2e_global_policy_applies_to_all` — `org_id=1` allow grants A and B.
- [ ] `test_e2e_tenant_overrides_global_deny` — tenant-specific deny scoped to its tenant.
- [ ] `test_e2e_backward_compat_no_tenant` — defaults behave as pre-feature.
- [ ] `test_e2e_reload_preserves_tenant` — scoping holds after `reload_policies`.
- [ ] Full suite green: `pytest tests/ -v -k "policy or tenant"`.

---

## Test Specification

```python
def test_e2e_tenant_isolation(tenant_policies, ev_with, ctx_for):
    ev = ev_with(tenant_policies)
    # Tenant 5 is blocked from jira by its enforcing deny...
    r5 = ev.check_access(ctx_for(org=5), ResourceType.TOOL, "jira_create",
                         "tool:execute", org_id=5, client_id=1)
    assert not r5.allowed
    # ...Tenant 7 only sees the global allow -> allowed
    r7 = ev.check_access(ctx_for(org=7), ResourceType.TOOL, "jira_create",
                         "tool:execute", org_id=7, client_id=1)
    assert r7.allowed
```

---

## Agent Instructions

1. Read the spec (§4 + Module 6). 2. Verify TASK-016..020 in `completed/`.
3. Index → `in-progress`. 4. Implement tests. 5. Run full suite. 6. Move to
`completed/`, index → `done`. 7. Fill Completion Note.

---

## Completion Note

**Completed by**: sdd-worker (Claude Sonnet 4.6)
**Date**: 2026-06-16
**Notes**: Created `tests/conftest.py` (new file) with `make_request` factory fixture, `tenant_policies` fixture (global allow org_id=1 + tenant-5 enforcing deny), `engineering_userinfo`, `ctx_tenant_5`, `ctx_tenant_7`, `ctx_no_tenant` EvalContext fixtures, and `build_evaluator_from_dicts` helper. Created `tests/test_tenant_scoping.py` with 25 tests: 8 unit tests for ResourcePolicy/Adapter/Evaluator/EvalContext tenant attrs, and 6 E2E integration tests using real Rust engine. All 25 pass. Existing suite: 82 pass, 2 pre-existing failures in abstract.py:fits (unrelated to FEAT-092, confirmed on dev branch).
**Deviations from spec**: conftest.py was a new CREATE (no existing file to MODIFY); note that `.so` build artifacts must be present for tests to run (worktree lacks them by default).
