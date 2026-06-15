# TASK-020: Rust tenant-aware evaluation (matches_tenant predicate)

**Feature**: per-tenant-policy-scoping (FEAT-092)
**Spec**: `sdd/specs/per-tenant-policy-scoping.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-018
**Assigned-to**: unassigned

---

## Context

The actual tenant enforcement lives in the Rust engine (`rs_pep`). This task adds
tenant fields to `PolicyDef`, reads the request tenant from `user_context`, and
applies the `matches_tenant` predicate inside `evaluate_resource`. Implements
**Module 5**. Consumes the JSON contract frozen by TASK-018.

---

## Scope

- `PolicyDef`: add `org_id: i64` and `client_id: i64` with serde default `1`
  (`#[serde(default = "default_tenant")]`).
- Parse `org_id`/`client_id` from the `user_context` `PyDict` in **both**
  `evaluate_single` and `filter_resources_batch` (default `1`).
- Add `matches_tenant(policy, req_org, req_client)` and call it **first** in
  `evaluate_resource` (cheapest predicate; short-circuits before regex).
  Semantics: `(org_id == 1 || org_id == req_org) && (client_id == 1 || client_id == req_client)`.
- Add Rust unit tests. Rebuild: `maturin develop --release` (from `rs_pep/`).

**NOT in scope**: Python serialization (TASK-018) or request resolution (TASK-019).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/rs_pep/src/lib.rs` | MODIFY | Tenant fields, `matches_tenant`, parse from `user_context`, tests |

---

## Implementation Notes

### Struct + default
```rust
#[derive(Debug, Deserialize, Clone)]
struct PolicyDef {
    name: String, effect: String,
    resources: Vec<String>, actions: Vec<String>,
    #[serde(default)] subjects: SubjectSpec,
    #[serde(default)] conditions: ConditionSpec,
    #[serde(default)] priority: i32,
    #[serde(default)] enforcing: bool,
    #[serde(default = "default_tenant")] org_id: i64,     // NEW
    #[serde(default = "default_tenant")] client_id: i64,  // NEW
}
fn default_tenant() -> i64 { 1 }
```

### Predicate (call first in evaluate_resource)
```rust
fn matches_tenant(policy: &PolicyDef, req_org: i64, req_client: i64) -> bool {
    (policy.org_id == 1 || policy.org_id == req_org)
        && (policy.client_id == 1 || policy.client_id == req_client)
}
```
`evaluate_resource` gains `req_org: i64, req_client: i64` params; add
`if !matches_tenant(policy, req_org, req_client) { continue; }` before
`policy_covers_resource`.

### Parse from user_context (both PyO3 fns)
```rust
let req_org = user_context.get_item("org_id")?
    .map(|v| v.extract::<i64>().unwrap_or(1)).unwrap_or(1);
let req_client = user_context.get_item("client_id")?
    .map(|v| v.extract::<i64>().unwrap_or(1)).unwrap_or(1);
```
Thread `req_org`/`req_client` into every `evaluate_resource(...)` call (single +
the rayon `par_iter` batch closure).

### Key Constraints
- Default `1` everywhere so old JSON (no tenant fields) deserializes to global.
- `matches_tenant` first → minimal overhead for non-matching tenants.
- A **stale `.so` fails open per-tenant** (treats all as global). Gate on a Rust
  unit test and call this out in the PR.

### References in Codebase
- `navigator_auth/rs_pep/src/lib.rs:26-40` (PolicyDef), `:284-380`
  (evaluate_resource), `:396-496` (filter_resources_batch), `:502-583`
  (evaluate_single), `:593-714` (tests).

---

## Acceptance Criteria

- [ ] `org_id=1`/`client_id=1` policy matches any request tenant.
- [ ] `org_id=5` policy matches `req_org=5`, not `req_org=7`.
- [ ] Both dimensions required (mismatch on `client_id` alone excludes the policy).
- [ ] JSON without tenant fields still deserializes (defaults to `1`).
- [ ] `cargo test` passes (from `rs_pep/`).
- [ ] `maturin develop --release` builds cleanly; Python imports `rs_pep`.

---

## Test Specification

```rust
#[test]
fn test_matches_tenant_global() {
    let p = PolicyDef { org_id: 1, client_id: 1, /* ..default.. */ };
    assert!(matches_tenant(&p, 5, 3));
    assert!(matches_tenant(&p, 7, 9));
}

#[test]
fn test_matches_tenant_exact() {
    let p = PolicyDef { org_id: 5, client_id: 1, /* ..default.. */ };
    assert!(matches_tenant(&p, 5, 99));   // client global
    assert!(!matches_tenant(&p, 7, 99));  // org mismatch
}
```

---

## Agent Instructions

1. Read the spec (Module 5). 2. Verify TASK-018 in `completed/` (JSON contract).
3. Index → `in-progress`. 4. Implement + `maturin develop --release`. 5. Verify
`cargo test`. 6. Move to `completed/`, index → `done`. 7. Fill Completion Note.

---

## Completion Note

**Completed by**:
**Date**:
**Notes**:
**Deviations from spec**: none
