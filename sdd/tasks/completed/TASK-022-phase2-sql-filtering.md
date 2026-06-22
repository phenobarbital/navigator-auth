# TASK-022: (Phase 2) SQL-side filtering + per-tenant evaluator instances

**Feature**: per-tenant-policy-scoping (FEAT-092)
**Spec**: `sdd/specs/per-tenant-policy-scoping.spec.md`
**Status**: pending
**Priority**: low
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-016, TASK-017, TASK-018, TASK-019, TASK-020, TASK-021
**Assigned-to**: unassigned

---

## Context

**Phase 2 / follow-up — NOT required for Phase 1 acceptance.** For deployments
with large per-tenant policy volumes, loading every tenant's policies into one
shared evaluator becomes wasteful. This task adds an optional SQL-side prefetch
plus a small LRU of per-tenant evaluator instances, behind a feature flag.
Implements **Module 7**. Start only after Phase 1 (TASK-016..021) is merged and
validated.

---

## Scope

- `pgStorage.load_policies(org_id=None, client_id=None)`: parameterized overload
  that, when given a tenant, fetches only
  `org_id IN (1, :req_org) AND client_id IN (1, :req_client) AND enabled = TRUE`.
  Keep the no-arg form (load all) for Phase-1 behaviour.
- PDP/evaluator: maintain a bounded LRU of per-tenant `PolicyEvaluator` instances
  (each holds that tenant's + global policies). Public API
  (`is_allowed`, `filter_obj`, `check_access`) unchanged.
- Gate the whole path behind `ABAC_TENANT_SQL_FILTERING` (default `False`).
- Phase-1 in-engine `matches_tenant` remains the correctness backstop.
- Hot-reload (`reload_policies`) must invalidate/refresh per-tenant evaluators.

**NOT in scope**: changing Phase-1 semantics; admin UI; schema-per-tenant.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/storages/pg.py` | MODIFY | Parameterized tenant `load_policies` |
| `navigator_auth/abac/pdp.py` | MODIFY | Per-tenant evaluator LRU + reload invalidation |
| `navigator_auth/abac/policies/evaluator.py` | MODIFY | Support per-tenant instantiation |
| `navigator_auth/conf.py` | MODIFY | `ABAC_TENANT_SQL_FILTERING` |
| `tests/test_tenant_sql_filtering.py` | CREATE | Phase-2 tests |

---

## Implementation Notes

### Key Constraints
- SQL must be parameterized (no string interpolation of tenant ids).
- LRU bound + eviction policy configurable; evictions must not drop the global set.
- When `ABAC_TENANT_SQL_FILTERING=False`, behaviour is byte-for-byte Phase 1.
- Decisions must be identical to Phase 1 for the same inputs (differential test
  vs the shared-evaluator path).

### References in Codebase
- `navigator_auth/abac/storages/pg.py:18-30` — `load_policies` query.
- `navigator_auth/abac/pdp.py:73-166` — load/reload paths.
- Spec §6 "Resolved Decisions" Q4 and Module 7.

---

## Acceptance Criteria

- [ ] `load_policies(org_id, client_id)` returns only global + that tenant's rows.
- [ ] Per-tenant evaluator LRU yields decisions identical to the Phase-1 shared path.
- [ ] Flag off ⇒ Phase-1 behaviour unchanged (regression suite green).
- [ ] Reload refreshes per-tenant evaluators.
- [ ] `pytest tests/ -v -k "tenant"` passes.

---

## Test Specification

```python
def test_load_policies_tenant_filter(pg_storage):
    rows = await pg_storage.load_policies(org_id=5, client_id=1)
    assert all(r["org_id"] in (1, 5) and r["client_id"] in (1, 1) for r in rows)

def test_per_tenant_matches_shared(shared_eval, tenant_eval, sample_requests):
    for req in sample_requests:
        assert shared_eval.check_access(**req).allowed == tenant_eval.check_access(**req).allowed
```

---

## Agent Instructions

1. Read the spec (Module 7 + Q4). 2. Confirm Phase 1 (TASK-016..021) merged.
3. Index → `in-progress`. 4. Implement behind the flag. 5. Verify parity with
Phase 1. 6. Move to `completed/`, index → `done`. 7. Fill Completion Note.

---

## Completion Note

**Completed by**: sdd-worker (Claude Sonnet 4.6)
**Date**: 2026-06-16
**Notes**: Added parameterized `load_policies(org_id=None, client_id=None)` to `pgStorage` using `$1`/`$2` placeholder syntax (asyncdb/asyncpg style). Added per-tenant PolicyEvaluator LRU (OrderedDict, bounded by `_TENANT_EVALUATOR_LRU_SIZE=128`) to PDP with `_get_tenant_evaluator`, `_build_tenant_evaluator`, `_invalidate_tenant_evaluators` methods. `reload_policies` now clears the LRU after swapping the shared index. All four PDP entry-points (`authorize`, `filter_files`, `is_allowed`, `filter_obj`) delegate to per-tenant evaluator when `ABAC_TENANT_SQL_FILTERING=True`. 12 unit tests pass; 2 live-DB tests marked skip pending PostgreSQL fixture. Phase-1 tests unaffected (94 pass, 2 pre-existing failures in abstract.py).
**Deviations from spec**: evaluator.py needed no changes (already supports per-tenant instantiation via `load_policies`). conf.py already had `ABAC_TENANT_SQL_FILTERING` from TASK-019.
