# TASK-030: P5 — Scope ↔ ABAC composition

**Feature**: Production-grade 3LO (Three-Legged OAuth2)
**Spec**: `sdd/specs/oauth2-3lo-implementation.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-024, TASK-029
**Assigned-to**: unassigned

---

## Context

Implements **Module 8** of FEAT-093 — the highest-value composition: **effective permission
= `granted_scopes ∩ user_ABAC`**. Includes the critical decision-cache-key fix. See spec §3
M8, source §11, Resolved Decision **D6**.

---

## Scope

- PEP fast gate: `@scope_required(*scopes)` in `abac/decorators.py` (mirror
  `groups_protected`) and `Guardian.has_scope(request, scopes)` in `abac/guardian.py` —
  `set(scopes).issubset(token_scopes)` else `AccessDenied(reason='insufficient_scope')` (403).
- Declarative policy scope: add `scopes: list` to `Policy` (`policies/policy.py`) and
  `ObjectPolicy` (`obj.py`); add a `scope_condition` parallel to `groups_condition`, included
  in the final AND. Add `ModelPolicy.scopes` (`storages/pg.py`) and `scopes` to **both**
  `load_policies` SELECT column lists; ensure the PDP loader passes `scopes` (default `[]`).
- **CRITICAL — cache-key fix** (`policies/evaluator.py`): extend `_make_cache_key` with
  `scope_key=frozenset(scopes)` and the public `client_uid` as **separate** components
  (distinct from the existing tenant `org_id`/`client_id` ints). Update the call site at
  `evaluator.py:433`. Non-token users get `scopes=frozenset()`, `client_uid=None`.
- `client_credentials` (2LO): evaluate ABAC against `client_uid` as a service principal (no
  required user groups/subject); the scope gate still applies.
- Action→scope registry: resolve required scope(s) from `OAUTH_SCOPE_ACTIONS`
  (no hardcoded scope names); `OAUTH_SCOPES` is the valid-scope registry (reject unknown at
  authorize per D5).
- DDL: `ALTER TABLE auth.policies ADD COLUMN IF NOT EXISTS scopes JSONB DEFAULT '[]'::jsonb`.
- Config: `OAUTH_SCOPES`, `OAUTH_SCOPE_ACTIONS`.

**NOT in scope**: surfacing scopes into userinfo (done in TASK-029); minting the scope claim
(done in TASK-024/token).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/decorators.py` | MODIFY | `@scope_required` |
| `navigator_auth/abac/guardian.py` | MODIFY | `has_scope` |
| `navigator_auth/abac/policies/policy.py` | MODIFY | `scopes` + `scope_condition` |
| `navigator_auth/abac/policies/obj.py` | MODIFY | `scopes` + `scope_condition` |
| `navigator_auth/abac/policies/evaluator.py` | MODIFY | **Cache-key fix**; client_credentials principal |
| `navigator_auth/abac/storages/pg.py` | MODIFY | `ModelPolicy.scopes` + both SELECTs |
| `navigator_auth/backends/oauth2/ddl.sql` | MODIFY | `auth.policies.scopes` column |
| `navigator_auth/conf.py` | MODIFY | `OAUTH_SCOPES`, `OAUTH_SCOPE_ACTIONS` |
| `tests/test_scope_abac.py` | CREATE | Scope-ceiling, AND-composition, cache regression, cc principal |

---

## Implementation Notes

### Key Constraints
- The OAuth `client_uid` (str) in the cache key is **distinct** from the FEAT-092 tenant
  `client_id` (int) — add a new component, never overload (D6).
- `load_policies` has **two** explicit SELECT column lists — add `scopes` to both.
- DENY wins; insufficient scope is an additional up-front DENY.

### References in Codebase
- `navigator_auth/abac/decorators.py:56-93` — `groups_protected` template.
- `navigator_auth/abac/policies/policy.py` — `groups_condition` template.
- `navigator_auth/abac/policies/evaluator.py:327-347,433` — `_make_cache_key` + call site.
- `navigator_auth/abac/storages/pg.py:35-42,47-51,69-91` — SELECTs + `ModelPolicy`.

---

## Acceptance Criteria

- [ ] `@scope_required`/`Guardian.has_scope` enforce 403 `insufficient_scope` (issubset).
- [ ] `Policy.scopes` evaluated as an AND-condition across `Policy`/`ObjectPolicy`.
- [ ] Cache key includes normalized scopes + `client_uid`; same-user different-scope tokens
      do not collide (regression test).
- [ ] `client_credentials` evaluated against `client_uid`; user-keyed policy not matched.
- [ ] Action→scope from `OAUTH_SCOPE_ACTIONS`; unknown scope rejected at authorize.
- [ ] Tests pass: `pytest tests/test_scope_abac.py -v`.

---

## Test Specification

```python
# tests/test_scope_abac.py
class TestScopeABAC:
    async def test_scope_required_403(self, ...): ...
    async def test_policy_scope_condition(self, ...): ...
    async def test_cache_regression_two_tokens(self, ...): ...   # proves §11.4
    async def test_client_credentials_principal(self, ...): ...
```

---

## Agent Instructions

1. Read the spec (§3 M8, source §11, D6). 2. Verify TASK-024 + TASK-029 completed.
3. Index → `in-progress`. 4. Implement. 5. Verify. 6. Move to `completed/`.
7. Index → `done` + Completion Note.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:
**Deviations from spec**: none
