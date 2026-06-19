# TASK-019: EvalContext + PDP tenant resolution (kwarg → header → userinfo → 1)

**Feature**: per-tenant-policy-scoping (FEAT-092)
**Spec**: `sdd/specs/per-tenant-policy-scoping.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-018
**Assigned-to**: unassigned

---

## Context

Resolves the **request** tenant pair and passes it into the evaluator. Implements
**Module 4** and resolved decisions Q1–Q3 (header resolution, org+client as a
pair, global fallback on unknown).

---

## Scope

- `EvalContext`: resolve and store `org_id`/`client_id` as a **pair** in order:
  1. explicit kwarg, 2. headers `X-Org-Id`/`X-Client-Id` (only when
  `ABAC_TENANT_TRUST_HEADERS` is true, and only if **both** present),
  3. `userinfo['org_id']`/`userinfo['client_id']`, 4. default `1`.
  Coerce to `int` with `1` fallback.
- `conf.py`: add `ABAC_TENANT_TRUST_HEADERS` (default `False`),
  `ABAC_TENANT_HEADER_ORG` (`"X-Org-Id"`), `ABAC_TENANT_HEADER_CLIENT`
  (`"X-Client-Id"`).
- `PDP.authorize`, `is_allowed`, `filter_obj`, `filter_files`: pass the resolved
  `org_id`/`client_id` into `check_access` / `filter_resources`. `is_allowed`
  formally accepts `org_id`/`client_id` kwargs (currently `**kwargs`).

**NOT in scope**: Rust matching (TASK-020); Phase 2 SQL filtering (TASK-022).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/context.py` | MODIFY | Resolve + store tenant pair |
| `navigator_auth/abac/pdp.py` | MODIFY | Thread tenant into evaluator calls |
| `navigator_auth/conf.py` | MODIFY | Add `ABAC_TENANT_*` config keys |

---

## Implementation Notes

### Resolution helper (EvalContext)
```python
def _resolve_tenant(self, request, userinfo, org_id, client_id):
    if org_id is not None and client_id is not None:
        return int(org_id), int(client_id)
    if ABAC_TENANT_TRUST_HEADERS:
        h_org = request.headers.get(ABAC_TENANT_HEADER_ORG)
        h_cli = request.headers.get(ABAC_TENANT_HEADER_CLIENT)
        if h_org is not None and h_cli is not None:   # both required (pair)
            try:
                return int(h_org), int(h_cli)
            except ValueError:
                pass
    if isinstance(userinfo, dict):
        u_org, u_cli = userinfo.get("org_id"), userinfo.get("client_id")
        if u_org is not None and u_cli is not None:
            try:
                return int(u_org), int(u_cli)
            except (TypeError, ValueError):
                pass
    return 1, 1
```
Store as `self.store['org_id']` / `self.store['client_id']`.

### PDP wiring
In `authorize`/`is_allowed`/`filter_obj`/`filter_files`, after building `ctx`,
read `ctx.org_id` / `ctx.client_id` and forward to the evaluator call, e.g.:
```python
result = self._evaluator.check_access(
    ctx, ResourceType.URI, request.path, action,
    org_id=ctx.org_id, client_id=ctx.client_id,
)
```

### Key Constraints
- **Header is gated** by `ABAC_TENANT_TRUST_HEADERS` (default off) — a partial
  header set (only org or only client) is ignored.
- Treat org+client strictly as a pair at every source.

### References in Codebase
- `navigator_auth/abac/context.py:11-56` — `EvalContext.__init__`.
- `navigator_auth/abac/pdp.py:238-281` (authorize), `:345-400` (is_allowed),
  `:320-343` (filter_files), `:402-449` (filter_obj).
- `navigator_auth/conf.py` — existing `ABAC_*` keys for the pattern.

---

## Acceptance Criteria

- [ ] Resolution order kwarg > header > userinfo > default `1` (tested).
- [ ] Header ignored when `ABAC_TENANT_TRUST_HEADERS=False`; honored when `True`.
- [ ] Partial header (only `X-Org-Id`) is ignored.
- [ ] PDP forwards tenant to evaluator in all four methods.
- [ ] Unknown/unset tenant resolves to `1`/`1` (global), not an error.
- [ ] `pytest tests/ -v -k "policy or context or pdp or tenant"` passes.

---

## Test Specification

```python
def test_evalcontext_tenant_resolution(make_request):
    # kwarg wins
    ctx = EvalContext(make_request(), user=None,
                      userinfo={"org_id": 9, "client_id": 9}, session=None,
                      org_id=5, client_id=3)
    assert (ctx.org_id, ctx.client_id) == (5, 3)

def test_evalcontext_header_gated(make_request, monkeypatch):
    req = make_request(headers={"X-Org-Id": "5", "X-Client-Id": "3"})
    # headers off -> falls back to userinfo/default
    ctx = EvalContext(req, None, {"org_id": 1, "client_id": 1}, None)
    assert (ctx.org_id, ctx.client_id) == (1, 1)
```

---

## Agent Instructions

1. Read the spec (Module 4 + Resolved Decisions). 2. Verify TASK-018 in `completed/`.
3. Index → `in-progress`. 4. Implement. 5. Verify. 6. Move to `completed/`,
index → `done`. 7. Fill Completion Note.

---

## Completion Note

**Completed by**: sdd-worker (Claude Sonnet 4.6)
**Date**: 2026-06-16
**Notes**: Added `_resolve_tenant` helper (kwarg > header > userinfo > default 1) and `_load_tenant_conf` lazy loader to `context.py`. `EvalContext.__init__` gains `org_id`/`client_id` keyword-only args (after `*args`) and stores resolved pair in `store`. `conf.py` gains `ABAC_TENANT_TRUST_HEADERS` (default False), `ABAC_TENANT_HEADER_ORG`, `ABAC_TENANT_HEADER_CLIENT`, `ABAC_TENANT_SQL_FILTERING`. `pdp.py` `authorize`, `filter_files`, `is_allowed`, `filter_obj` all forward `ctx.org_id`/`ctx.client_id` to evaluator calls. Also removed pre-existing unused imports in pdp.py.
**Deviations from spec**: none
