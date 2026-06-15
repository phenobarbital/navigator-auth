# Feature Specification: Per-Tenant Policy Scoping

**Feature ID**: FEAT-092
**Date**: 2026-06-16
**Author**: Jesus Lara
**Status**: approved
**Target version**: 1.1.0

---

## 1. Motivation & Business Requirements

### Problem Statement

The `auth.policies` table already carries two tenancy columns — `org_id` and
`client_id` (see `ModelPolicy` in `navigator_auth/abac/storages/pg.py:58-59`) —
but **they are loaded and then silently discarded**. Concretely, today:

1. `pgStorage.load_policies()` (`storages/pg.py:18-30`) selects `org_id, client_id`
   but the query has **no tenant filter** (`WHERE enabled = TRUE` only). Every
   enabled policy is loaded globally.
2. The `PDP` (`abac/pdp.py:73-104`) adapts and loads **all** policies into a
   single shared `PolicyEvaluator`. There is no per-request tenant context.
3. `PolicyAdapter.adapt_*` (`abac/policies/adapter.py`) does not carry `org_id`/
   `client_id` onto the resulting `ResourcePolicy`.
4. The serialized policy JSON sent to Rust
   (`evaluator.py:229-253`, `_serialize_policies_from_index`) omits tenant fields,
   and the Rust `PolicyDef` struct (`rs_pep/src/lib.rs:26-40`) has no tenant
   fields, so `evaluate_resource` cannot scope by tenant.

**Net effect:** a policy authored for `org_id=5` is enforced for *every* tenant.
There is no way to give two tenants different policy sets. This was explicitly
marked out of scope in FEAT-001
(`sdd/specs/policy-based-access-control.spec.md:38`); this spec closes that gap.

### Goals

- **G1**: Filter policy loading so the active policy set for a request is scoped
  to its tenant, with `org_id=1` / `client_id=1` acting as **global/inheritable
  defaults** that apply to all tenants (backward compatible with current data).
- **G2**: Thread `org_id`/`client_id` from the request/session through
  `EvalContext` → `PolicyEvaluator` → Rust evaluator.
- **G3**: Make the Rust evaluator tenant-aware: a policy matches a request only
  when its tenant scope is global (`1`) or equals the request's tenant.
- **G4**: Preserve existing single-tenant behaviour by default — deployments that
  never set a tenant continue to work unchanged.
- **G5**: Keep the hot-reload path (`PDP.reload_policies`) and the
  `/api/v1/abac/*` endpoints tenant-correct.

### Non-Goals (explicitly out of scope)

- Per-tenant **storage backends** or schema-per-tenant — all policies stay in the
  single `auth.policies` table.
- A tenant-management/admin UI or CRUD for orgs/clients.
- Per-tenant evaluator **instances** or per-tenant policy caches as separate
  processes — a single evaluator filters by tenant in-engine.
- Changing the meaning of `priority`, `effect`, or deny-over-allow precedence.
- RBAC changes. Tenant resolution from external IdP claims beyond what the
  session already exposes (see Open Questions).

---

## 2. Architectural Design

### Overview

Tenancy is modeled as **two integer scope fields on every policy** plus a
**tenant context on every request**. A policy is *in scope* for a request when:

```
(policy.org_id    == 1  OR  policy.org_id    == request.org_id)
AND
(policy.client_id == 1  OR  policy.client_id == request.client_id)
```

`1` is the reserved "global / inheritable" sentinel (matches the existing column
default). This rule is applied in the Rust evaluator as an additional predicate
in `evaluate_resource`, alongside the existing resource/action/subject/env
checks. The policy JSON gains two fields; the request gains a tenant dict.

**`org_id` and `client_id` are always resolved together as a single tenant pair**
(resolved decision, Open Q2): a request never carries one without the other —
both come from the same source, and both must satisfy `matches_tenant`.

The tenant of a **request** is resolved (in priority order) from
(resolved decision, Open Q1):
1. explicit `org_id`/`client_id` kwargs passed to `is_allowed`/`filter_obj`,
2. request **headers** `X-Org-Id` / `X-Client-Id` (for service-to-service
   calls) — **trusted only when set by the gateway**; see security note below,
3. the session user info (`userinfo['org_id']` / `userinfo['client_id']`),
4. fallback to the global default `1` (resolved decision, Open Q3 — an
   unknown/unset tenant falls back to **global policies only**, it does **not**
   fail closed).

> **Header trust (security).** `X-Org-Id`/`X-Client-Id` let a service impersonate
> any tenant, so they MUST be treated as untrusted unless the deployment strips
> and re-injects them at a trusted edge (reverse proxy / API gateway). A config
> flag `ABAC_TENANT_TRUST_HEADERS` (default **false**) gates header resolution;
> when disabled, the header source is skipped entirely and resolution falls
> through to session `userinfo`. When both `org_id` and `client_id` headers are
> present they are taken as a pair; a partial header set is ignored.

### Component Diagram

```
 auth.policies (org_id, client_id) ──► pgStorage.load_policies()
                                          │ (rows incl. tenant cols)
                                          ▼
                                   PolicyAdapter.adapt_*  ── attaches org_id/client_id ──►
                                          │
                                          ▼
                                   ResourcePolicy(.org_id, .client_id)
                                          │
                                          ▼
            PolicyEvaluator._serialize_policies_from_index()
                  (adds "org_id"/"client_id" to JSON)
                                          │  policies_json
                                          ▼
   request ─► EvalContext(org_id, client_id) ─► PolicyEvaluator.check_access()
                                          │  user_ctx["org_id"], user_ctx["client_id"]
                                          ▼
                          rs_pep::evaluate_single / filter_resources_batch
                                          │
                                          ▼
                          evaluate_resource()  ── matches_tenant(policy, req) ──► decision
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `pgStorage.load_policies` (`storages/pg.py`) | **unchanged query, keep cols** | Already selects `org_id, client_id`. No SQL filter added — filtering happens in-engine so a single load serves all tenants and hot-reload stays simple. |
| `ModelPolicy` (`storages/pg.py`) | **unchanged** | Columns already exist. |
| `PolicyAdapter` (`abac/policies/adapter.py`) | **enhances** | Carry `org_id`/`client_id` from dict onto `ResourcePolicy` in every `_adapt_*` path. |
| `ResourcePolicy` (`policies/resource_policy.py`) | **extends** | New `org_id`/`client_id` attributes (default `1`). |
| `PolicyEvaluator` (`policies/evaluator.py`) | **enhances** | Serialize tenant into JSON; inject request tenant into `user_ctx`. |
| `EvalContext` (`abac/context.py`) | **extends** | Store `org_id`/`client_id` resolved from request/session. |
| `PDP` (`abac/pdp.py`) | **enhances** | Resolve tenant in `authorize`/`is_allowed`/`filter_*`; pass through. |
| `rs_pep` (`rs_pep/src/lib.rs`) | **extends** | `PolicyDef` gains tenant fields; `UserContext`/env carries request tenant; new `matches_tenant` predicate. |

### Data Models

```python
# ResourcePolicy (policies/resource_policy.py) — new attributes
class ResourcePolicy(AbstractPolicy):
    def __init__(self, ..., org_id: int = 1, client_id: int = 1, **kwargs):
        ...
        self.org_id = org_id
        self.client_id = client_id
```

```python
# EvalContext (abac/context.py) — resolved tenant on the store
self.store['org_id']    = ...   # int, default 1
self.store['client_id'] = ...   # int, default 1
```

```jsonc
// Serialized policy JSON sent to Rust (evaluator.py) — two new fields
{
  "name": "engineering_tools",
  "effect": "allow",
  "resources": ["tool:jira_*"],
  "actions": ["tool:execute"],
  "subjects": { "groups": ["engineering"], "...": "..." },
  "conditions": { "...": "..." },
  "priority": 10,
  "enforcing": false,
  "org_id": 5,        // NEW — 1 = global/inheritable
  "client_id": 1      // NEW — 1 = global/inheritable
}
```

```rust
// rs_pep/src/lib.rs — PolicyDef gains tenant fields with global default = 1
#[derive(Debug, Deserialize, Clone)]
struct PolicyDef {
    name: String,
    effect: String,
    resources: Vec<String>,
    actions: Vec<String>,
    #[serde(default)] subjects: SubjectSpec,
    #[serde(default)] conditions: ConditionSpec,
    #[serde(default)] priority: i32,
    #[serde(default)] enforcing: bool,
    #[serde(default = "default_tenant")] org_id: i64,     // NEW
    #[serde(default = "default_tenant")] client_id: i64,  // NEW
}
fn default_tenant() -> i64 { 1 }
```

### New Public Interfaces

```python
# PolicyEvaluator.check_access — accept request tenant (defaults preserve behaviour)
def check_access(
    self, ctx, resource_type, resource_name, action,
    env=None, owner_reports_to=None,
    org_id: int = 1, client_id: int = 1,   # NEW
) -> EvaluationResult: ...

# PDP.is_allowed — already **kwargs; formally accept tenant
async def is_allowed(self, request, session=None, user=None,
                     org_id: int = None, client_id: int = None, **kwargs): ...
```

```rust
// rs_pep — tenant predicate, applied inside evaluate_resource()
fn matches_tenant(policy: &PolicyDef, req_org: i64, req_client: i64) -> bool {
    (policy.org_id == 1 || policy.org_id == req_org)
        && (policy.client_id == 1 || policy.client_id == req_client)
}
```

The Rust signatures `evaluate_single` / `filter_resources_batch` read
`org_id`/`client_id` from the existing `user_context` dict (no new positional
args), keeping the Python call sites stable.

---

## 3. Module Breakdown

### Module 1: ResourcePolicy tenant attributes
- **Path**: `navigator_auth/abac/policies/resource_policy.py`
- **Responsibility**: Add `org_id`/`client_id` constructor params (default `1`)
  and store them as attributes. No behavioural change in pure-Python methods.
- **Depends on**: none

### Module 2: Adapter carries tenant
- **Path**: `navigator_auth/abac/policies/adapter.py`
- **Responsibility**: In `_adapt_resource`, `_adapt_classic`, `_adapt_object`,
  `_adapt_file`, read `org_id`/`client_id` from the policy dict (default `1`) and
  pass to `ResourcePolicy`. Ensure the `_negated` deny policy inherits the same
  tenant as its parent.
- **Depends on**: Module 1

### Module 3: Evaluator serialization + request tenant injection
- **Path**: `navigator_auth/abac/policies/evaluator.py`
- **Responsibility**: Add `org_id`/`client_id` to `_serialize_policies_from_index`
  output. Extend `check_access` and `filter_resources` signatures with
  `org_id`/`client_id` (default `1`) and put them on the `user_ctx` dict passed to
  Rust. Include tenant in the cache key (`_make_cache_key`) so two tenants never
  share a cached decision.
- **Depends on**: Module 1

### Module 4: EvalContext + PDP tenant resolution
- **Path**: `navigator_auth/abac/context.py`, `navigator_auth/abac/pdp.py`,
  `navigator_auth/conf.py`
- **Responsibility**: `EvalContext` resolves and stores `org_id`/`client_id` as a
  **pair** in the order kwarg → `X-Org-Id`/`X-Client-Id` headers (only when
  `ABAC_TENANT_TRUST_HEADERS` is true) → `userinfo` → default `1`. Coerce to
  `int` with a `1` fallback. Add `ABAC_TENANT_TRUST_HEADERS` (default `False`) to
  `conf.py`. `PDP.authorize`, `is_allowed`, `filter_obj`, `filter_files` pass the
  resolved tenant into the evaluator calls.
- **Depends on**: Module 3

### Module 5: Rust tenant-aware evaluation
- **Path**: `navigator_auth/rs_pep/src/lib.rs`
- **Responsibility**: Add `org_id`/`client_id` to `PolicyDef` (serde default `1`).
  Parse `org_id`/`client_id` from `user_context` in both `evaluate_single` and
  `filter_resources_batch`. Add `matches_tenant` predicate and call it first in
  `evaluate_resource` (cheapest filter, short-circuits before regex). Add Rust
  unit tests. Rebuild with `maturin develop --release`.
- **Depends on**: Module 3 (JSON shape contract)

### Module 6: Tests & fixtures
- **Path**: `tests/` (mirror existing policy test layout)
- **Responsibility**: Python unit/integration tests for tenant scoping +
  backward-compat; ensure existing tests still pass.
- **Depends on**: Modules 1–5

### Module 7 *(Phase 2 — follow-up)*: SQL-side filtering + per-tenant evaluators
- **Path**: `navigator_auth/abac/storages/pg.py`, `navigator_auth/abac/pdp.py`,
  `navigator_auth/abac/policies/evaluator.py`
- **Responsibility**: For deployments with large per-tenant policy volumes, add an
  optional path that (a) prefetches only `org_id IN (1, :req_org) AND client_id IN
  (1, :req_client)` from SQL via a parameterized `load_policies(org_id, client_id)`
  overload, and (b) maintains a small LRU of **per-tenant evaluator instances**
  (each holding only that tenant's + global policies) instead of one shared
  evaluator. Public API (`is_allowed`, `filter_obj`, `check_access`) is unchanged;
  Phase 1's in-engine `matches_tenant` remains the correctness backstop.
  Gated by `ABAC_TENANT_SQL_FILTERING` (default `False`).
- **Depends on**: Phase 1 complete (Modules 1–6). Ships as a separate PR/iteration;
  **not required** for the Phase 1 acceptance criteria.

---

## 4. Test Specification

### Unit Tests

| Test | Module | Description |
|---|---|---|
| `test_resourcepolicy_tenant_defaults` | M1 | New `ResourcePolicy` defaults to `org_id=1, client_id=1`. |
| `test_adapter_carries_tenant` | M2 | A policy dict with `org_id=5, client_id=3` yields a `ResourcePolicy` with those values. |
| `test_adapter_negated_inherits_tenant` | M2 | The auto-generated `_negated` deny policy keeps the parent tenant. |
| `test_serialize_includes_tenant` | M3 | `_serialize_policies_from_index` JSON contains `org_id`/`client_id`. |
| `test_cache_key_tenant_isolation` | M3 | Same user/resource but different `org_id` produce different cache keys. |
| `test_evalcontext_tenant_resolution` | M4 | Resolution order kwarg > header > userinfo > default `1`. |
| `test_evalcontext_header_gated` | M4 | `X-Org-Id` header is ignored when `ABAC_TENANT_TRUST_HEADERS=False`; honored when `True`. |
| `test_evalcontext_partial_header_ignored` | M4 | A request with only `X-Org-Id` (no `X-Client-Id`) ignores the header pair and falls through. |
| `test_rust_matches_tenant_global` | M5 | `org_id=1` policy matches any request tenant (Rust unit test). |
| `test_rust_matches_tenant_exact` | M5 | `org_id=5` policy matches only `req_org=5`, denies `req_org=7`. |

### Integration Tests

| Test | Description |
|---|---|
| `test_e2e_tenant_isolation` | Tenant A's `allow` policy does **not** grant access to Tenant B for the same resource. |
| `test_e2e_global_policy_applies_to_all` | An `org_id=1` allow policy grants access to tenants A and B. |
| `test_e2e_tenant_overrides_global_deny` | A higher-priority tenant-specific deny overrides a global allow for that tenant only. |
| `test_e2e_backward_compat_no_tenant` | With all data at default `1` and no tenant on requests, decisions are identical to pre-feature behaviour. |
| `test_e2e_reload_preserves_tenant` | After `reload_policies`, tenant scoping still holds. |

### Test Data / Fixtures

```python
@pytest.fixture
def tenant_policies():
    """Three policies: global allow, tenant-5 deny, tenant-7 allow."""
    return [
        {"name": "global_tools",  "effect": "ALLOW", "policy_type": "policy",
         "resource": ["tool:*"], "actions": ["tool:execute"],
         "groups": ["engineering"], "priority": 1,
         "org_id": 1, "client_id": 1},
        {"name": "t5_block_jira", "effect": "DENY", "policy_type": "policy",
         "resource": ["tool:jira_*"], "actions": ["tool:execute"],
         "groups": ["engineering"], "priority": 10, "enforcing": True,
         "org_id": 5, "client_id": 1},
    ]

@pytest.fixture
def ctx_tenant_5(make_request):
    """EvalContext whose userinfo carries org_id=5."""
    ...
```

---

## 5. Acceptance Criteria

> This feature is complete when ALL of the following are true:

- [ ] `ResourcePolicy` exposes `org_id`/`client_id` (default `1`).
- [ ] `PolicyAdapter` carries tenant onto policies in all `_adapt_*` paths, incl. `_negated`.
- [ ] Serialized policy JSON includes `org_id`/`client_id`.
- [ ] `PolicyEvaluator.check_access` / `filter_resources` accept tenant and pass it to Rust; cache key is tenant-aware.
- [ ] `EvalContext`/`PDP` resolve tenant (as a pair) in order kwarg > header > `userinfo` > default `1`, with headers gated by `ABAC_TENANT_TRUST_HEADERS` (default off).
- [ ] Rust `evaluate_resource` applies `matches_tenant`; `org_id=1`/`client_id=1` are global.
- [ ] Tenant A cannot use Tenant B's tenant-specific policies (integration test green).
- [ ] Global (`1`) policies apply to all tenants (integration test green).
- [ ] **No breaking changes**: all existing `tests/test_policy*` pass with defaults.
- [ ] `rs_pep` rebuilds cleanly (`maturin develop --release`) and `cargo test` passes.
- [ ] `pytest tests/ -v -k "policy or tenant"` passes.

---

## 6. Implementation Notes & Constraints

### Patterns to Follow

- **Filter in-engine, not in SQL.** Keep `load_policies` loading all rows so the
  single shared evaluator + hot-reload path stay simple; the Rust `matches_tenant`
  predicate does the scoping per request. (Revisit only if policy counts grow to
  where loading all tenants is costly — see Open Questions.)
- `matches_tenant` must be the **first** predicate in `evaluate_resource` — it is
  the cheapest (two integer comparisons) and short-circuits before regex/glob.
- Default everything to `1` via `#[serde(default = "default_tenant")]` in Rust and
  `= 1` in Python so **older JSON without tenant fields still deserializes** to
  global scope (forward/backward compatible).
- Tenant must be part of the evaluator **cache key**, or Tenant B could read
  Tenant A's cached decision — this is a correctness/security requirement, not an
  optimization.

### Known Risks / Gotchas

- **Cache poisoning across tenants** — mitigated by including `org_id`/`client_id`
  in `_make_cache_key` (Module 3). Add an explicit test.
- **Negated/auto-generated policies** (`adapter.py:205-217`) — must inherit the
  parent's tenant or a tenant-specific deny could leak globally. Covered by
  `test_adapter_negated_inherits_tenant`.
- **`int` vs `None`** — `userinfo` may carry tenant as `str` or `None`; coerce to
  `int` with a `1` fallback at the EvalContext boundary to avoid type errors in
  the JSON/Rust path.
- **Rust ABI rebuild** — the `.so` must be recompiled; CI and local devs need
  `maturin develop --release`. Stale binaries will ignore tenant fields silently
  (they default to `1` = global), which *fails open per-tenant* — call this out
  in the PR and gate on a Rust unit test.
- **filter_resources_batch owner/tenant** — batch path currently passes
  `owner_reports_to=None`; tenant is independent and read from `user_context`, so
  no interaction, but verify the dict is threaded in both PyO3 functions.

### Configuration Keys (navigator_auth.conf / navconfig)

| Key | Default | Description |
|---|---|---|
| `ABAC_TENANT_TRUST_HEADERS` | `False` | Allow `X-Org-Id`/`X-Client-Id` headers to set the request tenant. Enable only behind a trusted gateway that strips client-supplied values. |
| `ABAC_TENANT_HEADER_ORG` | `"X-Org-Id"` | Header name for org id (overridable). |
| `ABAC_TENANT_HEADER_CLIENT` | `"X-Client-Id"` | Header name for client id (overridable). |
| `ABAC_TENANT_SQL_FILTERING` | `False` | *(Phase 2)* Enable SQL-side prefetch + per-tenant evaluator instances. |

### External Dependencies

| Package | Version | Reason |
|---|---|---|
| `PyO3` | `>=0.21` | Existing — tenant parsing from `PyDict`. |
| `maturin` | `>=1.0` | Existing — rebuild `rs_pep`. |
| `serde` / `serde_json` | existing | `#[serde(default)]` tenant fields. |

No new dependencies.

---

## 7. Resolved Decisions

> All open questions from the initial draft were resolved on 2026-06-16.

- [x] **Q1 — Header resolution.** Yes. The request tenant is resolvable from
  `X-Org-Id` / `X-Client-Id` headers for service-to-service calls, gated behind
  `ABAC_TENANT_TRUST_HEADERS` (default `False`) and trusted only when injected by
  a trusted edge. Resolution order: kwarg → headers → `userinfo` → default `1`.
- [x] **Q2 — Tenant granularity.** `org_id` **and** `client_id` are always used
  **together** as a single tenant pair. A policy is in scope only when both
  dimensions satisfy `matches_tenant`; requests never carry one without the other.
- [x] **Q3 — Unknown tenant.** Fall back to **global (`1`) policies only** — do
  **not** fail closed. An unset/unknown tenant behaves like a default-tenant
  request and sees only `org_id=1 AND client_id=1` policies.
- [x] **Q4 — Scaling to SQL-side filtering.** Yes — adopted as **Phase 2**
  (Module 7). Phase 1 ships the in-engine filter (correctness + simple
  hot-reload); Phase 2 adds SQL-side prefetch + per-tenant evaluator instances for
  large policy volumes, behind the same public API.

---

## Worktree Strategy

- **Isolation unit**: `per-spec` (sequential tasks).
- Modules 1→5 form a single data-contract chain (Python attrs → adapter → JSON →
  Rust struct); they must land in order and share state, so sequential execution
  in one worktree avoids churn on the JSON contract.
- **Parallelizable exceptions**: Module 6 (tests) can be drafted in parallel once
  the JSON shape (Module 3) is frozen.
- **Cross-feature dependencies**: builds on FEAT-001 (PBAC) and FEAT-002
  (Rust PEP); both are already merged. No other spec must merge first.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-06-16 | Jesus Lara | Initial draft — per-tenant policy scoping (default `1` = global/inheritable). |
| 0.2 | 2026-06-16 | Jesus Lara | Resolved all open questions: header resolution (gated), org+client as a pair, global fallback on unknown tenant, Phase 2 SQL-side filtering (Module 7). |
