# Feature Specification: Migrate Classic ABAC Policies to Rust-Accelerated Evaluation

**Feature ID**: FEAT-002
**Date**: 2026-04-03
**Author**: Jesus Lara
**Status**: implemented
**Target version**: 1.1.0

---

## 1. Motivation & Business Requirements

### Problem Statement

The ABAC system has two disconnected policy evaluation paths:

1. **Classic path** (`PDP.authorize()`): Evaluates `Policy`, `FilePolicy`, and `ObjectPolicy`
   in pure Python via `asyncio.to_thread()`. Sequential, no native acceleration, no
   `ResourceType` indexing.
2. **Resource path** (`PolicyEvaluator`): Evaluates `ResourcePolicy` with O(1) type indexing,
   LRU caching, and a Rust module (`navigator_auth_pep`) for parallel batch evaluation via
   Rayon. Disconnected from the middleware.

This duality means:
- The middleware never benefits from the Rust engine.
- Developers must choose between two policy models with different semantics.
- Policy changes require a server restart (no hot reload).

There are no classic policies in production yet, making this the ideal time to unify.

### Goals
- Unify all policy types under a single `PolicyEvaluator` engine backed by Rust.
- Convert classic `Policy`/`FilePolicy`/`ObjectPolicy` to `ResourcePolicy` at load time.
- Integrate `PolicyEvaluator` into the ABAC middleware for global resource blocking.
- Support both glob (`tool:jira_*`) and regex (`urn:uri:/epson.*$`) patterns in Rust.
- Enable hot reload of policies from DB and YAML without server restart.
- Keep `PDP` public interface (`authorize()`, `is_allowed()`, `filter_files()`) unchanged.

### Non-Goals (explicitly out of scope)
- Real-time per-object filtering on every HTTP request (PolicyEvaluator in middleware is
  for global blocking only).
- PostgreSQL LISTEN/NOTIFY for DB change detection (simple polling or explicit API call
  is sufficient for now).
- Python fallback when Rust module is unavailable (Rust is now mandatory).
- Migrating the policy authoring format (classic YAML/DB format continues to work).

---

## 2. Architectural Design

### Overview

**Option B from brainstorm**: Unified PolicyEvaluator as Single Engine.

At load time, a `PolicyAdapter` converts all policy dicts (classic, file, object) into
`ResourcePolicy` instances. The `PDP` delegates evaluation to `PolicyEvaluator`, which
uses the Rust engine for both single-resource checks (middleware) and batch filtering
(handlers). Hot reload is centralized: re-load, re-adapt, swap index atomically.

### Component Diagram

```
                         LOAD TIME
  +-----------+     +---------------+     +----------------+
  | pgStorage |---->|               |---->| ResourcePolicy |---+
  +-----------+     | PolicyAdapter |     +----------------+   |
  +-------------+   |               |     +----------------+   |
  | YAMLStorage |-->|               |---->| ResourcePolicy |---+
  +-------------+   +---------------+     +----------------+   |
                                                               v
                         RUNTIME                       +----------------+
  +------------+     +---------+     +----------+      | PolicyEvaluator|
  | HTTP Req   |---->| Middle- |---->| PDP      |----->|   PolicyIndex  |
  +------------+     | ware    |     | authorize|      |   LRU Cache    |
                     +---------+     +----------+      +-------+--------+
                          |                                    |
                          |  request.app['policy_evaluator']   |
                          +------->  (handler-level checks)    |
                                                               v
                                                    +--------------------+
                                                    | Rust Engine (PyO3) |
                                                    | evaluate_single()  |
                                                    | filter_batch()     |
                                                    | glob + regex       |
                                                    +--------------------+
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `PDP` (`pdp.py`) | modifies | `authorize()` delegates to PolicyEvaluator; `_load_policy_dicts()` uses PolicyAdapter |
| `PolicyEvaluator` (`evaluator.py`) | modifies | Becomes central engine; calls Rust `evaluate_single()` |
| `abac_middleware` (`middleware.py`) | extends | Registers PolicyEvaluator on `request.app`; global URI blocking |
| `Guardian` (`guardian.py`) | unchanged | PEP interface stable; benefits from faster PDP |
| `pgStorage` (`storages/pg.py`) | extends | Optional: reload trigger support |
| `YAMLStorage` (`storages/yaml_storage.py`) | unchanged | Output feeds PolicyAdapter |
| `Rust PEP` (`rust/src/lib.rs`) | extends | Adds regex, `evaluate_single()` |
| `ResourcePolicy` (`resource_policy.py`) | unchanged | Already the target model |
| `ResourcePattern` / `ResourceType` (`resources.py`) | extends | DATASET type already added |

### Data Models

```python
# PolicyAdapter output — all policies normalized to this shape
class ResourcePolicy(AbstractPolicy):
    """Unified policy representation for Rust evaluation."""
    name: str
    effect: PolicyEffect
    resources: List[str]          # ["uri:/api/v1/*", "tool:jira_*"]
    actions: List[str]            # ["tool:execute", "uri:GET"]
    subjects: SubjectSpec         # groups, users, roles, exclusions
    conditions: dict              # context-based conditions
    environment: dict             # time/date constraints
    priority: int
    enforcing: bool


# Adapter conversion map (internal)
class AdapterResult:
    """Result of adapting a classic policy dict."""
    policy: Optional[ResourcePolicy]
    warnings: List[str]           # conversion warnings
    skipped: bool                 # True if policy was unconvertible
    reason: str                   # skip reason if applicable
```

```rust
// Rust-side policy definition (extended with regex support)
struct PolicyDef {
    name: String,
    effect: String,               // "allow" or "deny"
    resources: Vec<String>,       // ["tool:jira_*", "uri:/epson.*$"]
    actions: Vec<String>,
    subjects: SubjectSpec,
    conditions: ConditionSpec,
    priority: i32,
    enforcing: bool,
}

// Pattern type detection
enum PatternKind {
    Exact,                        // "jira_create"
    Glob,                         // "jira_*"
    Regex,                        // "/epson.*$"
}
```

### New Public Interfaces

```python
# PolicyAdapter — load-time conversion
class PolicyAdapter:
    """Converts classic policy dicts to ResourcePolicy instances."""

    @staticmethod
    def adapt(policy_dict: dict) -> AdapterResult:
        """Convert a single policy dict to ResourcePolicy."""
        ...

    @staticmethod
    def adapt_batch(policy_dicts: List[dict]) -> Tuple[List[ResourcePolicy], List[str]]:
        """Convert a batch of policy dicts. Returns (policies, warnings)."""
        ...


# PDP — new reload method
class PDP:
    async def reload_policies(self) -> int:
        """Hot-reload policies from DB/YAML. Returns count of loaded policies."""
        ...

    @property
    def evaluator(self) -> PolicyEvaluator:
        """Access the PolicyEvaluator instance."""
        ...


# PolicyEvaluator — new Rust-backed single evaluation
class PolicyEvaluator:
    def check_access(
        self, ctx: EvalContext,
        resource_type: ResourceType, resource_name: str, action: str,
        env: Environment = None
    ) -> EvaluationResult:
        """Single resource check. Uses Rust evaluate_single()."""
        ...
```

```rust
// New Rust function exposed to Python
#[pyfunction]
fn evaluate_single(
    policies_json: &str,
    resource: &str,               // "uri:/api/v1/users"
    action: &str,                 // "uri:GET"
    user_context: &PyDict,        // {username, groups, roles}
    environment: &PyDict,         // {hour, dow, is_business_hours, ...}
) -> PyResult<PyObject>;          // {allowed, effect, matched_policy, reason}
```

---

## 3. Module Breakdown

### Module 1: Rust Regex + evaluate_single
- **Path**: `rust/src/lib.rs`, `rust/Cargo.toml`
- **Responsibility**: Extend pattern matching to support regex alongside glob. Add
  `evaluate_single()` PyO3 function for single-resource evaluation. Add `regex` crate.
- **Depends on**: None (standalone Rust changes)
- **Details**:
  - `matches_pattern()`: detect pattern kind (exact, glob, regex) and dispatch.
    Regex detected by presence of `^`, `$`, `(`, `)`, `+`, `{` metacharacters after
    splitting `type:pattern`.
  - `evaluate_single()`: evaluates one resource against all policies. Same logic as
    `evaluate_resource()` but exposed directly to Python (not just via batch).
  - Add Rust unit tests for regex patterns and `evaluate_single`.

### Module 2: PolicyAdapter
- **Path**: `navigator_auth/abac/policies/adapter.py` (new file)
- **Responsibility**: Convert classic policy dicts to `ResourcePolicy` instances at load time.
- **Depends on**: `ResourcePolicy`, `ResourceType`, `SubjectSpec`, `PolicyEffect`
- **Details**:
  - URN conversion: `urn:uri:/path` -> `uri:/path`; `urn:ns:type::parts` -> `type:parts`.
  - Classic `Policy`: maps `groups` -> `subjects.groups`, `subject` -> `subjects.users`,
    `resources` -> ResourcePolicy resources with type extraction, `context` -> conditions.
  - `FilePolicy`: maps file glob resources to `uri:` type patterns.
  - `ObjectPolicy`: maps object type/resources to respective `ResourceType`.
  - Negated patterns (`!resource`) converted to separate DENY ResourcePolicy.
  - Validates regex patterns at conversion time; logs + skips invalid ones.
  - HTTP method mapping: `GET` -> `uri:read`, `POST` -> `uri:write`, `DELETE` -> `uri:delete`, etc.

### Module 3: PDP Delegation
- **Path**: `navigator_auth/abac/pdp.py`
- **Responsibility**: Modify PDP to use PolicyAdapter for loading and PolicyEvaluator for
  evaluation instead of direct Python policy evaluation.
- **Depends on**: Module 1 (Rust), Module 2 (PolicyAdapter)
- **Details**:
  - `_load_policy_dicts()`: All policy types pass through `PolicyAdapter.adapt()` ->
    `ResourcePolicy` -> loaded into `PolicyEvaluator`.
  - `authorize()`: builds EvalContext, extracts `resource_type=URI` and
    `resource_name=request.path`, `action=method-mapped`, delegates to
    `PolicyEvaluator.check_access()`.
  - `is_allowed()`: delegates to `PolicyEvaluator.check_access()` with provided
    resource/action.
  - `filter_files()`: delegates to `PolicyEvaluator.filter_resources()` with URI patterns.
  - Add `self._evaluator: PolicyEvaluator` attribute initialized during `_load_policies()`.
  - Preserve existing interface signatures and return types (`PolicyResponse`).

### Module 4: PolicyEvaluator Rust Integration
- **Path**: `navigator_auth/abac/policies/evaluator.py`
- **Responsibility**: Wire PolicyEvaluator to use Rust engine for evaluation.
- **Depends on**: Module 1 (Rust)
- **Details**:
  - `check_access()`: on cache miss, serialize relevant policies to JSON, call Rust
    `evaluate_single()`, convert result to `EvaluationResult`.
  - `filter_resources()`: serialize policies to JSON, call Rust `filter_resources_batch()`,
    convert result to `FilteredResources`.
  - Policy JSON is pre-serialized and cached on the evaluator (not per-request).
  - Import: `from navigator_auth_pep import evaluate_single, filter_resources_batch`.
  - Add `_policies_json: str` cached attribute, rebuilt on index changes.

### Module 5: Hot Reload
- **Path**: `navigator_auth/abac/pdp.py`, `navigator_auth/abac/policies/evaluator.py`
- **Responsibility**: Enable reloading policies from DB/YAML without server restart.
- **Depends on**: Module 3 (PDP Delegation), Module 4 (Evaluator Integration)
- **Details**:
  - `PDP.reload_policies()`: async method that re-loads from storage, re-runs adapter,
    creates new `PolicyIndex`, atomically swaps `_evaluator._index` and clears cache.
  - `PolicyEvaluator.swap_index(new_index, new_json)`: thread-safe index swap.
  - REST endpoint: `POST /api/v1/abac/reload` triggers `PDP.reload_policies()`.
  - Optional: periodic reload with configurable interval (default disabled).

### Module 6: Middleware Integration
- **Path**: `navigator_auth/abac/middleware.py`
- **Responsibility**: Make PolicyEvaluator accessible to handlers via `request.app`.
- **Depends on**: Module 3 (PDP Delegation)
- **Details**:
  - During PDP startup, register `app['policy_evaluator'] = pdp.evaluator`.
  - Middleware `authorize()` call already goes through PDP, which now uses the evaluator.
  - No change to middleware flow — just ensure evaluator is accessible for handler-level
    checks.

### Module 7: Tests
- **Path**: `tests/test_policy_adapter.py`, `tests/test_evaluator_rust.py`,
  `tests/test_hot_reload.py`
- **Responsibility**: Validate adapter conversion, Rust evaluation, and hot reload.
- **Depends on**: All modules

---

## 4. Test Specification

### Unit Tests

| Test | Module | Description |
|---|---|---|
| `test_adapt_classic_policy` | Module 2 | Converts Policy dict with groups/subject/resources to ResourcePolicy |
| `test_adapt_urn_uri_pattern` | Module 2 | Converts `urn:uri:/api/v1/example/` to `uri:/api/v1/example/` |
| `test_adapt_urn_regex_pattern` | Module 2 | Converts `urn:uri:/epson.*$` to `uri:/epson.*$` with regex flag |
| `test_adapt_urn_namespace` | Module 2 | Converts `urn:navigator:dashboard::*` to `dashboard:*` |
| `test_adapt_negated_resource` | Module 2 | Converts `!resource` to separate DENY ResourcePolicy |
| `test_adapt_file_policy` | Module 2 | Converts FilePolicy with glob patterns to URI ResourcePolicy |
| `test_adapt_object_policy` | Module 2 | Converts ObjectPolicy with type/objects to typed ResourcePolicy |
| `test_adapt_invalid_regex` | Module 2 | Logs warning and skips policy with invalid regex |
| `test_adapt_batch` | Module 2 | Converts mixed batch of policy types |
| `test_rust_glob_matching` | Module 1 | Rust matches glob patterns (`tool:jira_*`) |
| `test_rust_regex_matching` | Module 1 | Rust matches regex patterns (`/epson.*$`) |
| `test_rust_evaluate_single` | Module 1 | Single resource evaluation returns correct result |
| `test_rust_evaluate_enforcing` | Module 1 | Enforcing policy short-circuits evaluation |
| `test_rust_deny_wins_on_tie` | Module 1 | Equal priority deny beats allow |
| `test_evaluator_check_access` | Module 4 | PolicyEvaluator.check_access() delegates to Rust |
| `test_evaluator_filter_batch` | Module 4 | PolicyEvaluator.filter_resources() uses Rust batch |
| `test_evaluator_caching` | Module 4 | LRU cache returns cached result on repeat |
| `test_pdp_authorize_delegates` | Module 3 | PDP.authorize() uses PolicyEvaluator |
| `test_pdp_is_allowed_delegates` | Module 3 | PDP.is_allowed() uses PolicyEvaluator |
| `test_hot_reload` | Module 5 | reload_policies() swaps index and clears cache |
| `test_hot_reload_preserves_inflight` | Module 5 | In-flight requests complete with old index |

### Integration Tests

| Test | Description |
|---|---|
| `test_middleware_authorize_flow` | Full HTTP request through middleware -> PDP -> Evaluator -> Rust |
| `test_middleware_uri_blocking` | Global URI policy blocks request path |
| `test_handler_policy_evaluator_access` | Handler accesses `request.app['policy_evaluator']` |
| `test_db_load_and_evaluate` | Load policies from pgStorage -> adapt -> evaluate in Rust |
| `test_yaml_load_and_evaluate` | Load policies from YAML -> adapt -> evaluate in Rust |
| `test_reload_endpoint` | POST /api/v1/abac/reload triggers reload and new policies apply |
| `test_mixed_policy_types` | Classic + ResourcePolicy coexist after adaptation |

### Test Data / Fixtures

```python
@pytest.fixture
def classic_policy_dict():
    return {
        "name": "admin_dashboard",
        "policy_type": "policy",
        "effect": "allow",
        "groups": ["admin"],
        "subject": ["jlara@trocglobal.com"],
        "resources": ["urn:uri:/api/v1/admin/*"],
        "actions": ["dashboard:view", "dashboard:edit"],
        "environment": {"is_business_hours": True},
        "priority": 10,
        "enforcing": False
    }

@pytest.fixture
def file_policy_dict():
    return {
        "name": "reports_access",
        "policy_type": "file",
        "effect": "allow",
        "groups": ["analytics"],
        "resources": ["urn:uri:/reports/*.pdf"],
        "actions": ["file:read"],
        "priority": 5
    }

@pytest.fixture
def resource_policy_dict():
    return {
        "name": "engineering_tools",
        "policy_type": "resource",
        "effect": "allow",
        "resources": ["tool:jira_*", "tool:github_*"],
        "actions": ["tool:execute"],
        "subjects": {"groups": ["engineering"]},
        "priority": 10
    }

@pytest.fixture
def regex_uri_policy_dict():
    return {
        "name": "block_printers",
        "policy_type": "policy",
        "effect": "deny",
        "groups": ["*"],
        "resources": ["urn:uri:/epson.*$"],
        "actions": [],
        "priority": 100,
        "enforcing": True
    }

@pytest.fixture
def sample_user_context():
    return {
        "username": "testuser",
        "groups": ["engineering", "analytics"],
        "roles": ["developer"]
    }

@pytest.fixture
def sample_environment():
    return Environment()  # Defaults to current time
```

---

## 5. Acceptance Criteria

> This feature is complete when ALL of the following are true:

- [ ] `PolicyAdapter` converts all classic policy types (policy, file, object) to
  `ResourcePolicy` without data loss for supported features.
- [ ] URN patterns (`urn:uri:/path`, `urn:ns:type::parts`) are correctly converted to
  `type:pattern` format.
- [ ] Rust engine matches both glob (`tool:jira_*`) and regex (`/epson.*$`) patterns.
- [ ] `evaluate_single()` Rust function is exposed via PyO3 and callable from Python.
- [ ] `PDP.authorize()` delegates to `PolicyEvaluator.check_access()` successfully.
- [ ] `PDP.is_allowed()` delegates to `PolicyEvaluator` for resource checks.
- [ ] Middleware registers `PolicyEvaluator` on `request.app['policy_evaluator']`.
- [ ] `PDP.reload_policies()` reloads from DB/YAML and swaps the evaluator index atomically.
- [ ] Policy evaluation in the middleware path completes within 10ms (p99).
- [ ] All unit tests pass (`pytest tests/test_policy_adapter.py tests/test_evaluator_rust.py -v`).
- [ ] All integration tests pass.
- [ ] Rust module compiles with `maturin develop` and all Rust tests pass (`cargo test`).
- [ ] Existing `PDP` public interface signatures unchanged (backward compatible).
- [ ] No Python fallback for Rust module — import failure prevents startup with clear error.

---

## 6. Implementation Notes & Constraints

### Patterns to Follow
- Use `PolicyAdapter` as a stateless utility (static methods) — no instance state needed.
- Rust pattern detection: check for regex metacharacters (`^$(){}+`) after the `type:` prefix.
  If found, use `regex` crate; otherwise use `glob-match`.
- Pre-serialize policies to JSON once on load/reload, cache on `PolicyEvaluator._policies_json`.
  Do not serialize per-request.
- Index swap must be atomic: build new `PolicyIndex` + new JSON string, then replace both
  references in a single assignment. Python's GIL ensures reference swap is atomic.
- Preserve `PolicyResponse` return type from PDP methods — wrap `EvaluationResult` into
  `PolicyResponse` in the PDP layer.

### URN Conversion Rules

| Input URN | Output ResourcePolicy Resource | ResourceType |
|---|---|---|
| `urn:uri:/api/v1/example/` | `uri:/api/v1/example/` | URI |
| `urn:uri:/epson.*$` | `uri:/epson.*$` | URI |
| `urn:navigator:dashboard::*` | `dashboard:*` | (custom or mapped) |
| `urn:navigator:dashboard::12345` | `dashboard:12345` | (custom or mapped) |
| `urn:navigator:dashboard::!12345` | Separate DENY `dashboard:12345` | (custom or mapped) |
| `tool:jira_*` (already new format) | `tool:jira_*` | TOOL |
| `dataset:sales_*` | `dataset:sales_*` | DATASET |

### HTTP Method to Action Mapping (for middleware URI policies)

| HTTP Method | Action |
|---|---|
| GET | `uri:read` |
| POST | `uri:write` |
| PUT | `uri:write` |
| PATCH | `uri:write` |
| DELETE | `uri:delete` |
| OPTIONS | (skip evaluation) |
| HEAD | `uri:read` |

### Known Risks / Gotchas
- **Context attribute matching**: Classic policies can match against `ctx.session.<attr>`
  or `ctx.user.<attr>`. These don't map to ResourcePolicy subject/condition model.
  **Mitigation**: Log a warning during adaptation. For now, these conditions are dropped
  with a warning. If needed in the future, a `_python_post_filter` can be added.
- **Regex ReDoS**: Unlikely because Rust's `regex` crate uses a linear-time NFA engine
  (no backtracking). However, validate that patterns compile at load time to catch syntax
  errors early.
- **Policy JSON size**: For large policy sets, the JSON string could be significant.
  **Mitigation**: At expected scale (< 100 policies), this is negligible. Monitor if
  policy count grows.
- **Hot reload race**: Between index swap and cache clear, a few requests may get stale
  cache hits. **Mitigation**: Cache TTL (300s) bounds this. For critical changes, the
  reload endpoint clears cache atomically with the swap.

### External Dependencies

| Package | Version | Reason |
|---|---|---|
| `pyo3` | `0.22` | Python-Rust FFI (already in use) |
| `rayon` | `1.10` | Parallel batch evaluation (already in use) |
| `glob-match` | `0.2` | Glob pattern matching (already in use) |
| `serde_json` | `1.0` | JSON serialization (already in use) |
| `regex` | `>=1.10` | Regex pattern matching in Rust (**new**) |

---

## 7. Open Questions

- [x] Should the periodic DB reload use a simple polling interval (e.g., every 60s) or
  a smarter mechanism (version counter in DB)? Polling is simpler but adds DB load.
  — *Owner: Jesus Lara*: Polling interval every 60 seconds.
- [x] How should unconvertible context conditions (`ctx.session.custom_field`) be handled?
  Current plan: drop with warning. Alternative: Python post-filter after Rust evaluation.
  — *Owner: Jesus Lara*: python post-filter after rust evaluation.
- [x] Should `FilePolicy.filter_files()` also route through Rust, or remain Python-only
  since it involves filesystem I/O anyway?: remain python-only.
  — *Owner: Jesus Lara*
- [x] What regex syntax boundary to document? Rust's `regex` crate supports most Perl-style
  syntax except backreferences and lookaheads. This should be documented for policy authors.
  — *Owner: Jesus Lara*: Rust's regex with clear documentation.

---

## Worktree Strategy

- **Default isolation**: `mixed` (some tasks parallelizable).
- **Parallel group 1** (Rust): Module 1 (regex + evaluate_single) — standalone, `rust/` directory only.
- **Parallel group 2** (Python adapter): Module 2 (PolicyAdapter) — new file, no conflicts.
- **Sequential after groups 1+2**: Module 3 (PDP Delegation), Module 4 (Evaluator Integration),
  Module 5 (Hot Reload), Module 6 (Middleware Integration) — these share `pdp.py` and
  `evaluator.py`, must be sequential.
- **Module 7** (Tests): can partially overlap with integration modules.
- **Cross-feature dependencies**: FEAT-001 (policy-based-access-control) should be merged
  first as it establishes the base PolicyEvaluator and ResourcePolicy infrastructure.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-04-03 | Jesus Lara | Initial draft from brainstorm Option B |
| 1.0 | 2026-04-03 | session-e2e-task | Fully implemented and verified with E2E tests |
