# Brainstorm: Migrate Classic ABAC Policies to Rust-Accelerated Evaluation

**Date**: 2026-04-03
**Author**: Jesus Lara
**Status**: exploration
**Recommended Option**: Option B

---

## Problem Statement

The ABAC middleware currently evaluates classic `Policy` objects (including `FilePolicy` and
`ObjectPolicy`) in pure Python via `PDP.authorize()`. This path runs sequentially using
`asyncio.to_thread()` without native acceleration. Meanwhile, the `PolicyEvaluator` with
`ResourcePolicy` has a high-performance Rust module (`navigator_auth_pep`) using Rayon for
parallel batch evaluation — but it is completely disconnected from the middleware flow.

**Who is affected:**
- **Developers**: Two separate policy models (classic vs resource) create confusion about
  which to use and how they're evaluated.
- **Operators**: No hot-reload capability means policy changes require server restarts.
- **End users**: Middleware latency is higher than necessary for policy evaluation.

**Why now:** There are no classic policies in production yet, making this the ideal time
to unify before adoption locks in the current architecture.

## Constraints & Requirements

- **Performance**: Policy evaluation must not exceed 10ms per request in the middleware path.
- **URN support**: Must handle existing URN patterns including `urn:uri:/api/v1/example/`
  and regex patterns like `urn:uri:/epson.*$`.
- **Pattern matching**: Rust engine must support both glob (`tool:jira_*`) and regex
  (`urn:uri:/epson.*$`) patterns.
- **Rust mandatory**: The `navigator_auth_pep` module is a required dependency (no Python
  fallback needed).
- **Hot reload**: Policy changes (especially DB-stored) must take effect without server
  restart.
- **Backward compatibility**: Existing policy dict/YAML format must continue to work;
  conversion happens at load time, not at authoring time.
- **Middleware scope**: `PolicyEvaluator` in the middleware is for global blocking (handlers,
  API endpoints), not for real-time per-object filtering on every request.

---

## Options Explored

### Option A: Extend Rust Engine Only — Keep Dual Python Paths

Add regex support and URN handling to the Rust `filter_resources_batch` function, but keep
the Python-side architecture as-is: `PDP.authorize()` continues to evaluate classic policies
in Python, and `PolicyEvaluator` remains a separate component. A new Rust function
`evaluate_single` is added for the PDP to call per-request.

The PDP would serialize each classic policy to JSON and call into Rust for individual
evaluation, replacing `asyncio.to_thread(policy.evaluate, ...)`.

**Pros:**
- Minimal architectural change — PDP and PolicyEvaluator stay independent.
- Rust acceleration for both paths without restructuring.
- Lower risk: classic policy semantics preserved exactly.

**Cons:**
- Two evaluation paths remain (PDP + PolicyEvaluator), duplicating logic.
- Per-request JSON serialization overhead for PDP calls (policies serialized on every request).
- No unification of the policy model — developers still must choose between Policy and ResourcePolicy.
- Hot reload requires changes in both PDP and PolicyEvaluator separately.

**Effort:** Medium

**Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `pyo3 0.22` | Python-Rust FFI | Already in use |
| `rayon 1.10` | Parallel evaluation | Already in use |
| `glob-match 0.2` | Glob pattern matching | Already in use |
| `regex 1.x` | Regex pattern matching | New dependency for URN support |

**Existing Code to Reuse:**
- `rust/src/lib.rs` — extend `matches_pattern()` with regex branch
- `navigator_auth/abac/pdp.py` — modify `authorize()` to call Rust
- `navigator_auth/abac/policies/evaluator.py` — unchanged

---

### Option B: Unified PolicyEvaluator as Single Engine (Recommended)

Unify all policy types under a single `PolicyEvaluator` that uses the Rust engine for
evaluation. At load time, classic `Policy`, `FilePolicy`, and `ObjectPolicy` dicts are
converted to `ResourcePolicy`-compatible format by a new `PolicyAdapter` layer. The PDP
delegates authorization to the `PolicyEvaluator` instead of evaluating policies itself.

**Architecture flow:**
1. **Load time**: `PDP._load_policy_dicts()` converts all policy dicts (classic, file, object)
   into `ResourcePolicy` instances via `PolicyAdapter`.
2. **PDP.authorize()**: Delegates to `PolicyEvaluator.check_access()` instead of iterating
   policies directly.
3. **PolicyEvaluator**: Uses the Rust engine for evaluation (single resource via
   `evaluate_single()`, batch via `filter_resources_batch()`).
4. **Middleware**: Gets access to `PolicyEvaluator` via `request.app['policy_evaluator']`
   for global resource blocking.
5. **Hot reload**: A `reload_policies()` method on PDP triggers re-load from DB/YAML,
   re-converts via adapter, and swaps the PolicyEvaluator's index atomically.

**URN conversion examples:**
- `urn:uri:/api/v1/example/` maps to `ResourcePolicy(resources=["uri:/api/v1/example/"])`
- `urn:uri:/epson.*$` maps to `ResourcePolicy(resources=["uri:/epson.*$"])` with regex flag
- Classic `Policy(groups=["admin"], resources=["urn:navigator:dashboard::*"])` maps to
  `ResourcePolicy(resources=["dashboard:*"], subjects={"groups": ["admin"]})`

**Pros:**
- Single evaluation engine — one path to optimize, test, and reason about.
- All policies benefit from Rust acceleration and Rayon parallelism.
- Developers use one policy model (`ResourcePolicy` format).
- Hot reload is centralized in one place (PolicyEvaluator index swap).
- PDP interface (`authorize()`, `is_allowed()`, `filter_files()`) stays intact — callers
  don't change.
- Middleware integration is natural: PolicyEvaluator is already designed for `check_access()`.

**Cons:**
- PolicyAdapter must handle all edge cases of classic policy format (context matching,
  nested URN parsing, negated resources).
- Higher upfront effort to build and validate the adapter layer.
- Some classic `Policy` features (arbitrary context attribute matching via `ctx.user.<attr>`,
  `ctx.session.<attr>`) may not map cleanly to ResourcePolicy's subject/condition model.

**Effort:** High

**Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `pyo3 0.22` | Python-Rust FFI | Already in use |
| `rayon 1.10` | Parallel evaluation | Already in use |
| `glob-match 0.2` | Glob pattern matching | Already in use |
| `regex 1.x` | Regex pattern matching in Rust | New: URN regex support |
| `serde_json 1.0` | JSON serialization | Already in use |

**Existing Code to Reuse:**
- `rust/src/lib.rs` — extend with regex support and `evaluate_single()` function
- `navigator_auth/abac/policies/evaluator.py` — PolicyEvaluator becomes the central engine
- `navigator_auth/abac/policies/resource_policy.py` — ResourcePolicy as the unified model
- `navigator_auth/abac/policies/resources.py` — ResourcePattern, ResourceType, SubjectSpec
- `navigator_auth/abac/pdp.py` — PDP delegates to PolicyEvaluator
- `navigator_auth/abac/policies/abstract.py` — PolicyEffect, PolicyResponse (shared types)
- `navigator_auth/abac/storages/pg.py` — DB loading stays, output feeds adapter
- `navigator_auth/abac/storages/yaml_storage.py` — YAML loading stays, output feeds adapter

---

### Option C: Compile Classic Policy Logic to Rust Directly

Instead of converting classic policies to ResourcePolicy format, implement the full classic
`Policy.evaluate()` logic in Rust — including groups matching, subject matching, arbitrary
context attribute lookups, environment evaluation, and URN parsing. The Rust module would
accept the raw classic policy format and the full EvalContext as serialized JSON.

This would be a 1:1 port of `Policy.evaluate()`, `FilePolicy.is_allowed()`, and
`ObjectPolicy.is_allowed()` to Rust, preserving all semantics exactly.

**Pros:**
- Zero conversion overhead — policies load as-is into Rust.
- Perfect semantic fidelity with current Python behavior.
- No adapter layer complexity.

**Cons:**
- Massive Rust implementation effort: must replicate all Python evaluation quirks
  (ctx.user attribute lookups, session matching, regex resource parts, negated patterns, etc.)
- Two policy models still exist (classic + resource) — just both in Rust now.
- Context serialization is expensive: EvalContext contains request objects, headers, session
  data that don't serialize trivially to JSON.
- Maintaining two Rust evaluation paths (classic + resource) defeats the purpose of unification.
- Testing burden doubles.

**Effort:** Very High

**Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `pyo3 0.22` | Python-Rust FFI | Already in use |
| `rayon 1.10` | Parallel evaluation | Already in use |
| `regex 1.x` | Full regex engine for URN patterns | New dependency |
| `serde_json 1.0` | Deep context serialization | Already in use |

**Existing Code to Reuse:**
- `rust/src/lib.rs` — massive extension required
- `navigator_auth/abac/policies/policy.py` — reference implementation to port
- `navigator_auth/abac/policies/obj.py` — reference implementation to port
- `navigator_auth/abac/policies/file.py` — reference implementation to port

---

### Option D: Event-Driven Hybrid with Watcher

Keep Python evaluation for classic policies but add a file/DB watcher that pre-compiles
policies into a Rust-compatible binary cache. On startup and on change events, policies are
serialized to a shared memory segment or binary file that Rust reads directly, avoiding
per-request JSON serialization.

The PolicyEvaluator would use memory-mapped policy data for zero-copy evaluation in Rust.

**Pros:**
- Near-zero per-request serialization cost.
- Elegant hot-reload via filesystem/DB watchers.
- Rust evaluator works on pre-compiled data.

**Cons:**
- Significant complexity: shared memory management, binary format design, cache invalidation.
- Over-engineered for the expected policy volume (< 50 policies, < 10ms target).
- Debugging binary policy cache is much harder than JSON.
- DB watcher adds infrastructure dependency (PostgreSQL LISTEN/NOTIFY or polling).

**Effort:** Very High

**Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `pyo3 0.22` | Python-Rust FFI | Already in use |
| `memmap2` | Memory-mapped files in Rust | New dependency |
| `bincode` | Binary serialization | New dependency |
| `tokio-postgres` | Async PostgreSQL for LISTEN/NOTIFY | New dependency |

**Existing Code to Reuse:**
- `rust/src/lib.rs` — redesign for memory-mapped input
- `navigator_auth/abac/storages/pg.py` — add LISTEN/NOTIFY support

---

## Recommendation

**Option B** is recommended because:

1. **Unification over acceleration**: The real problem isn't just speed — it's having two
   parallel policy models with different evaluation paths. Option B solves both by making
   `ResourcePolicy` the universal internal representation.

2. **Right level of effort**: Option A is faster to implement but leaves architectural debt
   (dual paths). Option C is a faithful port but doubles the Rust surface area for no
   unification benefit. Option D is over-engineered for the expected scale.

3. **Clean adapter boundary**: Converting at load time (not evaluation time) means the
   adapter runs once per policy change, not once per request. The per-request path is pure
   Rust evaluation against pre-indexed `ResourcePolicy` objects.

4. **Hot reload is natural**: Reloading means re-running the adapter + swapping the index.
   DB-triggered reload can use a simple version counter or timestamp check — no need for
   PostgreSQL LISTEN/NOTIFY at this stage.

5. **Acceptable tradeoff**: Some classic `Policy` features (deep context attribute matching
   like `ctx.session.custom_field`) may need to be expressed as ResourcePolicy conditions.
   This is a constraint, but given there are no production policies yet, it's the right
   time to standardize.

---

## Feature Description

### User-Facing Behavior

- **Policy authors** continue writing policies in YAML or storing them in the database using
  the existing format. Classic policy format (`policy_type: policy/file/object`) is accepted
  and automatically converted to `ResourcePolicy` at load time.
- **New policies** can be authored directly in `ResourcePolicy` format with `type:pattern`
  resources, which is now the recommended format.
- **Hot reload**: When a policy is saved to the database, the evaluator picks up the change
  without server restart. YAML-based policies reload on file change detection.
- **Middleware blocking**: Global policies (e.g., "block all access to `/admin/*` outside
  business hours") are enforced automatically by the middleware via the PolicyEvaluator.
- **Handler-level checks**: Individual handlers can call `request.app['policy_evaluator']`
  to check access to specific resources (tools, datasets, KBs).

### Internal Behavior

1. **Startup / Load**:
   - PDP loads policy dicts from DB (`pgStorage`) and YAML (`YAMLStorage`).
   - `PolicyAdapter` converts each dict to `ResourcePolicy`:
     - Classic `Policy`: maps `groups` to `subjects.groups`, `subject` to `subjects.users`,
       `resources` (URN) to `ResourcePolicy.resources` with type extraction,
       `context` to `conditions`, `environment` stays as-is.
     - `FilePolicy`: maps file glob resources to `uri:` type patterns.
     - `ObjectPolicy`: maps object resources to their respective `ResourceType`.
   - All `ResourcePolicy` instances are loaded into `PolicyEvaluator` (which indexes by
     `ResourceType` in `PolicyIndex`).
   - Policies are serialized to JSON and cached for Rust engine consumption.

2. **Per-Request Evaluation (Middleware)**:
   - Middleware calls `PDP.authorize(request)`.
   - PDP builds `EvalContext`, then calls `PolicyEvaluator.check_access()` with extracted
     resource type (URI from request path) and action (HTTP method mapped to action).
   - `PolicyEvaluator` checks its LRU cache. On miss, calls the Rust
     `evaluate_single()` function with the pre-serialized policies JSON, resource string,
     user context, and environment.
   - Rust evaluates: enforcing policies first, then regular by priority, deny-wins-on-tie.
   - Result returned as `EvaluationResult` (allowed, effect, matched_policy, reason).

3. **Batch Filtering (Handlers)**:
   - Handlers call `PolicyEvaluator.filter_resources()` with a list of resource names.
   - Delegates to Rust `filter_resources_batch()` with Rayon parallelism.

4. **Hot Reload**:
   - `PDP.reload_policies()` method: re-loads from DB/YAML, re-runs adapter, atomically
     swaps `PolicyEvaluator._index` and invalidates cache.
   - Triggered by: explicit API call, or periodic check (configurable interval).

5. **Rust Engine Extensions**:
   - `matches_pattern()` extended: tries glob first, if pattern contains regex metacharacters
     (`^`, `$`, `(`, `)`), falls back to regex matching.
   - New `evaluate_single()` PyO3 function for single-resource evaluation (middleware path).
   - URN-to-resource conversion handled in Python adapter (Rust sees `type:pattern` only).

### Edge Cases & Error Handling

- **Unconvertible policies**: If a classic policy has context conditions that can't map to
  ResourcePolicy conditions (e.g., `ctx.session.custom_field`), the adapter logs a warning
  and creates the ResourcePolicy with a special `_python_conditions` flag. These are
  evaluated in Python as a post-filter after Rust evaluation.
- **Invalid regex patterns**: Rust `regex` crate rejects invalid patterns at compile time.
  The adapter validates regex patterns during conversion; invalid patterns are logged and
  the policy is skipped.
- **Empty policy set**: If no policies match a request, default-deny applies (existing
  behavior preserved).
- **Rust module crash**: Since the module is mandatory, a compilation or import failure
  prevents server startup with a clear error message.
- **Cache invalidation race**: During hot reload, in-flight requests may see stale cache
  entries. This is acceptable — the cache TTL (300s default) bounds staleness, and the
  reload swaps the index atomically.
- **URN edge cases**: `urn:uri:/path` is converted to `uri:/path`. `urn:navigator:dashboard::*`
  is converted to `dashboard:*`. Negated patterns (`!resource`) are converted to separate
  DENY policies.

---

## Capabilities

### New Capabilities
- `policy-adapter`: Converts classic Policy/FilePolicy/ObjectPolicy dicts to ResourcePolicy
  format at load time.
- `rust-regex-matching`: Extends Rust engine with regex pattern support alongside glob.
- `rust-evaluate-single`: New Rust function for single-resource evaluation (middleware path).
- `policy-hot-reload`: Reload policies from DB/YAML without server restart.
- `middleware-policy-evaluator`: Integrates PolicyEvaluator into the ABAC middleware for
  global resource blocking.

### Modified Capabilities
- `policy-based-access-control`: PDP delegates evaluation to PolicyEvaluator instead of
  evaluating classic policies directly.
- `rust-pep-batch-filter`: Extended with regex support and `evaluate_single()`.

---

## Impact & Integration

| Affected Component | Impact Type | Notes |
|---|---|---|
| `navigator_auth/abac/pdp.py` | modifies | `authorize()` delegates to PolicyEvaluator; `_load_policy_dicts()` uses PolicyAdapter |
| `navigator_auth/abac/middleware.py` | extends | Stores PolicyEvaluator reference on `request.app` |
| `navigator_auth/abac/policies/evaluator.py` | modifies | Becomes central engine; adds `evaluate_single()` Rust call |
| `rust/src/lib.rs` | extends | Adds regex matching, `evaluate_single()` function |
| `rust/Cargo.toml` | modifies | Adds `regex` crate dependency |
| `navigator_auth/abac/policies/resources.py` | extends | New `DATASET` ResourceType (already added) |
| `navigator_auth/abac/storages/pg.py` | extends | Optional: add reload trigger support |
| `navigator_auth/abac/guardian.py` | minimal | PEP interface unchanged; benefits from faster PDP |
| `navigator_auth/abac/policies/policy.py` | unchanged | Still exists for reference; no longer in hot path |
| `navigator_auth/abac/policies/resource_policy.py` | unchanged | Already the target model |

---

## Parallelism Assessment

- **Internal parallelism**: Yes — tasks can be split:
  - Rust engine changes (regex, evaluate_single) are independent of Python adapter work.
  - PolicyAdapter is independent of PDP delegation changes.
  - Hot reload mechanism is independent of middleware integration.
- **Cross-feature independence**: Touches PDP and middleware which are core paths. Low
  conflict with other features if they don't modify `pdp.py` or `middleware.py`.
- **Recommended isolation**: `mixed` — Rust engine tasks in one worktree, Python adapter +
  PDP integration in another, middleware integration can be sequential after both.
- **Rationale**: Rust and Python changes are in different directories with no file overlap.
  PDP + middleware changes share Python files and should be sequential.

---

## Open Questions

- [ ] Should the periodic DB reload use a simple polling interval (e.g., every 60s) or a
  smarter mechanism (version counter in DB, pg_notify)? — *Owner: Jesus Lara*
- [ ] How should `_python_conditions` fallback work for unconvertible context conditions?
  Post-filter in Python after Rust, or reject the policy at load time? — *Owner: Jesus Lara*
- [ ] Should `FilePolicy.filter_files()` also route through Rust, or remain Python-only
  since it involves filesystem I/O anyway? — *Owner: Jesus Lara*
- [ ] What is the regex syntax boundary? Full PCRE, or a safe subset (no backreferences,
  no lookaheads) to prevent ReDoS? Rust's `regex` crate is linear-time by default which
  mitigates this. — *Owner: Jesus Lara*
