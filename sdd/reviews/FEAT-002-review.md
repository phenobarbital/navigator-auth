# Code Review: FEAT-002 — Migrate Classic ABAC Policies to Rust-Accelerated Evaluation

**Spec**: `sdd/specs/migrate-classic-policies-abac-rust.spec.md`
**Reviewed files**: `rust/src/lib.rs`, `navigator_auth/abac/policies/evaluator.py`, `navigator_auth/abac/policies/adapter.py`, `navigator_auth/abac/pdp.py`, `navigator_auth/abac/policies/environment.py`, `navigator_auth/abac/policies/resources.py`, `navigator_auth/abac/policyhandler.py`, `tests/test_unified_evaluation.py`
**Tasks covered**: TASK-009 through TASK-015
**Overall verdict**: ❌ **Needs Changes** — 4 critical bugs will cause runtime failures or security regressions before this reaches production.

---

## Summary

The architecture is sound and the Rust integration is well-structured. The `PolicyAdapter`, `PolicyEvaluator`, and hot-reload pipeline follow the spec closely. However, four critical issues must be fixed: (1) `filter_files()` is broken because the migration replaced all policy objects but the filter still checks for the old type; (2) `asyncio.create_task()` is called in a synchronous method, causing a startup crash when periodic reload is configured; (3) the Rust unit tests have a wrong argument count that prevents `cargo test` from compiling; and (4) `PDP.allowed_groups()` has an `UnboundLocalError` that will crash on unauthenticated requests. Several important issues follow, including a silent Python fallback that contradicts the spec's security contract.

---

## Critical Issues 🔴

### 1. `filter_files()` ALWAYS raises `PreconditionFailed` after migration — production regression

**`navigator_auth/abac/pdp.py:336`**

After FEAT-002, `self._policies` is populated exclusively with `ResourcePolicy` instances (the adapter converts `FilePolicy` dicts via `_adapt_classic`, which returns `ResourcePolicy`). The `type(p) == FilePolicy` check always evaluates to `False`, so `filtered` is always empty, and the function always raises `PreconditionFailed`.

### 2. `asyncio.create_task()` in a synchronous method — crashes on startup with periodic reload

**`navigator_auth/abac/pdp.py:205-206`**

`asyncio.create_task()` requires a running event loop. `setup()` is called synchronously during application initialization, before the aiohttp event loop is running. With `ABAC_RELOAD_INTERVAL > 0`, this will raise `RuntimeError: no running event loop`.

### 3. Rust unit tests fail to compile — `cargo test` is broken

**`rust/src/lib.rs:681` and `rust/src/lib.rs:721`**

`evaluate_resource()` has 7 parameters (including `owner_reports_to: Option<&str>`), but both unit tests call it with 6 arguments, omitting `owner_reports_to`. Rust requires exact argument counts, so `cargo test` will not compile.

### 4. `UnboundLocalError` in `allowed_groups()` — crash on unauthenticated requests

**`navigator_auth/abac/pdp.py:296-304`**

When `session[AUTH_SESSION_OBJECT]` raises `KeyError` (unauthenticated request), `userinfo` is never assigned, causing `UnboundLocalError` on the next line.

---

## Important Issues 🟠

### 5. Silent Python fallback violates the spec's security contract

**`navigator_auth/abac/policies/evaluator.py:393-395` and `561-571`**

The spec explicitly states: "No Python fallback when Rust module is unavailable (Rust is now mandatory)". This fallback creates a security concern: if Rust correctly denies a request but raises an exception due to a serialization issue, the Python fallback may produce a different (allowing) result, creating an authorization bypass window.

### 6. `python_conditions` collected but never evaluated — silent authorization bypass

**`navigator_auth/abac/policies/adapter.py:169-173`**

The spec question #2 was answered: "python post-filter after rust evaluation." However, no post-filter was implemented. Classic policies with `context` conditions are silently converted to policies without those conditions.

### 7. `PDP.reload_policies()` accesses a private method — encapsulation violation

**`navigator_auth/abac/pdp.py:156`**

`PDP` directly calls `self._evaluator._serialize_policies_from_index(new_index)`.

### 8. Cache key–based user invalidation is completely broken

**`navigator_auth/abac/policies/evaluator.py:327-329`**

Cache keys are MD5 hex digests — they never start with a `user_id`. This method silently does nothing when called with a `user_id`.

### 9. `subject` string not guarded against character-set expansion

**`navigator_auth/abac/policies/adapter.py:163-164`**

If `subject` is a bare string (not a list), `set("jlara@example.com")` produces a set of individual characters.

### 10. `PolicyIndex.add()` — O(N·K) re-sort on every insert

**`navigator_auth/abac/policies/evaluator.py:80-84`**

Sorting every bucket on every `add()` during batch loading is O(N·K·log N). Unnecessary.

### 11. `PDP.filter_obj()` will also always fail post-migration

**`navigator_auth/abac/pdp.py:433`**

Like `filter_files()`, this relies on `ObjectPolicy`-specific attributes (`_filter`, `fits()`).

---

## Suggestions 🟡

### 12. `Environment` — Monday (dow=0) conflated with "not set"

**`navigator_auth/abac/policies/environment.py:114-120`**

`day_of_week=0` means both "not overridden" and "Monday". Tests using `Environment(hour=10, day_of_week=0)` will fail on non-Monday days.

### 13. Rust — duplicated regex pre-compilation loop

**`rust/src/lib.rs:432-453` and `553-573`**

20-line regex detection + pre-compilation block is copy-pasted identically between `filter_resources_batch` and `evaluate_single`.

### 14. F-strings in `logger.error()` / `logger.warning()` calls

Multiple locations. F-strings are always evaluated regardless of log level. Use `%s` format.

### 15. JSON deserialization on every Rust call

Both `evaluate_single` and `filter_resources_batch` call `serde_json::from_str(policies_json)` on every invocation.

---

## Nitpicks 💡

- `_update_cache()` is not true LRU — `min()` scan is O(N). Use `collections.OrderedDict` for O(1) eviction.
- `PDP.policies()` method naming confusion with `_policies` attribute.
- Missing type hints on `adapt_batch` return annotation.

---

## Positive Observations ✅

- Rust evaluation engine is well-structured: pattern matching, priority resolution, deny-wins-on-tie, enforcing short-circuit, and hierarchy checks are all correct.
- `PolicyAdapter` is stateless and cleanly designed with comprehensive URN conversion.
- `PolicyEvaluator._build_user_context()` handles both `userinfo` dict and `ctx.user` object gracefully.
- `PolicyLoader` handles bad policies resiliently (logs and continues).
- `_periodic_reload()` correctly uses `asyncio.CancelledError` break.
- `on_shutdown()` cleanly cancels the reload task.
- Test coverage is broad: glob, regex, hierarchy, time-range, priorities, and negation.
- `PolicyHandler.reload` is properly auth-gated with `@groups_protected(groups=['superuser'])`.

---

## Acceptance Criteria Check

| Criterion | Status | Notes |
|---|---|---|
| `PolicyAdapter` converts classic/file/object policy types | ✅ | Works correctly |
| URN patterns convert to `type:pattern` format | ✅ | Correct |
| Rust matches glob and regex patterns | ✅ | Correct in lib.rs |
| `evaluate_single()` callable from Python | ✅ | Exposed via PyO3 |
| `PDP.authorize()` delegates to `PolicyEvaluator.check_access()` | ✅ | |
| `PDP.is_allowed()` delegates to `PolicyEvaluator` | ✅ | |
| Middleware registers `PolicyEvaluator` on `request.app` | ✅ | In `on_startup` |
| `PDP.reload_policies()` swaps index atomically | ✅ | Correct |
| Policy evaluation within 10ms (p99) | ✅ | ~0.03ms per completion note |
| All unit tests pass | ❌ | Rust unit tests won't compile (arg count mismatch) |
| All integration tests pass | ⚠️ | `filter_files` regression not covered |
| Rust compiles with `maturin develop` | ✅ | (PyO3 surface is fine) |
| `cargo test` passes | ❌ | Compile error in unit tests |
| PDP public interface unchanged | ⚠️ | `filter_files`/`filter_obj` are broken |
| No Python fallback for Rust | ❌ | Fallback present in `check_access` and `filter_resources` |
