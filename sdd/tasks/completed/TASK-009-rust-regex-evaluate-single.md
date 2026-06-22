# TASK-009: Rust Regex + evaluate_single

**Feature**: migrate-classic-policies-abac-rust
**Spec**: `sdd/specs/migrate-classic-policies-abac-rust.spec.md`
**Status**: in-progress
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: session-rust-task

---

## Context

> Spec Module 1. The Rust engine currently only supports glob matching via `glob-match`.
> To handle URN patterns like `urn:uri:/epson.*$`, regex support is needed. Additionally,
> `filter_resources_batch` is the only exposed function — the middleware needs a
> single-resource evaluation function (`evaluate_single`) to avoid batch overhead on
> per-request checks.

---

## Scope

- Add `regex` crate to `Cargo.toml` dependencies.
- Extend `matches_pattern()` in `lib.rs` to detect and dispatch regex patterns.
  - Pattern detection: if pattern contains `^`, `$`, `(`, `)`, `+`, `{` metacharacters
    (after the `type:` prefix split), treat as regex. Otherwise, use glob.
  - Cache compiled regex patterns using `lazy` or a local `HashMap<String, Regex>` to
    avoid recompilation per call.
- Add `evaluate_single()` PyO3 function that evaluates one resource against all policies.
  Same logic as `evaluate_resource()` but directly exposed to Python.
- Add Rust unit tests for regex patterns, mixed glob+regex, and `evaluate_single`.
- Expose `evaluate_single` in the `navigator_auth_pep` PyO3 module.

**NOT in scope**: Python-side integration (Module 4), PolicyAdapter (Module 2), PDP changes (Module 3).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `rust/Cargo.toml` | MODIFY | Add `regex = "1"` dependency |
| `rust/src/lib.rs` | MODIFY | Extend `matches_pattern()`, add `evaluate_single()`, add tests |

---

## Implementation Notes

### Pattern to Follow

```rust
// Pattern kind detection (add to lib.rs)
fn is_regex_pattern(pattern: &str) -> bool {
    // Regex metacharacters that don't appear in glob patterns
    pattern.contains('^') || pattern.contains('$') || pattern.contains('(')
        || pattern.contains(')') || pattern.contains('+') || pattern.contains('{')
}

// Extended matches_pattern
fn matches_pattern(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if is_regex_pattern(pattern) {
        // Use regex crate
        match regex::Regex::new(pattern) {
            Ok(re) => re.is_match(name),
            Err(_) => false, // Invalid regex = no match
        }
    } else if pattern.contains('*') || pattern.contains('?') {
        glob_match::glob_match(pattern, name)
    } else {
        pattern == name
    }
}

// evaluate_single signature
#[pyfunction]
#[pyo3(signature = (policies_json, resource, action, user_context, environment))]
fn evaluate_single(
    py: Python<'_>,
    policies_json: &str,
    resource: &str,
    action: &str,
    user_context: &Bound<'_, PyDict>,
    environment: &Bound<'_, PyDict>,
) -> PyResult<PyObject> {
    // Parse policies, user, env (same as filter_resources_batch)
    // Call evaluate_resource() for the single resource
    // Return dict: {allowed, effect, matched_policy, reason}
}
```

### Key Constraints
- Rust's `regex` crate is linear-time (NFA-based) — no ReDoS risk.
- `evaluate_single` must NOT use `py.allow_threads()` with Rayon — it's a single
  evaluation, no parallelism needed. Just release the GIL for the evaluation itself.
- Invalid regex patterns should return `false` (no match), not panic.
- Keep the existing `filter_resources_batch` working unchanged.

### References in Codebase
- `rust/src/lib.rs:82-91` — current `matches_pattern()` to extend
- `rust/src/lib.rs:202-247` — `evaluate_resource()` logic to reuse
- `rust/src/lib.rs:265-351` — `filter_resources_batch()` as pattern for PyO3 function

---

## Acceptance Criteria

- [ ] `cargo test` passes with all new and existing tests
- [ ] `matches_pattern("epson.*$", "epson_lx350")` returns true (regex)
- [ ] `matches_pattern("jira_*", "jira_create")` returns true (glob, unchanged)
- [ ] `matches_pattern("^/api/v[12]/.*", "/api/v1/users")` returns true (regex)
- [ ] `matches_pattern("invalid(regex[", "anything")` returns false (no panic)
- [ ] `evaluate_single` is callable from Python and returns `{allowed, effect, matched_policy, reason}`
- [ ] `evaluate_single` respects enforcing policies, priority, deny-wins-on-tie
- [ ] `maturin develop` compiles successfully
- [ ] Existing `filter_resources_batch` tests still pass

---

## Test Specification

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex_matching() {
        assert!(matches_pattern("epson.*$", "epson_lx350"));
        assert!(matches_pattern("^/api/v[12]/.*", "/api/v1/users"));
        assert!(matches_pattern("^/api/v[12]/.*", "/api/v2/admin"));
        assert!(!matches_pattern("^/api/v[12]/.*", "/web/home"));
    }

    #[test]
    fn test_invalid_regex_no_panic() {
        assert!(!matches_pattern("invalid(regex[", "anything"));
    }

    #[test]
    fn test_glob_still_works() {
        assert!(matches_pattern("jira_*", "jira_create"));
        assert!(matches_pattern("*", "anything"));
        assert!(!matches_pattern("jira_*", "github_pr"));
    }

    #[test]
    fn test_regex_vs_glob_disambiguation() {
        // Contains $ -> regex
        assert!(matches_pattern("/path.*$", "/path/to/resource"));
        // Contains only * -> glob
        assert!(matches_pattern("path_*", "path_abc"));
    }

    #[test]
    fn test_evaluate_resource_with_regex() {
        let policies = vec![PolicyDef {
            name: "block_printers".into(),
            effect: "deny".into(),
            resources: vec!["uri:epson.*$".into()],
            actions: vec![],
            subjects: SubjectSpec {
                groups: vec!["*".into()],
                ..Default::default()
            },
            conditions: ConditionSpec::default(),
            priority: 100,
            enforcing: true,
        }];
        let user = UserContext {
            username: "testuser".into(),
            groups: vec!["engineering".into()],
            roles: vec![],
        };
        let env = EnvironmentContext::default();

        assert!(!evaluate_resource(&policies, "uri:epson_lx350", "uri:read", &user, &env));
    }
}
```

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify `Depends-on` tasks are in `tasks/completed/`
3. **Update status** in `tasks/.index.json` -> `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `tasks/completed/TASK-009-rust-regex-evaluate-single.md`
7. **Update index** -> `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

**Completed by**: session-rust-task
**Date**: 2026-04-03
**Notes**: Implemented regex support in Rust matching engine and added `evaluate_single` PyO3 function. Added regex crate to dependencies. All Rust and Python verification tests passed.

**Deviations from spec**: none
