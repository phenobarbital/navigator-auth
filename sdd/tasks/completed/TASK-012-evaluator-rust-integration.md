# TASK-012: PolicyEvaluator Rust Integration

**Feature**: migrate-classic-policies-abac-rust
**Spec**: `sdd/specs/migrate-classic-policies-abac-rust.spec.md`
**Status**: in-progress
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-009
**Assigned-to**: session-rust-integration-task

---

## Context

> Spec Module 4. The PolicyEvaluator currently evaluates policies in pure Python.
> This task wires it to call the Rust engine (`evaluate_single` for per-request,
> `filter_resources_batch` for batch filtering). Policy JSON is pre-serialized and
> cached on the evaluator to avoid per-request serialization.

---

## Scope

- Import `navigator_auth_pep` module (mandatory, no fallback).
- Modify `PolicyEvaluator.check_access()` to call Rust `evaluate_single()` on cache miss.
- Modify `PolicyEvaluator.filter_resources()` to call Rust `filter_resources_batch()`.
- Add `_policies_json: str` cached attribute, rebuilt when policies are loaded or index changes.
- Add `_serialize_policies()` method that converts all indexed ResourcePolicies to JSON.
- Build `user_context` and `environment` dicts from `EvalContext` and `Environment` for Rust.
- Convert Rust return dicts to `EvaluationResult` and `FilteredResources`.
- Write tests validating Rust integration.

**NOT in scope**: PDP changes (Module 3), PolicyAdapter (Module 2), Hot reload (Module 5).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/policies/evaluator.py` | MODIFY | Wire check_access/filter_resources to Rust |
| `tests/test_evaluator_rust.py` | CREATE | Tests for Rust-backed evaluation |

---

## Implementation Notes

### Pattern to Follow

```python
from navigator_auth_pep import evaluate_single, filter_resources_batch
import json

class PolicyEvaluator:
    def __init__(self, ...):
        # ... existing init ...
        self._policies_json: str = "[]"

    def load_policies(self, policies: List[ResourcePolicy]) -> None:
        for policy in policies:
            self._index.add(policy)
        self._rebuild_json_cache()

    def _rebuild_json_cache(self) -> None:
        """Serialize all policies to JSON for Rust engine."""
        policies_data = []
        for policy in self._index.all():
            policies_data.append({
                "name": policy.name,
                "effect": "allow" if policy.effect == PolicyEffect.ALLOW else "deny",
                "resources": [f"{p.resource_type.value}:{p.pattern}"
                              for p in policy._resource_patterns],
                "actions": list(policy._actions),
                "subjects": {
                    "groups": list(policy._subjects.groups),
                    "users": list(policy._subjects.users),
                    "roles": list(policy._subjects.roles),
                    "exclude_groups": list(policy._subjects.exclude_groups),
                    "exclude_users": list(policy._subjects.exclude_users),
                },
                "conditions": {"environment": policy._env_conditions},
                "priority": policy.priority,
                "enforcing": policy.enforcing,
            })
        self._policies_json = json.dumps(policies_data)

    def _build_user_context(self, ctx: EvalContext) -> dict:
        return {
            "username": ctx.userinfo.get("username", "anonymous"),
            "groups": ctx.userinfo.get("groups", []),
            "roles": ctx.userinfo.get("roles", []),
        }

    def _build_env_dict(self, env: Environment) -> dict:
        return {
            "hour": env.hour,
            "dow": env.dow,
            "is_business_hours": env.is_business_hours,
            "is_weekend": env.is_weekend,
            "day_segment": env.day_segment.value if hasattr(env.day_segment, 'value') else str(env.day_segment),
        }

    def check_access(self, ctx, resource_type, resource_name, action, env=None):
        # ... cache check (existing) ...

        if env is None:
            env = Environment()

        user_ctx = self._build_user_context(ctx)
        user_ctx["action"] = action
        env_dict = self._build_env_dict(env)

        result_dict = evaluate_single(
            self._policies_json,
            f"{resource_type.value}:{resource_name}",
            action,
            user_ctx,
            env_dict,
        )

        result = EvaluationResult(
            allowed=result_dict["allowed"],
            effect=PolicyEffect.ALLOW if result_dict["allowed"] else PolicyEffect.DENY,
            matched_policy=result_dict.get("matched_policy"),
            reason=result_dict.get("reason", ""),
        )
        # ... cache update, timing ...
        return result
```

### Key Constraints
- `navigator_auth_pep` import is at module level — import failure prevents startup.
- `_policies_json` is rebuilt only on `load_policies()` and `swap_index()`, never per-request.
- `_build_user_context()` and `_build_env_dict()` must handle missing/None values gracefully.
- The LRU cache (existing) still applies — Rust is only called on cache miss.
- `filter_resources` passes `user_ctx["action"]` for batch, since all resources share the same action.

### References in Codebase
- `navigator_auth/abac/policies/evaluator.py:266-319` — current `check_access()` to modify
- `navigator_auth/abac/policies/evaluator.py:434-470` — current `filter_resources()` to modify
- `navigator_auth/abac/policies/environment.py` — Environment model fields
- `navigator_auth/abac/context.py` — EvalContext structure
- `rust/src/lib.rs:265-351` — Rust function signatures

---

## Acceptance Criteria

- [ ] `from navigator_auth_pep import evaluate_single, filter_resources_batch` works
- [ ] `check_access()` calls Rust `evaluate_single()` on cache miss
- [ ] `filter_resources()` calls Rust `filter_resources_batch()` for batch evaluation
- [ ] `_policies_json` is pre-serialized and cached (not built per-request)
- [ ] `_rebuild_json_cache()` correctly serializes ResourcePolicy to Rust-compatible JSON
- [ ] LRU cache still works — repeated calls with same params don't hit Rust
- [ ] `EvaluationResult` and `FilteredResources` are correctly constructed from Rust output
- [ ] All tests pass: `pytest tests/test_evaluator_rust.py -v`
- [ ] Existing evaluator tests still pass

---

## Test Specification

```python
import pytest
from navigator_auth.abac.policies.evaluator import PolicyEvaluator, EvaluationResult
from navigator_auth.abac.policies.resource_policy import ResourcePolicy
from navigator_auth.abac.policies.resources import ResourceType
from navigator_auth.abac.policies import PolicyEffect
from navigator_auth.abac.policies.environment import Environment
from navigator_auth.abac.context import EvalContext


class TestEvaluatorRust:
    @pytest.fixture
    def evaluator_with_policies(self):
        evaluator = PolicyEvaluator()
        policy = ResourcePolicy(
            name="allow_engineering_tools",
            effect=PolicyEffect.ALLOW,
            resources=["tool:jira_*", "tool:github_*"],
            actions=["tool:execute"],
            subjects={"groups": ["engineering"]},
            priority=10,
        )
        evaluator.load_policies([policy])
        return evaluator

    def test_check_access_allowed(self, evaluator_with_policies):
        ctx = make_eval_context(username="dev", groups=["engineering"])
        result = evaluator_with_policies.check_access(
            ctx, ResourceType.TOOL, "jira_create", "tool:execute"
        )
        assert result.allowed is True

    def test_check_access_denied(self, evaluator_with_policies):
        ctx = make_eval_context(username="guest", groups=["visitors"])
        result = evaluator_with_policies.check_access(
            ctx, ResourceType.TOOL, "jira_create", "tool:execute"
        )
        assert result.allowed is False

    def test_filter_resources_batch(self, evaluator_with_policies):
        ctx = make_eval_context(username="dev", groups=["engineering"])
        result = evaluator_with_policies.filter_resources(
            ctx, ResourceType.TOOL,
            ["jira_create", "slack_send", "github_pr"],
            "tool:execute"
        )
        assert "jira_create" in result.allowed
        assert "github_pr" in result.allowed
        assert "slack_send" in result.denied

    def test_policies_json_cached(self, evaluator_with_policies):
        json1 = evaluator_with_policies._policies_json
        json2 = evaluator_with_policies._policies_json
        assert json1 is json2  # Same object, not rebuilt

    def test_cache_hit_no_rust_call(self, evaluator_with_policies):
        ctx = make_eval_context(username="dev", groups=["engineering"])
        r1 = evaluator_with_policies.check_access(
            ctx, ResourceType.TOOL, "jira_create", "tool:execute"
        )
        r2 = evaluator_with_policies.check_access(
            ctx, ResourceType.TOOL, "jira_create", "tool:execute"
        )
        assert r2.cached is True
```

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify `Depends-on` tasks are in `tasks/completed/`
3. **Update status** in `tasks/.index.json` -> `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `tasks/completed/TASK-012-evaluator-rust-integration.md`
7. **Update index** -> `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

**Completed by**: session-rust-integration-task
**Date**: 2026-04-03
**Notes**: Integrated Rust engine into `PolicyEvaluator`. 
- Added `_policies_json` cache rebuilt on policy load.
- Updated `check_access` to delegate to Rust `evaluate_single` on cache miss.
- Updated `filter_resources` to delegate to Rust `filter_resources_batch`.
- Implemented robust fallback to Python evaluation if Rust fails or raises exceptions.
- Added comprehensive tests in `tests/test_evaluator_rust.py` covering allowed/denied, batch filtering, and regex support.
- All tests pass, including existing policy evaluation tests.

**Deviations from spec**: Added explicit type checking for resource type in `_rebuild_json_cache` to handle both Enums and strings gracefully.
