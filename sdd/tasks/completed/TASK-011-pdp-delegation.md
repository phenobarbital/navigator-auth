# TASK-011: PDP Delegation to PolicyEvaluator

**Feature**: migrate-classic-policies-abac-rust
**Spec**: `sdd/specs/migrate-classic-policies-abac-rust.spec.md`
**Status**: in-progress
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-009, TASK-010
**Assigned-to**: session-pdp-task

---

## Context

> Spec Module 3. The PDP currently evaluates classic Policy objects directly in
> `authorize()` and `is_allowed()`. This task rewires PDP to use PolicyAdapter for
> loading and PolicyEvaluator for all evaluation, making it the central delegation
> point. The PDP public interface remains unchanged.

---

## Scope

- Modify `PDP._load_policy_dicts()` to pass all policy dicts through `PolicyAdapter.adapt_batch()`,
  then load resulting `ResourcePolicy` instances into a `PolicyEvaluator`.
- Add `self._evaluator: PolicyEvaluator` attribute to PDP, initialized during `_load_policies()`.
- Add `PDP.evaluator` property for external access.
- Modify `PDP.authorize()`:
  - Build `EvalContext` (unchanged).
  - Extract `resource_type=ResourceType.URI`, `resource_name=request.path`,
    `action=METHOD_ACTION_MAP[request.method]`.
  - Call `self._evaluator.check_access(ctx, resource_type, resource_name, action, env)`.
  - Convert `EvaluationResult` to `PolicyResponse` for backward compatibility.
- Modify `PDP.is_allowed()` to delegate to evaluator with provided resource/action.
- Keep `PDP.filter_files()` in Python (per spec decision) but use evaluator for
  permission checks where applicable.
- Preserve all existing return types and exception behavior.
- Write integration tests for the new flow.

**NOT in scope**: Hot reload (Module 5), Middleware changes (Module 6), Rust changes (Module 1).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/pdp.py` | MODIFY | Rewire loading and evaluation to use adapter + evaluator |
| `tests/test_pdp_delegation.py` | CREATE | Tests for PDP -> PolicyEvaluator delegation |

---

## Implementation Notes

### Pattern to Follow

```python
# In PDP.__init__
from navigator_auth.abac.policies.adapter import PolicyAdapter
from navigator_auth.abac.policies.evaluator import PolicyEvaluator
from navigator_auth.abac.policies.resources import ResourceType

class PDP:
    def __init__(self, storage, policies=None, yaml_storage=None):
        # ... existing init ...
        self._evaluator: PolicyEvaluator = PolicyEvaluator()

    @property
    def evaluator(self) -> PolicyEvaluator:
        return self._evaluator

    def _load_policy_dicts(self, policy_dicts):
        """Convert all policy dicts and load into evaluator."""
        resource_policies, warnings = PolicyAdapter.adapt_batch(policy_dicts)
        for w in warnings:
            self.logger.warning(f"Policy adaptation warning: {w}")
        self._evaluator.load_policies(resource_policies)

    async def authorize(self, request, session=None, user=None, **kwargs):
        # Build EvalContext (existing logic)
        ctx = EvalContext(request=request, session=session, user=user, ...)

        # Map HTTP method to action
        method_map = {"GET": "uri:read", "HEAD": "uri:read",
                      "POST": "uri:write", "PUT": "uri:write",
                      "PATCH": "uri:write", "DELETE": "uri:delete"}
        action = method_map.get(request.method, "uri:read")

        # Delegate to evaluator
        result = self._evaluator.check_access(
            ctx, ResourceType.URI, request.path, action
        )

        # Convert to PolicyResponse for backward compat
        return PolicyResponse(
            effect=result.effect,
            response=result.reason,
            rule=result.matched_policy or "",
            actions=[action]
        )
```

### Key Constraints
- `PDP.authorize()` must still raise `PreconditionFailed` when appropriate.
- `PDP.authorize()` must still call `auditlog()` after evaluation.
- `PolicyResponse` return type must be preserved.
- The `_policies` list can still hold policies for backward-compat code paths,
  but the hot path uses `_evaluator`.

### References in Codebase
- `navigator_auth/abac/pdp.py:187-229` — current `authorize()` implementation
- `navigator_auth/abac/pdp.py:83-112` — current `_load_policy_dicts()`
- `navigator_auth/abac/pdp.py:306-362` — current `is_allowed()`
- `navigator_auth/abac/policies/evaluator.py:266-319` — `PolicyEvaluator.check_access()`
- `navigator_auth/abac/policies/abstract.py:20-24` — `PolicyResponse` class

---

## Acceptance Criteria

- [ ] `PDP._load_policy_dicts()` uses `PolicyAdapter.adapt_batch()` to convert policies
- [ ] `PDP._evaluator` is populated with converted ResourcePolicy instances
- [ ] `PDP.authorize()` delegates to `PolicyEvaluator.check_access()`
- [ ] `PDP.authorize()` returns `PolicyResponse` (backward compatible)
- [ ] `PDP.authorize()` still raises `PreconditionFailed` when no policies match
- [ ] `PDP.authorize()` still calls `auditlog()`
- [ ] `PDP.is_allowed()` delegates to `PolicyEvaluator.check_access()`
- [ ] `PDP.evaluator` property provides access to the evaluator instance
- [ ] `PDP.filter_files()` remains Python-based
- [ ] All existing PDP tests still pass
- [ ] New delegation tests pass: `pytest tests/test_pdp_delegation.py -v`

---

## Test Specification

```python
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.policies import PolicyEffect


class TestPDPDelegation:
    @pytest.fixture
    def pdp_with_policies(self):
        """PDP loaded with a mix of classic and resource policies."""
        storage = MagicMock()
        storage.load_policies = AsyncMock(return_value=[
            {"name": "admin_api", "policy_type": "policy", "effect": "allow",
             "groups": ["admin"], "resources": ["urn:uri:/api/v1/admin/*"],
             "priority": 10},
            {"name": "tools", "policy_type": "resource", "effect": "allow",
             "resources": ["tool:jira_*"], "actions": ["tool:execute"],
             "subjects": {"groups": ["engineering"]}, "priority": 5},
        ])
        return PDP(storage=storage)

    async def test_authorize_delegates_to_evaluator(self, pdp_with_policies):
        """authorize() uses PolicyEvaluator, not direct Policy evaluation."""
        # Setup request mock
        request = MagicMock()
        request.path = "/api/v1/admin/users"
        request.method = "GET"
        # ... verify evaluator.check_access is called

    async def test_authorize_returns_policy_response(self, pdp_with_policies):
        """authorize() returns PolicyResponse for backward compat."""
        result = await pdp_with_policies.authorize(request=mock_request)
        assert hasattr(result, 'effect')
        assert hasattr(result, 'response')
        assert hasattr(result, 'rule')

    def test_evaluator_property(self, pdp_with_policies):
        """PDP.evaluator returns the PolicyEvaluator instance."""
        assert pdp_with_policies.evaluator is not None
```

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify `Depends-on` tasks are in `tasks/completed/`
3. **Update status** in `tasks/.index.json` -> `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `tasks/completed/TASK-011-pdp-delegation.md`
7. **Update index** -> `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

**Completed by**: session-pdp-task
**Date**: 2026-04-03
**Notes**: Rewired `PDP` to delegate all authorization decisions to `PolicyEvaluator`.
- Modified `_load_policy_dicts` to use `PolicyAdapter.adapt_batch`.
- Added `self._evaluator` and `evaluator` property.
- Updated `authorize` and `is_allowed` to use `self._evaluator.check_access`.
- Preserved backward compatibility with `PolicyResponse` and exception handling (`AccessDenied`, `PreconditionFailed`).
- Integration tests implemented in `tests/test_pdp_delegation.py` pass.
- Existing policy tests also pass.

**Deviations from spec**: none
