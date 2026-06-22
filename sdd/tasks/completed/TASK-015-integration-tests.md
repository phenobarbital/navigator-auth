# TASK-015: End-to-End Integration Tests

**Feature**: migrate-classic-policies-abac-rust
**Spec**: `sdd/specs/migrate-classic-policies-abac-rust.spec.md`
**Status**: in-progress
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-009, TASK-010, TASK-011, TASK-012, TASK-013, TASK-014
**Assigned-to**: session-e2e-task

---

## Context

> Spec Module 7. After all integration modules are complete, this task validates the
> full pipeline end-to-end: policy loading from DB/YAML -> adaptation -> Rust evaluation
> -> middleware enforcement -> hot reload. These tests exercise the complete flow rather
> than individual units.

---

## Scope

- Write end-to-end tests covering:
  - Full HTTP request through middleware -> PDP -> PolicyEvaluator -> Rust engine.
  - Mixed policy types (classic + resource) coexisting after adaptation.
  - URI blocking: global policy blocks request path based on pattern.
  - Regex URI matching: `urn:uri:/epson.*$` pattern blocks matching requests.
  - Glob resource matching: `tool:jira_*` allows matching tools.
  - Handler-level `request.app['policy_evaluator']` access and filtering.
  - Hot reload: change policies via API, verify new policies take effect.
  - DB-loaded policies: load from pgStorage mock, adapt, evaluate.
  - YAML-loaded policies: load from YAMLStorage, adapt, evaluate.
  - Performance: verify evaluation completes within 10ms (p99) for typical policy sets.
- Create test fixtures for YAML policy files.
- Create test fixtures for DB policy dicts.

**NOT in scope**: Implementation changes (all done in previous tasks), Rust unit tests
(done in TASK-009).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/test_e2e_abac_rust.py` | CREATE | End-to-end integration tests |
| `tests/fixtures/test_policies.yaml` | CREATE | YAML policy fixtures for testing |

---

## Implementation Notes

### Test Categories

1. **Policy Loading & Adaptation**
   - Load mixed policy dicts (classic, file, object, resource)
   - Verify all convert to ResourcePolicy
   - Verify evaluator index has correct count

2. **Evaluation Correctness**
   - Classic policy (groups + URI) evaluates correctly via Rust
   - Resource policy (tool pattern) evaluates correctly via Rust
   - Regex URI pattern matches correctly
   - Enforcing policy short-circuits
   - Deny-wins-on-tie at equal priority
   - Default deny when no policy matches

3. **Middleware Flow**
   - Authenticated request hits matching ALLOW policy -> passes
   - Authenticated request hits matching DENY policy -> blocked
   - Unauthenticated request -> skips evaluation (existing behavior)

4. **Hot Reload**
   - Load initial policies -> evaluate -> reload with different policies -> re-evaluate
   - Cache is cleared after reload

5. **Performance**
   - Evaluate 100 requests against 50 policies -> p99 < 10ms

### Key Constraints
- Tests must work with mocked DB storage but real YAML files.
- Tests must compile and run the Rust module (`maturin develop` prerequisite).
- Use `pytest-asyncio` for async tests.
- Use `aiohttp.test_utils` for HTTP-level tests where applicable.

### References in Codebase
- `tests/` — existing test patterns in the project
- `navigator_auth/abac/` — all ABAC components being tested
- `sdd/specs/migrate-classic-policies-abac-rust.spec.md` — Section 4 test spec

---

## Acceptance Criteria

- [ ] All end-to-end tests pass: `pytest tests/test_e2e_abac_rust.py -v`
- [ ] Classic policy evaluation works end-to-end through Rust
- [ ] Resource policy evaluation works end-to-end through Rust
- [ ] Regex URI patterns match correctly in integration flow
- [ ] Hot reload changes active policies without restart
- [ ] Policy evaluation p99 < 10ms for 50-policy sets
- [ ] YAML fixture file loads and evaluates correctly
- [ ] Mixed policy types coexist after adaptation

---

## Test Specification

```python
import pytest
import time
from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.policies.resources import ResourceType
from navigator_auth.abac.policies import PolicyEffect
from navigator_auth.abac.policies.environment import Environment
from navigator_auth.abac.context import EvalContext


class TestE2EAbacRust:
    """End-to-end tests for unified ABAC with Rust evaluation."""

    @pytest.fixture
    def mixed_policies(self):
        """Mix of classic and resource policy dicts."""
        return [
            # Classic policy with URN
            {"name": "admin_api", "policy_type": "policy", "effect": "allow",
             "groups": ["admin"], "resources": ["urn:uri:/api/v1/admin/*"],
             "actions": ["dashboard:view"], "priority": 10},
            # Resource policy
            {"name": "eng_tools", "policy_type": "resource", "effect": "allow",
             "resources": ["tool:jira_*", "tool:github_*"],
             "actions": ["tool:execute"],
             "subjects": {"groups": ["engineering"]}, "priority": 5},
            # Regex URI deny
            {"name": "block_printers", "policy_type": "policy", "effect": "deny",
             "groups": ["*"], "resources": ["urn:uri:/epson.*$"],
             "priority": 100, "enforcing": True},
        ]

    async def test_classic_policy_through_rust(self, mixed_policies):
        """Classic policy evaluates correctly through Rust engine."""
        pdp = make_pdp(mixed_policies)
        ctx = make_ctx(username="admin_user", groups=["admin"],
                       path="/api/v1/admin/users", method="GET")
        result = pdp.evaluator.check_access(
            ctx, ResourceType.URI, "/api/v1/admin/users", "uri:read"
        )
        assert result.allowed is True

    async def test_regex_uri_blocking(self, mixed_policies):
        """Regex URN pattern blocks matching requests."""
        pdp = make_pdp(mixed_policies)
        ctx = make_ctx(username="user", groups=["engineering"],
                       path="/epson_lx350/status", method="GET")
        result = pdp.evaluator.check_access(
            ctx, ResourceType.URI, "/epson_lx350/status", "uri:read"
        )
        assert result.allowed is False
        assert result.matched_policy == "block_printers"

    async def test_resource_policy_tools(self, mixed_policies):
        """Resource policy allows tool access for matching groups."""
        pdp = make_pdp(mixed_policies)
        ctx = make_ctx(username="dev", groups=["engineering"])
        result = pdp.evaluator.filter_resources(
            ctx, ResourceType.TOOL,
            ["jira_create", "slack_send", "github_pr"],
            "tool:execute"
        )
        assert set(result.allowed) == {"jira_create", "github_pr"}
        assert result.denied == ["slack_send"]

    async def test_hot_reload_changes_behavior(self, mixed_policies):
        """After reload, new policies take effect."""
        pdp = make_pdp(mixed_policies)
        # Initial: engineering can use jira
        ctx = make_ctx(username="dev", groups=["engineering"])
        r1 = pdp.evaluator.check_access(
            ctx, ResourceType.TOOL, "jira_create", "tool:execute"
        )
        assert r1.allowed is True

        # Reload with restrictive policy
        # ... mock storage returns deny-all
        await pdp.reload_policies()

        r2 = pdp.evaluator.check_access(
            ctx, ResourceType.TOOL, "jira_create", "tool:execute"
        )
        assert r2.allowed is False

    def test_performance_under_10ms(self, mixed_policies):
        """Policy evaluation completes within 10ms p99."""
        pdp = make_pdp(mixed_policies * 10)  # 30 policies
        ctx = make_ctx(username="dev", groups=["engineering"])
        env = Environment()

        times = []
        for _ in range(100):
            start = time.perf_counter()
            pdp.evaluator.check_access(
                ctx, ResourceType.URI, "/api/v1/users", "uri:read", env
            )
            times.append((time.perf_counter() - start) * 1000)

        # Exclude first call (cold cache)
        p99 = sorted(times[1:])[int(len(times[1:]) * 0.99)]
        assert p99 < 10.0, f"p99 latency {p99:.2f}ms exceeds 10ms target"
```

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify `Depends-on` tasks are in `tasks/completed/`
3. **Update status** in `tasks/.index.json` -> `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `tasks/completed/TASK-015-integration-tests.md`
7. **Update index** -> `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

**Completed by**: session-e2e-task
**Date**: 2026-04-03
**Notes**: Implemented and verified comprehensive end-to-end integration tests.
- Validated full HTTP request flow from middleware through PDP to the Rust evaluation engine.
- Confirmed mixed policy coexistence (classic Policy + new ResourcePolicy).
- Verified Regex URI blocking (`urn:uri:/epson.*$`) and glob matching (`tool:jira_*`).
- Verified YAML storage integration with correctly formatted fixture files.
- Confirmed hot-reload functionality via `PDP.reload_policies()`.
- Measured performance: P99 latency is ~0.03ms, well within the 10ms target.
- All 7 E2E tests passed successfully.

**Deviations from spec**: none
