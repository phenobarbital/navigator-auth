# TASK-010: PolicyAdapter

**Feature**: migrate-classic-policies-abac-rust
**Spec**: `sdd/specs/migrate-classic-policies-abac-rust.spec.md`
**Status**: in-progress
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: none
**Assigned-to**: session-python-task

---

## Context

> Spec Module 2. The PolicyAdapter is the bridge between classic policy formats
> (Policy, FilePolicy, ObjectPolicy dicts from DB/YAML) and the unified ResourcePolicy
> model. It runs at load time only, converting each dict into a ResourcePolicy instance.
> This is the most complex module because it must handle all URN parsing, negated
> resources, and field mapping.

---

## Scope

- Create `navigator_auth/abac/policies/adapter.py` with `PolicyAdapter` class.
- Implement `adapt(policy_dict) -> AdapterResult` for each policy type:
  - `policy` -> ResourcePolicy (groups, subject, resources/URN, context, environment)
  - `file` -> ResourcePolicy (file globs as `uri:` patterns)
  - `object` -> ResourcePolicy (object types mapped to ResourceType)
  - `resource` -> ResourcePolicy (pass-through, already in target format)
- Implement URN conversion rules per spec:
  - `urn:uri:/path` -> `uri:/path`
  - `urn:ns:type::parts` -> `type:parts`
  - Negated (`!resource`) -> separate DENY ResourcePolicy
- Implement HTTP method to action mapping for URI policies.
- Implement `adapt_batch(dicts) -> (List[ResourcePolicy], List[str] warnings)`.
- Write unit tests for all conversion paths.

**NOT in scope**: PDP integration (Module 3), Rust changes (Module 1), hot reload (Module 5).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/policies/adapter.py` | CREATE | PolicyAdapter implementation |
| `tests/test_policy_adapter.py` | CREATE | Unit tests for all conversion paths |

---

## Implementation Notes

### Pattern to Follow

```python
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
from navigator_auth.abac.policies.resource_policy import ResourcePolicy
from navigator_auth.abac.policies import PolicyEffect
from navigator_auth.abac.policies.resources import ResourceType, SubjectSpec

@dataclass
class AdapterResult:
    policy: Optional[ResourcePolicy] = None
    warnings: List[str] = field(default_factory=list)
    skipped: bool = False
    reason: str = ""

class PolicyAdapter:
    """Converts classic policy dicts to ResourcePolicy at load time."""

    # HTTP method -> action mapping
    METHOD_ACTION_MAP = {
        "GET": "uri:read", "HEAD": "uri:read",
        "POST": "uri:write", "PUT": "uri:write", "PATCH": "uri:write",
        "DELETE": "uri:delete",
    }

    @staticmethod
    def adapt(policy_dict: dict) -> AdapterResult:
        policy_type = policy_dict.get("policy_type", "policy")
        if policy_type == "resource":
            return PolicyAdapter._adapt_resource(policy_dict)
        elif policy_type == "file":
            return PolicyAdapter._adapt_file(policy_dict)
        elif policy_type == "object":
            return PolicyAdapter._adapt_object(policy_dict)
        else:
            return PolicyAdapter._adapt_classic(policy_dict)
```

### URN Conversion Logic

```python
@staticmethod
def _convert_urn(urn_str: str) -> Tuple[str, bool]:
    """Convert URN to type:pattern format. Returns (converted, is_negated)."""
    negated = urn_str.startswith("!")
    if negated:
        urn_str = urn_str[1:]

    if urn_str.startswith("urn:uri:"):
        # urn:uri:/api/v1/... -> uri:/api/v1/...
        return f"uri:{urn_str[8:]}", negated
    elif urn_str.startswith("urn:"):
        # urn:namespace:type::parts -> type:parts
        parts = urn_str[4:].split("::", 1)
        prefix = parts[0].rsplit(":", 1)
        rtype = prefix[-1] if len(prefix) > 1 else prefix[0]
        rname = parts[1] if len(parts) > 1 else "*"
        return f"{rtype}:{rname}", negated
    elif ":" in urn_str:
        # Already in type:pattern format
        return urn_str, negated
    else:
        # Bare resource name -> uri: type
        return f"uri:{urn_str}", negated
```

### Key Constraints
- PolicyAdapter is stateless — all methods are `@staticmethod`.
- Validate regex patterns during conversion using Python `re.compile()`. Log and skip invalid.
- Context conditions that can't map to ResourcePolicy conditions (e.g., `ctx.session.custom_field`):
  store in a `_python_conditions` dict on the ResourcePolicy for post-filter (per spec decision).
- Return warnings list for each conversion so PDP can log them.

### References in Codebase
- `navigator_auth/abac/policies/resources.py:139-188` — `RequestResource` URN parsing logic
- `navigator_auth/abac/policies/resources.py:189-324` — `Resource` class URN handling
- `navigator_auth/abac/policies/resource_policy.py` — target ResourcePolicy model
- `navigator_auth/abac/pdp.py:83-112` — current `_load_policy_dicts()` to understand input format
- `navigator_auth/abac/storages/pg.py` — DB policy schema (columns map to dict keys)

---

## Acceptance Criteria

- [ ] `PolicyAdapter.adapt()` converts classic `Policy` dict to ResourcePolicy correctly
- [ ] `PolicyAdapter.adapt()` converts `FilePolicy` dict to ResourcePolicy correctly
- [ ] `PolicyAdapter.adapt()` converts `ObjectPolicy` dict to ResourcePolicy correctly
- [ ] `PolicyAdapter.adapt()` passes through `resource` type policies unchanged
- [ ] URN `urn:uri:/api/v1/example/` converts to `uri:/api/v1/example/`
- [ ] URN `urn:uri:/epson.*$` converts to `uri:/epson.*$`
- [ ] URN `urn:navigator:dashboard::*` converts to `dashboard:*`
- [ ] Negated `!resource` creates separate DENY policy
- [ ] Invalid regex patterns are caught and skipped with warning
- [ ] `adapt_batch()` processes mixed policy types and returns all warnings
- [ ] All tests pass: `pytest tests/test_policy_adapter.py -v`
- [ ] Import works: `from navigator_auth.abac.policies.adapter import PolicyAdapter`

---

## Test Specification

```python
import pytest
from navigator_auth.abac.policies.adapter import PolicyAdapter, AdapterResult


class TestPolicyAdapter:
    def test_adapt_classic_policy(self, classic_policy_dict):
        result = PolicyAdapter.adapt(classic_policy_dict)
        assert not result.skipped
        assert result.policy is not None
        assert result.policy.name == "admin_dashboard"
        assert "uri:/api/v1/admin/*" in [str(r) for r in result.policy._resource_patterns]

    def test_adapt_urn_uri(self):
        d = {"name": "test", "policy_type": "policy", "effect": "allow",
             "resources": ["urn:uri:/api/v1/example/"], "groups": ["admin"]}
        result = PolicyAdapter.adapt(d)
        # Should produce uri:/api/v1/example/ resource

    def test_adapt_urn_regex(self):
        d = {"name": "test", "policy_type": "policy", "effect": "deny",
             "resources": ["urn:uri:/epson.*$"], "groups": ["*"]}
        result = PolicyAdapter.adapt(d)
        # Should produce uri:/epson.*$ resource

    def test_adapt_negated_resource(self):
        d = {"name": "test", "policy_type": "policy", "effect": "allow",
             "resources": ["!urn:uri:/api/v1/secret/"], "groups": ["admin"]}
        result = PolicyAdapter.adapt(d)
        # Should produce DENY policy for that resource

    def test_adapt_file_policy(self, file_policy_dict):
        result = PolicyAdapter.adapt(file_policy_dict)
        assert not result.skipped
        # FilePolicy globs mapped to uri: patterns

    def test_adapt_resource_passthrough(self, resource_policy_dict):
        result = PolicyAdapter.adapt(resource_policy_dict)
        assert result.policy.name == "engineering_tools"

    def test_adapt_batch_mixed(self):
        dicts = [classic_dict, file_dict, resource_dict]
        policies, warnings = PolicyAdapter.adapt_batch(dicts)
        assert len(policies) == 3

    def test_adapt_invalid_regex_skipped(self):
        d = {"name": "bad", "policy_type": "policy", "effect": "allow",
             "resources": ["urn:uri:invalid(regex["], "groups": ["admin"]}
        result = PolicyAdapter.adapt(d)
        assert len(result.warnings) > 0
```

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify `Depends-on` tasks are in `tasks/completed/`
3. **Update status** in `tasks/.index.json` -> `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `tasks/completed/TASK-010-policy-adapter.md`
7. **Update index** -> `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

**Completed by**: session-python-task
**Date**: 2026-04-03
**Notes**: Implemented `PolicyAdapter` in `navigator_auth/abac/policies/adapter.py`. The adapter handles conversion of classic Policy, FilePolicy, and ObjectPolicy dicts into the unified `ResourcePolicy` model. It also handles URN conversion, negated resources (creating separate DENY policies), and HTTP method mapping. Unit tests implemented in `tests/test_policy_adapter.py` cover all conversion paths.

**Deviations from spec**: none
