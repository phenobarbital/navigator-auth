---
# SDD flow type and base branch (FEAT-145).
type: feature
base_branch: dev
projects: [abac]
tags: [pbac, policy-adapter, fail-closed, ledger-fix]
docs:
  policy: none
  pages: []
  api_modules: [navigator_auth.abac.policies.adapter]
---

# Feature Specification: Policy adapter fixes — ObjectPolicy objects= and ResourcePolicy environment

**Feature ID**: FEAT-111
**Date**: 2026-11-11
**Author**: Jesus Lara (spec scaffolded by Claude Code via /sdd-fix)
**Status**: approved
**Target version**: unreleased
**Parent**: FEAT-109 — PBAC example policy issues (`sdd/specs/policy-issues.spec.md`)
**Prerequisite**: met — PR #634 (FEAT-109) merged into `dev` at `142a9e1`; `from_policy` and its tests are on `dev`.
**Ledger group**: `fixgroup:7dca9c41b57f` — `issue:43c1d14ac3ac` (bug, major), `issue:6a034393d065` (tech_debt, minor)

---

## 1. Motivation & Business Requirements

### Problem Statement

FEAT-109 added `PolicyAdapter.from_policy()` so `PDP.add_policy()` can enforce programmatic policies.
Its rule is fail-closed: a restriction the evaluator cannot enforce must reject the policy, never be
dropped. Two ledger issues, filed while FEAT-109 was reviewed, show places where that rule does not hold.

1. **`issue:43c1d14ac3ac` — `objects=` on an `ObjectPolicy` is not validated.** `from_policy` validates
   only `policy.raw_resources`. The object names go through `_adapt_object`, which rebuilds resources
   from `objects=` without any check. Verified on `dev` @ `98f560d` (adapter.py identical to FEAT-109 head `3999ef9`):

   | Input | Today | Effect |
   |---|---|---|
   | `ObjectPolicy(objects=["bad["])` | skipped, reason is a bare regex error | fail-closed, but the reason does not say which object |
   | `ObjectPolicy(effect=DENY, resource=["urn:uri:/a"], objects=["secret"])` | registered with `uri:/a` only | **`objects=` silently dropped — the DENY no longer covers `secret`** |
   | `ObjectPolicy(objects=["x"], type="deployment")` | `object:x` | **`type=` ignored — a DENY targets the wrong resource type** |
   | `ObjectPolicy(objects=["!x"])` | literal `object:!x` | **negation silently lost** |
   | `ObjectPolicy(objects={"deployment": ["a", "b"]})` | `object:deployment` | **dict values silently dropped** |
   | `ObjectPolicy(objects=[5])` | skipped, `argument of type 'int' is not iterable` | fail-closed, opaque reason |
   | `Policy(objects=[...])` / `FilePolicy(objects=[...])` | `objects=` silently ignored | **silent loss** |

2. **`issue:6a034393d065` — `ResourcePolicy` pass-through skips environment validation.**
   `from_policy` returns any `ResourcePolicy` unchanged (`adapter.py:396-397`). The Rust engine ignores
   environment keys it does not know (`rs_pep/src/lib.rs:247`, `_ => continue`), so
   `ResourcePolicy(environment={"weekday": 1})`, `{"day_of_week": 1}` or `{"hour": "nine"}` registers
   with no time restriction at all. Classic policies already reject these
   (`PolicyAdapter._normalize_environment`); native ones do not.

### Goals
- `from_policy` validates `objects=` up front and rejects every input whose objects would be dropped,
  retyped, de-negated or flattened. The reason names the offending object.
- `from_policy` validates a `ResourcePolicy`'s native environment against what the evaluator honours,
  and rejects unknown keys and unsupported value shapes. A valid `ResourcePolicy` is still returned as
  the same, unmodified object.
- One source of truth for the object→resource conversion and for per-key environment value rules.

### Non-Goals (explicitly out of scope)
- The storage load path (`PolicyAdapter.adapt` / `_adapt_resource` / `adapt_batch`). Tightening it would
  start skipping already-stored policies at load. That needs its own decision.
- Native `ResourcePolicy.conditions` keys other than `is_manager` (also ignored by the engine): a separate gap.
- Supporting `!`-negated objects or dict-shaped `objects=`. They are rejected here, not implemented.
- Any change to `ObjectPolicy` / `AbstractPolicy` constructors or the Rust engine.

---

## Governing Decisions

decision audit not configured in this repository

---

## 2. Architectural Design

### Overview

Both fixes live in `PolicyAdapter.from_policy` (programmatic registration only).

- **Objects (Module 1).** A new `_resolve_objects(policy)` turns `objects=` into classic `type:pattern`
  resource strings, or returns a rejection reason. It applies the same conversion `_adapt_object` uses
  (shared via a new `_object_resources` helper, so the two paths cannot drift), honours
  `policy.attributes["type"]` (the `type=` kwarg, default `"object"`), and validates every resulting
  pattern with `_classic_resource_error`. `from_policy` then passes the resolved strings as the classic
  `resource` list and `objects: None`, so the adapter builds exactly what was validated.
- **Native environment (Module 2).** A new `_resource_policy_error(policy)` checks
  `policy._env_conditions` against `NATIVE_ENV_KEYS` (`ENGINE_ENV_KEYS` plus `is_manager`, which
  `PolicyEvaluator._serialize_policies_from_index` lifts into `conditions.is_manager`). It reuses the
  per-key value rules, extracted from `_normalize_environment` into `_environment_value_error`. Native
  policies get no alias normalisation: `day_of_week` is rejected with a hint to use `dow`, because the
  pass-through must not reinterpret native conditions (FEAT-109 spec, Module 1).

### Component Diagram
```
PDP.add_policy(policy)
   └─→ PolicyAdapter.from_policy(policy)
          ├─ ResourcePolicy ─→ _resource_policy_error ──(ok)──→ AdapterResult(policy=policy)   [M2]
          │                          └─ _environment_value_error (shared with _normalize_environment)
          └─ classic ─→ restrictions check ─→ _resolve_objects ─→ _classic_resource_error      [M1]
                                                   └─ _object_resources (shared with _adapt_object)
                         ─→ _normalize_environment ─→ adapt(policy_dict)
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `PolicyAdapter.from_policy` | modifies | adds the two guards; `resource`/`objects` dict keys change for ObjectPolicy |
| `PolicyAdapter._adapt_object` | refactor | calls `_object_resources`; output unchanged |
| `PolicyAdapter._normalize_environment` | refactor | per-key checks move to `_environment_value_error`; behaviour unchanged |
| `PDP.add_policy` | unchanged | already raises `ValueError` on `skipped` results |

### Data Models
No new models. `AdapterResult` is unchanged.

### New Public Interfaces
None. All new members are private static helpers on `PolicyAdapter`:
```python
NATIVE_ENV_KEYS: frozenset  # ENGINE_ENV_KEYS | {"is_manager"}
def _object_resources(objects: List[str], obj_type: str) -> List[str]: ...
def _resolve_objects(policy: AbstractPolicy) -> Tuple[Optional[List[str]], Optional[str]]: ...
def _environment_value_error(key: str, value: Any) -> Optional[str]: ...
def _resource_policy_error(policy: ResourcePolicy) -> Optional[str]: ...
```

---

## 3. Module Breakdown

| Module | Eligible? | Decided patterns / exact contracts | Why not (if no) |
|---|---|---|---|
| M1: objects= guard | no | rules fixed below | small, judgement in reason wording and edge cases |
| M2: native environment check | no | rules fixed below | same file as M1; refactor of an existing loop |

### Module 1: `objects=` guard (`issue:43c1d14ac3ac`)
- **Path**: `navigator_auth/abac/policies/adapter.py`, `tests/test_policy_adapter_from_policy.py`, `CHANGELOG.md`
- **Responsibility**: Reject or faithfully convert `objects=` in `from_policy`.
- **Rules** (in this order; the first failure wins):
  1. `policy.objects` falsy → no objects (unchanged behaviour).
  2. `policy` is not an `ObjectPolicy`, or is a `FilePolicy` → reject: `objects= is only supported on ObjectPolicy`.
  3. `policy.raw_resources` non-empty → reject: `resource= and objects= cannot be combined`.
  4. A `str` becomes a one-item list. Anything other than a list/tuple of non-empty `str` → reject (`unsupported objects shape`). Dicts are rejected because their values would be lost.
  5. An object starting with `!` → reject: negated objects are unsupported, use `resource=["!…"]`.
  6. `type` = `policy.attributes.get("type", "object")` must be a non-empty `str` without `:` → else reject.
  7. Convert with `_object_resources` (bare name → `f"{type}:{name}"`, anything containing `:` or starting with `urn:` verbatim) and validate with `_classic_resource_error`; on error reject with `invalid object …`.
- **Interface Skeleton**:
  ```python
  # navigator_auth/abac/policies/adapter.py (modifies)
  @staticmethod
  def _object_resources(objects: List[str], obj_type: str) -> List[str]:
      """Convert object names to classic resource strings, exactly as _adapt_object does."""
  @staticmethod
  def _resolve_objects(policy: AbstractPolicy) -> Tuple[Optional[List[str]], Optional[str]]:
      """Return (resources, None), (None, None) when there are no objects, or (None, reason)."""
  ```

### Module 2: native `ResourcePolicy` environment check (`issue:6a034393d065`)
- **Path**: `navigator_auth/abac/policies/adapter.py`, `tests/test_policy_adapter_from_policy.py`, `CHANGELOG.md`
- **Depends on**: Module 1 (same files)
- **Rules**: an empty environment passes. A non-`Mapping` is rejected. Keys outside `NATIVE_ENV_KEYS` are rejected; `day_of_week` gets a "use 'dow'" hint. Values follow the existing rules for engine keys, and `is_manager` must be a `bool`. On success, return the same object (`result.policy is policy`), unmodified.
- **Interface Skeleton**:
  ```python
  NATIVE_ENV_KEYS = ENGINE_ENV_KEYS | frozenset({"is_manager"})
  @staticmethod
  def _environment_value_error(key: str, value: Any) -> Optional[str]:
      """Return why value is unsupported for key, or None. Shared by classic and native checks."""
  @staticmethod
  def _resource_policy_error(policy: ResourcePolicy) -> Optional[str]:
      """Validate a native ResourcePolicy's environment without reinterpreting it."""
  ```

---

## 4. Test Specification

### Unit Tests
| Test | Module | Description |
|---|---|---|
| `test_from_policy_objects_converted` | M1 | `objects=["report_*"]` → `object:report_*`; `type="deployment"` → `deployment:x`; URN object → `deployment:prod`; string `objects="x"` accepted |
| `test_from_policy_objects_rejected` | M1 | parametrized over both effects: invalid regex, resource+objects, `!x`, dict, non-str item, empty string, bad `type`, objects on `Policy`/`FilePolicy` → skipped, reason present, no policies |
| `test_from_policy_resource_policy_environment` | M2 | valid native env (incl. `is_manager: True`, `is_business_hours`) passes and stays identical; `weekday`, `day_of_week`, `{"hour": "nine"}`, `{"is_manager": "yes"}`, non-Mapping → skipped |
| existing `test_from_policy_environment_normalization` | M2 | must keep passing unchanged (refactor guard) |

### Validation Contract

tests:
- tests/test_policy_adapter_from_policy.py
- tests/test_pdp_add_policy.py
- tests/test_policy_server_example.py
- tests/test_yaml_storage_double_load.py
- tests/test_tenant_scoping.py
- tests/test_unified_evaluation.py
markers: none

### Test Data / Fixtures
Reuse `_resources()` in `tests/test_policy_adapter_from_policy.py:12`. No new fixtures.

---

## 5. Acceptance Criteria

- [ ] Every row of the §1 table marked **silent** is now `skipped=True` with a reason naming the object/key, and no policy or additional policy.
- [ ] Valid `objects=` produce the `type:pattern` resources §3 Module 1 rule 7 describes; `type=` is honoured.
- [ ] A `ResourcePolicy` with an unknown or ill-shaped environment key is rejected; a valid one is returned as the same object.
- [ ] `_adapt_object`, `_normalize_environment`, `adapt`, `adapt_batch` behaviour is unchanged (existing tests pass).
- [ ] All Validation Contract tests pass; `ruff check` (if configured) clean on changed files.
- [ ] CHANGELOG "Unreleased" mentions both rejections under FEAT-109's `add_policy` entry or a new bullet.

---

## 6. Codebase Contract

Verified against `dev` @ `98f560d` (adapter.py identical to FEAT-109 head `3999ef9`).

### Verified Imports
```python
from navigator_auth.abac.policies import FilePolicy, ObjectPolicy, Policy, PolicyEffect  # tests/test_policy_adapter_from_policy.py:7
from navigator_auth.abac.policies.adapter import PolicyAdapter                          # tests/test_policy_adapter_from_policy.py:8
from navigator_auth.abac.policies.resource_policy import ResourcePolicy                 # adapter.py:6
from collections.abc import Mapping                                                     # adapter.py:3
from typing import Optional, List, Tuple, Any                                           # adapter.py:5
```

### Existing Class Signatures
```python
# navigator_auth/abac/policies/adapter.py
class PolicyAdapter:
    def _convert_urn(urn_str: str) -> Tuple[str, bool]: ...                 # line 66
    def _validate_resource(resource: str) -> Optional[str]: ...              # line 91
    def adapt(policy_dict: dict) -> AdapterResult: ...                       # line 106
    def _adapt_classic(policy_dict: dict) -> AdapterResult: ...              # line 160; resource list = policy_dict "resource" or "resources" (173)
    def _adapt_object(policy_dict: dict) -> AdapterResult: ...               # line 280; conversion loop 288-295
    ENGINE_ENV_KEYS = frozenset({"hour", "dow", "is_business_hours", "is_weekend", "day_segment"})  # line 300
    def _classic_resource_error(raw_resources: List[str]) -> Optional[str]: ...  # line 303
    def _normalize_environment(environment: Any) -> Tuple[Optional[dict], Optional[str]]: ...  # line 322; per-key loop 348-375
    def from_policy(policy: AbstractPolicy) -> AdapterResult: ...            # line 379; RP pass-through 396-397; dict 431-447 ("objects": policy.objects at 444)

# navigator_auth/abac/policies/abstract.py
class AbstractPolicy:
    raw_resources: list[str]   # lines 97-104
    objects                    # line 123 (constructor arg `objects: Optional[dict]`, line 74; stored verbatim)
    attributes: dict           # line 125 — unknown kwargs, e.g. type="deployment"

# navigator_auth/abac/policies/resource_policy.py
class ResourcePolicy(AbstractPolicy):   # line 7
    _env_conditions: dict               # line 73 (environment or {}); NOT passed to super, so .environment is None

# navigator_auth/abac/policies/evaluator.py:270-271 — serializes _env_conditions and lifts is_manager
```

### Integration Points
| New Component | Connects To | Via | Verified At |
|---|---|---|---|
| `_resolve_objects` | `from_policy` | call after restrictions check | `adapter.py:419` |
| `_resource_policy_error` | `from_policy` | replaces bare pass-through | `adapter.py:396` |
| `_object_resources` | `_adapt_object` | replaces loop | `adapter.py:288-295` |
| `_environment_value_error` | `_normalize_environment` | replaces loop body | `adapter.py:348-375` |

### Does NOT Exist (Anti-Hallucination)
- ~~`ObjectPolicy.type`~~ / ~~`AbstractPolicy.type`~~ — `type=` lands in `policy.attributes["type"]`
- ~~`ResourcePolicy.environment`~~ holding the native env — it is `None`; use `policy._env_conditions`
- ~~`PolicyAdapter.validate`~~, ~~`PolicyAdapter._validate_objects`~~ — do not exist
- ~~`ObjectPolicy.objects` used during classic evaluation~~ — nothing reads `self.objects` (only the adapter)

### Edit Sites (Blueprint Anchors)

Verified against: `98f560d` (dev, after PR #634)

| File | Action | Verbatim anchor line | Verified at | Occurrences |
|---|---|---|---|---|
| `navigator_auth/abac/policies/adapter.py` | MODIFY | `    def _adapt_object(policy_dict: dict) -> AdapterResult:` | `adapter.py:280` | 1 |
| `navigator_auth/abac/policies/adapter.py` | MODIFY | `    ENGINE_ENV_KEYS = frozenset` | `adapter.py:300` | 1 |
| `navigator_auth/abac/policies/adapter.py` | MODIFY | `        for key, value in env.items():` | `adapter.py:348` | 1 |
| `navigator_auth/abac/policies/adapter.py` | MODIFY | `        if isinstance(policy, ResourcePolicy):` | `adapter.py:396` | 1 |
| `navigator_auth/abac/policies/adapter.py` | MODIFY | `        error = PolicyAdapter._classic_resource_error(policy.raw_resources)` | `adapter.py:419` | 1 |
| `navigator_auth/abac/policies/adapter.py` | MODIFY | `                "objects": policy.objects,` | `adapter.py:444` | 1 |
| `tests/test_policy_adapter_from_policy.py` | MODIFY | `def test_from_policy_environment_normalization():` | `test_policy_adapter_from_policy.py:95` | 1 |
| `CHANGELOG.md` | MODIFY | `# Unreleased` | `CHANGELOG.md:1` | 1 |

---

## 7. Implementation Notes & Constraints

### Patterns to Follow
- Mirror `_normalize_environment`'s `(value, error)` tuple return for `_resolve_objects`.
- Every rejection is `AdapterResult(skipped=True, reason=f"Policy '{name}': …")`; `from_policy` never raises.
- Do not mutate the source policy (`objects`, `_env_conditions`, `attributes`).

### Known Risks / Gotchas
- `FilePolicy` subclasses `ObjectPolicy` — check `FilePolicy` first (as `from_policy` already does).
- `isinstance(True, int)` is true — keep the existing `bool` exclusions when extracting value rules.
- Example `examples/policy_server.py:67` uses `ResourcePolicy(environment={"is_business_hours": True})`; it must keep adapting (`tests/test_policy_server_example.py`).

### External Dependencies
None.

---

## 8. Open Questions

None. Decisions were settled while triaging the ledger group (rejection over support for negated/dict objects; storage path out of scope).

---

## 9. Design Research Cross-Check

Status: skipped (ledger fix of two scoped issues; no exploration doc).

---

## 10. Documentation

- **Policy**: `none` — the fix only adds a CHANGELOG line and docstrings.
- **API modules**: `navigator_auth.abac.policies.adapter`

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-11-11 | Claude Code (/sdd-fix) | Initial spec from ledger group fixgroup:7dca9c41b57f |
