# TASK-189: Policy-object adapter — `raw_resources` + `PolicyAdapter.from_policy`

**Feature**: FEAT-109 — PBAC example policy issues
**Spec**: `sdd/specs/policy-issues.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

`PDP.authorize` only asks the Rust-backed `PolicyEvaluator`, but `PDP.add_policy()` only appends to a
list the evaluator never reads, so every programmatic policy is silently ignored and the example
answers 428 for `/dashboard/` (spec §1 problem 1). Before the PDP can load such policies (TASK-190),
it needs a converter from a policy **object** to evaluator-ready `ResourcePolicy` objects.

This task implements spec §3 **Module 1** (Policy-object adapter):

1. `AbstractPolicy.__init__` records the original resource strings in `raw_resources` (a `Resource`
   object loses them for non-URI URNs) and stops crashing on a `str` resource
   (`list(Resource(resource))` raises `TypeError` today — reproduced at task time).
2. `PolicyAdapter.from_policy(policy)` converts `Policy`/`ObjectPolicy`/`FilePolicy` into the classic
   dict shape that `PolicyAdapter.adapt()` already understands, and passes `ResourcePolicy` through.
   It **rejects** (never silently weakens) policies whose restrictions the evaluator cannot enforce.

---

## Scope

- Add `self.raw_resources: list[str]` to `AbstractPolicy.__init__` and fix the `str` branch to
  `[Resource(resource)]`.
- Add `PolicyAdapter.ENGINE_ENV_KEYS`, `PolicyAdapter._classic_resource_error()`,
  `PolicyAdapter._normalize_environment()` and `PolicyAdapter.from_policy()` in `adapter.py`,
  inserted before `adapt_batch`.
- `from_policy` validation contract (spec §3 M1, applies to ALLOW and DENY alike):
  - non-empty `context`, `conditions` or `scopes` → `AdapterResult(skipped=True, reason=...)` naming
    the restriction(s);
  - every resource (negated `!` ones included) must convert and validate; one invalid pattern
    rejects the whole policy; an explicitly empty resource list stays valid (unrestricted);
  - environment: copy, `day_of_week` → `dow` (equal values under both keys OK, conflicting →
    reject), only the five engine keys, only supported value shapes; never mutate the source;
  - any adapter warning on the final `adapt()` result → reject (a warning means something was
    dropped).
- Write `tests/test_policy_adapter_from_policy.py` with the 8 M1 tests from spec §4.

**NOT in scope**: `PDP.add_policy` / `_registered` / reload / tenant changes (TASK-190); the
example file (TASK-193); changing `PolicyAdapter.adapt`, `_adapt_classic`, `_adapt_object`,
`adapt_batch` or the storage dict path (spec: "the existing storage dict adapter remains
unchanged"); any Rust engine change.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/policies/abstract.py` | MODIFY | `raw_resources` + `str` resource fix in `AbstractPolicy.__init__` |
| `navigator_auth/abac/policies/adapter.py` | MODIFY | imports + `from_policy` and its two validation helpers |
| `tests/test_policy_adapter_from_policy.py` | CREATE | M1 unit tests (spec §4) |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` HEAD `c5403d4` on 2026-11-11 (spec §6 anchors re-checked; all counts match).

### Verified Imports
```python
# stdlib
from collections.abc import Mapping
# adapter.py new imports — absolute, matching adapter.py:5-7 style
from navigator_auth.abac.policies.abstract import AbstractPolicy, PolicyEffect  # verified: abstract.py:42 (AbstractPolicy), :11 (PolicyEffect)
from navigator_auth.abac.policies.obj import ObjectPolicy                      # verified: obj.py:8
from navigator_auth.abac.policies.file import FilePolicy                       # verified: file.py:8 (subclasses ObjectPolicy)
from navigator_auth.abac.policies.resource_policy import ResourcePolicy        # verified: adapter.py:5 (already imported)
# tests
from navigator_auth.abac.policies import Policy, PolicyEffect, ObjectPolicy, FilePolicy  # verified: abac/policies/__init__.py:6-9
from navigator_auth.abac.policies.adapter import PolicyAdapter, AdapterResult   # verified: adapter.py:12,19
from navigator_auth.abac.policies.resource_policy import ResourcePolicy         # verified: resource_policy.py:7
```
No import cycle: `policy.py`, `obj.py`, `file.py`, `abstract.py` never import the adapter.

### Existing Signatures to Use
```python
# navigator_auth/abac/policies/abstract.py
class ActionKey:                                   # line 26: ActionKey("o:a") -> .object, .action
class AbstractPolicy(ABC):                         # line 42
    def __init__(self, name=None, description=None, actions: list = None,
                 resource: Union[list, str] = None, objects: Optional[dict] = None,
                 conditions: Optional[dict] = None, effect: PolicyEffect = PolicyEffect.ALLOW,
                 subject: Optional[list[str]] = None, groups: Optional[list] = None,
                 context: Optional[dict] = None, environment: Optional[Environment] = None,
                 priority: int = None, enforcing: bool = False, scopes: Optional[list] = None,
                 **kwargs): ...                    # lines 67-124
        # self.actions: list[ActionKey] (93); self.resources (94-99); self.context: dict (88/101);
        # self.conditions: dict (91/104); self.groups (105); self.effect (106);
        # self.environment (107); self.subject: list | None (109-114); self.priority: int (115);
        # self.objects (117); self.scopes: list (120); self.attributes = kwargs (122); self.enforcing (124)

# navigator_auth/abac/policies/adapter.py
@dataclass
class AdapterResult:                               # line 12
    policy: Optional[ResourcePolicy] = None; warnings: List[str]; additional_policies: List[ResourcePolicy]
    skipped: bool = False; reason: str = ""
class PolicyAdapter:                               # line 19
    @staticmethod
    def _convert_urn(urn_str: str) -> Tuple[str, bool]: ...          # line 49 ("!" -> negated)
    @staticmethod
    def _validate_resource(resource: str) -> Optional[str]: ...      # line 74 (warning str or None)
    @staticmethod
    def adapt(policy_dict: dict) -> AdapterResult: ...               # line 89 (never raises)
    @staticmethod
    def _adapt_classic(policy_dict: dict) -> AdapterResult: ...      # line 135 (reads 'resource' before 'resources')
    @staticmethod
    def adapt_batch(policy_dicts: List[dict]) -> Tuple[List[ResourcePolicy], List[str]]: ...  # line 276

# navigator_auth/abac/policies/resource_policy.py
class ResourcePolicy(AbstractPolicy):              # line 7; super().__init__ at 76 passes no `resource`
# Rust engine environment keys: rs_pep/src/lib.rs:241-247 (is_business_hours, is_weekend, hour,
# dow, day_segment; any other key is IGNORED -> today `day_of_week` silently never restricts).
# Value shapes: list (membership), object with min/max (range), scalar (equality) — lib.rs:250-277.
```

### Does NOT Exist
- ~~`AbstractPolicy.raw_resources`~~ — added by this task.
- ~~`AbstractPolicy.to_dict()` / `Policy.to_dict()`~~ — no serializer on policy classes.
- ~~`PolicyAdapter.from_policy`~~ — added by this task.
- ~~`ObjectPolicy.__init__` / `FilePolicy.__init__`~~ — neither overrides `AbstractPolicy.__init__`.
- ~~`Resource.raw_value` holding the URN~~ — it is `None`/rewritten for non-URI URNs; use `raw_resources`.
- ~~`ResourcePolicy.python_conditions` enforcement~~ — `_adapt_classic` attaches it, nothing reads it.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/abac/policies/abstract.py", "action": "MODIFY"},
    {"path": "navigator_auth/abac/policies/adapter.py", "action": "MODIFY"},
    {"path": "tests/test_policy_adapter_from_policy.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/abac/policies/abstract.py#AbstractPolicy",
    "sym:navigator_auth/abac/policies/abstract.py#AbstractPolicy.__init__",
    "sym:navigator_auth/abac/policies/abstract.py#ActionKey",
    "sym:navigator_auth/abac/policies/adapter.py#AdapterResult",
    "sym:navigator_auth/abac/policies/adapter.py#PolicyAdapter",
    "sym:navigator_auth/abac/policies/adapter.py#PolicyAdapter._convert_urn",
    "sym:navigator_auth/abac/policies/adapter.py#PolicyAdapter._validate_resource",
    "sym:navigator_auth/abac/policies/adapter.py#PolicyAdapter.adapt",
    "sym:navigator_auth/abac/policies/resource_policy.py#ResourcePolicy",
    "sym:navigator_auth/abac/policies/obj.py#ObjectPolicy",
    "sym:navigator_auth/abac/policies/file.py#FilePolicy",
    "sym:navigator_auth/abac/policies/policy.py#Policy"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- Adapter methods are `@staticmethod`s that **report** failures as `AdapterResult(skipped=True,
  reason=...)` and never raise (`adapter.py:101-102`). `PDP.add_policy` (TASK-190) turns a skip
  into `ValueError` — not this task.
- Check order matters: `ResourcePolicy` first (it subclasses `AbstractPolicy`), then `FilePolicy`
  before `ObjectPolicy` (`FilePolicy` subclasses `ObjectPolicy`).
- A rejected result carries **no** `policy` and **no** `additional_policies` — a partial ALLOW or a
  generated `<name>_negated` DENY must never escape.
- pytest runs with `filterwarnings = ["error"]`; `resources.py:281` logs (not warns) "is not a
  Regular Expression" when constructing a `Policy` with an invalid regex — that is fine.
- `bool` is an `int` subclass: for `hour`/`dow`, reject `True`/`False` explicitly.
- Do not "fix" `_adapt_object`'s `objects` handling or Python vs Rust subject semantics (spec §7).

### References in Codebase
- `navigator_auth/abac/policies/adapter.py:135-247` — `_adapt_classic`, the conversion `from_policy` feeds.
- `navigator_auth/abac/policies/evaluator.py:311-318` — `_build_env_dict`, the engine's env keys.

---

## Implementation Blueprint

> Write each block nearly verbatim, then complete every `# FILL IN:` marker. Never change a
> signature, class name, or file path the blueprint fixes.

### Steps (in order)
1. Replace the resource block in `AbstractPolicy.__init__` (abstract.py:94-99) — *why*: `from_policy`
   needs the verbatim strings, and a `str` resource must stop raising `TypeError`.
2. Extend the adapter imports (adapter.py:6) — *why*: `from_policy` dispatches on `AbstractPolicy`,
   `ObjectPolicy`, `FilePolicy`; imports stay absolute like adapter.py:5-7.
3. Insert the helpers block, then the `from_policy` block, directly above `adapt_batch`
   (adapter.py:275-276) — *why*: spec §6 Edit Sites fixes this location.
4. Complete the `_normalize_environment` value checks (FILL IN) — *why*: unsupported shapes must be
   rejected, not ignored by the engine.
5. Write the tests (8 from spec §4) and run the Validation Commands.

### `navigator_auth/abac/policies/abstract.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '        if type(resource) == str:  # pylint: disable=C0123  # noqa: E721' navigator_auth/abac/policies/abstract.py)
# REPLACE lines 94-99 (verified: abstract.py:94-99), i.e. from the anchor through `self.resources = None`:
        # raw_resources keeps the resource strings verbatim: Resource objects
        # drop them for non-URI URNs, and PolicyAdapter.from_policy needs them.
        if type(resource) == str:  # pylint: disable=C0123  # noqa: E721
            self.raw_resources: list[str] = [resource]
            self.resources = [Resource(resource)]
        elif isinstance(resource, list):
            self.raw_resources = [str(r) for r in resource]
            self.resources = [Resource(r) for r in resource]
        else:
            self.raw_resources = []
            self.resources = None
```
**Why**: spec §3 M1 skeleton: `str` → `[str]`, list copied with items `str()`-ed, `None` → `[]`;
`[Resource(resource)]` gives a `str` the same semantics as a one-item list. `self.resources` stays
`None` for no resource (existing `fits()` semantics depend on it).

### `navigator_auth/abac/policies/adapter.py` (MODIFY — imports)
```python
# occurrences: 1 (verified: grep -c 'from navigator_auth.abac.policies.abstract import PolicyEffect' navigator_auth/abac/policies/adapter.py)
# REPLACE line 6 (verified: adapter.py:6) and add two imports below it (before adapter.py:7):
from collections.abc import Mapping
from navigator_auth.abac.policies.abstract import AbstractPolicy, PolicyEffect
from navigator_auth.abac.policies.obj import ObjectPolicy
from navigator_auth.abac.policies.file import FilePolicy
```
**Why**: `Mapping` may instead go with the stdlib imports at adapter.py:1-4 — either is fine.

### `navigator_auth/abac/policies/adapter.py` (MODIFY — helpers)
```python
# occurrences: 1 (verified: grep -c '    def adapt_batch(policy_dicts: List[dict]) -> Tuple[List[ResourcePolicy], List[str]]:' navigator_auth/abac/policies/adapter.py)
# BEFORE — insert above the `@staticmethod` that decorates `adapt_batch` (verified: adapter.py:275-276):
    # Environment keys the Rust engine evaluates (rs_pep/src/lib.rs:241-247). The
    # engine silently ignores any other key, so from_policy rejects it instead.
    ENGINE_ENV_KEYS = frozenset({"hour", "dow", "is_business_hours", "is_weekend", "day_segment"})

    @staticmethod
    def _classic_resource_error(raw_resources: List[str]) -> Optional[str]:
        """Validate every classic resource, negated ones included.

        Args:
            raw_resources: ``AbstractPolicy.raw_resources`` (URNs, ``type:pattern``
                strings or bare paths; a leading ``!`` marks a negated resource).

        Returns:
            None when every resource converts and validates (an empty list is
            valid: unrestricted, existing semantics); otherwise the first problem.
        """
        for raw in raw_resources:
            converted, _negated = PolicyAdapter._convert_urn(raw)
            warning = PolicyAdapter._validate_resource(converted)
            if warning:
                return f"invalid resource {raw!r}: {warning}"
        return None

    @staticmethod
    def _normalize_environment(environment: Any) -> Tuple[Optional[dict], Optional[str]]:
        """Copy and validate a classic environment mapping for the Rust engine.

        ``day_of_week`` becomes ``dow``; equal values under both keys are accepted,
        conflicting values rejected. Only ``ENGINE_ENV_KEYS`` are accepted.

        Args:
            environment: ``AbstractPolicy.environment`` (None or a mapping). Never mutated.

        Returns:
            ``(normalized, None)`` on success (``normalized`` is None when there is no
            environment) or ``(None, reason)`` on rejection.
        """
        if not environment:
            return None, None
        if not isinstance(environment, Mapping):
            return None, f"unsupported environment shape: {type(environment).__name__}"
        env = dict(environment)
        if "day_of_week" in env:
            alias = env.pop("day_of_week")
            if "dow" in env and env["dow"] != alias:
                return None, "conflicting environment values for 'dow' and 'day_of_week'"
            env["dow"] = alias
        unknown = sorted(set(env) - PolicyAdapter.ENGINE_ENV_KEYS)
        if unknown:
            return None, f"unsupported environment keys: {', '.join(unknown)}"
        for key, value in env.items():
            # FILL IN: validate `value` for `key`; return (None, f"unsupported value for environment
            #   key {key!r}: ...") on the first failure — bounded by spec §3 M1 validation contract:
            #   hour, dow            -> int (NOT bool), list of such ints, or a dict whose keys are a
            #                           non-empty subset of {"min", "max"} with int/float (not bool) values;
            #   is_business_hours, is_weekend -> bool or list of bool;
            #   day_segment          -> str or list of str;
            #   reject range objects, tuples, sets, empty lists and range dicts on bool/str keys.
            pass
        return env, None
```
**Why**: spec M1 — "Accept scalar equality, lists of scalar values, and numeric range dictionaries
with only `min`/`max` and at least one bound; reject unsupported keys, shapes, and incompatible
value types. Do not mutate the source policy." `dict(environment)` is the copy.

### `navigator_auth/abac/policies/adapter.py` (MODIFY — `from_policy`)
```python
# Insert directly below the helpers block above (still above adapt_batch).
    @staticmethod
    def from_policy(policy: AbstractPolicy) -> AdapterResult:
        """Adapt a programmatic policy object for the PolicyEvaluator.

        ``ResourcePolicy`` passes through unchanged. ``FilePolicy`` -> "file",
        ``ObjectPolicy`` -> "object", any other ``AbstractPolicy`` -> "policy": they
        are converted to the classic policy dict (``resource`` = ``raw_resources``)
        and passed to :meth:`adapt` only after validation.

        Args:
            policy: The policy object to adapt. It is never mutated.

        Returns:
            AdapterResult: the policy (plus a ``<name>_negated`` DENY for ``!``
            resources) on success; ``skipped=True`` with ``reason`` and no policies
            when a context/conditions/scopes restriction, an invalid resource or an
            unsupported environment condition would be lost. Never raises.
        """
        if isinstance(policy, ResourcePolicy):
            return AdapterResult(policy=policy)
        if not isinstance(policy, AbstractPolicy):
            return AdapterResult(skipped=True, reason=f"not a policy object: {type(policy).__name__}")
        name = policy.name
        try:
            restricted = [
                label for label, value in (
                    ("context", policy.context),
                    ("conditions", policy.conditions),
                    ("scopes", policy.scopes),
                ) if value
            ]
            if restricted:
                return AdapterResult(skipped=True, reason=(
                    f"Policy '{name}': classic {', '.join(restricted)} restrictions are not "
                    "enforced by the policy evaluator; use subject/groups instead"))
            error = PolicyAdapter._classic_resource_error(policy.raw_resources)
            if error:
                return AdapterResult(skipped=True, reason=f"Policy '{name}': {error}")
            environment, error = PolicyAdapter._normalize_environment(policy.environment)
            if error:
                return AdapterResult(skipped=True, reason=f"Policy '{name}': {error}")
            if isinstance(policy, FilePolicy):
                policy_type = "file"
            elif isinstance(policy, ObjectPolicy):
                policy_type = "object"
            else:
                policy_type = "policy"
            policy_dict = {
                "policy_type": policy_type,
                "name": name,
                "description": policy.description,
                "effect": "ALLOW" if policy.effect == PolicyEffect.ALLOW else "DENY",
                "resource": list(policy.raw_resources),
                "actions": [f"{a.object}:{a.action}" for a in policy.actions],
                "subject": list(policy.subject or []),
                "groups": list(policy.groups or []),
                "context": {},
                "environment": environment,
                "priority": policy.priority,
                "enforcing": policy.enforcing,
                "objects": policy.objects,
                "org_id": policy.attributes.get("org_id", 1),
                "client_id": policy.attributes.get("client_id", 1),
            }
        except Exception as exc:  # pylint: disable=W0703
            return AdapterResult(skipped=True, reason=f"Policy '{name}': cannot convert: {exc}")
        result = PolicyAdapter.adapt(policy_dict)
        if result.skipped:
            return result
        if result.warnings:
            # A warning means adapt() dropped something: never return a weakened policy.
            return AdapterResult(skipped=True, reason=f"Policy '{name}': " + "; ".join(result.warnings))
        return result
```
**Why**: spec §2 Data Models fixes the dict shape (`effect` "ALLOW"/"DENY", `actions` as
`"object:action"`, `org_id`/`client_id` from `attributes`, default 1). A skip result is always
built fresh, so it carries no policy and no `additional_policies` (AC: no partial allow / no
generated deny escapes).

### `tests/test_policy_adapter_from_policy.py` (CREATE)
See **Test Specification** below — start from that scaffold and fill every test body.

### FILL IN checklist
- [ ] `adapter.py::PolicyAdapter._normalize_environment` value checks — bounded by spec §3 M1 contract (above)
- [ ] `tests/test_policy_adapter_from_policy.py` — all 8 test bodies; bounded by spec §4 M1 rows

---

## Acceptance Criteria

- [ ] `Policy(name="p", resource="urn:uri:/a")` constructs without `TypeError`; `p.raw_resources == ["urn:uri:/a"]` and `len(p.resources) == 1`.
- [ ] `from_policy(<ResourcePolicy>)` returns that same object (`result.policy is rp`).
- [ ] Classic URI regex, object URN (`urn:navigator:deployment::*` → `deployment:*`) and negated resource (`<name>_negated` DENY) convert as specified.
- [ ] Non-empty `context`, `conditions` or `scopes` (ALLOW and DENY, `Policy`/`ObjectPolicy`/`FilePolicy`) → `skipped=True` with a reason naming it, `policy is None`, `additional_policies == []`.
- [ ] Any invalid resource — positive, negated, or in a mixed valid/invalid list — → `skipped=True`, no policies.
- [ ] `day_of_week` → `dow`; equal aliases accepted; conflicting aliases and unsupported keys/shapes/types rejected; the source `policy.environment` is unchanged afterwards.
- [ ] `PolicyAdapter.adapt`, `_adapt_classic`, `_adapt_object`, `adapt_batch` unchanged (`git diff` shows only additions there).
- [ ] All Validation Commands pass.

---

## Validation Commands
- `pytest tests/test_policy_adapter_from_policy.py -q`
- `pytest tests/test_yaml_storage_double_load.py -q`

---

## Test Specification

```python
# tests/test_policy_adapter_from_policy.py
"""Tests for PolicyAdapter.from_policy and AbstractPolicy.raw_resources (FEAT-109 M1)."""
import copy

import pytest

from navigator_auth.abac.policies import Policy, PolicyEffect, ObjectPolicy, FilePolicy
from navigator_auth.abac.policies.adapter import PolicyAdapter
from navigator_auth.abac.policies.resource_policy import ResourcePolicy


def _resources(policy: ResourcePolicy) -> list[str]:
    """Return 'type:pattern' strings of an adapted policy."""
    return [f"{p.resource_type.value if hasattr(p.resource_type, 'value') else p.resource_type}:{p.pattern}"
            for p in policy._resource_patterns]


def test_raw_resources_captured():
    """str -> one Resource and [str]; list copied; None -> []."""
    p = Policy(name="s", resource="urn:uri:/a")
    assert p.raw_resources == ["urn:uri:/a"] and len(p.resources) == 1
    # FILL IN: list input is copied (mutating the caller's list does not change raw_resources); None -> []


def test_from_policy_resource_policy_passthrough():
    rp = ResourcePolicy(name="rp", resources=["tool:*"], actions=["tool:execute"])
    assert PolicyAdapter.from_policy(rp).policy is rp


def test_from_policy_classic_uri_regex():
    result = PolicyAdapter.from_policy(
        Policy(name="admin", resource=["urn:uri:/admin.*$"], groups=["admin"]))
    assert not result.skipped
    assert _resources(result.policy) == ["uri:/admin.*$"]
    # FILL IN: groups kept on result.policy._subjects.groups


def test_from_policy_object_policy_urn():
    # FILL IN: ObjectPolicy(resource=["urn:navigator:deployment::*"], actions=["deployment:approve"])
    #   -> resource "deployment:*", action "deployment:approve" kept
    ...


def test_from_policy_negated_resource():
    # FILL IN: Policy(resource=["urn:uri:/api/.*", "!urn:uri:/api/admin.*"]) -> additional
    #   policy named "<name>_negated" with effect DENY
    ...


@pytest.mark.parametrize("resources", [
    ["urn:uri:/admin["], ["!urn:uri:/admin["], ["urn:uri:/ok", "urn:uri:/bad["],
])
def test_from_policy_invalid_regex_skipped(resources):
    result = PolicyAdapter.from_policy(Policy(name="bad", resource=resources))
    assert result.skipped and result.reason
    assert result.policy is None and result.additional_policies == []


# FILL IN: test_from_policy_unsupported_restrictions_rejected — parametrize over
#   (Policy, ObjectPolicy, FilePolicy) x (ALLOW, DENY) x {context, conditions, scopes}; reason names it
# FILL IN: test_from_policy_environment_normalization — day_of_week -> dow; equal aliases OK;
#   conflicting aliases, unknown key, range(), {"min": ...,"foo": 1}, bool for hour, str for is_weekend
#   rejected; copy.deepcopy(policy.environment) == policy.environment after the call
```

---

## Agent Instructions

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug policy-issues --feature-id FEAT-109`).
2. **Read the spec** (`sdd/specs/policy-issues.spec.md` §2, §3 Module 1, §4, §6).
3. **Check dependencies** — none.
4. **Verify the Codebase Contract** before writing code; update it first if anything moved.
5. **Update status** in `sdd/tasks/index/policy-issues.json` → `"in-progress"` (set `started_at`).
6. **Implement** from the Implementation Blueprint; complete every `# FILL IN:`.
7. **Verify** — run the Validation Commands.
8. **Commit the code** — stage only the files listed above.
9. **Close the task** with `parrot sdd task close TASK-189 policy-issues verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any

## Completion Note

Merged via parrot-sdd-coder seat. Merge-tier sweep: 4 order-dependent failures in tests/test_yaml_storage_double_load.py (asyncio.get_event_loop; passes 12/12 in isolation) — not caused by this task.
