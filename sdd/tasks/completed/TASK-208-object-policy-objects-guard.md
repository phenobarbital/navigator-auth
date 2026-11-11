# TASK-208: Validate ObjectPolicy objects= in PolicyAdapter.from_policy

**Feature**: FEAT-111 — Policy adapter fixes — ObjectPolicy objects= and ResourcePolicy environment
**Spec**: `sdd/specs/policies-adapter-fixes.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned
**Discovered-from**: `issue:43c1d14ac3ac`

---

## Context

Ledger issue `issue:43c1d14ac3ac` (bug, major, found while FEAT-109 was reviewed):
"from_policy validates only policy.raw_resources; _adapt_object rebuilds resources from objects= which
are never checked." Spec §1 lists the verified failures. The ones that matter are **silent**: a DENY
`ObjectPolicy` with both `resource=` and `objects=` loses its objects, `type=` is ignored, a `!x` object
loses its negation, and dict values are dropped. Each of these makes a DENY cover less than written,
which fails open. This task implements spec §3 Module 1.

Base branch: `dev` (FEAT-109 / PR #634 merged at `142a9e1`, so `from_policy` is present). If `grep -c "def from_policy" navigator_auth/abac/policies/adapter.py` prints 0 in your worktree, STOP: it was branched from an old base.

---

## Scope

- Add `PolicyAdapter._object_resources(objects, obj_type)` and make `_adapt_object` use it (no
  behaviour change on the storage path).
- Add `PolicyAdapter._resolve_objects(policy)` implementing spec §3 Module 1 rules 1–7.
- Call it from `from_policy`; pass the resolved strings as the classic `resource` list and set
  `objects` to `None` in the policy dict, so the adapter builds exactly what was validated.
- Mention the new rejections in `from_policy`'s docstring and in `CHANGELOG.md` "Unreleased".
- Add tests for conversion and rejection.

**NOT in scope**: `ResourcePolicy` environment validation (TASK-209); the storage path (`adapt`,
`adapt_batch`, `_adapt_resource`); supporting negated or dict-shaped objects (they are rejected).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/policies/adapter.py` | MODIFY | `_object_resources`, `_resolve_objects`, `from_policy` wiring |
| `tests/test_policy_adapter_from_policy.py` | MODIFY | conversion + rejection tests |
| `CHANGELOG.md` | MODIFY | one bullet under "# Unreleased" |

---

## Codebase Contract (Anti-Hallucination)

Verified against `dev` @ `98f560d` (adapter.py identical to FEAT-109 head `3999ef9`).

### Verified Imports
```python
# adapter.py already imports everything needed (lines 1-10):
from typing import Optional, List, Tuple, Any                                  # adapter.py:5
from navigator_auth.abac.policies.abstract import AbstractPolicy, PolicyEffect  # adapter.py:7
from navigator_auth.abac.policies.obj import ObjectPolicy                       # adapter.py:8
from navigator_auth.abac.policies.file import FilePolicy                        # adapter.py:9
# tests (already imported at tests/test_policy_adapter_from_policy.py:7-9):
from navigator_auth.abac.policies import FilePolicy, ObjectPolicy, Policy, PolicyEffect
from navigator_auth.abac.policies.adapter import PolicyAdapter
```

### Existing Signatures to Use
```python
# navigator_auth/abac/policies/adapter.py
class PolicyAdapter:
    def _convert_urn(urn_str: str) -> Tuple[str, bool]: ...                    # line 66
    def _adapt_classic(policy_dict: dict) -> AdapterResult: ...                 # line 160; uses policy_dict "resource" before "resources" (line 173)
    def _adapt_object(policy_dict: dict) -> AdapterResult: ...                  # line 280; obj_type = policy_dict.get("type", "object") (283); loop 288-295
    def _classic_resource_error(raw_resources: List[str]) -> Optional[str]: ... # line 303 — converts via _convert_urn, then _validate_resource
    def from_policy(policy: AbstractPolicy) -> AdapterResult: ...               # line 379; FilePolicy checked before ObjectPolicy (425-430)

# navigator_auth/abac/policies/abstract.py
#   AbstractPolicy.raw_resources: list[str]  (lines 97-104)
#   AbstractPolicy.objects  (line 123, stored verbatim, any type)
#   AbstractPolicy.attributes: dict  (line 125) — the `type=` kwarg lands here
# FilePolicy(ObjectPolicy) — file.py:8; no __init__ override (neither Policy nor ObjectPolicy has one)
```

### Does NOT Exist
- ~~`policy.type`~~ — read `policy.attributes.get("type", "object")`
- ~~`PolicyAdapter._validate_objects`~~, ~~`PolicyAdapter.validate`~~ — not real
- Nothing in classic evaluation reads `AbstractPolicy.objects`; only the adapter does

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/abac/policies/adapter.py", "action": "MODIFY"},
    {"path": "tests/test_policy_adapter_from_policy.py", "action": "MODIFY"},
    {"path": "CHANGELOG.md", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/abac/policies/adapter.py#PolicyAdapter.from_policy",
    "sym:navigator_auth/abac/policies/adapter.py#PolicyAdapter._adapt_object",
    "sym:navigator_auth/abac/policies/adapter.py#PolicyAdapter._classic_resource_error"
  ]
}
```

---

## Implementation Blueprint

### Steps (in order)
1. Replace the conversion loop in `_adapt_object` with a call to the new `_object_resources`. *Why*: the guard and the storage path must convert identically, so there is one rule.
2. Add `_resolve_objects` just above `_normalize_environment`. *Why*: it follows the `(value, error)` style of the helpers already in that block.
3. Call `_resolve_objects` in `from_policy` just before the raw-resource check, and change the dict's `resource`/`objects` keys. *Why*: if the resolved list is passed as `resource`, `_adapt_classic` uses exactly the validated strings, and `_adapt_object` has nothing left to rebuild.
4. Write the tests, then run the Validation Commands.
5. Add the CHANGELOG bullet and the docstring sentence.

### `navigator_auth/abac/policies/adapter.py` (MODIFY) — `_adapt_object`
```python
# occurrences: 1 (verified: grep -c '    def _adapt_object(policy_dict: dict) -> AdapterResult:' navigator_auth/abac/policies/adapter.py)
# REPLACE lines 288-295 (from "        # Convert objects to type:pattern" through
# '        policy_dict["resources"] = new_resources') with:
        policy_dict["resources"] = PolicyAdapter._object_resources(objects, obj_type)
        return PolicyAdapter._adapt_classic(policy_dict)

    @staticmethod
    def _object_resources(objects: List[str], obj_type: str) -> List[str]:
        """Convert ObjectPolicy object names to classic resource strings.

        Shared by ``_adapt_object`` (storage) and ``from_policy`` (programmatic)
        so both paths build the same resources.

        Args:
            objects: Object names, ``type:pattern`` strings or URNs.
            obj_type: Resource type prefixed to bare names.

        Returns:
            ``f"{obj_type}:{name}"`` for a bare name; any value containing ``:``
            (``type:pattern`` or ``urn:...``) unchanged.
        """
        return [obj if (":" in obj or obj.startswith("urn:")) else f"{obj_type}:{obj}" for obj in objects]
```
**Why**: the expression is the exact negation of the old `if ":" not in obj and not obj.startswith("urn:")`
test, so storage output is unchanged. Keep the existing `return PolicyAdapter._adapt_classic(policy_dict)`;
it must not appear twice.

### `navigator_auth/abac/policies/adapter.py` (MODIFY) — `_resolve_objects`
```python
# occurrences: 1 (verified: grep -c '    def _normalize_environment(environment: Any)' navigator_auth/abac/policies/adapter.py)
# BEFORE — insert above the `    @staticmethod` line directly preceding
# `    def _normalize_environment(environment: Any) -> Tuple[Optional[dict], Optional[str]]:` (adapter.py:321-322)
    @staticmethod
    def _resolve_objects(policy: AbstractPolicy) -> Tuple[Optional[List[str]], Optional[str]]:
        """Resolve a programmatic policy's ``objects=`` into classic resources.

        Args:
            policy: The policy given to :meth:`from_policy`. Never mutated.

        Returns:
            ``(None, None)`` when the policy has no objects; ``(resources, None)``
            with validated ``type:pattern`` strings; ``(None, reason)`` when the
            objects would be dropped, retyped, de-negated or are invalid.
        """
        objects = policy.objects
        if not objects:
            return None, None
        if isinstance(policy, FilePolicy) or not isinstance(policy, ObjectPolicy):
            return None, "objects= is only supported on ObjectPolicy"
        if policy.raw_resources:
            return None, "resource= and objects= cannot be combined (objects= would be ignored)"
        if isinstance(objects, str):
            objects = [objects]
        # FILL IN: reject unless objects is a list/tuple whose items are all non-empty str
        #   (dict -> values would be lost; set -> unordered) — bounded by spec §3 M1 rule 4
        # FILL IN: reject any object starting with "!" ("negated objects are not supported;
        #   use resource=['!...']") — bounded by spec §3 M1 rule 5
        obj_type = policy.attributes.get("type", "object")
        # FILL IN: reject obj_type unless it is a non-empty str without ":" — bounded by rule 6
        resources = PolicyAdapter._object_resources(list(objects), obj_type)
        for obj, resource in zip(objects, resources):
            error = PolicyAdapter._classic_resource_error([resource])
            if error:
                return None, f"invalid object {obj!r}: {error}"
        return resources, None
```
**Why**: rule order follows spec §3 Module 1, and the first failure wins. Validating each object
separately lets the reason name the bad object, as the issue asks.

### `navigator_auth/abac/policies/adapter.py` (MODIFY) — `from_policy` wiring
```python
# occurrences: 1 (verified: grep -c 'error = PolicyAdapter._classic_resource_error(policy.raw_resources)' navigator_auth/abac/policies/adapter.py)
# BEFORE — insert directly above
# `            error = PolicyAdapter._classic_resource_error(policy.raw_resources)` (adapter.py:419, 12-space indent):
            object_resources, error = PolicyAdapter._resolve_objects(policy)
            if error:
                return AdapterResult(skipped=True, reason=f"Policy '{name}': {error}")
```
```python
# occurrences: 1 (verified: grep -c '"resource": list(policy.raw_resources),' navigator_auth/abac/policies/adapter.py)
# REPLACE in the policy_dict literal (adapter.py:436 and :444):
#   "resource": list(policy.raw_resources),   ->
                "resource": object_resources if object_resources is not None else list(policy.raw_resources),
#   "objects": policy.objects,                ->
                "objects": None,
```
**Why**: rule 3 guarantees `raw_resources` is empty whenever `object_resources` is set, so nothing is
merged or lost. `objects: None` makes `_adapt_object` build an empty `resources` list, and
`_adapt_classic` then uses the validated `resource` list (adapter.py:173).

### `tests/test_policy_adapter_from_policy.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'def test_from_policy_environment_normalization' tests/test_policy_adapter_from_policy.py)
# APPEND at end of file (after test_from_policy_environment_normalization, line 95-119):


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"objects": ["report_*"]}, ["object:report_*"]),
        ({"objects": "report_*"}, ["object:report_*"]),
        ({"objects": ("a", "b")}, ["object:a", "object:b"]),
        ({"objects": ["x"], "type": "deployment"}, ["deployment:x"]),
        ({"objects": ["urn:navigator:deployment::prod"]}, ["deployment:prod"]),
    ],
)
def test_from_policy_objects_converted(kwargs, expected):
    """Valid objects= become type:pattern resources; type= is honoured."""
    # FILL IN: build ObjectPolicy(name="objs", **kwargs); assert not skipped and _resources(...) == expected


@pytest.mark.parametrize("effect", [PolicyEffect.ALLOW, PolicyEffect.DENY])
@pytest.mark.parametrize(
    ("policy_class", "kwargs"),
    [
        (ObjectPolicy, {"objects": ["bad["]}),
        (ObjectPolicy, {"resource": ["urn:uri:/a"], "objects": ["secret"]}),
        (ObjectPolicy, {"objects": ["!x"]}),
        (ObjectPolicy, {"objects": {"deployment": ["a", "b"]}}),
        (ObjectPolicy, {"objects": [5]}),
        (ObjectPolicy, {"objects": [""]}),
        (ObjectPolicy, {"objects": ["x"], "type": ""}),
        (ObjectPolicy, {"objects": ["x"], "type": "a:b"}),
        (Policy, {"objects": ["x"]}),
        (FilePolicy, {"objects": ["x"]}),
    ],
)
def test_from_policy_objects_rejected(policy_class, kwargs, effect):
    """objects= that would be dropped, retyped, de-negated or invalid rejects the policy."""
    # FILL IN: assert skipped, "object" in reason.lower(), policy is None, additional_policies == [],
    #   and the source policy's .objects is unchanged (deepcopy before) — bounded by spec §5 AC-1
```

### `CHANGELOG.md` (MODIFY)
```markdown
<!-- occurrences: 1 (verified: grep -c '^# Unreleased' CHANGELOG.md) -->
<!-- AFTER — insert a new bullet directly below the FEAT-109 add_policy bullet (the one ending
     "`Policy(resource="...")` with a single string no longer raises `TypeError`."): -->
- **`PolicyAdapter.from_policy` validates `ObjectPolicy(objects=...)` (FEAT-111).** Objects are
  converted with the policy's `type=` (default `object`) and validated like `resource=`. A policy is
  rejected (`add_policy` raises `ValueError`) instead of losing objects silently: `resource=` combined
  with `objects=`, `!`-negated objects, dict-shaped or non-string objects, and `objects=` on `Policy` /
  `FilePolicy`.
```

### FILL IN checklist
- [ ] `_resolve_objects` shape check — rule 4 (list/tuple of non-empty `str`; dict/set/other rejected)
- [ ] `_resolve_objects` negation check — rule 5
- [ ] `_resolve_objects` type check — rule 6
- [ ] `from_policy` docstring: add that unsupported or invalid `objects=` also produce `skipped=True`
- [ ] both test bodies

---

## Acceptance Criteria

- [ ] Every §1 row marked silent for `objects=` now returns `skipped=True`, a reason naming the object or argument, and no policies
- [ ] Valid objects convert as in `test_from_policy_objects_converted`
- [ ] Storage path unchanged: `tests/test_yaml_storage_double_load.py` and `tests/test_unified_evaluation.py` still pass
- [ ] All Validation Commands pass
- [ ] No linting errors in changed files from the linters the repository configures

---

## Validation Commands

- `pytest tests/test_policy_adapter_from_policy.py -q`
- `pytest tests/test_pdp_add_policy.py -q`
- `pytest tests/test_policy_server_example.py -q`

---

## Completion Note

**Completed by**: Claude Code (/sdd-fix, actor agent:sdd-fix:64bffa2f)
**Date**: 2026-11-11
**Commits**: b181916 (guard + tests + CHANGELOG), 6058f0f (review fix)
**Notes**: Added `_object_resources` (shared with `_adapt_object`, storage output unchanged) and
`_resolve_objects`; `from_policy` now passes resolved objects as the classic `resource` list with
`objects: None`. All silent cases from spec §1 are rejected with a reason naming the object.
Validation: the 6 contract suites pass (146 tests); black and flake8 clean on changed files.

**Deviations from spec**: rule 6 is stricter than written. The adversarial codex review (CONFIRM) showed
`type="!deployment"` turned every object into an enforcing DENY, and the follow-up probe showed `type="urn"`
re-parsed `urn:<name>` as the wildcard `<name>:*`. `type=` must now match `[A-Za-z_][A-Za-z0-9_.-]*` and
not be `urn`. Codex's 3 `test_yaml_storage_double_load.py` failures were hostname resolution in its sandbox
(`socket.gethostbyname`), not a finding; they pass locally.
