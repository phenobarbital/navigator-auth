# TASK-209: Validate native ResourcePolicy environment in PolicyAdapter.from_policy

**Feature**: FEAT-111 — Policy adapter fixes — ObjectPolicy objects= and ResourcePolicy environment
**Spec**: `sdd/specs/policies-adapter-fixes.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-208
**Assigned-to**: unassigned
**Discovered-from**: `issue:6a034393d065`

---

## Context

Ledger issue `issue:6a034393d065` (tech_debt, minor, found while FEAT-109 was reviewed):
"adapter.py:396-397 passes valid ResourcePolicy through unvalidated; native environment keys the
engine ignores are not rejected." The Rust engine skips unknown environment keys
(`rs_pep/src/lib.rs:247`, `_ => continue`). So
`ResourcePolicy(environment={"day_of_week": 1})` or `{"weekday": 1}` registers through
`PDP.add_policy` with no time restriction at all. Classic policies already reject this. This task
implements spec §3 Module 2.

Base branch: `dev` (FEAT-109 / PR #634 merged at `142a9e1`, so `from_policy` is present). If `grep -c "def from_policy" navigator_auth/abac/policies/adapter.py` prints 0 in your worktree, STOP: it was branched from an old base.

---

## Scope

- Extract the per-key value rules from `_normalize_environment` into
  `PolicyAdapter._environment_value_error(key, value)`, without changing classic behaviour, and add an
  `is_manager` rule (`bool` only).
- Add `PolicyAdapter.NATIVE_ENV_KEYS = ENGINE_ENV_KEYS | frozenset({"is_manager"})`.
- Add `PolicyAdapter._resource_policy_error(policy)` and call it in `from_policy`'s `ResourcePolicy`
  branch. A valid policy is still returned as the same, unmodified object.
- Update `from_policy`'s docstring, extend the CHANGELOG bullet TASK-208 added, and add tests.

**NOT in scope**: the storage path (`_adapt_resource`, `adapt_batch`); native `conditions` keys;
alias normalisation for native policies (`day_of_week` is rejected with a hint, never rewritten).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/policies/adapter.py` | MODIFY | `NATIVE_ENV_KEYS`, `_environment_value_error`, `_resource_policy_error`, `from_policy` RP branch |
| `tests/test_policy_adapter_from_policy.py` | MODIFY | native environment tests |
| `CHANGELOG.md` | MODIFY | extend the FEAT-111 bullet |

---

## Codebase Contract (Anti-Hallucination)

Verified against `dev` @ `98f560d` (adapter.py identical to FEAT-109 head `3999ef9`). Line numbers move once TASK-208 lands, so
locate edits by the quoted anchors, not by line.

### Verified Imports
```python
from collections.abc import Mapping                                     # adapter.py:3
from typing import Optional, List, Tuple, Any                           # adapter.py:5
from navigator_auth.abac.policies.resource_policy import ResourcePolicy # adapter.py:6
# tests: copy, pytest, ResourcePolicy already imported (tests/test_policy_adapter_from_policy.py:3-9)
```

### Existing Signatures to Use
```python
# navigator_auth/abac/policies/adapter.py
    ENGINE_ENV_KEYS = frozenset({"hour", "dow", "is_business_hours", "is_weekend", "day_segment"})  # line 300
    def _normalize_environment(environment: Any) -> Tuple[Optional[dict], Optional[str]]: ...       # line 322; value loop 348-375
    def from_policy(policy: AbstractPolicy) -> AdapterResult: ...                                    # line 379; RP pass-through 396-397

# navigator_auth/abac/policies/resource_policy.py
class ResourcePolicy(AbstractPolicy):        # line 7
    _env_conditions                          # line 73: `environment or {}` — stored as given, any type
    # environment is NOT forwarded to AbstractPolicy, so policy.environment is None for native policies

# navigator_auth/abac/policies/evaluator.py:270-271
#   "environment": policy._env_conditions,
#   "is_manager": bool(policy.conditions.get("is_manager", False) or policy._env_conditions.get("is_manager", False))
```

### Does NOT Exist
- ~~`ResourcePolicy.environment`~~ holding the native env — it is `None`; read `policy._env_conditions`
- ~~`PolicyAdapter.NATIVE_ENV_KEYS`~~ before this task — you create it
- ~~a `day_of_week` alias for native policies~~ — reject it; do not normalise

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
    "sym:navigator_auth/abac/policies/adapter.py#PolicyAdapter._normalize_environment",
    "sym:navigator_auth/abac/policies/resource_policy.py#ResourcePolicy"
  ]
}
```

---

## Implementation Blueprint

### Steps (in order)
1. Add `NATIVE_ENV_KEYS` below `ENGINE_ENV_KEYS`. *Why*: `is_manager` is a native key the evaluator honours (evaluator.py:271), so rejecting it would break valid policies such as `tests/test_unified_evaluation.py:253`.
2. Move the value checks out of `_normalize_environment` into `_environment_value_error`. *Why*: one rule set for classic and native policies; the existing `test_from_policy_environment_normalization` guards the move.
3. Add `_resource_policy_error` and call it in `from_policy`'s `ResourcePolicy` branch. *Why*: this closes the issue while keeping the pass-through identity the FEAT-109 spec requires.
4. Run the full test file before adding new tests, to confirm the refactor changed nothing. Then add the tests.

### `navigator_auth/abac/policies/adapter.py` (MODIFY) — `NATIVE_ENV_KEYS`
```python
# occurrences: 1 (verified: grep -c '    ENGINE_ENV_KEYS = frozenset' navigator_auth/abac/policies/adapter.py)
# AFTER — insert below `    ENGINE_ENV_KEYS = frozenset({...})` (adapter.py:300):
    # Native ResourcePolicy environments may also carry is_manager, which
    # PolicyEvaluator._serialize_policies_from_index lifts into
    # conditions.is_manager (evaluator.py:271).
    NATIVE_ENV_KEYS = ENGINE_ENV_KEYS | frozenset({"is_manager"})
```

### `navigator_auth/abac/policies/adapter.py` (MODIFY) — `_normalize_environment` loop
```python
# occurrences: 1 (verified: grep -c '        for key, value in env.items():' navigator_auth/abac/policies/adapter.py)
# REPLACE the loop (from `        for key, value in env.items():` through the
# `                return None, f"unsupported value for environment key {key!r}: {value!r}"` line) with:
        for key, value in env.items():
            error = PolicyAdapter._environment_value_error(key, value)
            if error:
                return None, error
# keep the following `        return env, None` unchanged, then add the new static method after
# _normalize_environment ends:

    @staticmethod
    def _environment_value_error(key: str, value: Any) -> Optional[str]:
        """Check one environment value against what the policy evaluator honours.

        Shared by the classic (``_normalize_environment``) and native
        (``_resource_policy_error``) checks. Assumes ``key`` is already known.

        Args:
            key: An ``ENGINE_ENV_KEYS`` or ``NATIVE_ENV_KEYS`` key.
            value: The policy's expected value for ``key``.

        Returns:
            None when supported, otherwise the rejection reason.
        """
        # FILL IN: move the old loop body's `if key in {"hour", "dow"}: ... else: ...` chain here
        #   verbatim (it sets `valid`). Add `elif key == "is_manager": valid = isinstance(value, bool)`
        #   before the final `else`. Keep the bool exclusions: isinstance(True, int) is True.
        if not valid:
            return f"unsupported value for environment key {key!r}: {value!r}"
        return None
```
**Why**: the reason string is unchanged, so classic rejections read the same as before.

### `navigator_auth/abac/policies/adapter.py` (MODIFY) — `_resource_policy_error` + `from_policy`
```python
# occurrences: 1 (verified: grep -c '        if isinstance(policy, ResourcePolicy):' navigator_auth/abac/policies/adapter.py)
# REPLACE the two-line pass-through
#         if isinstance(policy, ResourcePolicy):
#             return AdapterResult(policy=policy)
# with:
        if isinstance(policy, ResourcePolicy):
            error = PolicyAdapter._resource_policy_error(policy)
            if error:
                return AdapterResult(skipped=True, reason=f"Policy '{policy.name}': {error}")
            return AdapterResult(policy=policy)
```
```python
# Add directly above the `    @staticmethod` that precedes `    def from_policy(` (occurrences: 1):
    @staticmethod
    def _resource_policy_error(policy: ResourcePolicy) -> Optional[str]:
        """Validate a native ResourcePolicy's environment without reinterpreting it.

        Args:
            policy: The ResourcePolicy given to :meth:`from_policy`. Never mutated.

        Returns:
            None when every environment key is honoured by the evaluator,
            otherwise the rejection reason.
        """
        env = policy._env_conditions  # pylint: disable=W0212
        if not env:
            return None
        if not isinstance(env, Mapping):
            return f"unsupported environment shape: {type(env).__name__}"
        unknown = sorted(str(key) for key in set(env) - PolicyAdapter.NATIVE_ENV_KEYS)
        if unknown:
            # FILL IN: when "day_of_week" is in unknown, append a hint "(use 'dow')" — spec §3 M2
            return f"unsupported environment keys: {', '.join(unknown)}"
        for key, value in env.items():
            error = PolicyAdapter._environment_value_error(key, value)
            if error:
                return error
        return None
```
**Why**: `from_policy` must never raise. This helper only reads plain mappings, but
`str(key)` keeps a non-string key from breaking `sorted`/`join`.

### `tests/test_policy_adapter_from_policy.py` (MODIFY)
```python
# APPEND at end of file (after TASK-208's tests):


@pytest.mark.parametrize(
    "environment",
    [
        {"is_business_hours": True},
        {"is_manager": True},
        {"dow": [0, 1, 2, 3, 4], "hour": {"min": 8, "max": 18}},
        {"day_segment": "morning"},
    ],
)
def test_from_policy_resource_policy_environment_valid(environment):
    """Valid native environments pass through as the same, unmodified object."""
    # FILL IN: rp = ResourcePolicy(name="rp", resources=["tool:*"], environment=environment);
    #   before = copy.deepcopy(rp._env_conditions); assert result.policy is rp, not skipped,
    #   rp._env_conditions == before


@pytest.mark.parametrize(
    "environment",
    [{"weekday": 1}, {"day_of_week": 1}, {"hour": "nine"}, {"hour": True}, {"is_manager": "yes"}, {"is_weekend": "no"}, ["dow"]],
)
def test_from_policy_resource_policy_environment_rejected(environment):
    """Unknown keys and unsupported shapes reject a native ResourcePolicy."""
    # FILL IN: assert skipped, reason present, policy is None, additional_policies == [];
    #   for {"day_of_week": 1} also assert "dow" in reason
```

### `CHANGELOG.md` (MODIFY)
```markdown
<!-- occurrences: 1 (verified after TASK-208: grep -c 'validates `ObjectPolicy(objects=...)` (FEAT-111)' CHANGELOG.md) -->
<!-- APPEND to the end of TASK-208's FEAT-111 bullet: -->
  A `ResourcePolicy` passed to `add_policy` now has its `environment` checked too: keys other than
  `hour`, `dow`, `is_business_hours`, `is_weekend`, `day_segment` and `is_manager`, or unsupported
  value shapes, raise `ValueError` instead of being silently ignored by the engine (use `dow`, not
  `day_of_week`, on native policies).
```

### FILL IN checklist
- [ ] `_environment_value_error` — move the value chain verbatim and add the `is_manager` branch
- [ ] `_resource_policy_error` — `day_of_week` hint
- [ ] `from_policy` docstring — `ResourcePolicy` is returned unchanged *if its environment is supported*
- [ ] both test bodies

---

## Acceptance Criteria

- [ ] Unknown or ill-shaped native environment keys → `skipped=True` with reason; `day_of_week` reason mentions `dow`
- [ ] Valid native environments → `result.policy is policy`, `_env_conditions` unchanged
- [ ] `test_from_policy_environment_normalization` passes unchanged (classic behaviour preserved)
- [ ] `examples/policy_server.py` still registers (`tests/test_policy_server_example.py`)
- [ ] All Validation Commands pass; no lint errors in changed files

---

## Validation Commands

- `pytest tests/test_policy_adapter_from_policy.py -q`
- `pytest tests/test_policy_server_example.py -q`
- `pytest tests/test_unified_evaluation.py -q`
- `pytest tests/test_pdp_add_policy.py -q`

---

## Completion Note

*(Agent fills this in when done)*
