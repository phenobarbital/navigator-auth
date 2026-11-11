---
# SDD flow type and base branch (FEAT-145).
type: feature
base_branch: dev
projects: [abac]
tags: [pbac, pdp, policy-registry, atomicity, ledger-fix]
docs:
  policy: none
  pages: []
  api_modules: [navigator_auth.abac.pdp, navigator_auth.abac.policies.evaluator]
---

# Feature Specification: PDP policy registry hardening — atomic load, name collisions, iterable `policies=`

**Feature ID**: FEAT-112
**Date**: 2026-11-11
**Author**: Jesus Lara (spec scaffolded by Claude Code via /sdd-fix)
**Status**: approved
**Target version**: unreleased
**Parent**: FEAT-109 — PBAC example policy issues (`sdd/specs/policy-issues.spec.md`, completed)
**Prerequisite**: met — PR #634 (FEAT-109) merged into `dev` at `142a9e1`; `PDP.add_policy` and `PDP._registered` are on `dev`.
**Sibling**: FEAT-111 (`policies-adapter-fixes`, in flight) edits `navigator_auth/abac/policies/adapter.py` only. FEAT-112 does not touch `adapter.py` and adds its tests in a new file, so the two do not conflict.
**Ledger group**: `fixgroup:9efcc68819f5` — `issue:5430348ff68e` (bug, major), `issue:518d25bdd2ff` (tech_debt, minor), `issue:d1c06c381acc` (tech_debt, minor)

---

## 1. Motivation & Business Requirements

### Problem Statement

FEAT-109 made `PDP.add_policy()` and `PDP(policies=...)` load programmatic policies into the
`PolicyEvaluator` and keep them in `PDP._registered`. Three ledger issues, filed while FEAT-109 was
reviewed, show where the registry and the evaluator can still disagree. All were reproduced on `dev`
@ `f22c5e0` (`pdp.py` and `evaluator.py` identical to `98f560d`).

1. **`issue:5430348ff68e` — `add_policy` is not atomic when the evaluator load fails (bug, major).**
   `PDP.add_policy` (pdp.py:150) calls `self._evaluator.load_policies(adapted)` before updating
   `_registered`/`_policies`. `PolicyEvaluator.load_policies` (evaluator.py:240-246) mutates the live
   `PolicyIndex` in place and only then serializes the whole index to JSON. If serialization raises,
   the policy stays in the index, the Rust JSON is stale, and `_registered` never learns about it.
   Reproduced:

   ```python
   pdp.add_policy(ResourcePolicy(name="rp_bad", resources=["uri:/y/"], actions=["uri:read"],
                                 environment={"when": datetime.now()}))
   # TypeError: Object of type datetime is not JSON serializable
   # index: ['ok', 'rp_bad']   registered: ['ok']   _has_external_policies(): True
   ```

   Consequences: (a) `_has_external_policies()` turns `True`, so `on_startup` → `_load_policies()`
   **skips the whole DB/YAML storage load**; (b) every later `load_policies` re-serializes the poisoned
   index and fails too, so no further `add_policy` can succeed; (c) the shared evaluator holds a policy
   that `reload_policies()` and every per-tenant evaluator drop. `_load_policy_dicts` (pdp.py:208-219)
   has the same ordering problem: it extends `_policies` before the evaluator load.
   (FEAT-111 TASK-209 will make the adapter reject this particular `environment`; the evaluator stays
   non-atomic for any other serialization or sort failure, so the fix belongs in the load path.)

2. **`issue:518d25bdd2ff` — the duplicate-name check covers only registered policies (tech_debt, minor).**
   `add_policy` (pdp.py:142-147) compares names against `_registered` only. Verified engine behaviour
   when a registered policy and a storage policy share a name:

   | Check | Result |
   |---|---|
   | `PolicyIndex.all()` and the Rust JSON | both policies kept |
   | Decision (`check_access`), DENY in either source | DENY wins — decisions are correct |
   | `PolicyIndex.get_by_name(name)` after `on_startup` | the **storage** policy (added last) |
   | `PolicyIndex.get_by_name(name)` after `reload_policies()` | the **registered** policy (added last) |

   `get_by_name` is what `decorators._find_policy` (decorators.py:1003-1015) uses, so a route decorated
   with a policy name gets a different policy before and after a reload. Nothing reports the collision.

3. **`issue:d1c06c381acc` — `PDP(policies=<tuple>)` is silently ignored (tech_debt, minor).**
   `PDP.__init__` (pdp.py:97) uses `isinstance(policies, list)`. A tuple, generator or set registers
   nothing and raises nothing; so does a single policy object passed by mistake.

### Goals
- A failed evaluator load leaves the evaluator, `_registered`, `_policies`, the cache and the tenant LRU
  exactly as they were, and `add_policy` raises `ValueError` as its contract already promises.
- `add_policy` rejects a name already present anywhere in the shared evaluator, not just in `_registered`.
- A storage/YAML policy whose name collides with a registered one is reported with a WARNING.
- `PDP(policies=...)` accepts any iterable of policies and raises `TypeError` for anything else.

### Non-Goals (explicitly out of scope)
- Dropping or renaming either colliding policy. Both stay enforced: dropping one could drop a DENY.
- Making `get_by_name` deterministic for colliding names (the WARNING tells operators to rename).
- Duplicate names *within* storage (two DB rows) and per-tenant evaluator builds (no warning there,
  to avoid one log line per tenant build).
- `PolicyAdapter` validation (FEAT-111) and `reload_policies` semantics.

---

## Governing Decisions

decision audit not configured in this repository

---

## 2. Architectural Design

### Overview

- **Copy-on-write load.** `PolicyEvaluator.load_policies` stages a copy of the current index, adds and
  finalizes there, serializes it, and only then assigns `_index` and `_policies_json`. Any exception
  leaves the evaluator untouched. A new `PolicyIndex.copy()` preserves `_by_name` and list order
  exactly, so successful loads behave as before (unlike rebuilding from `all()`).
- **PDP keeps its contract.** `add_policy` turns an evaluator-load failure into
  `ValueError("Policy '<name>' cannot be loaded into the evaluator: <cause>")` (chained), before
  touching `_registered`/`_policies`. `_load_policy_dicts` loads the evaluator first, then extends
  `_policies`.
- **Collision checks.** `add_policy` checks the adapted names against `_registered` (message unchanged:
  "already registered") and against every policy in the shared evaluator index (new message: "already
  loaded in the evaluator"). A new helper `_warn_registered_name_collisions(policies, source)` logs one
  WARNING per storage/YAML policy whose name matches a registered one; `_load_policy_dicts` and
  `reload_policies` call it.
- **Iterable `policies=`.** `None` → nothing; `str`/`bytes`/`Mapping` or a non-iterable → `TypeError`
  naming the received type; any other iterable → `add_policy` per item.

### Component Diagram
```
PDP.__init__(policies=iterable) ──► add_policy ──► PolicyAdapter.from_policy
                                        │  name check: _registered ∪ evaluator index
                                        ▼
                         PolicyEvaluator.load_policies  (copy → add → finalize → serialize → swap)
                                        │  failure ⇒ ValueError, nothing changed
                                        ▼
                           _registered / _policies / cache / tenant LRU updated
storage, YAML ──► _load_policy_dicts / reload_policies ──► _warn_registered_name_collisions (WARNING)
```

### Integration Points
- `decorators._find_policy` reads `evaluator._index.get_by_name` — unchanged; the WARNING documents
  the ambiguity it inherits.
- `PolicyEvaluator.load_from_file` / `load_from_directory` (evaluator.py:320-328) call
  `load_policies` and gain atomicity for free.
- `tests/test_pdp_add_policy.py` and `tests/test_yaml_storage_double_load.py` fake the evaluator
  (`_FakeIndex` has only `add`/`finalize`/`all`). PDP code must use only `_index.all()` on the index,
  never `get_by_name`/`copy`, so those fakes keep working.

### Data Models
None.

### New Public Interfaces
```python
class PolicyIndex:
    def copy(self) -> "PolicyIndex": ...          # shallow copy, same order and _by_name mapping

class PDP:
    def __init__(self, storage, policies: Optional[Iterable[AbstractPolicy]] = None, ...): ...
    def _warn_registered_name_collisions(self, policies: list[ResourcePolicy], source: str) -> None: ...
    def _load_policy_dicts(self, policies: list, source: str = "storage") -> None: ...
```

---

## 3. Module Breakdown

Three tasks, one per issue, run in order (all edit `pdp.py`).

### Module 1: atomic evaluator load (`issue:5430348ff68e`)
- `evaluator.py`: add `PolicyIndex.copy()`; rewrite `PolicyEvaluator.load_policies` as copy-on-write
  (materialize `policies` with `list()` first; log line unchanged). It does not clear the cache
  (unchanged: callers such as `add_policy` invalidate it).
- `pdp.py` `add_policy`: wrap `self._evaluator.load_policies(adapted)` in `try/except Exception` →
  `ValueError(...) from exc`; update the docstring "Raises" section.
- `pdp.py` `_load_policy_dicts`: call `self._evaluator.load_policies` before `self._policies.extend`.
- Tests in new `tests/test_pdp_registry_hardening.py`.

### Module 2: name collisions (`issue:518d25bdd2ff`)
- `pdp.py` `add_policy`: names in `self._evaluator._index.all()` that are not registered are also
  taken → `ValueError("Policy name '<n>' is already loaded in the evaluator")`. Keep the existing
  "already registered" message for registered names and the in-batch duplicate check.
- `pdp.py`: add `_warn_registered_name_collisions(policies, source)`; call it from
  `_load_policy_dicts` (new `source` keyword, default `"storage"`; `_load_policies` passes
  `"DB storage"` / `"YAML storage"`) and from `reload_policies` (on the adapted storage list, before
  `extend(self._registered)`, source `"storage reload"`).
- Tests pin the verified engine behaviour (both kept, DENY wins) and the WARNING.

### Module 3: iterable `policies=` (`issue:d1c06c381acc`)
- `pdp.py` `__init__`: replace `isinstance(policies, list)` with the rules in §2; type hint
  `Optional[Iterable[AbstractPolicy]]`; `from collections.abc import Iterable, Mapping`.
- Tests: tuple, generator and set register; `str`, `dict` and a single `Policy` raise `TypeError`;
  `None` and `()` register nothing.

---

## 4. Test Specification

### Unit Tests (all in `tests/test_pdp_registry_hardening.py`)
| Test | Module | Description |
|---|---|---|
| `test_policy_index_copy_is_independent` | M1 | adding to the copy leaves the original's `all()`, `_by_name`, `_by_type`, `_enforcing` unchanged; the copy keeps `_by_name` last-wins |
| `test_load_policies_failure_leaves_evaluator_unchanged` | M1 | serialization forced to fail (monkeypatched `_serialize_policies_from_index`) → exception, `_index` object, `all()` and `_policies_json` unchanged |
| `test_add_policy_load_failure_is_atomic` | M1 | after a failed load: `ValueError`, `_registered`, `_policies`, index, JSON, cache, tenant LRU unchanged; `_has_external_policies()` is `False`; a valid `add_policy` afterwards succeeds |
| `test_load_policy_dicts_failure_keeps_compat_list` | M1 | failing evaluator load inside `_load_policy_dicts` leaves `_policies` unchanged |
| `test_add_policy_rejects_name_loaded_from_storage` | M2 | after `_load_policies()` loads storage policy `x`, `add_policy(x)` raises "already loaded in the evaluator"; nothing changed |
| `test_storage_collision_with_registered_warns_and_keeps_both` | M2 | registered `dup` + storage `dup` → WARNING naming `dup` on startup and on `reload_policies()`; both in `all()`; a DENY in either source still denies |
| `test_no_collision_no_warning` | M2 | distinct names → no collision WARNING |
| `test_constructor_accepts_iterables` | M3 | parametrized tuple / generator / set → policies registered and enforced |
| `test_constructor_rejects_non_iterables` | M3 | parametrized `str`, `dict`, single `Policy` → `TypeError` naming the type |
| `test_constructor_empty_policies` | M3 | `None` and `()` → nothing registered |

### Validation Contract

tests:
- tests/test_pdp_registry_hardening.py
- tests/test_pdp_add_policy.py
- tests/test_yaml_storage_double_load.py
- tests/test_tenant_sql_filtering.py
- tests/test_tenant_scoping.py
- tests/test_unified_evaluation.py
- tests/test_policy_server_example.py
markers: none

### Test Data / Fixtures
Copy the `_stub_audit_log` / `pdp_with_storage` / `_ctx` pattern from `tests/test_pdp_add_policy.py`
(do not import from that module, and do not edit it — FEAT-111 runs it).

---

## 5. Acceptance Criteria

- [ ] A `load_policies` failure (any exception) leaves the evaluator's `_index` and `_policies_json` unchanged.
- [ ] `add_policy` raises `ValueError` on an evaluator-load failure and changes nothing; a valid policy can be added afterwards.
- [ ] `add_policy` rejects a name present in the shared evaluator, registered or not.
- [ ] A storage/YAML policy colliding with a registered name logs a WARNING on startup and reload; both policies stay enforced.
- [ ] `PDP(policies=...)` registers any iterable and raises `TypeError` for `str`/`bytes`/`Mapping`/non-iterables.
- [ ] All Validation Contract tests pass; existing tests unchanged.
- [ ] CHANGELOG "Unreleased" gains one bullet covering the three changes.

---

## 6. Codebase Contract

### Verified Imports
```python
from navigator_auth.abac.pdp import PDP                                   # pdp.py:71
from navigator_auth.abac.policies import Policy, PolicyEffect             # used by tests/test_pdp_add_policy.py:11
from navigator_auth.abac.policies.evaluator import PolicyEvaluator, PolicyIndex   # pdp.py:20
from navigator_auth.abac.policies.resource_policy import ResourcePolicy   # pdp.py:21
from navigator_auth.abac.policies.abstract import AbstractPolicy          # pdp.py:19
from navigator_auth.abac.policies.resources import ResourceType           # pdp.py:22
```

### Existing Class Signatures
```python
# navigator_auth/abac/policies/evaluator.py
class PolicyIndex:                                   # :84
    _by_type: Dict[ResourceType, List[ResourcePolicy]]   # defaultdict(list)
    _by_name: Dict[str, ResourcePolicy]
    _enforcing: List[ResourcePolicy]
    _all_policies: List[ResourcePolicy]
    def add(self, policy) -> None                    # :97
    def finalize(self) -> None                       # :110
    def get_by_name(self, name) -> Optional[ResourcePolicy]   # :125
    def all(self) -> List[ResourcePolicy]            # :129
class PolicyEvaluator:                               # :194
    def load_policies(self, policies: List[ResourcePolicy]) -> None    # :240
    def _rebuild_json_cache(self) -> None            # :248
    def _serialize_policies_from_index(self, index) -> str   # :252
    def swap_index(self, new_index, new_json=None) -> None   # :281
    def invalidate_cache(self, user_id=None) -> None # :396

# navigator_auth/abac/pdp.py
class PDP:
    def __init__(self, storage, policies: Optional[List[Policy]] = None, yaml_storage=None, evaluator=None)  # :74
    def add_policy(self, policy: AbstractPolicy) -> list[ResourcePolicy]   # :121
    def _has_external_policies(self) -> bool         # :159
    async def _load_policies(self)                   # :178
    def _load_policy_dicts(self, policies: list)     # :208
    async def _build_tenant_evaluator(self, org_id, client_id)   # :260
    async def reload_policies(self) -> int           # :337
```

### Integration Points
- `navigator_auth/decorators.py:1003` `_find_policy` → `index.get_by_name(name)`.
- `navigator_auth/abac/policies/evaluator.py:320-328` `load_from_file` / `load_from_directory` → `load_policies`.
- `examples/policy_server.py:582-591` builds `PDP(...)` without `policies=` and calls `add_policy` in a loop (unaffected).

### Does NOT Exist (Anti-Hallucination)
- `PolicyIndex.copy` (created by Module 1).
- `PolicyIndex.remove` — no removal API exists; do not add one.
- `PDP.remove_policy`, `PDP.unregister_policy`.
- `PDP._warn_registered_name_collisions` (created by Module 2).

### Edit Sites (Blueprint Anchors)
| Module | File | Anchor |
|---|---|---|
| M1 | `navigator_auth/abac/policies/evaluator.py` | `def all(self) -> List[ResourcePolicy]:` (add `copy` after it) |
| M1 | `navigator_auth/abac/policies/evaluator.py` | `def load_policies(self, policies: List[ResourcePolicy]) -> None:` |
| M1, M2 | `navigator_auth/abac/pdp.py` | `def add_policy(self, policy: AbstractPolicy) -> list[ResourcePolicy]:` |
| M1, M2 | `navigator_auth/abac/pdp.py` | `def _load_policy_dicts(self, policies: list):` |
| M2 | `navigator_auth/abac/pdp.py` | `resource_policies.extend(self._registered)` inside `reload_policies` (the one after `# Registered policies survive a reload`) |
| M3 | `navigator_auth/abac/pdp.py` | `if isinstance(policies, list):` in `__init__` |

---

## 7. Implementation Notes & Constraints

### Patterns to Follow
- Error messages keep FEAT-109's form: `Policy '<name>' ...` / `Policy name '<n>' is already ...`.
- `self.logger.warning("...%s...", arg)` with lazy `%s` arguments.
- PDP touches the index only through `all()` (fake evaluators in tests implement nothing else).

### Known Risks / Gotchas
- `_FakeIndex` / `_make_fake_evaluator` in two test files mock `load_policies`; keep calling
  `self._evaluator.load_policies` from `add_policy` (do not switch to `swap_index`).
  `test_load_policies_runs_with_only_registered` asserts `load_policies.call_count == 2`.
- `defaultdict` must stay a `defaultdict` in `PolicyIndex.copy()` (`add` appends to missing keys).
- Do not clear stats or the cache in `load_policies`; `swap_index` does, `load_policies` never did.
- `tests/test_oauth2_passkey_session.py` hangs at baseline — run test files individually, with a timeout.

### External Dependencies
None.

---

## 8. Open Questions

None. Collision handling (warn and keep both, never drop a policy) was settled during triage: the
engine was verified to keep both and let DENY win, so dropping either side could only weaken a decision.

---

## 9. Design Research Cross-Check

Status: skipped (ledger fix of three scoped issues; no exploration doc).

---

## 10. Documentation

- **Policy**: `none` — CHANGELOG bullet and docstrings only.
- **API modules**: `navigator_auth.abac.pdp`, `navigator_auth.abac.policies.evaluator`

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-11-11 | Claude Code (/sdd-fix) | Initial spec from ledger group fixgroup:9efcc68819f5 |
