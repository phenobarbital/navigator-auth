# TASK-210: Atomic evaluator load for `PDP.add_policy`

**Feature**: FEAT-112 — PDP policy registry hardening
**Spec**: `sdd/specs/abac-pdp-tech-debt.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned
**Discovered-from**: `issue:5430348ff68e`

---

## Context

Spec §1 item 1 and §3 Module 1. `PDP.add_policy` (pdp.py:150) calls
`self._evaluator.load_policies(adapted)` before it updates `_registered`/`_policies`, and
`PolicyEvaluator.load_policies` (evaluator.py:240-246) changes the live `PolicyIndex` in place before
it serializes the index for the Rust engine. When serialization raises (reproduced with a
`ResourcePolicy` whose `environment` holds a `datetime`), the index keeps the policy, the JSON is
stale, `_registered` does not know the policy, and `_has_external_policies()` turns `True` — so
`on_startup` skips the whole storage load, and every later `load_policies` fails on the poisoned index.

Fix the root cause in the evaluator (copy-on-write load) and keep the PDP contract
("raises `ValueError`, nothing is changed").

---

## Scope

- Add `PolicyIndex.copy()` — shallow copy of the four containers, keeping order and `_by_name`.
- Rewrite `PolicyEvaluator.load_policies` as copy-on-write: stage a copy, add, finalize, serialize,
  then assign `_index` and `_policies_json`. Any exception leaves the evaluator unchanged.
- In `PDP.add_policy`, convert an exception from `self._evaluator.load_policies(adapted)` into
  `ValueError("Policy '<name>' cannot be loaded into the evaluator: <cause>")` chained with `from exc`;
  update the docstring.
- In `PDP._load_policy_dicts`, load the evaluator first, then extend `self._policies`.
- Create `tests/test_pdp_registry_hardening.py` with the four M1 tests.

**NOT in scope**: name-collision checks and warnings (TASK-211); the `policies=` constructor
argument (TASK-212); `PolicyAdapter` (FEAT-111); `swap_index`, `reload_policies`, cache or stats
behaviour.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/policies/evaluator.py` | MODIFY | `PolicyIndex.copy()`; copy-on-write `PolicyEvaluator.load_policies` |
| `navigator_auth/abac/pdp.py` | MODIFY | `add_policy` wraps the load in `ValueError`; `_load_policy_dicts` loads evaluator first |
| `tests/test_pdp_registry_hardening.py` | CREATE | M1 tests + shared fixtures for TASK-211/212 |

---

## Codebase Contract (Anti-Hallucination)

### Verified Imports
```python
from navigator_auth.abac.pdp import PDP                                          # verified: pdp.py:71
from navigator_auth.abac.policies import Policy, PolicyEffect                    # verified: tests/test_pdp_add_policy.py:11
from navigator_auth.abac.policies.evaluator import PolicyEvaluator, PolicyIndex  # verified: pdp.py:20
from navigator_auth.abac.policies.resource_policy import ResourcePolicy          # verified: pdp.py:21
from navigator_auth.abac.policies.resources import ResourceType                  # verified: pdp.py:22
from collections import defaultdict                                              # verified: evaluator.py:14 (already imported)
```

### Existing Signatures to Use
```python
# navigator_auth/abac/policies/evaluator.py
class PolicyIndex:                                            # :84
    def __init__(self):                                       # :91
        self._by_type = defaultdict(list)                     # :92  Dict[ResourceType, List[ResourcePolicy]]
        self._by_name = {}                                    # :93  last added wins
        self._enforcing = []                                  # :94
        self._all_policies = []                               # :95
    def add(self, policy: ResourcePolicy) -> None             # :97
    def finalize(self) -> None                                # :110  sorts by -priority
    def get_by_name(self, name: str) -> Optional[ResourcePolicy]   # :125
    def all(self) -> List[ResourcePolicy]                     # :129  body: `return self._all_policies` (:131)
class PolicyEvaluator:                                        # :194
    self._index: PolicyIndex                                  # :228
    self._policies_json: str                                  # :233
    self._cache: Dict[CacheKey, Tuple[EvaluationResult, float]]   # :232
    def load_policies(self, policies: List[ResourcePolicy]) -> None   # :240-246
    def _rebuild_json_cache(self) -> None                     # :248  (keep; becomes unused internally)
    def _serialize_policies_from_index(self, index: PolicyIndex) -> str   # :252
    def check_access(self, ctx, resource_type, resource_name, action, ...)   # :410

# navigator_auth/abac/pdp.py
class PDP:                                                    # :71
    self._policies: list                                      # :81
    self._registered: list[ResourcePolicy]                    # :84
    self._evaluator: PolicyEvaluator                          # :90
    self._tenant_evaluators: OrderedDict[Tuple[int, int], PolicyEvaluator]   # :94
    def add_policy(self, policy: AbstractPolicy) -> list[ResourcePolicy]     # :121; load at :150
    def _has_external_policies(self) -> bool                  # :159
    def _load_policy_dicts(self, policies: list)              # :208-219
```

### Does NOT Exist
- ~~`PolicyIndex.copy`~~ — created by THIS task.
- ~~`PolicyIndex.remove`~~ / ~~`PolicyIndex.discard`~~ — no removal API; do not add one (copy-on-write needs none).
- ~~`PolicyEvaluator.add_policy`~~ / ~~`PolicyEvaluator.load_policy`~~ — only `load_policies` exists.
- ~~`PDP.remove_policy`~~ — does not exist.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/abac/policies/evaluator.py", "action": "MODIFY"},
    {"path": "navigator_auth/abac/pdp.py", "action": "MODIFY"},
    {"path": "tests/test_pdp_registry_hardening.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/abac/policies/evaluator.py#PolicyIndex",
    "sym:navigator_auth/abac/policies/evaluator.py#PolicyEvaluator.load_policies",
    "sym:navigator_auth/abac/policies/evaluator.py#PolicyEvaluator._serialize_policies_from_index",
    "sym:navigator_auth/abac/pdp.py#PDP.add_policy",
    "sym:navigator_auth/abac/pdp.py#PDP._load_policy_dicts"
  ]
}
```

---

## Implementation Blueprint

### Steps (in order)
1. Add `PolicyIndex.copy()` below `all()` — *why*: copy-on-write needs a staging index that keeps
   `_by_name` and list order exactly; rebuilding from `all()` would change which same-named policy
   `get_by_name` returns.
2. Replace the body of `PolicyEvaluator.load_policies` — *why*: assign `_index`/`_policies_json` only
   after add, finalize and serialization all succeeded, so a failure changes nothing (spec AC 1).
3. Wrap the evaluator load in `PDP.add_policy` — *why*: the docstring promises `ValueError` and "nothing
   is changed"; the registry updates below the load must not run after a failure.
4. Swap the two statements in `PDP._load_policy_dicts` — *why*: same ordering bug on the storage path.
5. Create the test file and run the Validation Commands.

### `navigator_auth/abac/policies/evaluator.py` (MODIFY) — `PolicyIndex.copy`
```python
# occurrences: 1 (verified: grep -c '^        return self._all_policies' navigator_auth/abac/policies/evaluator.py)
# AFTER — insert below `        return self._all_policies` (end of `def all`, verified: evaluator.py:131)

    def copy(self) -> "PolicyIndex":
        """Return a shallow copy that can change without touching this index.

        The policy objects are shared; the containers are new. Order and the
        ``_by_name`` mapping (last added wins) are kept exactly.

        Returns:
            A new ``PolicyIndex`` with the same contents.
        """
        clone = PolicyIndex()
        clone._by_type = defaultdict(list, {rtype: list(items) for rtype, items in self._by_type.items()})
        clone._by_name = dict(self._by_name)
        clone._enforcing = list(self._enforcing)
        clone._all_policies = list(self._all_policies)
        return clone
```
**Why this shape**: `_by_type` must stay a `defaultdict(list)` because `add()` appends to missing keys.
Do not deep-copy policies — they are immutable for the index and shared with `_registered`.

### `navigator_auth/abac/policies/evaluator.py` (MODIFY) — `load_policies`
```python
# occurrences: 1 (verified: grep -c '^    def load_policies(self, policies: List\[ResourcePolicy\]) -> None:' evaluator.py)
# REPLACE the whole method at evaluator.py:240-246 with:
    def load_policies(self, policies: List[ResourcePolicy]) -> None:
        """Add policies to the evaluator, all or nothing.

        The policies are added to a copy of the current index, which is then
        finalized and serialized for the Rust engine. The evaluator switches to
        the new index and JSON only when every step succeeded.

        Args:
            policies: The ``ResourcePolicy`` objects to add.

        Raises:
            Exception: Whatever ``PolicyIndex.add``/``finalize`` or the JSON
                serialization raised. The evaluator is left unchanged.
        """
        policies = list(policies)
        staged = self._index.copy()
        for policy in policies:
            staged.add(policy)
        staged.finalize()
        staged_json = self._serialize_policies_from_index(staged)
        self._index = staged
        self._policies_json = staged_json
        logger.info("Loaded %d policies", len(policies))
```
**Why**: do not clear the cache or stats here — `load_policies` never did; `add_policy` invalidates the
cache itself and `swap_index` stays the reload path. Keep `_rebuild_json_cache` (external callers).

### `navigator_auth/abac/pdp.py` (MODIFY) — `add_policy`
```python
# occurrences: 1 (verified: grep -c '^        self._evaluator.load_policies(adapted)' navigator_auth/abac/pdp.py)
# REPLACE `        self._evaluator.load_policies(adapted)` (verified: pdp.py:150) with:
        try:
            self._evaluator.load_policies(adapted)
        except Exception as exc:
            raise ValueError(f"Policy '{name}' cannot be loaded into the evaluator: {exc}") from exc
```
Also in the `add_policy` docstring "Raises" section (pdp.py:132-135), extend the `ValueError` entry:
`... or a policy with the same name is already registered, or the evaluator failed to load it
(the original error is chained). Nothing is changed when it raises.`
**Why**: `name` is already bound at pdp.py:137. The re-raise keeps pylint's broad-except check quiet.

### `navigator_auth/abac/pdp.py` (MODIFY) — `_load_policy_dicts`
```python
# occurrences: 1 (verified: grep -c '^    def _load_policy_dicts(self, policies: list):' navigator_auth/abac/pdp.py)
# REPLACE the method body at pdp.py:208-219 (signature unchanged in this task) with:
    def _load_policy_dicts(self, policies: list):
        """Convert policy dicts and load them into the evaluator.

        The evaluator is loaded first, so a load failure also leaves the
        compatibility list ``self._policies`` unchanged.
        """
        resource_policies, warnings = PolicyAdapter.adapt_batch(policies)
        for w in warnings:
            self.logger.warning("Policy adaptation warning: %s", w)
        # Load into evaluator (all or nothing).
        self._evaluator.load_policies(resource_policies)
        # Keep them in self._policies for backward compatibility (filter_files).
        self._policies.extend(resource_policies)
```

### `tests/test_pdp_registry_hardening.py` (CREATE)
```python
"""PDP policy registry hardening (FEAT-112): atomic load, name collisions, iterable policies=."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from navigator_auth.abac.pdp import PDP
from navigator_auth.abac.policies import Policy, PolicyEffect
from navigator_auth.abac.policies.evaluator import PolicyEvaluator, PolicyIndex
from navigator_auth.abac.policies.resources import ResourceType


@pytest.fixture(scope="module", autouse=True)
def _restore_event_loop():
    """pytest-asyncio leaves no current loop; legacy tests call get_event_loop()."""
    yield
    asyncio.set_event_loop(asyncio.new_event_loop())


@pytest.fixture(autouse=True)
def _stub_audit_log(monkeypatch):
    """Keep PDP tests local; audit-log construction otherwise resolves host DNS."""
    monkeypatch.setattr("navigator_auth.abac.pdp.AuditLog", lambda: MagicMock(log=AsyncMock()))


def _storage(rows=None):
    storage = AsyncMock()
    storage.load_policies = AsyncMock(return_value=list(rows or []))
    return storage


@pytest.fixture
def pdp():
    """A PDP with empty mocked storage and the native evaluator."""
    return PDP(storage=_storage())


def _ctx(username: str = "someone@acme.com"):
    ctx = MagicMock()
    ctx.user = None
    ctx.userinfo = {"username": username, "groups": []}
    return ctx


def _allow(name: str, path: str = "/dashboard/", priority: int = 5) -> Policy:
    return Policy(name=name, effect=PolicyEffect.ALLOW, resource=[f"urn:uri:{path}"], priority=priority)


def _fail_serializing(monkeypatch, name: str = "boom") -> None:
    """Make the evaluator's JSON serialization raise once policy ``name`` is in the index."""
    original = PolicyEvaluator._serialize_policies_from_index

    def _serialize(self, index):
        if any(policy.name == name for policy in index.all()):
            raise TypeError("Object of type datetime is not JSON serializable")
        return original(self, index)

    monkeypatch.setattr(PolicyEvaluator, "_serialize_policies_from_index", _serialize)


def test_policy_index_copy_is_independent():
    # FILL IN: build an index with two policies sharing a name; copy(); add a third to the copy;
    # assert the original's all(), _by_name, _by_type, _enforcing are unchanged and the copy's
    # get_by_name(shared) is the same object as the original's — bounded by spec §4 row 1
    ...


def test_load_policies_failure_leaves_evaluator_unchanged(pdp, monkeypatch):
    # FILL IN: add_policy(_allow("ok")); snapshot id(_index), [id(p) for p in all()], _policies_json;
    # _fail_serializing(monkeypatch); load_policies([adapted "boom"]) raises TypeError;
    # snapshots unchanged — bounded by AC 1
    ...


def test_add_policy_load_failure_is_atomic(pdp, monkeypatch):
    # FILL IN: as test_add_policy_rejection_is_atomic in tests/test_pdp_add_policy.py:125, but the
    # failure is _fail_serializing; also assert _has_external_policies() is False and that
    # add_policy(_allow("after", "/after/")) then succeeds and is enforced — bounded by AC 2
    ...


def test_load_policy_dicts_failure_keeps_compat_list(pdp, monkeypatch):
    # FILL IN: _fail_serializing; pdp._load_policy_dicts([{"name": "boom", "effect": "allow",
    # "resources": ["uri:/x/"], "actions": ["uri:read"]}]) raises; pdp._policies and the index
    # are unchanged — bounded by spec §3 Module 1
    ...
```
**Why this shape**: the fixtures are copied (not imported) from `tests/test_pdp_add_policy.py`, which
FEAT-111 also runs — do not edit that file. `_fail_serializing` makes the failure deterministic
whatever FEAT-111's adapter later rejects. TASK-211/212 append to this file.

### FILL IN checklist
- [ ] `test_policy_index_copy_is_independent` — independence + `_by_name` preserved; bounded by spec §4
- [ ] `test_load_policies_failure_leaves_evaluator_unchanged` — bounded by AC 1
- [ ] `test_add_policy_load_failure_is_atomic` — `ValueError` with "cannot be loaded into the evaluator", full snapshot incl. cache and tenant LRU, recovery; bounded by AC 2
- [ ] `test_load_policy_dicts_failure_keeps_compat_list` — bounded by spec §3 Module 1

---

## Acceptance Criteria

- [ ] A `load_policies` failure leaves `PolicyEvaluator._index` (same object) and `_policies_json` unchanged.
- [ ] `add_policy` raises `ValueError` (cause chained) on an evaluator failure; `_registered`, `_policies`, index, JSON, cache and tenant LRU unchanged; a valid `add_policy` succeeds afterwards.
- [ ] `_load_policy_dicts` leaves `_policies` unchanged when the evaluator load fails.
- [ ] Existing tests in the Validation Commands pass unchanged.
- [ ] `black --check -l 120` and `flake8` clean on the changed lines.

---

## Validation Commands
- `pytest tests/test_pdp_registry_hardening.py -q`
- `pytest tests/test_pdp_add_policy.py -q`
- `pytest tests/test_unified_evaluation.py -q`
- `pytest tests/test_yaml_storage_double_load.py -q`

---

## Test Specification

See the CREATE block above; spec §4 rows tagged M1.

---

## Agent Instructions

When you pick up this task:
1. **Work in the feature worktree** — never on `base_branch`
   (`parrot sdd worktree ensure --slug abac-pdp-tech-debt --feature-id FEAT-112`)
2. **Read the spec** at the path listed above for full context
3. **Check dependencies** — none
4. **Verify the Codebase Contract** before writing any code
5. **Update status** in `sdd/tasks/index/abac-pdp-tech-debt.json` → `"in-progress"` (set `started_at`)
6. **Implement** — start from the Implementation Blueprint, complete every `# FILL IN:`
7. **Verify** — run the Validation Commands
8. **Commit the code** — stage only the files this task lists
9. **Close the task** with `parrot sdd task close TASK-210 abac-pdp-tech-debt verified`
10. **Fill in the Completion Note**, then commit the SDD state

---

## Completion Note
*(Agent fills this in when done)*

**Completed by**:
**Date**:
**Notes**:
**Deviations from spec**: none
