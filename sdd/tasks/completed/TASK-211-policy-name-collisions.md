# TASK-211: Detect policy name collisions beyond registered policies

**Feature**: FEAT-112 — PDP policy registry hardening
**Spec**: `sdd/specs/abac-pdp-tech-debt.spec.md`
**Status**: done
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-210
**Assigned-to**: unassigned
**Discovered-from**: `issue:518d25bdd2ff`

---

## Context

Spec §1 item 2 and §3 Module 2. `add_policy` (pdp.py:142-147) checks names only against
`_registered`. Verified on `dev`: when a registered policy and a storage policy share a name, the
engine keeps both and DENY still wins, but `PolicyIndex.get_by_name` — used by
`decorators._find_policy` (decorators.py:1003) — returns the storage policy after `on_startup` and the
registered one after `reload_policies()`. Nothing reports the collision.

Decision (spec §8): keep both policies (dropping one could drop a DENY), reject the collision in
`add_policy`, and log a WARNING when storage brings a name that is already registered.

---

## Scope

- In `add_policy`, also reject an adapted name already present in the shared evaluator index
  (`self._evaluator._index.all()`): `ValueError("Policy name '<n>' is already loaded in the evaluator")`.
  Keep the existing "already registered" message and the in-batch duplicate check.
- Add `PDP._warn_registered_name_collisions(policies, source)`.
- Give `_load_policy_dicts` a `source: str = "storage"` keyword and call the helper there;
  `_load_policies` passes `"DB storage"` / `"YAML storage"`.
- Call the helper in `reload_policies` on the adapted storage list, before `extend(self._registered)`.
- Append the three M2 tests to `tests/test_pdp_registry_hardening.py`.

**NOT in scope**: dropping or renaming colliding policies; duplicates inside storage; per-tenant
evaluator builds (`_build_tenant_evaluator` gets no warning — one line per tenant build is noise);
making `get_by_name` deterministic; the constructor (TASK-212).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/pdp.py` | MODIFY | evaluator-wide name check; collision WARNING helper and its two call sites |
| `tests/test_pdp_registry_hardening.py` | MODIFY | M2 tests |

---

## Codebase Contract (Anti-Hallucination)

### Verified Imports
```python
# No new imports in pdp.py.
# Tests reuse what TASK-210 imported in tests/test_pdp_registry_hardening.py
# (PDP, Policy, PolicyEffect, ResourceType, MagicMock/AsyncMock, _storage, _ctx, _allow).
```

### Existing Signatures to Use
```python
# navigator_auth/abac/pdp.py (line numbers as on dev @ 0e8220a, before TASK-210)
class PDP:
    self.logger = logger                                     # :88  instance attribute — tests may replace it
    def add_policy(self, policy: AbstractPolicy) -> list[ResourcePolicy]:   # :121
        registered_names = {registered.name for registered in self._registered}   # :142
        adapted_names: set[str] = set()                      # :143
        # loop :144-147 raises "Policy name '...' is already registered"
    def _has_external_policies(self) -> bool                 # :159
    def sorted_policies(self):                               # :169  (insert the helper above it)
    async def _load_policies(self):                          # :178
        self._load_policy_dicts(policies)                    # :194
        self._load_policy_dicts(yaml_policies)               # :202
    def _load_policy_dicts(self, policies: list):            # :208 (TASK-210 rewrites its body)
    async def reload_policies(self) -> int:                  # :337
        # Registered policies survive a reload (storage alone does not hold them).   # :367
        resource_policies.extend(self._registered)           # :368

# navigator_auth/abac/policies/evaluator.py
class PolicyIndex:
    def all(self) -> List[ResourcePolicy]                    # :129 — the ONLY index method PDP may call
```

### Does NOT Exist
- ~~`PDP._warn_registered_name_collisions`~~ — created by THIS task.
- ~~`PolicyIndex.names()`~~ / ~~`PolicyIndex.__contains__`~~ — not defined; use `{p.name for p in index.all()}`.
- Do NOT call `self._evaluator._index.get_by_name` from PDP: `_FakeIndex` in
  `tests/test_pdp_add_policy.py:174` and `tests/test_yaml_storage_double_load.py` has only `add`/`finalize`/`all`.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/abac/pdp.py", "action": "MODIFY"},
    {"path": "tests/test_pdp_registry_hardening.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/abac/pdp.py#PDP.add_policy",
    "sym:navigator_auth/abac/pdp.py#PDP._load_policies",
    "sym:navigator_auth/abac/pdp.py#PDP._load_policy_dicts",
    "sym:navigator_auth/abac/pdp.py#PDP.reload_policies",
    "sym:navigator_auth/abac/policies/evaluator.py#PolicyIndex.all"
  ]
}
```

---

## Implementation Blueprint

### Steps (in order)
1. Extend the name check in `add_policy` — *why*: a name loaded from storage/YAML or a pre-loaded
   evaluator must be rejected too (spec AC 3); registered names keep their message so
   `tests/test_pdp_add_policy.py::test_add_policy_duplicate_name_raises` still matches.
2. Add `_warn_registered_name_collisions` above `sorted_policies` — *why*: one helper for both
   storage paths keeps the message identical.
3. Thread `source` through `_load_policy_dicts` and call the helper — *why*: startup path.
4. Call the helper in `reload_policies` — *why*: the periodic reload path.
5. Append the tests; run the Validation Commands.

### `navigator_auth/abac/pdp.py` (MODIFY) — `add_policy` name check
```python
# occurrences: 1 (verified: grep -c '^        registered_names = {registered.name for registered in self._registered}' pdp.py)
# REPLACE pdp.py:142-147 (from `registered_names = ...` through `adapted_names.add(adapted_policy.name)`) with:
        registered_names = {registered.name for registered in self._registered}
        loaded_names = {loaded.name for loaded in self._evaluator._index.all()}
        adapted_names: set[str] = set()
        for adapted_policy in adapted:
            if adapted_policy.name in registered_names or adapted_policy.name in adapted_names:
                raise ValueError(f"Policy name '{adapted_policy.name}' is already registered")
            if adapted_policy.name in loaded_names:
                raise ValueError(f"Policy name '{adapted_policy.name}' is already loaded in the evaluator")
            adapted_names.add(adapted_policy.name)
```
Also add to the `add_policy` docstring `ValueError` entry: "or a policy with that name is already
loaded in the evaluator (from storage, YAML or a pre-loaded evaluator)".

### `navigator_auth/abac/pdp.py` (MODIFY) — helper
```python
# occurrences: 1 (verified: grep -c '^    def sorted_policies(self):' navigator_auth/abac/pdp.py)
# BEFORE — insert above `    def sorted_policies(self):` (verified: pdp.py:169)
    def _warn_registered_name_collisions(self, policies: list[ResourcePolicy], source: str) -> None:
        """Log a WARNING for each policy whose name is also a registered policy's name.

        Both policies stay loaded and enforced (a DENY still wins); only lookups
        by name, such as ``PolicyIndex.get_by_name`` used by the decorators,
        return one of them.

        Args:
            policies: Policies about to be loaded from storage.
            source: Where they come from, for the log message.
        """
        registered_names = {policy.name for policy in self._registered}
        for name in sorted({policy.name for policy in policies} & registered_names):
            self.logger.warning(
                "Policy name '%s' from %s is also a registered policy; both are enforced, "
                "but lookups by name return only one of them. Rename one.",
                name,
                source,
            )
```

### `navigator_auth/abac/pdp.py` (MODIFY) — `_load_policy_dicts` and its callers
```python
# occurrences: 1 each (verified: grep -c on each anchor below)
# `    def _load_policy_dicts(self, policies: list):`  →  `    def _load_policy_dicts(self, policies: list, source: str = "storage"):`
#   and insert, right after the adaptation-warning loop and before `self._evaluator.load_policies(...)`:
        self._warn_registered_name_collisions(resource_policies, source)
#   add to its docstring: "Args: policies: raw policy dicts. source: label used in collision warnings."
# `            self._load_policy_dicts(policies)`       →  `            self._load_policy_dicts(policies, "DB storage")`
# `                self._load_policy_dicts(yaml_policies)` →  `                self._load_policy_dicts(yaml_policies, "YAML storage")`
```

### `navigator_auth/abac/pdp.py` (MODIFY) — `reload_policies`
```python
# occurrences: 2 for `        resource_policies.extend(self._registered)` (pdp.py:287 tenant build, :368 reload)
# Disambiguate by the comment that precedes ONLY the reload one (occurrences: 1):
#         # Registered policies survive a reload (storage alone does not hold them).
#         resource_policies.extend(self._registered)
# INSERT between the comment and the extend:
        self._warn_registered_name_collisions(resource_policies, "storage reload")
```
**Why**: the helper must see only the storage list, i.e. before the registered policies are appended.
Leave `_build_tenant_evaluator` (the :287 occurrence) untouched.

### `tests/test_pdp_registry_hardening.py` (MODIFY — append)
```python
_DENY_ROW = {"name": "dup", "effect": "deny", "resources": ["uri:/dup/"], "actions": ["uri:read"], "priority": 50}


@pytest.mark.asyncio
async def test_add_policy_rejects_name_loaded_from_storage():
    # FILL IN: PDP(storage=_storage([{... "name": "x", "effect": "allow", ...}])); await _load_policies();
    # add_policy(_allow("x")) raises ValueError "already loaded in the evaluator"; _registered == [];
    # index names unchanged — bounded by AC 3
    ...


@pytest.mark.asyncio
async def test_storage_collision_with_registered_warns_and_keeps_both():
    # FILL IN: PDP(storage=_storage([_DENY_ROW]), policies=[_allow("dup", "/dup/")]);
    # pdp.logger = MagicMock(); await pdp._load_policies(); a warning call names 'dup' and "DB storage";
    # both "dup" policies in evaluator._index.all(); check_access(_ctx(), ResourceType.URI, "/dup/",
    # "uri:read") is denied; then reload_policies() warns again ("storage reload") and still denies.
    # Also cover the reverse (registered DENY, storage ALLOW) → denied — bounded by AC 4
    ...


@pytest.mark.asyncio
async def test_no_collision_no_warning():
    # FILL IN: distinct names → no logger.warning call mentioning "also a registered policy"
    ...
```
**Why**: replace `pdp.logger` with a `MagicMock` instead of `caplog` — `navconfig.logging.logger`
propagation is not guaranteed; `self.logger` is a plain instance attribute (pdp.py:88).

### FILL IN checklist
- [ ] `test_add_policy_rejects_name_loaded_from_storage` — bounded by AC 3
- [ ] `test_storage_collision_with_registered_warns_and_keeps_both` — both directions, startup + reload; bounded by AC 4
- [ ] `test_no_collision_no_warning` — bounded by AC 4

---

## Acceptance Criteria

- [ ] `add_policy` rejects a name present anywhere in the shared evaluator ("already loaded in the evaluator"); registered names still say "already registered".
- [ ] A storage/YAML policy whose name matches a registered one logs one WARNING per name on startup and on reload; both policies stay in the index and a DENY in either source still denies.
- [ ] `_build_tenant_evaluator` unchanged.
- [ ] Existing tests in the Validation Commands pass unchanged.
- [ ] `black --check -l 120` and `flake8` clean on the changed lines.

---

## Validation Commands
- `pytest tests/test_pdp_registry_hardening.py -q`
- `pytest tests/test_pdp_add_policy.py -q`
- `pytest tests/test_yaml_storage_double_load.py -q`
- `pytest tests/test_tenant_sql_filtering.py -q`

---

## Test Specification

See the append block above; spec §4 rows tagged M2.

---

## Agent Instructions

When you pick up this task:
1. **Work in the feature worktree** (`parrot sdd worktree ensure --slug abac-pdp-tech-debt --feature-id FEAT-112`)
2. **Read the spec** for full context
3. **Check dependencies** — TASK-210 must be `"done"` in `sdd/tasks/index/abac-pdp-tech-debt.json`
4. **Verify the Codebase Contract** — line numbers shift after TASK-210; re-locate anchors by text
5. **Update status** → `"in-progress"` (set `started_at`)
6. **Implement** from the blueprint; complete every `# FILL IN:`
7. **Verify** — run the Validation Commands
8. **Commit the code** — stage only the files this task lists
9. **Close the task** with `parrot sdd task close TASK-211 abac-pdp-tech-debt verified`
10. **Fill in the Completion Note**, then commit the SDD state

---

## Completion Note
*(Agent fills this in when done)*

**Completed by**: Claude Code (/sdd-fix, actor agent:sdd-fix:953638ae)
**Date**: 2026-11-11
**Notes**: Implemented as blueprinted in commit f3752d5. `add_policy` checks names against
`_registered` and every policy in `self._evaluator._index.all()` ("already loaded in the evaluator");
new `_warn_registered_name_collisions` called from `_load_policy_dicts` (new `source` keyword; startup
passes "DB storage" / "YAML storage") and from `reload_policies` ("storage reload").
`_build_tenant_evaluator` untouched. Tests use a `MagicMock` logger. The two positive collision
tests and the storage-name rejection fail on the TASK-210 state and pass now.
Validation: test_pdp_registry_hardening (8), test_pdp_add_policy (13), test_yaml_storage_double_load
(12), test_tenant_sql_filtering (13 passed, 2 skipped — live-DB tests), test_policy_server_example (4)
— all passed. black -l 120 / flake8 clean on the changed files.
**Deviations from spec**: none
