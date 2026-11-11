# TASK-212: Accept any iterable for `PDP(policies=...)`

**Feature**: FEAT-112 — PDP policy registry hardening
**Spec**: `sdd/specs/abac-pdp-tech-debt.spec.md`
**Status**: pending
**Priority**: low
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-211
**Assigned-to**: unassigned
**Discovered-from**: `issue:d1c06c381acc`

---

## Context

Spec §1 item 3 and §3 Module 3. `PDP.__init__` (pdp.py:97) registers constructor policies only when
`isinstance(policies, list)`. A tuple, generator or set registers nothing and raises nothing; a single
policy object passed by mistake is ignored the same way. That is the silent failure FEAT-109 set out
to remove.

---

## Scope

- Replace the `isinstance(policies, list)` branch:
  - `None` → register nothing;
  - `str`, `bytes`, `Mapping`, or anything that is not an `Iterable` → `TypeError` naming the type;
  - any other iterable → `self.add_policy(policy)` per item.
- Change the type hint to `Optional[Iterable[AbstractPolicy]]` and add a Google-style `__init__` docstring.
- Add one CHANGELOG "Unreleased" bullet covering FEAT-112 (all three changes).
- Append the three M3 tests to `tests/test_pdp_registry_hardening.py`.

**NOT in scope**: `add_policy` behaviour (TASK-210/211); removing the now-unused `List`/`Policy`
imports (they may be re-exported, and the file already carries unused `Union`/`Any`).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/pdp.py` | MODIFY | iterable `policies=`, type hint, `__init__` docstring, import |
| `tests/test_pdp_registry_hardening.py` | MODIFY | M3 tests |
| `CHANGELOG.md` | MODIFY | one FEAT-112 bullet under "# Unreleased" |

---

## Codebase Contract (Anti-Hallucination)

### Verified Imports
```python
from collections.abc import Iterable, Mapping   # stdlib; NEW in pdp.py (pdp.py:2 has `from collections import OrderedDict`)
from navigator_auth.abac.policies.abstract import AbstractPolicy   # verified: pdp.py:19 (already imported)
```

### Existing Signatures to Use
```python
# navigator_auth/abac/pdp.py (dev @ 0e8220a)
from collections import OrderedDict                          # :2
class PDP:
    def __init__(
        self,
        storage: AbstractStorage,
        policies: Optional[List[Policy]] = None,             # :77
        yaml_storage: Optional[YAMLStorage] = None,
        evaluator: Optional[PolicyEvaluator] = None,
    ):                                                       # :74-80
        ...
        if isinstance(policies, list):                       # :97
            for policy in policies:                          # :98
                self.add_policy(policy)                      # :99

# Policy objects are hashable (verified: `{Policy(...)}` works) and NOT Iterable
# (verified: isinstance(Policy(...), collections.abc.Iterable) is False).
```

### Does NOT Exist
- ~~`PDP.register_policies`~~ / ~~`PDP.add_policies`~~ — not defined; loop over `add_policy`.
- ~~`navigator_auth.abac.pdp.Iterable`~~ — not imported yet; this task adds it.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/abac/pdp.py", "action": "MODIFY"},
    {"path": "tests/test_pdp_registry_hardening.py", "action": "MODIFY"},
    {"path": "CHANGELOG.md", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/abac/pdp.py#PDP.__init__",
    "sym:navigator_auth/abac/pdp.py#PDP.add_policy"
  ]
}
```

---

## Implementation Blueprint

### Steps (in order)
1. Add the `collections.abc` import — *why*: `Iterable`/`Mapping` checks.
2. Change the type hint and the registration branch — *why*: spec AC 5; reject `str`/`Mapping`
   explicitly because they are iterable but iterating them yields characters/keys, never policies.
3. Add the `__init__` docstring — *why*: project standard (Google style), documents the `TypeError`.
4. Add the CHANGELOG bullet; append tests; run the Validation Commands.

### `navigator_auth/abac/pdp.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '^from collections import OrderedDict' navigator_auth/abac/pdp.py)
# AFTER — insert below `from collections import OrderedDict` (verified: pdp.py:2)
from collections.abc import Iterable, Mapping

# occurrences: 1 (verified: grep -c '^        policies: Optional\[List\[Policy\]\] = None,' pdp.py)
# REPLACE `        policies: Optional[List[Policy]] = None,` (pdp.py:77) with:
        policies: Optional[Iterable[AbstractPolicy]] = None,

# occurrences: 1 (verified: grep -c '^        if isinstance(policies, list):' pdp.py)
# REPLACE pdp.py:97-99 (`if isinstance(policies, list):` and its 2-line body) with:
        if policies is not None:
            if isinstance(policies, (str, bytes, Mapping)) or not isinstance(policies, Iterable):
                raise TypeError(f"PDP policies= must be an iterable of policies, got {type(policies).__name__}")
            for policy in policies:
                self.add_policy(policy)
```
Insert this docstring as the first statement of `__init__` (before `self._policies: list = []`):
```python
        """Create the PDP.

        Args:
            storage: Storage the policies are loaded from on startup and reload.
            policies: Policies to register with ``add_policy``: any iterable
                (list, tuple, generator, set). ``None`` registers nothing.
            yaml_storage: Optional YAML policy storage.
            evaluator: Shared evaluator to use instead of a new one.

        Raises:
            TypeError: ``policies`` is a string, bytes, a mapping or not iterable.
            ValueError: ``add_policy`` rejected one of ``policies``.
        """
```
**Why**: keep registration last (after the evaluator and tenant LRU exist) — the existing comment at
pdp.py:95-96 explains it; keep that comment.

### `CHANGELOG.md` (MODIFY)
```markdown
# occurrences: 1 (verified: grep -c '^# Unreleased' CHANGELOG.md)
# AFTER — insert below the FEAT-109 `add_policy` bullet that ends with "`TypeError`." (CHANGELOG.md:15),
# as a new bullet:
- **PDP policy registry hardening (FEAT-112).** `PolicyEvaluator.load_policies` is now all-or-nothing:
  a failure (e.g. a policy that cannot be serialized) leaves the evaluator unchanged, and
  `PDP.add_policy` raises `ValueError` instead of leaving a half-loaded policy that made `on_startup`
  skip the storage load. `add_policy` also rejects a name already loaded from storage/YAML, and a
  storage/YAML policy named like a registered one logs a WARNING (both stay enforced).
  `PDP(policies=...)` accepts any iterable and raises `TypeError` for strings, mappings and
  non-iterables instead of silently ignoring a tuple.
```

### `tests/test_pdp_registry_hardening.py` (MODIFY — append)
```python
@pytest.mark.parametrize(
    "make",
    [tuple, lambda items: (item for item in items), set],
    ids=["tuple", "generator", "set"],
)
def test_constructor_accepts_iterables(make):
    # FILL IN: PDP(storage=_storage(), policies=make([_allow("a", "/a/"), _allow("b", "/b/")]));
    # both names in _registered; check_access(_ctx(), ResourceType.URI, "/a/", "uri:read").allowed — bounded by AC 5
    ...


@pytest.mark.parametrize("bad", ["public_dashboard", {"name": "x"}, _allow("single")], ids=["str", "dict", "policy"])
def test_constructor_rejects_non_iterables(bad):
    # FILL IN: pytest.raises(TypeError, match=type(bad).__name__) — bounded by AC 5
    ...


@pytest.mark.parametrize("empty", [None, ()], ids=["none", "empty-tuple"])
def test_constructor_empty_policies(empty):
    # FILL IN: _registered == [] and evaluator._index.all() == []
    ...
```

### FILL IN checklist
- [ ] `test_constructor_accepts_iterables` — registered and enforced; bounded by AC 5
- [ ] `test_constructor_rejects_non_iterables` — `TypeError` names the type; bounded by AC 5
- [ ] `test_constructor_empty_policies` — nothing registered

---

## Acceptance Criteria

- [ ] Tuple, generator and set `policies=` register and enforce every policy.
- [ ] `str`, `dict` and a single policy object raise `TypeError` naming the received type.
- [ ] `None` and `()` register nothing; `tests/test_pdp_add_policy.py::test_constructor_policies_registered` still passes.
- [ ] CHANGELOG "Unreleased" has the FEAT-112 bullet.
- [ ] `black --check -l 120` and `flake8` clean on the changed lines.

---

## Validation Commands
- `pytest tests/test_pdp_registry_hardening.py -q`
- `pytest tests/test_pdp_add_policy.py -q`
- `pytest tests/test_policy_server_example.py -q`

---

## Test Specification

See the append block above; spec §4 rows tagged M3.

---

## Agent Instructions

When you pick up this task:
1. **Work in the feature worktree** (`parrot sdd worktree ensure --slug abac-pdp-tech-debt --feature-id FEAT-112`)
2. **Read the spec** for full context
3. **Check dependencies** — TASK-211 must be `"done"` in `sdd/tasks/index/abac-pdp-tech-debt.json`
4. **Verify the Codebase Contract** — line numbers shift after TASK-210/211; re-locate anchors by text
5. **Update status** → `"in-progress"` (set `started_at`)
6. **Implement** from the blueprint; complete every `# FILL IN:`
7. **Verify** — run the Validation Commands
8. **Commit the code** — stage only the files this task lists
9. **Close the task** with `parrot sdd task close TASK-212 abac-pdp-tech-debt verified`
10. **Fill in the Completion Note**, then commit the SDD state

---

## Completion Note
*(Agent fills this in when done)*

**Completed by**:
**Date**:
**Notes**:
**Deviations from spec**: none
