# TASK-101: Same normalization for `AuthUser.groups` and `TokenUser.programs`

**Feature**: FEAT-102 — Normalize `AuthUser.organizations` received as JSON
**Spec**: `sdd/specs/fix-organizations-orgid.spec.md`
**Status**: done
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-99
**Assigned-to**: unassigned

---

## Context

Spec §8 Q3 (resolved by the author on 2026-10-13): `groups` and
`TokenUser.programs` have the same dict pass-through shape as organizations
and get the same treatment in this feature. This task implements spec §3
Module 4: `_coerce_group` / `_coerce_program` mirroring TASK-99's
`_coerce_organization`, `add_group` rewritten on top of the helper (keeping
the `str` shortcut — a bare name is a complete `Group`), `normalize_groups`
folded into `normalize_memberships`, and a `TokenUser` that normalizes
`programs` on construction, on `add_program`, and after the direct
assignment in `TokenAuth` (`token.py:103`). Criteria AC9, AC10.

---

## Scope

- `navigator_auth/identities.py`: add `_coerce_group(group) -> Group` and
  `_coerce_program(program) -> Program`; replace `add_group`; add
  `normalize_groups`; extend `normalize_memberships` to call it.
- `navigator_auth/backends/token.py`: give `TokenUser` a `__post_init__`,
  `add_program`, `normalize_programs`, `normalize_memberships` override;
  after `usr.programs = programs` call `usr.normalize_programs()`.
- Write `tests/unit/test_identities_groups_programs.py` (spec §4 Module 4 table).

**NOT in scope**: organizations (TASK-99); session hooks (TASK-100 — they
already call `normalize_memberships`, so groups/programs are covered there
automatically); ABAC policy `groups` sets (`abac/policies/*`); changing the
`Group` / `Program` models' fields.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/identities.py` | MODIFY | `_coerce_group`, `_coerce_program`, `add_group`, `normalize_groups`, `normalize_memberships` |
| `navigator_auth/backends/token.py` | MODIFY | `TokenUser` methods; normalize after assignment at `:103` |
| `tests/unit/test_identities_groups_programs.py` | CREATE | AC9/AC10 tests |

---

## Codebase Contract

### Verified Imports
```python
from typing import Any, List, Optional, Union     # identities.py:1 after TASK-99 (Union added there)
from collections.abc import Mapping                # identities.py after TASK-99
from datamodel.exceptions import ValidationError   # identities.py after TASK-99
from ..identities import AuthUser, Program         # verified: navigator_auth/backends/token.py:23 (extend with _coerce_program)
from navigator_auth.identities import AuthUser, Group, Guest, Program, Organization   # verified: identities.py:20, :34, :52, :37
from navigator_auth.backends.token import TokenUser                                   # verified: token.py:27
```

### Verified Signatures
```python
class Group(BaseModel):                       # identities.py:20-30
    group: str = Column(required=True)        # :26 ; Meta.strict = True (:28-29) -> unknown key TypeError
Guest = Group(group="guest")                  # identities.py:34 — used by backends/noauth.py:57 `user.add_group(Guest)`

class Program(BaseModel):                     # identities.py:52-64
    program_id: int = Column(required=True)   # :53
    program_name: str = Column(required=True) # :54
    program_slug: str = Column(required=False)# :55 — auto slugify(program_name) at :59-60 ; Meta.strict = True

class AuthUser(Identity):
    groups: List[Group] = Column(required=False, default_factory=list)   # identities.py:107
    def __post_init__(self, data) -> None:    # :115-130 — groups loop calls add_group per item (lines :117-123). UNCHANGED.
    def add_group(self, group: Group):        # :133-136 — str -> Group(group=group); else append. REPLACED here.
    def normalize_memberships(self) -> None:  # added by TASK-99: body is `self.normalize_organizations()` — EXTENDED here

# navigator_auth/backends/token.py
class TokenUser(AuthUser):                    # :27-29
    tenant: str                               # :28
    programs: list[Program]                   # :29 — no default: absent -> None
# TokenAuth.authenticate: :100 usr = await self.create_user(userdata); :103 usr.programs = programs; :104 usr.tenant = tenant

# Consumers that read groups by attribute (must keep working):
#   decorators.py:297-298 getattr(g, "group", None) ; :442-443 group.group in groups ; :795 ; :861
#   abac/decorators.py:123-124 group.group ; abac/pdp.py:507-508 group.group
```

### Does NOT Exist (do not reference)
- `_coerce_group`, `_coerce_program`, `normalize_groups`, `TokenUser.add_program`,
  `TokenUser.normalize_programs`, `TokenUser.__post_init__` — created by THIS task.
- `AuthUser.add_program` — programs live on `TokenUser` only.
- `Program.from_dict`, `Group.from_dict`.
- `tests/unit/test_identities_groups_programs.py` — created here.
- A `programs` default on `TokenUser` — `normalize_programs` must handle `None`.

---

## Implementation Blueprint

### Steps (in order)
1. Block A: add the two helpers right after `_coerce_organization` — same
   error contract so callers see one rule set; `str` is accepted for groups
   only, because a name fully determines a `Group` while a `Program` needs an
   id.
2. Block B: replace `add_group`, add `normalize_groups`, extend
   `normalize_memberships` — rebuild lists fully before assigning (atomic).
3. Block C: `token.py` — import, `TokenUser` methods, and the one-line
   normalization after `usr.programs = programs`.
4. Block D: tests; fill `FILL IN` bodies from spec §4 Module 4 table.
5. Run `pytest tests/unit/test_identities_groups_programs.py tests/unit/test_identities_organizations.py tests/test_allowed.py -v`.

### Block A — `navigator_auth/identities.py` (helpers)
```python
# AFTER — insert below the `_coerce_organization` function (TASK-99), i.e. above the line `class Program(BaseModel):`
# occurrences: 1 (verified: grep -c 'class Program(BaseModel):' navigator_auth/identities.py)
# NOTE: Program is defined AFTER this point; the helpers reference it at call time only (module-level name), which is fine.
def _coerce_group(group: Any) -> Group:
    """Return *group* as a ``Group``.

    Args:
        group: A ``Group`` (returned unchanged), a non-empty ``str`` (becomes
            ``Group(group=<str>)``) or a ``Mapping`` with the model's fields.

    Raises:
        TypeError: any other type.
        ValueError: the mapping cannot build a ``Group``, or the resulting
            ``group`` name is empty / whitespace-only (chained when possible).
    """
    if isinstance(group, Group):
        result = group
    elif isinstance(group, str):
        result = Group(group=group)
    elif isinstance(group, Mapping):
        try:
            result = Group(**dict(group))
        except (ValueError, TypeError, ValidationError) as err:
            raise ValueError(f"Invalid group entry {group!r}: {err}") from err
    else:
        raise TypeError(f"group must be a Group, str or mapping, got {type(group).__name__}")
    # FILL IN: AC9 — empty/whitespace `result.group` -> ValueError(f"Invalid group entry {group!r}: empty group")
    return result


def _coerce_program(program: Any) -> "Program":
    """Return *program* as a ``Program`` (instance kept; ``Mapping`` → ``Program(**dict(program))``).

    Raises:
        TypeError: not a ``Program`` or ``Mapping`` (``str`` included — ``program_id`` is required).
        ValueError: the mapping cannot build a ``Program``, or ``program_name`` is empty / whitespace-only.
    """
    # FILL IN: mirror _coerce_organization exactly (instance / Mapping / else TypeError; errors -> chained ValueError;
    #          AC9 check on program_name) — bounded by spec §2 New Public Interfaces for TokenUser.add_program.
    ...
```
**Why**: three helpers with one shape keep the "no silent incomplete
membership" rule (AC8/AC9) uniform; `str` for groups preserves
`add_group("name")` and `add_group(Guest)` callers (`noauth.py:57`).

### Block B — `navigator_auth/identities.py` (`AuthUser` methods)
```python
# REPLACE — the 4 lines starting at `def add_group(self, group: Group):`
# occurrences: 1 (verified: grep -c 'def add_group(self, group: Group):' navigator_auth/identities.py)
    def add_group(self, group: Union[Group, str, Mapping[str, Any]]) -> None:
        """Append *group* to ``self.groups`` as a ``Group`` (see :func:`_coerce_group`)."""
        self.groups.append(_coerce_group(group))

    def normalize_groups(self) -> None:
        """Re-run group normalization over ``self.groups`` (idempotent, atomic; ``None`` → ``[]``)."""
        current = list(self.groups or [])
        self.groups = [_coerce_group(g) for g in current]
```
```python
# REPLACE — inside `def normalize_memberships(self) -> None:` (TASK-99), the body line `self.normalize_organizations()`
# occurrences: 1 (verify after TASK-99: grep -c 'self.normalize_organizations()' navigator_auth/identities.py)
        self.normalize_organizations()
        self.normalize_groups()
```
Update the `normalize_memberships` docstring to say "organizations and groups".
**Why**: TASK-100's hooks already call `normalize_memberships()`, so legacy
sessions get groups normalized with no further hook change.

### Block C — `navigator_auth/backends/token.py`
```python
# REPLACE — line `from ..identities import AuthUser, Program`
# occurrences: 1 (verified: grep -c 'from ..identities import AuthUser, Program' navigator_auth/backends/token.py)
from typing import Any, Union
from collections.abc import Mapping
from ..identities import AuthUser, Program, _coerce_program
```
```python
# REPLACE — the 3-line class starting at `class TokenUser(AuthUser):`
# occurrences: 1 (verified: grep -c 'class TokenUser(AuthUser):' navigator_auth/backends/token.py)
class TokenUser(AuthUser):
    """Partner-token user; ``programs`` is normalized to ``Program`` instances (FEAT-102)."""

    tenant: str
    programs: list[Program]

    def __post_init__(self, data) -> None:
        """Run ``AuthUser.__post_init__`` then :meth:`normalize_programs`."""
        super(TokenUser, self).__post_init__(data)
        self.normalize_programs()

    def add_program(self, program: Union[Program, Mapping[str, Any]]) -> None:
        """Append *program* as a ``Program`` (see ``identities._coerce_program``)."""
        self.programs.append(_coerce_program(program))

    def normalize_programs(self) -> None:
        """Re-run program normalization over ``self.programs`` (idempotent, atomic; ``None`` → ``[]``)."""
        current = list(self.programs or [])
        self.programs = [_coerce_program(p) for p in current]

    def normalize_memberships(self) -> None:
        """``super().normalize_memberships()`` then :meth:`normalize_programs`."""
        super().normalize_memberships()
        self.normalize_programs()
```
```python
# AFTER — insert below the line `                usr.programs = programs` (keep that line)
# occurrences: 1 (verified: grep -c 'usr.programs = programs' navigator_auth/backends/token.py)
                usr.normalize_programs()
```
**Why**: `TokenAuth` assigns `programs` after `create_user`, bypassing
`__post_init__`; normalizing right after keeps the contract on the only
write path. A malformed program now raises `ValueError` inside
`authenticate` — FILL IN: decide whether to wrap it into
`InvalidAuth(..., status=401)` like the surrounding `except` blocks do
(`token.py:93-94`), bounded by: fail closed, never store dicts.

### Block D — `tests/unit/test_identities_groups_programs.py` (CREATE)
```python
"""FEAT-102 / TASK-101 — groups and programs normalization (spec §4 Module 4 table)."""
import pytest

from navigator_auth.identities import Group, Guest, Organization, Program
from navigator_auth.backends.basic import BasicUser
from navigator_auth.backends.token import TokenUser

PROGRAM_DICT = {"program_id": 1, "program_name": "P"}


def test_groups_str_dict_instance_normalized():
    inst = Group(group="x")
    user = BasicUser(id=1, data={}, groups=["editors", {"group": "admins"}, inst])
    assert [type(g) for g in user.groups] == [Group, Group, Group]
    assert user.groups[2] is inst
    user.add_group(Guest)
    assert user.groups[-1] is Guest                                     # AC10


@pytest.mark.parametrize("bad,exc", [
    ("", ValueError), ("  ", ValueError), ({"group": ""}, ValueError),
    ({"group": "x", "extra": 1}, ValueError), (7, TypeError), (None, TypeError),
])
def test_group_invalid_entries_raise(bad, exc):
    # FILL IN: AC9/AC10 — pytest.raises(exc) on BasicUser(id=1, data={}).add_group(bad)
    ...


def test_tokenuser_programs_normalized_on_construction_and_add():
    # FILL IN: AC10 — TokenUser(id=1, data={}, tenant="t", programs=[dict(PROGRAM_DICT)]) -> Program, program_slug == "p";
    #          add_program({...}) appends Program; TokenUser(..., tenant="t") without programs -> []
    ...


@pytest.mark.parametrize("bad,exc", [
    ("name", TypeError), ({"program_name": "x"}, ValueError), ({"program_id": 1, "program_name": ""}, ValueError),
])
def test_program_invalid_entries_raise(bad, exc):
    # FILL IN
    ...


def test_normalize_memberships_covers_all_lists():
    # FILL IN: user = TokenUser(id=1, data={}, tenant="t"); object.__setattr__ dicts into organizations/groups/programs;
    #          user.normalize_memberships() -> every element is Organization/Group/Program
    ...


def test_tokenauth_assignment_path_normalizes():
    # FILL IN: usr = TokenUser(id=1, data={}, tenant="t"); usr.programs = [dict(PROGRAM_DICT)]; usr.normalize_programs() -> Program
    ...
```

### FILL IN checklist
- [ ] Block A: AC9 check in `_coerce_group`; full body of `_coerce_program`.
- [ ] Block C: error handling for a malformed program inside `TokenAuth.authenticate` (fail closed).
- [ ] Block D: bodies of the five `FILL IN` tests.

---

## Implementation Notes

### Key Constraints
- Keep `add_group(str)` working — `Guest` and string names are used by backends.
- Never mutate the caller's objects; rebuild lists before assigning.
- `filterwarnings = error` in pytest.

### References in Codebase
- `navigator_auth/identities.py` — `_coerce_organization` (TASK-99) is the template.
- `navigator_auth/backends/noauth.py:57` — `user.add_group(Guest)` caller.
- `navigator_auth/backends/token.py:86-110` — the partner-token flow that assigns `programs`.

---

## Acceptance Criteria

- [ ] Implementation complete per scope.
- [ ] `pytest tests/unit/test_identities_groups_programs.py -v` passes.
- [ ] `pytest tests/unit/test_identities_organizations.py tests/unit/test_session_user_rehydration.py tests/test_allowed.py tests/test_auth_middleware_mechanism.py -v` still passes.
- [ ] `ruff check navigator_auth/identities.py navigator_auth/backends/token.py tests/unit/test_identities_groups_programs.py` clean.
- [ ] `python -c "from navigator_auth.backends.token import TokenUser; TokenUser(id=1, data={}, tenant='t', programs=[{'program_id': 1, 'program_name': 'P'}]).programs[0].program_slug"` prints nothing and exits 0.
- [ ] Spec AC9 and AC10 each have passing tests.

---

## Test Specification

See Block D. Minimum passing set: the six test functions listed there.

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at `sdd/specs/fix-organizations-orgid.spec.md` (§2 New Public Interfaces, §3 M4, §4, §6, §8 Q2/Q3).
2. **Check dependencies** — TASK-99 must be in `sdd/tasks/completed/` (TASK-100 recommended first; no shared files).
3. **Update status** in `sdd/tasks/index/fix-organizations-orgid.json` → `"in-progress"`.
4. **Implement** blocks A–D in order.
5. **Verify** all acceptance criteria.
6. **Move this file** to `sdd/tasks/completed/TASK-101-groups-programs-normalization.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback; parrot-sdd-coder unavailable: execution_not_found)
**Date**: 2026-10-12
**Notes**: _coerce_group/_coerce_program, TokenUser methods; TokenAuth.authenticate's existing broad except already fails closed (returns False) on a malformed program, so no InvalidAuth wrapping added. 73 related tests pass; ruff clean.

**Deviations from spec**: none
