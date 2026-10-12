# TASK-99: Normalize `AuthUser.organizations` in `identities.py`

**Feature**: FEAT-102 — Normalize `AuthUser.organizations` received as JSON
**Spec**: `sdd/specs/fix-organizations-orgid.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Spec §1: `AuthUser.organizations` is typed `List[Organization]` but holds
raw `dict`s whenever user data arrives as JSON, because
`Identity.__post_init__` never runs datamodel's own conversion and
`add_organization` only converts `str`. This task implements spec §3
Module 1: one choke point (`add_organization`) that coerces every input,
plus the idempotent `normalize_organizations()` / `normalize_memberships()`
methods that TASK-100 wires into session rehydration and TASK-101 extends
for groups/programs. Acceptance criteria AC1–AC5, AC8, AC9 (spec §5).

---

## Scope

- Add module helper `_coerce_organization(org) -> Organization` to
  `navigator_auth/identities.py` with the exact error contract of spec §2:
  instance → same object; `Mapping` → `Organization(**dict(org))`; any
  model failure → chained `ValueError`; other types → `TypeError`; empty or
  whitespace-only `org_id` / `organization` → `ValueError` (AC9).
- Rewrite `AuthUser.add_organization` to append `_coerce_organization(org)`.
  Remove the `str` branch (spec §8 Q1).
- Add `AuthUser.normalize_organizations()` (idempotent, atomic on failure,
  `None` → `[]`) and `AuthUser.normalize_memberships()` (calls
  `normalize_organizations()`; TASK-101 extends it).
- Document the accepted inputs, error contract and the legacy-session policy
  (spec §2 item 2) in the `AuthUser` class docstring.
- Write `tests/unit/test_identities_organizations.py` (spec §4 table 1).

**NOT in scope**: session hooks in `abstract.py` / `auth.py` /
`decorators.py` (TASK-100); `groups` / `programs` (TASK-101); version bump
(TASK-100); any change to `Organization`'s own fields or `Meta`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/identities.py` | MODIFY | imports, `_coerce_organization`, `add_organization`, `normalize_organizations`, `normalize_memberships`, docstrings |
| `tests/unit/test_identities_organizations.py` | CREATE | AC1–AC5, AC8, AC9 unit tests |

---

## Codebase Contract

### Verified Imports (all exist today)
```python
from typing import Any, List, Optional          # verified: navigator_auth/identities.py:1
from dataclasses import InitVar                  # verified: identities.py:2
from slugify import slugify                      # verified: identities.py:3
from datamodel import BaseModel, Column          # verified: identities.py:4
from datamodel.exceptions import ValidationError # verified: used in navigator_auth/backends/basic.py:13
from collections.abc import Mapping              # stdlib
from navigator_auth.identities import AuthUser, Organization        # verified: identities.py:95, :37
from navigator_auth.backends.basic import BasicUser                 # verified: backends/basic.py:35
from navigator_auth.backends.external import OauthUser              # verified: backends/external.py:69 (token, given_name, family_name)
from navigator_auth.backends.token import TokenUser                 # verified: backends/token.py:27 (tenant, programs)
from navigator_auth.backends.api import APIKeyUser                  # verified: backends/api.py:33 (token, api_key)
from navigator_auth.backends.noauth import AnonymousUser            # verified: backends/noauth.py:16
from navigator_auth.backends.django import DjangoUser               # verified: backends/django.py:36 (sessionid required)
from navigator_auth.backends.passkey import PasskeyUser             # verified: backends/passkey.py:59
```

### Verified Signatures
```python
class Organization(BaseModel):                       # identities.py:37-49
    org_id: str = Column(required=True)              # :38 — int input is coerced to str (verified)
    organization: str = Column(required=True)        # :39
    slug: str = Column(required=False)               # :40 — auto slugify(organization) at :44-45
    class Meta: strict = True; frozen = False        # :47-49 — unknown kwarg -> TypeError

class Identity(BaseModel):                           # identities.py:67-92
    def __post_init__(self, data):                   # :81-84 — create_field per data key; NO BaseModel.__post_init__ call
    Meta.strict = False                              # :91

class AuthUser(Identity):                            # identities.py:95-141
    organizations: List[Organization] = Column(required=False, default_factory=list)   # :108
    def __post_init__(self, data) -> None:           # :115-130 — copies list, resets, calls add_organization per item. UNCHANGED.
    def add_group(self, group: Group):               # :133-136 — leave alone (TASK-101)
    def add_organization(self, org: Organization):   # :138-141 — REPLACED by this task
```
Observed model errors (spec §6 reproduction): missing required field →
plain `ValueError` ("Missing Required Field *org_id*"); unknown key →
`TypeError`; `datamodel.exceptions.ValidationError` is NOT a `ValueError`
subclass → catch all three.

### Does NOT Exist (do not reference)
- `AuthUser.normalize_organizations`, `normalize_memberships`,
  `_coerce_organization` — created by THIS task.
- `Organization.from_dict`, `Organization.parse`, `Organization.validate_empty`.
- `BaseModel.__post_init__` call inside `Identity` — do not add one (spec §1 Non-Goals; it breaks later instances because `create_field` mutates class-level fields).
- `tests/unit/test_identities*.py` — no identities tests exist yet.
- `AuthUser.to_dict()` is NOT safe in tests (class-level `create_field` leak, spec §7).

---

## Implementation Blueprint

### Steps (in order)
1. Update the `typing` import and add `Mapping` + `ValidationError` imports
   (block A) — because the helper type-checks against `collections.abc.Mapping`
   (ORM row mappings qualify) and must catch datamodel's non-`ValueError` error.
2. Insert `_coerce_organization` after the `Organization` class (block B) — a
   module function, not a method, because TASK-101 mirrors it for `Group`/`Program`.
3. Replace `add_organization` and add the two `normalize_*` methods (block C).
   Build the new list fully before assigning — because AC8 requires the list to
   be unchanged after a failed call.
4. Extend the `AuthUser` class docstring with the legacy-session policy text
   from spec §2 item 2 (block C) — AC7 requires it to live in the docstring.
5. Create the test module (block D); fill the `FILL IN` bodies from spec §4.
6. Run `pytest tests/unit/test_identities_organizations.py tests/test_auth_middleware_mechanism.py -v`.

### Block A — `navigator_auth/identities.py` (imports)
```python
# REPLACE — line `from typing import Any, List, Optional`
# occurrences: 1 (verified: grep -c 'from typing import Any, List, Optional' navigator_auth/identities.py)
from typing import Any, List, Optional, Union
from collections.abc import Mapping
from dataclasses import InitVar
from slugify import slugify
from datamodel import BaseModel, Column
from datamodel.exceptions import ValidationError
```
**Why**: `Union`/`Mapping` are used in the new signatures; `ValidationError`
is raised by strict datamodel models and is not a `ValueError`.

### Block B — `navigator_auth/identities.py` (helper)
```python
# AFTER — insert below the `Organization` class, i.e. above the line `class Program(BaseModel):`
# occurrences: 1 (verified: grep -c 'class Program(BaseModel):' navigator_auth/identities.py)
def _coerce_organization(org: Any) -> Organization:
    """Return *org* as an ``Organization``.

    Args:
        org: An ``Organization`` instance (returned unchanged, same object) or a
            ``Mapping`` with the model's fields (``org_id``, ``organization``,
            optional ``slug``). The mapping is copied; the caller's object is
            never mutated.

    Returns:
        A valid ``Organization``.

    Raises:
        TypeError: *org* is neither an ``Organization`` nor a ``Mapping``
            (this includes ``str`` — the former string shortcut is gone).
        ValueError: the mapping cannot build a valid ``Organization``
            (missing required field, unknown key, model validation error),
            or ``org_id`` / ``organization`` is empty or whitespace-only.
            The original exception, when any, is chained.
    """
    if isinstance(org, Organization):
        result = org
    elif isinstance(org, Mapping):
        try:
            result = Organization(**dict(org))
        except (ValueError, TypeError, ValidationError) as err:
            raise ValueError(f"Invalid organization entry {org!r}: {err}") from err
    else:
        raise TypeError(
            "organization must be an Organization or a mapping, "
            f"got {type(org).__name__}"
        )
    # FILL IN: AC9 — if str(result.org_id).strip() == "" or str(result.organization).strip() == ""
    #          raise ValueError(f"Invalid organization entry {org!r}: empty org_id/organization")
    #          bounded by: applies to instances AND mappings; never mutate `org`.
    return result
```
**Why**: one function is the only place a value becomes an `Organization`, so
construction (`__post_init__` → `add_organization`) and later adds share it.

### Block C — `navigator_auth/identities.py` (`AuthUser` methods)
```python
# REPLACE — the 4 lines starting at `def add_organization(self, org: Organization):`
# occurrences: 1 (verified: grep -c 'def add_organization(self, org: Organization):' navigator_auth/identities.py)
    def add_organization(self, org: Union[Organization, Mapping[str, Any]]) -> None:
        """Append *org* to ``self.organizations`` as an ``Organization``.

        Delegates to :func:`_coerce_organization`; see it for accepted inputs
        and raised errors. Idempotent for already-valid instances.
        """
        self.organizations.append(_coerce_organization(org))

    def normalize_organizations(self) -> None:
        """Re-run organization normalization over ``self.organizations``.

        Intended for objects rehydrated without ``__post_init__`` (jsonpickle
        session payloads written before FEAT-102). Idempotent: a list that is
        already all ``Organization`` is rebuilt with the same objects. A
        ``None`` list becomes ``[]``.

        Raises:
            ValueError, TypeError: as :func:`_coerce_organization`; the list
                is left as it was before the call when an entry fails.
        """
        current = list(self.organizations or [])
        self.organizations = [_coerce_organization(o) for o in current]

    def normalize_memberships(self) -> None:
        """Normalize every membership list of this user in place.

        Calls :meth:`normalize_organizations`; subclasses with more
        membership lists override and call ``super()``. This is the method
        the session rehydration hooks call. Idempotent; raises like the parts.
        """
        self.normalize_organizations()
```
Also extend the `AuthUser` class docstring (`"""AuthUser ... """` at
`identities.py:96-99`, occurrences of `Model for any Authenticated User.`: 1)
with: *"Organizations: every element of ``organizations`` is an
``Organization``; mappings are coerced in ``add_organization``. Sessions
written before FEAT-102 may hold dicts — navigator-auth normalizes them in its
own rehydration points; code that calls ``session.decode('user')`` directly
must call ``normalize_memberships()`` or wait for re-login / session expiry."*
**Why**: the list comprehension completes (or raises) before assignment, which
gives AC8 atomicity for free; `list(... or [])` covers the `None` case.

### Block D — `tests/unit/test_identities_organizations.py` (CREATE)
```python
"""FEAT-102 / TASK-99 — AuthUser.organizations normalization (spec §4 table 1)."""
import copy

import pytest

from navigator_auth.identities import AuthUser, Organization
from navigator_auth.backends.basic import BasicUser
from navigator_auth.backends.external import OauthUser
from navigator_auth.backends.token import TokenUser
from navigator_auth.backends.api import APIKeyUser
from navigator_auth.backends.noauth import AnonymousUser
from navigator_auth.backends.django import DjangoUser
from navigator_auth.backends.passkey import PasskeyUser

ORG_DICT = {"org_id": "7", "organization": "Example", "slug": "example"}
ORG_DICT_NO_SLUG = {"org_id": 7, "organization": "Example Org"}
BAD_ORG_DICTS = [
    {"organization": "x"},
    {"org_id": "1"},
    {"org_id": "1", "organization": "n", "extra": 1},
    {"org_id": "", "organization": "x"},          # AC9
    {"org_id": "1", "organization": "   "},       # AC9
]
SUBCLASS_KWARGS = [
    (BasicUser, {}),
    (OauthUser, {"token": "t", "given_name": "a", "family_name": "b"}),
    (TokenUser, {"tenant": "t", "programs": []}),
    (APIKeyUser, {"token": "t", "api_key": "k"}),
    (AnonymousUser, {}),
    (DjangoUser, {"sessionid": "s"}),
    (PasskeyUser, {}),
]


def test_basicuser_dict_organizations_become_models():
    user = BasicUser(id=1, data={}, organizations=[dict(ORG_DICT)])
    assert isinstance(user.organizations[0], Organization)
    assert user.organizations[0].org_id == "7"                       # AC1


def test_dict_organizations_via_data_initvar():
    # FILL IN: same as above but payload inside data={"organizations": [...]} (create_user path) — AC1
    ...


def test_add_organization_dict_after_construction():
    # FILL IN: AC2
    ...


def test_mixed_list_normalized_and_instances_preserved():
    # FILL IN: AC3 — one dict + one instance; assert `user.organizations[1] is instance`
    ...


def test_fields_keep_model_semantics():
    # FILL IN: AC4 — ORG_DICT_NO_SLUG -> org_id == "7", slug == "example-org"; explicit slug kept
    ...


def test_normalization_idempotent_and_input_untouched():
    # FILL IN: AC5 — copy.deepcopy(input) == input after construction; normalize_organizations() twice -> equal list, same objects
    ...


@pytest.mark.parametrize("kwargs", [{}, {"organizations": None}, {"organizations": []}])
def test_absent_none_empty_organizations(kwargs):
    assert BasicUser(id=1, data={}, **kwargs).organizations == []


@pytest.mark.parametrize("bad", ["acme", 7, None, ["x"]])
def test_non_mapping_entries_raise_typeerror(bad):
    # FILL IN: AC8 — pytest.raises(TypeError) on add_organization(bad)
    ...


@pytest.mark.parametrize("bad", BAD_ORG_DICTS)
def test_bad_mapping_entries_raise_valueerror(bad):
    # FILL IN: AC8/AC9 — pytest.raises(ValueError) as exc; for the first three assert exc.value.__cause__ is not None
    ...


def test_failed_add_leaves_list_unchanged():
    # FILL IN: AC8 — after failed add_organization / normalize_organizations the list equals its prior value
    ...


@pytest.mark.parametrize("cls,extra", SUBCLASS_KWARGS)
def test_all_ident_subclasses_normalize(cls, extra):
    user = cls(id=1, data={}, organizations=[dict(ORG_DICT)], **extra)
    assert all(isinstance(o, Organization) for o in user.organizations)
    assert isinstance(user, AuthUser)
```
**Why**: parametrized subclass test proves no `_ident` needs its own change
(spec §5); never call `to_dict()` here (spec §7 gotcha).

### FILL IN checklist
- [ ] Block B: AC9 empty/whitespace check (instances and mappings).
- [ ] Block D: bodies of the nine `FILL IN` tests, bounded by the AC noted on each.
- [ ] Block C: `AuthUser` class docstring paragraph (legacy-session policy).

---

## Implementation Notes

### Key Constraints
- Never mutate the caller's mapping or list (`dict(org)`, `list(...)`).
- `str` input is a `TypeError` — do NOT resurrect `Organization(organization=org)`.
- Google-style docstrings and type hints on every new/changed signature.
- pytest runs with `filterwarnings = ["error"]` (`pyproject.toml:101-116`).

### References in Codebase
- `navigator_auth/identities.py:37-49` — `Organization` (target type).
- `navigator_auth/identities.py:115-141` — `AuthUser.__post_init__` / `add_organization`.
- `tests/unit/test_user_session_decorator.py` — test style (plain functions, no live services).

---

## Acceptance Criteria

- [ ] Implementation complete per scope; `AuthUser.__post_init__` body unchanged.
- [ ] `pytest tests/unit/test_identities_organizations.py -v` passes.
- [ ] `pytest tests/test_auth_middleware_mechanism.py tests/test_basic_auth.py -v` still passes.
- [ ] `ruff check navigator_auth/identities.py tests/unit/test_identities_organizations.py` clean.
- [ ] `python -c "from navigator_auth.identities import AuthUser, _coerce_organization"` works.
- [ ] Spec AC1, AC2, AC3, AC4, AC5, AC8, AC9 each have a passing test.

---

## Test Specification

See Block D. Minimum passing set: the eleven test functions listed there.

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at `sdd/specs/fix-organizations-orgid.spec.md` (§2, §3 M1, §4, §6, §7).
2. **Check dependencies** — none.
3. **Update status** in `sdd/tasks/index/fix-organizations-orgid.json` → `"in-progress"`.
4. **Implement** the blueprint blocks A–D in order.
5. **Verify** all acceptance criteria.
6. **Move this file** to `sdd/tasks/completed/TASK-99-organizations-normalization.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
