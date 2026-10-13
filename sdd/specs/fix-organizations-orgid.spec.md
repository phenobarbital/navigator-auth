---
type: feature
base_branch: dev
---

# Feature Specification: Normalize `AuthUser.organizations` received as JSON

**Feature ID**: FEAT-102
**Date**: 2026-10-12
**Author**: Jesus Lara
**Status**: approved
**Target version**: 0.28.7

> **Inputs:** free-form problem report passed to `/sdd-spec` (no brainstorm or
> proposal exists for this slug). Every code reference below was re-read on
> `dev` at `10ecfbe` on 2026-10-12; the failure was reproduced against the
> current tree (`datamodel` 0.10.21, `navigator-session` 1.1.0,
> `jsonpickle` 3.0.2), not only against the reported 0.28.4.

---

## 1. Motivation & Business Requirements

### Problem Statement

`AuthUser.organizations` is declared as `List[Organization]`
(`navigator_auth/identities.py:108`), but in practice it holds plain `dict`s
whenever the user data arrives as JSON — from a SQL view with JSON
aggregations, from the `AUTH_USER_MAPPING` mapping, or from any backend that
hands `create_user()` a decoded payload.

`AuthUser.__post_init__()` (`identities.py:115-130`) copies the incoming
list and re-adds every element through `add_organization()`
(`identities.py:138-141`). That method only converts `str`; a `dict` is
appended untouched, so the effective content never satisfies the declared
type:

```python
user = BasicUser(id=1, data={}, organizations=[
    {"org_id": "7", "organization": "Example", "slug": "example"},
])
user.organizations[0].org_id
# AttributeError: 'dict' object has no attribute 'org_id'
```

Reproduced on `dev` today (see §6 "Reproduction evidence"). Two aggravating
facts were established during research:

- **Root cause.** `Identity.__post_init__` (`identities.py:81-84`) never
  calls `BaseModel.__post_init__`, which is where `datamodel` 0.10 runs
  `processing_fields()` and converts nested mappings into model instances.
  A plain `datamodel` model with a `List[Organization]` field *does* convert
  `[{"org_id": ...}]` into `Organization` objects (verified for both
  `strict=True` and `strict=False`). `AuthUser` and every `_ident` subclass
  skip that step, so nothing downstream ever coerces the list.
- **Sessions do not repair it.** `navigator-session` stores the user object
  with `jsonpickle.encode()` and restores it through a `ModelHandler` that
  assigns `__dict__` directly (`navigator_session/data.py:21-36`). No
  constructor or `__post_init__` runs on restore (verified: zero calls), so a
  session saved with dicts is read back with dicts — and a session saved with
  `Organization` instances is read back with `Organization` instances.

Today the only in-repo consumer, `allowed_organizations`
(`navigator_auth/decorators.py:663-740`), silently fails closed: the
`AttributeError` is swallowed (`decorators.py:690`, `:724`) and the request is
answered with 401 even for a legitimate member. Downstream applications that
read `user.organizations[...].org_id` crash.

### Goals

- `AuthUser.organizations` honours its declared contract: every element is a
  valid `Organization`, whether the source provided mappings or instances.
- Normalization is centralised in `navigator_auth.identities` — consumers
  never branch on `dict` vs. model.
- The contract holds at construction time for `AuthUser` and all of its
  `_ident` subclasses (`BasicUser`, `OauthUser`, `TokenUser`, `APIKeyUser`,
  `AnonymousUser`, `DjangoUser`, `PasskeyUser`), and for later
  `add_organization()` calls.
- Missing / `None` / empty-list inputs keep today's behaviour (`[]`).
- Invalid entries have an explicit, tested, fail-loud behaviour; incomplete
  organizations are never accepted silently.
- Sessions already stored with dicts have a documented policy, exercised by a
  test, covering both navigator-auth's own rehydration points and downstream
  readers.

### Non-Goals (explicitly out of scope)

- Re-enabling `datamodel` validation on `Identity` (calling
  `BaseModel.__post_init__`). Rejected during research: `Identity.create_field`
  mutates the **class-level** `__dataclass_fields__` / `__columns__`
  (`datamodel/base.py:95-102`), so once one instance has created `user_id`,
  `processing_fields()` on the next instance fails with
  `AttributeError: 'BasicUser' object has no attribute 'user_id'` (reproduced
  with a probe subclass). Fixing that is a `datamodel`/`Identity` redesign, not
  this bug.
- Anything about `groups` / `programs` beyond the normalization in Module 4
  (§8 Q3 resolved: they ARE covered here). The ABAC policy classes' own
  `groups` sets (`abac/policies/*`) are unrelated and untouched.
- Changing `Organization`'s own model validation. The model still accepts
  `Organization(org_id="", organization="x")`; the empty-string rejection
  decided in §8 Q2 lives in the normalization helpers, not in the model.
- Migrating stored session payloads in Redis / cookies, or changing
  `navigator-session`'s `ModelHandler.restore`. navigator-session is a
  separate distribution; see §2 "Legacy session policy".
- Touching the 13 `session.decode("user")` call sites that do not read
  `.organizations` (`decorators.py:122,152,336,374,441,792,858,1043`,
  `abac/decorators.py:121`, `abac/guardian.py:43`, `backends/token.py:198`).

---

## 2. Architectural Design

### Overview

Two small, local changes plus tests:

1. **Normalize at the single choke point.** `AuthUser.add_organization()`
   becomes the only place an element enters `self.organizations`, and it
   coerces every input through a module-level helper
   `_coerce_organization(org) -> Organization`:
   - `Organization` instance → appended **as the same object** (identity
     preserved, no copy).
   - `collections.abc.Mapping` → `Organization(**dict(org))`. The mapping is
     copied first, so the caller's dict is never mutated. Any failure raised
     by the model (`ValueError` for a missing required field, `TypeError` for
     an unknown key, `datamodel.exceptions.ValidationError`) is re-raised as
     `ValueError("Invalid organization entry <repr>: <cause>")` chained with
     `from`, so callers get one exception type for "bad mapping".
   - anything else (`str`, `int`, `list`, `None`, …) → `TypeError`. The
     legacy `str` branch is **removed**: it has been raising
     `ValueError: Missing Required Field *org_id*` since `org_id` became
     required (verified), and fabricating an `org_id` from a name would be
     exactly the silent acceptance AC8 forbids (§8 Q1).
   `__post_init__` keeps its current shape (copy → reset → re-add), so the
   construction path and the later-add path share one code path and are
   idempotent: re-adding an `Organization` yields an equal list, and the input
   list/dicts are left untouched.
   **Empty strings are rejected (§8 Q2):** after coercion, an `org_id` or
   `organization` that is empty or whitespace-only raises the same chained
   `ValueError`, for instances and mappings alike.

2. **Legacy session policy — normalize at navigator-auth's own rehydration
   points, never migrate storage.** A new idempotent public method
   `AuthUser.normalize_organizations() -> None` rebuilds `self.organizations`
   through `add_organization()`; `AuthUser.normalize_memberships() -> None` is
   the single entry point the session hooks call (organizations + groups, plus
   programs on `TokenUser` — Module 4). It is called from the four places where
   navigator-auth itself turns a session payload back into a user and reads
   organizations:
   - `BaseAuthBackend.get_session_user` (`backends/abstract.py:378-387`)
   - `AuthHandler.get_session_user` (`auth.py:757-765`)
   - `allowed_organizations._wrap_function` / `_wrap_method`
     (`decorators.py:686-690`, `:720-724`)
   Well-formed legacy dicts self-heal on first read. A **malformed** legacy
   entry raises `ValueError` from `normalize_organizations()`; in
   `get_session_user` that is caught together with the existing
   `AttributeError, RuntimeError`, logged as a warning and the method returns
   `None` ("unable to decode user session") — i.e. the stale session is
   rejected and the client must re-authenticate (fail closed, explicit
   renewal). In `allowed_organizations` the `ValueError` joins the existing
   `except (AttributeError, TypeError, RuntimeError)` → `member = False` → 401.
   Downstream code that calls `session.decode("user")` directly is **not**
   migrated by this spec; the documented policy for it is "call
   `user.normalize_memberships()` or let the session expire
   (`SESSION_TIMEOUT`, default 360000 s) / re-login". New sessions written
   after this change already carry `Organization` instances, which jsonpickle
   restores as `Organization` (verified), so the policy only concerns payloads
   written before the upgrade.

3. **Login now fails loudly on malformed organizations.**
   `BaseAuthBackend.create_user` (`abstract.py:176-181`) wraps any exception
   from `self._ident(data=userdata)` into `InvalidAuth`. After this change a
   payload like `{"organizations": [{"organization": "x"}]}` (no `org_id`)
   makes the login fail with `InvalidAuth("Unable to created Session User:
   Invalid organization entry …")` instead of producing a half-broken user.
   This is intended (AC8) and is covered by a test; see §7 Known Risks.

### Component Diagram

```
                 JSON / SQL view / AUTH_USER_MAPPING
                               │
                               ▼
   BaseAuthBackend.create_user ──► _ident(data=userdata)   (BasicUser, OauthUser, …)
                                          │
                                          ▼
                              AuthUser.__post_init__
                                 copy → reset → add_organization(o)  ◄── later calls
                                          │
                                          ▼
                              _coerce_organization(o)
                        Organization ─► as-is │ Mapping ─► Organization(**dict(o))
                        other ─► TypeError    │ bad mapping ─► ValueError (chained)
                                          │
                                          ▼
                 remember() ──► session.save_encoded_data("user", user)   [jsonpickle]
                                          │
                                          ▼  (restore = __dict__ assignment, no __post_init__)
   get_session_user (abstract.py / auth.py) ──► user.normalize_organizations()
   allowed_organizations (decorators.py)   ──► user.normalize_organizations()
                                          │
                       ValueError ─► warning + None / member=False (fail closed)
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `Organization` (`identities.py:37-49`) | uses | Target type; its validation (`org_id`, `organization` required; `slug` auto-slugified; `strict=True`) is reused unchanged. |
| `AuthUser.__post_init__` / `add_organization` (`identities.py:115-141`) | modifies | Only `add_organization` body changes; `__post_init__` is untouched but now yields models. |
| `_ident` subclasses (`basic.py:35`, `external.py:69-77`, `token.py:27`, `api.py:33`, `noauth.py:16`, `django.py:36`, `passkey.py:59`) | inherits | All reach `AuthUser.__post_init__` (OauthUser via `super()`); no per-subclass change. |
| `BaseAuthBackend.create_user` (`abstract.py:176-181`) | behaviour change | Malformed organizations now surface as `InvalidAuth` at login. |
| `BaseAuthBackend.get_session_user` (`abstract.py:378-387`) | modifies | Calls `normalize_organizations()` when the decoded object is an `AuthUser`; catches `ValueError`. |
| `AuthHandler.get_session_user` (`auth.py:757-765`) | modifies | Same change; needs `from .identities import AuthUser` (no import cycle: `identities.py` imports only `slugify`/`datamodel`). |
| `allowed_organizations` (`decorators.py:663-740`) | modifies | Normalize before iterating; add `ValueError` to the except tuple. |
| `navigator_session.SessionData.encode/decode` (`data.py:308-345`), `ModelHandler` (`data.py:21-36`) | uses (read-only) | jsonpickle round-trip; not modified. |
| `Group` (`identities.py:20-30`), `AuthUser.add_group` (`identities.py:133-136`) | modifies (Module 4) | `add_group` coerces `str` / `Mapping` / instance; empty `group` rejected. `Guest = Group(group="guest")` (`identities.py:34`) still works (`noauth.py:57`). |
| `Program` (`identities.py:52-64`), `TokenUser` (`backends/token.py:27-29`), `TokenAuth.authenticate` (`token.py:103`) | modifies (Module 4) | `TokenUser.__post_init__` + `add_program` / `normalize_programs`; `token.py:103` normalizes after assigning `usr.programs`. |

### Data Models

No new models. `Organization` is unchanged:

```python
class Organization(BaseModel):            # verified: navigator_auth/identities.py:37
    org_id: str = Column(required=True)        # verified: :38  (int input coerced to str — verified)
    organization: str = Column(required=True)  # verified: :39
    slug: str = Column(required=False)         # verified: :40  (auto = slugify(organization), :44-45)
```

### New Public Interfaces

```python
# navigator_auth/identities.py

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
            (missing required field, unknown key, model validation error).
            The original exception is chained.
    """

class AuthUser(Identity):
    def add_organization(self, org: Union[Organization, Mapping[str, Any]]) -> None:
        """Append *org* to ``self.organizations`` as an ``Organization``.

        Delegates to :func:`_coerce_organization`; see it for accepted inputs
        and raised errors. Idempotent for already-valid instances.
        """

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

    def normalize_memberships(self) -> None:
        """Normalize every membership list of this user in place.

        Calls :meth:`normalize_organizations` and :meth:`normalize_groups`;
        subclasses with more membership lists override and call ``super()``
        (``TokenUser`` adds ``normalize_programs``). This is the method the
        session rehydration hooks call. Idempotent; raises like the parts.
        """

    def add_group(self, group: Union[Group, str, Mapping[str, Any]]) -> None:
        """Append *group* as a ``Group`` (``str`` → ``Group(group=...)``;
        ``Mapping`` → ``Group(**dict(group))``; instance kept as-is).
        Empty/whitespace ``group`` → ``ValueError``; other types → ``TypeError``.
        """

    def normalize_groups(self) -> None:
        """Re-run group normalization over ``self.groups`` (idempotent, atomic)."""


# navigator_auth/backends/token.py
class TokenUser(AuthUser):
    def __post_init__(self, data) -> None:
        """Run ``AuthUser.__post_init__`` then :meth:`normalize_programs`."""

    def add_program(self, program: Union[Program, Mapping[str, Any]]) -> None:
        """Append *program* as a ``Program`` (instance kept; ``Mapping`` →
        ``Program(**dict(program))``). ``str`` is NOT accepted (``program_id`` is
        required) → ``TypeError``; incomplete / empty ``program_name`` → ``ValueError``.
        """

    def normalize_programs(self) -> None:
        """Re-run program normalization over ``self.programs`` (``None`` → ``[]``)."""

    def normalize_memberships(self) -> None:
        """``super().normalize_memberships()`` then :meth:`normalize_programs`."""
```

---

## 3. Module Breakdown

### Module 1: Organization normalization in `identities.py`
- **Path**: `navigator_auth/identities.py`
- **Responsibility**: add `_coerce_organization`, rewrite `add_organization`,
  add `normalize_organizations`, document the accepted inputs / error
  contract and the legacy-session policy in the `AuthUser` docstring.
- **Depends on**: nothing new (`collections.abc.Mapping`, `typing.Union`).
- **Interface skeleton**:

```python
from typing import Any, List, Optional, Union      # verified: identities.py:1 (add Union)
from collections.abc import Mapping                # new import
from dataclasses import InitVar                    # verified: identities.py:2
from slugify import slugify                        # verified: identities.py:3
from datamodel import BaseModel, Column            # verified: identities.py:4


def _coerce_organization(org: Any) -> Organization:
    """<docstring in §2 New Public Interfaces>"""
    ...  # isinstance(org, Organization) -> org
    ...  # isinstance(org, Mapping)      -> Organization(**dict(org)); wrap errors in ValueError(...) from err
    ...  # else                          -> raise TypeError(...)


class AuthUser(Identity):                          # verified: identities.py:95
    organizations: List[Organization] = Column(required=False, default_factory=list)  # verified: :108

    def __post_init__(self, data) -> None:         # verified: identities.py:115-130 — UNCHANGED
        ...

    def add_organization(self, org: Union[Organization, Mapping[str, Any]]) -> None:  # replaces :138-141
        """<docstring in §2>"""
        self.organizations.append(_coerce_organization(org))

    def normalize_organizations(self) -> None:     # new
        """<docstring in §2>"""
        ...  # current = list(self.organizations or []); rebuilt = [_coerce_organization(o) for o in current]
        ...  # assign only after every element coerced (atomic w.r.t. failures)

    def normalize_memberships(self) -> None:     # new — the hook entry point (M2 calls this)
        """<docstring in §2>"""
        self.normalize_organizations()
        ...  # Module 4 adds self.normalize_groups() here
```

### Module 2: Rehydration hooks for legacy sessions
- **Path**: `navigator_auth/backends/abstract.py`, `navigator_auth/auth.py`,
  `navigator_auth/decorators.py`
- **Responsibility**: call `normalize_organizations()` where navigator-auth
  itself turns a session payload into a user and reads organizations; treat
  `ValueError` as "stale/corrupt session user" (fail closed).
- **Depends on**: Module 1.
- **Interface skeleton** (bodies are the existing ones plus the marked lines):

```python
# navigator_auth/backends/abstract.py
from ..identities import Identity, AuthBackend, AuthUser   # verified: abstract.py:39 (add AuthUser)

class BaseAuthBackend(ABC):
    async def get_session_user(self, session: Iterable, name: str = "user") -> Iterable:  # verified: :378
        try:
            user = None
            if session:
                user = session.decode(name)                         # verified: :382
                if user:
                    if isinstance(user, AuthUser):                  # new
                        user.normalize_memberships()                # new
                    user.is_authenticated = True                    # verified: :384
            return user
        except (AttributeError, RuntimeError, ValueError) as ex:    # verified: :386 (add ValueError)
            self.logger.warning(f"NAV: Unable to decode User session: {ex}")   # verified: :387

# navigator_auth/auth.py
from .identities import AuthUser                                    # new import (none exists today)

class AuthHandler:
    async def get_session_user(self, session: Iterable, name: str = "user") -> Iterable:  # verified: auth.py:757
        ...  # same two new lines after :760, add ValueError at :764

# navigator_auth/decorators.py — allowed_organizations            # verified: decorators.py:663
#   _wrap_function: after `user = session.decode("user")` (:686) insert
#       user.normalize_organizations()
#   and extend `except (AttributeError, TypeError, RuntimeError)` (:691) with ValueError.
#   _wrap_method: same at :720 / :725.
```

### Module 3: Tests
- **Path**: `tests/unit/test_identities_organizations.py` (new),
  `tests/unit/test_session_user_rehydration.py` (new)
- **Responsibility**: the unit and round-trip tests of §4. No live Redis:
  session round-trips use `jsonpickle` directly after
  `import navigator_session.data` (registers `ModelHandler`), and
  `get_session_user` is exercised with a `FakeSession` like
  `tests/unit/test_user_session_decorator.py:27-36`.
- **Depends on**: Modules 1 and 2.

### Module 4: Same normalization for `groups` and `TokenUser.programs` (§8 Q3)
- **Path**: `navigator_auth/identities.py`, `navigator_auth/backends/token.py`
- **Responsibility**: add `_coerce_group` / `_coerce_program` helpers next to
  `_coerce_organization` (same error contract, same empty-string rule);
  rewrite `add_group` (`identities.py:133-136`) to use the helper while
  keeping the `str` shortcut (a bare name IS a complete `Group`); add
  `normalize_groups` and fold it into `normalize_memberships`; give `TokenUser`
  a `__post_init__`, `add_program`, `normalize_programs` and a
  `normalize_memberships` override; make `token.py:103` normalize after
  `usr.programs = programs`.
- **Depends on**: Module 1 (helpers/pattern), Module 2 (hooks already call
  `normalize_memberships`).
- **Interface skeleton**: signatures in §2 New Public Interfaces.

```python
# navigator_auth/identities.py
def _coerce_group(group: Any) -> Group: ...        # str -> Group(group=group); Mapping -> Group(**dict(group)); Group -> as-is
def _coerce_program(program: Any) -> Program: ...  # Mapping -> Program(**dict(program)); Program -> as-is; str -> TypeError

class AuthUser(Identity):
    def add_group(self, group: Union[Group, str, Mapping[str, Any]]) -> None:   # replaces identities.py:133-136
        self.groups.append(_coerce_group(group))
    def normalize_groups(self) -> None: ...
    def normalize_memberships(self) -> None:
        self.normalize_organizations()
        self.normalize_groups()

# navigator_auth/backends/token.py
from ..identities import AuthUser, Program, _coerce_program   # verified: token.py imports AuthUser/Program today (check exact line in task)
class TokenUser(AuthUser):                                     # verified: token.py:27
    tenant: str                                                # verified: :28
    programs: list[Program]                                    # verified: :29
    def __post_init__(self, data) -> None:
        super(TokenUser, self).__post_init__(data)
        self.normalize_programs()
    def add_program(self, program: Union[Program, Mapping[str, Any]]) -> None: ...
    def normalize_programs(self) -> None: ...
    def normalize_memberships(self) -> None:
        super().normalize_memberships()
        self.normalize_programs()
# token.py:103  `usr.programs = programs`  ->  keep, then `usr.normalize_programs()`
```

### Delegation-eligible modules

| Module | Eligible | Decided patterns / exact contracts |
|---|---|---|
| M4 groups/programs | yes | Mirror of M1 with `str` kept for groups only; names fixed above. |
| M1 `identities.py` | yes | Skeleton above is final: helper name `_coerce_organization`, method name `normalize_organizations`, `TypeError` for non-mapping, `ValueError` (chained) for bad mapping, same-object preservation, atomic reassignment. |
| M2 rehydration hooks | yes | Exactly the four call sites and the two `except` tuples listed; `isinstance(user, AuthUser)` guard in the two `get_session_user` methods (the default `_ident` is bare `Identity`, `abstract.py:75`). |
| M3 tests | yes | Test names and fixtures in §4; style of `tests/unit/test_user_session_decorator.py`. |

---

## 4. Test Specification

### Unit Tests — `tests/unit/test_identities_organizations.py`

| Test | Module | Description / AC |
|---|---|---|
| `test_basicuser_dict_organizations_become_models` | M1 | AC1 — `BasicUser(id=1, data={}, organizations=[{dict}])`; `user.organizations[0].org_id == "7"`, element is `Organization`. |
| `test_dict_organizations_via_data_initvar` | M1 | AC1 — same payload passed inside `data={"organizations": [...]}` (the `create_user` path). |
| `test_add_organization_dict_after_construction` | M1 | AC2 — `add_organization({...})` appends an `Organization`. |
| `test_mixed_list_normalized_and_instances_preserved` | M1 | AC3 — list of one dict + one instance → both `Organization`; the instance is the **same object** (`is`). |
| `test_fields_keep_model_semantics` | M1 | AC4 — `slug` auto-generated from `organization` when absent/`None`; integer `org_id` coerced to `"7"`; explicit `slug` kept. |
| `test_normalization_idempotent_and_input_untouched` | M1 | AC5 — deep-copy of the input list/dicts equals the input after construction; calling `normalize_organizations()` twice yields an equal list and keeps the same objects. |
| `test_absent_none_empty_organizations` | M1 | Regression — `{}`, `organizations=None`, `organizations=[]` all give `[]`. |
| `test_invalid_entries_raise_explicitly` | M1 | AC8 — parametrized: `"acme"` → `TypeError`; `7` → `TypeError`; `None` → `TypeError`; `{"organization": "x"}` → `ValueError`; `{"org_id": "1"}` → `ValueError`; `{"org_id": "1", "organization": "n", "extra": 1}` → `ValueError`; `ValueError.__cause__` is not `None`. |
| `test_failed_add_leaves_list_unchanged` | M1 | AC8 — after a failed `add_organization`/`normalize_organizations`, `user.organizations` equals its pre-call value. |
| `test_all_ident_subclasses_normalize` | M1 | Parametrized over `BasicUser`, `OauthUser` (`token`, `given_name`, `family_name`), `TokenUser` (`tenant`, `programs=[]`), `APIKeyUser` (`token`, `api_key`), `AnonymousUser`, `DjangoUser` (`sessionid`), `PasskeyUser`. |

### Unit Tests — `tests/unit/test_identities_groups_programs.py` (Module 4)

| Test | Module | Description / AC |
|---|---|---|
| `test_groups_str_dict_instance_normalized` | M4 | AC10 — `groups=["editors", {"group": "admins"}, Group(group="x")]` → three `Group`; instance preserved (`is`); `Guest` still usable via `add_group(Guest)`. |
| `test_group_invalid_entries_raise` | M4 | AC9/AC10 — `""` / `"  "` / `{"group": ""}` → `ValueError`; `7` / `None` → `TypeError`; `{"group": "x", "extra": 1}` → `ValueError`. |
| `test_tokenuser_programs_normalized_on_construction_and_add` | M4 | AC10 — `TokenUser(id=1, data={}, tenant="t", programs=[{"program_id": 1, "program_name": "P"}])` → `Program` with `program_slug == "p"`; `add_program({...})` appends a `Program`; `programs` absent → `[]`. |
| `test_program_invalid_entries_raise` | M4 | `"name"` → `TypeError`; `{"program_name": "x"}` → `ValueError`; `{"program_id": 1, "program_name": ""}` → `ValueError`. |
| `test_normalize_memberships_covers_all_lists` | M4 | Legacy-shaped user (dicts forced into `organizations`, `groups`, `programs` via `object.__setattr__`) → after `normalize_memberships()` every element is a model. |
| `test_tokenauth_assignment_path_normalizes` | M4 | Mimic `token.py:103`: `usr.programs = [dict]; usr.normalize_programs()` → `Program`. |

### Integration / Round-trip Tests — `tests/unit/test_session_user_rehydration.py`

| Test | Description / AC |
|---|---|
| `test_jsonpickle_roundtrip_keeps_attribute_access` | AC6 — `jsonpickle.encode(user)` → `decode` (with `navigator_session.data` imported); `restored.organizations[0].org_id` works without any normalization call. |
| `test_legacy_dict_session_payload_is_normalized_by_get_session_user` | AC7 — build a legacy payload by encoding a user whose `__dict__["organizations"]` was forced to dicts (bypass the constructor with `object.__setattr__` after construction), decode it into a `FakeSession`, run `BaseAuthBackend.get_session_user(stub, session)` and `AuthHandler.get_session_user(stub, session)` (unbound call with a stub carrying `logger`); result has `Organization` elements and `is_authenticated is True`. |
| `test_legacy_malformed_session_payload_is_rejected` | AC7/AC8 — same but with `{"organization": "x"}`; both `get_session_user` variants return `None` and emit a warning (`caplog`). |
| `test_allowed_organizations_accepts_legacy_dict_session` | AC7 — `allowed_organizations(["Example"])` on a bare async handler with `decorators.get_session` patched (pattern of `tests/unit/test_user_session_decorator.py`); legacy dict payload → handler runs; malformed payload → `web.HTTPUnauthorized`. |
| `test_create_user_rejects_malformed_organizations` | §2 item 3 — `BaseAuthBackend.create_user(stub, {"organizations": [{"organization": "x"}]})` raises `InvalidAuth` whose `__cause__` is the `ValueError`. |

### Test Data / Fixtures

```python
ORG_DICT = {"org_id": "7", "organization": "Example", "slug": "example"}
ORG_DICT_NO_SLUG = {"org_id": 7, "organization": "Example Org"}       # -> slug "example-org", org_id "7"
BAD_ORG_DICTS = [{"organization": "x"}, {"org_id": "1"}, {"org_id": "1", "organization": "n", "extra": 1}]

@pytest.fixture
def legacy_user_payload() -> str:
    """jsonpickle string of a BasicUser whose organizations are raw dicts (pre-FEAT-102 session)."""
    import navigator_session.data  # noqa: F401 — registers ModelHandler
    user = BasicUser(id=1, data={"username": "legacy"})
    object.__setattr__(user, "organizations", [dict(ORG_DICT)])
    return jsonpickle.encode(user)

class FakeSession:           # as tests/unit/test_user_session_decorator.py:27-36, decode() -> jsonpickle.decode(payload)
    ...
```

Gotchas for test authors (from §7): `pyproject.toml` runs pytest with
`filterwarnings = ["error"]`; use `logging` (`caplog`) not `warnings`. Do not
call `user.to_dict()` on `AuthUser` objects in tests — `create_field` mutates
class-level fields and `to_dict()` then fails for instances built with other
`data` keys (reproduced).

---

## 5. Acceptance Criteria

> This feature is complete when ALL of the following are true:

- [ ] AC1 — `BasicUser` built with organizations given as dicts exposes
  `user.organizations[0].org_id` (`tests/unit/test_identities_organizations.py`).
- [ ] AC2 — `add_organization({...})` after construction gives the same result.
- [ ] AC3 — A list mixing dicts and valid `Organization` instances is fully
  normalized; instances are preserved as the same objects.
- [ ] AC4 — `org_id`, `organization`, `slug` keep the model's semantics and
  validation (`slug` auto-slugified, required fields enforced by the model).
- [ ] AC5 — Normalization is idempotent and does not mutate the input list or
  dicts.
- [ ] AC6 — A `jsonpickle` encode/decode cycle of a user keeps attribute access
  on organizations.
- [ ] AC7 — Legacy sessions holding dicts are normalized by
  `BaseAuthBackend.get_session_user`, `AuthHandler.get_session_user` and
  `allowed_organizations`; malformed legacy entries make those paths fail
  closed (`None` + warning / 401). The policy is documented in the `AuthUser`
  class docstring and in `normalize_organizations.__doc__`.
- [ ] AC8 — `str`, non-mapping values → `TypeError`; incomplete or unknown-key
  mappings → chained `ValueError`; the list is unchanged after a failure;
  `create_user` surfaces it as `InvalidAuth`. All tested.
- [ ] AC9 (§8 Q2) — An `org_id` or `organization` that is empty or
  whitespace-only is rejected with `ValueError` by the normalization helper,
  for mappings and instances alike; same rule for `Group.group` and
  `Program.program_name`.
- [ ] AC10 (§8 Q3) — `AuthUser.groups` and `TokenUser.programs` receive the
  same treatment: construction, `add_group` / `add_program`, and
  `normalize_memberships()` yield only `Group` / `Program` instances;
  `add_group("name")` keeps working; `tests/unit/test_identities_groups_programs.py`
  passes.
- [ ] No `_ident` subclass needs its own change (parametrized test over all
  seven).
- [ ] All new tests pass:
  `pytest tests/unit/test_identities_organizations.py tests/unit/test_session_user_rehydration.py -v`.
- [ ] Existing suites touching users/sessions still pass:
  `pytest tests/unit/test_user_session_decorator.py tests/test_allowed.py tests/test_basic_auth.py tests/test_basic_open_session.py tests/test_auth_middleware_mechanism.py -v`.
- [ ] `navigator_auth/version.py` bumped to `0.28.7` (repo convention: a
  `bump version` commit precedes a release).

---

## 6. Codebase Contract

> Every entry below was read on `dev` @ `10ecfbe` (2026-10-12).

### Existing symbols (verified)

| Symbol | Location | Signature / shape |
|---|---|---|
| `Organization` | `navigator_auth/identities.py:37-49` | `org_id: str = Column(required=True)`; `organization: str = Column(required=True)`; `slug: str = Column(required=False)`; `__post_init__` calls `super().__post_init__()` then slugifies; `Meta.strict = True, frozen = False`. |
| `Identity` | `identities.py:67-92` | `id: Any`, `auth_method`, `access_token`, `enabled`, `data: InitVar = {}`, `is_authenticated` (note typo `equired=False` at `:78`), `userdata: dict`; `__post_init__(self, data)` at `:81-84` does **not** call `BaseModel.__post_init__`; `Meta.strict = False`. |
| `AuthUser` | `identities.py:95-141` | fields `first_name, last_name, display_name, name, email, username`, `groups: List[Group]` (`:107`), `organizations: List[Organization] = Column(required=False, default_factory=list)` (`:108`), `superuser`; `__post_init__(self, data)` `:115-130`; `add_group(self, group: Group)` `:133-136`; `add_organization(self, org: Organization)` `:138-141` (`str` → `Organization(organization=org)`, else append). |
| `Group` | `identities.py:20-30` | `group: str = Column(required=True)`; same dict pass-through pattern via `add_group` (out of scope). |
| `BasicUser` | `navigator_auth/backends/basic.py:35-39` | `class BasicUser(AuthUser)` — empty body. `_ident: AuthUser = BasicUser` at `:48`. |
| `OauthUser` | `navigator_auth/backends/external.py:69-77` | adds `token, given_name, family_name`; `__post_init__(self, data)` calls `super(OauthUser, self).__post_init__(data)` at `:75`. Also `_ident` of `backends/oauth2/backend.py:268`. |
| `TokenUser` | `backends/token.py:27-29` | `tenant: str`, `programs: list[Program]`. |
| `APIKeyUser` | `backends/api.py:33-35` | `token: str`, `api_key: str`. |
| `AnonymousUser` | `backends/noauth.py:16-17` | `display_name: str = "Anonymous User"`. |
| `DjangoUser` | `backends/django.py:36-43` | `sessionid: str = Column(required=True)`. |
| `PasskeyUser` | `backends/passkey.py:59-60` | empty body; `PasskeyAuth(BasicAuth)`. |
| `BaseAuthBackend._ident` | `backends/abstract.py:75` | `_ident: Identity = Identity` (bare `Identity` has no `organizations` — hence the `isinstance(user, AuthUser)` guard). |
| `BaseAuthBackend.create_user` | `abstract.py:176-181` | `async def create_user(self, userdata) -> Identity`; `usr = self._ident(data=userdata)`; any `Exception` → `raise InvalidAuth(f"Unable to created Session User: {err}") from err`. |
| `BaseAuthBackend.get_user_mapping` / `get_userdata` | `abstract.py:184-205` | builds `userdata` from `USER_MAPPING` (`conf.py:279-285`, overridable via `AUTH_USER_MAPPING` JSON); returns `{AUTH_SESSION_OBJECT: userdata}` when the key is set. |
| `BaseAuthBackend.remember` | `abstract.py:290-312` | `session = await new_session(request, userdata)`; `await session.save_encoded_data(request, "user", user)` at `:304`. |
| `BaseAuthBackend.get_session_user` | `abstract.py:378-387` | `user = session.decode(name)`; sets `is_authenticated = True`; `except (AttributeError, RuntimeError)` → `self.logger.warning(...)` and implicit `None`. |
| `AuthHandler.get_session_user` | `navigator_auth/auth.py:757-765` | same logic; uses module `logging.warning`. `auth.py` has **no** import from `.identities` today (grep). |
| `allowed_organizations` | `navigator_auth/decorators.py:663-740` | `_wrap_function` decode at `:686`, loop `for o in user.organizations: if o.organization in org` `:687-690`, `except (AttributeError, TypeError, RuntimeError): member = False` `:691-692`; `_wrap_method` mirror at `:720-726`. Imports: `get_session` from `navigator_session` (`:8`), `logger` from `navconfig.logging` (`:9`). |
| `InvalidAuth` | `navigator_auth/exceptions.py:42` | `class InvalidAuth(AuthException)`; `AuthException(Exception)` at `:3`. |
| `SessionData.encode` / `decode` | `navigator_session/data.py:308-345` (site-packages, v1.1.0) | `jsonpickle.encode(obj)` / `jsonpickle.decode(self._data[key])`; decode errors → `RuntimeError`, missing key → `None`. |
| `SessionData.save_encoded_data` | `navigator_session/data.py:348-356` | `jsonpickle.encode(obj)` stored under `key`; `storage.save_session(...)`. |
| `ModelHandler` | `navigator_session/data.py:21-36` | registered for `datamodel.BaseModel` (`base=True`); `restore()` does `mdl.__new__(mdl)` + `cls.__dict__ = ...` — **no `__init__`/`__post_init__`** (verified: 0 calls). |
| `SESSION_TIMEOUT` | `navigator_session/conf.py:24` | `config.getint('SESSION_TIMEOUT', fallback=360000)`. |
| `BaseModel.create_field` | `datamodel/base.py:82-102` (v0.10.21) | raises `TypeError` on strict models; otherwise writes into `self.__columns__` and `self.__dataclass_fields__` — class-level dicts shared by all instances. |
| `BaseModel.__post_init__` | `datamodel/models.py` (v0.10.21) | `processing_fields(self, columns)`; raises `ValidationError` only when `Meta.strict is True`, else stores `__errors__`. This is where nested `List[Model]` conversion happens. |
| Test helpers | `tests/unit/test_user_session_decorator.py:10-36` | `FakeRequest` (mapping + attrs) and `FakeSession.decode(key)`; `patch("navigator_auth.decorators.get_session", new_callable=AsyncMock, ...)` at `:40-45`. |
| pytest config | `pyproject.toml:101-116` | `--strict-config --strict-markers`, `filterwarnings = ["error", ...]`, `log_cli = true`. |

### Reproduction evidence (2026-10-12, `dev` @ `10ecfbe`)

```
BasicUser(id=1, data={"user_id": 1}, organizations=[{"org_id": "7", ...}]).organizations[0]
  -> <class 'dict'>  ;  .org_id -> AttributeError: 'dict' object has no attribute 'org_id'
user.add_organization({"org_id": "8", "organization": "Other"})     -> list of ['dict', 'dict']
user.add_organization("acme")                                        -> ValueError :: Missing Required Field *org_id*
Organization(**{"organization": "x"})                                -> ValueError :: Missing Required Field *org_id*
Organization(**{"org_id": 7, "organization": "n"})                   -> Organization(org_id='7', organization='n', slug='n')
Organization(**{"org_id": "1", "organization": "n", "extra": 1})     -> TypeError: unexpected keyword argument 'extra'
Organization(org_id="", organization="x")                            -> accepted (slug='x')
BasicUser(id=1, data={}) / organizations=None / organizations=[]     -> [] in all three cases
Plain datamodel model with List[Organization] (strict True or False) -> dicts ARE converted to Organization
jsonpickle round-trip, dict orgs      -> ['dict'] ; Organization orgs -> ['Organization'] ; __post_init__ calls on decode: 0
Probe subclass calling BaseModel.__post_init__ -> converts, but 2nd instance: AttributeError 'Probe' object has no attribute 'user_id'
```

### Does NOT exist (do not reference)

- No `AuthUser.normalize_organizations`, `AuthUser.normalize`,
  `AuthUser.ensure_organizations`, or `_coerce_organization` — all **new** in
  this spec.
- No `Organization.from_dict` / `Organization.parse` helper; construction is
  `Organization(**mapping)` only.
- No `__post_restore__` hook in `navigator_session.data.ModelHandler`; jsonpickle
  restore cannot be intercepted from navigator-auth.
- No `navigator_auth/identities/` package — `identities.py` is a single module.
  `navigator_auth/identity/` (singular) is the unrelated identity-link
  subsystem (`identity/types.py` defines `TokenResponse`, a plain dataclass).
- No existing tests for `navigator_auth.identities` or `add_organization`
  (only `tests/test_auth_middleware_mechanism.py` imports the module).
- No `CHANGES.md` at the repo root (`docs/changes.rst` includes it, but the
  file is absent); no `docs/` page mentions `AuthUser` or organizations.
- `datamodel.exceptions.ValidationError` is **not** a `ValueError` subclass
  (`ValidationError → ModelException → Exception`); missing required fields
  are raised as a plain `ValueError` by the model. The helper must catch
  `(ValueError, TypeError, ValidationError)`.

---

## 7. Implementation Notes & Constraints

### Patterns to Follow
- Keep `AuthUser.__post_init__` as-is: it already funnels everything through
  `add_organization`, which is the point of the design (one path for
  construction and later adds).
- Use `collections.abc.Mapping`, not `dict`, so `MappingProxyType` / ORM row
  mappings qualify; copy with `dict(org)` before `Organization(**...)`.
- Rebuild in `normalize_organizations` into a temporary list and assign once
  (atomicity on failure — AC8 test `test_failed_add_leaves_list_unchanged`).
- Logging: `self.logger.warning` in `abstract.py`, module `logging.warning` in
  `auth.py` (existing styles); no `print`.
- Google-style docstrings; type hints on every new/changed signature.

### Known Risks / Gotchas
- **Login behaviour change.** Payloads with malformed organizations used to
  log in (with broken dicts) and now raise `InvalidAuth` in `create_user`.
  Mitigation: explicit test, release note in the PR description, and the
  fact that such users were already receiving 401 from
  `allowed_organizations`.
- **Legacy sessions.** Dict payloads written before this release are
  normalized only on navigator-auth's rehydration points; downstream
  `session.decode("user")` readers must call `normalize_organizations()` or
  wait for expiry / re-login. Documented in the class docstring (AC7).
- **`create_field` class mutation** (`datamodel/base.py:95-102`): dynamic
  fields leak across instances of the same class; `to_dict()` can fail for
  instances created with fewer `data` keys. Tests must not rely on
  `to_dict()`; use attribute access.
- **`filterwarnings = error`** in pytest: any `DeprecationWarning` raised by
  `jsonpickle`/`slugify` import paths would fail tests — import them at
  module top so failures are visible immediately.
- **Shared `.venv` + worktrees**: no compiled extensions are involved in the
  touched modules, so a plain `pytest` inside the worktree is reliable.
- `AuthHandler.get_session_user` and `BaseAuthBackend.get_session_user` are
  duplicated code; this spec edits both identically rather than unifying them
  (unification is out of scope).

### External Dependencies
| Package | Version | Reason |
|---|---|---|
| `datamodel` | `0.10.21` (installed) | `Organization` construction/validation — no new usage. |
| `navigator-session` | `>=1.1.0` (`pyproject.toml:52`) | jsonpickle session codec — read-only dependency for tests. |
| `jsonpickle` | `3.0.2` (transitive via navigator-session) | Used directly in tests to emulate the session round-trip without Redis. |
| `python-slugify` | installed | `Organization.__post_init__` slug — unchanged. |

No new dependency is added.

---

## 8. Open Questions

> Decisions marked *Resolved by spec author* were taken because this spec was
> produced unattended with no brainstorm; they are the defaults the
> implementation follows unless the reviewer changes them before `approved`.

- [x] Q1 — What happens to the legacy `add_organization("name")` string
  shortcut? — *Resolved by spec author*: removed; `str` raises `TypeError`.
  It has been dead since `org_id` became required (raises `ValueError` today,
  reproduced), and inventing an `org_id` would silently accept an incomplete
  organization (AC8). *Owner for override: Jesus Lara*.
- [x] Q4 — Normalize stored sessions on read, or require renewal? — *Resolved
  by spec author*: both, split by validity — well-formed legacy dicts are
  normalized at navigator-auth's rehydration points (`get_session_user` ×2,
  `allowed_organizations`); malformed ones invalidate the session user (fail
  closed → re-login). Storage is never migrated. *Owner for override: Jesus
  Lara*.
- [x] Q5 — Unknown keys in a mapping (e.g. extra SQL-view columns): tolerate or
  reject? — *Resolved by spec author*: reject (`ValueError`), consistent with
  `Organization.Meta.strict = True`. Tolerating would need a documented
  allow-list and silently drops data. *Owner for override: Jesus Lara*.
- [x] Q2 — Should empty strings (`org_id=""` / `organization=""`) be rejected
  during normalization? — *Resolved by Jesus Lara, 2026-10-13*: yes, rejected.
  Implemented in the normalization helpers (AC9), not in the model.
- [x] Q3 — Apply the same normalization to `groups` (`add_group`) and
  `TokenUser.programs`? — *Resolved by Jesus Lara, 2026-10-13*: yes, apply —
  folded into this spec as Module 4 / AC10 (not a follow-up).

---

## 9. Design Research Cross-Check

Status: skipped (no accepted exploration document — `/sdd-spec` ran from a
free-form report; `codex` is installed but the FEAT-545 seat only runs over an
accepted brainstorm/proposal).

| # | Suggestion | Disposition | Reason | Landed in |
|---|---|---|---|---|
| — | — | — | — | — |

---

## Worktree Strategy

- **Default isolation unit**: `per-spec` — one worktree
  `.worktrees/feat-FEAT-102-fix-organizations-orgid` (from `origin/dev`),
  tasks sequential: M1 → M2 → M4 (M3's tests are folded into the task that
  owns each module).
- **Parallelizable tasks**: none worth it; M2 depends on M1's method name,
  M3 depends on both. Total change is ~60 lines of library code plus tests.
- **Cross-feature dependencies**: none. No other open spec touches
  `identities.py`, `get_session_user` or `allowed_organizations`.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-10-12 | Jesus Lara | Initial draft from the problem report; reproduction and root cause recorded in §6. |
| 0.2 | 2026-10-13 | Jesus Lara | Status → approved. Q2 (reject empty strings → AC9) and Q3 (groups/programs → Module 4, AC10) resolved and folded into §1/§2/§3/§4/§5. |
