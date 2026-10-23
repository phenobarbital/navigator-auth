# TASK-118: Generic allowlist redaction module (`handlers/redaction.py`)

**Feature**: FEAT-105 — Owner-or-Superuser ABAC Ownership for the Auth Model CRUD Surfaces
**Spec**: `sdd/specs/user-identities-ownership-abac.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 1**. This is the bottom layer of the four-layer
design (spec §2 Overview layer 3, goal **G3**): every response from the three
hardened surfaces is projected through an **explicit allowlist** of public
columns, so credential material can never be serialized — not through
`?fields=`, not through `?_filter=`, not through `:meta`, for any role.

It must be a standalone, pure, synchronous module because three handlers on
**two different base classes** share it (`UserIdentityHandler` and
`UserAccountHandler` on `navigator.views.ModelView`; `PartnerKeyHandler` on
the local `handlers/model.py` `ModelHandler`). Keeping it free of HTTP and DB
plumbing is what makes it testable without a request, and is why it lands
first and alone.

**Why an allowlist and not the upstream `_hidden` mechanism.** The installed
`navigator-api` derives `_hidden` from `secret=True` columns only. Neither
`UserIdentity.access_token` (`models.py:104`) nor `PartnerKey.token`
(`handlers/partners.py:25`) declares `secret=True`, so upstream hides nothing
on these models on **any** navigator version. The allowlist is the only thing
that redacts these surfaces — see the "Environment drift" note below.

> **Environment drift (read this).** The spec's §6 "Exists — upstream
> `navigator`" table was recorded against `navigator-api` **3.2.2** and
> instructs "implement against the installed behaviour". The version actually
> installed in `.venv` today is **4.0.1**, which already contains the §2
> Prerequisite fix (`_hidden` from `secret=True`, `_hidden` as an exclusion
> list, per-instance metadata lists, parameterized `_filtering`). The spec's
> *design* is unaffected — it was written to not depend on upstream — but the
> spec's upstream line numbers are stale. Every upstream anchor quoted in
> these tasks was re-verified against 4.0.1. This task touches no upstream
> code at all.

---

## Scope

- Create `navigator_auth/handlers/redaction.py` with exactly four public
  functions: `safe_fields`, `redact_row`, `redact_rows`, `redact_schema`.
- Create the `tests/unit/handlers/` test package and
  `tests/unit/handlers/test_model_redaction.py`.

**NOT in scope**:
- Any handler change. `userattrs.py`, `partners.py`, `model.py` and
  `handler.py` must be untouched — wiring happens in TASK-121..TASK-126.
- The guard mixin (`handlers/guards.py`) — TASK-122.
- `policy_allows()` in `decorators.py` — TASK-119.
- The identity-specific `masked()`-shape projection (`has_refresh_token`,
  `has_id_token`, `expired`, `auth_data` → `profile`). That mapping is
  surface-specific and belongs to `UserIdentityHandler` in TASK-124. This
  module stays **model-agnostic**: it only ever drops columns, it never
  renames or derives one.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/redaction.py` | CREATE | The four projection primitives |
| `tests/unit/handlers/__init__.py` | CREATE | New test package (empty file) |
| `tests/unit/handlers/test_model_redaction.py` | CREATE | Unit tests |

---

## Codebase Contract

> Every fact below was re-verified on `dev` @ `62fd419` (2026-10-23).

### Verified imports — the only ones this module may use

```python
from typing import Any, Optional, Union     # stdlib
from datamodel import BaseModel             # verified: navigator_auth/handlers/model.py:7
```

`datamodel.BaseModel` is already imported this way by
`navigator_auth/handlers/model.py:7`, so the dependency is established.

### Row shapes this module must accept

Rows arrive in three shapes, all of which occur in the real handlers:

| Shape | Where it comes from | Read a column with |
|---|---|---|
| `datamodel` / `asyncdb` Model instance | `Model.get()` / `Model.filter()` (`handlers/model.py:199,216`) | `getattr(row, name, None)` |
| `dict` | `conn.query()` / `conn.fetch_all()` rows, and `PartnerKey.insert()` results | `row.get(name)` |
| `None` | an empty `get()` result | returns `{}` |

The upstream helper that does exactly this is
`ModelView._row_value` (verified: `.venv/lib/python3.11/site-packages/navigator/views/model.py:184-189`):

```python
    @staticmethod
    def _row_value(row: Any, column: str, default: Any = None) -> Any:
        """Read one column from a row (``dict``, ``BaseModel`` or object)."""
        if isinstance(row, dict):
            return row.get(column, default)
        return getattr(row, column, default)
```

Do **not** import it (it is a method on a View, and `PartnerKeyHandler` does
not inherit from `ModelView`). Reimplement the same two-branch read locally.

### `Model.schema(as_dict=True)` — the `:meta` payload shape

Verified by executing it against `UserIdentity`:

```python
# top-level keys
['$schema', '$id', 'settings', 'additionalProperties', 'title', 'description',
 'type', 'table', 'schema', 'properties', 'required', 'display_name', '$defs']

# schema["properties"] is a dict keyed by column name
['identity_id', 'display_name', 'title', ..., 'access_token',
 'refresh_token', 'id_token', 'token_type', ..., 'key_version', 'created_at']

# schema["required"] is a list of column names
['identity_id', 'user_id']
```

### CRITICAL — `schema(as_dict=True)` returns a CACHED, SHARED dict

Verified by executing:

```python
a = UserIdentity.schema(as_dict=True)
b = UserIdentity.schema(as_dict=True)
a is b                          # True
a['properties'] is b['properties']   # True
hasattr(UserIdentity, '__computed_schema__')   # True
```

`redact_schema()` therefore **must not mutate its argument**. Mutating it
would permanently strip columns from the model's process-wide cached schema,
corrupting every other consumer — upstream `head()`'s `X-Columns` header
(`.venv/.../navigator/views/abstract.py:450-467`), the local `head()`
(`navigator_auth/handlers/model.py:131-141`) and any validation that reads
the schema. This has a dedicated test (AC-8).

### The column sets this module is driven by (spec §2 Data Models)

Declared on the handlers, not here — this module takes them as arguments:

| Handler | `credential_columns` | `public_columns` |
|---|---|---|
| `UserIdentityHandler` | `access_token`, `refresh_token`, `id_token`, `key_version` | `identity_id`, `user_id`, `display_name`, `title`, `nickname`, `email`, `phone`, `short_bio`, `avatar`, `auth_provider`, `provider_user_id`, `scopes`, `token_type`, `expires_at`, `refreshed_at`, `created_at`, `enabled`, `auth_data`, `attributes` |
| `UserAccountHandler` | *(none)* | `account_id`, `user_id`, `provider`, `uid`, `address`, `account`, `created_at` |
| `PartnerKeyHandler` | `token` | `partner_id`, `name`, `partner`, `issuer`, `created_at`, `revoked`, `enabled`, `grants`, `programs` |

Every one of those column names was verified to exist on its model:
`UserIdentity` (`navigator_auth/models.py:77-110`), `UserAccount`
(`navigator_auth/models.py:297-308`), `PartnerKey`
(`navigator_auth/handlers/partners.py:15-30`).

### Does NOT Exist (do not reference)

- `navigator_auth/handlers/redaction.py` — **this task creates it**. There is
  no redaction module anywhere in `navigator_auth/` today.
- `navigator_auth/identity/redaction.py` — spec rev 0.1 proposed this path;
  rev 0.2 moved it to `handlers/redaction.py` because three surfaces share
  it. **Do not create both.**
- `tests/unit/handlers/` — a new package. `tests/unit/identity/__init__.py`
  and `tests/unit/middlewares/__init__.py` are the existing pattern (both
  are plain empty-ish files).
- `navigator_auth/handlers/guards.py` — TASK-122 creates it. Do not import
  from it, and do not put any of these functions there.
- `navigator_auth.libs.redaction`, `navigator_auth.libs.projection` — no such
  module. `navigator_auth/libs/` holds compiled Cython (`cipher`, `json`,
  `parser`, `policy_eval`) plus `sanitize.py`; do not add to it.
- A `datamodel` or `asyncdb` helper that already does allowlist projection —
  there is none. `BaseModel.to_dict()` is an **instance** method with no
  allowlist parameter, and `Model.get_columns()` is a classmethod returning
  every column. Neither solves this.
- `ModelView._project_row` / `_visible_columns` / `_row_value` — these exist
  upstream (`.venv/.../navigator/views/model.py:203-234`) but are **View
  methods** driven by `_hidden`, which is empty on these models. Do not
  import, subclass or call them.

---

## Implementation Blueprint

### `navigator_auth/handlers/redaction.py` — CREATE

```python
"""Allowlist-driven redaction for the auth model CRUD surfaces (FEAT-105).

Pure, synchronous projection primitives shared by ``UserIdentityHandler``,
``UserAccountHandler`` and ``PartnerKeyHandler``. They sit on two different
handler base classes, so nothing here may touch ``self``, a request, or a
database connection.

The contract is one-directional: a column is serialized only when it is
named in ``public_columns``. Nothing in this module can ever *add* a column
to a response, which is what makes "a credential cannot be reached through
any parameter combination" (spec G3) a property of construction rather than
of review.
"""
from typing import Any, Optional, Union

from datamodel import BaseModel


def _row_value(row: Any, column: str, default: Any = None) -> Any:
    """Read one column from a row, whichever shape it has.

    Args:
        row: A ``dict``, a ``datamodel`` model instance, or any object.
        column: Column name to read.
        default: Returned when the column is absent.

    Returns:
        The column value, or ``default``.
    """
    if isinstance(row, dict):
        return row.get(column, default)
    return getattr(row, column, default)


def safe_fields(
    fields: Optional[list[str]],
    public_columns: frozenset[str],
) -> Optional[list[str]]:
    """Intersect a caller projection with the allowlist (never a union).

    Args:
        fields: The columns the caller asked for (``?fields=``), or ``None``
            when no projection was requested.
        public_columns: The handler's allowlist.

    Returns:
        ``None`` when ``fields`` is ``None`` — meaning "no projection was
        asked for", which callers must read as "serialize the whole
        allowlist". Otherwise the members of ``fields`` that are in
        ``public_columns``, in the caller's order, which may be an empty
        list when the caller asked **only** for forbidden columns.
    """
    # FILL IN: return None for fields is None; otherwise the order-preserving
    # intersection with public_columns, de-duplicated — bounded by AC-1/AC-2.


def redact_row(
    row: Union[BaseModel, dict, None],
    public_columns: frozenset[str],
    fields: Optional[list[str]] = None,
) -> dict:
    """Project one row onto ``public_columns`` (intersected with ``fields``).

    Args:
        row: The row to project, in any of the three accepted shapes.
        public_columns: The handler's allowlist.
        fields: Optional caller projection, already safe to pass raw — it is
            run through :func:`safe_fields` here.

    Returns:
        A plain ``dict`` holding only allowed columns. ``{}`` when ``row`` is
        ``None`` or nothing is allowed.
    """
    # FILL IN: resolve the effective column list via safe_fields (None ->
    # sorted(public_columns) for a stable key order), then build the dict with
    # _row_value. Never raise on a column the row lacks — bounded by AC-3/AC-4.


def redact_rows(
    rows: Any,
    public_columns: frozenset[str],
    fields: Optional[list[str]] = None,
) -> Any:
    """Vectorized :func:`redact_row`, preserving list-vs-scalar shape.

    Args:
        rows: A single row, a list of rows, or ``None``.
        public_columns: The handler's allowlist.
        fields: Optional caller projection.

    Returns:
        A ``list[dict]`` for a list input, a ``dict`` for a scalar input, and
        ``None`` for ``None`` — the shape the caller passed in.
    """
    # FILL IN: None -> None; list/tuple -> [redact_row(r, ...) for r in rows];
    # anything else -> redact_row(rows, ...) — bounded by AC-5.


def redact_schema(
    schema: dict,
    credential_columns: frozenset[str],
) -> dict:
    """Strip credential columns from a ``Model.schema(as_dict=True)`` payload.

    Used by the ``:meta`` path so the JSON-schema response cannot enumerate
    the columns the rest of this module refuses to serialize.

    Args:
        schema: The payload returned by ``Model.schema(as_dict=True)``.
        credential_columns: Columns to remove from ``properties`` and
            ``required``.

    Returns:
        A **new** dict. The argument is never mutated.
    """
    # FILL IN: shallow-copy the top level, then replace "properties" with a
    # new dict minus credential_columns and "required" with a new list minus
    # credential_columns. Tolerate either key being absent or not a
    # dict/list — bounded by AC-6/AC-7/AC-8.
```

**Why `safe_fields` must distinguish `None` from `[]`.** They mean opposite
things. `None` is "the caller named no columns", which must serialize the
whole allowlist. `[]` is "the caller named columns and every one of them was
forbidden", which must serialize nothing. Collapsing the two — e.g. with
`if not fields:` — turns `?fields=access_token` into a request for the full
row, which is the precise bypass this module exists to prevent (AC-2).

**Why intersect rather than subtract.** Subtracting `credential_columns` from
whatever the caller asked for is a denylist: it is correct only while the
denylist is complete, and it silently starts leaking the day a column is
added to the model. Intersecting with `public_columns` fails the other way —
a new column is invisible until someone adds it to the allowlist — which is
the direction a security boundary must fail in (spec G3).

**Why the allowlist is sorted when no `fields` is given.** `frozenset`
iteration order varies between processes (string hash randomization), so an
unsorted projection would produce a different key order on every run,
making response snapshots and `test_identity_projection_matches_masked`
(TASK-124) flaky. Sort once, here.

**Why `redact_schema` copies instead of popping.** `Model.schema(as_dict=True)`
returns the **same cached dict object** on every call (verified above, it is
memoized as `__computed_schema__`). `schema["properties"].pop("access_token")`
would therefore delete that column from the model's schema for the lifetime
of the process, for every caller — including upstream `head()`, which builds
its `X-Columns` header from the same payload. Copy the two containers you
change and leave the original alone.

**Why `_row_value` is private and duplicated.** Upstream has an identical
helper, but it is a `staticmethod` on `ModelView`, and `PartnerKeyHandler`
does not inherit from `ModelView` (`navigator_auth/handlers/partners.py:13`
imports the local base). Importing a View to read a dict key would couple
this module to the very class the feature is defending against.

### `tests/unit/handlers/__init__.py` — CREATE

```python
# empty — marks tests/unit/handlers as a package, like
# tests/unit/identity/__init__.py and tests/unit/middlewares/__init__.py
```

**Why this may already exist.** TASK-120 (policy pack) is marked
`parallel: true` alongside this task and also writes into
`tests/unit/handlers/`. Both tasks create this file with identical (empty)
content, so a concurrent create is harmless. Create it if absent; do not
fail and do not "fix" it if it is already there.

### `tests/unit/handlers/test_model_redaction.py` — CREATE

```python
"""Unit tests for the allowlist redaction primitives (FEAT-105, TASK-118)."""
import pytest

from navigator_auth.handlers.redaction import (
    redact_row,
    redact_rows,
    redact_schema,
    safe_fields,
)

IDENTITY_PUBLIC = frozenset({
    "identity_id", "user_id", "display_name", "title", "nickname", "email",
    "phone", "short_bio", "avatar", "auth_provider", "provider_user_id",
    "scopes", "token_type", "expires_at", "refreshed_at", "created_at",
    "enabled", "auth_data", "attributes",
})
IDENTITY_CREDENTIALS = frozenset({
    "access_token", "refresh_token", "id_token", "key_version",
})


class TestSafeFields:
    def test_none_stays_none(self):
        """No projection asked for is NOT the same as an empty projection."""
        # FILL IN: safe_fields(None, IDENTITY_PUBLIC) is None — bounded by AC-1.

    def test_intersects_never_unions(self):
        """Spec §4: ["access_token","email"] -> ["email"]; ["access_token"] -> []."""
        # FILL IN: both cases, and assert the result is [] (not None) for the
        # all-forbidden case — bounded by AC-2.

    def test_preserves_caller_order(self):
        """The caller's column order survives the intersection."""
        # FILL IN: ["email","phone"] and ["phone","email"] differ — AC-1.


class TestRedactRow:
    def test_drops_everything_outside_allowlist(self):
        """Columns absent from public_columns never appear — model row."""
        # FILL IN: build a row double carrying every credential column with a
        # non-None value; assert no credential key is in the result and that
        # an allowed key is — bounded by AC-3.

    def test_drops_everything_outside_allowlist_dict(self):
        """Same property for a dict row (the conn.query() shape)."""
        # FILL IN: same assertions with a plain dict row — bounded by AC-3.

    def test_fields_cannot_project_a_credential(self):
        """fields=["access_token","email"] yields email only."""
        # FILL IN: bounded by AC-4.

    def test_none_row_is_empty_dict(self):
        """A missing row projects to {} rather than raising."""
        # FILL IN: redact_row(None, IDENTITY_PUBLIC) == {} — AC-3.

    def test_absent_column_does_not_raise(self):
        """An allowlisted column the row lacks comes back as None."""
        # FILL IN: dict row with only {"email": ...}; result has every
        # allowlisted key, extras None — bounded by AC-3.

    def test_key_order_is_stable(self):
        """Two calls in one process agree on key order."""
        # FILL IN: list(a) == list(b) for two redact_row calls — AC-9.


class TestRedactRows:
    def test_preserves_list_vs_scalar_shape(self):
        """list -> list, scalar -> dict, None -> None."""
        # FILL IN: all three shapes — bounded by AC-5.


class TestRedactSchema:
    def test_strips_credential_columns(self):
        """:meta payload loses every credential_columns member."""
        # FILL IN: use the real UserIdentity.schema(as_dict=True); assert no
        # credential column is in result["properties"] — bounded by AC-6.

    def test_strips_credentials_from_required(self):
        """A credential column named in "required" is removed too."""
        # FILL IN: synthetic schema whose "required" lists a credential
        # column — bounded by AC-7.

    def test_does_not_mutate_the_cached_schema(self):
        """The model's memoized schema survives a redaction."""
        # FILL IN: from navigator_auth.models import UserIdentity;
        # call redact_schema(UserIdentity.schema(as_dict=True), CREDS), then
        # assert "access_token" is STILL in
        # UserIdentity.schema(as_dict=True)["properties"] — bounded by AC-8.

    def test_tolerates_a_schema_without_the_keys(self):
        """{} and a schema with no "required" do not raise."""
        # FILL IN: redact_schema({}, CREDS) and a properties-only dict — AC-6.
```

**Why `test_does_not_mutate_the_cached_schema` is the important one here.**
Every other test checks a property of the returned value. This one checks
the property that breaks other code: `Model.schema(as_dict=True)` is
memoized and shared, so an in-place `pop` passes all the other tests while
silently corrupting `head()`'s `X-Columns` and any schema consumer for the
rest of the process. Keep it, and keep it reading the real model.

**Why the tests use the real `UserIdentity` schema rather than a fixture.**
The column *names* are the thing under test. A hand-written fixture would
keep passing if `models.py` renamed `access_token`; reading the live schema
makes the test fail, which is the signal you want.

### Steps (in order)

1. Create `navigator_auth/handlers/redaction.py` with the module docstring,
   the two imports and the five functions exactly as blueprinted.
2. Fill `safe_fields` first — every other function depends on its
   `None` vs `[]` contract, so get that right before moving on.
3. Fill `redact_row`, then `redact_rows` (which is a thin wrapper over it),
   then `redact_schema`.
4. Create `tests/unit/handlers/__init__.py` **if it does not already exist**
   (a parallel task may have created it; that is fine).
5. Create the test module and fill all thirteen bodies.
6. Run `pytest tests/unit/handlers/test_model_redaction.py -v`, then
   `ruff check navigator_auth/handlers/redaction.py tests/unit/handlers/`.
7. Confirm the blast radius: `git diff --name-only` must list exactly the
   three files in the table above and nothing else. In particular no file
   under `navigator_auth/handlers/` other than the new `redaction.py`.

### FILL IN checklist

- [ ] `safe_fields` body — `None` -> `None`, else ordered intersection — AC-1, AC-2
- [ ] `redact_row` body — allowlist ∩ fields, stable order, tolerant reads — AC-3, AC-4, AC-9
- [ ] `redact_rows` body — shape preservation — AC-5
- [ ] `redact_schema` body — copy, strip `properties` and `required` — AC-6, AC-7, AC-8
- [ ] `test_none_stays_none` — AC-1
- [ ] `test_intersects_never_unions` — AC-2
- [ ] `test_preserves_caller_order` — AC-1
- [ ] `test_drops_everything_outside_allowlist` (+ `_dict` variant) — AC-3
- [ ] `test_fields_cannot_project_a_credential` — AC-4
- [ ] `test_none_row_is_empty_dict`, `test_absent_column_does_not_raise` — AC-3
- [ ] `test_key_order_is_stable` — AC-9
- [ ] `test_preserves_list_vs_scalar_shape` — AC-5
- [ ] `test_strips_credential_columns`, `test_strips_credentials_from_required` — AC-6, AC-7
- [ ] `test_does_not_mutate_the_cached_schema` — AC-8
- [ ] `test_tolerates_a_schema_without_the_keys` — AC-6

---

## Acceptance Criteria

- [ ] **AC-1** `safe_fields(None, PUBLIC) is None`; a non-`None` `fields` returns the intersection in the caller's order.
- [ ] **AC-2** `safe_fields(["access_token", "email"], IDENTITY_PUBLIC) == ["email"]` and `safe_fields(["access_token"], IDENTITY_PUBLIC) == []` — an empty list, never `None`.
- [ ] **AC-3** `redact_row` returns only allowlisted keys for a model row, for a `dict` row and for `None` (`{}`), and never raises on a column the row lacks.
- [ ] **AC-4** `redact_row(row, PUBLIC, fields=["access_token", "email"])` contains `email` and no credential key.
- [ ] **AC-5** `redact_rows` returns a `list` for a list, a `dict` for a scalar and `None` for `None`.
- [ ] **AC-6** `redact_schema(UserIdentity.schema(as_dict=True), IDENTITY_CREDENTIALS)["properties"]` contains none of `access_token`, `refresh_token`, `id_token`, `key_version`; `redact_schema({}, …)` does not raise.
- [ ] **AC-7** A credential column named in `schema["required"]` is absent from the returned `required`.
- [ ] **AC-8** After `redact_schema`, `UserIdentity.schema(as_dict=True)["properties"]` still contains `access_token` — the cached schema is not mutated.
- [ ] **AC-9** Two `redact_row` calls with the same arguments produce the same key order.
- [ ] **AC-10** `pytest tests/unit/handlers/test_model_redaction.py -v` passes and `ruff check navigator_auth/handlers/redaction.py tests/unit/handlers/` is clean.
- [ ] **AC-11** No file outside the three in "Files to Create / Modify" is modified; in particular `userattrs.py`, `partners.py`, `model.py`, `handler.py` and `decorators.py` are untouched.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/unit/handlers/test_model_redaction.py -v
ruff check navigator_auth/handlers/redaction.py tests/unit/handlers/
```

```python
from navigator_auth.handlers.redaction import (
    redact_row, redact_rows, redact_schema, safe_fields,
)
```

---

## Agent Instructions

1. **Read the spec** at `sdd/specs/user-identities-ownership-abac.spec.md` —
   §2 Overview layer 3, §2 Data Models, §3 Module 1, §4 the four Module-1
   test rows.
2. **Check dependencies** — none.
3. **Update status** in `sdd/tasks/index/user-identities-ownership-abac.json`
   → `"in-progress"`.
4. **Implement** per the blueprint. Do not widen scope to the handlers.
5. **Verify** every acceptance criterion, AC-8 and AC-11 included.
6. **Move this file** to `sdd/tasks/completed/TASK-118-generic-redaction-allowlist.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
