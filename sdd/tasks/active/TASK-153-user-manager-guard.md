# TASK-153: Put `UserManager` behind the guard and remove its password hooks

**Feature**: FEAT-107 — Write-envelope hardening for the remaining auth CRUD handlers
**Spec**: `sdd/specs/auth-model-crud-hardening.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-149, TASK-151
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 2** — the most sensitive handler. Not
delegation-eligible. Today `UserManager(ModelView)` (`handlers/users/user.py:11`)
has no guard, no allowlist and a CRUD password path; driving its write hooks
with a client payload set `is_superuser`, `is_staff`, `user_role`, `email` and a
hashed `password` (spec §1, confirmed by execution).

After this task it is `class UserManager(OwnerOrSuperuserGuard,
GuardedModelViewHooks, ModelHandler)` with the §2 configuration: an owner edits
a profile allowlist, a policy-approved superuser edits a wider allowlist and
creates users, and **no** CRUD path writes `is_superuser` / `user_role` /
`is_staff` / `password`. Privileged flags move to the role endpoint (TASK-156);
passwords stay on `UserSession.password_change` / `password_reset`.

### Spec deviations recorded at /sdd-task time

1. **Action strings** are `user:read|create|update|delete` (not bare verbs —
   `ActionKey` requires `object:verb`; see TASK-150).
2. **Verb semantics on this base.** Verified in navigator-api 3.2.2:
   `PUT` without a PK **inserts** (`model.py:996-1007`); `POST` needs a PK from
   the body or the URL and otherwise answers **400** (`model.py:1157-1170`), so
   `POST /api/v1/users` cannot create a user. Creation is therefore
   **`PUT /api/v1/users`** (AC19 and the integration test
   `test_admin_can_create_user_then_reset_password` say POST — treat that as PUT).
   Updates are `PATCH` (owner and admin) or `POST /api/v1/users/{id}` (admin only:
   TASK-151 makes POST approve create **and** update).
3. **Required lists follow the verbs.** The spec's principle — every required
   column must be writable on the path that uses the verb — is kept, but its two
   lists were attached to the wrong verbs. On this base:
   - `required_by_put()` (PUT = create) → `['first_name', 'last_name', 'username', 'email']` ⊆ `creatable_by_admin`.
   - `required_by_post()` (POST = admin upsert) → `['first_name', 'last_name', 'display_name']` ⊆ `writable_by_admin`.
   - `required_by_patch()` stays upstream's default `[]` (owner edits are partial).
4. **Connection pool changes.** `ModelView.dbname` defaults to `'nav.model'`
   (`navigator/views/abstract.py:169`); `handlers/handler.py` `ModelHandler` sets
   `'authdb'`. Moving the base moves `UserManager` onto the `authdb` pool, like the
   three group handlers already are. Intended; mention it in the Completion Note.

---

## Scope

- Change the base to `(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler)`
  with `ModelHandler` from `navigator_auth/handlers/handler.py`.
- Add the §2 configuration block (with the deviation-1 action names).
- Remove `_set_password` and `_calculate_password`, and the now-unused
  `set_basic_password` / `ModelView` imports (spec AC8).
- Set `required_by_put()` / `required_by_post()` per deviation 3.
- Keep `_set_created_by` and `_set_display_name` unchanged.
- Write `tests/unit/handlers/test_user_manager_write_envelope.py`.

**NOT in scope**:
- The role endpoint (TASK-156) and its route.
- `UserSession` (`handlers/users/session.py`) — unchanged (spec AC9).
- `handlers/__init__.py` — `UserManager.configure(app, '/api/v1/users')` stays as is.
- The end-to-end HTTP suite (TASK-157).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/users/user.py` | MODIFY | Base change, configuration, password hooks removed, required lists |
| `tests/unit/handlers/test_user_manager_write_envelope.py` | CREATE | M2 unit tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `6b8cc84` on 2026-11-11.

### Verified Imports

```python
# navigator_auth/handlers/users/user.py today (verified: user.py:1-8)
from asyncdb.models import Model                          # :1
from navigator.views.model import ModelView, NotSet       # :2  → keep NotSet only
from ...models import User                                # :3
from ...conf import AUTH_USER_MODEL, AUTH_USER_VIEW       # :4-7
from .passwd import set_basic_password                    # :8  → REMOVE

# to add (relative to navigator_auth/handlers/users/)
from typing import Optional
from ..guards import OwnerOrSuperuserGuard                # guards.py:31
from ..guard_hooks import GuardedModelViewHooks           # TASK-151
from ..handler import ModelHandler                        # handler.py:4 — the ModelView-based one
```

### Existing Signatures to Use

```python
# navigator_auth/handlers/users/user.py
class UserManager(ModelView):                                       # :11
    model: Model = User
    get_model: Model = AUTH_USER_VIEW
    name: str = "Users"
    model_name: str = AUTH_USER_MODEL
    pk: str = "user_id"
    def required_by_put(self):                                      # :23
        return ['first_name', 'last_name', 'display_name', 'username', 'email']   # :24
    required_by_post = required_by_put                              # :26
    async def _set_created_by(self, value, column, **kwargs): ...   # :28 (User has no created_by: inert)
    async def _set_display_name(self, value, column, **kwargs): ... # :31
    async def _set_password(self, value, column, **kwargs): ...     # :40  → REMOVE
    async def _calculate_password(self, value, column, *args, **kwargs): ...   # :49 → REMOVE (ends at :58, EOF)

# navigator_auth/models.py:39-70 — User columns
#   user_id(pk, auto) userid(UUID) first_name last_name display_name email alt_email
#   password(secret, repr=False) username(required) user_role is_superuser is_staff
#   title avatar is_active is_new timezone attributes created_at last_login
#   is_new / attributes are in NO allowlist → refused for everyone (G3, intended).

# navigator_auth/handlers/users/session.py — unchanged password paths
async def password_change(self, request): ...   # :119 requires old_password, 403 on userid mismatch
async def password_reset(self, request): ...    # :170 any superuser; sets user.is_new = True (:205)
```

- Pattern to copy: `UserIdentityHandler(OwnerOrSuperuserGuard, ModelHandler)` at
  `userattrs.py:363` (guard first in the MRO).
- After TASK-151: `GuardedModelViewHooks.action_object` must be set (`"user"`),
  else every verb answers 501.

### Does NOT Exist (Anti-Hallucination)

- ~~a password hook anywhere on `UserManager` after this task~~ — `grep -n set_basic_password navigator_auth/handlers/users/user.py` must be empty (AC8).
- ~~`POST /api/v1/users` creating a user~~ — upstream answers 400 without a PK (deviation 2).
- ~~`User.created_by`~~ — commented out (`models.py:66`).
- ~~a `UserType` check in this handler~~ — `user_role` is privileged; only TASK-156 writes it.

---

## Implementation Blueprint

### `navigator_auth/handlers/users/user.py` — MODIFY (block 1: imports)

```python
# REPLACE the two lines `from navigator.views.model import ModelView, NotSet` (verified: user.py:2, occurrences: 1)
# and `from .passwd import set_basic_password` (verified: user.py:8, occurrences: 1) so the import block reads:
from typing import Optional
from asyncdb.models import Model
from navigator.views.model import NotSet
from ...models import User
from ...conf import (
    AUTH_USER_MODEL,
    AUTH_USER_VIEW
)
from ..guards import OwnerOrSuperuserGuard
from ..guard_hooks import GuardedModelViewHooks
from ..handler import ModelHandler
```

### `navigator_auth/handlers/users/user.py` — MODIFY (block 2: class header and configuration)

```python
# REPLACE `class UserManager(ModelView):` (verified: user.py:11, occurrences: 1) and its docstring (:12-15)
class UserManager(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler):
    """User CRUD behind the owner-or-superuser guard (FEAT-107).

    Guard first in the MRO, as ``UserIdentityHandler`` (userattrs.py:363).

    * An owner may PATCH ``writable_by_owner`` on their own row.
    * A policy-approved superuser (``users_admin_access``) may PATCH/POST
      ``writable_by_admin`` and create through PUT with ``creatable_by_admin``.
    * ``privileged_columns`` are writable by NO CRUD path. Flags go through
      ``POST /api/v1/users/{id}/role`` (``users:grant_role``); passwords through
      ``UserSession.password_change`` / ``password_reset``. A user created here
      has no password until a superuser calls ``password_reset``.
    * Reads: a non-superuser sees only their own row.
    """

    model: Model = User
    get_model: Model = AUTH_USER_VIEW
    name: str = "Users"
    model_name: str = AUTH_USER_MODEL
    pk: str = "user_id"

    action_object: str = "user"
    owner_column: Optional[str] = "user_id"
    policy_name: str = "users_admin_access"
    superuser_actions = frozenset({"user:read", "user:create", "user:update", "user:delete"})
    writable_by_owner = frozenset({"first_name", "last_name", "display_name", "title", "avatar", "timezone"})
    writable_by_admin = writable_by_owner | frozenset({"is_active", "email", "alt_email"})
    #: username is set once, at creation, and never updated.
    creatable_by_admin = writable_by_admin | frozenset({"username"})
    privileged_columns = frozenset(
        {"is_superuser", "user_role", "is_staff", "password", "userid", "user_id", "created_at", "last_login"}
    )
```

**Why**: the configuration is the spec §2 block verbatim except the action
strings. Keep the class attributes the original handler had (`model`,
`get_model`, `name`, `model_name`, `pk`) — `get_model` is the read model.

### `navigator_auth/handlers/users/user.py` — MODIFY (block 3: required lists)

```python
# REPLACE the three lines starting at `    def required_by_put(self):` (verified: user.py:23) —
#   `        return ['first_name', 'last_name', 'display_name', 'username', 'email']` (:24, occurrences: 1),
#   blank line, `    required_by_post = required_by_put` (:26, occurrences: 1):
    def required_by_put(self):
        """PUT creates on this base (navigator model.py:996-1007): ⊆ creatable_by_admin."""
        return ['first_name', 'last_name', 'username', 'email']

    def required_by_post(self):
        """POST is an admin upsert (approved for create AND update): ⊆ writable_by_admin."""
        return ['first_name', 'last_name', 'display_name']
```

**Why**: a required column outside the verb's allowlist makes the verb unusable
(the spec's own argument). `display_name` is satisfied server-side by
`_set_display_name` when omitted, because `_is_required` runs on processed data.

### `navigator_auth/handlers/users/user.py` — MODIFY (block 4: remove password hooks)

```python
# DELETE from `    async def _set_password(self, value, column, **kwargs):` (verified: user.py:40, occurrences: 1)
# through the end of the file (the `_calculate_password` method ends at :58, EOF).
# Nothing replaces them.
```

**Why**: a password must not be settable through generic CRUD when
`password_change` (old password + session/URL match) and `password_reset` exist
(spec §1 Non-Goals, R5). Note `_post_data` calls `_set_<column>` for every model
column, so leaving `_set_password` would hash any `password` key a client sent —
the column check refuses that key anyway, but the hook must go (AC8).

### `tests/unit/handlers/test_user_manager_write_envelope.py` — CREATE

```python
"""UserManager behind the guard (FEAT-107, TASK-153) — includes the inverted §1 probe."""

import pytest
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard
from navigator_auth.handlers.handler import ModelHandler
from navigator_auth.handlers.users.user import UserManager

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

ESCALATION_PAYLOAD = {"is_superuser": True, "is_staff": True, "user_role": 10,
                      "email": "attacker@evil.test", "password": "hunter2"}   # spec §4 fixture, verbatim

# FILL IN: request/session/PDP/connection harness — reuse the one written for
#   tests/unit/handlers/test_guard_model_view_hooks.py (TASK-151).


class TestConfiguration:
    def test_usermanager_guard_first_in_mro(self): ...              # guard index < ModelHandler index
    def test_usermanager_has_no_password_hooks(self): ...            # no _set_password / _calculate_password attr
    def test_no_set_basic_password_reference(self): ...              # AC8: source text grep
    def test_usermanager_required_lists_are_writable(self): ...     # deviation 3 subsets
    def test_privileged_never_writable(self): ...                    # privileged ∩ every writable/creatable set == ∅
    def test_config_matches_policy_pack(self): ...                   # policy_name + actions ∈ auth_crud_admin_access.yaml


class TestWrites:
    async def test_usermanager_escalation_payload_refused(self): ...           # owner PATCH own row → 403, row unchanged
    async def test_usermanager_escalation_payload_refused_for_admin(self): ... # superuser + policy → 403
    async def test_owner_can_edit_profile(self): ...                           # AC10
    async def test_admin_can_update_non_privileged_column(self): ...           # AC10
    async def test_username_not_updatable(self): ...                           # admin PATCH username → 403
    async def test_usermanager_create_without_password(self): ...              # AC19 via PUT
    async def test_usermanager_create_refuses_privileged_and_password(self): ...  # 403, not silently dropped


class TestReads:
    async def test_non_superuser_list_bound_to_own_row(self): ...
    async def test_foreign_user_id_param_refused(self): ...
```

### Steps (in order)

1. Apply blocks 1–4 — because block 2 needs block 1's imports and block 4 makes
   the `set_basic_password` import dead.
2. Confirm the MRO: `UserManager.__mro__` lists `OwnerOrSuperuserGuard`,
   `GuardedModelViewHooks`, then `ModelHandler`, `ModelView` — because the
   hooks must override `ModelView`'s and the guard must come first (spec §7).
3. Write the tests. `test_config_matches_policy_pack` parses
   `navigator_auth/abac/default_policies/auth_crud_admin_access.yaml` with
   `YAMLStorage._parse_file` and checks `users_admin_access`'s actions equal
   `UserManager.superuser_actions` — because a rename on either side kills the
   admin path silently.
4. Run `pytest tests/unit/handlers/test_user_manager_write_envelope.py -v`, then
   `pytest tests/unit/handlers/ -v` and
   `grep -n set_basic_password navigator_auth/handlers/users/user.py` (expect no output).

### FILL IN checklist

- [ ] Test harness (from TASK-151's test module).
- [ ] All test bodies; each refusal test also asserts no `update()`/`insert()` was awaited.
- [ ] Completion Note mentions the `nav.model` → `authdb` pool change.

---

## Acceptance Criteria

- [ ] `pytest tests/unit/handlers/test_user_manager_write_envelope.py -v` passes.
- [ ] `pytest tests/unit/handlers/ tests/test_check_superuser.py tests/test_allowed.py tests/test_policy_allows.py -v` passes (AC2).
- [ ] The §1 payload is refused for the owner and for an approved superuser; the row is unmodified (spec AC3).
- [ ] `is_superuser`, `user_role`, `is_staff`, `password` are writable by no CRUD verb (spec AC4).
- [ ] `grep -rn "set_basic_password" navigator_auth/handlers/users/user.py` is empty and neither password hook exists (spec AC8).
- [ ] An approved superuser can create a user through `PUT /api/v1/users` with no password and default privileged flags (spec AC19, deviation 2).
- [ ] An owner can PATCH their profile allowlist; an approved superuser can PATCH `email` / `is_active` of another user (spec AC10).

---

## Test Specification

See the CREATE block above.

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at `sdd/specs/auth-model-crud-hardening.spec.md` (§1, §2 Data Models, §3 Module 2, §7 R1, R5).
2. **Check dependencies** — TASK-149 and TASK-151 are `done` in `sdd/tasks/index/auth-model-crud-hardening.json`.
3. **Re-verify** the `user.py` anchors (`grep -c`) — stop and report if any count is not 1.
4. **Update status** → `"in-progress"`.
5. **Implement** the blueprint and complete every `FILL IN`.
6. **Verify** the acceptance criteria (`source .venv/bin/activate` first).
7. **Move this file** to `sdd/tasks/completed/` and set the index entry to `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: create via PUT; required lists follow the verbs; `object:verb` actions | other
