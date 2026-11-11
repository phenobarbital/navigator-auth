# TASK-154: Guard the group handlers and wire the protected-group checks

**Feature**: FEAT-107 — Write-envelope hardening for the remaining auth CRUD handlers
**Spec**: `sdd/specs/auth-model-crud-hardening.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-149, TASK-151, TASK-152
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 3** (`UserGroupManager`, `GroupPermissionManager`),
the `GroupManager` half of **Module 4**, and the **Module 9 call sites**. All
three classes live in `navigator_auth/handlers/groups.py` and sit on the
`handlers/handler.py` base (`ModelHandler(ModelView)`), so they reuse
`GuardedModelViewHooks` from TASK-151. The M9 parts are not delegation-eligible.

Two independent escalation routes run through these tables, which ABAC itself
reads: joining a group (including `superuser`, which `_check_superuser` treats
as `is_superuser`) and granting a permission to a group. Plus the group-name
route: renaming an ordinary group into `security_admin` / `superuser`.

**`owner_column = None` on both mapping handlers is the point, not an
oversight (spec R4).** `UserGroup`'s primary key is `(user_id, group_id)`
(`models.py:209-211`): the row's "owner" is the user it grants the group to. With
`owner_column = "user_id"` the guard's owner fast-path would return `True` for a
row a user writes for themselves into `superuser`. `None` makes the superuser
path the only path (`guards.py:39-41`). `test_usergroup_owner_column_is_none`
guards against a well-meant future "fix".

### Spec deviations recorded at /sdd-task time

1. **Action strings** are `group:*`, `user_group:*`, `group_permission:*` (see TASK-150).
2. **`UserGroupManager` is mounted twice**: `/api/v1/user_groups` and
   `/api/v1/usergroups` (`handlers/__init__.py:33,35`). Same class, same guard;
   TASK-150's pack covers both. Test both paths.
3. **Reads are gated** (user decision 2026-11-11): all three are ownerless, so
   GET/HEAD is superuser + policy only. A user can no longer list groups or their
   memberships through these routes; their session already carries their groups.
4. **Verb semantics** (TASK-151): PUT creates, POST is an upsert approved for
   create *and* update, PATCH updates. On the mapping handlers `update ∉
   superuser_actions`, so POST and PATCH are refused outright; membership rows
   are created with PUT and removed with DELETE.

---

## Scope

- Rebase the three classes onto `(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler)`
  with the spec §2 configuration (deviation-1 action names).
- `GroupManager`: protected-name checks on create (new name), update (stored
  **and** new name — covers rename into/out of, deactivation, any edit) and
  delete (stored name).
- `UserGroupManager`: protected check on create (group name **resolved from the
  database** for each row's `group_id`, `member_id=row.user_id`) and on delete
  (resolved name, `member_id=None`).
- A module helper that resolves a `group_id` to its stored `group_name`.
- Write `tests/unit/handlers/test_group_handlers_access.py`.

**NOT in scope**:
- `PermissionHandler` (TASK-155, other base, other file).
- The guard-side protected-group logic itself (TASK-152).
- Route registration — `handlers/__init__.py` is unchanged.
- Any protected-group check on `GroupPermissionManager` (spec §8: nothing
  authorizes by permission name).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/groups.py` | MODIFY | Three guarded classes, group-name resolver, M9 call sites |
| `tests/unit/handlers/test_group_handlers_access.py` | CREATE | M3 / M4 (groups) / M9 handler-level tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `6b8cc84` on 2026-11-11.

### Verified Imports

```python
# navigator_auth/handlers/groups.py today (verified: groups.py:1-11)
from datamodel import BaseModel
from ..models import Group, UserGroup, GroupPermission
from ..conf import AUTH_GROUP_MODEL, AUTH_USER_GROUP_MODEL
from .handler import ModelHandler                            # :11 — the ModelView-based base

# to add
from typing import Any, Iterable, Optional
from asyncdb.exceptions import NoDataFound                   # used at userattrs.py:4
from datamodel.exceptions import ValidationError             # used at userattrs.py:6
from .guards import OwnerOrSuperuserGuard                    # guards.py:31
from .guard_hooks import GuardedModelViewHooks               # TASK-151
```

### Existing Signatures to Use

```python
# navigator_auth/handlers/groups.py
class GroupManager(ModelHandler):                 # :14
    model: BaseModel = Group; model_name: str = AUTH_GROUP_MODEL; name: str = "Group"; pk: str = "group_id"
class UserGroupManager(ModelHandler):             # :21
    model: BaseModel = UserGroup; model_name: str = AUTH_USER_GROUP_MODEL; name: str = "User Group"
    pk: list = ["user_id", "group_id"]
class GroupPermissionManager(ModelHandler):       # :28
    model: BaseModel = GroupPermission; name: str = "Group Permissions"; pk: list = ["permission_id", "group_id"]

# navigator_auth/models.py
class Group(Model):          # :188  group_id(pk, auto) group_name(required) is_active client_id description
                             #       created_at updated_at created_by
class UserGroup(Model):      # :209  user_id(pk) group_id(pk) created_at created_by
class GroupPermission(Model):# :243  group_id(pk) permission_id(pk) created_at updated_at

# After TASK-152 — navigator_auth/handlers/guards.py
async def authorize_protected_group(self, group_names: Iterable[str], *, member_id: Optional[int] = None) -> None
def protected_groups() -> frozenset[str]

# After TASK-151 — navigator_auth/handlers/guard_hooks.py (GuardedModelViewHooks)
async def _pre_put(self, *a, **kw) -> bool          # raw keys + query columns, create check
async def _pre_post(self, *a, **kw) -> bool         # create AND update check
async def _set_update(self, model, data) -> None     # update check, then ModelView._set_update (mutates in memory)
async def _del_primary_data(self, args: dict)        # returns objid (dict for a list pk), delete check
self._guard_write_keys: frozenset[str]               # raw client keys of this request

# upstream: json_data() is cached (navigator/views/base.py:340) — a second read returns the same body.
# upstream persists AFTER _set_update returns: obj.update() (model.py:819-831, 987) or
#   self.model.updating(...) (model.py:1203) — a raise inside _set_update prevents the write.
```

- `handler.py` `ModelHandler._set_created_by` fills `created_by` server-side
  (`handler.py:9-10`) — never part of the client keys.
- Connection idiom for a lookup inside a hook: `userattrs.py:263-270`
  (`async with await self.handler(request=self.request) as conn:` then
  `Model.Meta.connection = conn` and `await Model.get(**pk)`, catching
  `(NoDataFound, ValidationError)`).

### Does NOT Exist (Anti-Hallucination)

- ~~a group-name lookup helper~~ — written here.
- ~~a group name in the `UserGroup` payload~~ — the payload has only `user_id` / `group_id`; never trust a `group_name` sent with it.
- ~~`update` on a mapping table~~ — not in `superuser_actions`, so refused.
- ~~an owner column on `GroupPermission`~~ — none exists.

---

## Implementation Blueprint

### `navigator_auth/handlers/groups.py` — MODIFY (block 1: imports and resolver)

```python
# REPLACE the import block — anchor `from .handler import ModelHandler` (verified: groups.py:11, occurrences: 1)
from typing import Any, Iterable, Optional
from asyncdb.exceptions import NoDataFound
from datamodel import BaseModel
from datamodel.exceptions import ValidationError
from ..models import (
    Group,
    UserGroup,
    GroupPermission
)
from ..conf import (
    AUTH_GROUP_MODEL,
    AUTH_USER_GROUP_MODEL
)
from .guards import OwnerOrSuperuserGuard
from .guard_hooks import GuardedModelViewHooks
from .handler import ModelHandler


async def _stored_group_name(view: Any, group_id: Any) -> Optional[str]:
    """Return the STORED ``group_name`` for ``group_id``, or ``None``.

    Protected-group checks key on the name in the database, never on a name
    the client sent (spec M9, ``test_protected_group_resolved_from_db_not_payload``).
    """
    if group_id is None:
        return None
    # FILL IN: open `async with await view.handler(request=view.request) as conn`, set
    #   Group.Meta.connection = conn, `row = await Group.get(group_id=group_id)`; catch
    #   (NoDataFound, ValidationError) → None; return getattr(row, "group_name", None).
    raise NotImplementedError
```

### `navigator_auth/handlers/groups.py` — MODIFY (block 2: `GroupManager`)

```python
# REPLACE `class GroupManager(ModelHandler):` and its 4-line body (verified: groups.py:14-18, occurrences: 1)
class GroupManager(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler):
    """Group definitions. ``superuser`` policy for ordinary groups; any write
    whose OLD or NEW name is protected also needs ``users:grant_role`` (M9)."""

    model: BaseModel = Group
    model_name: str = AUTH_GROUP_MODEL
    name: str = "Group"
    pk: str = "group_id"

    action_object: str = "group"
    owner_column: Optional[str] = None
    policy_name: str = "groups_admin_access"
    superuser_actions = frozenset({"group:read", "group:create", "group:update", "group:delete"})
    writable_by_admin = frozenset({"group_name", "description", "is_active", "client_id"})
    privileged_columns = frozenset({"group_id", "created_at", "created_by"})

    async def _payload_names(self) -> set:
        """``group_name`` values the client sent (body is already validated by _client_keys)."""
        # FILL IN: data = await self.json_data(); elements = data if list else [data];
        #   return {e.get("group_name") for e in elements if isinstance(e, dict)} - {None}
        raise NotImplementedError

    async def _pre_put(self, *args, **kwargs) -> bool:
        await super()._pre_put(*args, **kwargs)
        await self.authorize_protected_group(await self._payload_names())
        return True

    async def _pre_post(self, *args, **kwargs) -> bool:
        await super()._pre_post(*args, **kwargs)
        await self.authorize_protected_group(await self._payload_names())   # new name, if any
        return True

    async def _set_update(self, model, data) -> None:
        stored = getattr(model, "group_name", None)       # read BEFORE super() mutates the model
        await super()._set_update(model, data)            # surface policy + allowlist, in-memory set
        await self.authorize_protected_group({stored, (data or {}).get("group_name")} - {None})

    async def _del_primary_data(self, args: dict):
        objid = await super()._del_primary_data(args)     # surface policy for delete
        await self.authorize_protected_group({await _stored_group_name(self, objid)} - {None})
        return objid
```

**Why**:
- `stored` is read before `super()._set_update`, because `ModelView._set_update`
  calls `model.set(...)` and the stored name would already be the new one.
- The protected check runs after `super()` so the surface policy and allowlist
  are decided first (spec M9: "runs AFTER authorize_row()"); raising there still
  prevents the write, because upstream persists only after `_set_update` returns.
- Checking BOTH names closes "add members to `sales`, then rename it to
  `security_admin`" and renaming/deactivating a protected group (spec §2 Data Models).
- `_pre_post` checks the new name because POST's insert branch never reaches
  `_set_update`; its update branch also runs `_set_update`, which adds the stored name.

### `navigator_auth/handlers/groups.py` — MODIFY (block 3: `UserGroupManager`)

```python
# REPLACE `class UserGroupManager(ModelHandler):` and its 4-line body (verified: groups.py:21-25, occurrences: 1)
class UserGroupManager(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler):
    """Membership is admin-only. Created with PUT, removed with DELETE, never edited.

    ``owner_column`` is None ON PURPOSE (spec R4): the composite PK
    ``(user_id, group_id)`` makes the row's "owner" the user it grants the
    group to, so ownership would be self-certifying. A user cannot read their
    own memberships here; their session carries their groups.

    A row whose group is protected is additionally gated by M9.
    """

    model: BaseModel = UserGroup
    model_name: str = AUTH_USER_GROUP_MODEL
    name: str = "User Group"
    pk: list = ["user_id", "group_id"]

    action_object: str = "user_group"
    owner_column: Optional[str] = None
    policy_name: str = "user_groups_admin_access"
    superuser_actions = frozenset({"user_group:read", "user_group:create", "user_group:delete"})
    writable_by_owner = frozenset()
    writable_by_admin = frozenset()          # rows are created/deleted whole, never edited
    creatable_by_admin = frozenset({"user_id", "group_id"})   # the composite PK IS the row
    privileged_columns = frozenset()         # immutability comes from update ∉ superuser_actions

    async def _pre_put(self, *args, **kwargs) -> bool:
        await super()._pre_put(*args, **kwargs)
        # FILL IN: for each element of `await self.json_data()` (dict or list of dicts):
        #   name = await _stored_group_name(self, element.get("group_id"));
        #   await self.authorize_protected_group({name} - {None}, member_id=element.get("user_id"))
        return True

    async def _del_primary_data(self, args: dict):
        objid = await super()._del_primary_data(args)     # dict {"user_id": .., "group_id": ..}
        group_id = objid.get("group_id") if isinstance(objid, dict) else None
        await self.authorize_protected_group({await _stored_group_name(self, group_id)} - {None})
        return objid
```

**Why**: the name is resolved from the database per row, never taken from the
payload. `member_id` is passed on create only, so removing oneself from a
protected group is allowed (de-escalation) but adding oneself never is. No
`_pre_post` / `_set_update` override: TASK-151's `_pre_post` already refuses
(`user_group:update` ∉ `superuser_actions`).

### `navigator_auth/handlers/groups.py` — MODIFY (block 4: `GroupPermissionManager`)

```python
# REPLACE `class GroupPermissionManager(ModelHandler):` and its 3-line body (verified: groups.py:28-31, occurrences: 1)
class GroupPermissionManager(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler):
    """Group ↔ permission grants: admin-only, created/deleted whole. No owner
    column exists; stays on the plain superuser policy because no authorization
    path matches a permission by name (spec §8)."""

    model: BaseModel = GroupPermission
    name: str = "Group Permissions"
    pk: list = ["permission_id", "group_id"]

    action_object: str = "group_permission"
    owner_column: Optional[str] = None
    policy_name: str = "group_permissions_admin_access"
    superuser_actions = frozenset({"group_permission:read", "group_permission:create", "group_permission:delete"})
    writable_by_admin = frozenset()
    creatable_by_admin = frozenset({"group_id", "permission_id"})
    privileged_columns = frozenset()
```

### `tests/unit/handlers/test_group_handlers_access.py` — CREATE

```python
"""Group handlers behind the guard + protected groups (FEAT-107, TASK-154)."""

import pytest
from navigator_auth.handlers.groups import GroupManager, GroupPermissionManager, UserGroupManager

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

# FILL IN: harness from tests/unit/handlers/test_guard_model_view_hooks.py (TASK-151), plus a fake
#   Group table {1: "superuser", 2: "security_admin", 3: "sales"} behind the mocked connection, and a
#   PDP holding the five TASK-150 surface policies + users_grant_role.


class TestConfiguration:
    def test_usergroup_owner_column_is_none(self): ...             # AC7, spec R4
    def test_grouppermission_owner_column_is_none(self): ...       # AC7
    def test_config_matches_policy_pack(self): ...                 # three handlers vs auth_crud_admin_access.yaml


class TestMappingTables:
    async def test_user_cannot_self_join_group(self): ...          # AC6, both /user_groups and /usergroups
    async def test_user_cannot_grant_permission_to_group(self): ...  # AC6
    async def test_mapping_row_create_allowed_for_admin(self): ... # AC20, ordinary group "sales"
    async def test_mapping_row_update_refused(self): ...           # AC20, PATCH and POST → 403
    async def test_reads_superuser_only(self): ...                 # deviation 3


class TestGroupDefinitions:
    async def test_group_definition_allowlist(self): ...           # group_name/description ok; group_id 403
    async def test_ordinary_group_crud_needs_only_superuser(self): ...


class TestProtectedGroups:
    async def test_superuser_cannot_add_member_to_protected_group(self): ...
    async def test_grantor_can_add_member_to_protected_group(self): ...
    async def test_no_self_add_to_protected_group(self): ...
    async def test_protected_group_resolved_from_db_not_payload(self): ...   # group_id=1 + group_name "sales" in body
    async def test_member_removal_needs_grant_role(self): ...
    async def test_rename_into_protected_name_refused(self): ...
    async def test_rename_out_of_protected_name_refused(self): ...           # rename, deactivate, delete
```

### Steps (in order)

1. Apply blocks 1–4 — block 1 first, because the classes use the resolver and the new imports.
2. Complete `_stored_group_name`, `_payload_names` and `UserGroupManager._pre_put`.
3. Write the tests with a fake `Group` table behind the mocked connection —
   because `test_protected_group_resolved_from_db_not_payload` must prove the
   check ignores a `group_name` sent in the body.
4. Exercise `UserGroupManager` on both `/api/v1/user_groups/...` and
   `/api/v1/usergroups/...` request paths — because the guard evaluates
   `resource=self.request.path` and the second route was missing from the spec.
5. Run `pytest tests/unit/handlers/test_group_handlers_access.py -v`, then `pytest tests/unit/handlers/ -v`.

### FILL IN checklist

- [ ] `_stored_group_name` body.
- [ ] `GroupManager._payload_names` body.
- [ ] `UserGroupManager._pre_put` loop.
- [ ] Test harness (fake Group table, PDP with the shipped pack) and all test bodies.

---

## Acceptance Criteria

- [ ] `pytest tests/unit/handlers/test_group_handlers_access.py -v` passes.
- [ ] `pytest tests/unit/handlers/ -v` passes (AC2).
- [ ] An ordinary authenticated session cannot join a group or grant a permission (spec AC6).
- [ ] `UserGroupManager.owner_column is None` and `GroupPermissionManager.owner_column is None` (spec AC7).
- [ ] Membership of a protected group can be added or removed, and a protected group renamed (into or out of a protected name), deactivated or deleted, only by an actor holding `users:grant_role` who belongs to it; nobody can add themselves; ordinary groups need only the superuser policy (spec AC17).
- [ ] An approved superuser can create mapping rows for ordinary groups and update none (spec AC20).

---

## Test Specification

See the CREATE block above.

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at `sdd/specs/auth-model-crud-hardening.spec.md` (§2 Overview points 2–3, §3 Modules 3, 4, 9, §7 R4).
2. **Check dependencies** — TASK-149, TASK-151, TASK-152 are `done` in `sdd/tasks/index/auth-model-crud-hardening.json`.
3. **Re-verify** the `groups.py` anchors (`grep -c`) — stop and report if any count is not 1.
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

**Deviations from spec**: `object:verb` actions; reads gated (user decision); both membership routes | other
