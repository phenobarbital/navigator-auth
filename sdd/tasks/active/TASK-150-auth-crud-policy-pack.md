# TASK-150: ABAC policy pack for the five auth CRUD surfaces and `users:grant_role`

**Feature**: FEAT-107 — Write-envelope hardening for the remaining auth CRUD handlers
**Spec**: `sdd/specs/auth-model-crud-hardening.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 6**. Configuration only — one YAML file and its
contract test. Delegation-eligible per spec §3.

`policy_allows()` fails closed when a named policy is absent
(`decorators.py:1185-1188`), so shipping this pack is what *enables* the admin
path on the five hardened handlers — never what grants escalation. Every policy
name and action string here is a contract with a handler class written in a
later task (TASK-153, TASK-154, TASK-155, TASK-156, and the protected-group check
in TASK-152). A rename on either side silently kills the admin path, which is
exactly what the contract test exists to catch.

### Spec deviations recorded at /sdd-task time (read before writing the YAML)

1. **Action strings must be `object:verb`.** The spec (§2 Data Models) writes
   bare `{"read", "create", "update", "delete"}`. That cannot work:
   `ActionKey.__init__` does `self.object, self.action = action.split(':', 1)`
   (`abac/policies/abstract.py:28`), so a bare `"read"` raises
   `ValueError: not enough values to unpack` — verified by execution on
   2026-11-11. Inside `policy_allows()` that exception is swallowed into a deny,
   so the admin path would be permanently closed. FEAT-105 already uses this
   convention (`identity:read`, `partner:create`) and its pack test enforces it
   (`test_every_action_is_object_colon_verb`). This task fixes the names:

   | Handler | Policy | Actions |
   |---|---|---|
   | `UserManager` | `users_admin_access` | `user:read` `user:create` `user:update` `user:delete` |
   | `GroupManager` | `groups_admin_access` | `group:read` `group:create` `group:update` `group:delete` |
   | `UserGroupManager` | `user_groups_admin_access` | `user_group:read` `user_group:create` `user_group:delete` |
   | `GroupPermissionManager` | `group_permissions_admin_access` | `group_permission:read` `group_permission:create` `group_permission:delete` |
   | `PermissionHandler` | `permissions_admin_access` | `permission:read` `permission:create` `permission:update` `permission:delete` |
   | `UserRoleHandler` + protected groups | `users_grant_role` | `users:grant_role` (unchanged from spec) |

2. **`UserGroupManager` has two routes.** It is configured at both
   `/api/v1/user_groups` **and** `/api/v1/usergroups`
   (`navigator_auth/handlers/__init__.py:33,35`). The spec lists only the first.
   The guard passes `resource=self.request.path` (`guards.py:152-157`), so both
   `user_groups_admin_access` and `users_grant_role` must cover both prefixes, or
   the second route is admin-dead.

3. **The pack is not auto-loaded.** Nothing in `navigator_auth/` references
   `default_policies/` (verified: `grep -rn default_policies navigator_auth --include=*.py`
   is empty). Operators load it into `POLICY_STORAGE_DIR`, as with FEAT-105's
   pack. TASK-158 documents this; this task only ships the file.

---

## Scope

- Create `navigator_auth/abac/default_policies/auth_crud_admin_access.yaml` with
  exactly six policies: the five surface policies (subjects `superuser`) and
  `users_grant_role` (subjects `security_admin`).
- Create `tests/unit/handlers/test_auth_crud_policy_pack.py`: parses the pack
  with `YAMLStorage._parse_file` and asserts names, actions, resources,
  subjects, effect, priority, enforcing; plus the AC12 property of
  `admin_full_access.yaml` (actions enumerated, no wildcard, no `users:grant_role`).

**NOT in scope**:
- Any Python in `navigator_auth/` (handlers set their own `policy_name` /
  `superuser_actions` in TASK-153..156).
- Editing `admin_full_access.yaml` or `auth_model_admin_access.yaml` — spec R8:
  widening `admin_full_access.yaml`'s `actions` collapses the separation.
- Loading the pack at startup.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/default_policies/auth_crud_admin_access.yaml` | CREATE | Six policies |
| `tests/unit/handlers/test_auth_crud_policy_pack.py` | CREATE | Contract test between the YAML and the handler classes |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `6b8cc84` on 2026-11-11.

### Verified Imports

```python
from pathlib import Path
import pytest
from navigator_auth.abac.storages.yaml_storage import YAMLStorage   # used by test_auth_model_policy_pack.py:12
```

### Existing Signatures / Shapes to Use

```yaml
# navigator_auth/abac/default_policies/auth_model_admin_access.yaml — the FEAT-105 shape to copy
version: "1.0"
defaults:
  effect: deny
policies:
  - name: user_identities_admin_access
    effect: allow
    description: >-
      ...
    resources: ["uri:/api/v1/user_identity*"]
    actions: ["identity:read", "identity:revoke", "identity:delete"]
    subjects:
      groups: ["superuser"]
    priority: 90
    enforcing: true
```

```python
# YAMLStorage._parse_file(path) -> list[dict]   (staticmethod/classmethod; used at test_auth_model_policy_pack.py:50)
#   parsed dict keys used by the FEAT-105 test: name, actions, resources, subjects{groups},
#   effect ("ALLOW" — upper-cased), enforcing (bool), priority (int), policy_type ("resource")

# navigator_auth/abac/policies/abstract.py:26-28
class ActionKey:
    def __init__(self, action: str):
        self.object, self.action = action.split(':', 1)   # bare "read" → ValueError

# navigator_auth/abac/policies/resources.py:93,115-120 — resource patterns are fnmatch'ed one by one
```

- `admin_full_access.yaml` (verified 2026-11-11): `resources` include `"uri:*"`;
  `actions` is an enumerated list of 12 strings (`tool:*`-style objects, none of
  them `users:*` or `*`); `subjects.groups: [superuser, admin]`; `priority: 100`.
- Resource prefixes do not collide: `uri:/api/v1/users*` does not match
  `/api/v1/user_groups…` and `uri:/api/v1/groups*` does not match
  `/api/v1/group_permissions…` (fnmatch: the literal `s` must follow).

### Does NOT Exist (Anti-Hallucination)

- ~~`auth_crud_admin_access.yaml`~~ — created by this task.
- ~~any existing policy covering `/api/v1/users`, `/api/v1/groups`,
  `/api/v1/user_groups`, `/api/v1/usergroups`, `/api/v1/group_permissions`,
  `/api/v1/permissions`~~ — none.
- ~~a `security_admin` group in any fixture or migration~~ — the pack only names it (spec §6).
- ~~automatic loading of `abac/default_policies/`~~ — not referenced by any code.

---

## Implementation Blueprint

### `navigator_auth/abac/default_policies/auth_crud_admin_access.yaml` — CREATE

```yaml
version: "1.0"
defaults:
  effect: deny
policies:
  - name: users_admin_access
    effect: allow
    description: >-
      Superusers may read, create, update and delete users, bounded in code by
      the handler's write allowlist. Never grants is_superuser / user_role /
      is_staff / password: those are privileged columns no CRUD path writes.
    resources: ["uri:/api/v1/users*"]
    actions: ["user:read", "user:create", "user:update", "user:delete"]
    subjects:
      groups: ["superuser"]
    priority: 90
    enforcing: true

  - name: groups_admin_access
    effect: allow
    description: >-
      Superusers may manage ordinary groups. A protected group (superuser,
      security_admin, ...) additionally needs users:grant_role, checked in code.
    resources: ["uri:/api/v1/groups*"]
    actions: ["group:read", "group:create", "group:update", "group:delete"]
    subjects:
      groups: ["superuser"]
    priority: 90
    enforcing: true

  # FILL IN: user_groups_admin_access — resources BOTH "uri:/api/v1/user_groups*" and
  #   "uri:/api/v1/usergroups*" (deviation 2); actions user_group:read/create/delete (no update:
  #   a membership row is created/deleted whole); description says a protected group needs users:grant_role.
  # FILL IN: group_permissions_admin_access — "uri:/api/v1/group_permissions*";
  #   group_permission:read/create/delete.
  # FILL IN: permissions_admin_access — "uri:/api/v1/permissions*"; permission:read/create/update/delete.

  - name: users_grant_role
    effect: allow
    description: >-
      Change a user's privileged flags (is_superuser, user_role, is_staff), and
      change membership or definition of a protected group. Deliberately NOT
      granted to `superuser`; held by security_admin, the same group as
      FEAT-106's mfa:disenroll.
    resources:
      - "uri:/api/v1/users*"
      - "uri:/api/v1/user_groups*"
      - "uri:/api/v1/usergroups*"
      - "uri:/api/v1/groups*"
    actions: ["users:grant_role"]
    subjects:
      groups: ["security_admin"]
    priority: 90
    enforcing: true
```

**Why**: `priority: 90` and `defaults: {effect: deny}` match the FEAT-105 pack,
so the two packs compose predictably. `users_grant_role` covers every route that
checks the action (the role endpoint under `/api/v1/users/{id}/role`, and the
protected-group checks on both membership routes and on `/api/v1/groups`),
because the guard evaluates `resource=self.request.path`.

### `tests/unit/handlers/test_auth_crud_policy_pack.py` — CREATE

```python
"""The FEAT-107 policy pack parses and declares what the five guards expect.

Contract test between a YAML file and handler classes: a renamed policy or
action silently kills the superuser path, because policy_allows() fails closed
on a policy it cannot find by name. Mirrors test_auth_model_policy_pack.py.
"""

from pathlib import Path

import pytest

from navigator_auth.abac.storages.yaml_storage import YAMLStorage

POLICIES = Path(__file__).resolve().parents[3] / "navigator_auth" / "abac" / "default_policies"
PACK = POLICIES / "auth_crud_admin_access.yaml"
ADMIN_FULL = POLICIES / "admin_full_access.yaml"

EXPECTED_ACTIONS = {
    "users_admin_access": {"user:read", "user:create", "user:update", "user:delete"},
    "groups_admin_access": {"group:read", "group:create", "group:update", "group:delete"},
    "user_groups_admin_access": {"user_group:read", "user_group:create", "user_group:delete"},
    "group_permissions_admin_access": {"group_permission:read", "group_permission:create", "group_permission:delete"},
    "permissions_admin_access": {"permission:read", "permission:create", "permission:update", "permission:delete"},
    "users_grant_role": {"users:grant_role"},
}
EXPECTED_RESOURCES = {
    "users_admin_access": ["uri:/api/v1/users*"],
    "groups_admin_access": ["uri:/api/v1/groups*"],
    "user_groups_admin_access": ["uri:/api/v1/user_groups*", "uri:/api/v1/usergroups*"],
    "group_permissions_admin_access": ["uri:/api/v1/group_permissions*"],
    "permissions_admin_access": ["uri:/api/v1/permissions*"],
    "users_grant_role": ["uri:/api/v1/users*", "uri:/api/v1/user_groups*",
                         "uri:/api/v1/usergroups*", "uri:/api/v1/groups*"],
}


@pytest.fixture(scope="module")
def parsed():
    assert PACK.exists(), f"policy pack missing: {PACK}"
    return {p["name"]: p for p in YAMLStorage._parse_file(PACK)}


class TestPolicyPack:
    def test_policy_pack_parses(self, parsed): ...                       # FILL IN: exactly the six names
    def test_actions_match_the_handler_contract(self, parsed): ...      # FILL IN
    def test_every_action_is_object_colon_verb(self, parsed): ...       # FILL IN: copy FEAT-105's assertion
    def test_resources_cover_every_route(self, parsed): ...             # FILL IN: order-insensitive compare
    def test_surface_policies_grant_superuser_only(self, parsed): ...   # FILL IN: five policies → ["superuser"]
    def test_grant_role_held_by_security_admin(self, parsed): ...       # FILL IN: AC16 — ["security_admin"], never superuser
    def test_effect_priority_enforcing(self, parsed): ...               # FILL IN: "ALLOW", 90, True


class TestSeparationOfDuties:
    def test_grant_role_absent_from_admin_full_access(self): ...       # FILL IN: AC12, see Steps
```

### Steps (in order)

1. Write the YAML first, completing the three `FILL IN` policies in the same
   style as the two written ones — because the test asserts exact sets.
2. Write the test module; for `test_grant_role_absent_from_admin_full_access`,
   parse `ADMIN_FULL` with the same `_parse_file` and assert, for every policy in
   it: `"users:grant_role"` not in `actions`, no action equals `"*"`, and no
   action ends with `":*"` — because the separation rests on that list staying
   enumerated (spec AC12, R8).
3. Run `pytest tests/unit/handlers/test_auth_crud_policy_pack.py tests/unit/handlers/test_auth_model_policy_pack.py -v`
   — the second file proves the FEAT-105 pack is untouched.
4. As a parse smoke check, build each parsed policy's actions with
   `ActionKey` (`from navigator_auth.abac.policies.abstract import ActionKey`) in
   `test_every_action_is_object_colon_verb` — because that is the exact call that
   would raise on a bare verb.

### FILL IN checklist

- [ ] Three remaining policies in the YAML (`user_groups_admin_access`, `group_permissions_admin_access`, `permissions_admin_access`).
- [ ] Eight test bodies.
- [ ] `ActionKey(a)` constructed for every action in the pack without raising.

---

## Acceptance Criteria

- [ ] `pytest tests/unit/handlers/test_auth_crud_policy_pack.py -v` passes.
- [ ] `pytest tests/unit/handlers/test_auth_model_policy_pack.py -v` still passes (FEAT-105 pack untouched).
- [ ] The pack declares exactly six policies with the names and actions in the Context table (spec AC16 for `users_grant_role`).
- [ ] `users:grant_role` is held only by `security_admin` and is not reachable through `admin_full_access.yaml` (spec AC12, AC16).
- [ ] Both `/api/v1/user_groups*` and `/api/v1/usergroups*` are covered.

---

## Test Specification

See the CREATE block above — eight tests, all synchronous, no app or database.

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at `sdd/specs/auth-model-crud-hardening.spec.md` (§3 Module 6, §6 Key facts, §7 R8).
2. **Check dependencies** — none.
3. **Re-verify** the FEAT-105 pack shape (`auth_model_admin_access.yaml`) and `admin_full_access.yaml` before writing.
4. **Update status** in `sdd/tasks/index/auth-model-crud-hardening.json` → `"in-progress"`.
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

**Deviations from spec**: action strings are `object:verb` (see Context) | other
