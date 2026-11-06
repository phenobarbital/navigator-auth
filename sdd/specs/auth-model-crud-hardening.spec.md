---
# SDD flow type and base branch (FEAT-145).
type: feature
base_branch: dev
projects: [handlers, abac, models, auth-backends]
tags: [security, privilege-escalation, abac, crud, write-envelope]
docs:
  policy: required
  pages: []
  api_modules: [navigator_auth.handlers]
---

# Feature Specification: Write-envelope hardening for the remaining auth CRUD handlers

**Feature ID**: FEAT-107
**Date**: 2026-11-06
**Author**: Jesus Lara
**Status**: draft
**Target version**: 0.30.0

---

## 1. Motivation & Business Requirements

> Why does this feature exist? What problem does it solve?

### Problem Statement

FEAT-105 hardened three of the eight model-CRUD handlers over the auth schema
(`UserIdentityHandler`, `UserAccountHandler`, `PartnerKeyHandler`). **Five were
left as generic model views over the most privileged tables in the system**, and
the generic write path has no column allowlist.

`ModelView._set_update()` (`navigator/views/model.py:629-652`) iterates every key
in the request payload and writes it whenever the key is a model field. There is
no write allowlist anywhere in that path — `_hidden` (`:145-148`, `:178-179`) is
a *response* filter, populated from `repr=False` metadata, and it never gates a
write.

**Confirmed by execution**, not by reading: driving the real
`UserManager` write hooks over the real `User` model with the payload a client
would send produced

```
is_superuser   False               ->  True
is_staff       False               ->  True
user_role      None                ->  10        (UserType.ROOT)
email          victim@example.com  ->  attacker@evil.test
password       (unset)             ->  set and hashed by _calculate_password
```

Nothing else in the request path closes this:

1. `UserManager(ModelView)` (`handlers/users/user.py:11`) carries no decorator,
   no guard, no `public_columns` and no `policy_name`.
2. `ModelView` enforces no authorization of its own — its MRO is
   `ModelView → AbstractModel → BaseView → CorsViewMixin → _PreflightHandler →
   BaseHandler → View → AbstractView`, and neither `model.py` nor `base.py`
   mentions `is_authenticated` / `login_required`.
3. `AUTHORIZATION_MIDDLEWARES = ()` by default (`conf.py:264`): there is no
   blanket ABAC evaluation of every request. `Guardian` is an explicit API that
   a handler or decorator has to call.
4. No ABAC policy in `navigator_auth/abac/default_policies/` or `settings/`
   mentions `/api/v1/users`.

So authorization on these routes is whatever authentication the auth middleware
provides — and **three independent escalation routes** exist, because the same
shape repeats on the tables ABAC itself reads:

| Route | Handler | What a write grants |
|---|---|---|
| user columns | `UserManager` | `is_superuser` / `user_role` / `is_staff` on any user, plus their password and e-mail |
| group membership | `UserGroupManager` | join any group — including `superuser`, which `admin_full_access.yaml` authorizes on `subjects.groups` |
| group permissions | `GroupPermissionManager` | grant any permission to any group |

**Who is affected**: every deployment that exposes these routes and relies on the
handlers for authorization. **Why now**: FEAT-106 documented the account-takeover
half of this as an accepted risk (`basicauth-otp-2fa.spec.md` §7 R1) on the
understanding that it was pre-existing and bounded. Investigating it for this
spec showed it is not bounded to account takeover: it is privilege escalation,
and it has two more routes than the one recorded there.

### Goals

- **G1** — Close privilege escalation on all five remaining handlers.
- **G2** — Give the guard a **write-column allowlist**, which it does not have
  today, enforced on *both* the owner path and the admin path.
- **G3** — Allowlists, never denylists: a column added to a model later must be
  closed by default.
- **G4** — Preserve legitimate administration — an administrator may update
  non-privileged columns of another user, and a user may edit their own profile.
- **G5** — Privileged grants (`is_superuser`, `user_role`, `is_staff`) only
  through a dedicated endpoint with its own ABAC action, audited.
- **G6** — Base-agnostic: the five handlers sit on **two different**
  `ModelHandler` classes, and both must be covered.
- **G7** — No regression on FEAT-105's three already-guarded handlers.

### Non-Goals (explicitly out of scope)

- **Re-doing FEAT-105's three handlers.** They are consumed as the pattern and
  must keep passing their existing tests.
- **Introducing a blanket authorization middleware.**
  `AUTHORIZATION_MIDDLEWARES` staying empty by default is a deployment choice
  with repo-wide consequences; changing it is a separate decision. This feature
  makes each handler authorize itself instead, which is also what FEAT-105 chose.
- **Changing the password or profile endpoints.** `UserSession.password_change`
  (`handlers/users/session.py:119`, already requires `old_password` and 403s when
  the session user does not match the URL `userid`), `password_reset` (`:170`) and
  `user_profile` (`:244`) already exist and are the correct paths. This feature
  only stops the *generic CRUD* from being a second, unguarded way to do the same
  thing.
- **An admin UI.** Out of scope; see §7 R1 for the breaking-change note.
- **The FEAT-106 MFA surface.** `mfa:disenroll` and the MFA handlers are
  specified there.

---

## Governing Decisions

<!-- GENERATED by `parrot sdd spec consequences <spec> --render` — do not edit by hand. -->

decision audit not configured in this repository

---

## 2. Architectural Design

### Overview

Finish what FEAT-105 started: put every auth-schema CRUD handler behind
`OwnerOrSuperuserGuard`, configured per surface. But configuration alone is **not
sufficient**, and that is the central finding of this spec.

**The guard has no write-column allowlist.** Its three column attributes are
about *reading*: `public_columns` is documented as "The serialization allowlist. A
column absent from it is invisible, including to its own owner"
(`guards.py:43-45`), and `credential_columns` is never-serialize. The write
envelope that FEAT-105's tests exercise works by leaving `update` out of
`superuser_actions` (default `{"read", "revoke", "delete"}`, `guards.py:56`) —
which blocks the **verb** for a non-owner, not the **columns**.

**And the owner path is a blanket allow.** `authorize_row()` begins:

```python
user_id, is_superuser = await self.acting_user()
if self.owner_column is not None and owner_id is not None and str(owner_id) == str(user_id):
    return True        # guards.py:140-141
```

It returns before any action check and before any column consideration. Two
consequences drive the whole design:

1. **A user owns their own `User` row.** So on `UserManager`, ownership alone
   would authorize setting one's own `is_superuser = true`. The guard must gain a
   write allowlist, applied to the owner path too.
2. **Ownership is self-certifying on a mapping table.** The "owner" of a
   `UserGroup` row (`user_id` is part of its composite primary key,
   `models.py:209-211`) is the very user the row grants a group to. With
   `owner_column = "user_id"` a user could create their own row pointing at the
   `superuser` group and line 141 would return `True`. Both mapping handlers must
   therefore run with `owner_column = None`, which the guard documents as making
   "the superuser path the only path for every verb" (`guards.py:39-41`). The
   accepted cost: a user cannot read their own memberships *through that
   handler* — the session already carries their groups.

So the design is: **one new guard capability plus five per-surface
configurations plus one new endpoint** for the privileged grants that the CRUD
will no longer accept.

### Component Diagram

```
                         OwnerOrSuperuserGuard  (handlers/guards.py)
   existing, read-side:   public_columns · credential_columns
   existing, verb-side:   superuser_actions · policy_name · owner_column
   NEW, write-side:       writable_by_owner · writable_by_admin · privileged_columns
                                     │
                                     │ enforced in the write hooks, on BOTH paths
                                     ▼
        ┌────────────────────────────┴───────────────────────────────┐
        │                                                            │
   guarded by FEAT-105 (unchanged)                    hardened by THIS feature
   ├── UserIdentityHandler   (model.py base)          ├── UserManager            → User
   ├── UserAccountHandler    (model.py base)          ├── GroupManager           → Group
   └── PartnerKeyHandler     (model.py base)          ├── UserGroupManager       → UserGroup
                                                      ├── GroupPermissionManager → GroupPermission
                                                      └── PermissionHandler      → Permission
                                                                    │
   two different bases, both must work:                             │
     handlers/handler.py:4  ModelHandler(ModelView)   ← groups.py   │
     handlers/model.py:16   ModelHandler(BaseView)    ← permissions.py, userattrs.py, partners.py
                                                                    │
                                     ┌──────────────────────────────┘
                                     ▼
            privileged columns are writable by NO CRUD path, only by:
            POST /api/v1/users/{id}/role   → action `users:grant_role`
                                           → audited, ABAC policy pack
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `OwnerOrSuperuserGuard` | **extends** | Gains the write-allowlist attributes and their enforcement. Existing attributes and behaviour unchanged, so FEAT-105's three handlers keep working. `handlers/guards.py:31`. |
| `OwnerOrSuperuserGuard.authorize_row()` | modifies | The owner blanket-allow at `guards.py:140-141` must consult the write allowlist for write actions. **The single most delicate edit in this feature.** |
| `UserManager` | modifies | `ModelView` → `OwnerOrSuperuserGuard, ModelHandler`, guard first in MRO. `handlers/users/user.py:11`. |
| `UserManager._set_password` / `_calculate_password` | **removes** | A password must not be settable through generic CRUD when `UserSession.password_change` exists and does it correctly. |
| `GroupManager`, `UserGroupManager`, `GroupPermissionManager` | modifies | `handlers/groups.py:14,21,28`. These use the `handlers/handler.py:4` base. |
| `PermissionHandler` | modifies | `handlers/permissions.py:7`. Uses the `handlers/model.py:16` base — the other one. |
| `handlers/model.py` `ModelHandler` | depends on | 446-line local reimplementation over `BaseView` with its own `get`/`put`/`patch` (`:122,216,252`). The write enforcement must cover its write path too, not only `ModelView._set_update`. |
| `handlers/handler.py` `ModelHandler` | depends on | Thin `ModelView` subclass (`dbname='authdb'`), so its writes go through `ModelView._set_update` (`navigator/views/model.py:629`). |
| `UserSession.password_change` | uses (unchanged) | The retained path for passwords. `handlers/users/session.py:119`. |
| `UserSession.user_profile` | uses (unchanged) | `handlers/users/session.py:244`. |
| `abac/default_policies/` | **new file(s)** | Policies for the five surfaces plus `users:grant_role`. |
| `handlers/__init__.py` | modifies | `UserManager.configure(app, '/api/v1/users')` at `:38`; registers the new role endpoint. |
| `abac/audit.py` `AuditLog` | uses | The guard already audits every decision via `audit_decision()` (`guards.py:158`). The role endpoint adds its own record. |

### Data Models

No new tables and no model changes. What this feature adds is **declarative
configuration per handler**, so the allowlists are the "data model":

```python
# The new guard attributes (navigator_auth/handlers/guards.py)
writable_by_owner: frozenset[str] = frozenset()   # owner may write these, nothing else
writable_by_admin: frozenset[str] = frozenset()   # admin path may write these
privileged_columns: frozenset[str] = frozenset()  # writable by NO CRUD path, ever

# Per-surface configuration decided by this spec
#
# UserManager → User (models.py:39)
owner_column       = "user_id"
writable_by_owner  = {"first_name", "last_name", "display_name", "title",
                      "avatar", "timezone"}
writable_by_admin  = writable_by_owner | {"is_active", "email", "alt_email"}
privileged_columns = {"is_superuser", "user_role", "is_staff", "password",
                      "userid", "user_id", "created_at", "last_login"}
superuser_actions  = {"read", "update", "delete"}
policy_name        = "users_admin_access"

# UserGroupManager → UserGroup (models.py:209) — a mapping table
owner_column       = None          # ownership would be self-certifying (§2 Overview)
writable_by_owner  = frozenset()
writable_by_admin  = frozenset()   # rows are created/deleted whole, never edited
privileged_columns = {"user_id", "group_id"}
superuser_actions  = {"read", "create", "delete"}
policy_name        = "user_groups_admin_access"

# GroupPermissionManager → GroupPermission (models.py:243) — a mapping table
owner_column       = None
writable_by_admin  = frozenset()
privileged_columns = {"group_id", "permission_id"}
superuser_actions  = {"read", "create", "delete"}
policy_name        = "group_permissions_admin_access"

# GroupManager → Group (models.py:188)
owner_column       = None
writable_by_admin  = {"group_name", "description", "is_active", "client_id"}
privileged_columns = {"group_id", "created_at", "created_by"}
superuser_actions  = {"read", "create", "update", "delete"}
policy_name        = "groups_admin_access"

# PermissionHandler → Permission (models.py:223)
owner_column       = None
writable_by_admin  = {"permission", "description"}
privileged_columns = {"permission_id", "created_at"}
superuser_actions  = {"read", "create", "update", "delete"}
policy_name        = "permissions_admin_access"
```

### New Public Interfaces

```python
# navigator_auth/handlers/users/role.py  (new)
class UserRoleHandler(OwnerOrSuperuserGuard, ModelHandler):
    """The ONLY way to change a privileged user flag.

    POST /api/v1/users/{id}/role  {"is_superuser": bool, "user_role": int,
                                   "is_staff": bool}

    Gated by the `users:grant_role` ABAC action, which is deliberately absent
    from `admin_full_access.yaml`'s enumerated action list, so a stock
    superuser does not inherit it. Never self-service: an actor may not grant
    themselves a flag they do not already hold.
    """
```

---

## 3. Module Breakdown

#### Delegation-eligible modules

| Module | Eligible? | Decided patterns / exact contracts | Why not (if no) |
|---|---|---|---|
| M1: guard write allowlist | **no** | — | The security core. It edits the blanket-allow at `guards.py:140-141` and must hold for both write paths and both handler bases. A wrong edit opens the hole it is closing, and the failure is silent. Thinking model only. |
| M2: `UserManager` migration | **no** | — | Changes the base class and removes the password hooks on the most sensitive handler; the MRO order (guard first) is load-bearing. |
| M3: mapping handlers | yes | `owner_column=None`, action sets and `privileged_columns` fixed in §2; the only judgement (why not `user_id`) is already recorded. | — |
| M4: definition handlers | yes | Allowlists and action sets fixed in §2. | — |
| M5: role endpoint | **no** | — | A new privilege-granting surface; the self-grant prohibition and the ABAC action wiring are the whole point. |
| M6: ABAC policy pack | yes | Exact YAML shape verified in §6; names, actions and priority fixed. Configuration only. | — |
| M7: regression tests | yes | The probe that proved the escalation is written and its expected inversion is unambiguous. | — |
| M8: docs & changelog | yes | Breaking-change note and content fixed in §10. | — |

### Module 1: Write-column allowlist on `OwnerOrSuperuserGuard`
- **Path**: `navigator_auth/handlers/guards.py` (modifies)
- **Responsibility**: Give the guard the write-side control it lacks, and apply it
  on the owner path as well as the admin path.
- **Depends on**: nothing.
- **NOT delegation-eligible.**
- **Interface Skeleton**:
  ```python
  # navigator_auth/handlers/guards.py  (modifies)
  class OwnerOrSuperuserGuard:                       # verified: guards.py:31
      # existing, unchanged:
      owner_column: Optional[str] = "user_id"        # verified: guards.py:52
      credential_columns: frozenset[str] = frozenset()
      public_columns: frozenset[str] = frozenset()   # SERIALIZATION allowlist, not write
      policy_name: Optional[str] = None
      superuser_actions: frozenset[str] = frozenset({"read", "revoke", "delete"})  # :56

      # NEW:
      writable_by_owner: frozenset[str] = frozenset()
      writable_by_admin: frozenset[str] = frozenset()
      privileged_columns: frozenset[str] = frozenset()

      async def authorize_columns(self, payload: dict, *, is_owner: bool) -> None:
          """Refuse the request when the payload touches a column this path may
          not write. Allowlist semantics: a key absent from the applicable
          `writable_by_*` set is refused, so a column added to the model later
          is closed by default (G3). A key in `privileged_columns` is refused on
          every path, owner included.

          Raises web.HTTPForbidden, naming no column the caller may not see.
          """

      async def authorize_row(self, action: str, owner_id: Optional[int], ...):
          """MODIFIES the owner fast-path.

          verified anchor: guards.py:141
              if self.owner_column is not None and owner_id is not None and str(owner_id) == str(user_id):
                  return True

          That early return is a blanket allow — no action check, no column
          check — which is correct for a row a user wholly owns but wrong for
          `auth.users`, where the row carries the user's own privilege flags.
          For a write action the owner path must now pass through
          authorize_columns(..., is_owner=True) before returning.

          The non-owner path below it is unchanged: not-superuser → refuse,
          action outside superuser_actions → refuse, no policy_name → refuse,
          then policy_allows(). (guards.py:142-158)
          """
  ```
- **Note on coverage**: the enforcement must sit where **both** bases funnel their
  writes — `ModelView._set_update` for the `handlers/handler.py:4` base, and
  `handlers/model.py`'s own `put` (`:216`) / `patch` (`:252`) for the
  `handlers/model.py:16` base. A hook placed on only one leaves half the surface
  open.

### Module 2: `UserManager` migration
- **Path**: `navigator_auth/handlers/users/user.py` (modifies)
- **Responsibility**: Put the user CRUD behind the guard and stop it being a
  second, unguarded password/e-mail/privilege write path.
- **Depends on**: M1.
- **NOT delegation-eligible.**
- **Interface Skeleton**:
  ```python
  # navigator_auth/handlers/users/user.py  (modifies)
  # verified anchor: `class UserManager(ModelView):`  user.py:11
  class UserManager(OwnerOrSuperuserGuard, ModelHandler):
      """User CRUD. Guard first in the MRO so its hooks win over ModelView's
      (the ordering FEAT-105 used — verified: userattrs.py:363)."""
      model = User                                   # verified: models.py:39
      pk = "user_id"
      # the configuration block from §2 Data Models

      # REMOVED: _set_password / _calculate_password.
      # A password is set through UserSession.password_change
      # (session.py:119 — requires old_password and 403s when the session user
      # does not match the URL userid) or password_reset (:170). Keeping a CRUD
      # path would re-open privileged writes under a different name.

      def required_by_put(self):
          """MUST no longer include 'email'. verified anchor: user.py:24
          `return ['first_name', 'last_name', 'display_name', 'username', 'email']`
          Required-field lists are not allowlists; writability is decided by
          writable_by_owner / writable_by_admin."""
  ```

### Module 3: Mapping handlers — `UserGroupManager`, `GroupPermissionManager`
- **Path**: `navigator_auth/handlers/groups.py` (modifies)
- **Responsibility**: Close the two escalation routes that go through the tables
  ABAC itself reads.
- **Depends on**: M1, M6.
- **Interface Skeleton**:
  ```python
  # navigator_auth/handlers/groups.py  (modifies)
  # verified anchors: `class UserGroupManager(ModelHandler):`        groups.py:21
  #                   `class GroupPermissionManager(ModelHandler):`  groups.py:28
  class UserGroupManager(OwnerOrSuperuserGuard, ModelHandler):
      """Membership is admin-only.

      owner_column is None ON PURPOSE. UserGroup's composite primary key is
      (user_id, group_id) (verified: models.py:209-211), so the row's "owner"
      is the user it grants the group to — ownership is self-certifying, and
      guards.py:141 would return True for a row a user writes for themselves
      into the `superuser` group. None makes the superuser path the only path
      (guards.py:39-41).

      Accepted cost: a user cannot read their own memberships here. Their
      session already carries their groups.
      """

  class GroupPermissionManager(OwnerOrSuperuserGuard, ModelHandler):
      """Same reasoning; no owner column exists at all on this table."""
  ```

### Module 4: Definition handlers — `GroupManager`, `PermissionHandler`
- **Path**: `navigator_auth/handlers/groups.py`, `navigator_auth/handlers/permissions.py`
  (modifies)
- **Responsibility**: Guard the group and permission definitions.
- **Depends on**: M1, M6.
- **Interface Skeleton**:
  ```python
  # verified anchors: `class GroupManager(ModelHandler):`       groups.py:14
  #                   `class PermissionHandler(ModelHandler):`  permissions.py:7
  class GroupManager(OwnerOrSuperuserGuard, ModelHandler): ...
  class PermissionHandler(OwnerOrSuperuserGuard, ModelHandler):
      """NOTE: permissions.py imports ModelHandler from `.model`
      (handlers/model.py:16, over BaseView), NOT from `.handler`
      (handlers/handler.py:4, over ModelView). Confirm M1's enforcement covers
      this base's own put/patch (model.py:216,252) before relying on it."""
  ```

### Module 5: Privileged-grant endpoint
- **Path**: `navigator_auth/handlers/users/role.py` (new),
  `navigator_auth/handlers/__init__.py` (modifies)
- **Responsibility**: The single, auditable way to change a privileged flag now
  that no CRUD path accepts one.
- **Depends on**: M1, M6.
- **NOT delegation-eligible.**
- **Interface Skeleton**:
  ```python
  # navigator_auth/handlers/users/role.py  (new)
  class UserRoleHandler(OwnerOrSuperuserGuard, ModelHandler):
      """POST /api/v1/users/{id}/role — change is_superuser / user_role / is_staff.

      Gated by the `users:grant_role` ABAC action. The separation is structural,
      the same argument as FEAT-106's mfa:disenroll: admin_full_access.yaml
      wildcards its RESOURCES (uri:*) at priority 100 but ENUMERATES its actions
      with no wildcard (verified: §6), so a new action string falls outside it,
      and policy_allows() fails closed when no policy matches.

      Refuses a self-grant: the acting user may not raise their own flags, and
      may not grant a flag they do not themselves hold. Writes an audit record
      with actor, target, old and new value.
      """
  # navigator_auth/handlers/__init__.py  (modifies)
  # verified anchor: `    UserManager.configure(app, '/api/v1/users')`  __init__.py:38
  ```

### Module 6: ABAC policy pack
- **Path**: `navigator_auth/abac/default_policies/auth_crud_admin_access.yaml` (new)
- **Responsibility**: Declare the five surfaces' admin policies plus
  `users:grant_role`. Configuration only, no Python.
- **Depends on**: nothing (names must match M2–M5).
- **Interface Skeleton**: shape verified in §6; `priority: 90`,
  `defaults: {effect: deny}`, one policy per surface with its action set and
  group, and `users_grant_role` granted to a group that is **not** `superuser`.

### Module 7: Regression tests
- **Path**: `tests/test_auth_crud_write_envelope.py` (new)
- **Responsibility**: Prove the escalation is closed, and that it was open.
- **Depends on**: M1–M6.
- **Interface Skeleton**: the probe that produced the §1 evidence lives at
  `/tmp/claude-1000/-home-jesuslara-proyectos-navigator-auth/19149647-3a2f-431a-99b8-0ef5f9dcb373/scratchpad/probe_usermanager_write.py`
  and should be folded in with its assertions inverted — the payload that set
  `is_superuser=True` must now be refused.

### Module 8: Documentation and changelog
- **Path**: `docs/auth_crud_authorization.rst` (new), `CHANGELOG.md` (modifies)
- **Responsibility**: The breaking-change notice and the operator contract.
- **Depends on**: all.

---

## 4. Test Specification

### Unit Tests

| Test | Module | Description |
|---|---|---|
| `test_owner_cannot_write_privileged_column` | M1 | The owner path refuses `is_superuser` on the owner's **own** row — the blanket allow at `guards.py:141` no longer covers writes. |
| `test_owner_can_write_profile_allowlist` | M1 | `first_name` etc. succeed for the owner. |
| `test_unknown_column_refused_by_default` | M1 | A column absent from both `writable_by_*` sets is refused (allowlist, not denylist). |
| `test_admin_cannot_write_privileged_column` | M1 | The admin path refuses `is_superuser` too. |
| `test_admin_can_write_admin_allowlist` | M1 | `is_active` / `email` succeed for the admin path. |
| `test_refusal_names_no_hidden_column` | M1 | The 403 body does not disclose a column the caller may not see. |
| `test_feat105_handlers_unchanged` | M1 | `UserIdentityHandler`, `UserAccountHandler`, `PartnerKeyHandler` keep their existing behaviour with the new attributes defaulting empty (G7). |
| `test_usermanager_escalation_payload_refused` | M2 | **The inverted probe**: the §1 payload (`is_superuser`, `is_staff`, `user_role`, `password`) is refused and the model is unmodified. |
| `test_usermanager_has_no_password_hooks` | M2 | `_set_password` / `_calculate_password` are gone, so no CRUD path hashes a password. |
| `test_usermanager_guard_first_in_mro` | M2 | Guard precedes the model base, as in `userattrs.py:363`. |
| `test_usergroup_owner_column_is_none` | M3 | Guards against a future "fix" that sets it to `user_id`, which would re-open self-grant. |
| `test_user_cannot_self_join_group` | M3 | A non-admin POST to the membership route is refused. |
| `test_user_cannot_grant_permission_to_group` | M3 | Same for `GroupPermission`. |
| `test_group_definition_allowlist` | M4 | `group_name`/`description` writable by admin; `group_id` never. |
| `test_permission_handler_uses_baseview_base` | M4 | The enforcement covers `handlers/model.py`'s own write path, not only `ModelView._set_update`. |
| `test_role_endpoint_requires_grant_action` | M5 | A superuser without `users:grant_role` is refused. |
| `test_role_endpoint_refuses_self_grant` | M5 | An actor cannot raise their own flags. |
| `test_role_endpoint_refuses_granting_unheld_flag` | M5 | Cannot grant what you do not hold. |
| `test_role_endpoint_audits` | M5 | Actor, target, old and new value recorded. |
| `test_policy_pack_parses` | M6 | The YAML yields the six policies with the right actions, groups and effect. |
| `test_grant_role_absent_from_admin_full_access` | M6 | Asserts the property the separation rests on: `admin_full_access.yaml` does not wildcard actions. |

### Integration Tests

| Test | Description |
|---|---|
| `test_authenticated_user_cannot_escalate_via_users_crud` | End-to-end over HTTP: an ordinary authenticated session PATCHes `/api/v1/users/{id}` with `is_superuser: true` and gets 403; the row is unchanged. |
| `test_authenticated_user_cannot_escalate_via_user_groups` | Same for joining the `superuser` group. |
| `test_authenticated_user_cannot_escalate_via_group_permissions` | Same for granting a permission. |
| `test_admin_can_still_administer_users` | A properly authorized admin updates a non-privileged column successfully (G4 did not over-close). |
| `test_user_can_still_edit_own_profile` | Owner profile edit still works. |
| `test_password_change_still_works` | `UserSession.password_change` is unaffected by removing the CRUD hooks. |
| `test_role_grant_end_to_end` | Authorized grant succeeds and is audited; unauthorized is refused. |

### Validation Contract

tests:
- tests/test_auth_crud_write_envelope.py
- tests/unit/handlers/test_owner_superuser_guard.py
- tests/unit/handlers/test_user_identity_handler_access.py
- tests/unit/handlers/test_auth_model_policy_pack.py
- tests/test_check_superuser.py
- tests/test_allowed.py
- tests/test_policy_allows.py
markers: none

### Test Data / Fixtures

```python
# extends tests/conftest.py
@pytest.fixture
def ordinary_session(): ...     # authenticated, not superuser, no grant action
@pytest.fixture
def admin_session(): ...        # superuser WITH the surface's policy
@pytest.fixture
def grantor_session(): ...      # holds users:grant_role
@pytest.fixture
def escalation_payload():       # the §1 payload, verbatim
    return {"is_superuser": True, "is_staff": True, "user_role": 10,
            "email": "attacker@evil.test", "password": "hunter2"}
```

---

## 5. Acceptance Criteria

> This feature is complete when ALL of the following are true:

- [ ] **AC1** — `pytest tests/test_auth_crud_write_envelope.py -v` passes.
- [ ] **AC2** — FEAT-105's suites still pass unchanged:
  `pytest tests/unit/handlers/ tests/test_check_superuser.py tests/test_allowed.py
  tests/test_policy_allows.py -v` (G7).
- [ ] **AC3** — The §1 payload is **refused** on `/api/v1/users/{id}` for every
  actor, owner included, and the row is unmodified.
- [ ] **AC4** — `is_superuser`, `user_role` and `is_staff` are writable by **no**
  CRUD path on any of the five handlers.
- [ ] **AC5** — A column absent from both `writable_by_*` sets is refused
  (allowlist semantics, G3). Adding a column to `User` does not make it writable.
- [ ] **AC6** — An ordinary authenticated session cannot join a group or grant a
  permission.
- [ ] **AC7** — `UserGroupManager.owner_column is None` and
  `GroupPermissionManager.owner_column is None`.
- [ ] **AC8** — No `_set_password` / `_calculate_password` on `UserManager`, and
  `grep -rn "set_basic_password" navigator_auth/handlers/users/user.py` is empty.
- [ ] **AC9** — `UserSession.password_change`, `password_reset` and `user_profile`
  behave exactly as before.
- [ ] **AC10** — An authorized admin can still update a non-privileged column of
  another user, and an owner can still edit their own profile allowlist (G4).
- [ ] **AC11** — The role endpoint requires `users:grant_role`, refuses a
  self-grant, refuses granting an unheld flag, and audits every call.
- [ ] **AC12** — `users:grant_role` is **not** reachable through
  `admin_full_access.yaml` (its `actions:` list stays enumerated, no wildcard).
- [ ] **AC13** — The write enforcement holds on **both** handler bases:
  `handlers/handler.py:4` (via `ModelView._set_update`) and
  `handlers/model.py:16` (via its own `put`/`patch` at `:216`/`:252`).
- [ ] **AC14** — Every refusal is audited through the guard's existing
  `audit_decision()` and discloses no column the caller may not see.
- [ ] **AC15** — `docs/auth_crud_authorization.rst` and `CHANGELOG.md` document
  the breaking change (§10).

---

## 6. Codebase Contract

> **CRITICAL — Anti-Hallucination Anchor**
> This section is the single source of truth for what exists in the codebase.

**Verified against**: `d820852` (dev), 2026-11-06.

### Verified Imports

```python
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard   # guards.py:31
from navigator_auth.handlers.redaction import safe_fields          # redaction.py:36
from navigator_auth.handlers.handler import ModelHandler           # handler.py:4  (over ModelView)
from navigator_auth.handlers.model import ModelHandler             # model.py:16   (over BaseView) — DIFFERENT CLASS
from navigator_auth.models import User, Group, UserGroup, GroupPermission, Permission
#   User:39 · Group:188 · UserGroup:209 · Permission:223 · GroupPermission:243
from navigator_auth.decorators import policy_allows                # used by guards.py
from navigator.views.model import ModelView                        # site-packages
```

### Existing Class Signatures

```python
# navigator_auth/handlers/guards.py:31
class OwnerOrSuperuserGuard:
    owner_column: Optional[str] = "user_id"                                  # :52
    credential_columns: frozenset[str] = frozenset()                         # :53
    public_columns: frozenset[str] = frozenset()                             # :54  SERIALIZATION allowlist
    policy_name: Optional[str] = None                                        # :55
    superuser_actions: frozenset[str] = frozenset({"read", "revoke", "delete"})  # :56

    async def _session_info(self) -> tuple[Any, dict, Any]: ...              # raises 401
    async def authorize_row(self, action, owner_id: Optional[int], ...):     # :114
        # :140-141 — the blanket owner allow this feature must narrow:
        #   user_id, is_superuser = await self.acting_user()
        #   if self.owner_column is not None and owner_id is not None and str(owner_id) == str(user_id):
        #       return True
        # :142-158 — not-superuser / action-not-in-superuser_actions /
        #   no-policy_name → refuse; then policy_allows(); audit_decision()
    async def audit_decision(self, action, allowed, owner_id, reason): ...    # :282
```

```python
# The five handlers to harden, with their bases.
class UserManager(ModelView): ...                    # handlers/users/user.py:11
    def required_by_put(self):
        return ['first_name', 'last_name', 'display_name', 'username', 'email']   # :24
    async def _set_password(self, value, column, **kwargs): ...        # to be REMOVED
    async def _calculate_password(self, value, column, *a, **kw): ...  # to be REMOVED

class GroupManager(ModelHandler): ...                # handlers/groups.py:14   (handler.py base)
class UserGroupManager(ModelHandler): ...            # handlers/groups.py:21   (handler.py base)
class GroupPermissionManager(ModelHandler): ...      # handlers/groups.py:28   (handler.py base)
class PermissionHandler(ModelHandler): ...           # handlers/permissions.py:7 (model.py base!)

# The pattern to copy — FEAT-105, already guarded:
class UserIdentityHandler(OwnerOrSuperuserGuard, ModelHandler): ...  # userattrs.py:363
class UserAccountHandler(OwnerOrSuperuserGuard, ModelHandler): ...   # userattrs.py:17
class PartnerKeyHandler(OwnerOrSuperuserGuard, ModelHandler): ...    # partners.py:33
```

```python
# The two different ModelHandler bases — both must be covered.
# navigator_auth/handlers/handler.py:4
class ModelHandler(ModelView):
    dbname: str = 'authdb'
    async def _set_created_by(self, value, column, **kwargs): ...

# navigator_auth/handlers/model.py:16  — 446 lines, a local reimplementation
class ModelHandler(BaseView):
    def __init__(self, request, *args, **kwargs): ...   # :22
    async def get(self): ...                            # :122
    async def put(self): ...                            # :216
    async def patch(self): ...                          # :252
```

```python
# site-packages/navigator/views/model.py — the unguarded write path (the root cause)
class ModelView(AbstractModel):
    _hidden: list = []                       # :79 — RESPONSE filter only
    #   populated from `repr is False` metadata     :145-148
    #   consumed when returning data                :178-179
    async def _calculate_column(self, name, value, column, data=None, **kw): ...
    async def _set_update(self, model, data):          # :629
        """for key, val in data.items():
               if key in model.get_fields():   ← the ONLY check. No allowlist.
                   ... model.set(key, newval)"""
    async def patch(self): ...                          # :691
    async def put(self): ...                            # :907
# MRO: ModelView → AbstractModel → BaseView → CorsViewMixin → _PreflightHandler
#      → BaseHandler → View → AbstractView → ABC → object
#      (no authentication or authorization of its own)
```

```python
# navigator_auth/models.py — the five models and their privileged columns.
class User(Model):                                      # :39
    user_role: UserType = Column(required=False, widget="/properties/select")  # :53
    is_superuser: bool = Column(required=True, default=False)                  # :54
    is_staff: bool = Column(required=False, default=True)                      # :55
    is_active: bool = Column(required=True, default=True)                      # :58
    password: str = Column(required=False, max=255, secret=True, repr=False)   # :51
    email: str = Column(required=False, max=254, label="User's Email")         # :49

class Group(Model):                                     # :188
    group_id / group_name / is_active / client_id / description / created_at
    / updated_at / created_by                                                  # :189-198

class UserGroup(Model):                                 # :209
    user_id: User = Column(required=True, primary_key=True)                    # :210
    group_id: Group = Column(required=True, primary_key=True)                  # :211
    # composite PK ⇒ the row's "owner" is its beneficiary ⇒ owner_column MUST be None

class Permission(Model):                                # :223
    permission_id / permission / description / created_at / updated_at         # :224-228

class GroupPermission(Model):                           # :243
    group_id: Group = Column(required=True, primary_key=True)                  # :246
    permission_id: Permission = Column(required=True, primary_key=True)        # :247
```

```python
# The retained, correct password/profile paths — do not change.
class UserSession(BaseHandler):                         # handlers/users/session.py:18
    async def password_change(self, request): ...        # :119 requires old_password;
    #   403s when the URL userid != session user_id      # :145-148
    async def password_reset(self, request): ...         # :170
    async def user_profile(self, request): ...           # :244
def set_basic_password(password, token_num=6, iterations=80000, salt=None): ...
def check_password(current_password, password): ...      # handlers/users/passwd.py
```

**Key facts**

- `AUTHORIZATION_MIDDLEWARES = ()` (`navigator_auth/conf.py:264`) — no blanket
  ABAC middleware by default, so a handler that does not authorize itself is
  authorized by authentication alone.
- `ABAC_DEFAULT_EFFECT = "deny"` (`conf.py:710`) applies to **policy evaluation**,
  not to routes nobody evaluates.
- No policy in `abac/default_policies/` or `settings/` mentions `/api/v1/users`.
- `admin_full_access.yaml` grants `superuser`/`admin` resources
  `tool:* kb:* vector:* agent:* mcp:* uri:*` at `priority: 100` but **enumerates
  its actions with no wildcard** — which is what keeps `users:grant_role` outside
  it (AC12), the same mechanism FEAT-106 relies on for `mfa:disenroll`.
- `policy_allows()` fails closed when a named policy is absent (FEAT-105
  TASK-119), so shipping the pack is what *enables* admin access, never what
  grants escalation.
- The FEAT-105 pack shape to copy, from
  `abac/default_policies/auth_model_admin_access.yaml`: `version: "1.0"`,
  `defaults: {effect: deny}`, then per policy `name` / `effect: allow` /
  `resources: ["uri:/api/v1/<surface>*"]` / `actions: [...]` /
  `subjects: {groups: [...]}` / `priority: 90` / `enforcing: true`.

### Integration Points

| New Component | Connects To | Via | Verified At |
|---|---|---|---|
| `writable_by_owner` / `writable_by_admin` / `privileged_columns` | `OwnerOrSuperuserGuard` | new class attributes | `navigator_auth/handlers/guards.py:52-56` |
| `authorize_columns()` | `authorize_row()` owner fast-path | called before the early `return True` for write actions | `navigator_auth/handlers/guards.py:141` |
| write enforcement | `ModelView._set_update` | the `handlers/handler.py:4` base funnels here | `navigator/views/model.py:629` |
| write enforcement | `handlers/model.py` `put` / `patch` | the other base's own write path | `navigator_auth/handlers/model.py:216,252` |
| `UserManager` | `OwnerOrSuperuserGuard` | base change, guard first in MRO | `navigator_auth/handlers/users/user.py:11` |
| `UserRoleHandler` | `users:grant_role` policy | `policy_allows()` via the guard | `navigator_auth/handlers/guards.py:151` |
| new routes | `handlers/__init__.py` `setup_handlers` | registration | `navigator_auth/handlers/__init__.py:38` |
| every refusal | `audit_decision()` | existing audit path | `navigator_auth/handlers/guards.py:282` |

### Does NOT Exist (Anti-Hallucination)

- ~~a write-column allowlist anywhere in `OwnerOrSuperuserGuard`~~ — it has
  `public_columns` (serialization) and `credential_columns` (never-serialize)
  only. **This is the gap this feature fills**; do not assume the guard already
  does it.
- ~~`writable_by_owner`, `writable_by_admin`, `privileged_columns`,
  `authorize_columns()`~~ — none exist yet.
- ~~a write allowlist in `ModelView`~~ — `_hidden` is a response filter, not a
  write gate (`navigator/views/model.py:145-148,178-179`).
- ~~an ABAC policy covering `/api/v1/users`, `/api/v1/groups`,
  `/api/v1/user_groups`, `/api/v1/permissions`~~ — none.
- ~~`users:grant_role`~~ and ~~`UserRoleHandler`~~ — do not exist.
- ~~a blanket authorization middleware~~ — `AUTHORIZATION_MIDDLEWARES = ()`
  (`conf.py:264`). Do not assume requests are authorized before reaching a
  handler.
- ~~one single `ModelHandler`~~ — there are **two** unrelated classes with that
  name (`handlers/handler.py:4` over `ModelView`, `handlers/model.py:16` over
  `BaseView`). Check which one a handler imports before reasoning about its write
  path.
- ~~`User.is_superuser` being read-only or `repr=False`~~ — it is a plain writable
  column (`models.py:54`).

### Edit Sites (Blueprint Anchors)

> Verified against: `d820852`. `/sdd-task` MUST re-run the `grep -c` per row.

| File | Action | Verbatim anchor line | Verified at | Occurrences |
|---|---|---|---|---|
| `navigator_auth/handlers/guards.py` | MODIFY | `    superuser_actions: frozenset[str] = frozenset({"read", "revoke", "delete"})` | `guards.py:56` | 1 |
| `navigator_auth/handlers/guards.py` | MODIFY | `        if self.owner_column is not None and owner_id is not None and str(owner_id) == str(user_id):` | `guards.py:141` | 1 |
| `navigator_auth/handlers/users/user.py` | MODIFY | `class UserManager(ModelView):` | `user.py:11` | 1 |
| `navigator_auth/handlers/users/user.py` | MODIFY | `        return ['first_name', 'last_name', 'display_name', 'username', 'email']` | `user.py:24` | 1 |
| `navigator_auth/handlers/groups.py` | MODIFY | `class GroupManager(ModelHandler):` | `groups.py:14` | 1 |
| `navigator_auth/handlers/groups.py` | MODIFY | `class UserGroupManager(ModelHandler):` | `groups.py:21` | 1 |
| `navigator_auth/handlers/groups.py` | MODIFY | `class GroupPermissionManager(ModelHandler):` | `groups.py:28` | 1 |
| `navigator_auth/handlers/permissions.py` | MODIFY | `class PermissionHandler(ModelHandler):` | `permissions.py:7` | 1 |
| `navigator_auth/handlers/__init__.py` | MODIFY | `    UserManager.configure(app, '/api/v1/users')` | `__init__.py:38` | 1 |
| `navigator_auth/handlers/model.py` | MODIFY | `(unverified — check before use)` | — | — |
| `navigator_auth/handlers/users/role.py` | CREATE | — | — | — |
| `navigator_auth/abac/default_policies/auth_crud_admin_access.yaml` | CREATE | — | — | — |
| `tests/test_auth_crud_write_envelope.py` | CREATE | — | — | — |
| `docs/auth_crud_authorization.rst` | CREATE | — | — | — |

---

## 7. Implementation Notes & Constraints

### Patterns to Follow

- Guard mixin **first** in the MRO, as `userattrs.py:363` does, so its hooks win
  over the model view's.
- Allowlists, never denylists (G3). A denylist makes the next column added to a
  model writable by default — the exact mechanism that produced this
  vulnerability.
- Per-surface behaviour is *configuration*, not forked logic — the principle
  `guards.py:34-36` states explicitly. Resist adding an override per handler.
- Every refusal raised, not returned (`guards.py:130-137`): a falsy return from a
  `_pre_*` hook produces a fixed 412 instead of the intended status.
- Every decision audited through the existing `audit_decision()`.
- A refusal must not disclose a column the caller cannot see — reuse
  `redaction.py:36` `safe_fields()`.

### Known Risks / Gotchas

- **R1 — this is a breaking change for any client that writes privileged columns
  through the CRUD.** An admin UI that sets `is_superuser` via
  `PATCH /api/v1/users/{id}` will start getting 403 and must move to the role
  endpoint. That is the point of the feature, but it needs the changelog entry
  and the migration note in §10, not a silent 403 in production.
- **R2 — the owner fast-path edit is the whole feature, and it is one line.**
  `guards.py:141` returns `True` before any check. Narrowing it incorrectly
  either leaves the hole open or locks every owner out of their own profile.
  Review the clause placement, not just its presence.
- **R3 — two handler bases, and it is easy to harden only one.** `groups.py`
  imports `ModelHandler` from `.handler` (over `ModelView`), `permissions.py`
  from `.model` (over `BaseView`, 446 lines with its own `put`/`patch`). An
  enforcement hook on `ModelView._set_update` alone silently misses
  `PermissionHandler` — and the FEAT-105 handlers use the `model.py` base too, so
  a hook only there would miss `groups.py`. AC13 exists for this.
- **R4 — `owner_column = "user_id"` on a mapping table re-opens the hole.**
  It reads like a bug fix ("surely a user owns their own membership"). It is the
  escalation. `test_usergroup_owner_column_is_none` is a guard against a
  well-intentioned future change.
- **R5 — removing `_set_password` could be read as a regression.** It is not:
  `UserSession.password_change` (`session.py:119`) already requires
  `old_password` and matches the session user against the URL. AC9 pins it.
- **R6 — the reachability premise is verified by code reading, not by a live
  request.** The *write path* was confirmed by execution (§1), but "any
  authenticated user can reach `PATCH /api/v1/users/{id}`" rests on the four
  static facts in §1 — no DB or Redis was available to run the HTTP path. The
  integration tests in §4 are what close that gap; run them first, before
  assuming the scope is right.
- **R7 — the role endpoint must refuse a self-grant**, or it becomes the
  escalation it replaces. Also refuse granting a flag the actor does not hold.
- **R8 — do not widen `admin_full_access.yaml`.** Adding `users:*` or `"*"` to
  its `actions` list would collapse the separation AC12 asserts, here and for
  FEAT-106's `mfa:disenroll`.
- **R9 — `AUTHORIZATION_MIDDLEWARES` stays empty.** This feature deliberately
  does not change it (§1 Non-Goals), so each handler must authorize itself. A
  future decision to add a blanket middleware would be a different, larger change.
- **R10 — the shared `.venv` is editable-installed against the main checkout**, so
  a bare `pytest` in a worktree can import another branch's compiled extensions.
  Rebuild before trusting a surprising result; never `uv sync` from a worktree.

### External Dependencies

| Package | Version | Reason |
|---|---|---|
| — | — | **None.** No new dependency: this is guard logic, handler configuration and YAML policy. |

---

## Decisions

<!-- OPTIONAL, authored. Omitted: no decision-audit taxonomy is configured in this
     repository, so there are no `about:` subsystem ids to cite. The architectural
     decisions are recorded in §2 Overview, §7 and §8. -->

## Decision Waivers

<!-- None. -->

## Consequences

<!-- GENERATED by `parrot sdd spec consequences <spec> --render` — do not edit by hand. -->

---

## 8. Open Questions

- [x] Verify the escalation empirically before specifying? — *Resolved with the user*: yes. Confirmed by executing the real `UserManager` write hooks over the real `User` model: `is_superuser` False→True, `is_staff` False→True, `user_role`→10, `email` overwritten, `password` set and hashed. → §1, M7.
- [x] One spec or a hotfix first? — *Resolved with the user*: **one feature spec** covering everything, on `dev`. → frontmatter, §1.
- [x] Scope — just `UserManager`, or all five unguarded handlers? — *Resolved with the user*: **all five**, because `UserGroupManager` and `GroupPermissionManager` are independent escalation routes through the tables ABAC itself reads. → §1 problem table, M3, M4.
- [x] May a superuser UPDATE another user through the CRUD? — *Resolved with the user*: yes, but **only on a non-privileged allowlist**. `superuser_actions` gains `update`, bounded by `writable_by_admin`. → §2 Data Models, AC10.
- [x] May a user edit their own row, and which columns? — *Resolved with the user*: a **profile allowlist** (`first_name`, `last_name`, `display_name`, `title`, `avatar`, `timezone`), never the privileged columns. This also closes the `TODO: Allow User editing own data` in `UserManager`'s own docstring. → §2, AC10.
- [x] How do privileged flags get set legitimately? — *Resolved with the user*: a **dedicated endpoint with its own ABAC action** (`users:grant_role`), audited, never through the generic CRUD. → M5, AC11, AC12.
- [ ] Which group should hold `users:grant_role` by default? FEAT-106 faces the same question for `mfa:disenroll` and named `security_admin` provisionally; neither group exists yet. Decide once for both, so a deployment does not end up with two bespoke groups. — *Owner: Jesus Lara*
- [ ] Should `GroupManager` and `PermissionHandler` (the *definition* CRUDs, not the assignment ones) also require a non-`superuser` group, or is `superuser` adequate there? The escalation routes are the two mapping tables; these two are lower risk and stricter settings cost operability. — *Owner: Jesus Lara*
- [ ] Does any existing deployment write privileged columns through the CRUD today? That determines whether R1's breaking change needs a deprecation window or can ship directly. — *Owner: Jesus Lara*

---

## 9. Design Research Cross-Check

> Independent design opinion from the `codex` seat over the **accepted exploration
> doc** (never over this spec).
> Status: **skipped** (no accepted exploration document — this spec was authored
> directly from `/sdd-spec` with interactive clarification, so §3b's precondition
> of an `accepted` brainstorm or proposal was not met).

A cross-check is still worth running before implementation, over this spec's §2
and §6 rather than over an exploration doc — the FEAT-106 pass found two real
defects in a spec of the same shape, and the one-line change at `guards.py:141`
(§7 R2) is exactly the kind of edit an independent reader catches.

| # | Suggestion (kind) | Disposition | Reason | Landed in |
|---|---|---|---|---|
| — | — | — | — | — |

Summary: **0** confirmed · **0** rejected · **0** escalated (not run).

---

## 10. Documentation

- **Policy**: `required`
- **Pages**:
  - `docs/auth_crud_authorization.rst` — create. Must cover: which handlers are
    guarded and with what configuration; the difference between
    `public_columns` (read) and the new `writable_by_*` (write); why the mapping
    tables have `owner_column = None`; the new role endpoint and the ABAC action
    it needs; which group must hold it; the warning that widening
    `admin_full_access.yaml`'s `actions` collapses the separation; and that
    `AUTHORIZATION_MIDDLEWARES` is empty by default, so a custom handler that
    does not use the guard is authorized by authentication alone.
  - `CHANGELOG.md` — update, **with a breaking-change notice**: privileged
    columns are no longer writable through `PATCH`/`PUT /api/v1/users/{id}`;
    callers must use `POST /api/v1/users/{id}/role`. Passwords are no longer
    settable through the user CRUD; use `password_change` / `password_reset`.
- **API modules**: `navigator_auth.handlers`

---

## Worktree Strategy

- **Default isolation unit**: `per-spec`.
- **Rationale**: M1 changes `guards.py`, which every other module depends on, and
  M2–M5 all touch handlers that share the guard's contract. The ordering is
  forced — guard capability, then the five configurations, then the role endpoint
  that depends on the privileged columns being closed. M1, M2 and M5 are not
  delegation-eligible and must land in order.
- **Parallelizable within the worktree**: M3 and M4 once M1 exists; M6 and M8 at
  any point after the names are fixed.
- **Cross-feature dependencies**: **FEAT-106 overlaps on policy conventions, not
  on files.** It adds `mfa:disenroll` under the same `default_policies/`
  convention and faces the identical "which group holds the privileged action"
  question (§8). Merging both without deciding that once will produce two
  bespoke groups. No file conflicts: FEAT-106 touches `basic.py`, `auth.py`,
  `conf.py` and a new `mfa/` package; this touches `guards.py` and the handlers.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-11-06 | Jesus Lara | Initial draft. Escalation confirmed by execution; scope widened from `UserManager` to all five unguarded handlers after finding two further routes. |
