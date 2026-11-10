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
- **G8** — Membership of a **protected group** is a privilege grant and is
  treated as one. Groups are matched by *name* everywhere authorization looks
  at them, so joining `superuser` is equivalent to `is_superuser`
  (`decorators.py:288-311`) and joining `security_admin` is equivalent to
  holding `users:grant_role` and FEAT-106's `mfa:disenroll`. Adding a member to
  a protected group, or renaming / deleting / re-activating one, needs
  `users:grant_role` — never the plain `superuser` CRUD policy, never
  self-service.

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
3. **A group is identified by its name, so the group CRUDs can grant
   privilege too.** `_check_superuser()` treats membership of the group named
   `SUPERUSER_GROUP = "superuser"` as superuser (`decorators.py:288-311`), and
   every ABAC policy matches `subjects.groups` against the *names* in
   `userinfo["groups"]` (`abac/policies/policy.py:22`). With only the
   `superuser` CRUD policy on `UserGroupManager` and `GroupManager`, a plain
   superuser could (a) add themselves to `security_admin` and inherit
   `users:grant_role` — and FEAT-106's `mfa:disenroll` — or (b) add a member to
   an ordinary group and then rename it to `security_admin` or `superuser`; and
   adding anyone to the `superuser` group grants `is_superuser` without going
   through the role endpoint (G5). The separation of duties both features rely
   on would be nominal. Hence **protected groups** (M9): a configurable set,
   always containing `superuser`, whose membership and definition can only be
   changed by an actor holding `users:grant_role`, and never for oneself.

So the design is: **one new guard capability, five per-surface
configurations, one new endpoint** for the privileged grants that the CRUD
will no longer accept, **and protected groups** so the group CRUDs cannot
become a back door to those same grants.

### Component Diagram

```
                         OwnerOrSuperuserGuard  (handlers/guards.py)
   existing, read-side:   public_columns · credential_columns
   existing, verb-side:   superuser_actions · policy_name · owner_column
   NEW, write-side:       writable_by_owner · writable_by_admin · privileged_columns
   NEW, group-side:       authorize_protected_group()  ← AUTH_PROTECTED_GROUPS (conf.py)
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

            protected groups (superuser, security_admin, …): membership,
            rename, delete, (de)activation only with `users:grant_role`,
            never for oneself  → UserGroupManager, GroupManager (M9)
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
| `navigator_auth/conf.py` | modifies | New setting `AUTH_PROTECTED_GROUPS` (M9), next to the ABAC settings. |
| `decorators.SUPERUSER_GROUP` | uses | `decorators.py:288`. Always part of the effective protected set, whatever the setting says. |
| `decorators.policy_allows()` | uses | Already called by `authorize_row()` with `resource=self.request.path` (`guards.py:151-156`); M9 calls it a second time with `users_grant_role` / `users:grant_role`. |

### Data Models

No new tables and no model changes. What this feature adds is **declarative
configuration per handler**, so the allowlists are the "data model":

```python
# The new guard attributes (navigator_auth/handlers/guards.py)
writable_by_owner: frozenset[str] = frozenset()   # owner may UPDATE these, nothing else
writable_by_admin: frozenset[str] = frozenset()   # admin path may UPDATE these
creatable_by_admin: Optional[frozenset[str]] = None  # admin path may CREATE with these;
                                                  # None → same as writable_by_admin
privileged_columns: frozenset[str] = frozenset()  # writable by NO CRUD path, ever
                                                  # (create or update)

# Protected groups (navigator_auth/conf.py) — M9
AUTH_PROTECTED_GROUPS = [e.strip() for e in config.get(
    "AUTH_PROTECTED_GROUPS", fallback="superuser,security_admin").split(",") if e.strip()]
# Effective set = set(AUTH_PROTECTED_GROUPS) | {SUPERUSER_GROUP}: an operator
# may ADD groups (any group named in a privileged policy) but can never
# un-protect `superuser`, whose membership is is_superuser.

# Per-surface configuration decided by this spec
#
# UserManager → User (models.py:39)
owner_column       = "user_id"
writable_by_owner  = {"first_name", "last_name", "display_name", "title",
                      "avatar", "timezone"}
writable_by_admin  = writable_by_owner | {"is_active", "email", "alt_email"}
creatable_by_admin = writable_by_admin | {"username"}   # username set once, never updated
privileged_columns = {"is_superuser", "user_role", "is_staff", "password",
                      "userid", "user_id", "created_at", "last_login"}
superuser_actions  = {"read", "create", "update", "delete"}
policy_name        = "users_admin_access"
# Created users get the model defaults for every privileged column and NO
# password; the initial password goes through UserSession.password_reset
# (session.py:170), which also sets is_new=True (§8).

# UserGroupManager → UserGroup (models.py:209) — a mapping table
owner_column       = None          # ownership would be self-certifying (§2 Overview)
writable_by_owner  = frozenset()
writable_by_admin  = frozenset()   # rows are created/deleted whole, never edited
creatable_by_admin = {"user_id", "group_id"}   # the composite PK IS the row
privileged_columns = frozenset()   # immutability comes from update ∉ superuser_actions
superuser_actions  = {"read", "create", "delete"}
policy_name        = "user_groups_admin_access"
# + M9: create/delete of a row whose group is protected ALSO needs
#   users:grant_role, refuses actor == row.user_id on create, and refuses a
#   protected group the actor does not belong to.

# GroupPermissionManager → GroupPermission (models.py:243) — a mapping table
owner_column       = None
writable_by_admin  = frozenset()
creatable_by_admin = {"group_id", "permission_id"}
privileged_columns = frozenset()
superuser_actions  = {"read", "create", "delete"}
policy_name        = "group_permissions_admin_access"

# GroupManager → Group (models.py:188)
owner_column       = None
writable_by_admin  = {"group_name", "description", "is_active", "client_id"}
privileged_columns = {"group_id", "created_at", "created_by"}
superuser_actions  = {"read", "create", "update", "delete"}
policy_name        = "groups_admin_access"      # superuser — adequate for ordinary groups
# + M9: any create/update/delete whose OLD or NEW group_name is protected ALSO
#   needs users:grant_role. Closes "add members to `sales`, then rename it to
#   `security_admin`", and deleting / deactivating a protected group.

# PermissionHandler → Permission (models.py:223)
owner_column       = None
writable_by_admin  = {"permission", "description"}
privileged_columns = {"permission_id", "created_at"}
superuser_actions  = {"read", "create", "update", "delete"}
policy_name        = "permissions_admin_access" # superuser — adequate: no authorization
                                                # path matches a permission by name
```

`GroupPermissionManager` and `PermissionHandler` stay on the `superuser` policy
(§8): nothing in the package authorizes by permission name, so they carry no
equivalent of the group-name escalation.

### New Public Interfaces

```python
# navigator_auth/handlers/users/role.py  (new)
class UserRoleHandler(OwnerOrSuperuserGuard, ModelHandler):
    """The ONLY way to change a privileged user flag.

    POST /api/v1/users/{id}/role  {"is_superuser": bool, "user_role": int,
                                   "is_staff": bool}

    Gated by the `users:grant_role` ABAC action, which is deliberately absent
    from `admin_full_access.yaml`'s enumerated action list, so a stock
    superuser does not inherit it. Held by default by `security_admin` — the
    same group FEAT-106 uses for `mfa:disenroll`. Never self-service: an actor
    may not grant themselves a flag they do not already hold.
    """

# navigator_auth/handlers/guards.py  (modifies) — M9
class OwnerOrSuperuserGuard:
    async def authorize_protected_group(
        self, group_names: Iterable[str], *, member_id: Optional[int] = None
    ) -> None:
        """No-op unless one of `group_names` is protected. Otherwise refuse
        unless policy_allows("users_grant_role", action="users:grant_role"),
        refuse when member_id is the acting user (adding a member only), and
        refuse a protected group the acting user does not belong to — the
        group analogue of M5's "cannot grant what you do not hold". Raises;
        never returns False. Audits through audit_decision()."""
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
| M9: protected groups | **no** | — | Decides who can make someone superuser or `security_admin` through the group tables. The self-add refusal, the old-*and*-new-name check on rename, and the "always includes `superuser`" rule are each a one-clause mistake away from re-opening G8. |

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
      creatable_by_admin: Optional[frozenset[str]] = None   # None → writable_by_admin
      privileged_columns: frozenset[str] = frozenset()

      async def authorize_columns(
          self, payload: dict, *, is_owner: bool, creating: bool = False
      ) -> None:
          """Refuse the request when the payload touches a column this path may
          not write. Allowlist semantics: a key absent from the applicable set
          is refused, so a column added to the model later is closed by default
          (G3). The applicable set is:

              creating             → creatable_by_admin (or writable_by_admin)
              updating, owner      → writable_by_owner
              updating, admin path → writable_by_admin

          A key in `privileged_columns` is refused on every path, owner
          included, create included. There is no owner create path: a create
          always goes through the superuser path of authorize_row().

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
      # This includes CREATE: a user created through POST has no password
      # until a superuser calls password_reset, which also sets is_new=True.

      def required_by_put(self):
          """MUST become ['first_name', 'last_name', 'display_name'].
          verified anchor: user.py:24
          `return ['first_name', 'last_name', 'display_name', 'username', 'email']`
          Every required column must be writable on every path that can PUT,
          or PUT becomes unusable: 'username' is in no writable_by_* set
          (immutable after creation) and 'email' is not owner-writable.
          Required-field lists are not allowlists; writability is decided by
          writable_by_owner / writable_by_admin."""

      def required_by_post(self):
          """Replaces `required_by_post = required_by_put` (user.py:26):
          ['first_name', 'last_name', 'username', 'email'] — a subset of
          creatable_by_admin. POST is superuser-only (no owner create path)."""
  ```

### Module 3: Mapping handlers — `UserGroupManager`, `GroupPermissionManager`
- **Path**: `navigator_auth/handlers/groups.py` (modifies)
- **Responsibility**: Close the two escalation routes that go through the tables
  ABAC itself reads.
- **Depends on**: M1, M6, M9 (protected-group check on create/delete).
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

      The superuser path is enough for ordinary groups only. A row whose
      group is protected is additionally gated by M9.
      """

  class GroupPermissionManager(OwnerOrSuperuserGuard, ModelHandler):
      """Same reasoning; no owner column exists at all on this table.
      Stays on the plain superuser policy: no authorization path matches a
      permission by name (§2 Data Models)."""
  ```

### Module 4: Definition handlers — `GroupManager`, `PermissionHandler`
- **Path**: `navigator_auth/handlers/groups.py`, `navigator_auth/handlers/permissions.py`
  (modifies)
- **Responsibility**: Guard the group and permission definitions.
- **Depends on**: M1, M6, M9 (`GroupManager` protected-name check).
- **Interface Skeleton**:
  ```python
  # verified anchors: `class GroupManager(ModelHandler):`       groups.py:14
  #                   `class PermissionHandler(ModelHandler):`  permissions.py:7
  class GroupManager(OwnerOrSuperuserGuard, ModelHandler):
      """`superuser` policy for ordinary groups; a write touching a protected
      group (by its old or new name) is additionally gated by M9."""
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

      Consequence of the two rules together, by design: granting is_superuser
      needs an actor who is BOTH superuser and holds users:grant_role
      (by default, a superuser who is also in security_admin).
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
  group (the five surface policies → `superuser`), plus:
  ```yaml
  - name: users_grant_role
    effect: allow
    description: >-
      Change a user's privileged flags, and change membership or definition of
      a protected group. Deliberately NOT granted to `superuser`.
    # The guard passes resource=self.request.path (guards.py:151-156), so the
    # policy must cover all three routes that check this action.
    resources: ["uri:/api/v1/users*", "uri:/api/v1/user_groups*", "uri:/api/v1/groups*"]
    actions: ["users:grant_role"]
    subjects:
      groups: ["security_admin"]   # shared with FEAT-106's mfa:disenroll (§8)
    priority: 90
    enforcing: true
  ```

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

### Module 9: Protected groups
- **Path**: `navigator_auth/conf.py`, `navigator_auth/handlers/guards.py`,
  `navigator_auth/handlers/groups.py` (modifies)
- **Responsibility**: Stop the group CRUDs from granting what M5 reserves to
  `users:grant_role` (G8, §2 Overview point 3).
- **Depends on**: M1, M6. M3 and M4 call into it.
- **NOT delegation-eligible.**
- **Interface Skeleton**:
  ```python
  # navigator_auth/conf.py  (modifies) — next to ABAC_DEFAULT_EFFECT (:710)
  AUTH_PROTECTED_GROUPS = [e.strip() for e in config.get(
      "AUTH_PROTECTED_GROUPS", fallback="superuser,security_admin").split(",") if e.strip()]

  # navigator_auth/handlers/guards.py  (modifies)
  def protected_groups() -> frozenset[str]:
      """set(AUTH_PROTECTED_GROUPS) | {SUPERUSER_GROUP}. An operator can add
      to the set but cannot remove `superuser` from it."""

  class OwnerOrSuperuserGuard:
      async def authorize_protected_group(
          self, group_names: Iterable[str], *, member_id: Optional[int] = None
      ) -> None:
          """Runs AFTER authorize_row() has already passed the superuser path.

          1. No name in protected_groups() → return (ordinary group).
          2. policy_allows("users_grant_role", self.request,
                           action="users:grant_role",
                           resource=self.request.path) must allow → else 403.
          3. member_id is not None and str(member_id) == str(acting user) → 403
             (no self-add; removing oneself is a de-escalation and allowed).
          4. The acting user must belong to every protected group named —
             for `superuser`, "belongs" means _check_superuser() is True
             (flag OR group) — else 403. Same rule as M5's unheld flag.
          Every outcome audited via audit_decision(); refusals raised.
          """

  # navigator_auth/handlers/groups.py  (modifies) — the call sites
  # UserGroupManager, create & delete:
  #     resolve row.group_id → Group.group_name at write time (never trust a
  #     name from the payload), then
  #     authorize_protected_group([name], member_id=row.user_id if create else None)
  # GroupManager, create / update / delete:
  #     authorize_protected_group({stored_name, payload.get("group_name")} - {None})
  #     — BOTH the stored and the new name, so renaming INTO and OUT OF a
  #     protected name are both gated, and so is (de)activating or deleting one.
  ```
- **Bootstrap**: with `users:grant_role` held only by `security_admin` and
  self-add refused, nobody can add the *first* `security_admin` member through
  the API. That is intended — it is seeded out-of-band (SQL or a deployment
  script), exactly as FEAT-106's M11 leaves `mfa:disenroll` unusable until an
  operator ships the policy. §10 documents it.

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
| `test_grant_role_held_by_security_admin` | M6 | `users_grant_role` names `security_admin`, not `superuser`, and covers `/api/v1/users*`, `/api/v1/user_groups*` and `/api/v1/groups*`. |
| `test_create_uses_creatable_allowlist` | M1 | On create the payload is checked against `creatable_by_admin` (falling back to `writable_by_admin`); `privileged_columns` still refused. |
| `test_mapping_row_create_allowed_for_admin` | M1, M3 | A superuser with the surface policy can create a `UserGroup` / `GroupPermission` row for an **ordinary** group (the PK columns are creatable, not privileged). |
| `test_mapping_row_update_refused` | M3 | No path updates a mapping row: `update ∉ superuser_actions`, no owner column. |
| `test_usermanager_create_without_password` | M2 | A superuser POST with the §2 creatable columns succeeds; the stored row has no password and default privileged flags. |
| `test_usermanager_create_refuses_privileged_and_password` | M2 | A POST carrying `is_superuser` or `password` is refused, not silently dropped. |
| `test_usermanager_required_lists_are_writable` | M2 | `required_by_put() ⊆ writable_by_owner` and `required_by_post() ⊆ creatable_by_admin`. |
| `test_protected_groups_always_include_superuser` | M9 | `AUTH_PROTECTED_GROUPS=""` (or any list without it) still protects `superuser`. |
| `test_superuser_cannot_add_member_to_protected_group` | M9 | A superuser holding `user_groups_admin_access` but not `users:grant_role` cannot add anyone to `superuser` or `security_admin`. |
| `test_grantor_can_add_member_to_protected_group` | M9 | A superuser who holds `users:grant_role` and belongs to the group can add another user to it. |
| `test_no_self_add_to_protected_group` | M9 | Even a holder of `users:grant_role` cannot add themselves to a protected group. |
| `test_cannot_add_to_protected_group_not_held` | M9 | A `security_admin` member who is not superuser cannot add anyone to `superuser`. |
| `test_protected_group_resolved_from_db_not_payload` | M9 | The protected check uses the stored `group_name` for the `group_id`, not a name supplied in the request. |
| `test_rename_into_protected_name_refused` | M9 | Renaming an ordinary group to `security_admin` / `superuser` without `users:grant_role` is refused. |
| `test_rename_out_of_protected_name_refused` | M9 | Renaming, deactivating or deleting a protected group without `users:grant_role` is refused. |
| `test_ordinary_group_crud_needs_only_superuser` | M9 | Ordinary groups keep the plain superuser policy (no over-closing). |

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
| `test_superuser_cannot_escalate_via_security_admin_membership` | A plain superuser POSTs `/api/v1/user_groups` adding themselves to `security_admin` and gets 403; then tries the rename route (`PATCH /api/v1/groups/{id}` to `security_admin`) and gets 403. |
| `test_admin_can_create_user_then_reset_password` | Superuser POST `/api/v1/users` (no password) → 201; `password_reset` sets the password and `is_new=True`. |

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
def grantor_session(): ...      # superuser AND in security_admin → holds users:grant_role
@pytest.fixture
def security_admin_only_session(): ...  # in security_admin, NOT superuser
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
- [ ] **AC16** — `users:grant_role` is held by `security_admin` in the shipped
  pack — the same group as FEAT-106's `mfa:disenroll` — and by no policy that
  names `superuser`.
- [ ] **AC17** — Membership of a protected group can be added or removed, and a
  protected group renamed (into or out of a protected name), deactivated or
  deleted, **only** by an actor holding `users:grant_role` who belongs to that
  group; nobody can add themselves. Ordinary groups need only the `superuser`
  policy (G8).
- [ ] **AC18** — The effective protected set always contains `superuser`,
  whatever `AUTH_PROTECTED_GROUPS` says.
- [ ] **AC19** — A superuser can still create a user through
  `POST /api/v1/users`, limited to `creatable_by_admin`; the user is created
  with no password and default privileged flags (G4).
- [ ] **AC20** — The superuser path can create mapping rows for ordinary groups
  (`creatable_by_admin` holds their PK columns) and can update none.

---

## 6. Codebase Contract

> **CRITICAL — Anti-Hallucination Anchor**
> This section is the single source of truth for what exists in the codebase.

**Verified against**: `d820852` (dev), 2026-11-06. Rows added in revision 0.2
(M9, `creatable_by_admin`, user creation) verified against `b10a3a3`
(2026-11-11); `navigator_auth/` is unchanged between the two commits, so the
original anchors still hold.

### Verified Imports

```python
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard   # guards.py:31
from navigator_auth.handlers.redaction import safe_fields          # redaction.py:36
from navigator_auth.handlers.handler import ModelHandler           # handler.py:4  (over ModelView)
from navigator_auth.handlers.model import ModelHandler             # model.py:16   (over BaseView) — DIFFERENT CLASS
from navigator_auth.models import User, Group, UserGroup, GroupPermission, Permission
#   User:39 · Group:188 · UserGroup:209 · Permission:223 · GroupPermission:243
from navigator_auth.decorators import policy_allows                # used by guards.py
from navigator_auth.decorators import SUPERUSER_GROUP              # decorators.py:288 — "superuser"
from navigator_auth.decorators import _check_superuser             # decorators.py:291 — flag OR group name
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
    required_by_post = required_by_put                                  # :26 — POST creates users today
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
    async def password_reset(self, request): ...         # :170 any superuser, any userid;
    #   works on a user with no password; sets is_new=True — the initial-password
    #   path for users created through POST (§8)
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
- **Groups are identified by name in every authorization check.**
  `_check_superuser()` returns True for membership of `SUPERUSER_GROUP`
  (`decorators.py:288-311`, via `userinfo["groups"]` or `g.group` /
  `g.group_name`), and ABAC policies match `subjects.groups` with
  `set(ctx.userinfo["groups"]).isdisjoint(self.groups)`
  (`abac/policies/policy.py:22`). Renaming a group therefore changes who holds
  what — the basis of M9.
- **No authorization path matches a permission by name.** `Permission.permission`
  is only slugified on save (`models.py:232-233`); nothing in `decorators.py` or
  `abac/` reads it. That is why `PermissionHandler` / `GroupPermissionManager`
  stay on the plain `superuser` policy.
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
| `AUTH_PROTECTED_GROUPS` | `conf.py` | new setting after `ABAC_DEFAULT_EFFECT` | `navigator_auth/conf.py:710` |
| `protected_groups()` | `SUPERUSER_GROUP` | always unioned in | `navigator_auth/decorators.py:288` |
| `authorize_protected_group()` | `policy_allows()` | second call, `users_grant_role` / `users:grant_role`, `resource=self.request.path` | `navigator_auth/handlers/guards.py:151-156` |
| `authorize_protected_group()` | `_check_superuser()` | "belongs to `superuser`" test | `navigator_auth/decorators.py:291` |
| `UserManager.required_by_post` | own method | replaces the alias | `navigator_auth/handlers/users/user.py:26` |

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
- ~~`creatable_by_admin`, `authorize_protected_group()`, `protected_groups()`,
  `AUTH_PROTECTED_GROUPS`~~ — none exist yet.
- ~~a `security_admin` group~~ — not defined anywhere (FEAT-106 records the
  same). The pack *names* it; nothing may assume a deployment has created it.
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
| `navigator_auth/handlers/users/user.py` | MODIFY | `    required_by_post = required_by_put` | `user.py:26` | 1 |
| `navigator_auth/conf.py` | MODIFY | `ABAC_DEFAULT_EFFECT = config.get("ABAC_DEFAULT_EFFECT", fallback="deny")` | `conf.py:710` | 1 |
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
  and the migration note in §10, not a silent 403 in production. **Decided
  (§8): ships directly in 0.30.0, no deprecation window and no compatibility
  flag** — a transition period would keep the escalation open for its whole
  duration. Callers that break are identifiable from the 403s the guard
  already audits.
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
- **R11 — the protected set must list every group named by a privileged
  policy.** An operator who moves `users:grant_role` or `mfa:disenroll` to a
  group of their own, without adding that group to `AUTH_PROTECTED_GROUPS`,
  re-opens G8 for it: a plain superuser can join it. §10 states this next to
  the setting. Deriving the set from the policy pack automatically was
  considered and rejected: it couples the guard to PDP internals, and a
  configuration that is explicit and audited is easier to review.
- **R12 — nobody can add the first `security_admin` member through the API.**
  Intended (self-add refused, and nobody holds `users:grant_role` before the
  first member exists). Seed it out-of-band. Until then the role endpoint and
  protected-group changes are unusable — fail closed, as FEAT-106's
  `mfa:disenroll` is.
- **R13 — `password_reset` bounds the separation of duties.** It lets any
  superuser set any user's password (`session.py:170-205`), including a
  `security_admin` member's, and then sign in as them. Changing
  `password_reset` is a Non-Goal here (§1), so the separation that `users:grant_role`
  provides is only as strong as that endpoint. Mitigation available today:
  FEAT-106's OTP enforcement on `security_admin` members, which a password reset
  alone does not get past. Recommended follow-up: refuse `password_reset` on a
  member of a protected group unless the actor holds `users:grant_role`.

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
- [x] Which group should hold `users:grant_role` by default? — *Resolved with the user (2026-11-11)*: **`security_admin`, shared with FEAT-106's `mfa:disenroll`** (FEAT-106 is approved with that group). One privileged group to provision and document, not two. Granting `is_superuser` therefore needs an actor who is both superuser and `security_admin` (M5's "cannot grant what you do not hold"). → M5, M6, AC16, §10.
- [x] Should `GroupManager` and `PermissionHandler` require a non-`superuser` group? — *Resolved with the user (2026-11-11)*: **`superuser` is adequate for ordinary groups and for permissions, with protected groups on top.** Answering it showed that the question was framed too narrowly: groups are matched by *name* (`decorators.py:288-311`, `abac/policies/policy.py:22`), so with the `superuser` policy alone a superuser could join `security_admin`, or rename a group into it, and inherit `users:grant_role` and `mfa:disenroll`; and joining `superuser` is `is_superuser` without the role endpoint. Hence protected groups (`AUTH_PROTECTED_GROUPS`, default `superuser,security_admin`, `superuser` always included): adding or removing members, and renaming into or out of a protected name, deactivating or deleting the group, all need `users:grant_role`, the actor must belong to the group, and nobody can add themselves. `PermissionHandler` and `GroupPermissionManager` stay on `superuser`: nothing authorizes by permission name. → §2 Overview pt 3, G8, M9, AC17, AC18, R11–R13.
- [x] Does any existing deployment write privileged columns through the CRUD today? — *Resolved with the user (2026-11-11)*: **ship directly in 0.30.0**, breaking change with a CHANGELOG notice and migration note, no deprecation window and no compatibility flag. → R1, §10.
- [x] May a superuser still create users through `POST /api/v1/users`? — *Raised while resolving the above, resolved with the user (2026-11-11)*: the draft silently removed creation (`create ∉ superuser_actions` plus no password hooks), although `UserManager` creates users today (`required_by_post = required_by_put`, `user.py:26`). **Yes, the superuser creates, without a password**: `create` goes back into `superuser_actions`, the payload is bounded by the new `creatable_by_admin` (`writable_by_admin | {"username"}`), privileged columns are refused and keep their model defaults, and the initial password goes through `password_reset` (which also sets `is_new=True`). The same `creatable_by_admin` attribute fixes a contradiction in the draft: the mapping tables listed their PK columns as `privileged_columns` with an empty write set, so no row could ever be created. → M1, M2, §2 Data Models, AC19, AC20.

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
    does not use the guard is authorized by authentication alone. Also:
    protected groups and `AUTH_PROTECTED_GROUPS` — that it must list **every**
    group a privileged policy names (R11) and that `superuser` is always
    protected; that `security_admin` holds both `users:grant_role` and
    FEAT-106's `mfa:disenroll`; how to seed the first `security_admin` member
    out-of-band (R12); the `password_reset` caveat and the OTP mitigation (R13);
    and the user-creation flow (POST without password, then `password_reset`).
  - `CHANGELOG.md` — update, **with a breaking-change notice** (no deprecation
    window, §8): privileged columns are no longer writable through
    `PATCH`/`PUT`/`POST /api/v1/users`; callers must use
    `POST /api/v1/users/{id}/role`. Passwords are no longer settable through the
    user CRUD, including on create; use `password_change` / `password_reset`.
    `username` is no longer updatable. Membership and definition of
    `superuser` / `security_admin` now require `users:grant_role`. How to find
    affected callers: the guard's audited 403s on these routes.
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
  any point after the names are fixed. M9 after M1 and M6, before the M3/M4
  tests that exercise protected groups.
- **Cross-feature dependencies**: **FEAT-106 shares the `security_admin` group
  (§8) and one file.** Both packs name `security_admin`, and M9 is what makes
  FEAT-106's `mfa:disenroll` separation hold too: without it a plain superuser
  could join `security_admin` through `/api/v1/user_groups`. The one shared
  file is `conf.py` — FEAT-106 adds its MFA settings, this adds
  `AUTH_PROTECTED_GROUPS` after `ABAC_DEFAULT_EFFECT` (`:710`); expect at most a
  trivial textual conflict. Otherwise FEAT-106 touches `basic.py`, `auth.py`
  and a new `mfa/` package; this touches `guards.py` and the handlers.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-11-06 | Jesus Lara | Initial draft. Escalation confirmed by execution; scope widened from `UserManager` to all five unguarded handlers after finding two further routes. |
| 0.2 | 2026-11-11 | Jesus Lara | §8 resolved. `users:grant_role` → `security_admin` (shared with FEAT-106). New M9 protected groups (G8, AC17–18), after finding that name-matched groups let a superuser join or rename into `security_admin`/`superuser`. Ships directly, no deprecation window. User creation kept (superuser, no password) via new `creatable_by_admin`, which also fixes mapping-table creation. `required_by_put`/`required_by_post` made consistent with the write sets. R11–R13 added. |
