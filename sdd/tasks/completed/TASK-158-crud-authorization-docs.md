# TASK-158: Document the auth CRUD authorization contract and the breaking changes

**Feature**: FEAT-107 — Write-envelope hardening for the remaining auth CRUD handlers
**Spec**: `sdd/specs/auth-model-crud-hardening.spec.md`
**Status**: done
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-150, TASK-153, TASK-154, TASK-155, TASK-156
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 8** and **§10 Documentation** (`policy: required`,
AC15). FEAT-107 ships in 0.30.0 **with no deprecation window and no
compatibility flag** (spec §8, R1): a transition period would keep the
escalation open. So the CHANGELOG notice and the operator page are the only
warning a client gets before it starts receiving 403s. Write them from what the
code actually does — read the Completion Notes of TASK-149..157 first and
reflect any deviation they record.

### What the documentation must reflect beyond spec §10 (decided at /sdd-task time)

1. **Reads are now gated** (user decision 2026-11-11): a non-superuser sees only
   their own row on `/api/v1/users`; `/api/v1/groups`, `/api/v1/user_groups`,
   `/api/v1/usergroups`, `/api/v1/group_permissions`, `/api/v1/permissions` are
   superuser + policy only for every verb, GET and HEAD included. This is a
   second breaking change not listed in spec §10.
2. **Verb semantics on these routes**: user creation is `PUT /api/v1/users`
   (POST needs a PK and answers 400 without one); POST is an admin upsert approved
   for create *and* update, so owners edit their profile with **PATCH**;
   membership rows are created with PUT and removed with DELETE.
3. **`?_filter=` answers 400** on the four `ModelView`-based routes (no
   `public_columns` declared); upstream navigator-api 3.2.2 interpolated it into SQL.
4. **ABAC action names** are `object:verb`: `user:*`, `group:*`, `user_group:*`,
   `group_permission:*`, `permission:*`, `users:grant_role`.
5. **The pack is not auto-loaded**: copy
   `navigator_auth/abac/default_policies/auth_crud_admin_access.yaml` into the
   deployment's `POLICY_STORAGE_DIR`, as for FEAT-105's pack. Without it every
   admin path fails closed.
6. **`UserManager` now uses the `authdb` connection pool** (it used the
   `ModelView` default `nav.model`). Operators with a separate auth database need
   `authdb` configured — the group handlers already require it.

---

## Scope

- Create `docs/auth_crud_authorization.rst` covering every bullet of spec §10
  "Pages" plus items 1–6 above.
- Add it to the `docs/index.rst` toctree.
- Add a **breaking-change** entry at the top of `CHANGELOG.md` under `# Unreleased`.

**NOT in scope**:
- Code changes.
- Editing `documentation/*.md` (FEAT-105's pages) beyond, optionally, a one-line
  cross-reference from `documentation/pdp.md` — skip if unsure.
- Release/version bump to 0.30.0.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `docs/auth_crud_authorization.rst` | CREATE | Operator contract page |
| `docs/index.rst` | MODIFY | toctree entry |
| `CHANGELOG.md` | MODIFY | Breaking-change entry under `# Unreleased` |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `6b8cc84` on 2026-11-11.

### Existing structure to follow

```text
docs/index.rst:33-45   .. toctree::  (:maxdepth: 2, :caption: Contents:)
                       api, config, settings, token_exchange, passkey, password_recovery,
                       vault, security, changes
docs/*.rst             reStructuredText; titles underlined with "=" (see docs/security.rst)
CHANGELOG.md:1         "# Unreleased", then "- **Bold lead sentence (FEAT-NNN, client-visible
                       behaviour change).** prose…" bullets (FEAT-105 entry at :3-15 is the model)
```

### Facts to cite (verified)

- `AUTHORIZATION_MIDDLEWARES = ()` — `navigator_auth/conf.py:264`.
- `AUTH_PROTECTED_GROUPS` — `navigator_auth/conf.py`, after `ABAC_DEFAULT_EFFECT` (TASK-152); default `superuser,security_admin`; `superuser` always protected.
- `admin_full_access.yaml` — `uri:*` resources, enumerated actions (no wildcard), priority 100.
- `UserSession.password_change` (`handlers/users/session.py:119`), `password_reset` (`:170`, sets `is_new = True`), `user_profile` (`:244`).
- Routes: `navigator_auth/handlers/__init__.py:22-38` plus `/api/v1/users/{id:\d+}/role` (TASK-156).

### Does NOT Exist (Anti-Hallucination)

- ~~`docs/auth_crud_authorization.rst`~~ — created here.
- ~~a compatibility flag or deprecation window~~ — none, by decision (spec §8).
- ~~automatic loading of `abac/default_policies/`~~ — operators copy the file.
- ~~a way to add the first `security_admin` member through the API~~ — out-of-band only (spec R12).

---

## Implementation Blueprint

### `docs/auth_crud_authorization.rst` — CREATE

```rst
Auth CRUD authorization
=======================

FEAT-107 puts every model-CRUD handler over the auth schema behind
``OwnerOrSuperuserGuard``. This page is the operator contract.

.. warning::

   ``AUTHORIZATION_MIDDLEWARES`` is empty by default (``conf.py:264``): no
   blanket ABAC middleware evaluates requests. A custom handler that does not
   use the guard is authorized by authentication alone.

Guarded surfaces
----------------

.. FILL IN: a table — route(s), handler, base, owner_column, policy, actions, writable_by_owner,
   writable_by_admin, creatable_by_admin, privileged_columns — for /api/v1/users,
   /api/v1/groups, /api/v1/user_groups + /api/v1/usergroups, /api/v1/group_permissions,
   /api/v1/permissions, plus the three FEAT-105 surfaces in one line each for completeness.

Reading versus writing
----------------------

.. FILL IN: public_columns is the READ allowlist; writable_by_* / creatable_by_admin are the
   WRITE allowlists; privileged_columns are writable by no CRUD path. Allowlists, never
   denylists: a column added to a model later is closed by default. Reads are gated too
   (Context item 1). Verb semantics (Context item 2). ?_filter= (Context item 3).

Why the mapping tables have no owner
------------------------------------

.. FILL IN: UserGroup's PK (user_id, group_id) makes the row's owner its beneficiary;
   owner_column = None makes the superuser path the only path. Do not "fix" it (spec R4).

Privileged flags: ``POST /api/v1/users/{id}/role``
--------------------------------------------------

.. FILL IN: payload, users:grant_role, held by security_admin (shared with FEAT-106's
   mfa:disenroll), never self-service, cannot change a flag you do not hold; granting
   is_superuser needs a superuser in security_admin; every call audited. WARNING: adding
   "users:*" or "*" to admin_full_access.yaml's actions collapses this separation (spec R8).

Protected groups
----------------

.. FILL IN: AUTH_PROTECTED_GROUPS (default superuser,security_admin; superuser always
   included); membership add/remove, rename into/out of, deactivate, delete need
   users:grant_role AND membership of the group; nobody adds themselves. MUST list every
   group a privileged policy names (spec R11). Seeding the first security_admin member
   out-of-band, with an example SQL INSERT into auth.user_groups (spec R12).

Users and passwords
-------------------

.. FILL IN: create with PUT (no password; privileged columns keep model defaults), then
   password_reset sets the password and is_new=True; passwords never through the CRUD.
   Caveat (spec R13): password_reset lets any superuser set any user's password, including a
   security_admin member's — FEAT-106's OTP enforcement on security_admin is the mitigation.

Deploying the policy pack
-------------------------

.. FILL IN: copy auth_crud_admin_access.yaml into POLICY_STORAGE_DIR (not auto-loaded); without
   it every admin path fails closed. List the six policy names. authdb pool note (Context item 6).

Finding affected callers
------------------------

.. FILL IN: the guard audits every refusal through AuditLog (DENY records naming actor, action,
   reason) — query those for 403s on these routes after the upgrade.
```

### `docs/index.rst` — MODIFY

```rst
.. REPLACE the two toctree lines `   vault` / `   security` (verified: docs/index.rst:43-44;
   occurrences: 1 each, `grep -cx`) with:
   vault
   security
   auth_crud_authorization
```

### `CHANGELOG.md` — MODIFY

```markdown
<!-- AFTER — insert below `# Unreleased` (verified: CHANGELOG.md:1, occurrences: 1), above the FEAT-105 entry -->

- **BREAKING — write envelope on the auth CRUD handlers (FEAT-107, no
  deprecation window).** `/api/v1/users*`, `/api/v1/groups*`,
  `/api/v1/user_groups*`, `/api/v1/usergroups*`, `/api/v1/group_permissions*` and
  `/api/v1/permissions*` were authorized by authentication alone; any session
  could set `is_superuser` / `user_role` / `is_staff`, join any group (including
  `superuser`) or grant any permission. FILL IN: the rest of the entry — privileged
  columns no longer writable through PATCH/PUT/POST (use `POST /api/v1/users/{id}/role`,
  `users:grant_role`, held by `security_admin`); passwords no longer settable through
  the user CRUD, create included (use `password_change` / `password_reset`); `username`
  no longer updatable; users are created with PUT; owners edit with PATCH; reads are
  gated; `?_filter=` answers 400; membership/definition of protected groups needs
  `users:grant_role` (`AUTH_PROTECTED_GROUPS`); new pack
  `abac/default_policies/auth_crud_admin_access.yaml` must be deployed; find affected
  callers through the guard's audited 403s. See `docs/auth_crud_authorization.rst`.
```

### Steps (in order)

1. Read the Completion Notes of TASK-149..157 — because the docs must describe
   the shipped behaviour, including any deviation recorded there.
2. Write the `.rst` page, completing each `FILL IN` section.
3. Add the toctree entry and the CHANGELOG entry.
4. Build check (optional, if Sphinx is installed): `sphinx-build -b html docs /tmp/docs-build -q`
   — or at least `python -m docutils docs/auth_crud_authorization.rst /dev/null`.

### FILL IN checklist

- [ ] Every section of the `.rst` page.
- [ ] The full CHANGELOG entry.
- [ ] Each spec §10 bullet appears on the page (checklist: guarded handlers + config;
      public_columns vs writable_by_*; mapping tables owner None; role endpoint + action + group;
      admin_full_access warning; AUTHORIZATION_MIDDLEWARES; AUTH_PROTECTED_GROUPS and R11;
      security_admin holds both actions; seeding R12; password_reset caveat R13; user-creation flow).

---

## Acceptance Criteria

- [ ] `docs/auth_crud_authorization.rst` exists, is in the `docs/index.rst` toctree, and covers every spec §10 bullet plus Context items 1–6 (spec AC15).
- [ ] `CHANGELOG.md` has a breaking-change entry for FEAT-107 under `# Unreleased` (spec AC15).
- [ ] The page parses as reStructuredText without errors.

---

## Test Specification

No automated tests. Verification is the §10 checklist above plus an RST parse.

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at `sdd/specs/auth-model-crud-hardening.spec.md` (§7 R1, R8, R11–R13, §10).
2. **Check dependencies** — TASK-150, TASK-153, TASK-154, TASK-155, TASK-156 are `done` in `sdd/tasks/index/auth-model-crud-hardening.json`.
3. **Update status** → `"in-progress"`.
4. **Implement** the blueprint and complete every `FILL IN`.
5. **Verify** the acceptance criteria.
6. **Move this file** to `sdd/tasks/completed/` and set the index entry to `"done"`.
7. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: sdd-worker (orchestrator)
**Date**: 2026-11-11
**Seat**: Backend: codex · Model: gpt-5.6-terra
**Notes**: docs/auth_crud_authorization.rst, docs/index.rst toctree, CHANGELOG breaking-change entry. Docs only. Review: zero fixes (feedback coder-review:6f340814539081aac9e30508).
