Auth CRUD authorization
=======================

FEAT-107 puts every model-CRUD handler over the auth schema behind
``OwnerOrSuperuserGuard``. This page is the operator contract for the breaking
change in 0.30.0.

.. warning::

   ``AUTHORIZATION_MIDDLEWARES`` is empty by default: there is no blanket ABAC
   middleware evaluating every request. A custom handler that does not use the
   guard is authorized by authentication alone.

Guarded surfaces
----------------

The policy names below are supplied by the deployment policy pack. The action
names are ``object:verb``; a policy must allow the listed action as well as the
handler's local allowlist.

.. list-table::
   :header-rows: 1
   :widths: 15 15 12 10 16 18 20 20 20

   * - Route(s)
     - Handler / base
     - Owner column
     - Policy
     - Actions
     - Owner writes
     - Admin updates
     - Admin creates
     - Privileged or closed columns
   * - ``/api/v1/users``
     - ``UserManager`` / ``ModelView`` base on ``authdb``
     - ``user_id``
     - ``users_admin_access``
     - ``user:read``, ``user:create``, ``user:update``, ``user:delete``
     - ``first_name``, ``last_name``, ``display_name``, ``title``, ``avatar``, ``timezone``
     - Owner set plus ``is_active``, ``email``, ``alt_email``
     - Admin update set plus ``username``
     - ``is_superuser``, ``user_role``, ``is_staff``, ``password``, IDs and audit fields
   * - ``/api/v1/groups``
     - ``GroupManager`` / ``ModelView``
     - None
     - ``groups_admin_access``
     - ``group:read``, ``group:create``, ``group:update``, ``group:delete``
     - None
     - ``group_name``, ``description``, ``is_active``, ``client_id``
     - Same as admin updates
     - ``group_id``, ``created_at``, ``created_by``
   * - ``/api/v1/user_groups`` and ``/api/v1/usergroups``
     - ``UserGroupManager`` / ``ModelView``
     - None
     - ``user_groups_admin_access``
     - ``user_group:read``, ``user_group:create``, ``user_group:delete``
     - None
     - None
     - ``user_id``, ``group_id``
     - None; the mapping row itself is admin-only
   * - ``/api/v1/group_permissions``
     - ``GroupPermissionManager`` / ``ModelView``
     - None
     - ``group_permissions_admin_access``
     - ``group_permission:read``, ``group_permission:create``, ``group_permission:delete``
     - None
     - None
     - ``group_id``, ``permission_id``
     - None; the mapping row itself is admin-only
   * - ``/api/v1/permissions``
     - ``PermissionHandler`` / local ``handlers/model.py`` base
     - None
     - ``permissions_admin_access``
     - ``permission:read``, ``permission:create``, ``permission:update``, ``permission:delete``
     - None
     - ``permission``, ``description``
     - Same as admin updates
     - ``permission_id``, ``created_at``

For completeness, FEAT-105 continues to guard ``/api/v1/user_identity*``
(``UserIdentityHandler``, owner ``user_id``, ``user_identities_admin_access``),
``/api/v1/user_accounts*`` (``UserAccountHandler``, owner ``user_id``,
``user_accounts_admin_access``), and ``/api/v1/partner/tokens*``
(``PartnerKeyHandler``, no owner, ``partner_keys_admin_access``). Those
surfaces retain their FEAT-105 read projections, credential redaction, and
verb restrictions.

Reading versus writing
----------------------

``public_columns`` is a **read** serialization allowlist. The
``writable_by_owner``, ``writable_by_admin``, and ``creatable_by_admin`` sets
are **write** allowlists; ``privileged_columns`` are writable through no CRUD
path. These are allowlists, never denylists, so a future model column is closed
until an operator deliberately approves it.

Reads are also gated. A non-superuser sees only their own row at
``/api/v1/users``. Every verb, including ``GET`` and ``HEAD``, for groups,
membership mappings, group-permission mappings, and permissions requires a
policy-approved superuser. The four ``ModelView``-based routes (users, groups,
user groups, and group permissions) answer ``400`` to ``?_filter=`` because
they declare no ``public_columns``; this avoids the old upstream SQL
interpolation behaviour.

Use ``PUT /api/v1/users`` to create a user. It creates no password and leaves
privileged columns at their model defaults. ``POST`` is an admin upsert and is
approved for both create and update; it requires a primary key, so a POST
without one answers ``400``. Owners edit their profile with ``PATCH``.
Membership rows are created with ``PUT`` and removed with ``DELETE``.

Why the mapping tables have no owner
------------------------------------

``UserGroup`` has the composite primary key ``(user_id, group_id)``. Treating
``user_id`` as its owner would let the beneficiary authorize their own group
membership, including membership in ``superuser``. Therefore the mapping
handlers use ``owner_column = None``: the policy-approved superuser path is the
only path. Do not change this to make a mapping row look owner-editable.

Privileged flags: ``POST /api/v1/users/{id}/role``
---------------------------------------------------

The role endpoint accepts a non-empty JSON object containing only
``is_superuser``, ``user_role``, and/or ``is_staff`` with their strict value
types. It requires the ``users:grant_role`` action from the
``users_grant_role`` policy, which is held by ``security_admin`` (the same
group that holds FEAT-106's ``mfa:disenroll``). It is never self-service and an
actor cannot grant a flag or role level they do not hold. Granting
``is_superuser`` additionally requires an actor who is both a superuser and a
``security_admin`` member. Every decision is audited.

.. warning::

   Do not add ``users:*`` or ``*`` to ``admin_full_access.yaml`` actions. That
   would collapse the deliberate separation between ordinary superuser CRUD and
   privileged grants.

Protected groups
----------------

``AUTH_PROTECTED_GROUPS`` defaults to ``superuser,security_admin``;
``superuser`` is protected even if it is omitted from configuration. Adding or
removing a member of a protected group, renaming a group into or out of a
protected name, or deactivating or deleting one requires ``users:grant_role``
and membership in that group. Nobody may add themselves. The setting must list
every group named by a privileged policy, otherwise an ordinary superuser could
join that group through the CRUD API.

The first ``security_admin`` member must be seeded out of band, because no API
caller holds ``users:grant_role`` before that member exists. For example, an
operator can perform a reviewed database change such as:

.. code-block:: sql

   INSERT INTO auth.user_groups (user_id, group_id)
   SELECT 123, group_id FROM auth.groups WHERE group_name = 'security_admin';

Replace ``123`` with the provisioned administrator's user ID and use the
deployment's approved database-change process.

Users and passwords
-------------------

Create users with ``PUT`` without a password, then use ``password_reset`` to
set the initial password; it also sets ``is_new = True``. Passwords never pass
through the generic CRUD endpoints. ``password_change`` remains the
self-service path.

There is an important remaining boundary: ``password_reset`` allows any
superuser to set any user's password, including a ``security_admin`` member's.
That endpoint is outside FEAT-107. FEAT-106's OTP enforcement for
``security_admin`` members is the current mitigation.

Deploying the policy pack
-------------------------

The pack is not auto-loaded. Copy
``navigator_auth/abac/default_policies/auth_crud_admin_access.yaml`` into the
deployment's ``POLICY_STORAGE_DIR``. Without it, every admin path fails closed.
It contains ``users_admin_access``, ``groups_admin_access``,
``user_groups_admin_access``, ``group_permissions_admin_access``,
``permissions_admin_access``, and ``users_grant_role``.

``UserManager`` now uses the ``authdb`` connection pool rather than the
``nav.model`` default. Deployments using a separate auth database must configure
``authdb``; the group handlers already require that pool.

Finding affected callers
------------------------

The guard audits every refusal through ``AuditLog``. After upgrading, query
``DENY`` audit records for ``403`` responses on these routes; they name the
actor, action, and reason and identify callers that need migration.
