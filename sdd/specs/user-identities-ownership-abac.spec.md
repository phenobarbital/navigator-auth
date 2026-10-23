---
type: feature
base_branch: dev
---

<!-- LANGUAGE: English only. -->

# Feature Specification: User Identities — Owner-or-Superuser ABAC Ownership

**Feature ID**: FEAT-105
**Date**: 2026-10-23
**Author**: Jesus Lara
**Status**: draft
**Target version**: 0.29.0

---

## 1. Motivation & Business Requirements

### Problem Statement

`UserIdentity` (`auth.user_identities`) is the Identity Vault row: it holds a
user's **linked external provider credentials** — `access_token`,
`refresh_token`, `id_token` (ciphered `bytes`), plus `provider_user_id`,
`scopes`, `key_version`, the provider profile `auth_data`, and PII (`email`,
`phone`, `nickname`, `short_bio`).

Two HTTP surfaces reach that table today, and only one of them is safe:

1. **Safe** — the Identity Vault handler
   (`navigator_auth/handlers/user_identities.py`, mounted at
   `/api/v1/user/identities*`). Every operation is anchored to the
   **session** `user_id` (`BaseIdentityView._user_id`,
   `handlers/user_identities.py:38-59`) and every response goes through
   `IdentityStore.masked()` (`identity/store.py:465`), which never returns
   token material. Its own module docstring states the intent:
   *"All endpoints operate strictly on the authenticated session user's own
   identities. Access to other users' credentials … is out of scope here —
   compose it via the ABAC layer."* That composition was never built.

2. **Unsafe** — the generic model CRUD handler
   `UserIdentityHandler(ModelHandler)` (`handlers/userattrs.py:53-59`),
   mounted at `/api/v1/user_identity/{id:.*}` and
   `/api/v1/user_identity{meta}` (`handlers/__init__.py:58-65`).
   `ModelHandler` here is `navigator.views.ModelView`
   (`handlers/handler.py:1-10`), i.e. unrestricted model CRUD. It has:
   - **no ownership binding** — any authenticated session can
     `GET`/`PUT`/`PATCH`/`POST`/`DELETE` **another user's** identity by
     `identity_id`, or list/filter the whole table via query parameters
     (`?user_id=<victim>`). The only ownership-ish hook present,
     `_set_user_id` (`handlers/userattrs.py:58`), merely *fills* `user_id`
     from the session on writes that omit it; it does not restrict reads and
     does not stop an explicit `user_id` in the payload or URL;
   - **no redaction** — the serialized row is the model row. The credential
     columns are in it.

Worse, the upstream response layer is actively hostile here.
`navigator.views.ModelView._get_model()` collects every `repr=False` column
into `self._hidden` (`.venv/.../navigator/views/model.py:144-148`), and
`_model_response()` then uses `_hidden` as the **whitelist of fields to
return** (`:178-179`, `_fields = self._hidden` → `row[field] = getattr(...)`),
not as an exclusion list. For `UserIdentity` the `repr=False` columns are
*exactly* `identity_id, auth_data, attributes, provider_user_id, scopes,
access_token, refresh_token, id_token, token_type, expires_at, refreshed_at,
key_version, created_at` (`models.py:77-117`) — the credential set. On top of
that, `_required` / `_primaries` / `_hidden` are **class attributes of
`ModelView`** mutated in place via `self._hidden.append(...)`, so they are
shared across every subclass in the process and the effective projection
depends on which handler was instantiated first. Either branch leaks
credential columns; which one you get is non-deterministic.

Two more bypasses on the same handler:

- `?fields=access_token,refresh_token` is honoured verbatim
  (`get_parameters`, `.venv/.../navigator/views/abstract.py:434-447`, then
  `_model_response(..., fields=...)`), projecting any column by name.
- `?_filter=<field>=<value>` reaches `_filtering()`
  (`.venv/.../navigator/views/model.py:419-447`), which interpolates
  **unvalidated** `field` and `value` straight into
  `SELECT {field} FROM {schema}.{table} WHERE {field} LIKE '{value}%'` — a
  column-projection oracle *and* a SQL-injection sink on the credential
  table.

The business rule the product actually wants is simple and is not expressed
anywhere: **querying, editing and managing user identities is the user's own
prerogative over their own identities, or a `superuser`'s — and a superuser
sees credentials redacted.**

### Goals

- **G1** — Bind every `UserIdentity` model operation to an owner:
  non-superusers can only read and manage rows where
  `user_identities.user_id` equals the session `user_id`.
- **G2** — Allow cross-user access only to the `superuser` group, governed by
  a named ABAC policy, and **fail closed**: no PDP, no policy, unreadable
  decision ⇒ deny.
- **G3** — Never serialize token material to anyone, through any parameter
  combination, on the model surface — by construction (explicit allowlist),
  not by relying on the upstream `_hidden` whitelist inversion.
- **G4** — Keep `/api/v1/user_identity*` working for existing clients
  (hardened in place, not deprecated or removed).
- **G5** — Constrain what a superuser may *write* on someone else's identity:
  revoke (`enabled=false`) and delete only.
- **G6** — Audit every cross-user access through the existing
  `navigator_auth/abac/audit.py` `AuditLog`.
- **G7** — Close the parameter bypasses on this handler: `fields`, `_filter`,
  and an explicit foreign `user_id`.

### Non-Goals (explicitly out of scope)

- Changing the Identity Vault handler
  (`handlers/user_identities.py`). It is already owner-scoped and masked; the
  decrypted-credential endpoint
  `/api/v1/user/identities/{provider}/credential` keeps serving the **owner**
  their own credential and is untouched.
- Fixing `navigator.views.ModelView` upstream. The `_hidden` whitelist
  inversion, the shared class-level `_hidden`/`_required`/`_primaries`, and
  the `_filtering()` SQL interpolation are upstream defects; this feature
  neutralizes them **locally** for the identity surface and does not wait for
  a navigator release. Reporting them upstream is a follow-up, not a
  deliverable.
- Generalizing owner-or-superuser to every `ModelHandler` in
  `navigator_auth/handlers/` (`UserAccountHandler`, `PartnerKeyHandler`, …).
  The guard introduced here is written to be reusable, but applying it
  elsewhere is a separate spec.
- A `ResourceType.IDENTITY` enum member. The policy uses the existing
  `ResourceType.URI` (`abac/policies/resources.py:15-30`), consistent with
  `uri:*` in `abac/default_policies/admin_full_access.yaml`.
- Row-level ownership expressed *inside* the policy language.
  `ResourcePolicy.evaluate_conditions` can only compare `EvalContext`
  attributes (`abac/policies/resource_policy.py:119-150`) and silently
  **passes** when the attribute is missing (`if actual is None: continue`),
  so ownership stays in code and the policy governs only the cross-user
  capability.

---

## 2. Architectural Design

### Overview

Three layers, each closed by default:

1. **Ownership binding (code, mandatory).** A new reusable mixin,
   `IdentityAccessGuard`, resolves the acting `(user_id, is_superuser)` pair
   from the session using the hardened `_check_superuser`
   (`decorators.py:291-312`, which already resists `groups="ex_superuser…"`
   substring confusion). `UserIdentityHandler` calls it on every verb. Owner
   ⇒ allowed. Not owner ⇒ superuser path. Neither ⇒ refused. A foreign row
   fetched by primary key answers **404**, not 403, so `identity_id` cannot
   be used as an existence oracle.

2. **ABAC policy (configuration, authoritative for cross-user).** The
   superuser path additionally requires the named policy
   `user_identities_admin_access` to allow the action. The decision is taken
   programmatically through a new public wrapper `policy_allows()` over the
   existing fail-closed `_check_policies()` (`decorators.py:1103-1158`): no
   PDP ⇒ deny; policy not declared ⇒ deny; evaluation raises ⇒ deny. The
   policy ships in the default pack so a stock deployment behaves correctly,
   but the code never *depends* on the file existing — a missing policy only
   ever removes superuser access, never grants it.

3. **Redaction (code, unconditional).** Every response on the model surface
   is projected through `redact_identity()`, an explicit allowlist mirroring
   `IdentityStore.masked()` (`identity/store.py:465-496`). The credential
   columns live in `IDENTITY_CREDENTIAL_COLUMNS` and can never appear — not
   via `fields=`, not via `_filter`, not via `:meta`, for the owner or for a
   superuser. The owner still gets real credentials, but only from the vault
   endpoint that exists for exactly that purpose.

### Component Diagram

```
                       ┌──────────────────────────────────────────┐
 GET/PUT/PATCH/POST/   │ UserIdentityHandler (handlers/userattrs) │
 DELETE                │   = navigator ModelView CRUD             │
 /api/v1/user_identity │                                          │
 ───────────────────▶  │  1. _guard_request()  ◀── IdentityAccess │
                       │        │                     Guard       │
                       │        ├─ owner?  ────────────── allow   │
                       │        ├─ superuser? ─┐                  │
                       │        └─ else ───────┼──── 403 / 404    │
                       │                       ▼                  │
                       │             policy_allows(               │
                       │               'user_identities_          │
                       │                admin_access', action)    │
                       │                       │                  │
                       │             _check_policies (fail-closed)│
                       │                       │                  │
                       │                   PDP / YAML pack        │
                       │                       │                  │
                       │                  AuditLog.log()          │
                       │                                          │
                       │  2. _sanitize_query()   fields/_filter/  │
                       │                          user_id         │
                       │  3. _filter_user_id()   forced WHERE     │
                       │  4. _model_response() ──▶ redact_identity│
                       └──────────────────────────────────────────┘
```

### Integration Points

| Existing component | Integration type | Notes |
|---|---|---|
| `navigator.views.ModelView` (via `handlers/handler.py:4`) | overrides hooks | `_pre_get`/`_pre_put`/`_pre_patch`/`_pre_post`/`_pre_delete` (`abstract.py:553-571`), `_filter_user_id` column hook (`model.py:336-355`), `_model_response` (`model.py:158-213`) |
| `navigator_auth.decorators._check_policies` (`:1103`) | wraps (new public API) | new `policy_allows()` — fail-closed ABAC decision outside a decorator |
| `navigator_auth.decorators._check_superuser` (`:291`) | reuses | single source of truth for superuser detection; `client_access.py:57` `_require_superuser` checks only the attribute, not group membership, so it is NOT reused |
| `IdentityStore.masked()` (`identity/store.py:465`) | mirrors shape | redaction allowlist produces the same keys, so vault and model surfaces agree |
| `navigator_auth/abac/default_policies/` | adds file | loaded by `YAMLStorage.load_policies()` (`abac/storages/yaml_storage.py:34-67`) from `POLICY_STORAGE_DIR` (`conf.py:705`) |
| `navigator_auth/abac/audit.py` `AuditLog.log(answer, status, user, *, tenant=None)` (`:277`) | uses | `answer` needs `.response` / `.rule` → a `PolicyResponse` is passed |
| `UserIdentity` / `VwUserIdentity` (`models.py:77`, `:119`) | reads metadata | `AUTH_USER_IDENTITY_MODEL` (`conf.py:150`, default `None`) can swap the model: a configured model without a `user_id` column must fail closed |

### Data Models

```python
# navigator_auth/identity/redaction.py  (new)

#: Columns that must never be serialized by any HTTP surface.
IDENTITY_CREDENTIAL_COLUMNS: frozenset[str] = frozenset({
    "access_token", "refresh_token", "id_token", "key_version",
})

#: Columns that may be serialized, mirroring IdentityStore.masked().
IDENTITY_PUBLIC_COLUMNS: frozenset[str] = frozenset({
    "identity_id", "user_id", "display_name", "title", "nickname",
    "email", "phone", "short_bio", "avatar", "auth_provider",
    "provider_user_id", "scopes", "token_type", "expires_at",
    "refreshed_at", "created_at", "enabled", "auth_data", "attributes",
})
```

Decision D3 keeps the `masked()` shape, so `auth_data` (provider profile),
`scopes` and `provider_user_id` stay visible to a superuser; only token
material and `key_version` are withheld, plus the two derived booleans
`has_refresh_token` / `has_id_token` are added in their place.

### New Public Interfaces

```python
# navigator_auth/decorators.py  (added)

async def policy_allows(
    policy: Union[str, list],
    request: web.Request,
    action: str = None,
    resource: str = None,
    resource_type: Any = None,
    require_all: bool = False,
) -> tuple[bool, str, Any]:
    """Evaluate ABAC policies for a request outside a decorator.

    Public, documented wrapper over the fail-closed :func:`_check_policies`
    used by :func:`check_access`, for handlers whose decision depends on data
    only known at request time (e.g. the owner of a row).

    Returns:
        ``(allowed, reason, response)`` — ``response`` is the last
        ``PolicyResponse`` produced, or ``None`` when nothing was evaluated.
        ``allowed`` is ``False`` when ABAC is absent, the policy is not
        declared, or evaluation raised.
    """
```

```python
# navigator_auth/identity/redaction.py  (new)

def redact_identity(
    row: Union[BaseModel, dict],
    fields: list[str] = None,
) -> dict:
    """Project an identity row onto the public allowlist.

    Token material (:data:`IDENTITY_CREDENTIAL_COLUMNS`) is replaced by the
    booleans ``has_refresh_token`` / ``has_id_token``; ``expired`` is derived
    from ``expires_at`` exactly as :meth:`IdentityStore.masked` does.

    Args:
        row: A ``UserIdentity`` instance or an already-serialized dict.
        fields: Optional caller-requested projection; intersected with the
            allowlist, never unioned.
    """
```

```python
# navigator_auth/handlers/identity_guard.py  (new)

class IdentityAccessGuard:
    """Owner-or-superuser authorization for identity model handlers."""

    #: Named ABAC policy consulted for any cross-user access.
    identity_policy: str = "user_identities_admin_access"
    #: Actions a superuser may take on another user's identity (D4).
    superuser_actions: frozenset[str] = frozenset({
        "identity:read", "identity:revoke", "identity:delete",
    })

    async def acting_user(self) -> tuple[int, bool]:
        """Return ``(user_id, is_superuser)`` for the current session."""

    async def authorize_identity(
        self, action: str, target_user_id: Optional[int]
    ) -> bool:
        """Authorize ``action`` against the row owned by ``target_user_id``.

        Returns ``True`` when the caller is the owner. Returns ``True`` for a
        superuser only when ``action`` is in :attr:`superuser_actions` **and**
        :attr:`identity_policy` allows it; that case is audited. Any other
        outcome refuses the request (403, or 404 on a primary-key lookup so a
        foreign ``identity_id`` is not confirmed).
        """
```

---

## 3. Module Breakdown

### Module 1: Redaction allowlist

- **Path**: `navigator_auth/identity/redaction.py` *(new)*
- **Responsibility**: the single definition of what an identity row may ever
  expose, plus the projection function. Pure, synchronous, no I/O — so it is
  trivially testable and reusable by both HTTP surfaces.
- **Depends on**: nothing in this spec. Mirrors `IdentityStore.masked()`
  (`identity/store.py:465`).

**Interface skeleton**

```python
"""Redaction allowlist for auth.user_identities (FEAT-105)."""
from typing import Union, Optional
from datamodel import BaseModel

IDENTITY_CREDENTIAL_COLUMNS: frozenset[str]
IDENTITY_PUBLIC_COLUMNS: frozenset[str]

def redact_identity(
    row: Union[BaseModel, dict], fields: Optional[list[str]] = None
) -> dict:
    """Project one identity row onto IDENTITY_PUBLIC_COLUMNS."""

def redact_identities(
    rows: Union[list, BaseModel, dict], fields: Optional[list[str]] = None
) -> Union[list[dict], dict]:
    """Vectorized :func:`redact_identity`, preserving list-vs-scalar shape."""

def safe_fields(fields: Optional[list[str]]) -> Optional[list[str]]:
    """Intersect a caller projection with the allowlist (never a union)."""
```

### Module 2: Public ABAC evaluation API

- **Path**: `navigator_auth/decorators.py` *(modified)*
- **Responsibility**: expose `policy_allows()` so handlers can take a
  fail-closed ABAC decision that depends on request-time data, without
  importing the private `_check_policies`.
- **Depends on**: existing `_check_policies` (`decorators.py:1103`),
  `_get_pdp` (`:994`), `_find_policy` (`:1003`), `_policy_allows` (`:1031`).

**Interface skeleton**

```python
async def policy_allows(                      # verified: navigator_auth/decorators.py:1103
    policy: Union[str, list],
    request: web.Request,
    action: str = None,
    resource: str = None,
    resource_type: Any = None,
    require_all: bool = False,
) -> tuple[bool, str, Any]:
    """Public, fail-closed ABAC evaluation for a live request."""
    # delegates to _check_policies(request, names, action, resource,
    #                              resource_type, require_all)
```

`__all__` / module exports updated so `from navigator_auth.decorators import
policy_allows` resolves.

### Module 3: Owner-or-superuser guard mixin

- **Path**: `navigator_auth/handlers/identity_guard.py` *(new)*
- **Responsibility**: the authorization decision and its audit trail, kept
  out of the CRUD handler so it can be reused and unit-tested without HTTP
  plumbing.
- **Depends on**: Module 2; `_check_superuser` (`decorators.py:291`);
  `AuditLog` (`abac/audit.py:189`); `PolicyResponse` / `PolicyEffect`
  (`abac/policies/abstract.py:11-24`).

**Interface skeleton**

```python
"""Owner-or-superuser authorization for identity model handlers (FEAT-105)."""
from typing import Optional
from navigator_session import get_session            # verified: navigator_auth/handlers/model.py:16
from navigator_auth.conf import AUTH_SESSION_OBJECT
from navigator_auth.decorators import _check_superuser   # verified: navigator_auth/decorators.py:291
from navigator_auth.decorators import policy_allows      # Module 2

class IdentityAccessGuard:
    identity_policy: str = "user_identities_admin_access"
    superuser_actions: frozenset[str] = frozenset({
        "identity:read", "identity:revoke", "identity:delete"})

    async def acting_user(self) -> tuple[int, bool]:
        """(user_id, is_superuser) from the session; 401 when absent."""

    async def authorize_identity(
        self, action: str, target_user_id: Optional[int],
        *, not_found_on_deny: bool = False,
    ) -> bool:
        """Owner ⇒ True. Superuser ⇒ policy-gated + audited. Else refuse."""

    async def _audit_cross_user(
        self, action: str, allowed: bool, target_user_id: Optional[int],
        reason: str,
    ) -> None:
        """Record the cross-user decision via AuditLog.log()."""
        # AuditLog.log(answer, status, user, tenant=None)
        # verified: navigator_auth/abac/audit.py:277 — answer needs .response/.rule
```

### Module 4: Harden `UserIdentityHandler`

- **Path**: `navigator_auth/handlers/userattrs.py` *(modified)*
- **Responsibility**: wire the guard, the forced ownership filter, the query
  sanitation and the redacted serialization into the live CRUD endpoint, and
  neutralize the upstream `_hidden` / `_filter` / `fields` hazards locally.
- **Depends on**: Modules 1, 3.

**Interface skeleton**

```python
class UserIdentityHandler(IdentityAccessGuard, ModelHandler):
    model: Any = UserIdentity                   # verified: navigator_auth/models.py:77
    model_name: str = AUTH_USER_IDENTITY_MODEL  # verified: navigator_auth/conf.py:150
    name: str = "User Identity"
    pk: str = "identity_id"

    # Per-subclass copies: ModelView mutates these CLASS-level lists in place
    # (self._hidden.append), contaminating every sibling handler.
    # verified: .venv/.../navigator/views/model.py:79, 144-148
    _hidden: list = []
    _required: list = []
    _primaries: list = []

    #: Vault-managed columns: never writable through the model surface.
    readonly_columns: frozenset[str]

    async def _set_user_id(self, value, column, data):      # existing, kept
        ...

    async def _filter_user_id(self, value, column, data):
        """Force WHERE user_id = <acting user> for non-superusers.

        ModelView calls every ``_filter_<column>`` hook and merges the result
        into the query (``filter(**qp, **_filter)`` / ``{**_filter, **args}``).
        verified: .venv/.../navigator/views/model.py:336-384
        """

    async def _sanitize_query(self) -> None:
        """Refuse the parameter bypasses before any DB access.

        - ``_filter`` is rejected outright: ``_filtering()`` interpolates it
          into raw SQL. verified: .venv/.../navigator/views/model.py:419-447
        - ``fields`` is intersected with the redaction allowlist.
        - an explicit foreign ``user_id`` is refused rather than merged: the
          merge ``filter(**qp, **_filter)`` would raise TypeError (duplicate
          keyword) and surface as a 500.
        """

    async def _pre_get(self, *args, **kwargs) -> bool: ...     # identity:read
    async def _pre_put(self, *args, **kwargs) -> bool: ...     # owner only
    async def _pre_patch(self, *args, **kwargs) -> bool: ...   # owner | revoke
    async def _pre_post(self, *args, **kwargs) -> bool: ...    # owner | revoke
    async def _pre_delete(self, *args, **kwargs) -> bool: ...  # identity:delete

    async def _model_response(self, response, fields=None, headers=None, status=200):
        """Redact, then delegate to the parent implementation.

        verified: .venv/.../navigator/views/model.py:158-213 (the parent uses
        ``_hidden`` as a WHITELIST — this override never relies on it).
        """
```

Behavioural contract (all verbs):

| Verb / target | Owner | Superuser (other user) | Other user |
|---|---|---|---|
| `GET` by `identity_id` | redacted row | redacted row, audited | **404** |
| `GET` list / filter | own rows only (forced `user_id`) | `?user_id=<n>` allowed, audited | own rows only |
| `PUT` (insert) | own row (`user_id` forced) | 403 | 403 |
| `PATCH` / `POST` | own row, non-credential columns | only `enabled=false`, audited | 403 |
| `DELETE` | own row | allowed, audited | **404** |
| `?fields=access_token` | dropped | dropped | dropped |
| `?_filter=…` | **400** | **400** | **400** |
| `:meta` | schema, credential columns stripped | same | same |

Any attempt to write a column in `readonly_columns` (`access_token`,
`refresh_token`, `id_token`, `key_version`, `provider_user_id`, `token_type`,
`expires_at`, `refreshed_at`, `scopes`) is refused with **400** for everyone,
including the owner: those are vault-managed
(`IdentityStore.update_tokens`, `identity/store.py:409`).
If the configured model has no `user_id` column, ownership cannot be
established and every verb answers **501**.

### Module 5: Default ABAC policy

- **Path**: `navigator_auth/abac/default_policies/user_identities_owner_or_admin.yaml` *(new)*
- **Responsibility**: ship the named policy the guard consults, in the format
  `YAMLStorage._parse_file` accepts (`policy_type` defaults to `resource` →
  `resources` plural + structured `subjects`).
- **Depends on**: nothing in code (the guard denies when it is absent).

```yaml
version: "1.0"
defaults:
  effect: deny
policies:
  - name: user_identities_admin_access
    effect: allow
    description: >-
      Superusers may read (redacted), revoke and delete other users' linked
      identities. Never grants token material: redaction is enforced in code.
    resources:
      - "uri:/api/v1/user_identity*"
    actions:
      - "identity:read"
      - "identity:revoke"
      - "identity:delete"
    subjects:
      groups:
        - superuser
    priority: 90
    enforcing: true
```

### Module 6: Tests

- **Path**: `tests/unit/identity/test_identity_redaction.py`,
  `tests/unit/identity/test_user_identity_handler_access.py`,
  `tests/unit/identity/test_identity_policy_pack.py` *(new)*
- **Responsibility**: cover §4. Follows the existing handler-test pattern
  (`make_mocked_request` + patched `get_session`,
  `tests/unit/identity/test_identity_handlers.py:1-67`).
- **Depends on**: Modules 1–5.

### Module 7: Documentation

- **Path**: `documentation/identity-vault.md` *(modified)*, `documentation/pdp.md` *(modified)*
- **Responsibility**: document the owner-or-superuser rule, the redacted
  superuser view, the policy name and the refused parameters.
- **Depends on**: Modules 1–5.

### Delegation-eligible modules

| Module | Delegation-eligible | Why / decided contract |
|---|---|---|
| 1 — Redaction | **Yes** | Column sets and function signatures fixed above; pure functions. |
| 2 — `policy_allows` | **Yes** | Thin wrapper; signature and fail-closed semantics fixed. |
| 3 — Guard mixin | **No** | The deny-shape decisions (404-vs-403, audit payload) are design calls. |
| 4 — Handler hardening | **No** | Interacts with undocumented upstream `ModelView` behaviour; needs judgement per verb. |
| 5 — Policy YAML | **Yes** | Full file content given. |
| 6 — Tests | **Yes** | Cases enumerated in §4. |
| 7 — Docs | **Yes** | Behaviour table in Module 4 is the source. |

---

## 4. Test Specification

### Unit Tests

| Test | Module | Description |
|---|---|---|
| `test_redaction_never_emits_token_columns` | 1 | Every column in `IDENTITY_CREDENTIAL_COLUMNS` is absent from `redact_identity()` output, for a model row and for a dict. |
| `test_redaction_adds_presence_booleans` | 1 | `has_refresh_token` / `has_id_token` reflect the ciphered columns; `expired` matches `IdentityStore.masked()` for naive and aware `expires_at`. |
| `test_safe_fields_intersects_never_unions` | 1 | `safe_fields(["access_token", "email"]) == ["email"]`; `safe_fields(["access_token"]) == []`. |
| `test_redaction_shape_matches_masked` | 1 | Key set agrees with `IdentityStore.masked()` so the two surfaces cannot drift. |
| `test_policy_allows_denies_without_pdp` | 2 | No `abac` / `security` on the app ⇒ `(False, …)`. |
| `test_policy_allows_denies_undeclared_policy` | 2 | PDP present, policy absent ⇒ `(False, …)`. |
| `test_policy_allows_denies_on_evaluation_error` | 2 | A policy whose `is_allowed` raises ⇒ `(False, …)`, no exception escapes. |
| `test_policy_allows_grants_for_superuser_group` | 2 | Pack policy + `groups=["superuser"]` ⇒ `(True, …)`. |
| `test_acting_user_requires_session` | 3 | No session ⇒ 401. |
| `test_acting_user_superuser_via_group_only` | 3 | `userinfo={"groups": ["superuser"]}` is a superuser; `groups="ex_superuser_revoked"` is not (guards the `_check_superuser` contract, cf. `tests/test_check_superuser.py`). |
| `test_authorize_owner_needs_no_policy` | 3 | Owner is allowed with no PDP configured at all. |
| `test_authorize_superuser_refresh_denied` | 3 | `identity:refresh` is not in `superuser_actions` ⇒ refused even when the policy would allow (D4). |
| `test_authorize_cross_user_audited` | 3 | `AuditLog.log` called once with a `PolicyResponse` carrying `.response` and `.rule`. |
| `test_get_foreign_identity_returns_404` | 4 | Non-owner `GET` by `identity_id` ⇒ 404, body contains no provider/column data. |
| `test_get_forces_owner_filter` | 4 | Listing without params issues `filter(user_id=<acting>)`. |
| `test_get_foreign_user_id_param_refused` | 4 | `?user_id=<other>` as a non-superuser ⇒ 403, and no `TypeError`/500. |
| `test_fields_param_cannot_project_tokens` | 4 | `?fields=access_token,refresh_token,email` returns `email` only. |
| `test_filter_param_rejected` | 4 | `?_filter=access_token=x` ⇒ 400 and `_filtering()` is never reached. |
| `test_meta_strips_credential_columns` | 4 | `:meta` schema omits `IDENTITY_CREDENTIAL_COLUMNS`. |
| `test_write_to_credential_column_refused` | 4 | Owner `PATCH {"access_token": "..."}` ⇒ 400. |
| `test_cross_user_write_refused` | 4 | Non-superuser `PATCH`/`PUT`/`POST`/`DELETE` on a foreign row ⇒ 403/404. |
| `test_superuser_revoke_and_delete_allowed` | 4 | Superuser `PATCH {"enabled": false}` and `DELETE` succeed and are audited; `PATCH {"display_name": …}` on a foreign row ⇒ 403. |
| `test_hidden_lists_are_per_subclass` | 4 | `UserIdentityHandler._hidden is not ModelView._hidden`; instantiating another `ModelHandler` first does not change the identity response. |
| `test_model_without_user_id_fails_closed` | 4 | A configured model lacking `user_id` ⇒ 501 on every verb. |
| `test_policy_pack_parses` | 5 | `YAMLStorage._parse_file()` on the new file yields one `resource` policy named `user_identities_admin_access` with the three actions and `subjects.groups == {"superuser"}`. |

### Integration Tests

| Test | Description |
|---|---|
| `test_identity_surface_end_to_end_owner` | Owner links an identity through the vault, then reads it through `/api/v1/user_identity/{id}`: metadata present, zero token bytes anywhere in the payload. |
| `test_identity_surface_end_to_end_superuser` | Superuser reads, revokes and deletes a foreign identity; responses redacted, three audit records written, a `PUT` refresh attempt refused. |

### Test Data / Fixtures

```python
@pytest.fixture
def identity_row():
    """UserIdentity double with ciphered token columns populated."""

@pytest.fixture
def owner_session():   # user_id=42, groups=["users"]
    ...

@pytest.fixture
def superuser_session():  # user_id=7, groups=["superuser"]
    ...

@pytest.fixture
def pdp_with_pack(tmp_path):
    """PDP whose YAMLStorage points at abac/default_policies/."""
```

---

## 5. Acceptance Criteria

> This feature is complete when ALL of the following are true:

- [ ] `pytest tests/unit/identity/test_identity_redaction.py tests/unit/identity/test_user_identity_handler_access.py tests/unit/identity/test_identity_policy_pack.py -v` passes.
- [ ] `pytest tests/unit/identity tests/unit/vault tests/test_check_superuser.py tests/test_check_access.py -q` passes (no regression on the existing identity, vault and authorization suites).
- [ ] No response from `/api/v1/user_identity*` contains `access_token`, `refresh_token`, `id_token` or `key_version` under any combination of `fields`, `_filter`, `:meta`, primary key or query parameters — asserted, not assumed.
- [ ] A non-superuser cannot read, write or delete an identity whose `user_id` differs from the session `user_id`; reads by primary key answer 404, not 403.
- [ ] A superuser can read (redacted), revoke (`enabled=false`) and delete a foreign identity, and cannot refresh its tokens or edit any other column on it.
- [ ] With ABAC absent, with the PDP present but the policy undeclared, and with a policy that raises on evaluation, cross-user access is denied in all three cases (fail-closed) while owner access keeps working.
- [ ] `?_filter=` is refused with 400 on this handler, so `ModelView._filtering()`'s raw-SQL path is unreachable from the identity surface.
- [ ] `navigator_auth/abac/default_policies/user_identities_owner_or_admin.yaml` parses through `YAMLStorage._parse_file()` and declares `user_identities_admin_access`.
- [ ] Every cross-user decision (allow and deny) produces one `AuditLog` record naming the actor, the action, the target `user_id` and the policy rule.
- [ ] `/api/v1/user_identity*` routes still exist with the same paths and methods — no client-visible breakage beyond the removal of credential columns and the refusal of `_filter` (G4).
- [ ] `documentation/identity-vault.md` documents the owner-or-superuser rule, the redacted superuser view and the refused parameters.
- [ ] `ruff check navigator_auth/identity/redaction.py navigator_auth/handlers/identity_guard.py navigator_auth/handlers/userattrs.py navigator_auth/decorators.py` is clean.

---

## 6. Codebase Contract (anti-hallucination)

> Every entry below was read on `dev` @ `67c700e` on 2026-10-23.

### Exists — navigator-auth

| Symbol | Location | Signature / fact |
|---|---|---|
| `UserIdentity` | `navigator_auth/models.py:77` | `asyncdb.models.Model`; PK `identity_id: UUID`; `user_id: User = Column(required=True, fk="user_id|username", api="users")`; credential columns `access_token/refresh_token/id_token: Optional[bytes]`, `token_type`, `expires_at`, `refreshed_at`, `key_version`, `provider_user_id`, `scopes`, `auth_data`, `attributes`, `enabled`; `Meta.name = "user_identities"`, `Meta.schema = AUTH_DB_SCHEMA`, `Meta.strict = True` |
| `VwUserIdentity` | `navigator_auth/models.py:119` | read-only view model; **no** credential columns; `Meta.name = "vw_user_identities"` |
| `UserIdentityHandler` | `navigator_auth/handlers/userattrs.py:53` | `class UserIdentityHandler(ModelHandler)`; `model = UserIdentity`; `model_name = AUTH_USER_IDENTITY_MODEL`; `pk = "identity_id"`; single method `async def _set_user_id(self, value, column, data)` |
| `ModelHandler` (the one in use) | `navigator_auth/handlers/handler.py:1-10` | `class ModelHandler(ModelView)` from `navigator.views`; `dbname = "authdb"`; `async def _set_created_by(self, value, column, **kwargs)` |
| `ModelHandler` (unused) | `navigator_auth/handlers/model.py:21` | a *second*, independent `ModelHandler(BaseView)` in this repo. `userattrs.py:17-18` imports from `.handler`, with `from .model import ModelHandler` commented out — do NOT edit `handlers/model.py` believing it serves `/api/v1/user_identity` |
| Route registration | `navigator_auth/handlers/__init__.py:58-65` | `r"/api/v1/user_identity/{id:.*}"` → `api_auth_useridentity_id`; `r"/api/v1/user_identity{meta:\:?.*}"` → `api_auth_useridentity` |
| `BaseIdentityView._user_id` | `navigator_auth/handlers/user_identities.py:38` | resolves `user_id` from `self.user` then the session; `_json_error(401, …)` when absent |
| `IdentityStore.masked` | `navigator_auth/identity/store.py:465` | `def masked(self, identity: UserIdentity) -> dict` — returns `expired, identity_id, auth_provider, provider_user_id, scopes, token_type, expires_at, refreshed_at, created_at, enabled, has_refresh_token, has_id_token, profile`; no token material |
| `IdentityStore.decrypt_credential` | `navigator_auth/identity/store.py:444` | `-> TokenResponse`; raises `IdentityCredentialError` |
| `IdentityStore.update_tokens` | `navigator_auth/identity/store.py:409` | `async def update_tokens(self, identity: UserIdentity, token: TokenResponse) -> UserIdentity` — the only legitimate writer of credential columns |
| `_check_superuser` | `navigator_auth/decorators.py:291` | `def _check_superuser(userinfo: dict, user: object = None) -> bool`; checks `superuser`/`is_superuser`, then `SUPERUSER_GROUP` membership on a real collection only, then `user.groups[].group`/`group_name` |
| `SUPERUSER_GROUP` | `navigator_auth/decorators.py:288` | `= "superuser"` |
| `is_superuser` | `navigator_auth/decorators.py:315` | decorator; takes `content_type` only — cannot express row ownership, hence not sufficient alone |
| `allowed_groups` | `navigator_auth/decorators.py:414` | `(groups: list, content_type: str = "application/json") -> Callable` |
| `check_access` | `navigator_auth/decorators.py:1170` | `(policy, action=None, resource=None, resource_type=None, require_all=False, content_type="application/json")`; docstring states it "always fails closed" |
| `_check_policies` | `navigator_auth/decorators.py:1103` | `async (request, names: list, action, resource, resource_type, require_all) -> tuple[bool, str, Any]`; denies when `_get_pdp` is `None`, when `_find_policy` returns `None`, and on any evaluation exception |
| `_get_pdp` | `navigator_auth/decorators.py:994` | reads `request.app["abac"]`, else `getattr(request.app["security"], "pdp", None)` |
| `_abac_eval_context` | `navigator_auth/decorators.py:1044` | builds the `EvalContext` the PDP would build |
| `_apply_decorator` | `navigator_auth/decorators.py:48` | the func-vs-method dispatch used by every decorator here |
| `EvalContext.__init__` | `navigator_auth/abac/context.py:89` | `(request, user, userinfo, session, *args, org_id=None, client_id=None, **kwargs)`; stores `user`, `userinfo`, `session`, `auth_method`, `mfa`, `org_id`, `client_id` — **no row/object ownership key** |
| `ResourcePolicy` | `navigator_auth/abac/policies/resource_policy.py:7` | `__init__(name, effect, description, resources, actions, subjects, conditions, environment, priority, enforcing, org_id=1, client_id=1)`; `covers_resource`, `covers_action`, `matches_subject`, `evaluate_conditions`, `evaluate`, `is_allowed` |
| `ResourcePolicy.evaluate_conditions` | `navigator_auth/abac/policies/resource_policy.py:119` | custom conditions do `actual = getattr(ctx, key, None)` and `if actual is None: continue` — a missing attribute **passes** |
| `SubjectSpec` | `navigator_auth/abac/policies/resources.py:128` | `groups/users/roles/exclude_groups/exclude_users`; `from_dict`; `matches_user(username, user_groups, user_roles)`; `'*'` in groups = any authenticated user |
| `ResourceType` | `navigator_auth/abac/policies/resources.py:15` | `TOOL, KB, VECTOR, AGENT, MCP, URI, DATASET, WIDGET, CARD, SLUG, DATASOURCE, DRIVER, RAW_QUERY` |
| `PolicyResponse` | `navigator_auth/abac/policies/abstract.py:19` | `ClassDict` with `effect`, `response`, `rule` — the shape `AuditLog.log` expects |
| `AuditLog.log` | `navigator_auth/abac/audit.py:277` | `async def log(self, answer, status, user, *, tenant: str = None)`; `answer.response` / `answer.rule` read by the backends |
| `YAMLStorage._parse_file` | `navigator_auth/abac/storages/yaml_storage.py:103` | accepts `version`, `defaults.effect`, `policies[]` with `name, effect, description, resources, actions, subjects{groups,users,roles,…}, conditions{context,environment}, priority, enforcing, policy_type` (default `resource`) |
| `POLICY_STORAGE_DIR` | `navigator_auth/conf.py:705` | default `BASE_DIR / "env" / "policies"` |
| `AUTH_USER_IDENTITY_MODEL` | `navigator_auth/conf.py:150` | `config.get(..., fallback=None)` — when set, `ModelView.__init__` swaps the model |
| `admin_full_access.yaml` | `navigator_auth/abac/default_policies/admin_full_access.yaml` | existing pack entry already granting `uri:*` to groups `superuser`, `admin`, `priority: 100` |
| `_require_superuser` | `navigator_auth/handlers/client_access.py:57` | the existing admin idiom, but attribute-only (no group check) — reference, not reuse |
| Handler test pattern | `tests/unit/identity/test_identity_handlers.py:1-67` | `make_mocked_request` + `FakeSession` + `patch("navigator_auth.decorators.get_session")` **and** the handler module's own `get_session` |
| `_check_superuser` tests | `tests/test_check_superuser.py:1-45` | existing type-confusion cases to keep green |

### Exists — upstream `navigator` (read, not modified)

| Symbol | Location | Fact |
|---|---|---|
| `ModelView` | `.venv/lib/python3.11/site-packages/navigator/views/model.py:57` | `_required/_primaries/_hidden` declared as **class** attributes (`:77-79`) |
| `ModelView._get_model` | `…/model.py:130-152` | appends `repr=False` columns to `self._hidden` **in place**, guarded by `if not self._primaries` — shared across subclasses |
| `ModelView._model_response` | `…/model.py:158-213` | `elif self._hidden is not None: _fields = self._hidden`, then projects **only** `_fields` — the whitelist inversion |
| `ModelView._get_data` | `…/model.py:317-418` | calls every `_filter_<column>` hook, then `get(**{**_filter, **args})` on the PK path and `filter(**qp, **_filter)` on the query path (duplicate key ⇒ `TypeError`) |
| `ModelView._filtering` | `…/model.py:419-447` | `SELECT {field} FROM {schema}.{table} WHERE {field} LIKE '{value}%'` from the unvalidated `_filter` query param |
| `ModelView.get/put/patch/post/delete` | `…/model.py:449, 907, 691, 1062, 1400` | each decorated `@service_auth` (`:106-117`): session + `self._userid`, then `_post_auth` |
| `AbstractModel._pre_*` | `.venv/.../navigator/views/abstract.py:553-571` | `_pre_get/_pre_patch/_pre_put/_pre_post/_pre_delete`, all `async (*args, **kwargs) -> True` |
| `AbstractModel.get_parameters` | `.venv/.../navigator/views/abstract.py:434` | returns `[args, meta, qp, fields]`, popping `fields` out of `qp` |
| `AbstractModel.get_userid` | `.venv/.../navigator/views/abstract.py:310` | `async (session, idx="user_id")` |

### Does NOT exist (do not reference)

- `navigator_auth/identity/redaction.py` — created by Module 1.
- `navigator_auth/handlers/identity_guard.py` — created by Module 3.
- `navigator_auth.decorators.policy_allows` — created by Module 2. Today only
  the private `_check_policies` exists.
- `ResourceType.IDENTITY` / `ResourceType.MODEL` — not in the enum
  (`abac/policies/resources.py:15-30`). Use `ResourceType.URI`.
- Any `owner`, `object_owner`, `resource_owner` or `row_user_id` key on
  `EvalContext` — ownership is not expressible in the policy language.
- An `ObjectPolicy`-based row filter for this surface. `PDP.filter_obj`
  (`abac/pdp.py:616`) and `ObjectPolicy._filter` (`policies/obj.py:208`)
  filter opaque object *names*, not SQL rows.
- Any loader that reads `navigator_auth/abac/default_policies/`. No Python
  file references that directory; it is a pack an operator copies into
  `POLICY_STORAGE_DIR`. The guard therefore must not assume the policy is
  loaded.
- `navigator_auth/libs/json.py` — the import in `models.py:14` is
  `from .libs.json import json_encoder`; the module is not at that literal
  path (packaged elsewhere). Do not try to patch bytes serialization there.
- A `superuser` flag on `UserIdentity`. `navigator_auth/identities.py:235`
  `superuser` belongs to the auth **user** identity object, not to this
  model.

---

## 7. Implementation Notes & Constraints

### Patterns to Follow

- Async-first; no blocking I/O in the guard. The policy evaluation path is
  already async (`_check_policies`).
- Google-style docstrings and strict type hints on every new symbol
  (`.claude/rules/python-development.md`).
- `self.logger` / module logger, never `print`. Note `ModelView._get_data`
  contains stray `print("FILTER")` / `print("ALL")` upstream calls — do not
  copy that style.
- Refusals go through the handler's own error helpers so the response shape
  matches the rest of `navigator_auth/handlers/`.
- Deny messages must not confirm the existence of a foreign row: the
  primary-key path answers 404 with a generic body.
- The guard is a mixin placed **before** `ModelHandler` in the MRO so its
  hooks win.

### Known Risks / Gotchas

- **Upstream `_hidden` whitelist inversion** (`…/navigator/views/model.py:178-179`)
  — the single highest-risk item. Mitigation: never rely on `_hidden`;
  declare per-subclass empty lists and redact in an overridden
  `_model_response`. A task must *reproduce* the current behaviour first and
  record it in the task notes, because the projection depends on
  instantiation order across the whole process.
- **Shared class-level `_required`/`_primaries`/`_hidden`** — mutated in
  place by `_get_model()`; another handler can change this one's behaviour.
  Mitigation: per-subclass copies (and this is why a test asserts the
  identity of those lists).
- **Duplicate-keyword 500** — `filter(**qp, **_filter)` raises `TypeError`
  when the caller passes `?user_id=`. Sanitize `qp` *before* the hook runs;
  do not count on the merge to resolve the conflict.
- **`_filter` raw SQL** — refusing the parameter is the mitigation; do not
  attempt to sanitize the field/value and let it through.
- **`conditions` fail-open in `ResourcePolicy`** — `if actual is None:
  continue` means a condition on a key the context does not carry is
  *satisfied*. Never express the ownership rule as a policy condition.
- **Swappable model** (`AUTH_USER_IDENTITY_MODEL`) — a deployment pointing
  this handler at a model without `user_id` (e.g. a custom view) must fail
  closed with 501, not silently serve unfiltered rows.
- **Policy pack is not auto-loaded** — a stock deployment that never copies
  `default_policies/` into `POLICY_STORAGE_DIR` will have *no* superuser
  cross-user access. That is the intended fail-closed outcome; the docs must
  say so explicitly, or operators will read it as a bug.
- **Audit volume** — a superuser listing many users' identities writes one
  record per decision, not per row. Keep the audit call at the decision
  level.

### External Dependencies

| Package | Version | Reason |
|---|---|---|
| — | — | None. Everything needed (`pyyaml`, `aiohttp`, `navigator-session`, `asyncdb`, `datamodel`) is already a dependency. |

---

## 8. Open Questions

Resolved before drafting (user decisions, 2026-10-23) — carried into the
sections named:

- [x] How is owner-or-superuser enforced? — *Resolved by Jesus Lara*: **ABAC
  policy + default-deny in the handler.** The handler applies a hard gate
  (row owner, or `superuser` group) **and** a YAML policy ships in
  `abac/default_policies/` so the PDP governs it; the code never depends on
  the policy existing — absent PDP or policy ⇒ deny. → §2 Overview layers 1–2,
  §3 Modules 3 & 5, §5 criterion 6.
- [x] What happens to the generic `/api/v1/user_identity` route? — *Resolved
  by Jesus Lara*: **harden and keep.** Same paths and verbs, with a forced
  `user_id` filter, redaction and a superuser gate for cross-user access. No
  deprecation, no removal. → §1 G4, §3 Module 4, §5 criterion 10.
- [x] What does a superuser see on another user's identity? — *Resolved by
  Jesus Lara*: **the `masked()` shape as-is** — provider, `provider_user_id`,
  scopes, token type, timestamps, `expired`, `enabled`,
  `has_refresh_token`/`has_id_token` and the `auth_data` profile. Zero token
  material for anyone, owner included; the owner's real credential stays with
  `/api/v1/user/identities/{provider}/credential`. → §2 Data Models, §3
  Module 1, §5 criterion 3.
- [x] What may a superuser write on another user's identity? — *Resolved by
  Jesus Lara*: **revoke and delete only** (`enabled=false`, `DELETE`). No
  token refresh, no editing other columns. → §3 Module 4 behaviour table, §5
  criterion 5.

Still open:

- [ ] Should the refused `_filter` parameter answer **400** (malformed
  request, as specified) or be silently ignored? 400 is specified because a
  silent drop can look like a successful filter; confirm this is acceptable
  for existing clients — *Owner: Jesus Lara*
- [ ] Is `auth_data` (the full provider profile) acceptable in the superuser
  view, given it is PII the user never explicitly shared with an
  administrator? D3 says yes (it is in `masked()` today); flagging it because
  it is the one PII decision this spec inherits rather than makes — *Owner:
  Jesus Lara*
- [ ] Should the same guard be applied to `UserAccountHandler`
  (`handlers/userattrs.py:20`), which exposes `auth.user_accounts` with the
  same unrestricted-CRUD shape? Out of scope here (§1 Non-Goals); needs its
  own spec if the answer is yes — *Owner: Jesus Lara*
- [ ] Report the three upstream `navigator.views.ModelView` defects (whitelist
  inversion, shared class attributes, `_filtering` SQL interpolation) to the
  `navigator` project? — *Owner: Jesus Lara*

---

## 9. Design Research Cross-Check

**Model**: —
**Status**: skipped (no exploration document for this slug — `/sdd-spec` was
invoked directly with an inline brief, so there is no *accepted* brainstorm or
proposal to review; `sdd/templates/design_research.prompt.md` and
`design_research.schema.json` are also not present in this repository)

| Suggestion | Disposition | Reason | Landed in |
|---|---|---|---|
| — | — | — | — |

---

## Worktree Strategy

- **Default isolation unit**: `per-spec`. One worktree,
  `.worktrees/feat-FEAT-105-user-identities-ownership-abac`, branched from
  `origin/dev`; tasks run sequentially inside it.
- **Rationale**: Modules 3, 4 and 6 all converge on `handlers/userattrs.py`
  and its tests; parallel worktrees would collide on the same file and on the
  same behaviour table.
- **Parallelizable subset** (if a pool is used): Module 1 (redaction),
  Module 2 (`policy_allows`) and Module 5 (policy YAML) touch disjoint files
  and have fully specified contracts, so they can run concurrently *before*
  Modules 3 → 4 → 6, which must be sequential.
- **Cross-feature dependencies**: none. No other open spec touches
  `handlers/userattrs.py`, `decorators.py` or `identity/`.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-10-23 | Jesus Lara | Initial draft — owner-or-superuser ABAC ownership and redaction for `auth.user_identities` (D1–D4 resolved up front) |
