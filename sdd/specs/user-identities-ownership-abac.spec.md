---
type: feature
base_branch: dev
---

<!-- LANGUAGE: English only. -->

# Feature Specification: Owner-or-Superuser ABAC Ownership for the Auth Model CRUD Surfaces

**Feature ID**: FEAT-105
**Date**: 2026-10-23
**Author**: Jesus Lara
**Status**: draft
**Target version**: 0.29.0

> **Scope note (rev 0.2)**: this spec started at `auth.user_identities` only.
> While auditing that surface, the same unrestricted-CRUD shape was found on
> `auth.user_accounts` and — with a **plaintext JWT** in it — on
> `auth.partner_keys`. Per the 2026-10-23 decisions (§8 Q7), all three are in
> scope and share one reusable guard.

---

## 1. Motivation & Business Requirements

### Problem Statement

Three HTTP surfaces in `navigator_auth/handlers/` expose auth tables through
**generic model CRUD** with no ownership binding and no redaction. Each one is
reachable by any authenticated session.

**A — `auth.user_identities` (the Identity Vault row).**
`UserIdentityHandler` (`handlers/userattrs.py:53-59`) is mounted at
`/api/v1/user_identity/{id:.*}` and `/api/v1/user_identity{meta}`
(`handlers/__init__.py:58-65`). Its base, `ModelHandler`
(`handlers/handler.py:1-10`), is `navigator.views.ModelView` — unrestricted
CRUD. The model (`models.py:77-117`) carries the linked external credential:
`access_token`, `refresh_token`, `id_token` (ciphered `bytes`), plus
`provider_user_id`, `scopes`, `key_version`, the provider profile `auth_data`
and PII (`email`, `phone`, `nickname`, `short_bio`). There is **no ownership
check**: any session can `GET`/`PUT`/`PATCH`/`POST`/`DELETE` another user's
identity by `identity_id`, or list and filter the whole table with
`?user_id=<victim>`. The only ownership-ish hook, `_set_user_id`
(`handlers/userattrs.py:58`), merely *fills* `user_id` from the session on
writes that omit it; it restricts no read and blocks no explicit `user_id`.

The contrast is deliberate and documented: the purpose-built Identity Vault
handler (`handlers/user_identities.py`, `/api/v1/user/identities*`) anchors
every operation to the session `user_id` (`:38-59`) and masks every response
(`IdentityStore.masked()`, `identity/store.py:465`). Its module docstring even
says *"Access to other users' credentials … is out of scope here — compose it
via the ABAC layer."* That composition was never built.

**B — `auth.user_accounts` (social accounts).**
`UserAccountHandler` (`handlers/userattrs.py:20-51`), same `ModelView` base,
mounted at `/api/v1/user_accounts/{id:.*}` and `/api/v1/user_accounts{meta}`
(`handlers/__init__.py:38-46`). `UserAccount` (`models.py:297-314`) holds no
token material, but the ownership hole is identical and the data is PII
(`provider`, `uid`, `address`, the `account` dict). It also carries a **second
SQL-injection sink**: `_set_address` (`handlers/userattrs.py:29-50`)
interpolates the client-supplied `data['provider']` into
`SELECT social_url FROM auth.social_networks WHERE social_network =
'{provider}'` via `str.format` and runs it with `conn.fetchval`.

**C — `auth.partner_keys` (partner authentication tokens).**
`PartnerKeyHandler` (`handlers/partners.py:38-39`) is mounted at
`/api/v1/partner/tokens/{id:.*}` and `/api/v1/partner/tokens{meta}`
(`handlers/__init__.py:47-56`). This one uses the **other** `ModelHandler` in
the repo — the local `BaseView`-based class in `handlers/model.py:21`, not
navigator's `ModelView`. `PartnerKey.token` (`handlers/partners.py:24`) is a
**plaintext JWT signed with `AUTH_TOKEN_SECRET`**, declared with neither
`repr=False` nor `secret=True`, and the local base returns the whole model
(`handlers/model.py:85-105`). Any authenticated session can therefore read
every partner's bearer token, and `PartnerKey` has **no `user_id` column at
all**, so there is no owner to fall back on: this surface has no legitimate
non-admin use.

On top of the missing authorization, the upstream response layer offers no
protection on surfaces A and B. The four facts below were re-verified by
executing `datamodel` 0.10.21 directly on 2026-10-23, which **corrected**
rev 0.1 of this spec: the mechanism is not what the code reads like.

- **No projection happens at all today, so the full row ships.**
  `ModelView._get_model()` tries to collect hidden columns with
  `field.metadata["repr"] is False`
  (`.venv/.../navigator/views/model.py:145-150`), but `repr` is **not** a
  `field.metadata` key — datamodel exposes it as the dataclass `Field.repr`
  attribute, and `metadata` carries only `required, nullable, primary,
  validator, alias, widget, encoder, decoder, readonly` plus `secret` when
  declared. The lookup therefore raises `KeyError` on every column and is
  swallowed, so `_hidden` is **always `[]`**. In `_model_response` that makes
  `_fields` falsy and `result = response` — **the entire model row is
  serialized**, ciphered `access_token` / `refresh_token` / `id_token` bytes
  included. That is the live leak on `/api/v1/user_identity`.
- **A latent whitelist inversion sits behind it.** `_model_response()` uses
  `_hidden` as the **whitelist of fields to return** (`:178-179`,
  `_fields = self._hidden`), not as an exclusion list. For `UserIdentity` the
  `repr=False` columns are *exactly* the credential set, so "fixing" the
  metadata key alone would have flipped the endpoint from returning
  everything to returning **only** the credential columns. It also leaves
  `_fields` unbound (→ `UnboundLocalError`) when `_hidden` is `None`.
- **Shared class-level state.** `_required` / `_primaries` / `_hidden` are
  class attributes of `ModelView` (`:77-79`) mutated in place via
  `self._hidden.append(...)`, and the derivation is guarded by
  `if not self._primaries`. So the first View instantiated in a process fills
  them for every other subclass, and every later subclass skips derivation
  entirely — one handler's column metadata driving an unrelated handler's
  response projection.
- **`?fields=` projects anything.** `get_parameters()`
  (`.venv/.../navigator/views/abstract.py:434-447`) passes the caller's list
  straight into `_model_response(..., fields=...)`, which honours it
  verbatim. This one **is** live: `?fields=access_token,refresh_token`
  returns those columns.
- **`?_filter=` is a latent raw-SQL sink, currently unreachable.**
  `_filtering()` (`.venv/.../navigator/views/model.py:419-447`) interpolates
  **unvalidated** `field` and `value` into
  `SELECT {field} FROM {schema}.{table} WHERE {field} LIKE '{value}%'` — a
  column-projection oracle *and* an injection point on the credential table.
  It never reaches the database today because the line above it,
  `ftype = self.get_model.column(field)`, calls an **instance** method on the
  Model **class**, binding `field` to `self`; that raises `TypeError`, which
  `get()` catches (`:494-499`) and answers **406**. The sink is one unrelated
  bug-fix away from being exploitable, and `filter_param.split('=')` raises
  `ValueError` on a malformed parameter.

The business rule the product wants is simple and is written nowhere:
**querying, editing and managing these rows is the user's own prerogative over
their own rows, or a `superuser`'s — and a superuser never sees credentials.**

### Goals

- **G1** — Bind every row operation to an owner: non-superusers reach only
  rows whose owner column equals the session `user_id`.
- **G2** — Allow cross-user access only to the `superuser` group, governed by
  a named ABAC policy, **failing closed**: no PDP, no policy, unreadable
  decision ⇒ deny.
- **G3** — Never serialize credential material to anyone, through any
  parameter combination, by construction (explicit allowlist) — not by relying
  on the upstream `_hidden` whitelist inversion.
- **G4** — Keep all six routes working with the same paths and verbs
  (hardened in place, not deprecated or removed).
- **G5** — Constrain superuser writes on someone else's row to revoke
  (`enabled=false` / `revoked=true`) and delete.
- **G6** — Audit every cross-user and every admin decision through the
  existing `AuditLog` (`abac/audit.py:189`).
- **G7** — Replace the `?_filter=` raw-SQL path on these handlers with a
  **parameterized** filter restricted to allowlisted columns (§8 Q5).
- **G8** — `auth.partner_keys` becomes a **superuser-only** surface, and its
  `token` is returned exactly once — in the creation response — never on a
  read.
- **G9** — Parameterize `_set_address`'s `social_networks` lookup, closing the
  second injection sink.

### Non-Goals (explicitly out of scope)

- Changing the Identity Vault handler (`handlers/user_identities.py`). It is
  already owner-scoped and masked; `/api/v1/user/identities/{provider}/credential`
  keeps serving the **owner** their own decrypted credential, untouched.
- The other generic-CRUD handlers in this repo, audited and deliberately
  deferred: `UserManager` (`handlers/users/user.py:11`, `ModelView` over
  `User` — note `User.password` is `secret=True`, `models.py:51`),
  `GroupManager` / `UserGroupManager` / `GroupPermissionManager`
  (`handlers/groups.py:14-28`), `PermissionHandler`
  (`handlers/permissions.py:7`) and `PolicyHandler`
  (`abac/policyhandler.py:8`, already `groups_protected(['superuser'])`).
  The guard built here is written to be reusable by them; applying it is a
  separate spec.
- `UserDevices` (`models.py:143`, `token` + `api_key`): **not exposed** — no
  handler and no route reference it. Verified, nothing to do.
- Row-level ownership expressed *inside* the policy language.
  `ResourcePolicy.evaluate_conditions` can only compare `EvalContext`
  attributes (`abac/policies/resource_policy.py:119-150`) and silently
  **passes** when the attribute is missing (`if actual is None: continue`), so
  ownership stays in code; the policy governs only the admin capability.
- A `ResourceType.IDENTITY` enum member. The policies use the existing
  `ResourceType.URI` (`abac/policies/resources.py:15-30`), consistent with
  `uri:*` in `abac/default_policies/admin_full_access.yaml`.

---

## 2. Architectural Design

### Prerequisite: `ModelView` fixed in the `navigator` repository — DONE

Per §8 Q8 the upstream defects were repaired **first**, in
`phenobarbital/navigator` at `/home/jesuslara/proyectos/navigator/navigator`,
commit **`7bc5896`** (branch `fix/modelview-response-projection-and-filtering`,
cut from `origin/dev`). It is **merged into navigator's `origin/dev` and
version-bumped to `navigator-api` 3.2.4** (`a117f29`), i.e. in release
process. What landed there:

1. `_hidden` is derived from `secret=True` columns (the `metadata["repr"]`
   lookup never worked — see §1), and `repr=False` is deliberately **not**
   treated as a serialization rule, because Models commonly declare their
   primary key that way.
2. `_model_response()` treats `_hidden` as an **exclusion** list; an explicit
   `?fields=` request cannot name a hidden column; `dict` rows project by key;
   the `UnboundLocalError` path is gone.
3. `_required` / `_primaries` / `_hidden` are per-instance, with an explicit
   class-level declaration still winning.
4. `_filtering()` validates the column against the Model (400 otherwise),
   binds the value as `$1`, quotes the identifiers, and answers 400 on a
   malformed parameter instead of raising.

Evidence: 18 new unit tests in
`tests/test_modelview_projection_and_filtering.py`; suite 378 passed, with
the 3 `tests/utils/test_file_web.py` errors and the 2 `navigator_eventbus`
collection errors confirmed pre-existing by re-running against the stashed
change.

**This spec still does not depend on that fix, and the local hardening below
is not reduced because of it.** Three reasons:

- `pyproject.toml:53` pins `navigator-api>=0.5.0`, so navigator-auth installs
  against any navigator — including the 3.2.2 currently in this repo's
  `.venv`. A security property that holds only on the newest upstream release
  is not a security property until the floor is raised (§8 Q9).
- The deployed copy is whatever the environment resolved at install time.
  3.2.4 being tagged does not retro-fix a running deployment.
- Even on 3.2.4 it does **not** redact these surfaces: upstream derives
  `_hidden` from `secret=True`, and neither `UserIdentity.access_token`
  (`models.py:104-106`) nor `PartnerKey.token` (`handlers/partners.py:24`)
  is declared `secret=True`. Only this feature's explicit allowlist hides
  them.

### Overview

Four layers, each closed by default, shared by all three surfaces through one
reusable mixin:

1. **Ownership binding (code, mandatory).** `OwnerOrSuperuserGuard` resolves
   the acting `(user_id, is_superuser)` pair from the session using the
   hardened `_check_superuser` (`decorators.py:291-312`, which already resists
   `groups="ex_superuser_revoked"` substring confusion). Each handler declares
   its `owner_column`. Owner ⇒ allowed. Not owner ⇒ superuser path. Neither ⇒
   refused. A foreign row fetched by primary key answers **404**, not 403, so
   the id cannot be used as an existence oracle. `owner_column = None`
   (partner keys) means *no owner exists* ⇒ superuser-only for every verb.

2. **ABAC policy (configuration, authoritative for the admin path).** The
   superuser path additionally requires the handler's named policy to allow
   the action, taken programmatically through a new public `policy_allows()`
   wrapper over the existing fail-closed `_check_policies()`
   (`decorators.py:1103-1158`): no PDP ⇒ deny; policy not declared ⇒ deny;
   evaluation raises ⇒ deny. The policies ship in the default pack so a stock
   deployment behaves correctly, but the code never *depends* on the file
   existing — a missing policy only ever removes admin access, never grants
   it.

3. **Redaction (code, unconditional).** Every response is projected through
   `redact_row()`, driven by the handler's explicit `public_columns`
   allowlist. `credential_columns` can never appear — not via `fields=`, not
   via the safe filter, not via `:meta`, for any role. For
   `UserIdentityHandler` the projection is additionally shaped to match
   `IdentityStore.masked()` (`identity/store.py:465-496`) so the two identity
   surfaces cannot drift.

4. **Safe filtering (code, replaces upstream).** `_filtering()` is overridden.
   `?_filter=<field>=<value>` is accepted **only** when `<field>` is in
   `public_columns`, and is executed as a parameterized query
   (`conn.fetch_all("… WHERE <col> LIKE $1 AND <owner_col> = $2", …)`, the
   idiom already used in `passkey/store.py:44` and
   `middlewares/strategies.py:87`) with the ownership predicate ANDed in. A
   non-allowlisted or malformed field answers **400**. The upstream
   interpolation path becomes unreachable from these handlers.

### Component Diagram

```
  /api/v1/user_identity*   /api/v1/user_accounts*   /api/v1/partner/tokens*
            │                        │                        │
   UserIdentityHandler       UserAccountHandler        PartnerKeyHandler
   (navigator ModelView)     (navigator ModelView)     (LOCAL handlers/model.py)
            └────────────────────────┼────────────────────────┘
                                     ▼
                   ┌─────────────────────────────────────────┐
                   │  OwnerOrSuperuserGuard   (handlers/      │
                   │                           guards.py)    │
                   │  owner_column / credential_columns /    │
                   │  public_columns / policy_name /         │
                   │  superuser_actions                      │
                   │                                         │
                   │  acting_user()  ──▶ _check_superuser    │
                   │  authorize_row()                        │
                   │     ├─ owner?          ───────── allow  │
                   │     ├─ superuser? ──▶ policy_allows()   │
                   │     │                   └─ _check_       │
                   │     │                      policies     │
                   │     │                      (fail-closed)│
                   │     └─ else ──────────── 403 / 404      │
                   │  _sanitize_query()   fields / user_id   │
                   │  _safe_filter()      parameterized SQL  │
                   │  _audit()        ──▶ AuditLog.log()     │
                   └──────────────────┬──────────────────────┘
                                      ▼
                        redact_row()  (handlers/redaction.py)
```

### Integration Points

| Existing component | Integration type | Notes |
|---|---|---|
| `navigator.views.ModelView` (via `handlers/handler.py:4`) | overrides hooks | `_pre_get/_pre_put/_pre_patch/_pre_post/_pre_delete` (`abstract.py:553-571`), the `_filter_<column>` hook (`model.py:336-355`), `_model_response` (`model.py:158-213`), `_filtering` (`model.py:419-447`) |
| local `ModelHandler` (`handlers/model.py:21`) | overrides verbs | has **no** `_pre_*` and **no** `_filter_*` hooks — the guard is called at the top of each overridden verb, and `_post_get` (`:85`) is where redaction attaches |
| `navigator_auth.decorators._check_policies` (`:1103`) | wraps (new public API) | `policy_allows()` — fail-closed ABAC decision outside a decorator |
| `navigator_auth.decorators._check_superuser` (`:291`) | reuses | single source of truth; `client_access.py:57` `_require_superuser` checks only the attribute, not group membership, so it is NOT reused |
| `navigator_auth.decorators.is_superuser` (`:315`) | rejected | consults no policy, so it cannot satisfy G2's policy-governed path |
| `IdentityStore.masked()` (`identity/store.py:465`) | shape parity | the identity projection emits the same keys |
| `navigator_auth/abac/default_policies/` | adds file | parsed by `YAMLStorage._parse_file` (`abac/storages/yaml_storage.py:103`), loaded from `POLICY_STORAGE_DIR` (`conf.py:705`) |
| `AuditLog.log(answer, status, user, *, tenant=None)` (`abac/audit.py:277`) | uses | `answer` needs `.response` / `.rule` → a `PolicyResponse` is passed |
| `auth.social_networks` lookup (`handlers/userattrs.py:24-26`) | rewritten | `str.format` → `$1` parameter (G9) |

### Data Models

```python
# navigator_auth/handlers/redaction.py  (new) — generic, model-agnostic

def safe_fields(
    fields: Optional[list[str]], public_columns: frozenset[str]
) -> Optional[list[str]]:
    """Intersect a caller projection with an allowlist (never a union)."""
```

Per-surface column sets, declared on each handler:

| Handler | `owner_column` | `credential_columns` | `public_columns` |
|---|---|---|---|
| `UserIdentityHandler` | `user_id` | `access_token`, `refresh_token`, `id_token`, `key_version` | `identity_id`, `user_id`, `display_name`, `title`, `nickname`, `email`, `phone`, `short_bio`, `avatar`, `auth_provider`, `provider_user_id`, `scopes`, `token_type`, `expires_at`, `refreshed_at`, `created_at`, `enabled`, `auth_data`, `attributes` |
| `UserAccountHandler` | `user_id` | *(none)* | `account_id`, `user_id`, `provider`, `uid`, `address`, `account`, `created_at` |
| `PartnerKeyHandler` | `None` *(no owner column)* | `token` | `partner_id`, `name`, `partner`, `issuer`, `created_at`, `revoked`, `enabled`, `grants`, `programs` |

The identity projection keeps the `masked()` shape (§8 Q6): `auth_data` stays
visible as `profile`, token material is replaced by `has_refresh_token` /
`has_id_token`, and `expired` is derived from `expires_at`.

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
    known only at request time (e.g. the owner of a row).

    Returns:
        ``(allowed, reason, response)`` — ``response`` is the last
        ``PolicyResponse`` produced, or ``None`` when nothing was evaluated.
        ``allowed`` is ``False`` when ABAC is absent, the policy is not
        declared, or evaluation raised.
    """
```

```python
# navigator_auth/handlers/guards.py  (new)

class OwnerOrSuperuserGuard:
    """Owner-or-superuser authorization for generic model handlers.

    Base-agnostic: works over ``navigator.views.ModelView`` and over the
    local ``handlers/model.py`` ``ModelHandler``; it needs only
    ``self.request`` and a session.
    """

    owner_column: Optional[str] = "user_id"
    credential_columns: frozenset[str] = frozenset()
    public_columns: frozenset[str] = frozenset()
    policy_name: str = None
    superuser_actions: frozenset[str] = frozenset({"read", "revoke", "delete"})

    async def acting_user(self) -> tuple[int, bool]: ...
    async def authorize_row(
        self, action: str, owner_id: Optional[int],
        *, not_found_on_deny: bool = False,
    ) -> bool: ...
```

---

## 3. Module Breakdown

### Module 1: Generic redaction allowlist

- **Path**: `navigator_auth/handlers/redaction.py` *(new)*
- **Responsibility**: the projection primitives shared by all three surfaces.
  Pure and synchronous — no I/O, trivially testable.
- **Depends on**: nothing in this spec.

```python
"""Allowlist-driven redaction for the auth model CRUD surfaces (FEAT-105)."""
from typing import Any, Optional, Union
from datamodel import BaseModel

def safe_fields(
    fields: Optional[list[str]], public_columns: frozenset[str]
) -> Optional[list[str]]:
    """Intersect a caller projection with the allowlist (never a union)."""

def redact_row(
    row: Union[BaseModel, dict, None],
    public_columns: frozenset[str],
    fields: Optional[list[str]] = None,
) -> dict:
    """Project one row onto ``public_columns`` (∩ ``fields`` when given)."""

def redact_rows(
    rows: Any,
    public_columns: frozenset[str],
    fields: Optional[list[str]] = None,
) -> Any:
    """Vectorized :func:`redact_row`, preserving list-vs-scalar shape."""

def redact_schema(schema: dict, credential_columns: frozenset[str]) -> dict:
    """Strip credential columns from a ``Model.schema(as_dict=True)`` payload
    so ``:meta`` cannot enumerate them."""
```

### Module 2: Public ABAC evaluation API

- **Path**: `navigator_auth/decorators.py` *(modified)*
- **Responsibility**: expose `policy_allows()` so handlers take a fail-closed
  ABAC decision that depends on request-time data without importing a private
  symbol.
- **Depends on**: `_check_policies` (`decorators.py:1103`), `_get_pdp`
  (`:994`), `_find_policy` (`:1003`), `_policy_allows` (`:1031`).

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

Module exports updated so `from navigator_auth.decorators import policy_allows`
resolves.

### Module 3: `OwnerOrSuperuserGuard` mixin

- **Path**: `navigator_auth/handlers/guards.py` *(new)*
- **Responsibility**: the authorization decision, the query sanitation, the
  parameterized safe filter and the audit trail — kept out of the CRUD
  handlers so one implementation serves both handler bases and can be unit
  tested without HTTP plumbing.
- **Depends on**: Modules 1, 2; `_check_superuser` (`decorators.py:291`);
  `AuditLog` (`abac/audit.py:189`); `PolicyResponse` / `PolicyEffect`
  (`abac/policies/abstract.py:11-24`).

```python
"""Owner-or-superuser authorization for generic model handlers (FEAT-105)."""
from typing import Any, Optional
from navigator_session import get_session               # verified: navigator_auth/handlers/model.py:16
from navigator_auth.conf import AUTH_SESSION_OBJECT
from navigator_auth.decorators import _check_superuser  # verified: navigator_auth/decorators.py:291
from navigator_auth.decorators import policy_allows     # Module 2

class OwnerOrSuperuserGuard:
    owner_column: Optional[str] = "user_id"
    credential_columns: frozenset[str] = frozenset()
    public_columns: frozenset[str] = frozenset()
    policy_name: str = None
    superuser_actions: frozenset[str] = frozenset({"read", "revoke", "delete"})

    async def acting_user(self) -> tuple[int, bool]:
        """``(user_id, is_superuser)`` from the session; 401 when absent."""

    async def authorize_row(
        self, action: str, owner_id: Optional[int],
        *, not_found_on_deny: bool = False,
    ) -> bool:
        """Owner ⇒ True. Superuser ⇒ policy-gated and audited. Else refuse.

        ``owner_column is None`` (no owner exists, e.g. partner keys) ⇒ the
        superuser path is the ONLY path. ``not_found_on_deny`` answers 404
        instead of 403 so a primary-key probe cannot confirm a foreign row.
        """

    async def sanitize_query(self, qp: dict, fields: Optional[list]) -> tuple[dict, Optional[list]]:
        """Drop/refuse the parameter bypasses before any DB access.

        - ``fields`` → intersected with ``public_columns``.
        - an explicit foreign ``owner_column`` value ⇒ 403 for a non-superuser.
          It is refused rather than merged because ``filter(**qp, **_filter)``
          would raise ``TypeError`` on the duplicate keyword and surface as a
          500. verified: .venv/.../navigator/views/model.py:384
        """

    async def safe_filter(self, expr: str) -> list[dict]:
        """Parameterized replacement for ``ModelView._filtering`` (G7).

        ``expr`` is ``<field>=<value>``. ``<field>`` must be in
        ``public_columns`` AND a real model column, else 400. The value is
        bound as ``$1`` — never interpolated — and the ownership predicate is
        ANDed in for non-superusers.
        verified idiom: navigator_auth/passkey/store.py:44,
                        navigator_auth/middlewares/strategies.py:87
        """

    async def audit_decision(
        self, action: str, allowed: bool, owner_id: Optional[int], reason: str
    ) -> None:
        """Record the decision via ``AuditLog.log()``.
        verified: navigator_auth/abac/audit.py:277 — answer needs .response/.rule
        """
```

### Module 4: Harden `UserIdentityHandler`

- **Path**: `navigator_auth/handlers/userattrs.py` *(modified)*
- **Responsibility**: wire the guard into the identity CRUD endpoint and
  neutralize the upstream `_hidden` / `fields` / `_filter` hazards locally.
- **Depends on**: Modules 1, 3.

```python
class UserIdentityHandler(OwnerOrSuperuserGuard, ModelHandler):
    model: Any = UserIdentity                   # verified: navigator_auth/models.py:77
    model_name: str = AUTH_USER_IDENTITY_MODEL  # verified: navigator_auth/conf.py:150
    name: str = "User Identity"
    pk: str = "identity_id"

    owner_column: str = "user_id"
    credential_columns = frozenset({
        "access_token", "refresh_token", "id_token", "key_version"})
    public_columns = frozenset({...})           # §2 Data Models
    policy_name: str = "user_identities_admin_access"
    superuser_actions = frozenset({
        "identity:read", "identity:revoke", "identity:delete"})

    #: Vault-managed columns: never writable through the model surface.
    readonly_columns = frozenset({
        "access_token", "refresh_token", "id_token", "key_version",
        "provider_user_id", "token_type", "expires_at", "refreshed_at",
        "scopes"})

    # Per-subclass copies: ModelView mutates these CLASS-level lists in place
    # (self._hidden.append), contaminating every sibling handler.
    # verified: .venv/.../navigator/views/model.py:79, 144-148
    _hidden: list = []
    _required: list = []
    _primaries: list = []

    async def _set_user_id(self, value, column, data): ...   # existing, kept
    async def _filter_user_id(self, value, column, data):
        """Force ``WHERE user_id = <acting user>`` for non-superusers.
        verified: .venv/.../navigator/views/model.py:336-384"""
    async def _pre_get(self, *args, **kwargs) -> bool: ...     # identity:read
    async def _pre_put(self, *args, **kwargs) -> bool: ...     # owner only
    async def _pre_patch(self, *args, **kwargs) -> bool: ...   # owner | revoke
    async def _pre_post(self, *args, **kwargs) -> bool: ...    # owner | revoke
    async def _pre_delete(self, *args, **kwargs) -> bool: ...  # identity:delete
    async def _filtering(self, queryparams: dict): ...         # → safe_filter
    async def _model_response(self, response, fields=None, headers=None, status=200):
        """Redact to the masked() shape, then delegate upstream.
        verified: .venv/.../navigator/views/model.py:158-213 (the parent uses
        ``_hidden`` as a WHITELIST — this override never relies on it)."""
```

Behavioural contract:

| Verb / target | Owner | Superuser (other user) | Other user |
|---|---|---|---|
| `GET` by `identity_id` | redacted row | redacted row, audited | **404** |
| `GET` list / filter | own rows only (forced `user_id`) | `?user_id=<n>` allowed, audited | own rows only |
| `PUT` (insert) | own row (`user_id` forced) | 403 | 403 |
| `PATCH` / `POST` | own row, non-readonly columns | only `enabled=false`, audited | 403 |
| `DELETE` | own row | allowed, audited | **404** |
| `?fields=access_token` | dropped | dropped | dropped |
| `?_filter=auth_provider=git` | own rows, parameterized | allowed, audited | own rows |
| `?_filter=access_token=x` | **400** | **400** | **400** |
| `:meta` | schema minus credential columns | same | same |

Writing any `readonly_columns` member is refused with **400** for everyone,
owner included: those are vault-managed (`IdentityStore.update_tokens`,
`identity/store.py:409`). If the configured model has no `user_id` column
(`AUTH_USER_IDENTITY_MODEL` can swap it), ownership cannot be established and
every verb answers **501**.

### Module 5: Harden `UserAccountHandler`

- **Path**: `navigator_auth/handlers/userattrs.py` *(modified)*
- **Responsibility**: same guard over `auth.user_accounts`, plus closing the
  `_set_address` injection sink (G9).
- **Depends on**: Modules 1, 3.

```python
class UserAccountHandler(OwnerOrSuperuserGuard, ModelHandler):
    model: Any = UserAccount                    # verified: navigator_auth/models.py:297
    name: str = "User Account"
    pk: str = "account_id"

    owner_column: str = "user_id"
    credential_columns = frozenset()            # no token material on this model
    public_columns = frozenset({
        "account_id", "user_id", "provider", "uid", "address", "account",
        "created_at"})
    policy_name: str = "user_accounts_admin_access"
    superuser_actions = frozenset({
        "account:read", "account:revoke", "account:delete"})

    _hidden: list = []
    _required: list = []
    _primaries: list = []

    social_network: str = (
        "SELECT social_url FROM auth.social_networks "
        "WHERE social_network = $1"
    )  # G9: was str.format interpolation — verified: handlers/userattrs.py:24-26

    async def _set_user_id(self, value, column, data): ...   # existing, kept
    async def _set_address(self, value, column, data):
        """Resolve the social URL with a BOUND parameter.
        verified (vulnerable form): navigator_auth/handlers/userattrs.py:29-50"""
    async def _filter_user_id(self, value, column, data): ...
    async def _pre_get / _pre_put / _pre_patch / _pre_post / _pre_delete: ...
    async def _filtering(self, queryparams: dict): ...
    async def _model_response(self, response, fields=None, headers=None, status=200): ...
```

Behaviour mirrors Module 4's table, minus the credential rows (this model has
none) and with `account:*` actions.

### Module 6: Lock down `PartnerKeyHandler`

- **Path**: `navigator_auth/handlers/partners.py` *(modified)*
- **Responsibility**: make `auth.partner_keys` superuser-only and stop serving
  the plaintext JWT. This handler sits on the **local** `ModelHandler`
  (`handlers/model.py:21`), which has no `_pre_*` and no `_filter_*` hooks, so
  the guard is invoked at the top of each overridden verb and redaction
  attaches to `_post_get` (`handlers/model.py:85`).
- **Depends on**: Modules 1, 3.

```python
class PartnerKeyHandler(OwnerOrSuperuserGuard, ModelHandler):
    model: Any = PartnerKey                     # verified: navigator_auth/handlers/partners.py:15
    name: str = "Partner Key Authentication"
    pk: list[str] = ["partner_id"]              # NOTE: a list, not a str

    owner_column: Optional[str] = None          # no user_id column exists
    credential_columns = frozenset({"token"})
    public_columns = frozenset({
        "partner_id", "name", "partner", "issuer", "created_at", "revoked",
        "enabled", "grants", "programs"})
    policy_name: str = "partner_keys_admin_access"
    superuser_actions = frozenset({
        "partner:read", "partner:create", "partner:revoke", "partner:delete"})

    async def _get_token(self, value, column, data): ...     # existing, kept
    async def get(self): ...      # guard → super() → _post_get redacts
    async def put(self): ...      # guard → super(); token in the 201 body ONCE
    async def patch(self): ...    # guard → super(); token never echoed
    async def post(self): ...     # guard → super(); token only when it CREATES
    async def delete(self): ...   # guard → super()
    async def _post_get(self, result, fields=None):
        """Redact ``token`` out of every read.
        verified: navigator_auth/handlers/model.py:85-105"""
```

Behavioural contract:

| Verb | Superuser | Anyone else |
|---|---|---|
| `GET` (any form) | rows without `token` | **403** |
| `PUT` / `POST` that creates | 201 **including** `token` (once) | 403 |
| `PATCH` / `POST` that updates | 202 without `token` | 403 |
| `DELETE` | allowed, audited | 403 |
| `:meta` | schema minus `token` | 403 |

`PartnerKey.token` keeps its column definition for now; a follow-up may add
`repr=False` / `secret=True`, but the guard must not depend on it (the local
base ignores `repr`).

### Module 7: Default ABAC policies

- **Path**: `navigator_auth/abac/default_policies/auth_model_admin_access.yaml` *(new)*
- **Responsibility**: ship the three named policies the guards consult, in the
  format `YAMLStorage._parse_file` accepts (`policy_type` defaults to
  `resource` → `resources` plural + structured `subjects`).
- **Depends on**: nothing in code — the guards deny when a policy is absent.

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
    resources: ["uri:/api/v1/user_identity*"]
    actions: ["identity:read", "identity:revoke", "identity:delete"]
    subjects:
      groups: ["superuser"]
    priority: 90
    enforcing: true

  - name: user_accounts_admin_access
    effect: allow
    description: >-
      Superusers may read, revoke and delete other users' social accounts.
    resources: ["uri:/api/v1/user_accounts*"]
    actions: ["account:read", "account:revoke", "account:delete"]
    subjects:
      groups: ["superuser"]
    priority: 90
    enforcing: true

  - name: partner_keys_admin_access
    effect: allow
    description: >-
      Partner keys have no owner: only superusers may manage them. The signed
      token is returned once at creation and never on a read.
    resources: ["uri:/api/v1/partner/tokens*"]
    actions:
      ["partner:read", "partner:create", "partner:revoke", "partner:delete"]
    subjects:
      groups: ["superuser"]
    priority: 90
    enforcing: true
```

### Module 8: Tests

- **Path**: `tests/unit/handlers/test_model_redaction.py`,
  `tests/unit/handlers/test_owner_superuser_guard.py`,
  `tests/unit/handlers/test_user_identity_handler_access.py`,
  `tests/unit/handlers/test_user_account_handler_access.py`,
  `tests/unit/handlers/test_partner_key_handler_access.py`,
  `tests/unit/handlers/test_auth_model_policy_pack.py` *(all new;
  `tests/unit/handlers/` is a new package)*
- **Responsibility**: cover §4, following the existing handler-test pattern
  (`make_mocked_request` + patched `get_session`,
  `tests/unit/identity/test_identity_handlers.py:1-67`).
- **Depends on**: Modules 1–7.

### Module 9: Documentation

- **Path**: `documentation/identity-vault.md` *(modified)*,
  `documentation/pdp.md` *(modified)*
- **Responsibility**: document the owner-or-superuser rule, the redacted admin
  view, the three policy names, the superuser-only partner surface with
  return-once token semantics, and the refused/parameterized `_filter`.
- **Depends on**: Modules 1–7.

### Delegation-eligible modules

| Module | Delegation-eligible | Why / decided contract |
|---|---|---|
| 1 — Redaction | **Yes** | Signatures fixed; pure functions. |
| 2 — `policy_allows` | **Yes** | Thin wrapper; fail-closed semantics fixed. |
| 3 — Guard mixin | **No** | Deny-shape (404 vs 403), audit payload and the safe-filter SQL are design calls. |
| 4 — Identity handler | **No** | Interacts with undocumented upstream `ModelView` behaviour; per-verb judgement. |
| 5 — Account handler | **Yes**, after Module 4 | Same pattern as Module 4 plus a mechanical parameterization; column sets given. |
| 6 — Partner handler | **No** | Different base class, no pre-hooks, and the return-once token rule needs care. |
| 7 — Policy YAML | **Yes** | Full file content given. |
| 8 — Tests | **Yes** | Cases enumerated in §4. |
| 9 — Docs | **Yes** | Behaviour tables above are the source. |

---

## 4. Test Specification

### Unit Tests

| Test | Module | Description |
|---|---|---|
| `test_redact_row_drops_everything_outside_allowlist` | 1 | Columns absent from `public_columns` never appear, for a model row and for a dict. |
| `test_safe_fields_intersects_never_unions` | 1 | `safe_fields(["access_token","email"], PUBLIC) == ["email"]`; `["access_token"] → []`. |
| `test_redact_schema_strips_credential_columns` | 1 | `:meta` payload loses every `credential_columns` member. |
| `test_identity_projection_matches_masked` | 1+4 | Key set agrees with `IdentityStore.masked()` so the two identity surfaces cannot drift; `has_refresh_token` / `has_id_token` / `expired` correct for naive and aware `expires_at`. |
| `test_policy_allows_denies_without_pdp` | 2 | No `abac` / `security` on the app ⇒ `(False, …)`. |
| `test_policy_allows_denies_undeclared_policy` | 2 | PDP present, policy absent ⇒ `(False, …)`. |
| `test_policy_allows_denies_on_evaluation_error` | 2 | A policy whose `is_allowed` raises ⇒ `(False, …)`, nothing escapes. |
| `test_policy_allows_grants_for_superuser_group` | 2 | Pack policy + `groups=["superuser"]` ⇒ `(True, …)`. |
| `test_acting_user_requires_session` | 3 | No session ⇒ 401. |
| `test_acting_user_superuser_via_group_only` | 3 | `groups=["superuser"]` is a superuser; `groups="ex_superuser_revoked"` is not (guards the `_check_superuser` contract, cf. `tests/test_check_superuser.py`). |
| `test_authorize_owner_needs_no_policy` | 3 | Owner allowed with no PDP configured at all. |
| `test_authorize_ownerless_requires_superuser` | 3 | `owner_column=None` ⇒ a non-superuser is refused for every action. |
| `test_authorize_action_outside_superuser_actions` | 3 | An action absent from `superuser_actions` is refused even when the policy would allow it. |
| `test_authorize_cross_user_audited` | 3 | `AuditLog.log` called once with a `PolicyResponse` carrying `.response` and `.rule`. |
| `test_safe_filter_rejects_non_allowlisted_field` | 3 | `_filter=access_token=x` ⇒ 400; no query is issued. |
| `test_safe_filter_binds_value_as_parameter` | 3 | The executed SQL contains `$1` and the hostile value `' OR 1=1 --` is passed as an argument, not interpolated. |
| `test_safe_filter_ands_owner_predicate` | 3 | A non-superuser's filter carries `owner_column = <acting user>`. |
| `test_get_foreign_row_returns_404` | 4,5 | Non-owner `GET` by PK ⇒ 404, body leaks no column data. |
| `test_get_forces_owner_filter` | 4,5 | Listing without params issues `filter(user_id=<acting>)`. |
| `test_get_foreign_user_id_param_refused` | 4,5 | `?user_id=<other>` as a non-superuser ⇒ 403, and no `TypeError`/500. |
| `test_fields_param_cannot_project_credentials` | 4 | `?fields=access_token,refresh_token,email` returns `email` only. |
| `test_write_to_readonly_column_refused` | 4 | Owner `PATCH {"access_token": …}` ⇒ 400. |
| `test_cross_user_write_refused` | 4,5 | Non-superuser `PATCH`/`PUT`/`POST`/`DELETE` on a foreign row ⇒ 403/404. |
| `test_superuser_revoke_and_delete_allowed` | 4,5 | Superuser `PATCH {"enabled": false}` and `DELETE` succeed and are audited; `PATCH {"display_name": …}` on a foreign row ⇒ 403. |
| `test_hidden_lists_are_per_subclass` | 4,5 | `UserIdentityHandler._hidden is not ModelView._hidden`; instantiating another `ModelHandler` first does not change the response. |
| `test_model_without_owner_column_fails_closed` | 4 | A configured model lacking `user_id` ⇒ 501 on every verb. |
| `test_set_address_uses_bound_parameter` | 5 | `provider="x'; DROP TABLE auth.users; --"` reaches the driver as an argument; the SQL text still contains `$1`. |
| `test_partner_get_requires_superuser` | 6 | Any non-superuser `GET`/`PUT`/`PATCH`/`POST`/`DELETE` ⇒ 403. |
| `test_partner_read_never_returns_token` | 6 | Superuser `GET` (single, list and `:meta`) carries no `token`. |
| `test_partner_create_returns_token_once` | 6 | Creating `PUT`/`POST` ⇒ 201 with `token`; the next `GET` of the same row has none. |
| `test_partner_update_does_not_echo_token` | 6 | Updating `PATCH`/`POST` ⇒ 202 without `token`. |
| `test_partner_pk_is_list` | 6 | The list-shaped `pk` path still resolves (guards the `pk: list[str]` quirk). |
| `test_policy_pack_parses` | 7 | `YAMLStorage._parse_file()` yields the three `resource` policies with the right actions and `subjects.groups == {"superuser"}`. |

### Integration Tests

| Test | Description |
|---|---|
| `test_identity_surface_end_to_end_owner` | Owner links an identity through the vault, then reads it through `/api/v1/user_identity/{id}`: metadata present, zero token bytes anywhere in the payload. |
| `test_identity_surface_end_to_end_superuser` | Superuser reads, revokes and deletes a foreign identity; responses redacted, audit records written, a `PUT` refresh attempt refused. |
| `test_partner_key_lifecycle_superuser_only` | Superuser creates a partner key (token returned once), lists it (no token), revokes and deletes it; a regular user is refused at every step. |

### Test Data / Fixtures

```python
@pytest.fixture
def identity_row():       # UserIdentity double with ciphered token columns
    ...

@pytest.fixture
def account_row():        # UserAccount double
    ...

@pytest.fixture
def partner_row():        # PartnerKey double with a plaintext JWT in `token`
    ...

@pytest.fixture
def owner_session():      # user_id=42, groups=["users"]
    ...

@pytest.fixture
def superuser_session():  # user_id=7, groups=["superuser"]
    ...

@pytest.fixture
def pdp_with_pack():      # PDP whose YAMLStorage points at abac/default_policies/
    ...

@pytest.fixture
def recording_conn():     # captures (sql, *args) so parameterization is assertable
    ...
```

---

## 5. Acceptance Criteria

> This feature is complete when ALL of the following are true:

- [ ] `pytest tests/unit/handlers -v` passes (the six new test modules).
- [ ] `pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q` passes — no regression on the existing identity, vault, middleware and authorization suites.
- [ ] No response from `/api/v1/user_identity*` contains `access_token`, `refresh_token`, `id_token` or `key_version`, and no response from `/api/v1/partner/tokens*` contains `token` except the creation response — under any combination of `fields`, `_filter`, `:meta`, primary key or query parameters. Asserted, not assumed.
- [ ] A non-superuser cannot read, write or delete a `user_identities` or `user_accounts` row whose `user_id` differs from the session `user_id`; reads by primary key answer 404, not 403.
- [ ] A superuser can read (redacted), revoke and delete a foreign `user_identities` / `user_accounts` row, and cannot refresh its tokens or edit any other column on it.
- [ ] Every `/api/v1/partner/tokens*` verb answers 403 for a non-superuser.
- [ ] With ABAC absent, with the PDP present but the policy undeclared, and with a policy that raises on evaluation, the admin path is denied in all three cases (fail-closed) while owner access keeps working.
- [ ] `?_filter=<public column>=<value>` works through the parameterized path — the executed statement contains `$1` and the value never appears in the SQL text — and `?_filter=<credential or unknown column>=…` answers 400. `ModelView._filtering()` is unreachable from all three handlers.
- [ ] `_set_address`'s `social_networks` lookup binds `provider` as a parameter; no `str.format` on SQL remains in `navigator_auth/handlers/`.
- [ ] `navigator_auth/abac/default_policies/auth_model_admin_access.yaml` parses through `YAMLStorage._parse_file()` and declares the three policies.
- [ ] Every admin/cross-user decision (allow and deny) produces one `AuditLog` record naming the actor, the action, the target owner and the policy rule.
- [ ] All six routes still exist with the same paths and verbs — no client-visible breakage beyond the removal of credential columns, the 403s on the partner surface and the 400 on a non-allowlisted `_filter` (G4).
- [ ] `documentation/identity-vault.md` and `documentation/pdp.md` document the rule, the redacted admin view, the three policy names and the partner return-once token.
- [ ] `ruff check navigator_auth/handlers/ navigator_auth/decorators.py` is clean.
- [x] **Prerequisite, done separately**: the `ModelView` defects are fixed in `/home/jesuslara/proyectos/navigator/navigator` (`7bc5896`, §2 Prerequisite). Unchanged obligation: every criterion above must also pass against the *currently installed* `navigator-api` 3.2.2 — the local hardening may not depend on the upstream fix, which is unreleased and does not redact these columns anyway.

---

## 6. Codebase Contract (anti-hallucination)

> Every entry below was read on `dev` @ `67c700e` on 2026-10-23.

### Exists — navigator-auth

| Symbol | Location | Signature / fact |
|---|---|---|
| `UserIdentity` | `navigator_auth/models.py:77` | `asyncdb.models.Model`; PK `identity_id: UUID`; `user_id: User = Column(required=True, fk="user_id|username", api="users")`; credential columns `access_token/refresh_token/id_token: Optional[bytes]`, `token_type`, `expires_at`, `refreshed_at`, `key_version`, `provider_user_id`, `scopes`, `auth_data`, `attributes`, `enabled`; `Meta.name="user_identities"`, `Meta.schema=AUTH_DB_SCHEMA`, `Meta.strict=True` |
| `VwUserIdentity` | `navigator_auth/models.py:119` | read-only view model, **no** credential columns; `Meta.name="vw_user_identities"` |
| `UserAccount` | `navigator_auth/models.py:297` | `account_id: UUID` PK (`repr=False`), `user_id: User` (required), `provider: str` (required), `uid`, `address` (`repr=False`), `account: Optional[dict]`, `created_at` (`repr=False`); `Meta.name="user_accounts"` |
| `UserDevices` | `navigator_auth/models.py:143` | has `token` + `api_key`, **no handler and no route** — confirmed unexposed |
| `User.password` | `navigator_auth/models.py:51` | `Column(required=False, max=255, secret=True, repr=False)` — relevant only to the deferred `UserManager` surface |
| `PartnerKey` | `navigator_auth/handlers/partners.py:15` | `partner_id: UUID` PK (`repr=False`), `name`, `partner`, `issuer` (default `'navigator'`), **`token: str = Column(required=True)`** (no `repr=False`, no `secret=True`), `created_at`, `revoked`, `enabled`, `grants: dict`, `programs: list`; `Meta.name='partner_keys'` |
| `PartnerKeyHandler` | `navigator_auth/handlers/partners.py:38` | `class PartnerKeyHandler(ModelHandler)` where `ModelHandler` is the **local** one (`from .model import ModelHandler`, `:13`); `pk: list[str] = ["partner_id"]`; `async def _get_token(self, value, column, data)` builds a `jwt.encode` payload from `name`/`partner`/`issuer` with `AUTH_TOKEN_SECRET` |
| `UserIdentityHandler` | `navigator_auth/handlers/userattrs.py:53` | `model=UserIdentity`, `model_name=AUTH_USER_IDENTITY_MODEL`, `pk="identity_id"`; single method `_set_user_id` |
| `UserAccountHandler` | `navigator_auth/handlers/userattrs.py:20` | `model=UserAccount`, `pk="account_id"`; `social_network` raw query (`:24-26`); `_set_user_id` (`:26`); `_set_address` (`:29-50`) — **`self.social_network.format(provider=provider)` then `conn.fetchval(qry, column='social_url')`**, an injection sink |
| `ModelHandler` (navigator-based, in use by A and B) | `navigator_auth/handlers/handler.py:1-10` | `class ModelHandler(ModelView)`; `dbname="authdb"`; `async def _set_created_by(self, value, column, **kwargs)` |
| `ModelHandler` (local, in use by C) | `navigator_auth/handlers/model.py:21` | `class ModelHandler(BaseView)`; `model`, `model_name`, `name`, `pk="id"`; `get_userid` (`:50`), `_get_data` (`:63`), `_post_get(result, fields=None)` (`:85`), `session()` (`:106`), `head/get/put/patch/post/delete`; **no `_pre_*` hooks, no `_filter_*` hooks** |
| Who uses which base | `grep` on `navigator_auth/handlers/` | `.handler` (navigator `ModelView`): `userattrs.py` (both handlers), `groups.py:14-28`. `.model` (local): `partners.py:13`, `permissions.py:4`. Direct `ModelView`: `users/user.py:11`. `abac/policyhandler.py:8` uses the local one and is already `groups_protected(['superuser'])` |
| Routes — identities | `navigator_auth/handlers/__init__.py:58-65` | `r"/api/v1/user_identity/{id:.*}"` → `api_auth_useridentity_id`; `r"/api/v1/user_identity{meta:\:?.*}"` → `api_auth_useridentity` |
| Routes — accounts | `navigator_auth/handlers/__init__.py:38-46` | `r"/api/v1/user_accounts/{id:.*}"` → `api_auth_useraccount_id`; `r"/api/v1/user_accounts{meta:\:?.*}"` → `api_auth_useraccount` |
| Routes — partner keys | `navigator_auth/handlers/__init__.py:47-56` | `r"/api/v1/partner/tokens/{id:.*}"` → `api_auth_partnerkey_id`; `r"/api/v1/partner/tokens{meta:\:?.*}"` → `api_auth_partnerkey` |
| `BaseIdentityView._user_id` | `navigator_auth/handlers/user_identities.py:38` | resolves `user_id` from `self.user` then the session; `_json_error(401, …)` when absent |
| `IdentityStore.masked` | `navigator_auth/identity/store.py:465` | `def masked(self, identity: UserIdentity) -> dict` → `expired, identity_id, auth_provider, provider_user_id, scopes, token_type, expires_at, refreshed_at, created_at, enabled, has_refresh_token, has_id_token, profile`; no token material |
| `IdentityStore.update_tokens` | `navigator_auth/identity/store.py:409` | `async (identity: UserIdentity, token: TokenResponse) -> UserIdentity` — the only legitimate writer of credential columns |
| `_check_superuser` | `navigator_auth/decorators.py:291` | `(userinfo: dict, user: object = None) -> bool`; checks `superuser`/`is_superuser`, then `SUPERUSER_GROUP` membership **on a real collection only**, then `user.groups[].group`/`group_name` |
| `SUPERUSER_GROUP` | `navigator_auth/decorators.py:288` | `= "superuser"` |
| `is_superuser` / `allowed_groups` | `navigator_auth/decorators.py:315`, `:414` | decorators; neither consults a policy |
| `check_access` | `navigator_auth/decorators.py:1170` | `(policy, action=None, resource=None, resource_type=None, require_all=False, content_type="application/json")`; docstring: "always fails closed"; works on functions, methods and whole classes |
| `_check_policies` | `navigator_auth/decorators.py:1103` | `async (request, names, action, resource, resource_type, require_all) -> tuple[bool, str, Any]`; denies when `_get_pdp` is `None`, when `_find_policy` returns `None`, and on any evaluation exception |
| `_get_pdp` | `navigator_auth/decorators.py:994` | `request.app["abac"]`, else `getattr(request.app["security"], "pdp", None)` |
| `_abac_eval_context` | `navigator_auth/decorators.py:1044` | builds the `EvalContext` the PDP would build |
| `_apply_decorator` | `navigator_auth/decorators.py:48` | the func-vs-method dispatch every decorator here uses |
| `EvalContext.__init__` | `navigator_auth/abac/context.py:89` | `(request, user, userinfo, session, *args, org_id=None, client_id=None, **kwargs)`; stores `user`, `userinfo`, `session`, `auth_method`, `mfa`, `org_id`, `client_id` — **no row-ownership key** |
| `ResourcePolicy` | `navigator_auth/abac/policies/resource_policy.py:7` | `__init__(name, effect, description, resources, actions, subjects, conditions, environment, priority, enforcing, org_id=1, client_id=1)` |
| `ResourcePolicy.evaluate_conditions` | `navigator_auth/abac/policies/resource_policy.py:119` | custom conditions do `actual = getattr(ctx, key, None)` and `if actual is None: continue` — a missing attribute **passes** |
| `SubjectSpec` | `navigator_auth/abac/policies/resources.py:128` | `groups/users/roles/exclude_groups/exclude_users`; `from_dict`; `matches_user(username, user_groups, user_roles)`; `'*'` in groups = any authenticated user |
| `ResourceType` | `navigator_auth/abac/policies/resources.py:15` | `TOOL, KB, VECTOR, AGENT, MCP, URI, DATASET, WIDGET, CARD, SLUG, DATASOURCE, DRIVER, RAW_QUERY` |
| `PolicyResponse` | `navigator_auth/abac/policies/abstract.py:19` | `ClassDict` with `effect`, `response`, `rule` — the shape `AuditLog.log` expects |
| `AuditLog.log` | `navigator_auth/abac/audit.py:277` | `async def log(self, answer, status, user, *, tenant: str = None)`; backends read `answer.response` / `answer.rule` |
| `YAMLStorage._parse_file` | `navigator_auth/abac/storages/yaml_storage.py:103` | accepts `version`, `defaults.effect`, `policies[]` with `name, effect, description, resources, actions, subjects{groups,users,roles,…}, conditions{context,environment}, priority, enforcing, policy_type` (default `resource`) |
| `POLICY_STORAGE_DIR` | `navigator_auth/conf.py:705` | default `BASE_DIR / "env" / "policies"` |
| `AUTH_USER_IDENTITY_MODEL` | `navigator_auth/conf.py:150` | `config.get(..., fallback=None)` — when set, `ModelView.__init__` swaps the model |
| `admin_full_access.yaml` | `navigator_auth/abac/default_policies/admin_full_access.yaml` | existing pack entry already granting `uri:*` to groups `superuser`, `admin`, `priority: 100` |
| Parameterized-query idiom | `navigator_auth/passkey/store.py:44`, `navigator_auth/middlewares/strategies.py:87` | `await conn.fetch_one("… WHERE col = $1", value)` / `conn.fetch_all` |
| `navigator-api` pin | `pyproject.toml:53` | `"navigator-api>=0.5.0"` — installed 3.2.2; the floor is NOT raised by this feature |
| Handler test pattern | `tests/unit/identity/test_identity_handlers.py:1-67` | `make_mocked_request` + `FakeSession` + `patch("navigator_auth.decorators.get_session")` **and** the handler module's own `get_session` |
| `_check_superuser` tests | `tests/test_check_superuser.py:1-45` | existing type-confusion cases to keep green |

### Exists — upstream `navigator` (the behaviour to defend against)

> The facts below describe the **installed** `navigator-api` 3.2.2 copy under
> `.venv/`, which is what a deployment runs. The `navigator` working copy was
> byte-identical to it (verified by `diff`) until the §2 Prerequisite fix
> (`7bc5896`, unreleased), so these line numbers describe both the installed
> copy and that fix's "before" state. **Implement against the installed
> behaviour**, not against the fix.

| Symbol | Location | Fact |
|---|---|---|
| `ModelView` | `navigator/views/model.py:57` | `_required/_primaries/_hidden` declared as **class** attributes (`:77-79`) |
| `ModelView._get_model` | `…/model.py:130-152` | derives column metadata only `if not self._primaries`, appending to the **shared class lists** in place. The hidden-column branch tests `field.metadata["repr"]`, and `repr` is **not** a metadata key (it is the dataclass `Field.repr` attribute) — verified by running `datamodel` 0.10.21: `metadata` holds `required, nullable, primary, validator, alias, widget, encoder, decoder, readonly` (+ `secret` when declared). So the lookup always raises `KeyError` and **`_hidden` is always `[]`** |
| `ModelView._model_response` | `…/model.py:158-213` | `elif self._hidden is not None: _fields = self._hidden`, then projects **only** `_fields` — a whitelist, latent while `_hidden` is empty. With `_hidden == []` and no `?fields=`, `_fields` is falsy ⇒ `result = response` ⇒ **the full row is serialized**. `_fields` is left unbound when `_hidden` is `None` |
| `ModelView._get_data` | `…/model.py:317-418` | calls every `_filter_<column>` hook, then `get(**{**_filter, **args})` on the PK path and `filter(**qp, **_filter)` on the query path (duplicate key ⇒ `TypeError`) |
| `ModelView._filtering` | `…/model.py:419-447` | `SELECT {field} FROM {schema}.{table} WHERE {field} LIKE '{value}%'` from the unvalidated `_filter` param — but **unreachable**: the preceding `ftype = self.get_model.column(field)` calls an instance method on the Model class, raising `TypeError` (verified: `ModelMixin.column() missing 1 required positional argument: 'name'`), which `get()` catches (`:494-499`) and answers **406**. `filter_param.split('=')` would raise `ValueError` on a malformed value |
| `datamodel` field introspection | `datamodel/models.py:102-156` (0.10.21) | `get_columns()` / `get_column(name)` are **classmethods**; `column(name)`, `columns()`, `get_fields()`, `to_dict()` are **instance** methods; `secret=True` lands in `field.metadata["secret"]`, `repr=False` on `Field.repr` |
| `ModelView` verbs | `…/model.py:449, 907, 691, 1062, 1400` | each decorated `@service_auth` (`:106-117`): session + `self._userid`, then `_post_auth` |
| `AbstractModel._pre_*` | `navigator/views/abstract.py:553-571` | `_pre_get/_pre_patch/_pre_put/_pre_post/_pre_delete`, all `async (*args, **kwargs) -> True` |
| `AbstractModel.get_parameters` | `navigator/views/abstract.py:434` | returns `[args, meta, qp, fields]`, popping `fields` out of `qp` |
| `AbstractModel.get_userid` | `navigator/views/abstract.py:310` | `async (session, idx="user_id")` |

### Does NOT exist (do not reference)

- `navigator_auth/handlers/redaction.py` — created by Module 1.
- `navigator_auth/handlers/guards.py` — created by Module 3.
- `navigator_auth/identity/redaction.py` — rev 0.1 of this spec proposed it;
  rev 0.2 moved the module to `handlers/redaction.py` because three surfaces
  share it. Do not create both.
- `navigator_auth.decorators.policy_allows` — created by Module 2. Today only
  the private `_check_policies` exists.
- `tests/unit/handlers/` — a new test package (no `__init__.py` exists there
  yet; `tests/unit/identity/` and `tests/unit/middlewares/` are the pattern).
- `ResourceType.IDENTITY` / `ResourceType.MODEL` / `ResourceType.PARTNER` —
  not in the enum (`abac/policies/resources.py:15-30`). Use `ResourceType.URI`.
- Any `owner`, `object_owner`, `resource_owner` or `row_user_id` key on
  `EvalContext` — ownership is not expressible in the policy language.
- An `ObjectPolicy`-based row filter. `PDP.filter_obj` (`abac/pdp.py:616`) and
  `ObjectPolicy._filter` (`policies/obj.py:208`) filter opaque object *names*,
  not SQL rows.
- Any loader that reads `navigator_auth/abac/default_policies/`. No Python
  file references that directory; it is a pack an operator copies into
  `POLICY_STORAGE_DIR`. The guards must not assume a policy is loaded.
- A `user_id` (or any owner) column on `PartnerKey`
  (`handlers/partners.py:15-30`) — hence `owner_column = None`.
- `navigator_auth/libs/json.py` — the import in `models.py:14` is
  `from .libs.json import json_encoder`; the module is not at that literal
  path. Do not try to patch bytes serialization there.
- A `superuser` flag on `UserIdentity`. `navigator_auth/identities.py:235`
  `superuser` belongs to the auth **user** identity object, not to this model.

---

## 7. Implementation Notes & Constraints

### Patterns to Follow

- Async-first; no blocking I/O in the guard. `_check_policies` is already
  async.
- Google-style docstrings and strict type hints on every new symbol
  (`.claude/rules/python-development.md`).
- Module logger / `self.logger`, never `print`. (`ModelView._get_data`
  contains stray `print("FILTER")` / `print("ALL")` upstream — do not copy
  that style; fixing it belongs to the navigator repair.)
- All SQL goes through bound parameters (`$1`, …) as in `passkey/store.py:44`.
  After this feature, no `str.format`-built SQL may remain in
  `navigator_auth/handlers/`.
- Refusals use each handler's own error helper so response shapes stay
  consistent with the rest of `navigator_auth/handlers/`.
- Deny messages must not confirm a foreign row's existence: the primary-key
  path answers 404 with a generic body.
- The guard mixin goes **before** the handler base in the MRO so its hooks
  win.
- One mixin, three configurations: per-surface behaviour lives in class
  attributes, not in forked copies of the logic.

### Known Risks / Gotchas

- **The installed `ModelView` performs no projection** — `_hidden` is always
  empty (`metadata["repr"]` never resolves), so today the full row ships.
  Mitigation: never rely on `_hidden` at all; redact in an overridden
  `_model_response` from this feature's own allowlist. A task should
  *reproduce* the current response first and record it in the task notes.
- **A latent whitelist inversion** — if the deployed navigator is ever
  upgraded to a version that populates `_hidden` *without* the exclusion fix,
  the same endpoint would return **only** the credential columns. The
  override removes both outcomes; do not "improve" it by delegating back to
  the parent projection.
- **Shared class-level `_required`/`_primaries`/`_hidden`** — mutated in place
  by `_get_model()`, whose derivation is skipped entirely once any sibling has
  filled `_primaries`; another handler can therefore change this one's
  behaviour. Hence the per-subclass copies and the test that asserts their
  identity.
- **`?_filter=` answers 406 today, not a filtered result** — the sink is
  guarded by an unrelated `TypeError`. Clients cannot be relying on it, so
  replacing it with the parameterized `safe_filter()` is not a behaviour
  regression; and the guard must not be removed before the replacement is in
  place.
- **Duplicate-keyword 500** — `filter(**qp, **_filter)` raises `TypeError`
  when the caller passes `?user_id=`. Sanitize `qp` *before* the hook runs.
- **Two different handler bases** — surfaces A/B get hooks, surface C does
  not. The guard must not assume `_pre_*` exists; Module 6 overrides verbs
  explicitly. A test per verb is the only way to be sure the partner surface
  is covered.
- **`pk: list[str]` on `PartnerKeyHandler`** — the local base branches on
  `isinstance(self.pk, list)` and splits `params["id"]` by `/`
  (`handlers/model.py:160-190`). The guard must read the owner/target from the
  resolved args, not re-parse the URL.
- **Partner token compatibility** — admin tooling that currently reads
  `token` from `GET /api/v1/partner/tokens` will stop receiving it. The token
  is deterministic from `(name, partner, issuer)` + `AUTH_TOKEN_SECRET`
  (`handlers/partners.py:43-66`), so a lost token can be re-derived by
  re-creating the key; that is the documented recovery path, and the
  creation response is the single delivery point. Call this out in the
  release notes.
- **`conditions` fail-open in `ResourcePolicy`** — `if actual is None:
  continue` means a condition on a key the context does not carry is
  *satisfied*. Never express ownership as a policy condition.
- **Swappable identity model** (`AUTH_USER_IDENTITY_MODEL`) — a deployment
  pointing the handler at a model without `user_id` must fail closed with 501,
  not silently serve unfiltered rows.
- **Policy pack is not auto-loaded** — a deployment that never copies
  `default_policies/` into `POLICY_STORAGE_DIR` gets *no* admin cross-user
  access at all. That is the intended fail-closed outcome; say so explicitly
  in the docs or operators will read it as a bug.
- **Audit volume** — one record per *decision*, not per row, so a superuser
  listing many rows does not flood the audit backend.
- **Upstream fix is not a dependency** — `pyproject.toml:53` pins
  `navigator-api>=0.5.0`. Raising that floor to a fixed navigator release is
  explicitly *not* part of this feature (§8 Q9).

### External Dependencies

| Package | Version | Reason |
|---|---|---|
| — | — | None. `pyyaml`, `aiohttp`, `navigator-session`, `asyncdb`, `datamodel`, `pyjwt` are already dependencies, and the `navigator-api` floor is unchanged. |

### Cross-repository prerequisite

| Repo | Path | Work |
|---|---|---|
| `phenobarbital/navigator` | `/home/jesuslara/proyectos/navigator/navigator` → `navigator/views/model.py` | **Done and shipping** (§2 Prerequisite): commit `7bc5896` (branch `fix/modelview-response-projection-and-filtering` off `origin/dev`), 18 new tests, suite 378 passed; merged to navigator `origin/dev` and bumped to `navigator-api` **3.2.4** (`a117f29`). The `navigator-api>=0.5.0` floor here is still unchanged (§8 Q9). Tracked in that repo, not in this spec's task list. |

---

## 8. Open Questions

All resolved. Decisions taken by Jesus Lara on 2026-10-23, routed into the
sections named after each one.

- [x] **Q1 — How is owner-or-superuser enforced?** *Resolved*: **ABAC policy +
  default-deny in the handler.** The handler applies a hard gate (row owner,
  or `superuser` group) **and** YAML policies ship in
  `abac/default_policies/` so the PDP governs them; the code never depends on
  a policy existing — absent PDP or policy ⇒ deny. → §2 Overview layers 1–2,
  §3 Modules 3 & 7, §5 criterion 7.
- [x] **Q2 — What happens to the generic routes?** *Resolved*: **harden and
  keep.** Same paths and verbs, with a forced owner filter, redaction and a
  policy-gated admin path. No deprecation, no removal. → §1 G4, §3 Modules
  4–6, §5 criterion 12.
- [x] **Q3 — What does a superuser see on another user's identity?**
  *Resolved*: **the `masked()` shape as-is.** Zero token material for anyone,
  owner included; the owner's real credential stays with
  `/api/v1/user/identities/{provider}/credential`. → §2 Data Models, §3
  Module 1, §5 criterion 3.
- [x] **Q4 — What may a superuser write on another user's row?** *Resolved*:
  **revoke and delete only.** No token refresh, no editing other columns. →
  §3 Module 4 behaviour table, §5 criterion 5.
- [x] **Q5 — `_filter`: 400, ignore, or reimplement?** *Resolved*:
  **reimplement safely over the allowlist.** `?_filter=<field>=<value>` is
  accepted only for columns in `public_columns`, executed as a parameterized
  query with the ownership predicate ANDed in; a non-allowlisted or malformed
  field answers 400. The upstream interpolation path is overridden out of
  reach. → §1 G7, §2 Overview layer 4, §3 Module 3 `safe_filter`, §4 three
  `safe_filter` tests, §5 criterion 8.
- [x] **Q6 — Is `auth_data` acceptable in the admin view?** *Resolved*:
  **yes, keep `profile`.** Coherent with `masked()` today; no divergence of
  shape by role. The PII exposure is accepted knowingly. → §2 Data Models,
  §3 Module 4.
- [x] **Q7 — How far does the scope reach?** *Resolved*: **all three
  surfaces** — `user_identities`, `user_accounts` and `partner_keys` — under
  one reusable guard. This replaced rev 0.1's non-goal. The remaining
  generic-CRUD handlers (`UserManager`, groups, permissions, policies) stay
  out of scope and are listed as audited-and-deferred. → §1 Problem Statement
  A/B/C + Non-Goals, §3 Modules 4/5/6, §5 criteria 3/4/6.
- [x] **Q8 — The `ModelView` defects are in your own `navigator` repo.**
  *Resolved*: **fix `ModelView` there first** — and it is now **done and
  released** (`7bc5896`, merged to navigator `origin/dev`, shipping as
  `navigator-api` 3.2.4). The local hardening still ships as defense in
  depth, because `pyproject.toml:53` allows `navigator-api>=0.5.0`, the
  deployed copy is whatever was resolved at install time (3.2.2 in this
  repo's `.venv`), and upstream `_hidden` is derived from `secret=True` —
  which neither
  `UserIdentity.access_token` nor `PartnerKey.token` declares. Doing the
  upstream fix first also surfaced that rev 0.1 of this spec described the
  wrong mechanism (see §1, corrected in rev 0.3). → §2 Prerequisite, §7
  Cross-repository prerequisite, §5 last criterion.
- [ ] **Q9 — Should `pyproject.toml` raise the `navigator-api>=0.5.0` floor
  to `>=3.2.4` now that the fix is shipping?** Non-blocking; nothing in
  FEAT-105 depends on it, and the local hardening is written to be correct on
  3.2.2 as well. Recommendation: **raise it in a separate commit, and keep the
  local hardening anyway** — the floor buys a correct upstream projection for
  every *other* `ModelView` in this repo (users, groups, permissions,
  policies: the deferred surfaces in §1 Non-Goals), which this feature does
  not touch. Do not bundle the bump into FEAT-105: it would make a dependency
  upgrade a prerequisite of a security fix — *Owner: Jesus Lara*

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
- **Rationale**: Modules 4 and 5 edit the same file
  (`handlers/userattrs.py`), and Modules 4–6 all converge on the same guard
  contract and the same behaviour tables. Parallel worktrees would collide.
- **Parallelizable subset** (if a pool is used): Module 1 (redaction),
  Module 2 (`policy_allows`) and Module 7 (policy YAML) touch disjoint files
  with fully specified contracts and can run concurrently. Then Module 3
  (guard), then Modules 4 → 5 (same file, sequential), then Module 6, then
  Modules 8 → 9.
- **Cross-feature dependencies**: none inside this repo. One
  **cross-repository** prerequisite: the `ModelView` fix in
  `/home/jesuslara/proyectos/navigator/navigator` (§7), done first and
  tracked there.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-10-23 | Jesus Lara | Initial draft — owner-or-superuser ABAC ownership and redaction for `auth.user_identities` (Q1–Q4 resolved up front) |
| 0.2 | 2026-10-23 | Jesus Lara | Resolved Q5–Q8: safe parameterized `_filter`; `auth_data` kept; scope widened to `user_accounts` and `partner_keys` (plaintext JWT, superuser-only, return-once token) under one reusable `OwnerOrSuperuserGuard`; `ModelView` repaired upstream first while local hardening stays defense-in-depth. Redaction module moved to `handlers/redaction.py`; added G7–G9 and the `_set_address` injection fix |
| 0.3 | 2026-10-23 | Jesus Lara | **Corrected §1 and §6** after executing `datamodel` 0.10.21 and the upstream fix: `_hidden` is always empty (`repr` is not a `metadata` key), so the full row ships today and the whitelist inversion is latent; `?_filter=` answers 406 because `get_model.column(field)` raises `TypeError` first, so the SQL sink is unreachable rather than live. Recorded the navigator `ModelView` fix as done (`7bc5896`, unreleased) and why it does not reduce the local hardening |
| 0.4 | 2026-10-23 | Jesus Lara | Upstream fix merged to navigator `origin/dev` and bumped to `navigator-api` 3.2.4 (`a117f29`): §2, §7 and §8 Q8 updated from "local, unreleased" to "shipping", and Q9 re-scoped to raising the floor to `>=3.2.4` in a separate commit for the benefit of the deferred `ModelView` surfaces |
