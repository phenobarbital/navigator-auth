# TASK-155: Guard `PermissionHandler` on the local `handlers/model.py` base

**Feature**: FEAT-107 — Write-envelope hardening for the remaining auth CRUD handlers
**Spec**: `sdd/specs/auth-model-crud-hardening.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-149
**Assigned-to**: unassigned

---

## Context

Implements the `PermissionHandler` half of **spec §3 Module 4** and the
`handlers/model.py` half of **AC13** ("the write enforcement holds on both
handler bases"). This is spec risk R3: `permissions.py` imports `ModelHandler`
from `.model` — a 446-line local reimplementation over `navigator.views.BaseView`
with its own `get` / `put` / `patch` / `post` / `delete` and **no `_pre_*`
hooks** — not from `.handler`. TASK-151's `GuardedModelViewHooks` does nothing
here.

The pattern already exists in the repo: `PartnerKeyHandler` sits on the same
local base and gates **every verb at its top** (`partners.py:40-43`, `118-197`).
Copy it. It is the only FEAT-107 handler on this base, so a per-handler override
is simpler and safer than a second shared mixin.

### Spec deviations recorded at /sdd-task time

1. **Action strings** are `permission:read|create|update|delete` (see TASK-150).
2. **The local base writes through four verbs, not two.** The spec names `put`
   (`model.py:216`) and `patch` (`:252`). `post` (`:315`) is an upsert that
   updates through the same `result.set(...)` loop (`:371-374`) or inserts
   (`:357-360`, `:378-383`), and `delete` (`:400`) removes rows. All four are gated
   here; `post` approves **both** create and update (`partners.py:177-192`).
3. **Reads are gated** (user decision 2026-11-11): `get` and `head` are superuser
   + policy only. Today any authenticated session can list permissions.

### Verb semantics of the local base (verified)

| Verb | Behaviour | Where | Gate here |
|---|---|---|---|
| `head` | schema headers | `model.py:106-120` | `permission:read` |
| `get` | `:meta` schema, by PK, or `filter(**qp)` | `:122-214` | `permission:read` |
| `put` | **always inserts** `self.model(**data)` | `:216-250` | `permission:create`, `creating=True` |
| `patch` | `:meta` → `__fields__`; else fetch by `data[pk]` or URL `id`, `result.set` for every key | `:252-313` | `:meta` → read; else `permission:update` |
| `post` | fetch by PK; missing → insert, found → `result.set` loop | `:315-398` | `permission:create` **and** `permission:update` |
| `delete` | fetch by PK, `result.delete()` | `:400-446` | `permission:delete`, 404 on deny |

`_get_data` (`:56-72`) reads `json_data()` and applies `_get_<column>` hooks;
`Permission` has none, so the processed data equals the raw body. The local base
never merges query parameters into a write.

---

## Scope

- Rebase `PermissionHandler` onto `(OwnerOrSuperuserGuard, ModelHandler)` (local
  base, unchanged import) with the spec §2 configuration.
- Override `head`, `get`, `put`, `patch`, `post`, `delete` to authorize first,
  then delegate to `super()`.
- A `_client_keys()` helper: raw body keys, 400 unless the body is a JSON object.
- Write `tests/unit/handlers/test_permission_handler_access.py`.

**NOT in scope**:
- `GroupPermissionManager` (TASK-154 — different base, different file).
- Response redaction (no credential columns on `Permission`).
- Route registration (`handlers/__init__.py:22-29` unchanged).
- Changing `handlers/model.py` itself — `PartnerKeyHandler` depends on it as is.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/permissions.py` | MODIFY | Guarded class, per-verb gates |
| `tests/unit/handlers/test_permission_handler_access.py` | CREATE | Verb-level tests on the local base |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `6b8cc84` on 2026-11-11.

### Verified Imports

```python
# navigator_auth/handlers/permissions.py today (verified: permissions.py:1-4)
from datamodel import BaseModel
from ..models import Permission
from ..conf import AUTH_PERMISSION_MODEL         # fallback None (conf.py:148) → model stays Permission
from .model import ModelHandler                  # :4 — the LOCAL base over BaseView. Keep it.

# to add
from typing import Optional
from .guards import OwnerOrSuperuserGuard        # guards.py:31
```

### Existing Signatures to Use

```python
# navigator_auth/handlers/permissions.py
class PermissionHandler(ModelHandler):           # :7
    model: BaseModel = Permission
    model_name: str = AUTH_PERMISSION_MODEL
    name: str = "Permissions"
    pk: str = "permission_id"                    # :11 (file ends here)

# navigator_auth/handlers/model.py (local base)
class ModelHandler(BaseView):                    # :16
    async def _get_data(self, session=None) -> Any: ...   # :56  json_data() + _get_<col> hooks; 400 on bad body
    async def session(self): ...                 # :96  403 when no session
    async def head(self): ...                    # :106
    async def get(self): ...                     # :122
    async def put(self): ...                     # :216
    async def patch(self): ...                   # :252
    async def post(self): ...                    # :315
    async def delete(self): ...                  # :400
    def match_parameters(self, request=None) -> dict   # used at :126, :256 (from BaseView)

# navigator_auth/models.py:223 — Permission columns
#   permission_id(pk, db auto) permission description created_at updated_at
#   __post_init__ slugifies description into `permission` when absent (:230-233)

# After TASK-149 — guard API
async def authorize_row(self, action, owner_id, *, not_found_on_deny=False, payload=None, creating=False) -> bool
```

- Pattern to copy line by line: `PartnerKeyHandler` (`partners.py:76-90` `_require_superuser`,
  `112-116` `_meta_requested`, `118-197` verbs). Its tests:
  `tests/unit/handlers/test_partner_key_handler_access.py` (drives the VERBS on the local base).

### Does NOT Exist (Anti-Hallucination)

- ~~`_pre_get` / `_pre_put` / … on the local base~~ — none; gate inside each verb.
- ~~`_set_update` on the local base~~ — writes use `result.set(key, val)` directly (`model.py:307-309`, `371-373`).
- ~~a query-parameter merge into writes on the local base~~ — only upstream `ModelView.put` does that.
- ~~an owner column on `Permission`~~ — none; `owner_column = None`.

---

## Implementation Blueprint

### `navigator_auth/handlers/permissions.py` — MODIFY (whole class)

```python
# REPLACE from `from datamodel import BaseModel` (permissions.py:1) to EOF (:11).
# Anchors: `from .model import ModelHandler` (occurrences: 1), `class PermissionHandler(ModelHandler):` (occurrences: 1)
from typing import Optional
from datamodel import BaseModel
from ..models import Permission
from ..conf import AUTH_PERMISSION_MODEL
from .guards import OwnerOrSuperuserGuard
from .model import ModelHandler


class PermissionHandler(OwnerOrSuperuserGuard, ModelHandler):
    """Superuser-only CRUD over ``auth.permissions`` (FEAT-107).

    Sits on the LOCAL ``handlers/model.py`` base, which has no ``_pre_*``
    hooks — so, as in ``PartnerKeyHandler``, the guard is invoked at the top
    of every verb. No owner column: the superuser path is the only path.
    Stays on the plain ``superuser`` policy: nothing authorizes by permission
    name (spec §8).
    """

    model: BaseModel = Permission
    model_name: str = AUTH_PERMISSION_MODEL
    name: str = "Permissions"
    pk: str = "permission_id"

    owner_column: Optional[str] = None
    policy_name: str = "permissions_admin_access"
    superuser_actions = frozenset({"permission:read", "permission:create", "permission:update", "permission:delete"})
    writable_by_admin = frozenset({"permission", "description"})
    privileged_columns = frozenset({"permission_id", "created_at"})

    def _meta_requested(self) -> bool:
        # FILL IN: copy partners.py:112-116
        raise NotImplementedError

    async def _client_keys(self) -> frozenset[str]:
        """Raw body keys; 400 unless the body is a JSON object (the local base inserts ``model(**data)``)."""
        # FILL IN: `data = await self.json_data()` in try/except Exception → None; not a dict → 400 via
        #   self.error(response={"error": "A JSON object body is required"}, status=400); return frozenset(data).
        raise NotImplementedError

    async def head(self):
        await self.authorize_row("permission:read", None)
        return await super().head()

    async def get(self):
        await self.authorize_row("permission:read", None)
        return await super().get()

    async def put(self):
        """The local base's put ALWAYS inserts (model.py:216-250)."""
        keys = await self._client_keys()
        await self.authorize_row("permission:create", None, payload=keys, creating=True)
        return await super().put()

    async def patch(self):
        if self._meta_requested():
            await self.authorize_row("permission:read", None)
            return await super().patch()
        keys = await self._client_keys()
        await self.authorize_row("permission:update", None, payload=keys)
        return await super().patch()

    async def post(self):
        """Upsert: approve BOTH verbs, with the same keys (partners.py:177-192)."""
        keys = await self._client_keys()
        await self.authorize_row("permission:create", None, payload=keys, creating=True)
        await self.authorize_row("permission:update", None, payload=keys)
        return await super().post()

    async def delete(self):
        await self.authorize_row("permission:delete", None, not_found_on_deny=True)
        return await super().delete()
```

**Why**:
- Every verb authorizes **before** `super()`, so nothing reaches the database
  first; the guard raises, so there is no return value to forget to check.
- `permission_id` is privileged, so a client cannot send it in the body; PATCH,
  POST and DELETE therefore take the id from the URL — which the local base already
  falls back to (`model.py:270-273`, `325-328`, `414-417`).
- `updated_at` is in no set, so it is refused (allowlist, spec G3).

### `tests/unit/handlers/test_permission_handler_access.py` — CREATE

```python
"""PermissionHandler on the LOCAL handlers/model.py base (FEAT-107, TASK-155).

The local base has no _pre_* hooks, so these tests drive the VERBS — the same
approach as test_partner_key_handler_access.py.
"""

import pytest
from navigator.views.model import ModelView
from navigator_auth.handlers.model import ModelHandler as LocalBase
from navigator_auth.handlers.permissions import PermissionHandler

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

VERBS = ["get", "head", "put", "patch", "post", "delete"]

# FILL IN: FakeSession / _session / _Patches / PDP / app["authdb"] connection harness, copied from
#   tests/unit/handlers/test_partner_key_handler_access.py.


class TestBase:
    def test_permission_handler_uses_baseview_base(self): ...    # issubclass LocalBase, NOT ModelView (spec §4, AC13)
    def test_config_matches_policy_pack(self): ...               # permissions_admin_access vs auth_crud_admin_access.yaml


class TestGates:
    async def test_every_verb_requires_superuser(self): ...      # ordinary session → 403 on all VERBS, no DB call
    async def test_put_refuses_privileged_column(self): ...      # permission_id / created_at → 403
    async def test_put_allows_permission_and_description(self): ...
    async def test_unknown_column_refused(self): ...             # updated_at → 403
    async def test_patch_refuses_non_object_body(self): ...      # 400
    async def test_patch_meta_is_read_gated(self): ...
    async def test_post_requires_create_and_update(self): ...    # policy granting only create → 403
    async def test_delete_denied_is_404(self): ...
```

### Steps (in order)

1. Replace the module with the block above and complete the two helpers.
2. Write the tests by copying the harness from
   `test_partner_key_handler_access.py` — because it already fakes
   `request.app["authdb"].acquire()`, which this base uses instead of
   `self.handler(...)`.
3. In `test_every_verb_requires_superuser`, assert the fake connection was never
   acquired — because AC13 is about the database never being reached.
4. Run `pytest tests/unit/handlers/test_permission_handler_access.py tests/unit/handlers/test_partner_key_handler_access.py -v`
   (the second proves the shared local base is untouched).

### FILL IN checklist

- [ ] `_meta_requested` (copy) and `_client_keys`.
- [ ] Test harness and all test bodies.

---

## Acceptance Criteria

- [ ] `pytest tests/unit/handlers/test_permission_handler_access.py -v` passes.
- [ ] `pytest tests/unit/handlers/ -v` passes (AC2).
- [ ] The write enforcement holds on the `handlers/model.py` base for `put`, `patch` **and** `post`; `delete`, `get`, `head` are superuser + policy only (spec AC13, deviations 2–3).
- [ ] `permission_id`, `created_at` and any unlisted column are refused on every write verb (spec AC5 for this surface).
- [ ] `ruff check navigator_auth/handlers/permissions.py tests/unit/handlers/test_permission_handler_access.py` is clean.

---

## Test Specification

See the CREATE block above.

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at `sdd/specs/auth-model-crud-hardening.spec.md` (§3 Module 4, §7 R3).
2. **Check dependencies** — TASK-149 is `done` in `sdd/tasks/index/auth-model-crud-hardening.json`.
3. **Re-verify** the local base line numbers in the verb table (`navigator_auth/handlers/model.py`).
4. **Update status** → `"in-progress"`.
5. **Implement** the blueprint and complete every `FILL IN`.
6. **Verify** the acceptance criteria (`source .venv/bin/activate` first).
7. **Move this file** to `sdd/tasks/completed/` and set the index entry to `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: sdd-worker (orchestrator)
**Date**: 2026-11-11
**Seat**: Backend: native · Model: sonnet
**Notes**: PermissionHandler behind OwnerOrSuperuserGuard. Merge-tier validation: 45 passed (tasks 151/152/155 together). Review: zero fixes (feedback coder-review:6a6321f77911351038fcac1e).
