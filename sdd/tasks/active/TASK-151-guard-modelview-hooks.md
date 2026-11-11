# TASK-151: Shared guard verb hooks for the `ModelView`-based `ModelHandler`

**Feature**: FEAT-107 — Write-envelope hardening for the remaining auth CRUD handlers
**Spec**: `sdd/specs/auth-model-crud-hardening.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-149
**Assigned-to**: unassigned

---

## Context

Implements the **coverage half of spec §3 Module 1** ("the enforcement must sit
where both bases funnel their writes") for the `handlers/handler.py:4` base —
`ModelHandler(ModelView)`. Four of the five hardened handlers sit on it:
`UserManager` (TASK-153, after its base change), `GroupManager`,
`UserGroupManager`, `GroupPermissionManager` (TASK-154). The fifth,
`PermissionHandler`, sits on the *other* base and is wired in TASK-155. Not
delegation-eligible: a hook missed here re-opens the hole silently.

**The guard does not hook itself into anything.** `OwnerOrSuperuserGuard` only
offers coroutines (`authorize_row`, `authorize_columns`, `sanitize_query`,
`safe_filter`). FEAT-105's handlers call them from their own verb hooks
(`userattrs.py:84-272`). FEAT-107 has four handlers on the same base, and the
spec says per-surface behaviour is configuration, not forked logic (§7). So this
task writes the hooks **once**, as a mixin:

```python
class UserManager(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler): ...
```

The mixin cannot live on `OwnerOrSuperuserGuard` itself: the FEAT-105 handlers
inherit the guard and define their own `_set_update`, `_pre_put`, … whose
`super()` calls would then run these hooks too (G7 regression). A separate class
keeps FEAT-105 untouched. Guard first, `ModelHandler` last, so
`test_usermanager_guard_first_in_mro` (spec §4) holds.

### Reads are gated too (user decision, 2026-11-11)

The spec puts `read` in every handler's `superuser_actions` but no AC mentions
reads. Asked during `/sdd-task`, the user chose **gate reads**: an ownerless
surface (groups, memberships, group permissions) is superuser + policy only; an
owned surface (users) shows a non-superuser only their own row. This mixin
implements both read shapes.

### Verified write paths of upstream `ModelView` (navigator-api 3.2.2) — the map this task must cover

| Path | Goes through `_set_update`? | Where |
|---|---|---|
| `PUT` dict, body carries an existing PK → update | yes | `model.py:976-987` |
| `PUT` dict, no PK → `self.model(**data).insert()` | **no** | `model.py:996-1007` |
| `PUT` list → `self.model.create(data)` (bulk insert) | **no** | `model.py:941-956` |
| `PUT` merges query params into the row: `data = {**qp, **data}` | — | `model.py:965` |
| `POST` list, per entry update | yes | `model.py:1114` |
| `POST` list, per entry insert | **no** | `model.py:1123-1135` |
| `POST` dict, `objid` is a list → `self.model.updating(_filter=objid, **data)` | **no** | `model.py:1172-1185` |
| `POST` dict, existing row → update | yes | `model.py:1202` |
| `POST` dict, missing row → insert | **no** | `model.py:1217-1238` |
| `POST` without a PK in body or URL → 400 (POST never creates without a PK) | — | `model.py:1157-1170` |
| `PATCH` dict / list → update | yes | `model.py:760-819` |
| `PATCH /<id>/<attribute>` with a non-dict body → `obj.set(_attribute, …)` | **no** | `model.py:820-830` |
| `DELETE` → `self._del_primary_data(args)` when defined | — | `model.py:1413-1417` |

`_post_data` / `_patch_data` also **add** keys server-side through every
`_set_<column>` hook (`model.py:506-549`, `653-689`) — e.g. `_set_created_by`
fills `created_by`. A column check on the processed data would refuse every
create on `Group` (`created_by` is privileged there). So the check runs on the
**raw client keys**, captured before upstream processes them.

Conclusion — the rule this mixin implements, independent of upstream's routing:

- **PUT** = create: `authorize_row(create, None, payload=raw ∪ query-columns, creating=True)` in `_pre_put`; if the row turns out to exist, `_set_update` re-checks as an update.
- **POST** = upsert: approve **both** `create` and `update` with the same raw keys in `_pre_post` — the `PartnerKeyHandler.post` precedent (`partners.py:177-192`). This also covers the `updating(...)` bypass. Consequence: an owner edits their own row with PATCH, not POST.
- **PATCH** = update: require a JSON object (or list of objects) body in `_pre_patch`; decide the row in `_set_update`, where the row and its owner are known.
- **`_set_update`** fails closed if no pre-hook captured the raw keys.
- **DELETE**: resolve the target in `_del_primary_data`, authorize `delete` (404 on deny).

### Spec deviation recorded at /sdd-task time
- The installed upstream `ModelView._filtering` (navigator-api **3.2.2**,
  `model.py:419-447`) interpolates the `_filter` value into SQL. The guard's
  docstring (`guards.py:215-220`) refers to 4.0.1, which is not what is
  installed. This mixin overrides `_filtering` to go through the guard's
  parameterized `safe_filter`, and refuses `_filter` when the host declares no
  `public_columns` (none of the four do) — fail closed.

---

## Scope

- Create `navigator_auth/handlers/guard_hooks.py` with `GuardedModelViewHooks`:
  - `action_object` class attribute and `_action(verb)` → `"<object>:<verb>"` (501 when unset).
  - `_client_keys(include_query=False)` → raw client keys; 400 on a non-object body.
  - Reads: `_pre_get`, `_get_data` (owned surfaces only), `_filtering`, `head`.
  - Writes: `_pre_put`, `_pre_post`, `_pre_patch`, `_pre_delete`, `_set_update`, `_del_primary_data`.
- Write `tests/unit/handlers/test_guard_model_view_hooks.py` against synthetic
  hosts built on the real `handlers/handler.py` `ModelHandler`.

**NOT in scope**:
- Configuring any real handler (TASK-153, TASK-154).
- The `handlers/model.py` base (TASK-155).
- Protected-group checks (TASK-152 provides them, TASK-154 calls them).
- Response projection / redaction of read results (`public_columns` stays
  unset on the five handlers; `password` is already hidden by upstream `_hidden`
  because it is `secret=True`, `models.py:51`).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/guard_hooks.py` | CREATE | `GuardedModelViewHooks` mixin |
| `tests/unit/handlers/test_guard_model_view_hooks.py` | CREATE | Hook-level tests over synthetic hosts |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `6b8cc84` on 2026-11-11. Upstream paths are under
> `.venv/lib/python3.11/site-packages/navigator/views/` (navigator-api 3.2.2).

### Verified Imports

```python
import logging
from typing import Any, Optional
from aiohttp import web
from asyncdb.exceptions import NoDataFound                 # used at userattrs.py:4
from datamodel.exceptions import ValidationError           # used at userattrs.py:6
# test side:
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard   # guards.py:31
from navigator_auth.handlers.handler import ModelHandler           # handler.py:4 (over ModelView)
from navigator_auth.models import User, UserGroup                  # models.py:39, :209
```

### Existing Signatures to Use

```python
# After TASK-149 — navigator_auth/handlers/guards.py
class OwnerOrSuperuserGuard:
    owner_column: Optional[str]; public_columns: frozenset[str]; policy_name: Optional[str]
    superuser_actions: frozenset[str]
    writable_by_owner / writable_by_admin / privileged_columns: frozenset[str]
    creatable_by_admin: Optional[frozenset[str]]
    async def acting_user(self) -> tuple[int, bool]: ...                      # 401
    async def authorize_row(self, action, owner_id, *, not_found_on_deny=False,
                            payload=None, creating=False) -> bool: ...        # raises
    async def sanitize_query(self, qp: dict, fields) -> tuple[dict, Optional[list[str]]]: ...  # :163
    async def safe_filter(self, expr: str) -> list[dict]: ...                 # :207, parameterized
    #   widens for a superuser only via an action in superuser_actions ending with ":read" (:255-258)

# navigator_auth/handlers/handler.py:4
class ModelHandler(ModelView):
    dbname: str = 'authdb'
    async def _set_created_by(self, value, column, **kwargs): ...

# navigator/views/model.py (upstream ModelView) — hooks this mixin overrides
async def _get_data(self, qp, args): ...                     # :317
async def _filtering(self, queryparams: dict) -> web.Response | None: ...   # :419  (interpolates SQL!)
async def _set_update(self, model, data): ...                # :629
def _del_primary(self, args: dict = None) -> Any: ...        # :1326  str pk → args.get('id'); list pk → dict
async def _get_primary_data(self, args): ...                 # :310
# navigator/views/abstract.py
async def head(self): ...                                    # :450 (@service_auth, no pre-hook)
async def _pre_get/_pre_patch/_pre_put/_pre_post/_pre_delete(self, *a, **kw): ...  # :553-569 → True
def get_args(self) -> dict: ...                              # used by get_parameters :439
# navigator/views/base.py
def query_parameters(self, request: web.Request) -> dict: ...   # :309
async def json_data(self, request: web.Request = None): ...     # :340 — body is cached; safe to read twice
```

- A falsy return from a `_pre_*` hook becomes a fixed **412** (`model.py:697-703`
  and siblings). Refuse by **raising** (`self.error`, `authorize_row`), never by
  returning `False`.
- FEAT-105 reference implementation of every hook in this task:
  `UserAccountHandler` — `_pre_get` `userattrs.py:84-91`, `_get_data` `:93-133`,
  `_pre_put` `:141-156`, `_require_structured_patch` `:162-176`, `_set_update`
  `:228-249`, `_del_primary_data` `:251-272`.
- Test harness to copy: `tests/unit/handlers/test_user_account_handler_access.py`
  (drives a real `handler.py`-based handler with mocked request/session/model).

### Does NOT Exist (Anti-Hallucination)

- ~~`navigator_auth/handlers/guard_hooks.py`~~ / ~~`GuardedModelViewHooks`~~ — created here.
- ~~a `_pre_head` hook upstream~~ — `head` has none; override `head` itself.
- ~~`_del_primary_data` upstream~~ — upstream only *calls* it when the host defines it (`model.py:1413`).
- ~~a parameterized `_filtering` in the installed navigator-api~~ — 3.2.2 interpolates.
- ~~`action_object` on the guard~~ — it lives on this mixin.

---

## Implementation Blueprint

### `navigator_auth/handlers/guard_hooks.py` — CREATE (block 1 of 3: header and helpers)

```python
"""Verb hooks that put a navigator ``ModelView`` behind ``OwnerOrSuperuserGuard`` (FEAT-107).

Use with the ``handlers/handler.py`` ``ModelHandler`` (over ``ModelView``)::

    class UserManager(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler): ...

Guard first, this mixin second, the model base last. The mixin calls the
guard's coroutines and delegates to ``ModelView`` through ``super()``.

Rules (see TASK-151 for the verified upstream write paths):

* PUT is a create: the raw client keys plus any query-string column are
  checked with ``creating=True`` before upstream touches the database.
* POST is an upsert: both ``create`` and ``update`` must be approved.
* PATCH is an update: the row and its owner are decided in ``_set_update``.
* Every column check uses the keys the CLIENT sent, never the processed data
  (``_set_<column>`` hooks add server-side keys such as ``created_by``).
* Refusals are raised. A falsy ``_pre_*`` return would become a fixed 412.
"""

import logging
from typing import Any, Optional

from aiohttp import web
from asyncdb.exceptions import NoDataFound
from datamodel.exceptions import ValidationError

logger = logging.getLogger("navigator.auth.guard_hooks")


class GuardedModelViewHooks:
    """ModelView verb hooks for an ``OwnerOrSuperuserGuard`` host.

    Attributes:
        action_object: The ``object`` half of every ABAC action this host
            checks, e.g. ``"user"`` → ``user:read`` / ``user:update``. Must
            match the host's ``superuser_actions`` and the policy pack.
    """

    action_object: str = ""
    #: Raw client keys of the current write, set by a ``_pre_*`` hook.
    _guard_write_keys: Optional[frozenset[str]] = None

    def _action(self, verb: str) -> str:
        """Return ``"<action_object>:<verb>"``; 501 when the host forgot to set it."""
        if not self.action_object:
            raise web.HTTPNotImplemented(text='{"error": "Not Implemented"}', content_type="application/json")
        return f"{self.action_object}:{verb}"

    async def _client_keys(self, *, include_query: bool = False) -> frozenset[str]:
        """Return (and remember) the column names the client sent.

        Args:
            include_query: Also count query-string keys that are model
                columns — upstream PUT merges them into the row (model.py:965).

        Raises:
            web.HTTPBadRequest: the body is not a JSON object or a non-empty
                list of objects (closes the single-attribute PATCH form,
                model.py:820-830, which never reaches ``_set_update``).
        """
        # FILL IN: read `await self.json_data()` inside try/except Exception (malformed → treat as None);
        #   normalise to a list of elements; 400 unless it is a NON-EMPTY list of dicts;
        #   keys = union of element keys; if include_query, add
        #   {k for k in self.query_parameters(self.request) if k in self.model.get_columns()}.
        #   Store frozenset(keys) on self._guard_write_keys and return it.
        raise NotImplementedError
```

**Why**: the raw-key capture is the single source every check uses; storing it on
the instance lets `_set_update` (which only sees processed data) check exactly
what the client sent. aiohttp creates one view instance per request, so the
attribute is per-request.

### `navigator_auth/handlers/guard_hooks.py` — CREATE (block 2 of 3: reads)

```python
    # ------------------------------------------------------------------
    # Reads (gated: user decision 2026-11-11)
    # ------------------------------------------------------------------
    async def _pre_get(self, *args, **kwargs) -> bool:
        """Ownerless surface → superuser + policy. Owned → 401 and no foreign owner param."""
        if self.owner_column is None:
            await self.authorize_row(self._action("read"), None)
            return True
        await self.acting_user()
        qp = dict(self.query_parameters(self.request))
        qp.pop("fields", None)
        await self.sanitize_query(qp, None)
        return True

    async def _get_data(self, qp, args):
        """Bind an owned surface's reads to the acting user unless a superuser is approved."""
        if self.owner_column is None:
            return await super()._get_data(qp, args)
        # FILL IN: port UserAccountHandler._get_data (userattrs.py:93-133) verbatim, replacing
        #   `self._require_owner_column()` with `self.owner_column` and the literal "account:read"
        #   with `self._action("read")`. Keep the instance-level `_filter_<owner>` binding
        #   (a class-level hook cannot express the superuser case) and the 404-on-deny for a
        #   primary-key read of a foreign row.
        raise NotImplementedError

    async def _filtering(self, queryparams: dict):
        """Replace upstream's interpolated ``_filter`` (model.py:419-447) with ``safe_filter``."""
        expr = (queryparams or {}).get("_filter")
        if not expr:
            return None
        if not self.public_columns:
            self.error(response={"error": "Invalid _filter"}, status=400)
        rows = await self.safe_filter(expr)
        return self.json_response(rows, status=200)

    async def head(self):
        """Same gate as GET; HEAD has no upstream pre-hook (abstract.py:450)."""
        if self.owner_column is None:
            await self.authorize_row(self._action("read"), None)
        else:
            await self.acting_user()
        return await super().head()
```

**Why**: `:meta` on GET is served after `_pre_get` (`model.py:451-460`), so it is
gated with the rest. `safe_filter` already ANDs the owner predicate for
non-superusers and binds the value as `$1`; refusing `_filter` when
`public_columns` is empty keeps it fail-closed for the four FEAT-107 hosts.

### `navigator_auth/handlers/guard_hooks.py` — CREATE (block 3 of 3: writes)

```python
    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------
    async def _pre_put(self, *args, **kwargs) -> bool:
        """PUT inserts: always the superuser create path, checked on raw keys + query columns."""
        keys = await self._client_keys(include_query=True)
        await self.authorize_row(self._action("create"), None, payload=keys, creating=True)
        return True

    async def _pre_post(self, *args, **kwargs) -> bool:
        """POST upserts, so approve BOTH verbs with the same keys (partners.py:177-192)."""
        keys = await self._client_keys()
        # FILL IN: for a str pk, refuse (400) a PK value containing "/" — from the body's pk / "id"
        #   key or from self.get_args().get("id"). Upstream get_primary splits it into a list
        #   (model.py:248-251) and POST then calls self.model.updating(_filter=objid, **data)
        #   (model.py:1172-1185), which never reaches _set_update — so a host's _set_update
        #   checks (TASK-154's stored protected-group name) would be skipped.
        await self.authorize_row(self._action("create"), None, payload=keys, creating=True)
        await self.authorize_row(self._action("update"), None, payload=keys)
        return True

    async def _pre_patch(self, *args, **kwargs) -> bool:
        """401, then a structured body. The row is decided in ``_set_update``."""
        if self.get_args().get("meta") == ":meta":
            # FILL IN: same gate as head() — ownerless → authorize_row(read, None); owned → acting_user()
            return True
        await self.acting_user()
        await self._client_keys()
        return True

    async def _pre_delete(self, *args, **kwargs) -> bool:
        """401 only; the target row is resolved in ``_del_primary_data``."""
        await self.acting_user()
        return True

    async def _set_update(self, model, data) -> None:
        """Authorize an update against the fetched row, then delegate to ModelView."""
        keys = self._guard_write_keys
        if keys is None:
            # Reached without one of our pre-hooks: fail closed rather than skip the check.
            self.error(response={"error": "Forbidden"}, status=403)
        owner_id = getattr(model, self.owner_column, None) if self.owner_column else None
        # FILL IN: refuse a payload that would move the row to another owner — bounded by
        #   userattrs.py:237-241: data[owner_column] is None → pop it; a different value → 403.
        await self.authorize_row(self._action("update"), owner_id, payload=keys)
        return await super()._set_update(model, data)

    async def _del_primary_data(self, args: dict):
        """Resolve and authorize the delete target; 404 on deny. No id → 400."""
        try:
            objid = self._del_primary(args)
        except (TypeError, KeyError):
            objid = None
        if not objid:
            self.error(response={"error": "A primary key is required in the URL"}, status=400)
        if self.owner_column is None:
            await self.authorize_row(self._action("delete"), None, not_found_on_deny=True)
            return objid
        # FILL IN: owned surface — 400 on a list objid (multi-delete cannot be authorized row by row
        #   here); fetch the row with {self.pk: objid} under `async with await self.handler(request=self.request)`
        #   catching (NoDataFound, ValidationError) → owner None; then
        #   authorize_row(self._action("delete"), owner_id, not_found_on_deny=True). Copy userattrs.py:263-272.
        return objid
```

**Why**:
- `_pre_put` checks before any DB access, so the bulk-insert and plain-insert
  branches (which never call `_set_update`) are covered.
- `_pre_post` requiring `update` too means an owner cannot use POST on an owned
  surface: owners edit through PATCH. Document it in TASK-158.
- `_set_update` uses the stashed raw keys, not `data`, because `data` contains
  server-filled keys.
- A host's subclass may add checks (TASK-154's protected groups) by overriding a
  hook and calling `super()` **first**, so this mixin's authorization always runs.

### `tests/unit/handlers/test_guard_model_view_hooks.py` — CREATE

```python
"""GuardedModelViewHooks over the ModelView-based ModelHandler (FEAT-107, TASK-151)."""

import pytest
from navigator_auth.handlers.guard_hooks import GuardedModelViewHooks
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard
from navigator_auth.handlers.handler import ModelHandler
from navigator_auth.models import User, UserGroup

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")


class OwnedHost(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler):
    model = User
    pk = "user_id"
    action_object = "user"
    owner_column = "user_id"
    policy_name = "users_admin_access"
    superuser_actions = frozenset({"user:read", "user:create", "user:update", "user:delete"})
    writable_by_owner = frozenset({"first_name", "last_name", "display_name", "title", "avatar", "timezone"})
    writable_by_admin = writable_by_owner | {"is_active", "email", "alt_email"}
    creatable_by_admin = writable_by_admin | {"username"}
    privileged_columns = frozenset({"is_superuser", "user_role", "is_staff", "password",
                                    "userid", "user_id", "created_at", "last_login"})


class OwnerlessHost(OwnerOrSuperuserGuard, GuardedModelViewHooks, ModelHandler):
    model = UserGroup
    pk = ["user_id", "group_id"]
    action_object = "user_group"
    owner_column = None
    policy_name = "user_groups_admin_access"
    superuser_actions = frozenset({"user_group:read", "user_group:create", "user_group:delete"})
    creatable_by_admin = frozenset({"user_id", "group_id"})

# FILL IN: request/session/PDP/model-connection harness — copy from
#   tests/unit/handlers/test_user_account_handler_access.py

class TestWrites:
    async def test_put_checks_raw_keys_as_create(self): ...               # privileged refused; created_by NOT sent → passes
    async def test_put_counts_query_string_columns(self): ...            # PUT ?is_superuser=true → 403
    async def test_post_requires_create_and_update(self): ...            # policy granting only create → 403
    async def test_post_refuses_slash_in_str_pk(self): ...               # POST /users/5/6 → 400, no updating()
    async def test_patch_refuses_non_object_body(self): ...              # text / scalar JSON → 400
    async def test_set_update_owner_uses_owner_allowlist(self): ...      # owner: first_name ok, email 403
    async def test_set_update_without_prehook_fails_closed(self): ...    # _guard_write_keys None → 403
    async def test_delete_requires_pk(self): ...                         # no id → 400
    async def test_delete_foreign_row_is_404_for_non_superuser(self): ...

class TestReads:
    async def test_ownerless_get_superuser_only(self): ...               # ordinary session → 403
    async def test_owned_get_foreign_owner_param_refused(self): ...      # ?user_id=<other> → 403
    async def test_filter_refused_without_public_columns(self): ...      # 400 and no SQL executed
    async def test_head_gated_for_ownerless(self): ...

class TestIsolation:
    def test_feat105_handlers_do_not_inherit_hooks(self): ...            # UserAccountHandler / UserIdentityHandler / PartnerKeyHandler
    def test_missing_action_object_is_501(self): ...
```

### Steps (in order)

1. Write block 1 and complete `_client_keys` — because every other hook depends
   on it and its 400 is what closes the single-attribute PATCH bypass.
2. Write blocks 2 and 3. Port the two FEAT-105 bodies (`_get_data`,
   `_del_primary_data` owned branch) by copying, not re-deriving — because their
   edge cases (instance-level filter binding, 404 on foreign PK) are already
   tested in FEAT-105.
3. Write the tests, copying the request/session/PDP harness from
   `test_user_account_handler_access.py` — because it already mocks
   `self.handler(...)` connections for the `handler.py` base.
4. Run `pytest tests/unit/handlers/test_guard_model_view_hooks.py -v`, then the
   whole `tests/unit/handlers/` directory (G7).
5. `ruff check navigator_auth/handlers/guard_hooks.py`.

### FILL IN checklist

- [ ] `_client_keys` body (400 contract, query-column union, stash).
- [ ] `_get_data` owned branch (port of `userattrs.py:93-133`).
- [ ] `_pre_patch` `:meta` gate.
- [ ] `_pre_post` refusal of a `/` inside a str-pk value.
- [ ] `_set_update` owner-move refusal (`userattrs.py:237-241`).
- [ ] `_del_primary_data` owned branch (`userattrs.py:263-272`), list objid → 400.
- [ ] Test harness and all test bodies.

---

## Acceptance Criteria

- [ ] `pytest tests/unit/handlers/test_guard_model_view_hooks.py -v` passes.
- [ ] `pytest tests/unit/handlers/ -v` passes (FEAT-105 suites unchanged, G7).
- [ ] No write path in the table above reaches the database without a column check on the raw client keys (spec AC13, `handler.py` half).
- [ ] `PUT ?<privileged>=…` is refused; a non-object PATCH body is refused with 400.
- [ ] `_filter` never reaches upstream's interpolated `_filtering`.
- [ ] `UserAccountHandler`, `UserIdentityHandler`, `PartnerKeyHandler` are not subclasses of `GuardedModelViewHooks`.
- [ ] `ruff check navigator_auth/handlers/guard_hooks.py tests/unit/handlers/test_guard_model_view_hooks.py` is clean.

---

## Test Specification

See the CREATE block above. Every refusal test asserts the exception class
(`web.HTTPForbidden` / `HTTPBadRequest` / `HTTPNotFound`) **and** that no
model `insert` / `update` / `create` / `updating` was awaited on the mocked
connection.

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at `sdd/specs/auth-model-crud-hardening.spec.md` (§3 Module 1 "Note on coverage", §7 R3).
2. **Check dependencies** — TASK-149 is `done` in `sdd/tasks/index/auth-model-crud-hardening.json`.
3. **Re-verify** the upstream line numbers in the write-path table against the installed navigator-api (`uv pip show navigator-api`); stop and report if it is no longer 3.2.2.
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

**Deviations from spec**: shared mixin instead of per-handler hooks; reads gated (user decision) | other
