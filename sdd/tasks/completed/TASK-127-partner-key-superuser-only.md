# TASK-127: Lock down `PartnerKeyHandler` — superuser-only, return-once token

**Feature**: FEAT-105 — Owner-or-Superuser ABAC Ownership for the Auth Model CRUD Surfaces
**Spec**: `sdd/specs/user-identities-ownership-abac.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-122
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 6** and goal **G8**. `auth.partner_keys` is the
worst of the three surfaces: `PartnerKey.token` holds a **plaintext signed
JWT** (`jwt.encode(payload, AUTH_TOKEN_SECRET, AUTH_JWT_ALGORITHM)` —
`handlers/partners.py:59-64`), the column has neither `repr=False` nor
`secret=True` (`:25`), and `PartnerKeyHandler` is generic CRUD reachable by
any authenticated session at `/api/v1/partner/tokens/{id:.*}` and
`/api/v1/partner/tokens{meta}` (`handlers/__init__.py:48-56`). So today any
logged-in user can `GET` every partner's signing token and authenticate as
that partner.

After this task (spec §3 Module 6's table):

| Verb | Superuser | Anyone else |
|---|---|---|
| `GET` (any form) | rows without `token` | **403** |
| `PUT` / `POST` that creates | 201 **including** `token` (once) | 403 |
| `PATCH` / `POST` that updates | 202 without `token` | 403 |
| `DELETE` | allowed, audited | 403 |
| `:meta` | schema minus `token` | 403 |

Two things make this task different from the other two surfaces:

1. **`owner_column = None`** — partner keys have no owner column at all
   (verified below), so the superuser path is the *only* path for every verb.
   There is no self-service tier to preserve.
2. **A different base class.** `PartnerKeyHandler` sits on the **local**
   `navigator_auth/handlers/model.py` `ModelHandler`, which has **no
   `_pre_*` hooks and no `_filter_<column>` hooks**. The guard must therefore
   be invoked at the top of each overridden verb, and redaction attaches to
   `_post_get` and to each verb's own response.

**Why the token may be returned once.** An operator creating a partner key
has to receive the signed token to hand to the partner; it is not recoverable
afterwards, because nothing stores a recoverable copy. Returning it in the
creation response and never again is the standard shape for a credential the
server cannot show twice.

> **Environment drift.** Spec §6's upstream `navigator` table describes
> `navigator-api` 3.2.2 vs the installed 4.0.1 — but this surface inherits
> from the **local** base, not from `ModelView`, so almost none of that
> applies here. The local base is in this repository and is quoted verbatim
> below.

---

## Scope

- Make `PartnerKeyHandler` inherit `OwnerOrSuperuserGuard` **before** the
  local `ModelHandler`, with `owner_column = None`.
- Invoke the guard at the top of `get`, `put`, `patch`, `post`, `delete` and
  `head`; refuse **403** for every non-superuser.
- Redact `token` out of every read (`_post_get`), out of `:meta` on both the
  `get()` and the `patch()` paths, out of `head()`'s `X-Columns`, and out of
  every update and delete response.
- Keep `token` in the **creation** response only.
- Keep `_get_token` exactly as it is.
- Add `tests/unit/handlers/test_partner_key_handler_access.py`.

**NOT in scope**:
- `UserIdentityHandler` / `UserAccountHandler` — TASK-123..126.
- Changing `PartnerKey`'s column definitions. Spec §3 Module 6: *"`PartnerKey.token`
  keeps its column definition for now; a follow-up may add `repr=False` /
  `secret=True`, but the guard must not depend on it (the local base ignores
  `repr`)."* Do not add either flag.
- Changing the local `navigator_auth/handlers/model.py` base. Other handlers
  depend on it (`permissions.py:4`, `abac/policyhandler.py:8`); a change there
  is a different spec. Override in the subclass.
- Rotating, re-ciphering or hashing the stored token, or adding a
  `token_hash` column. Spec §1 Non-Goals keeps this feature to access control
  and redaction.
- `?_filter=` on this surface. The local base has **no** `_filtering` and no
  `_filter` parameter at all (verified below), so there is nothing to
  override — and because every verb is superuser-only and every response is
  redacted, there is no gap. Say so in the Completion Note rather than adding
  a filter.
- Fixing the local base's `delete()` not-found status quirk (see the contract
  note). Out of scope; record it.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/partners.py` | MODIFY | Guard the handler; redact `token` from every non-creation response |
| `tests/unit/handlers/test_partner_key_handler_access.py` | CREATE | Access and return-once-token tests |

---

## Codebase Contract

> Every fact below was re-verified on `dev` @ `62fd419` (2026-10-23).

### `navigator_auth/handlers/partners.py` — the complete current file (68 lines)

```python
from typing import Any
from uuid import UUID
from datetime import datetime
import jwt
from asyncdb.models import Model, Column
from ..conf import (
    AUTH_DB_SCHEMA,
    AUTH_TOKEN_ISSUER,
    AUTH_JWT_ALGORITHM,
    AUTH_TOKEN_SECRET
)
from ..exceptions import ConfigError
from .model import ModelHandler

class PartnerKey(Model):
    partner_id: UUID = Column(
        required=True,
        primary_key=True,
        db_default="auto",
        repr=False
    )
    name: str = Column(required=True)
    partner: str = Column(required=True)
    issuer: str = Column(required=True, default='navigator')
    token: str = Column(required=True)
    created_at: datetime = Column(required=False, default=datetime.now)
    revoked: bool = Column(default=False)
    enabled: bool = Column(default=True)
    grants: dict = Column(default_factory=dict)
    programs: list = Column(default_factory=list)

    class Meta:
        name = 'partner_keys'
        schema = AUTH_DB_SCHEMA
        strict = True
        connection = None


class PartnerKeyHandler(ModelHandler):
    model: Any = PartnerKey
    name: str = "Partner Key Authentication"
    pk: list[str] = ["partner_id"]

    async def _get_token(self, value, column, data):
        """
        Generate the Token using data.
        """
        try:
            payload = {
                'name': data['name'],
                'partner': data['partner'],
                'issuer': AUTH_TOKEN_ISSUER
            }
        except KeyError as exc:
            raise ConfigError(
                f"Invalid Data for Partner Token Creation: {exc}"
            ) from exc
        try:
            return jwt.encode(
                payload=payload,
                key=AUTH_TOKEN_SECRET,
                algorithm=AUTH_JWT_ALGORITHM,

            )
        except Exception as exc:
            raise RuntimeError(
                f"Unable to generate Token: {exc}"
            ) from exc
```

Key facts: `class PartnerKey` at `:15`; `token: str = Column(required=True)`
at `:25` — **no `repr=False`, no `secret=True`**; `revoked` at `:27`,
`enabled` at `:28`; `class PartnerKeyHandler(ModelHandler)` at `:39`;
`pk: list[str] = ["partner_id"]` at `:42` — **a list, not a str**;
`_get_token` at `:44`.

There is **no `user_id` or any owner column on `PartnerKey`** — hence
`owner_column = None`.

### The LOCAL base — `navigator_auth/handlers/model.py`

`class ModelHandler(BaseView)` at `:21`. Verified members:

| Member | Line | Note |
|---|---|---|
| `model` / `model_name` / `name` / `pk = "id"` | `:22-25` | class attributes |
| `__init__(request, *args, **kwargs)` | `:27-34` | honours `model_name` via `get_authmodel`, and **overrides `self.pk` from `self.model.Meta.pk` when present** (`:32-33`) |
| `get_authmodel(model)` | `:36` | import-by-path with a silent fallback |
| `get_userid(session, idx='user_id')` | `:50` | `self.error(reason="Unauthorized", status=403)` when absent — note **403**, not 401 |
| `_get_data(session=None)` | `:64` | calls the `_get_<column>` hooks — **this is how `_get_token` runs** (`:75-81`) |
| `_post_get(result, fields=None)` | `:88` | the single read-response hook; applies `fields` by `getattr` and then `self.json_response(content=result)` |
| `session()` | `:112` | sets `self._session`; `self.error(..., status=403)` when absent |
| `head()` | `:127` | `X-Columns` from `self.model.schema(as_dict=True)["properties"]` — **enumerates `token`** |
| `get()` | `:143` | `:meta` at `:149-152` returns the **raw** `self.model.schema(as_dict=True)`; list-`pk` path at `:175-187`; `_post_get` at `:210` (PK) and `:219` (list) |
| `put()` | `:245` | `result = await resultset.insert()`; `self.json_response(content=result, status=201)` at `:257` — **returns the inserted row, token included** |
| `patch()` | `:284` | `:meta` at `:290-293` returns `self.model.__fields__` (a **second, different** metadata leak); update → `json_response(content=data, status=202)` at `:348` |
| `post()` | `:352` | insert branch → `201` at `:399` and at `:425`; update branch → `202` at `:417` |
| `delete()` | `:445` | `result.delete()` → `json_response(content=data, status=202)` at `:493` |

**No `_pre_*` hooks and no `_filter_<column>` hooks exist on this base** —
confirmed by reading the whole file. So:

- the guard cannot be hung off a pre-hook; it must be the first statement of
  each overridden verb;
- there is no `?_filter=` path at all on this surface (nothing reads a
  `_filter` query parameter), so spec G7 has nothing to close here.

### Two `:meta` leaks, not one

`get()` `:149-152`:

```python
            if params["meta"] == ":meta":
                # returning JSON schema of Model:
                response = self.model.schema(as_dict=True)
                return self.json_response(content=response)
```

`patch()` `:290-293`:

```python
            if params["meta"] == ":meta":
                ## returning the columns on Model:
                fields = self.model.__fields__
                return self.json_response(content=fields)
```

The second returns `__fields__`, not a schema — a different payload shape
that also names `token`. Both need handling (AC-9).

### CRITICAL — `schema(as_dict=True)` is a CACHED, SHARED dict

Verified by executing it against a model: two calls return the *same* dict
object and the class gains `__computed_schema__`. So the `:meta` override
must not mutate it — use `redact_schema` (TASK-118), which copies.

### `self.error()` raises

Verified `.venv/lib/python3.11/site-packages/navigator/views/base.py:201-243`:
`error()` maps the status to a `web.HTTPException` and **raises** it. The
local base inherits it (`ModelHandler(BaseView)` `:21`;
`BaseView(CorsViewMixin, BaseHandler, web.View)` at `base.py:619`;
`error` on `BaseHandler` at `base.py:201`). So a guard refusal raised inside
an overridden verb reaches the client with its own status.

**Quirk, out of scope:** `delete()` at `:490` calls
`self.error(reason=f"{self.name} was Not Found", status=204)`, and 204 is not
in `error()`'s status map, so it falls through to
`else: obj = web.HTTPBadRequest(**args)` — a missing partner key answers
**400**. Do not fix it here; record it in the Completion Note so it can be
filed.

### `_get_token` is invoked through `_get_data`

Verified `navigator_auth/handlers/model.py:72-81`:

```python
            for name, column in self.model.get_columns().items():
                ### if a function with name _get_{column name} exists
                ### then that function is called for getting the field value
                if hasattr(self, f'_get_{name}'):
                    fn = getattr(self, f'_get_{name}')
                    data[name] = await fn(
                        value=data.get(name, None),
                        column=column,
                        data=data
                    )
```

So `_get_token` runs on every `put`/`patch`/`post`/`delete` (each calls
`_get_data`), **regenerating the JWT from the payload every time** — not only
on create. Two consequences:

- `_get_token` raises `ConfigError` when `name` or `partner` is missing
  (`partners.py:54-57`), so a `PATCH` that omits them already fails. That is
  pre-existing behaviour; do not change it.
- The token in an **update** response is a freshly minted JWT, not a stored
  one. Redacting it from the 202 is still required (spec §3 Module 6's
  table), and is what "never echoed" means.

### The guard configuration for this surface (spec §2 Data Models)

| Attribute | Value |
|---|---|
| `owner_column` | `None` — **no owner column exists** |
| `credential_columns` | `token` |
| `public_columns` | `partner_id`, `name`, `partner`, `issuer`, `created_at`, `revoked`, `enabled`, `grants`, `programs` |
| `policy_name` | `"partner_keys_admin_access"` |
| `superuser_actions` | `partner:read`, `partner:create`, `partner:revoke`, `partner:delete` |

Every name verified against `navigator_auth/handlers/partners.py:15-30`.
`public_columns` is the full column set **minus `token`** — nine of ten
columns. The four actions (note `partner:create`, which the other two
surfaces do not have) must match TASK-120's pack exactly.

### Guard primitives (TASK-122)

- `await self.acting_user()` → `(user_id, is_superuser)`; raises 401 with no
  session.
- `await self.authorize_row(action, owner_id, *, not_found_on_deny=False)` →
  returns `True`, **raises** on deny. With `owner_column is None` the owner
  branch can never be taken, so the superuser path is the only path — exactly
  what this surface needs (TASK-122 AC-6).
- `await self.sanitize_query(qp, fields)` → sanitized; with
  `owner_column is None` there is no owner parameter to refuse, but the
  `credential_columns` drop still applies.
- `redact_rows` / `redact_schema` / `safe_fields` from
  `navigator_auth.handlers.redaction` (TASK-118).

### Does NOT Exist (do not reference)

- `_pre_get` / `_pre_put` / `_pre_patch` / `_pre_post` / `_pre_delete` on the
  local base — **they do not exist**. Defining them on `PartnerKeyHandler`
  would create methods nobody calls, i.e. a handler that looks guarded and
  is not. This is the single most likely way to get this task wrong.
- `_filter_<column>` hooks, `_filtering`, `_model_response`,
  `_get_meta_info`, `get_parameters`, `_post_data`, `_patch_data`,
  `_set_update`, `_del_primary_data` on the local base — all are `ModelView`
  members and **none** is inherited here. Verified by reading
  `navigator_auth/handlers/model.py` in full.
- A `user_id` / `owner` / `partner_user_id` column on `PartnerKey`
  (`partners.py:15-30`) — hence `owner_column = None`.
- `secret=True` / `repr=False` on `PartnerKey.token` — and do not add them
  (spec §3 Module 6; the local base ignores `repr` entirely).
- A stored hash or a second copy of the token anywhere. `_get_token` mints it
  from the payload; nothing persists a recoverable duplicate.
- `groups_protected(['superuser'])` as the mechanism. It exists and is used by
  `abac/policyhandler.py:8`, but spec §1/§2 require the **policy-governed**
  path (`policy_allows`), which a group decorator cannot provide (spec §6:
  `decorators.is_superuser` "consults no policy, so it cannot satisfy G2's
  policy-governed path"). Use the guard.
- `tests/unit/handlers/test_partner_key_handler_access.py` — this task
  creates it.

---

## Implementation Blueprint

### `navigator_auth/handlers/partners.py` — MODIFY (three blocks)

**Block 1 — imports:**

```python
# AFTER — insert below `from .model import ModelHandler`
# anchor (verified: navigator_auth/handlers/partners.py:13)
# occurrences: 1 (verified: grep -cF 'from .model import ModelHandler' navigator_auth/handlers/partners.py)
from .model import ModelHandler
from .guards import OwnerOrSuperuserGuard
from .redaction import redact_rows, redact_schema
```

**Block 2 — the class declaration and configuration:**

```python
# AFTER — replace the `class PartnerKeyHandler(ModelHandler):` line and the
# three attribute lines beneath it
# anchor (verified: navigator_auth/handlers/partners.py:39-42)
# occurrences: 1 (verified: grep -cF 'class PartnerKeyHandler(ModelHandler):' navigator_auth/handlers/partners.py)

class PartnerKeyHandler(OwnerOrSuperuserGuard, ModelHandler):
    """Superuser-only CRUD over ``auth.partner_keys`` (FEAT-105, G8).

    Partner keys have no owner, so every verb is superuser-only and
    policy-gated. ``token`` holds a plaintext signed JWT and is returned
    **once**, in the creation response, and never on a read or an update.

    This handler sits on the LOCAL ``handlers/model.py`` base, which has no
    ``_pre_*`` and no ``_filter_*`` hooks — so the guard is invoked at the
    top of each verb below, not through a pre-hook.
    """

    model: Any = PartnerKey                     # verified: partners.py:15
    name: str = "Partner Key Authentication"
    pk: list[str] = ["partner_id"]              # NOTE: a list, not a str

    #: No owner column exists on PartnerKey -> the superuser path is the only
    #: path, for every verb (spec G8).
    owner_column: Optional[str] = None
    credential_columns = frozenset({"token"})
    public_columns = frozenset({
        "partner_id", "name", "partner", "issuer", "created_at", "revoked",
        "enabled", "grants", "programs"})
    policy_name: str = "partner_keys_admin_access"
    superuser_actions = frozenset({
        "partner:read", "partner:create", "partner:revoke", "partner:delete"})
```

`Optional` must be imported — `partners.py:1` currently imports only
`typing.Any`. `# FILL IN: extend that import to
`from typing import Any, Optional`.`

**Why `pk` stays a `list`.** `partners.py:42` declares
`pk: list[str] = ["partner_id"]` and the local base branches on
`isinstance(self.pk, list)` in `get()` (`model.py:175-187`), `patch()`
(`:307-319`), `post()` (`:367-379`) and `delete()` (`:466-478`), splitting
`params["id"]` on `/`. Changing it to a `str` would be a behaviour change
outside this feature's scope — and `__init__` may overwrite it anyway from
`Meta.pk` (`model.py:32-33`). Leave it, and keep spec §4's
`test_partner_pk_is_list`.

**Block 3 — the guarded verbs and the redaction:**

```python
# AFTER — append inside `class PartnerKeyHandler`, below `_get_token`
# anchor: the `) from exc` line that ends _get_token's final raise
# occurrences: FILL IN — verify with
#   grep -cF ') from exc' navigator_auth/handlers/partners.py
# (there are two `from exc` raises in _get_token, at :57 and :68) ->
# disambiguate by quoting the `raise RuntimeError(` / f-string / `) from exc`
# trio of the SECOND one.

    async def _require_superuser(self, action: str) -> None:
        """Refuse unless the caller is a policy-approved superuser.

        ``owner_column`` is ``None``, so :meth:`authorize_row` can never take
        its owner branch and the superuser path is the only path
        (TASK-122). Pass ``owner_id=None``: there is no owner to compare
        against.

        Args:
            action: One of ``superuser_actions``.

        Raises:
            web.HTTPForbidden: not a superuser, or the policy denied.
            web.HTTPUnauthorized: no session.
        """
        # FILL IN: await self.authorize_row(action, None). Nothing else —
        # authorize_row already audits and already fails closed. Bounded by
        # AC-1, AC-2, AC-3.

    def _redact(self, result):
        """Project a result onto ``public_columns`` (drops ``token``)."""
        # FILL IN: return redact_rows(result, self.public_columns) —
        # shape-preserving (TASK-118 AC-5). Bounded by AC-5.

    async def head(self):
        """Superuser-only; ``X-Columns`` must not enumerate ``token``.

        The local base builds the header from the full model schema
        (navigator_auth/handlers/model.py:127-141).
        """
        # FILL IN: await self._require_superuser("partner:read"), then build
        # the response from the redacted schema (or call super() and rewrite
        # the X-Columns header). Bounded by AC-1, AC-10.

    async def get(self):
        """Superuser-only read; ``token`` never returned.

        Handles ``:meta`` before delegating, because the local base serves it
        from the raw model schema (model.py:149-152) and bypasses
        ``_post_get`` entirely.
        """
        # FILL IN:
        #  1. await self._require_superuser("partner:read")
        #  2. intercept :meta here: build
        #     redact_schema(self.model.schema(as_dict=True),
        #     self.credential_columns) and return it. Do NOT mutate the
        #     schema — it is the model's cached dict.
        #  3. otherwise return await super().get(); _post_get (below) redacts
        #     the rows. Bounded by AC-1, AC-4, AC-9.

    async def _post_get(self, result: Any, fields: list[str] = None):
        """Redact ``token`` out of every read.

        The local base's single read-response hook
        (navigator_auth/handlers/model.py:88-110); it is called on both the
        primary-key path (:210) and the list path (:219).
        """
        # FILL IN: fields = safe_fields(fields, self.public_columns); then
        # return await super()._post_get(self._redact(result), fields=fields).
        # Note super() reads columns with getattr (model.py:102,109) and the
        # redacted rows are dicts — FILL IN: verify which shape super()
        # tolerates and either pre-apply `fields` yourself or pass None.
        # Bounded by AC-4, AC-5, AC-6.

    async def put(self):
        """Superuser-only create; the 201 carries ``token`` ONCE."""
        # FILL IN: await self._require_superuser("partner:create"), then
        # return await super().put() UNREDACTED — this is the one response
        # that may carry the token (model.py:257). Bounded by AC-1, AC-7.

    async def patch(self):
        """Superuser-only update; ``token`` never echoed.

        The local base serves a SECOND ``:meta`` here, returning
        ``self.model.__fields__`` (model.py:290-293) — a different payload
        from ``get()``'s schema, and it names ``token`` too.
        """
        # FILL IN:
        #  1. await self._require_superuser("partner:revoke")
        #  2. intercept the :meta branch and return the field set minus
        #     credential_columns.
        #  3. otherwise delegate and redact the 202 body.
        # Bounded by AC-1, AC-8, AC-9.

    async def post(self):
        """Superuser-only upsert: 201 WITH token when it creates, 202 without.

        ``post()`` branches at runtime: insert -> 201 (model.py:399, :425),
        update -> 202 (:417). The action and the redaction both depend on
        which branch ran, which is only knowable from the status of the
        response super() returns.
        """
        # FILL IN:
        #  - authorize for BOTH possibilities before delegating: this verb may
        #    create or update, so require "partner:create" (the wider of the
        #    two) — FILL IN: decide whether to require both partner:create and
        #    partner:revoke, bounded by AC-7/AC-8, and say why in the
        #    Completion Note.
        #  - response = await super().post()
        #  - leave a 201 body untouched (it created); redact a 202 body (it
        #    updated). Read response.status to tell them apart.
        # Bounded by AC-1, AC-7, AC-8.

    async def delete(self):
        """Superuser-only delete, audited; response carries no ``token``."""
        # FILL IN: await self._require_superuser("partner:delete"), delegate,
        # then redact the 202 body (model.py:493 returns whatever
        # result.delete() produced). Bounded by AC-1, AC-11.
```

**Why `_require_superuser` delegates to `authorize_row` instead of calling
`acting_user()` and checking the flag.** The flag alone is spec §6's
rejected option: `decorators.is_superuser` and
`client_access._require_superuser` "consult no policy", so they cannot
satisfy G2's policy-governed admin path. Going through `authorize_row` also
gets the fail-closed policy check and the audit record for free, and keeps
all three surfaces on one decision function.

**Why `owner_id=None` is passed rather than the partner id.**
`authorize_row`'s `owner_id` means *the user who owns this row*. A partner id
is not a user id; passing it would make the owner comparison accidentally
meaningful the day someone's `user_id` equals a partner id. `owner_column is
None` already forces the superuser branch — pass `None` and let it.

**Why the guard is the first statement of each verb and not a decorator.**
`@service_auth` and the `_pre_*` hooks do not exist on this base. A decorator
would work but would hide the one fact a reader of this file most needs: that
on this base nothing else is checking. An explicit first line in each verb is
auditable by reading the class.

**Why `get()` intercepts `:meta` rather than relying on `_post_get`.** The
local base returns the `:meta` response at `model.py:152`, before `_get_data`
and before `_post_get` — so a redaction that lives only in `_post_get` leaves
`GET /api/v1/partner/tokens:meta` naming `token` to any superuser, and the
whole surface's column list to anyone the guard lets through. Same reason
`patch()` has to intercept its own, differently-shaped `:meta`.

**Why `put()`'s response is deliberately **not** redacted.** It is the single
exception in the whole feature: the token has to reach the operator once. Mark
it clearly, and make sure `post()`'s create branch is the only other place
that can do it — those two, and nothing else (AC-7).

**Why `post()` needs the response status to decide.** The local base chooses
insert or update after reading the row (`model.py:385-417`), so the handler
cannot know in advance. Branching on `response.status` after `super().post()`
is the only honest way to apply "token on create, not on update" — and the
alternative (always redacting `post`) would silently break partner creation
through that verb.

**Why there is no `_filtering` override here.** The local base reads no
`_filter` query parameter at all (verified: the string `_filter` does not
appear in `navigator_auth/handlers/model.py`). Spec G7 is about the
`ModelView`-based surfaces. Adding a filter would be new functionality.

### `tests/unit/handlers/test_partner_key_handler_access.py` — CREATE

```python
"""PartnerKeyHandler is superuser-only and returns `token` once (FEAT-105).

Spec §4's Module-6 rows. This handler sits on the LOCAL handlers/model.py
base, which has no _pre_* hooks — so these tests drive the VERBS, not hooks.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.handlers.partners import PartnerKey, PartnerKeyHandler

pytestmark = pytest.mark.filterwarnings(
    "ignore::aiohttp.web_exceptions.NotAppKeyWarning"
)

SENTINEL_JWT = "eyJhbGciOiJIUzI1NiJ9.SENTINEL.signature"
PUBLIC = frozenset({
    "partner_id", "name", "partner", "issuer", "created_at", "revoked",
    "enabled", "grants", "programs",
})


class FakeSession(dict):
    def decode(self, key):
        return self.get(key)


def _session(user_id=7, groups=("users",)):
    # FILL IN: as TASK-123's helper.

def _patch_sessions(session):
    # FILL IN: patch navigator_auth.decorators.get_session AND
    # navigator_auth.handlers.guards.get_session.

def _handler(method="GET", path="/api/v1/partner/tokens/abc", match_info=None,
             pdp=None):
    # FILL IN: build the app dict, the mocked request, then the handler. The
    # local base's __init__ (navigator_auth/handlers/model.py:27-34) touches
    # self.model.Meta — construct normally if that works, else via __new__.

def _partner_row(token=SENTINEL_JWT):
    # FILL IN: a PartnerKey double (or instance) carrying the sentinel token
    # plus every public column.

def _permissive_pdp():
    # FILL IN: a PDP whose partner_keys_admin_access policy allows all four
    # partner:* actions — mirror tests/test_check_access.py's FakePDP.


class TestConfiguration:
    def test_guard_precedes_the_base_in_the_mro(self):
        # FILL IN — AC-12
    def test_owner_column_is_none(self):
        """No owner exists, so the superuser path is the only path."""
        # FILL IN: assert PartnerKeyHandler.owner_column is None — AC-12
    def test_public_columns_is_every_column_but_token(self):
        # FILL IN: assert set(PartnerKey.get_columns()) - PUBLIC == {"token"}
        # — this catches both a typo in the allowlist and a new column added
        # to the model without a decision. Bounded by AC-13.
    def test_policy_name_and_four_actions_match_the_pack(self):
        # FILL IN — AC-14
    def test_partner_pk_is_list(self):
        """The list-shaped pk still resolves (guards the pk quirk)."""
        # FILL IN: assert isinstance(PartnerKeyHandler.pk, list) and drive a
        # PK GET so the list branch at model.py:175-187 executes — AC-15
    def test_token_column_flags_unchanged(self):
        """PartnerKey.token still has no secret=True / repr=False."""
        # FILL IN: spec §3 Module 6 forbids depending on them; this test
        # states that the protection does not come from there — AC-16


class TestSuperuserOnly:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("verb", ["get", "put", "patch", "post", "delete", "head"])
    async def test_every_verb_refuses_a_non_superuser(self, verb):
        """403 for a plain authenticated user, on every verb."""
        # FILL IN: assert web.HTTPForbidden — bounded by AC-1.

    @pytest.mark.asyncio
    async def test_unauthenticated_is_401(self):
        # FILL IN — AC-2
    @pytest.mark.asyncio
    async def test_superuser_denied_without_pdp(self):
        """Fail-closed: no ABAC => no access, even for a superuser."""
        # FILL IN: there is no owner path here, so this surface is fully
        # closed without a policy — AC-3.
    @pytest.mark.asyncio
    async def test_superuser_denied_when_policy_raises(self):
        # FILL IN — AC-3
    @pytest.mark.asyncio
    async def test_each_verb_is_audited(self):
        # FILL IN: one AuditLog record per allowed verb — AC-11


class TestTokenRedaction:
    @pytest.mark.asyncio
    async def test_get_single_row_has_no_token(self):
        # FILL IN: assert SENTINEL_JWT absent from the body — AC-4
    @pytest.mark.asyncio
    async def test_get_list_has_no_token(self):
        # FILL IN — AC-5
    @pytest.mark.asyncio
    async def test_fields_param_cannot_project_the_token(self):
        """?fields=token,name returns name only."""
        # FILL IN — AC-6
    @pytest.mark.asyncio
    async def test_get_meta_has_no_token(self):
        """GET :meta returns the schema minus token."""
        # FILL IN — AC-9
    @pytest.mark.asyncio
    async def test_patch_meta_has_no_token(self):
        """PATCH :meta returns __fields__ minus token — a DIFFERENT payload."""
        # FILL IN: the local base serves this from self.model.__fields__
        # (model.py:290-293), not from the schema. Bounded by AC-9.
    @pytest.mark.asyncio
    async def test_meta_does_not_mutate_the_cached_schema(self):
        """PartnerKey.schema(as_dict=True) still lists token afterwards."""
        # FILL IN: the payload is the model's memoized dict — AC-9
    @pytest.mark.asyncio
    async def test_head_x_columns_has_no_token(self):
        # FILL IN — AC-10
    @pytest.mark.asyncio
    async def test_delete_response_has_no_token(self):
        # FILL IN — AC-11
    @pytest.mark.asyncio
    async def test_sentinel_appears_nowhere_in_any_read_body(self):
        """Serialize and scan every read response for the sentinel."""
        # FILL IN: loop over get/list/:meta/head/patch/delete and assert
        # SENTINEL_JWT is absent from each serialized body. This is the test
        # that catches a leak through a nested structure such as `grants`,
        # which the per-key assertions above would miss. Bounded by AC-4.


class TestReturnOnceToken:
    @pytest.mark.asyncio
    async def test_put_create_returns_the_token(self):
        """PUT => 201 WITH token — the one permitted exposure."""
        # FILL IN: assert status 201 and SENTINEL_JWT present — AC-7
    @pytest.mark.asyncio
    async def test_post_that_creates_returns_the_token(self):
        """POST's insert branch => 201 WITH token (model.py:399, :425)."""
        # FILL IN — AC-7
    @pytest.mark.asyncio
    async def test_post_that_updates_does_not_echo_the_token(self):
        """POST's update branch => 202 WITHOUT token (model.py:417)."""
        # FILL IN: the two POST branches are chosen at runtime; make super()
        # return each status in turn — bounded by AC-8.
    @pytest.mark.asyncio
    async def test_patch_does_not_echo_the_token(self):
        """PATCH => 202 WITHOUT token, although _get_token re-minted one."""
        # FILL IN: _get_token runs on every write (model.py:75-81), so the
        # row handed to the response DOES carry a fresh JWT — the redaction
        # is what removes it. Bounded by AC-8.
    @pytest.mark.asyncio
    async def test_created_token_is_not_readable_afterwards(self):
        """Create, then GET the same row: the token is gone."""
        # FILL IN: assert the 201 contained it and the subsequent GET does
        # not — this is the whole "return once" claim in one test. AC-7, AC-4.
```

**Why `test_every_verb_refuses_a_non_superuser` is parametrized over all six
verbs.** The guard is invoked by hand at the top of each verb on this base.
There is no shared pre-hook to get right once, so the most likely defect is
*one* verb left unguarded — and a test that only exercises `get` would never
see it.

**Why `test_token_column_flags_unchanged` exists.** Spec §3 Module 6 says the
guard must not depend on `repr=False` / `secret=True`, and a later reader may
"harden" the model by adding them. That is fine in itself, but if the
protection ever *comes* from there, this feature's guarantee has quietly
moved into a model the operator can swap. The test states where the
protection lives.

**Why `test_sentinel_appears_nowhere_in_any_read_body` scans serialized
bodies.** Per-key assertions check the keys we thought of. `PartnerKey.grants`
is a free-form `dict` and `programs` a `list`; a token copied into either
would pass every key-level test. Scan the text.

**Why `test_created_token_is_not_readable_afterwards` is the headline test.**
"Returned exactly once" is a property of a *sequence* of requests, not of one
response. Each half can pass alone while the property fails.

### Steps (in order)

1. Confirm the dependency: `from navigator_auth.handlers.guards import
   OwnerOrSuperuserGuard` must import (TASK-122). Also confirm
   `handlers/redaction.py` exists (TASK-118, a TASK-122 dependency).
2. **Read `navigator_auth/handlers/model.py` in full** before writing
   anything. This base is nothing like `ModelView`, and the contract table
   above is a summary, not a substitute.
3. Apply Block 1 (imports — remember `Optional`) and Block 2 (class +
   configuration). Verify the MRO and `owner_column is None`.
4. Apply Block 3. Fill `_require_superuser` and `_redact` first, then guard
   the six verbs **one at a time**, running
   `TestSuperuserOnly::test_every_verb_refuses_a_non_superuser` after each so
   you can see the parametrized case flip from fail to pass.
5. Then do the redaction: `_post_get`, `get`'s `:meta`, `patch`'s `:meta`,
   `head`, `delete`, and finally `post`'s status branch.
6. Create the test module; fill the five helpers first.
7. Run `pytest tests/unit/handlers/test_partner_key_handler_access.py -v`,
   then `pytest tests/unit/handlers -v`, then the regression gate
   `pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q`.
8. `ruff check navigator_auth/handlers/partners.py tests/unit/handlers/`.
9. Confirm the blast radius: `git diff --name-only` lists only
   `navigator_auth/handlers/partners.py` and the new test file. `PartnerKey`'s
   column definitions and `_get_token` must be unchanged (AC-16, AC-17).

### FILL IN checklist

- [ ] `from typing import Any, Optional` — `Optional` is not imported today
- [ ] Block 3 anchor — two `) from exc` lines exist in `_get_token`; disambiguate
- [ ] `_require_superuser` — delegate to `authorize_row(action, None)` — AC-1, AC-2, AC-3
- [ ] `_redact` — `redact_rows`, shape-preserving — AC-5
- [ ] `head` — guard + redacted `X-Columns` — AC-1, AC-10
- [ ] `get` — guard + `:meta` interception + delegate — AC-1, AC-4, AC-9
- [ ] `_post_get` — redact rows; resolve the dict-vs-getattr `fields` question — AC-4, AC-5, AC-6
- [ ] `put` — guard, delegate, **do not redact** — AC-1, AC-7
- [ ] `patch` — guard + its own `__fields__` `:meta` + redact the 202 — AC-1, AC-8, AC-9
- [ ] `post` — guard (decide the action set and say why) + status-based redaction — AC-1, AC-7, AC-8
- [ ] `delete` — guard + redact — AC-1, AC-11
- [ ] test helpers `_session` / `_patch_sessions` / `_handler` / `_partner_row` / `_permissive_pdp`
- [ ] `TestConfiguration` — 6 bodies — AC-12..AC-16
- [ ] `TestSuperuserOnly` — 5 bodies (one parametrized over 6 verbs) — AC-1, AC-2, AC-3, AC-11
- [ ] `TestTokenRedaction` — 9 bodies — AC-4, AC-5, AC-6, AC-9, AC-10, AC-11
- [ ] `TestReturnOnceToken` — 5 bodies — AC-7, AC-8

---

## Acceptance Criteria

- [ ] **AC-1** Every verb — `GET`, `PUT`, `PATCH`, `POST`, `DELETE`, `HEAD` — answers **403** for an authenticated non-superuser.
- [ ] **AC-2** A request with no session answers **401**.
- [ ] **AC-3** With no PDP, with `partner_keys_admin_access` undeclared, or with a policy that raises, **every** verb is denied even for a superuser — this surface has no owner path to fall back on.
- [ ] **AC-4** No read response contains `token` — single row, list, `:meta`, `head` — and the sentinel JWT appears nowhere in any serialized read body.
- [ ] **AC-5** List and scalar response shapes are preserved by the redaction.
- [ ] **AC-6** `?fields=token,name` returns `name` only.
- [ ] **AC-7** `PUT`, and `POST` on its **insert** branch, answer **201 including `token`**; a subsequent `GET` of the same row carries none.
- [ ] **AC-8** `PATCH`, and `POST` on its **update** branch, answer **202 without `token`**, although `_get_token` re-minted one during `_get_data`.
- [ ] **AC-9** `GET :meta` (model schema) and `PATCH :meta` (`__fields__`) both omit `token`, and serving them does not mutate `PartnerKey.schema(as_dict=True)`.
- [ ] **AC-10** `HEAD`'s `X-Columns` header does not name `token`.
- [ ] **AC-11** `DELETE` succeeds for a policy-approved superuser, its response carries no `token`, and each allowed verb produces exactly one `AuditLog` record.
- [ ] **AC-12** `PartnerKeyHandler` inherits `OwnerOrSuperuserGuard` **before** the local `ModelHandler`, and `owner_column is None`.
- [ ] **AC-13** `set(PartnerKey.get_columns()) - public_columns == {"token"}`.
- [ ] **AC-14** `policy_name` and the four `partner:*` actions match TASK-120's policy pack exactly.
- [ ] **AC-15** `pk` is still a `list` and the list-shaped primary-key path resolves.
- [ ] **AC-16** `PartnerKey`'s column definitions are unchanged — `token` still has neither `secret=True` nor `repr=False` — and `_get_token` is unchanged.
- [ ] **AC-17** Nothing outside `navigator_auth/handlers/partners.py` is modified; in particular `navigator_auth/handlers/model.py` is untouched.
- [ ] **AC-18** `pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q` passes and `ruff check navigator_auth/handlers/partners.py tests/unit/handlers/` is clean.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/unit/handlers/test_partner_key_handler_access.py -v
pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q   # regression
ruff check navigator_auth/handlers/partners.py tests/unit/handlers/
```

```python
from navigator_auth.handlers.partners import PartnerKey, PartnerKeyHandler
assert PartnerKeyHandler.owner_column is None
assert set(PartnerKey.get_columns()) - PartnerKeyHandler.public_columns == {"token"}
```

---

## Agent Instructions

1. **Read the spec** at `sdd/specs/user-identities-ownership-abac.spec.md` —
   §1 Problem Statement C, §1 G8, §2 Data Models, §3 Module 6 (including its
   behavioural table), §4 the five `test_partner_*` rows, §7 Patterns to
   Follow.
2. **Read `navigator_auth/handlers/model.py` in full.** This surface's base
   has no `_pre_*` and no `_filter_*` hooks; assuming otherwise is the main
   way to produce a handler that looks guarded and is not.
3. **Check dependencies** — TASK-122 must be in `sdd/tasks/completed/`.
4. **Update status** in `sdd/tasks/index/user-identities-ownership-abac.json`
   → `"in-progress"`.
5. **Implement** per the blueprint. Guard the six verbs one at a time.
6. **Verify** every acceptance criterion, AC-1 (all six verbs), AC-7, AC-8
   and AC-17 included.
7. **Record in the Completion Note**: the `post()` action-set decision, the
   absence of a `?_filter=` path on this base, and the local `delete()`
   not-found status quirk (204 → 400) so it can be filed separately.
8. **Move this file** to `sdd/tasks/completed/TASK-127-partner-key-superuser-only.md`.
9. **Update index** → `"done"`.
10. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback)
**Date**: 2026-10-24
**Notes**: 36 tests pass; ruff clean on partners.py. Decisions: post() requires BOTH partner:create and partner:revoke (it chooses insert/update at runtime; requiring only create would let create-only policies mutate keys). No _filtering added (local base has no _filter). DEVIATION: _post_get does not delegate to super() — local base calls json_response(content=...) which the installed navigator-api 4.0.1 rejects (param is 'response') and its fields branch reads the wrong variable; I used positional json_response(). OBSERVATION (pre-existing, out of scope, local base handlers/model.py): put/patch/post/delete/get-meta there also call json_response(content=...) and will TypeError on 4.0.1; and delete() maps 'not found' to status 204 which error() turns into 400.

**Deviations from spec**: none
