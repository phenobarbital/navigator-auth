# TASK-123: `UserIdentityHandler` — guard configuration and hardened read path

**Feature**: FEAT-105 — Owner-or-Superuser ABAC Ownership for the Auth Model CRUD Surfaces
**Spec**: `sdd/specs/user-identities-ownership-abac.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-122
**Assigned-to**: unassigned

---

## Context

First of three tasks implementing **spec §3 Module 4**. This one wires
`OwnerOrSuperuserGuard` into `UserIdentityHandler`, declares the per-surface
configuration, and closes the **read** path:

| Verb / target | Owner | Superuser (other user) | Other user |
|---|---|---|---|
| `GET` by `identity_id` | row returned | row returned, audited | **404** |
| `GET` list / filter | own rows only (forced `user_id`) | `?user_id=<n>` allowed, audited | own rows only |

(Redaction of those rows is TASK-125; writes are TASK-124.)

`UserIdentityHandler` is the most exposed of the three surfaces: its model
carries the Identity Vault's linked external credential — `access_token`,
`refresh_token`, `id_token` as ciphered `bytes`, plus `provider_user_id`,
`scopes`, `key_version`, the provider profile `auth_data`, and PII (`email`,
`phone`, `nickname`, `short_bio`). Today any authenticated session can
`GET /api/v1/user_identity/<someone-else's-id>` or list the whole table with
`?user_id=<victim>`; the only ownership-ish hook, `_set_user_id`
(`userattrs.py:59`), merely *fills* `user_id` on writes that omit it.

The contrast is deliberate and documented: the purpose-built Identity Vault
handler (`handlers/user_identities.py`) anchors every operation to the
session `user_id` (`:38-59`), and its module docstring says *"Access to other
users' credentials … is out of scope here — compose it via the ABAC layer."*
This task is the start of that composition.

**Why the read path is its own task.** The ownership binding for reads is the
one genuinely hard mechanic in Module 4: upstream fetches the row **after**
`_pre_get` has already returned, so "is this row mine?" cannot be answered in
the pre-hook, and the obvious hook (`_filter_<column>`) has two verified
traps (below). Separating it keeps that decision reviewable on its own and
keeps every blueprint block under the size cap.

> **Environment drift (read this).** Spec §6's upstream `navigator` table was
> recorded against `navigator-api` **3.2.2**; `.venv` has **4.0.1**, which
> already contains the §2 Prerequisite fix. Every upstream anchor below was
> **re-verified against 4.0.1**; where it contradicts the spec, the spec is
> stale and this task is right. The local hardening is unchanged — spec §2
> explains why it must not depend on the upstream version, and §6 records the
> decisive fact: upstream derives `_hidden` from `secret=True`, which **no**
> credential column on `UserIdentity` declares.

---

## Scope

- Make `UserIdentityHandler` inherit `OwnerOrSuperuserGuard` **before**
  `ModelHandler` and declare the five guard attributes plus
  `readonly_columns` and the per-subclass `_hidden` / `_required` /
  `_primaries` lists.
- Add a shared `_require_owner_column()` gate answering **501** when the
  configured model has no owner column.
- Harden the read path: ownership injection for both the primary-key and the
  list/query paths, `?user_id=` sanitation, and **404** (not 204, not 403) for
  a foreign or missing row fetched by primary key.
- Keep the existing `_set_user_id` exactly as it is.
- Add `tests/unit/handlers/test_user_identity_handler_access.py` covering the
  read-path rows of spec §4.

**NOT in scope**:
- `_pre_put` / `_pre_patch` / `_pre_post` / `_pre_delete`, the
  `readonly_columns` **write refusal**, and the superuser revoke-only
  constraint — **TASK-124**. Declare `readonly_columns` here (it is
  configuration); enforce it there.
- `_model_response`, the `masked()`-shape projection, `_get_meta_info` /
  `:meta` redaction and `_filtering` → `safe_filter` — **TASK-125**. This
  task's tests must therefore **not** assert anything about response
  *contents* beyond which rows come back.
- `UserAccountHandler` (TASK-126) and `PartnerKeyHandler` (TASK-127), even
  though `UserAccountHandler` is in the same file. Touch only the
  `UserIdentityHandler` class body — plus the module's import line.
- `social_network` / `_set_address` — TASK-121.
- Changing `handlers/handler.py`, `handlers/model.py`, `guards.py`,
  `redaction.py` or `decorators.py`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/userattrs.py` | MODIFY | Import the guard; rewrite the `UserIdentityHandler` class body |
| `tests/unit/handlers/test_user_identity_handler_access.py` | CREATE | Read-path access tests |

---

## Codebase Contract

> Re-verified on `dev` @ `62fd419` against installed `navigator-api` **4.0.1**
> (2026-10-23).

### `UserIdentityHandler` today (verified: `navigator_auth/handlers/userattrs.py:53-60`)

```python
class UserIdentityHandler(ModelHandler):
    model: Any = UserIdentity
    model_name: str = AUTH_USER_IDENTITY_MODEL
    name: str = "User Identity"
    pk: str = "identity_id"

    async def _set_user_id(self, value, column, data):
        return await self.get_userid(session=self._session)
```

Module imports already present (`userattrs.py:1-17`): `typing.Any`,
`asyncdb.exceptions.NoDataFound`, `asyncdb.exceptions.DriverError`,
`navigator_session.get_session`, `navigator_session.AUTH_SESSION_OBJECT`,
`..models.{UserAccount, UserIdentity, VwUserIdentity}`,
`..conf.AUTH_USER_IDENTITY_MODEL`, `.handler.ModelHandler`.

`ModelHandler` here is the **navigator-based** one
(`navigator_auth/handlers/handler.py:4`, `class ModelHandler(ModelView)`,
`dbname = 'authdb'`).

### `UserIdentity` — the model (verified: `navigator_auth/models.py:77-110`)

PK `identity_id: UUID` (`primary_key=True`, `repr=False`). Owner
`user_id: User = Column(required=True, fk="user_id|username", api="users", label="User")`.
Credential columns `access_token / refresh_token / id_token: Optional[bytes]`,
plus `token_type`, `expires_at`, `refreshed_at`, `key_version`,
`provider_user_id`, `scopes`. PII `display_name`, `title`, `nickname`,
`email`, `phone`, `short_bio`, `avatar`. Plus `auth_provider`, `auth_data`,
`attributes`, `enabled`, `created_at`.
`Meta.name = "user_identities"`, `Meta.schema = AUTH_DB_SCHEMA`,
`Meta.strict = True`.

**None of the credential columns declares `secret=True`** — they are
`repr=False` only. This is why upstream redaction does not apply (see below)
and why TASK-125's allowlist is the only thing that hides them.

### `AUTH_USER_IDENTITY_MODEL` can swap the model

Verified `navigator_auth/conf.py:150`:

```python
AUTH_USER_IDENTITY_MODEL = config.get("AUTH_USER_IDENTITY_MODEL", fallback=None)
```

`ModelView.__init__` honours it, so the runtime model may be something other
than `UserIdentity` and may lack a `user_id` column. Spec §3 Module 4: when
it does, *"ownership cannot be established and every verb answers 501."*

### CRITICAL — `_pre_*` hooks run BEFORE anything is fetched or parsed

Verified `.venv/.../navigator/views/model.py:552-564`:

```python
    @service_auth
    async def get(self):
        """GET Model information."""
        if not await self._pre_get():
            return self.error(
                response={
                    "message": f"{self.__name__} Error on Pre-Validation"
                },
                status=412
            )
        args, meta, qp, fields = self.get_parameters()
        response = await self._get_meta_info(meta, fields)
        if response is not None:
            return response
        try:
            # Add Filtering
            response = await self._filtering(qp)
            if response is not None:
                return response
            data = await self._get_data(qp, args)
            return await self._model_response(data, fields=fields)
```

Same shape for the other verbs — `_pre_patch` at `:800`, `_pre_put` at
`:1015`, `_pre_post` at `:1170`, `_pre_delete` at `:1508`, each the first
statement in the method, before `get_parameters()`.

Two consequences this task must live with:

1. A `_pre_*` hook **cannot** know the target row's owner. It can read
   `self.request` (so: the session, the path, the raw query string), and
   nothing else. Row-level ownership must be enforced further down.
2. Returning a falsy value from a `_pre_*` hook yields a fixed **412**. Use
   `self.error(..., status=…)`, which **raises** (verified:
   `.venv/.../navigator/views/base.py:201-243`) and so delivers 401/403/404/501
   with the right status. The guard's `authorize_row` relies on exactly this.

### CRITICAL — the two traps in the `_filter_<column>` hook

Spec §3 Module 4 names `_filter_user_id` as the ownership mechanism. Verified
against 4.0.1, that hook alone **cannot** express the superuser case:

```python
        async def _get_filters():                 # model.py:395
            value = {}
            for name, column in self.model.get_columns().items():
                fn = getattr(self, f'_filter_{name}', None)
                if fn:
                    ...
                    try:
                        value[name] = await fn(value=val, column=column, data=value)
                    except NotSet:
                        return                    # model.py:413-414  -> returns None
            return value
        _filter = await _get_filters()            # model.py:415
```

- **Trap 1 — `NotSet` poisons the whole filter.** `except NotSet: return`
  returns `None` from `_get_filters`, and every consumer then does
  `**_filter` (`model.py:424`, `:446`, `:455`) — `**None` raises `TypeError`,
  which `_get_data` wraps as `ModelError` (`:468-471`) and `get()` answers as
  **400** (`:577-583`). So a hook cannot opt out by raising `NotSet`.
- **Trap 2 — the hook's return value is always stored.** There is no "leave
  this column unfiltered" return. Returning `None` lands
  `user_id: None` in `_filter`, i.e. `WHERE user_id IS NULL`.

Where `_filter` is applied (verified, both paths):

```python
                if _primary is not None:
                    ...
                        elif isinstance(self.pk, str):
                            args = {self.pk: _primary}       # model.py:437
                        ...
                        args = {**_filter, **args}           # model.py:443
                        return await self.get_model.get(**args)
                elif len(qp) > 0:
                    print("FILTER")
                    query = await self.get_model.filter(**qp, **_filter)   # model.py:446
```

Good news: `_filter` **is** merged into the primary-key path (`:443`), so a
forced owner predicate makes a foreign row invisible by PK as well as in
lists. Bad news: `filter(**qp, **_filter)` (`:446`) raises `TypeError` on a
duplicate key, so a surviving `?user_id=` in `qp` collides with a forced
`_filter['user_id']` — which is why the guard's `sanitize_query` drops or
refuses that parameter *before* the DB (TASK-122 AC-14/AC-15).

**Therefore: implement the ownership injection in an overridden
`_get_data(qp, args)`**, which sees both paths and can branch on
superuser-ness, and do **not** define `_filter_user_id`. This is a
**deviation from spec §3 Module 4's named method**, forced by the two traps
above; record it in the Completion Note. (If you find a working
`_filter_user_id` shape that handles the superuser case without `NotSet` and
without the collision, that is acceptable too — the AC are written about
behaviour, not about which hook you used.)

### What a foreign row by primary key answers today — and why 404 needs work

With the owner predicate merged at `model.py:443`, `get(**args)` finds
nothing, `_get_data` raises `NoDataFound`, and `get()` catches it at
`.venv/.../navigator/views/model.py:587-592`:

```python
        except NoDataFound:
            headers = {
                "X-STATUS": "EMPTY",
                "X-MESSAGE": f"Data on {self.__name__} not Found",
            }
            return self.no_content(headers=headers)
```

That is **204 No Content**, not 404. Spec §3 Module 4's table and §5
criterion 4 require **404** on the primary-key path. So the handler must
shape it — see the blueprint's `_pre_get` / `_get_data` note (AC-7).

### Upstream metadata lists in 4.0.1 — why the per-subclass declaration stays

Verified `.venv/.../navigator/views/model.py:77-79` (class attributes) and
`:141,:145-182`:

```python
        if '_primaries' not in self.__dict__:
            self._init_column_metadata()
        ...
            if metadata.get('secret') is True:
                hidden.append(name)
        self._required = list(self._required) or required
        self._primaries = list(self._primaries) or primaries
        self._hidden = list(self._hidden) or hidden
```

4.0.1 already stores them **per instance** and already derives `_hidden` from
`secret=True`. So the cross-contamination the spec warns about is fixed
upstream — but spec §2 is explicit that this feature must be correct on older
navigators too (`pyproject.toml:53` pins `navigator-api>=0.5.0`). Declaring
`_hidden: list = []` / `_required: list = []` / `_primaries: list = []` on the
subclass is **harmless on 4.0.1** (an empty list is falsy, so the `or`
branches still derive from the model, and a class attribute does not appear
in `self.__dict__`, so `_init_column_metadata` still runs) and protective on
3.2.2. Declare them, and keep spec §4's `test_hidden_lists_are_per_subclass`.

### Session / acting-user helpers available

| Helper | Location | Note |
|---|---|---|
| `OwnerOrSuperuserGuard.acting_user()` | `handlers/guards.py` (TASK-122) | `(user_id, is_superuser)`; 401 when absent |
| `OwnerOrSuperuserGuard.authorize_row()` | TASK-122 | returns `True`, **raises** on deny |
| `OwnerOrSuperuserGuard.sanitize_query()` | TASK-122 | `(qp, fields)` sanitized; refuses a foreign owner param |
| `AbstractModel.get_userid(session, idx='user_id')` | `.venv/.../navigator/views/abstract.py:310` | pre-existing; `_set_user_id` uses it — leave that call as is |
| `AbstractModel.get_parameters()` | `.venv/.../navigator/views/abstract.py:434` | returns `[args, meta, qp, fields]`, `fields` popped out of `qp` |
| `self.query_parameters(self.request)` | `.venv/.../navigator/views/base.py` | the raw query dict, usable from a `_pre_*` hook |

### The guard configuration for this surface (spec §2 Data Models)

| Attribute | Value |
|---|---|
| `owner_column` | `"user_id"` |
| `credential_columns` | `access_token`, `refresh_token`, `id_token`, `key_version` |
| `public_columns` | `identity_id`, `user_id`, `display_name`, `title`, `nickname`, `email`, `phone`, `short_bio`, `avatar`, `auth_provider`, `provider_user_id`, `scopes`, `token_type`, `expires_at`, `refreshed_at`, `created_at`, `enabled`, `auth_data`, `attributes` |
| `policy_name` | `"user_identities_admin_access"` |
| `superuser_actions` | `identity:read`, `identity:revoke`, `identity:delete` |
| `readonly_columns` | `access_token`, `refresh_token`, `id_token`, `key_version`, `provider_user_id`, `token_type`, `expires_at`, `refreshed_at`, `scopes` |

Every name verified against `navigator_auth/models.py:77-110`. The policy
name must match TASK-120's pack exactly.

### Existing handler-test pattern (verified: `tests/unit/identity/test_identity_handlers.py:1-67`)

```python
class FakeSession(dict):
    """Session double supporting decode()/get()/mapping access."""

    def decode(self, key):
        return self.get(key)


def _request(method, path, app_map=None, match_info=None, user=None):
    app = {"auth": MagicMock(), "authdb": MagicMock(), "redis": MagicMock()}
    if app_map:
        app.update(app_map)
    request = make_mocked_request(method, path, app=app)
    if match_info:
        request.match_info.update(match_info)
    return request
```

and the session is patched in **both** places (`:35-46`):

```python
    return (
        patch("navigator_auth.decorators.get_session",
              new=AsyncMock(return_value=session)),
        patch("navigator_auth.handlers.user_identities.get_session",
              new=AsyncMock(return_value=session)),
    )
```

For this task the second patch target is
`navigator_auth.handlers.guards.get_session` (the guard reads the session
itself — TASK-122).

### Does NOT Exist (do not reference)

- `_filter_user_id` on `UserIdentityHandler` today — only `_set_user_id`
  exists (`userattrs.py:59`). And see the two traps above before adding it.
- `_pre_get` / `_pre_put` / `_pre_patch` / `_pre_post` / `_pre_delete` on
  `UserIdentityHandler` today — all five are inherited no-ops returning
  `True` (`.venv/.../navigator/views/abstract.py:553-571`).
- `VwUserIdentity` as a read model here. It is imported in `userattrs.py:11`
  but **unused** by either handler; it is a credential-free view
  (`navigator_auth/models.py:119`). Switching reads to it is **not** this
  feature's design (spec §2 chooses an explicit allowlist over a second
  model) — do not do it, and do not remove the unused import either (that is
  unrelated churn).
- A `superuser` column on `UserIdentity`. The `superuser` at
  `navigator_auth/identities.py:235` belongs to the auth **user** object.
- `ResourceType.IDENTITY` — not in the enum
  (`abac/policies/resources.py:15-30`); the guard passes
  `resource=self.request.path` and lets `policy_allows` default the type to
  `URI` (`decorators.py:1136-1139`).
- `self._session` as a dependable attribute inside a `_pre_*` hook. It is set
  by `@service_auth` (`model.py:106-117`) which runs **outside** the verb, so
  it is populated for the verb body — but the guard must not rely on it
  (TASK-122 reads the session itself). `_set_user_id`'s existing
  `self._session` use is pre-existing and stays.
- `tests/unit/handlers/test_user_account_handler_access.py` /
  `test_partner_key_handler_access.py` — TASK-126 / TASK-127 own those.

---

## Implementation Blueprint

### `navigator_auth/handlers/userattrs.py` — MODIFY (three blocks)

**Block 1 — the import:**

```python
# AFTER — insert below `from .handler import ModelHandler`
# anchor (verified: navigator_auth/handlers/userattrs.py:17)
# occurrences: 1 (verified: grep -cF 'from .handler import ModelHandler' navigator_auth/handlers/userattrs.py)
from .handler import ModelHandler
from .guards import OwnerOrSuperuserGuard
```

**Block 2 — the class declaration and configuration:**

```python
# AFTER — replace the `class UserIdentityHandler(ModelHandler):` line and the
# four attribute lines beneath it
# anchor (verified: navigator_auth/handlers/userattrs.py:53-57)
# occurrences: 1 (verified: grep -cF 'class UserIdentityHandler(ModelHandler):' navigator_auth/handlers/userattrs.py)
# NOTE: do NOT anchor on `async def _set_user_id(self, value, column, data):`
# — occurrences: 2 (verified: grep -cF on that line), one per handler in this
# file. Anchor on the class line.

class UserIdentityHandler(OwnerOrSuperuserGuard, ModelHandler):
    """Owner-or-superuser CRUD over ``auth.user_identities`` (FEAT-105).

    The guard mixin comes first in the MRO so its hooks win over
    ``ModelView``'s. Credential material is never serialized: see
    ``credential_columns`` and the redaction in ``_model_response``.
    """

    model: Any = UserIdentity                   # verified: navigator_auth/models.py:77
    model_name: str = AUTH_USER_IDENTITY_MODEL  # verified: navigator_auth/conf.py:150
    name: str = "User Identity"
    pk: str = "identity_id"

    owner_column: str = "user_id"
    credential_columns = frozenset({
        "access_token", "refresh_token", "id_token", "key_version"})
    public_columns = frozenset({
        "identity_id", "user_id", "display_name", "title", "nickname",
        "email", "phone", "short_bio", "avatar", "auth_provider",
        "provider_user_id", "scopes", "token_type", "expires_at",
        "refreshed_at", "created_at", "enabled", "auth_data", "attributes"})
    policy_name: str = "user_identities_admin_access"
    superuser_actions = frozenset({
        "identity:read", "identity:revoke", "identity:delete"})

    #: Vault-managed columns: never writable through the model surface. The
    #: only legitimate writer is IdentityStore.update_tokens
    #: (verified: navigator_auth/identity/store.py:409). Enforced in TASK-124.
    readonly_columns = frozenset({
        "access_token", "refresh_token", "id_token", "key_version",
        "provider_user_id", "token_type", "expires_at", "refreshed_at",
        "scopes"})

    # Per-subclass copies. Harmless on navigator-api 4.0.1 (which already
    # keeps them per instance and derives _hidden from secret=True:
    # navigator/views/model.py:141,178-182) and protective on 3.2.2, where
    # ModelView mutated these CLASS-level lists in place and contaminated
    # every sibling handler. pyproject.toml:53 pins navigator-api>=0.5.0, so
    # both are in scope. Never RELY on _hidden: no credential column on
    # UserIdentity declares secret=True.
    _hidden: list = []
    _required: list = []
    _primaries: list = []

    async def _set_user_id(self, value, column, data):   # existing, unchanged
        return await self.get_userid(session=self._session)
```

**Why the mixin goes first in the MRO.** Python resolves left to right, so
`OwnerOrSuperuserGuard` must precede `ModelHandler` for any method it defines
to win. Putting it second would silently give you the upstream behaviour with
a guard object attached — the worst failure mode, because it looks wired.

**Why `readonly_columns` is declared here but enforced in TASK-124.** It is
configuration, and configuration belongs with the other class attributes so
the surface is described in one place. Splitting the *declaration* across two
tasks would mean TASK-124 editing this block again. The write refusal that
reads it is genuinely TASK-124's.

**Why `public_columns` keeps `auth_data`.** Resolved in spec §8 Q6: the admin
view keeps `profile`, matching `IdentityStore.masked()` today, so the two
identity surfaces cannot drift by role. The PII exposure is accepted
knowingly.

**Why `provider_user_id` and `scopes` are in *both* `public_columns` and
`readonly_columns`.** They are readable metadata and unwritable vault state.
The two sets answer different questions — what may be serialized, and what
may be written — and a column can legitimately be in both.

**Block 3 — the owner-column gate and the hardened read path:**

```python
# AFTER — append inside `class UserIdentityHandler`, below `_set_user_id`
# anchor: the `return await self.get_userid(session=self._session)` line that
# ends _set_user_id INSIDE UserIdentityHandler
# occurrences: 2 for that bare line (verified: grep -cF
# 'return await self.get_userid(session=self._session)'
# navigator_auth/handlers/userattrs.py) -> FILL IN: disambiguate by quoting
# the three preceding lines, i.e. the `class UserIdentityHandler(...)` block's
# own `_set_user_id`, not UserAccountHandler's at the top of the file.

    def _require_owner_column(self) -> str:
        """Return the owner column, or refuse the request with 501.

        ``AUTH_USER_IDENTITY_MODEL`` (conf.py:150) can swap the model at
        import time. A model without an owner column cannot be ownership-
        bound at all, and a surface that cannot be bound must not serve —
        spec §3 Module 4.

        Returns:
            The owner column name.

        Raises:
            web.HTTPException: 501, when the configured model has no such
                column.
        """
        # FILL IN: columns = self.get_model.get_columns() (a classmethod:
        # verified datamodel 0.10.21, and used this way at
        # navigator/views/model.py:170 and navigator_auth/handlers/model.py:72).
        # Refuse with self.error(status=501, ...) when self.owner_column is
        # falsy or absent from columns; otherwise return it.
        # Bounded by AC-9.

    async def _pre_get(self, *args, **kwargs) -> bool:
        """Gate the read path before any parameter parsing or DB access.

        Cannot see the target row — upstream calls this as the first
        statement of ``get()``, before ``get_parameters()``
        (verified: navigator/views/model.py:552-564). So it does the checks
        that need only the session and the raw query string; row-level
        ownership is bound in :meth:`_get_data`.

        Returns:
            ``True``. A refusal is raised, never returned — returning a falsy
            value would yield a fixed 412 (navigator/views/model.py:555-561).
        """
        # FILL IN:
        #  1. self._require_owner_column()  (501 gate)
        #  2. await self.acting_user()      (401 when there is no session)
        #  3. run the raw query parameters through self.sanitize_query(...) so
        #     a non-superuser naming a FOREIGN owner value is refused 403 here
        #     — before the DB, and before the TypeError collision at
        #     navigator/views/model.py:446. Use
        #     self.query_parameters(self.request); discard the sanitized
        #     result (it is recomputed in _get_data from get_parameters()).
        #  4. return True
        # Bounded by AC-1, AC-4, AC-9.

    async def _get_data(self, qp: dict, args: dict):
        """Bind every read to an owner before delegating upstream.

        This is the single ownership-injection point, chosen over spec §3's
        ``_filter_user_id`` because the ``_filter_<column>`` hook cannot
        express the superuser case on any navigator version: raising
        ``NotSet`` makes ``_get_filters`` return ``None`` and every consumer
        then does ``**None`` (navigator/views/model.py:413-414, 424, 446,
        455), and the hook's return value is always stored, so there is no
        "leave unfiltered" result.

        ``_get_data`` sees both the primary-key path (model.py:421-444) and
        the query path (model.py:445-459), so it can bind one and widen the
        other.

        Args:
            qp: Query parameters with ``fields`` already popped out.
            args: URL arguments, including the primary key.

        Returns:
            Whatever the upstream implementation returns for the bound query.
        """
        # FILL IN:
        #  - user_id, is_superuser = await self.acting_user()
        #  - qp, _ = await self.sanitize_query(qp, None)
        #  - NON-superuser: force the owner predicate into the query so a
        #    foreign row is invisible on BOTH paths. On the PK path upstream
        #    merges _filter into get(**args) at model.py:443; the equivalent
        #    here is to put the acting user_id into `qp` (query path) and to
        #    make sure the PK path carries it too — verify which of the two
        #    upstream branches your request takes with _get_primary_data
        #    (model.py:370-375) before deciding where to inject.
        #  - SUPERUSER: inject nothing; a `?user_id=<n>` that survived
        #    sanitize_query is theirs to use. Authorize and audit via
        #    await self.authorize_row("identity:read", owner_id=<the value
        #    they asked for, or None for a table-wide read>).
        #  - delegate: return await super()._get_data(qp, args)
        #  - PK path shaping: a bound PK read that matches nothing must answer
        #    404, not upstream's 204 no_content (model.py:587-592). Raise it
        #    from here (self.error(status=404, ...)) with a body that names no
        #    column value, so the id cannot be used as an existence oracle.
        # Bounded by AC-2, AC-3, AC-5, AC-6, AC-7, AC-8.
```

**Why the superuser read is authorized in `_get_data` and not in
`_pre_get`.** `authorize_row` must be reached **once per request** with the
real action, and its audit record should name the target owner. In
`_pre_get` the owner is unknowable; in `_get_data` the request's intent
(`?user_id=<n>`, or table-wide) is already parsed. Calling it in both places
would double every audit record.

**Why the non-superuser predicate is forced rather than checked after the
fetch.** Fetch-then-compare means the row — credentials included — is in
process memory before the decision, and every later code path (logging, an
exception handler, a serializer) is a potential leak. Pushing `user_id = <me>`
into the WHERE clause means the database never hands over a foreign row at
all. It also makes the list path correct for free.

**Why a bound PK miss must be 404 and not upstream's 204.** Both hide the
row, so this is not about secrecy — it is about the contract in spec §3
Module 4's table and §5 criterion 4, and about the client: a 204 on
`GET /api/v1/user_identity/<uuid>` says "this identity exists and is empty",
which is a different and misleading fact. Use one generic 404 for *both*
"does not exist" and "not yours", which is what makes it a non-oracle.

**Why `_require_owner_column` answers 501 rather than 403 or 500.** 501 Not
Implemented says the *server* is not configured to serve this, which is
exactly true: the operator pointed `AUTH_USER_IDENTITY_MODEL` at a model this
surface cannot ownership-bind. 403 would blame the caller; 500 would look
like a crash and get retried.

### `tests/unit/handlers/test_user_identity_handler_access.py` — CREATE

```python
"""Read-path access control on UserIdentityHandler (FEAT-105, TASK-123).

Covers spec §4 rows test_get_foreign_row_returns_404,
test_get_forces_owner_filter, test_get_foreign_user_id_param_refused,
test_hidden_lists_are_per_subclass and
test_model_without_owner_column_fails_closed.

Response CONTENTS (redaction, :meta, _filter) are TASK-125's tests — assert
nothing about them here beyond which rows come back.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

pytestmark = pytest.mark.filterwarnings(
    "ignore::aiohttp.web_exceptions.NotAppKeyWarning"
)

OWNER_ID = 42
OTHER_ID = 99


class FakeSession(dict):
    """Session double supporting decode()/get()/mapping access.

    Verified pattern: tests/unit/identity/test_identity_handlers.py:12-17.
    """

    def decode(self, key):
        return self.get(key)


def _session(user_id=OWNER_ID, groups=("users",)):
    # FILL IN: FakeSession({"session": {"user_id": user_id, "username": "u",
    # "groups": list(groups)}}) — the shape navigator/views/abstract.py:316-320
    # and decorators.py:1061 read.


def _patch_sessions(session):
    """Patch get_session everywhere it is imported."""
    # FILL IN: patch both "navigator_auth.decorators.get_session" and
    # "navigator_auth.handlers.guards.get_session" with
    # AsyncMock(return_value=session) — the two-place pattern at
    # tests/unit/identity/test_identity_handlers.py:35-46.


def _handler(method="GET", path="/api/v1/user_identity/abc", match_info=None,
             pdp=None):
    """A UserIdentityHandler bound to a mocked request."""
    # FILL IN: build the app dict as in
    # tests/unit/identity/test_identity_handlers.py:20-27 ({"auth":…,
    # "authdb":…, "redis":…}), add app["abac"] = pdp when given, make the
    # mocked request, update match_info, then construct the handler.
    # ModelView.__init__ may need the request only — if it reaches for the
    # database, build with __new__ and set .request yourself, as
    # TASK-121's test does. Bounded by AC-10.


class TestOwnerColumnGate:
    @pytest.mark.asyncio
    async def test_model_without_owner_column_fails_closed(self):
        """A configured model lacking user_id => 501 on the read path."""
        # FILL IN: patch the handler's model with a double whose
        # get_columns() has no "user_id"; assert _pre_get raises with
        # status 501 — bounded by AC-9.


class TestReadPathOwnership:
    @pytest.mark.asyncio
    async def test_get_forces_owner_filter(self):
        """Listing without parameters queries only the acting user's rows."""
        # FILL IN: patch super()._get_data (or the model's filter) to record
        # its kwargs; assert user_id == OWNER_ID was applied — bounded by
        # AC-2.

    @pytest.mark.asyncio
    async def test_get_foreign_row_returns_404(self):
        """A non-owner GET by primary key => 404, body leaks no column data."""
        # FILL IN: make the bound query return nothing; assert
        # web.HTTPNotFound and that the body contains neither OTHER_ID nor a
        # column name — bounded by AC-6, AC-7.

    @pytest.mark.asyncio
    async def test_missing_row_and_foreign_row_are_indistinguishable(self):
        """The same 404 body for "not found" and "not yours"."""
        # FILL IN: compare the two responses' status AND text — bounded by
        # AC-7.

    @pytest.mark.asyncio
    async def test_get_foreign_user_id_param_refused(self):
        """?user_id=<other> as a non-superuser => 403, and no TypeError/400."""
        # FILL IN: assert web.HTTPForbidden from _pre_get, and explicitly
        # assert it is NOT HTTPBadRequest (which is what the
        # filter(**qp, **_filter) collision at model.py:446 would produce)
        # — bounded by AC-4.

    @pytest.mark.asyncio
    async def test_own_user_id_param_is_accepted(self):
        """?user_id=<self> is allowed and does not collide."""
        # FILL IN: bounded by AC-5.

    @pytest.mark.asyncio
    async def test_superuser_may_read_a_foreign_row(self):
        """A superuser with the policy may name another user's rows."""
        # FILL IN: superuser session + a PDP whose
        # user_identities_admin_access policy allows identity:read; assert the
        # query is NOT narrowed to the superuser's own id — bounded by AC-3.

    @pytest.mark.asyncio
    async def test_superuser_cross_user_read_is_audited(self):
        """Exactly one AuditLog record per cross-user read."""
        # FILL IN: patch AuditLog in navigator_auth.handlers.guards; assert
        # log awaited once — bounded by AC-8.

    @pytest.mark.asyncio
    async def test_superuser_without_policy_is_denied_but_owner_is_not(self):
        """Fail-closed: no PDP => no admin read; own rows still readable."""
        # FILL IN: two assertions on the same app — bounded by AC-3.

    @pytest.mark.asyncio
    async def test_unauthenticated_read_is_401(self):
        """No session => 401 from the pre-hook."""
        # FILL IN: patch get_session to return None — bounded by AC-1.


class TestMetadataLists:
    def test_hidden_lists_are_per_subclass(self):
        """_hidden/_required/_primaries are not shared with ModelView."""
        # FILL IN: from navigator.views import ModelView; assert
        # UserIdentityHandler._hidden is not ModelView._hidden; instantiate
        # another ModelHandler subclass FIRST and assert this handler's lists
        # are unaffected — bounded by AC-11.
```

**Why `test_get_foreign_user_id_param_refused` asserts the status is *not*
400.** 403 and 400 both refuse the request, so a naive assertion passes
either way — but a 400 means the parameter reached
`filter(**qp, **_filter)` and collided (`model.py:446`), i.e. the guard did
**not** sanitize and the only thing saving you is an upstream `TypeError`.
Pin the distinction.

**Why `test_missing_row_and_foreign_row_are_indistinguishable` exists
separately from the 404 test.** 404 alone is not the property; *identical*
404s are. If the two bodies differ by one word, the endpoint is still an
existence oracle for every identity id, which is what spec §2 layer 1 set out
to remove.

**Why `test_superuser_without_policy_is_denied_but_owner_is_not` asserts
both halves.** A fail-closed implementation that also broke self-service
would pass a deny-only assertion. The pair is the actual requirement (spec
§5 criterion 7).

### Steps (in order)

1. Confirm the dependency: `from navigator_auth.handlers.guards import
   OwnerOrSuperuserGuard` must import. If not, TASK-122 is not merged — stop.
2. Apply Block 1 (the import).
3. Apply Block 2 (class line + configuration). Then run
   `python -c "from navigator_auth.handlers.userattrs import UserIdentityHandler as H; print(H.__mro__[:3]); print(sorted(H.public_columns))"`
   and confirm `OwnerOrSuperuserGuard` precedes `ModelHandler`.
4. Apply Block 3 and fill `_require_owner_column` first (every verb depends
   on it), then `_pre_get`, then `_get_data`.
5. Create the test module. Fill `_session`, `_patch_sessions` and `_handler`
   first — all three are shared by TASK-124 and TASK-125's tests in this same
   file, so get them right and keep them at module level.
6. Fill the test bodies class by class, running each as you go.
7. Run `pytest tests/unit/handlers/test_user_identity_handler_access.py -v`,
   then the regression gate
   `pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q`.
8. `ruff check navigator_auth/handlers/userattrs.py tests/unit/handlers/`.
9. Confirm the blast radius: `git diff navigator_auth/handlers/userattrs.py`
   must show **no change inside `class UserAccountHandler`** (AC-12), and
   `git diff --name-only` must list only `userattrs.py` and the new test file.

### FILL IN checklist

- [ ] Block 3 anchor disambiguation — two `return await self.get_userid(...)` lines exist in this file
- [ ] `_require_owner_column` body — 501 gate — AC-9
- [ ] `_pre_get` body — 501 gate, 401, foreign-owner-param refusal — AC-1, AC-4, AC-9
- [ ] `_get_data` body — owner predicate for non-superusers, superuser widen + authorize + audit, 404 shaping — AC-2, AC-3, AC-5..AC-8
- [ ] `_session` / `_patch_sessions` / `_handler` test helpers — AC-10
- [ ] `test_model_without_owner_column_fails_closed` — AC-9
- [ ] `test_get_forces_owner_filter` — AC-2
- [ ] `test_get_foreign_row_returns_404` — AC-6, AC-7
- [ ] `test_missing_row_and_foreign_row_are_indistinguishable` — AC-7
- [ ] `test_get_foreign_user_id_param_refused` — AC-4
- [ ] `test_own_user_id_param_is_accepted` — AC-5
- [ ] `test_superuser_may_read_a_foreign_row` — AC-3
- [ ] `test_superuser_cross_user_read_is_audited` — AC-8
- [ ] `test_superuser_without_policy_is_denied_but_owner_is_not` — AC-3
- [ ] `test_unauthenticated_read_is_401` — AC-1
- [ ] `test_hidden_lists_are_per_subclass` — AC-11

---

## Acceptance Criteria

- [ ] **AC-1** `UserIdentityHandler` inherits `OwnerOrSuperuserGuard` **before** `ModelHandler`, and a read with no session answers **401**.
- [ ] **AC-2** A `GET` list with no parameters queries only rows whose `user_id` equals the session `user_id`.
- [ ] **AC-3** A superuser whose policy allows `identity:read` may read another user's rows; with no PDP, with the policy undeclared, or with a policy that raises, the admin read is denied while the owner's own read keeps working.
- [ ] **AC-4** `?user_id=<other>` as a non-superuser answers **403** — not 400, not 500 — and no query is issued.
- [ ] **AC-5** `?user_id=<self>` is accepted and does not collide with the forced predicate.
- [ ] **AC-6** A non-owner `GET` by `identity_id` answers **404**.
- [ ] **AC-7** The 404 for a foreign row and the 404 for a nonexistent row are **identical** in status and body, and neither names a column value.
- [ ] **AC-8** Each cross-user read produces exactly one `AuditLog` record.
- [ ] **AC-9** When the configured model has no `user_id` column, the read path answers **501**.
- [ ] **AC-10** `_set_user_id` is unchanged and still resolves the session `user_id`.
- [ ] **AC-11** `UserIdentityHandler._hidden is not ModelView._hidden`; instantiating another `ModelHandler` subclass first does not change this handler's metadata lists.
- [ ] **AC-12** `class UserAccountHandler` in the same file is unchanged, and nothing under `navigator_auth/` outside `userattrs.py` is modified.
- [ ] **AC-13** `pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q` passes and `ruff check navigator_auth/handlers/userattrs.py tests/unit/handlers/` is clean.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/unit/handlers/test_user_identity_handler_access.py -v
pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q   # regression
ruff check navigator_auth/handlers/userattrs.py tests/unit/handlers/
```

```python
from navigator.views import ModelView
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard
from navigator_auth.handlers.userattrs import UserIdentityHandler

assert UserIdentityHandler.__mro__.index(OwnerOrSuperuserGuard) < \
       UserIdentityHandler.__mro__.index(ModelView)
```

---

## Agent Instructions

1. **Read the spec** at `sdd/specs/user-identities-ownership-abac.spec.md` —
   §1 Problem Statement A, §2 Overview layer 1, §2 Data Models, §3 Module 4
   (configuration and the behavioural table's read rows), §4 the read-path
   rows, §7 Patterns to Follow.
2. **Check dependencies** — TASK-122 (`handlers/guards.py`) must be in
   `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/user-identities-ownership-abac.json`
   → `"in-progress"`.
4. **Implement** per the blueprint. Read the two `_filter_<column>` traps
   before choosing your injection point, and **record the mechanism you used**
   in the Completion Note — the spec names `_filter_user_id`, which
   verification shows cannot carry the superuser case.
5. **Verify** every acceptance criterion, AC-7 and AC-12 included.
6. **Move this file** to `sdd/tasks/completed/TASK-123-identity-handler-read-path.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback)
**Date**: 2026-10-24
**Notes**: 14 tests pass. Mechanism: owner predicate injected by installing an instance-level _filter_user_id in _get_data for non-superusers only (no class hook; avoids NotSet/None traps); superuser PK reads authorized against fetched row owner (404 on deny). DEVIATION: BaseHandler.error() has no 501 mapping (falls to 400), so _require_owner_column raises web.HTTPNotImplemented directly. ruff: only the 4 pre-existing unused imports in userattrs.py.

**Deviations from spec**: none
