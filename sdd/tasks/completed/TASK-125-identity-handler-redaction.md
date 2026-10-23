# TASK-125: `UserIdentityHandler` — redaction, `:meta` and the safe `_filter`

**Feature**: FEAT-105 — Owner-or-Superuser ABAC Ownership for the Auth Model CRUD Surfaces
**Spec**: `sdd/specs/user-identities-ownership-abac.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-124
**Assigned-to**: unassigned

---

## Context

Last of three tasks implementing **spec §3 Module 4**. TASK-123 and TASK-124
closed *who may reach which row*; this one closes *what comes back*, i.e.
spec **G3**: credential material is never serialized to anyone, through any
parameter combination, **by construction**.

The remaining rows of spec §3 Module 4's behavioural table:

| Verb / target | Owner | Superuser (other user) | Other user |
|---|---|---|---|
| `?fields=access_token` | dropped | dropped | dropped |
| `?_filter=auth_provider=git` | own rows, parameterized | allowed, audited | own rows |
| `?_filter=access_token=x` | **400** | **400** | **400** |
| `:meta` | schema minus credential columns | same | same |

Plus the shape rule from spec §8 Q6: the identity projection matches
`IdentityStore.masked()` (`identity/store.py:465`) so the two identity
surfaces — this generic CRUD one and the purpose-built vault one — cannot
drift by role.

**Why redaction is a separate task from the access control.** They fail
differently and are tested differently. Access control is about *which rows*
and is asserted on status codes; redaction is about *which keys* and is
asserted on payloads. Splitting them keeps each blueprint under the size cap
and means a redaction regression cannot be masked by an access-control test
passing.

> **Environment drift (read this).** Spec §6's upstream table was recorded
> against `navigator-api` **3.2.2**; `.venv` has **4.0.1**. This task is the
> one most affected: upstream's `_model_response` and `_filtering` were
> *both* repaired in 4.0.1. Every anchor below was **re-verified against
> 4.0.1**, and the section "Why the overrides are still required on 4.0.1"
> explains why none of them can be dropped.

---

## Scope

- Override `_model_response` to project every response through the
  `public_columns` allowlist, in the `IdentityStore.masked()` shape.
- Override `_get_meta_info` so `:meta` cannot enumerate credential columns.
- Override `head()` so its `X-Columns` header cannot enumerate them either.
- Override `_filtering` to route `?_filter=` through the guard's
  `safe_filter`.
- Extend `tests/unit/handlers/test_user_identity_handler_access.py`, and add
  `tests/unit/handlers/test_identity_projection_parity.py` for the
  `masked()`-shape agreement.

**NOT in scope**:
- Any access-control change. `_pre_*`, `_get_data`, `_set_update`,
  `_del_primary_data`, `_post_data`, `_patch_data`, `_reject_readonly` and
  `_require_owner_column` are TASK-123/124's and must not be touched.
- `UserAccountHandler` (TASK-126) / `PartnerKeyHandler` (TASK-127).
- Changing `redaction.py` (TASK-118) or `guards.py` (TASK-122). If
  `redact_rows` or `safe_filter` is missing something, raise it rather than
  working around it here.
- Changing `IdentityStore.masked()` or anything under
  `navigator_auth/identity/`. Spec §1 Non-Goals: the vault handler is already
  owner-scoped and masked and stays untouched.
- Adding `secret=True` / `repr=False` to any model column. Spec §2 is
  explicit that the guard must not depend on model flags.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/userattrs.py` | MODIFY | Add `_model_response`, `_get_meta_info`, `head`, `_filtering` to `UserIdentityHandler` |
| `tests/unit/handlers/test_user_identity_handler_access.py` | MODIFY | Add the redaction / `:meta` / `_filter` test classes |
| `tests/unit/handlers/test_identity_projection_parity.py` | CREATE | `masked()`-shape agreement |

---

## Codebase Contract

> Re-verified on `dev` @ `62fd419` against installed `navigator-api` **4.0.1**
> (2026-10-23). Unqualified line numbers are in
> `.venv/lib/python3.11/site-packages/navigator/views/model.py`.

### Why the overrides are still required on 4.0.1 (the spec's §6 is stale)

4.0.1 **does** project responses and **does** parameterize `_filter`:

```python
    def _visible_columns(self, row: Any, fields: list = None) -> Optional[list]:   # :203
        hidden = frozenset(self._hidden or ())
        if fields:
            return [column for column in fields if column not in hidden]
        if not hidden:
            return None
        return [column for column in self._row_columns(row) if column not in hidden]
```

and `_hidden` is derived from `secret=True` only:

```python
            if metadata.get('secret') is True:      # :178
                hidden.append(name)
```

**But no credential column on `UserIdentity` declares `secret=True`** —
verified `navigator_auth/models.py:104-110`: `access_token`,
`refresh_token`, `id_token`, `token_type`, `expires_at`, `refreshed_at`,
`key_version` are all `repr=False` only, and `repr` is deliberately **not**
treated as a serialization rule upstream (the docstring at `:161-167` says
so). So `self._hidden == []`, `_visible_columns` returns `None`, and
`_project_row` returns the row **as-is** (`:224-229`):

```python
    def _project_row(self, row: Any, fields: list = None) -> Any:
        columns = self._visible_columns(row, fields)
        if columns is None:
            return row
        return {column: self._row_value(row, column) for column in columns}
```

**The full row, token bytes included, is serialized today — on 4.0.1 as on
3.2.2.** The allowlist override is the only thing that stops it. Say this in
the override's docstring; a future reader looking at `_visible_columns` will
reasonably assume the problem is already handled upstream.

Same for `_filtering` (`:479-547`): it is validated and bound as `$1`, but
its allowlist is "a real column, not in `_hidden`" — so
`?_filter=access_token=x` is **valid** upstream and returns token bytes — and
it carries **no ownership predicate** (`SELECT "<col>" FROM <table> WHERE
"<col>"::text LIKE $1`, `:535-538`), so it reads across all users.

### `_model_response` — the signature to override (verified: `:237-243`)

```python
    async def _model_response(
            self,
            response: Any,
            fields: list = None,
            headers: dict = None,
            status: int = 200
    ) -> web.Response:
```

Its body (`:244-270`): `None` → `self.no_content(headers=headers)`; falsy →
`self.error(...)` "Record not Found"; otherwise
`result = self._project_response(response, fields)` then
`self.json_response(result, headers=headers, status=status)` and a
send-and-forget `self._get_callback` hop. Delegating to `super()` after
redacting keeps the callback and the no-content/error branches.

Where it is called from `get()` (verified `:573`):
`return await self._model_response(data, fields=fields)`.

### `:meta` is served BEFORE `_filtering` and `_get_data`, and is NOT projected

Verified `:561-564`:

```python
        args, meta, qp, fields = self.get_parameters()
        response = await self._get_meta_info(meta, fields)
        if response is not None:
            return response
```

and `.venv/.../navigator/views/abstract.py:470-519`:

```python
    async def _get_meta_info(self, meta: str, fields: list):
        if meta == ":meta":
            ...
            else:
                # returning JSON schema of Model:
                response = self.model.schema(as_dict=True)
                return self.json_response(response)
        elif meta == ':sample':
            # return a JSON sample of data:
            response = self.model.sample()
```

So `:meta` bypasses `_model_response` entirely and returns the **raw model
schema**, which lists every credential column. It must be overridden
separately — this is why `redact_schema` exists in TASK-118.

Note `:sample` is served by the same method and also leaks the column set.
Handle both (AC-8).

### CRITICAL — `Model.schema(as_dict=True)` is a CACHED, SHARED dict

Verified by executing it:

```python
a = UserIdentity.schema(as_dict=True)
b = UserIdentity.schema(as_dict=True)
a is b                                # True
a['properties'] is b['properties']    # True
hasattr(UserIdentity, '__computed_schema__')   # True
```

So the `:meta` override **must not mutate** the payload. `redact_schema`
(TASK-118) already returns a new dict and has a test for exactly this
(TASK-118 AC-8) — use it, do not pop keys yourself.

### `head()` also enumerates the columns

Verified `.venv/.../navigator/views/abstract.py:449-467`:

```python
    @service_auth
    async def head(self):
        """Getting Model information."""
        ## calculating resource:
        response = self.model.schema(as_dict=True)
        columns = list(response["properties"].keys())
        size = len(str(response))
        ...
        headers = {
            "Content-length": size,
            "X-Columns": f"{columns!r}",
            ...
        }
        return self.no_content(headers=headers)
```

`X-Columns` lists `access_token`, `refresh_token`, `id_token`,
`key_version`. **Spec §3 Module 4 does not mention `head()`** — its method
list stops at `_model_response`. But spec G3 says credentials must not be
enumerable "through any parameter combination … for any role", and §5
criterion 3 says "no response from `/api/v1/user_identity*` contains" them.
A `HEAD` response's headers are a response. Including it here is a small,
bounded extension of the spec's own stated goal; it is flagged as such, and
the implementer should record it in the Completion Note.

### `IdentityStore.masked()` — the shape to match (verified: `navigator_auth/identity/store.py:465-496`)

```python
    def masked(self, identity: UserIdentity) -> dict:
        """API-safe representation: never includes token material."""
        expires_at = identity.expires_at
        expired = False
        if expires_at is not None:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            expired = expires_at <= datetime.now(timezone.utc)
        return {
            "expired": expired,
            "identity_id": str(identity.identity_id),
            "auth_provider": identity.auth_provider,
            "provider_user_id": identity.provider_user_id,
            "scopes": list(identity.scopes or []),
            "token_type": identity.token_type,
            "expires_at": (
                identity.expires_at.isoformat() if identity.expires_at else None
            ),
            "refreshed_at": (
                identity.refreshed_at.isoformat() if identity.refreshed_at else None
            ),
            "created_at": (
                identity.created_at.isoformat() if identity.created_at else None
            ),
            "enabled": identity.enabled,
            "has_refresh_token": identity.refresh_token is not None,
            "has_id_token": getattr(identity, "id_token", None) is not None,
            "profile": identity.auth_data or {},
        }
```

Three derivations this task must reproduce (spec §2 Data Models):
`auth_data` is emitted as **`profile`**; token material becomes
**`has_refresh_token`** / **`has_id_token`**; **`expired`** is derived from
`expires_at`, treating a naive datetime as UTC.

`masked()` emits 13 keys. `public_columns` (TASK-123) holds 19 names, and the
two sets are deliberately different: this surface additionally serves the
PII columns (`display_name`, `title`, `nickname`, `email`, `phone`,
`short_bio`, `avatar`, `attributes`, `user_id`) which the vault endpoint has
no reason to. The parity requirement is about the **credential-related
keys**, not key-set equality — see the blueprint's note and AC-5.

### `redact_rows` / `safe_fields` — the TASK-118 contract consumed here

```python
def safe_fields(fields: Optional[list[str]], public_columns: frozenset[str]) -> Optional[list[str]]
def redact_row(row, public_columns, fields=None) -> dict
def redact_rows(rows, public_columns, fields=None) -> Any     # preserves list-vs-scalar
def redact_schema(schema: dict, credential_columns: frozenset[str]) -> dict
```

`safe_fields(None, …)` returns `None` ("no projection asked"); an all-
forbidden `fields` returns `[]` ("nothing allowed"). The two must stay
distinguishable in this override too (AC-3).

### `safe_filter` — the TASK-122 contract consumed here

`async def safe_filter(self, expr: str) -> Any` — parses `<field>=<value>`,
refuses 400 for a field outside `public_columns` or absent from the model,
binds the value as `$1`, ANDs the owner predicate for a non-superuser, and
audits a superuser filter.

`_filtering`'s own contract (verified `:479` and the call at `:568-570`):
it must return `None` when there is no `_filter` parameter, so `get()`
continues into the normal flow:

```python
            response = await self._filtering(qp)
            if response is not None:
                return response
```

Returning anything non-`None` when `_filter` is absent would make **every**
GET return the filter response.

### Does NOT Exist (do not reference)

- `_model_response` / `_get_meta_info` / `head` / `_filtering` on
  `UserIdentityHandler` today — all four are inherited.
- `ModelView._hidden` as a redaction mechanism for this model — it is `[]`
  (no `secret=True` column). Do not populate it instead of overriding; spec
  §2 layer 3 requires the allowlist, and a populated `_hidden` would still
  be an exclusion list, i.e. a denylist.
- `VwUserIdentity` (`navigator_auth/models.py:119`) as the response model.
  It is imported but unused in `userattrs.py:11`; swapping to it is not the
  design (spec §2 chose an explicit allowlist over a second model).
- `IdentityStore.masked()` as something to **call** from here. It is an
  instance method on a store that needs a cipher and a connection
  (`navigator_auth/identity/store.py`), and this handler's rows are not
  guaranteed to be `UserIdentity` instances (`AUTH_USER_IDENTITY_MODEL` can
  swap the model). Reproduce the *shape*; do not instantiate the store. The
  parity test imports `masked` only to read its key set.
- `navigator_auth/identity/redaction.py` — spec rev 0.1's path; rev 0.2
  moved it to `handlers/redaction.py`. Only the latter exists (TASK-118).
- `json_encoder` bytes handling in `navigator_auth/libs/json.py` as a place
  to fix this. Spec §6: the import at `models.py:14` is
  `from .libs.json import json_encoder` and the module is **not** at that
  literal path. Do not try to patch bytes serialization there.
- `_get_callback` / `_patch_callback` as redaction points. They are
  send-and-forget hooks (`:263-270`) that receive the **already-built**
  response; by then the bytes have been serialized.

---

## Implementation Blueprint

### `navigator_auth/handlers/userattrs.py` — MODIFY (two blocks)

Both append inside `class UserIdentityHandler`, below TASK-124's methods.

> **Anchor warning.** `async def _set_user_id(self, value, column, data):`
> and `return await self.get_userid(session=self._session)` each occur
> **twice** in this file (one per handler). `# FILL IN: disambiguate —
> anchor on a line unique to UserIdentityHandler, e.g. TASK-124's
> `_del_primary_data` definition, quoting 2-3 surrounding lines.`

**Block 1 — the response projection:**

```python
    def _masked_shape(self, row: dict) -> dict:
        """Reshape an allowlisted row into the ``IdentityStore.masked()`` form.

        Keeps the two identity surfaces from drifting (spec §8 Q6):
        ``auth_data`` is emitted as ``profile``, token material becomes
        ``has_refresh_token`` / ``has_id_token``, and ``expired`` is derived
        from ``expires_at``.

        Args:
            row: An already-redacted row (credential columns are gone).

        Returns:
            The reshaped row.
        """
        # FILL IN: mirror navigator_auth/identity/store.py:465-496 —
        #  - rename auth_data -> profile, defaulting to {}
        #  - scopes -> list(... or [])
        #  - identity_id -> str(...)
        #  - expires_at / refreshed_at / created_at -> .isoformat() or None
        #  - derive expired: None -> False; a NAIVE datetime is treated as
        #    UTC (store.py:469-471) before comparing to now(timezone.utc)
        #  - has_refresh_token / has_id_token: these cannot be read from the
        #    redacted row (the columns are gone by then) — take them from the
        #    ORIGINAL row in _model_response and pass them in, or compute them
        #    there. Decide and keep it in one place.
        # Bounded by AC-4, AC-5, AC-6.

    async def _model_response(
        self,
        response: Any,
        fields: list = None,
        headers: dict = None,
        status: int = 200,
    ) -> web.Response:
        """Project every response through ``public_columns``, then delegate.

        Required even on navigator-api 4.0.1, whose own projection is driven
        by ``_hidden`` (navigator/views/model.py:203-229) — and ``_hidden`` is
        derived from ``secret=True`` columns only (model.py:178), which **no**
        credential column on ``UserIdentity`` declares
        (navigator_auth/models.py:104-110). Upstream therefore returns the
        full row, token bytes included. This override is the only thing that
        redacts this surface; do not remove it as redundant.

        Args:
            response: The row or rows to serialize.
            fields: The caller's ``?fields=`` projection.
            headers: Extra response headers.
            status: HTTP status.

        Returns:
            The upstream response, built from redacted rows.
        """
        # FILL IN:
        #  1. leave the None / falsy branches to super() — do not reimplement
        #     no_content / "not Found" (model.py:244-256).
        #  2. safe = safe_fields(fields, self.public_columns)
        #  3. redacted = redact_rows(response, self.public_columns, safe)
        #  4. reshape each row through _masked_shape
        #  5. return await super()._model_response(redacted, fields=None,
        #     headers=headers, status=status)
        #     Pass fields=None: the projection is already applied, and
        #     handing the raw `fields` to super() would let it re-project the
        #     reshaped dict by column names that no longer exist (profile vs
        #     auth_data). Bounded by AC-1, AC-2, AC-3.
```

**Why `fields=None` is passed to `super()`.** The reshape renames
`auth_data` → `profile`, so upstream's `_visible_columns(row, fields)` would
look for `auth_data` in a dict that no longer has it and return `None` for
it. The projection is this override's job and must happen exactly once.

**Why the allowlist is applied *before* the reshape.** The reshape is a
rename/derive step; running it first would mean deciding what to hide after
having built derived values out of hidden inputs. Redact, then shape.

**Why `has_refresh_token` / `has_id_token` need the pre-redaction row.** They
are *derived from* `refresh_token` / `id_token`, which `redact_rows` removes
(they are in `credential_columns` and absent from `public_columns`). So the
booleans must be computed from the original row. This is the one place where
the order "redact then shape" needs care — pick one home for it (compute in
`_model_response` and pass down, or hand `_masked_shape` both rows) and keep
it there (AC-6).

**Why spec §5 criterion 3's "under any combination" is satisfied here and
not by checking parameters.** There is no enumeration of bad parameter
combinations in this override. Every response passes through one allowlist
intersection, so a parameter that was never anticipated cannot widen it.
That is what "by construction" in spec G3 means.

**Block 2 — `:meta`, `head()` and the safe filter:**

```python
    async def _get_meta_info(self, meta: str, fields: list):
        """Redact the ``:meta`` / ``:sample`` payloads.

        ``get()`` serves these BEFORE ``_filtering`` and ``_get_data``
        (navigator/views/model.py:561-564) and they bypass
        ``_model_response`` entirely, returning ``self.model.schema(as_dict=True)``
        raw (navigator/views/abstract.py:470-519) — which enumerates every
        credential column.

        Args:
            meta: The ``{meta}`` URL segment, e.g. ``":meta"``.
            fields: The caller's projection, passed through.

        Returns:
            The redacted meta response, or ``None`` when ``meta`` is not a
            meta request (so ``get()`` continues into the normal flow).
        """
        # FILL IN:
        #  - delegate to super() and, when it returned a response for :meta or
        #    :sample, rebuild it from redact_schema(<payload>,
        #    self.credential_columns). super() returns a web.Response, so the
        #    payload is no longer a dict at that point — prefer intercepting
        #    BEFORE super(): handle meta == ":meta" / ":sample" here by
        #    building the payload yourself from
        #    self.get_model.schema(as_dict=True) and passing it through
        #    redact_schema, then self.json_response(...). Return None for
        #    every other `meta` value so the caller continues.
        #  - NEVER mutate the schema payload: schema(as_dict=True) returns the
        #    model's CACHED dict (verified: a is b). redact_schema already
        #    copies (TASK-118 AC-8) — rely on it.
        # Bounded by AC-7, AC-8, AC-9.

    async def head(self):
        """Keep ``X-Columns`` from enumerating the credential columns.

        Upstream builds the header from the full model schema
        (navigator/views/abstract.py:449-467). Not named in spec §3 Module 4,
        but spec G3 forbids enumerating credentials "through any parameter
        combination … for any role" and §5 criterion 3 speaks of every
        response from this surface — headers included.
        """
        # FILL IN: call super().head(), then rewrite the X-Columns header
        # from sorted(self.public_columns) and drop the credential names;
        # alternatively build the no_content response here from the redacted
        # schema. Keep X-Model / X-Tablename / X-Schema as upstream sets them.
        # Bounded by AC-10.

    async def _filtering(self, queryparams: dict):
        """Route ``?_filter=`` through the guard's parameterized safe filter.

        Required even on navigator-api 4.0.1, whose own ``_filtering``
        (model.py:479-547) *is* parameterized: its allowlist is "a real column
        not in ``_hidden``" — and ``_hidden`` is empty here — so
        ``?_filter=access_token=x`` is a VALID filter upstream and returns
        token bytes; and it applies no ownership predicate
        (model.py:535-538), so it reads across every user.

        Args:
            queryparams: The request query parameters.

        Returns:
            The filter response, or ``None`` when no ``_filter`` was
            requested — ``get()`` checks for ``None`` to continue into the
            normal flow (model.py:568-570).
        """
        # FILL IN:
        #  - expr = queryparams.get('_filter'); return None when falsy. This
        #    early return is load-bearing: a non-None return on a plain GET
        #    would make every GET answer with the filter response.
        #  - rows = await self.safe_filter(expr)   (400s on a bad field)
        #  - return the rows through self._model_response(rows) so the result
        #    is redacted and reshaped like every other read.
        # Bounded by AC-11, AC-12, AC-13, AC-14.
```

**Why `_get_meta_info` is better intercepted before `super()` than after.**
`super()` returns a `web.Response` whose body is already serialized JSON;
redacting it would mean parsing the body back out. Build the payload here,
pass it through `redact_schema`, and return `None` for every `meta` value
you do not handle so the normal flow continues.

**Why `:sample` is handled too.** It is served by the same method
(`abstract.py:517-519`, `self.model.sample()`) and also describes the column
set. Leaving it open means `?` → `:sample` enumerates exactly what `:meta`
was just stopped from enumerating.

**Why `head()` is in scope although spec §3 Module 4 omits it.** Spec G3 and
§5 criterion 3 are about what this surface reveals, and `X-Columns` reveals
the credential column names to any authenticated caller. It is a one-header
fix. It is called out as a spec extension so it is a decision, not drift —
record it in the Completion Note.

**Why `_filtering` returns through `_model_response` rather than
`json_response` directly.** Otherwise the filter path is a second
serialization route with its own redaction, and the two will drift. One exit
point, one allowlist. (Note that upstream's own `_filtering` selects a single
column and returns it raw — passing it through `_model_response` makes the
filter response shaped like every other read, which the parity test checks.)

### `tests/unit/handlers/test_user_identity_handler_access.py` — MODIFY

```python
# AFTER — append at end of file
# anchor: the final line of `class TestDeletePath` (TASK-124)
# occurrences: 1 (verified after TASK-124: grep -cF 'class TestDeletePath'
# tests/unit/handlers/test_user_identity_handler_access.py)

CREDENTIALS = ("access_token", "refresh_token", "id_token", "key_version")


class TestResponseRedaction:
    @pytest.mark.asyncio
    async def test_no_credential_key_in_any_response(self):
        """A full row in => no credential key out, for the owner."""
        # FILL IN: build a row double carrying non-None values in all four
        # credential columns; assert none of CREDENTIALS is in the payload
        # — bounded by AC-1.

    @pytest.mark.asyncio
    async def test_fields_param_cannot_project_credentials(self):
        """?fields=access_token,refresh_token,email returns email only."""
        # FILL IN: bounded by AC-3.

    @pytest.mark.asyncio
    async def test_fields_naming_only_credentials_returns_no_data(self):
        """?fields=access_token yields an empty projection, not the full row."""
        # FILL IN: this is the safe_fields None-vs-[] contract (TASK-118
        # AC-2) observed at the handler — bounded by AC-3.

    @pytest.mark.asyncio
    async def test_superuser_response_is_redacted_too(self):
        """A superuser read of a foreign row carries no token material."""
        # FILL IN: bounded by AC-2.

    @pytest.mark.asyncio
    async def test_list_and_scalar_shapes_preserved(self):
        """A list response stays a list; a single row stays an object."""
        # FILL IN: bounded by AC-1.

    @pytest.mark.asyncio
    async def test_no_token_bytes_anywhere_in_the_payload(self):
        """Serialize and scan: the sentinel bytes appear nowhere."""
        # FILL IN: put b"SENTINEL-TOKEN-BYTES" in access_token; assert the
        # sentinel is absent from the full serialized body, not just from the
        # top-level keys. This catches a leak through a nested dict such as
        # attributes or profile — bounded by AC-1.


class TestMetaRedaction:
    @pytest.mark.asyncio
    async def test_meta_strips_credential_columns(self):
        """:meta loses every credential column."""
        # FILL IN: bounded by AC-7.

    @pytest.mark.asyncio
    async def test_sample_strips_credential_columns(self):
        """:sample is served by the same method and is redacted too."""
        # FILL IN: bounded by AC-8.

    @pytest.mark.asyncio
    async def test_meta_does_not_mutate_the_cached_schema(self):
        """UserIdentity.schema(as_dict=True) still lists access_token after."""
        # FILL IN: the schema dict is memoized and SHARED (verified a is b);
        # an in-place pop would corrupt it process-wide — bounded by AC-9.

    @pytest.mark.asyncio
    async def test_meta_returns_none_for_a_non_meta_request(self):
        """_get_meta_info(None, …) is None so get() continues."""
        # FILL IN: bounded by AC-7.

    @pytest.mark.asyncio
    async def test_head_x_columns_has_no_credentials(self):
        """HEAD's X-Columns header enumerates no credential column."""
        # FILL IN: bounded by AC-10.


class TestSafeFilterWiring:
    @pytest.mark.asyncio
    async def test_filter_on_credential_column_is_400(self):
        """?_filter=access_token=x => 400 and no query issued."""
        # FILL IN: bounded by AC-12.

    @pytest.mark.asyncio
    async def test_filter_on_public_column_is_parameterized(self):
        """?_filter=auth_provider=git executes with $1."""
        # FILL IN: assert "$1" in the recorded SQL and "git" among the args
        # — bounded by AC-13.

    @pytest.mark.asyncio
    async def test_filter_result_is_redacted(self):
        """The filter response carries no credential key."""
        # FILL IN: the filter path is a SECOND serialization route; without
        # this it can leak while every other test passes — bounded by AC-14.

    @pytest.mark.asyncio
    async def test_filtering_returns_none_without_the_parameter(self):
        """No _filter => None, so get() continues into the normal flow."""
        # FILL IN: a non-None return here would make EVERY GET answer with
        # the filter response (model.py:568-570) — bounded by AC-11.

    @pytest.mark.asyncio
    async def test_upstream_filtering_is_unreachable(self):
        """ModelView._filtering is never called from this handler."""
        # FILL IN: patch navigator.views.model.ModelView._filtering with a
        # MagicMock that raises; drive a _filter request; assert it was never
        # called — this is spec §5 criterion 8's "unreachable" claim, asserted
        # rather than assumed. Bounded by AC-15.
```

### `tests/unit/handlers/test_identity_projection_parity.py` — CREATE

```python
"""The CRUD identity projection agrees with IdentityStore.masked() (FEAT-105).

Spec §4 row `test_identity_projection_matches_masked`, spec §8 Q6. Two
surfaces serve the same table: /api/v1/user_identity* (this feature) and
/api/v1/user/identities* (the vault). If their shapes drift, a client
hardened against one is wrong about the other.
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from navigator_auth.handlers.userattrs import UserIdentityHandler

MASKED_KEYS = frozenset({
    "expired", "identity_id", "auth_provider", "provider_user_id", "scopes",
    "token_type", "expires_at", "refreshed_at", "created_at", "enabled",
    "has_refresh_token", "has_id_token", "profile",
})


class TestProjectionParity:
    def test_masked_key_set_is_still_what_we_think(self):
        """Pin IdentityStore.masked()'s key set so drift is caught here."""
        # FILL IN: build a UserIdentity double, call
        # IdentityStore.masked(store_double, identity) as an UNBOUND function
        # (it needs no store state — verified: store.py:465-496 touches only
        # `identity`), and assert set(result) == MASKED_KEYS. If this test
        # fails, masked() changed and the handler projection must follow.
        # Bounded by AC-5.

    def test_credential_related_keys_agree(self):
        """Every masked() key that concerns credentials is produced here too."""
        # FILL IN: assert the handler's projection of the same row contains
        # has_refresh_token, has_id_token, expired, profile, scopes,
        # token_type, expires_at, refreshed_at — and NONE of access_token,
        # refresh_token, id_token, key_version. The two key sets are NOT
        # equal: this surface additionally serves the PII columns the vault
        # endpoint has no reason to. Bounded by AC-5.

    def test_has_refresh_token_true_and_false(self):
        """The boolean follows the underlying column, both ways."""
        # FILL IN: refresh_token=b"ct" -> True; None -> False — AC-6.

    def test_has_id_token_uses_getattr_default(self):
        """A row lacking id_token entirely yields False, not an error."""
        # FILL IN: mirrors store.py:494's getattr(..., None) — AC-6.

    def test_expired_for_naive_and_aware_expires_at(self):
        """A naive datetime is read as UTC (store.py:469-471)."""
        # FILL IN: four cases — naive past, naive future, aware past, aware
        # future — bounded by AC-4.

    def test_expired_is_false_when_expires_at_is_none(self):
        """No expiry => not expired."""
        # FILL IN: bounded by AC-4.

    def test_profile_defaults_to_empty_dict(self):
        """auth_data None => profile {}."""
        # FILL IN: bounded by AC-4.
```

**Why `test_masked_key_set_is_still_what_we_think` pins the *other* side.**
This feature cannot stop someone editing `masked()` later. Pinning its key
set here means such an edit fails a test in *this* feature's suite, with a
message that says which surface moved — instead of the two drifting silently
for a release.

**Why the two key sets are asserted *unequal* rather than equal.** Spec §8
Q6 asks for shape parity on the credential-related keys, not for identical
payloads: this surface serves `email`, `phone`, `display_name` and the rest,
which `masked()` deliberately omits. An `assertEqual` on the key sets would
be wrong and would get "fixed" by dropping the PII columns from
`public_columns` — losing functionality spec G4 requires.

**Why `test_upstream_filtering_is_unreachable` patches and asserts
not-called.** Spec §5 criterion 8 ends with "`ModelView._filtering()` is
unreachable from all three handlers". That is a claim about a code path, and
the only way to assert it is to make the upstream method explode and show it
never runs.

### Steps (in order)

1. Confirm TASK-124 landed, and that `safe_fields` / `redact_rows` /
   `redact_schema` import from `navigator_auth.handlers.redaction` and
   `safe_filter` exists on the guard.
2. Add Block 1. Fill `_masked_shape` first, then `_model_response`. Decide
   where `has_refresh_token` / `has_id_token` are computed and write it down
   in a comment — it is the one ordering subtlety here.
3. Run `TestResponseRedaction` before going further; a wrong projection makes
   every later failure look like a `:meta` or filter bug.
4. Add Block 2. Fill `_get_meta_info`, then `head`, then `_filtering`.
5. Append the test classes to the existing access-test module, reusing its
   module-level helpers.
6. Create `test_identity_projection_parity.py` and fill its seven bodies.
7. Run `pytest tests/unit/handlers -v`, then the regression gate
   `pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q`.
8. `ruff check navigator_auth/handlers/userattrs.py tests/unit/handlers/`.
9. Confirm the blast radius: `git diff navigator_auth/handlers/userattrs.py`
   shows **no change inside `class UserAccountHandler`** and no change to the
   access-control methods from TASK-123/124 (AC-16).

### FILL IN checklist

- [ ] Block anchors — disambiguate the duplicated `_set_user_id` / `get_userid` lines
- [ ] `_masked_shape` body — rename, derive, isoformat, naive-as-UTC — AC-4, AC-5, AC-6
- [ ] `_model_response` body — redact, reshape, delegate with `fields=None` — AC-1, AC-2, AC-3
- [ ] `_get_meta_info` body — `:meta` + `:sample`, no mutation, `None` otherwise — AC-7, AC-8, AC-9
- [ ] `head` body — `X-Columns` from `public_columns` — AC-10
- [ ] `_filtering` body — `None` early return, `safe_filter`, redacted exit — AC-11..AC-14
- [ ] `TestResponseRedaction` — 6 bodies — AC-1, AC-2, AC-3
- [ ] `TestMetaRedaction` — 5 bodies — AC-7..AC-10
- [ ] `TestSafeFilterWiring` — 5 bodies — AC-11..AC-15
- [ ] `test_identity_projection_parity.py` — 7 bodies — AC-4, AC-5, AC-6

---

## Acceptance Criteria

- [ ] **AC-1** No response from this handler contains `access_token`, `refresh_token`, `id_token` or `key_version` — as a key or as a value anywhere in the serialized body — and list-vs-scalar shape is preserved.
- [ ] **AC-2** The same holds for a superuser reading a foreign row.
- [ ] **AC-3** `?fields=access_token,refresh_token,email` returns `email` only; `?fields=access_token` returns no data rather than the full row.
- [ ] **AC-4** The projection emits `profile` (from `auth_data`, `{}` when null) and derives `expired` correctly for a naive `expires_at` (read as UTC), an aware one, and `None`.
- [ ] **AC-5** The projection's credential-related keys agree with `IdentityStore.masked()`'s, and a change to `masked()`'s key set fails a test in this suite.
- [ ] **AC-6** `has_refresh_token` / `has_id_token` follow the underlying columns both ways, and a row lacking `id_token` yields `False` rather than raising.
- [ ] **AC-7** `:meta` returns the model schema minus every `credential_columns` member; `_get_meta_info` returns `None` for a non-meta request.
- [ ] **AC-8** `:sample` is redacted too.
- [ ] **AC-9** After a `:meta` request, `UserIdentity.schema(as_dict=True)["properties"]` still contains `access_token` — the cached schema is not mutated.
- [ ] **AC-10** `HEAD`'s `X-Columns` header enumerates no credential column.
- [ ] **AC-11** `_filtering` returns `None` when no `_filter` parameter is present.
- [ ] **AC-12** `?_filter=access_token=x` answers **400** and issues no query.
- [ ] **AC-13** `?_filter=auth_provider=git` executes a statement containing `$1` with the value bound, not interpolated.
- [ ] **AC-14** The `_filter` response is redacted like every other read.
- [ ] **AC-15** `ModelView._filtering` is never called from this handler — asserted by patching it to raise.
- [ ] **AC-16** `class UserAccountHandler` is unchanged, TASK-123/124's methods are unchanged, and nothing under `navigator_auth/` outside `userattrs.py` is modified.
- [ ] **AC-17** `pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q` passes and `ruff check navigator_auth/handlers/userattrs.py tests/unit/handlers/` is clean.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/unit/handlers/test_user_identity_handler_access.py tests/unit/handlers/test_identity_projection_parity.py -v
pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q   # regression
ruff check navigator_auth/handlers/userattrs.py tests/unit/handlers/
```

```python
from navigator_auth.handlers.redaction import redact_rows, redact_schema, safe_fields
from navigator_auth.identity.store import IdentityStore   # for masked()'s key set only
```

---

## Agent Instructions

1. **Read the spec** at `sdd/specs/user-identities-ownership-abac.spec.md` —
   §1 G3/G7, §2 Overview layers 3 and 4, §2 Data Models, §3 Module 4 (the
   response rows of the behavioural table), §4 rows
   `test_identity_projection_matches_masked`,
   `test_fields_param_cannot_project_credentials`, the three `safe_filter`
   rows, §5 criteria 3 and 8, §8 Q6.
2. **Check dependencies** — TASK-124 must be in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/user-identities-ownership-abac.json`
   → `"in-progress"`.
4. **Implement** per the blueprint. Note that `head()` is a flagged, bounded
   extension beyond spec §3 Module 4's method list — record it in the
   Completion Note.
5. **Verify** every acceptance criterion, AC-9, AC-15 and AC-16 included.
6. **Move this file** to `sdd/tasks/completed/TASK-125-identity-handler-redaction.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback)
**Date**: 2026-10-24
**Notes**: 119 unit tests in tests/unit/handlers pass; regression green. Extensions beyond blueprint: head() X-Columns redacted (as the task asked); _get_meta_info also handles :info (upstream routes :info through _model_response with a column-keyed dict); _patch/_post/_put/_delete_response overridden with _scrub() so write responses cannot echo token bytes (upstream serializes the written row verbatim). _masked_shape(row, original) takes the original row for has_*_token. With ?fields= the response is the plain allowlist subset (no reshape).

**Deviations from spec**: none
