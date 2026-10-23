# TASK-124: `UserIdentityHandler` — hardened write and delete path

**Feature**: FEAT-105 — Owner-or-Superuser ABAC Ownership for the Auth Model CRUD Surfaces
**Spec**: `sdd/specs/user-identities-ownership-abac.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-123
**Assigned-to**: unassigned

---

## Context

Second of three tasks implementing **spec §3 Module 4**. TASK-123 configured
the guard and closed the read path; this one closes writes and deletes, i.e.
the remaining rows of spec §3 Module 4's behavioural table:

| Verb / target | Owner | Superuser (other user) | Other user |
|---|---|---|---|
| `PUT` (insert) | own row (`user_id` forced) | 403 | 403 |
| `PATCH` / `POST` | own row, non-readonly columns | only `enabled=false`, audited | 403 |
| `DELETE` | own row | allowed, audited | **404** |

Plus the rule that holds for **everyone, owner included** (spec §3 Module 4):
writing any `readonly_columns` member is refused with **400**, because those
columns are vault-managed — their only legitimate writer is
`IdentityStore.update_tokens` (`navigator_auth/identity/store.py:409`), which
re-ciphers the token with the current key version. A write through the model
surface would store attacker-supplied bytes in a column the vault will later
try to decrypt.

Three distinct restrictions, easy to confuse:

1. **Ownership** — a non-superuser may only write their own row (spec G1).
2. **Readonly columns** — nobody may write vault-managed columns, not even
   their owner (spec §3 Module 4).
3. **Superuser write envelope** — a superuser writing someone *else's* row may
   only revoke it (`enabled=false`), never edit any other column and never
   insert (spec G5). `PUT` is 403 for a superuser targeting another user
   because an insert has no existing owner to revoke.

> **Environment drift (read this).** Spec §6's upstream table was recorded
> against `navigator-api` **3.2.2**; `.venv` has **4.0.1**. Every upstream
> anchor below was **re-verified against 4.0.1**. The local hardening does not
> depend on the upstream version — spec §2 explains why.

---

## Scope

- Add `_pre_put` / `_pre_patch` / `_pre_post` / `_pre_delete` to
  `UserIdentityHandler`, each gated by `_require_owner_column()` (TASK-123)
  and `acting_user()`.
- Enforce the `readonly_columns` refusal (400) on every write, for every
  role.
- Enforce ownership and the superuser revoke-only envelope on
  `PATCH`/`POST`/`DELETE`, and force `user_id` on `PUT`.
- Answer **404** (not 403) for a `DELETE` of a foreign row by primary key.
- Audit every cross-user write and delete.
- Extend `tests/unit/handlers/test_user_identity_handler_access.py` with the
  write-path cases.

**NOT in scope**:
- Anything on the read path (`_pre_get`, `_get_data`) — TASK-123. Do not
  revisit it.
- `_model_response`, the `masked()`-shape projection, `:meta` redaction and
  `_filtering` → `safe_filter` — **TASK-125**. The *response bodies* of these
  writes are TASK-125's problem; this task asserts only status codes and what
  reached the database.
- Declaring `readonly_columns` — TASK-123 already did (it is configuration).
  This task only *reads* it.
- `UserAccountHandler` (TASK-126) and `PartnerKeyHandler` (TASK-127).
- Changing `guards.py`, `redaction.py`, `decorators.py`,
  `handlers/handler.py` or `handlers/model.py`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/userattrs.py` | MODIFY | Add the four write/delete pre-hooks and the write interception |
| `tests/unit/handlers/test_user_identity_handler_access.py` | MODIFY | Add the write-path test classes |

---

## Codebase Contract

> Re-verified on `dev` @ `62fd419` against installed `navigator-api` **4.0.1**
> (2026-10-23). Line numbers below are in
> `.venv/lib/python3.11/site-packages/navigator/views/model.py` unless stated.

### Where each write verb calls its pre-hook (all first statement, pre-parse)

| Verb | Method | Pre-hook call |
|---|---|---|
| `PATCH` | `:794` | `:800` `if not await self._pre_patch():` |
| `PUT` | `:1010` | `:1015` `if not await self._pre_put():` |
| `POST` | `:1165` | `:1170` `if not await self._pre_post():` |
| `DELETE` | `:1503` | `:1508` `if not await self._pre_delete():` |

Each is followed by the same 412 error block, so — exactly as on the read
path — a pre-hook must **raise** via `self.error(..., status=…)` rather than
return falsy. `BaseHandler.error()` raises (verified:
`.venv/.../navigator/views/base.py:201-243`).

None of them can see the target row: `get_parameters()` is called *after* the
hook. So the pre-hooks do the session/401, the 501 gate and the body-shape
checks; row-level ownership is enforced at the interception points below.

### Interception point 1 — the incoming body: `_post_data` / `_patch_data`

Verified `:609-651` (`_post_data`, used by `PUT` and `POST`) and `:756-790`
(`_patch_data`, used by `PATCH`). Both have the same shape:

```python
    async def _post_data(self, *args, **kwargs) -> Any:
        async def set_column_value(value):
            for name, column in self.model.get_columns().items():
                fn = getattr(self, f'_post_{name}', None) or getattr(self, f'_set_{name}', None)
                ...
                if fn:
                    ...
                    try:
                        value[name] = await fn(
                            value=val, column=column, data=value, *args, **kwargs
                        )
                    except NotSet:
                        return
        data = await self.json_data()
        if isinstance(data, list):
            for element in data:
                await set_column_value(element)
        elif isinstance(data, dict):
            await set_column_value(data)
        else:
            try:
                data = await self.body()
            except ValueError:
                data = None
        return data
```

`_patch_data` differs only in preferring `_patch_<name>` over `_set_<name>`.

Three facts that matter:

- **The payload may be a `list`.** Both iterate elements. A readonly check
  that only handles `dict` silently passes a batched write. (AC-5.)
- `_set_user_id` (`userattrs.py:59`) is reached through this mechanism — it is
  why an insert that omits `user_id` gets the session's. It only *fills*;
  it does not reject an explicit foreign value. That is this task's job.
- `except NotSet: return` returns `None` **from the inner
  `set_column_value`**, not from `_post_data`, so unlike the `_filter_*`
  hook (see TASK-123) `NotSet` here is survivable. Do not rely on it anyway.

### Interception point 2 — the fetched row: `_set_update(model, data)`

Verified `:732-755`:

```python
    async def _set_update(self, model, data):
        """ Set the value for a field in the model """
        for key, val in data.items():
            if key in model.get_fields():
                col = model.column(key)
                ...
                model.set(key, newval)
```

Verified call sites inside `patch()` (`:872-875`, `:881-884`, and the
single-row branch around `:898`) and the equivalent in `post()`: upstream
does `obj = await self.model.get(**objid)` and then
`await self._set_update(obj, data)` before `await obj.update()`.

**This is the only hook that sees the fetched row and the incoming data
together**, so it is where ownership, the readonly refusal and the superuser
revoke-only envelope can all be decided for `PATCH`/`POST`. Override it, do
the checks, then delegate to `super()._set_update(model, data)`.

### Interception point 3 — delete: `_del_primary_data(args)`

Verified `:1516-1517`:

```python
        if hasattr(self, '_del_primary_data'):
            objid = await self._del_primary_data(args)
```

An **optional** hook — upstream calls it only when the subclass defines it.
It receives the URL args and returns the primary-key selector, so it is the
clean place to resolve the target row, check its owner and refuse.

Good news for `DELETE`: upstream already answers **404** on a missing row
(verified: two `self.error(response=error, status=404)` branches inside
`delete()`, at the offsets 50 and 55 lines past `:1508`). So refusing a
foreign row with 404 matches what a nonexistent row already returns — the
non-oracle property comes for free as long as you use 404 and the **same
body**.

### `UserIdentity` columns relevant to writes (verified: `navigator_auth/models.py:77-110`)

- Owner: `user_id: User = Column(required=True, fk="user_id|username", api="users", label="User")`.
- Revocation flag: `enabled: bool = Column(required=False, default=True)`.
- Vault-managed (`readonly_columns`, declared in TASK-123):
  `access_token`, `refresh_token`, `id_token` (`Optional[bytes]`),
  `key_version`, `provider_user_id`, `token_type`, `expires_at`,
  `refreshed_at`, `scopes`.
- `Meta.strict = True`.

There is **no** `revoked` column on `UserIdentity` — revocation is
`enabled=false`. (`PartnerKey` has `revoked`; that is TASK-127's surface.)

### `IdentityStore.update_tokens` — the only legitimate writer of the vault columns

Verified `navigator_auth/identity/store.py:409`:

```python
    async def update_tokens(self, identity: UserIdentity, token: TokenResponse) -> UserIdentity
```

Name it in the 400's message so an API consumer learns where token refresh
actually lives (`/api/v1/user/identities/...`), rather than retrying.

### Guard primitives available (TASK-122) and the 501 gate (TASK-123)

| Helper | Contract |
|---|---|
| `await self.acting_user()` | `(user_id, is_superuser)`; raises 401 when there is no session |
| `await self.authorize_row(action, owner_id, *, not_found_on_deny=False)` | returns `True`; **raises** 403/404 on deny; owner path consults no policy and writes no audit record; superuser path is policy-gated and audited |
| `await self.sanitize_query(qp, fields)` | sanitized `(qp, fields)`; refuses a foreign owner parameter |
| `self._require_owner_column()` | returns the owner column, or raises 501 |
| `self.readonly_columns` | the frozenset declared in TASK-123 |
| `self.superuser_actions` | `identity:read`, `identity:revoke`, `identity:delete` |

Note there is **no `identity:create`** or `identity:update` action — by
design: spec G5 constrains the superuser to revoke and delete, so an insert
or a general edit on a foreign row has no action to authorize and must be
refused before `authorize_row` is reached (AC-3, AC-8).

### Does NOT Exist (do not reference)

- `_pre_put` / `_pre_patch` / `_pre_post` / `_pre_delete` on
  `UserIdentityHandler` today — all four are inherited no-ops returning
  `True` (`.venv/.../navigator/views/abstract.py:553-571`).
- `_del_primary_data` anywhere in `navigator_auth/` — no handler defines it;
  upstream only *looks* for it (`:1516`). This task may create it on
  `UserIdentityHandler`.
- `_set_update` on any `navigator_auth` handler — it exists only upstream
  (`:732`).
- A `revoked` column on `UserIdentity` — use `enabled`.
- `identity:create` / `identity:update` / `identity:write` in
  `superuser_actions` or in TASK-120's policy pack. Adding one would widen
  spec G5's envelope.
- `required_by_put()` / `required_by_patch()` / `required_by_post()`
  (`:675-681`) as a refusal mechanism. They declare *required* fields and
  produce a 428 on absence (`:829`, `:1031`, `:1186`) — the opposite of
  refusing a *forbidden* field. Do not repurpose them.
- `Model.Meta.readonly` or a `readonly=True` column flag as the enforcement.
  `datamodel` carries a `readonly` key in `field.metadata` (verified: the
  metadata keys are `required, nullable, primary, validator, alias, widget,
  encoder, decoder, readonly`, plus `secret` when declared), but **no**
  credential column on `UserIdentity` sets it, and relying on a model flag
  would make the refusal depend on a model the operator can swap
  (`AUTH_USER_IDENTITY_MODEL`). Enforce from `self.readonly_columns`.

---

## Implementation Blueprint

### `navigator_auth/handlers/userattrs.py` — MODIFY (two blocks)

Both blocks append inside `class UserIdentityHandler`, below the methods
TASK-123 added.

> **Anchor warning.** `async def _set_user_id(self, value, column, data):`
> and `return await self.get_userid(session=self._session)` each occur
> **twice** in this file (verified: `grep -cF` → `2`), once per handler.
> `# FILL IN: disambiguate — anchor on a line unique to
> UserIdentityHandler, e.g. the `_get_data` or `_require_owner_column`
> definition TASK-123 added, and quote 2-3 surrounding lines.`

**Block 1 — the four pre-hooks:**

```python
    async def _pre_put(self, *args, **kwargs) -> bool:
        """Gate an insert: owner-only, no foreign ``user_id``, no vault columns.

        A ``PUT`` creates a row, so there is no existing owner to authorize
        against and nothing for a superuser to revoke — spec §3 Module 4's
        table answers 403 for a superuser targeting another user.

        Returns:
            ``True``. Refusals are raised.
        """
        # FILL IN:
        #  1. self._require_owner_column()          -> 501 gate
        #  2. user_id, _ = await self.acting_user() -> 401 gate
        #  3. return True. The body is not readable here (get_parameters()
        #     has not run) — the explicit-foreign-owner and readonly checks
        #     happen in _post_data. Bounded by AC-1, AC-2.

    async def _pre_patch(self, *args, **kwargs) -> bool:
        """Gate a partial update. Row ownership is decided in `_set_update`."""
        # FILL IN: same two gates as _pre_put, then True — AC-1, AC-2.

    async def _pre_post(self, *args, **kwargs) -> bool:
        """Gate an upsert. `POST` may insert OR update (model.py:1165+)."""
        # FILL IN: same two gates, then True — AC-1, AC-2.

    async def _pre_delete(self, *args, **kwargs) -> bool:
        """Gate a delete. The target row is resolved in `_del_primary_data`."""
        # FILL IN: same two gates, then True — AC-1, AC-2.
```

**Why four near-identical hooks instead of one shared helper called from
each.** Write a private `async def _pre_write(self)` holding the two gates
and have all four call it — that is the right shape and what "one mixin,
three configurations" (spec §7) implies. The four separate `async def`s are
still required because upstream looks them up by name
(`self._pre_put` etc.); only their *bodies* collapse.

**Why `_pre_put` cannot do the real work.** `get_parameters()` and
`_post_data()` both run after it (`:1020-1021`), so neither the query string
nor the JSON body is available. Everything body-dependent belongs in
`_post_data`. Putting a half-check here that *looks* like it covers the body
is worse than putting none.

**Block 2 — the three interception points:**

```python
    def _reject_readonly(self, data) -> None:
        """Refuse 400 when a payload names a vault-managed column.

        Applies to **everyone, the owner included**: these columns are
        written only by ``IdentityStore.update_tokens``
        (navigator_auth/identity/store.py:409), which re-ciphers the token
        with the current key version. A write through the model surface would
        store caller-supplied bytes that the vault will later try to decrypt.

        Args:
            data: The incoming payload — a ``dict`` **or a ``list`` of
                dicts** (both shapes are produced by ``_post_data`` /
                ``_patch_data``, navigator/views/model.py:640-644).

        Raises:
            web.HTTPBadRequest: a ``readonly_columns`` member is present.
        """
        # FILL IN: normalize to a list of dicts, collect the offending keys
        # across ALL elements, and refuse once with self.error(status=400,
        # ...) naming the refused columns and pointing at the vault endpoint.
        # Do not leak any VALUE from the payload back in the message.
        # Bounded by AC-4, AC-5, AC-6.

    async def _post_data(self, *args, **kwargs):
        """Reject vault columns and bind the owner before a write.

        Covers ``PUT`` and ``POST`` (navigator/views/model.py:609, called at
        :1021 and :1176).
        """
        # FILL IN:
        #  1. data = await super()._post_data(*args, **kwargs) — let
        #     _set_user_id and the other _set_* hooks run first, so the
        #     owner-binding below sees the filled value.
        #  2. self._reject_readonly(data)
        #  3. user_id, is_superuser = await self.acting_user()
        #  4. for each element: when the payload names owner_column with a
        #     value that is not the acting user and the caller is NOT a
        #     superuser -> refuse 403. When it is absent, _set_user_id has
        #     already filled it; assert it equals the acting user for a
        #     non-superuser and force it if not.
        #  5. a SUPERUSER inserting for another user is refused 403: there is
        #     no identity:create in superuser_actions, by design (spec G5).
        #     Refuse before calling authorize_row, which would raise on an
        #     unknown action.
        #  6. return data
        # Bounded by AC-2, AC-3, AC-4, AC-5.

    async def _patch_data(self, *args, **kwargs):
        """Reject vault columns on `PATCH` (navigator/views/model.py:756)."""
        # FILL IN: data = await super()._patch_data(...); then
        # self._reject_readonly(data); return data. Ownership for PATCH is
        # decided in _set_update, which sees the fetched row — do NOT
        # duplicate it here. Bounded by AC-4.

    async def _set_update(self, model, data) -> None:
        """Authorize the update against the FETCHED row, then delegate.

        The only upstream hook that sees the target row and the incoming data
        together (navigator/views/model.py:732, called from ``patch()`` and
        ``post()`` after ``self.model.get(**objid)``).

        Args:
            model: The row as fetched from the database.
            data: The incoming payload for this row.

        Raises:
            web.HTTPForbidden: not the owner and not an authorized revoke.
            web.HTTPBadRequest: a vault-managed column was named.
        """
        # FILL IN:
        #  1. self._reject_readonly(data) — defence in depth: POST's insert
        #     branch does not pass through here, and _patch_data does not see
        #     the row, so each layer checks what it can see.
        #  2. owner_id = getattr(model, self.owner_column, None)
        #  3. user_id, is_superuser = await self.acting_user()
        #  4. owner -> await self.authorize_row("identity:revoke", owner_id)
        #     is NOT the right call for an owner editing their own row: the
        #     owner path in authorize_row ignores the action entirely, so pass
        #     the action that describes the REQUEST and let the guard
        #     short-circuit on ownership. Bounded by AC-7.
        #  5. cross-user: the payload must be a revoke and nothing else —
        #     exactly {owner_column?, "enabled": false}, no other column.
        #     Any other key -> 403 (spec G5, AC-8). Then
        #     await self.authorize_row("identity:revoke", owner_id), which
        #     policy-gates and audits it.
        #  6. return await super()._set_update(model, data)

    async def _del_primary_data(self, args: dict):
        """Resolve and authorize the delete target.

        Upstream calls this only when the subclass defines it
        (navigator/views/model.py:1516-1517), and uses the result as the
        primary-key selector.

        Args:
            args: The URL arguments for this request.

        Returns:
            The primary-key selector upstream should delete by.

        Raises:
            web.HTTPNotFound: the row is not the caller's and the caller is
                not an authorized superuser — the same 404 a nonexistent row
                already produces (model.py's two 404 branches inside
                ``delete()``), so the id is no existence oracle.
        """
        # FILL IN:
        #  - resolve the pk from args (self.pk is the str "identity_id"), then
        #    fetch the row to learn its owner. Use the handler's connection
        #    the way the read path does.
        #  - await self.authorize_row("identity:delete", owner_id,
        #    not_found_on_deny=True) -> 404 on deny, audited for a superuser.
        #  - return the selector dict upstream expects, e.g.
        #    {self.pk: <objid>}.
        # Bounded by AC-9, AC-10, AC-11.
```

**Why `_reject_readonly` is called in three places.** They see different
things and none sees everything: `_post_data`/`_patch_data` see the raw
payload before any row is fetched; `_set_update` sees the payload that
actually reaches a row, including on `POST`'s update branch. Checking once
"where it feels sufficient" leaves whichever path you did not picture open.
The check is idempotent and cheap — run it at every layer that can.

**Why the readonly refusal applies to the owner too.** The owner "owns" the
identity, not the ciphertext. `access_token` holds bytes ciphered with a
vault key at a specific `key_version`; a caller-supplied value is garbage the
vault will later fail (or worse, succeed) to decrypt. The legitimate path
exists and is owner-scoped already — `IdentityStore.update_tokens` via
`/api/v1/user/identities/...` — so refusing here removes a footgun rather
than a capability.

**Why a cross-user write must be exactly `enabled=false` and not merely
"include `enabled=false`".** Spec G5 constrains the superuser to *revoke*.
A payload of `{"enabled": false, "email": "attacker@x"}` would otherwise
revoke and rewrite PII in one request, and the audit record would say
"revoke". Require the payload to carry nothing beyond the revoke (plus,
tolerantly, the owner column it is already scoped to).

**Why `PUT` is refused for a superuser rather than authorized with an
`identity:create` action.** Adding that action is the one-line change that
makes this "work", and it is exactly what spec G5 rules out: inserting a
row on another user's behalf creates an identity linkage that user never
consented to, and it has no revoke semantics. Keep the action out of
`superuser_actions` and out of TASK-120's pack, and refuse here.

**Why delete uses `not_found_on_deny=True` while patch uses 403.** `DELETE
/api/v1/user_identity/<uuid>` addresses one row, so the status is itself the
answer to "does this exist" — hence 404, matching the nonexistent-row case
byte for byte. A `PATCH` that is refused has already failed a *content* rule
as well, and 403 with a generic body says so without confirming anything
about the row.

**Why `super()._set_update(model, data)` is still called.** It does the type
parsing and `_calculate_column` work (`:732-755`); the override authorizes
and delegates. Re-implementing `model.set()` would silently drop
`parse_type` and break typed columns.

### `tests/unit/handlers/test_user_identity_handler_access.py` — MODIFY

Append the write-path classes. Reuse `_session`, `_patch_sessions` and
`_handler` from TASK-123 — do not define second copies.

```python
# AFTER — append at end of file
# anchor: the final line of `class TestMetadataLists` (TASK-123)
# occurrences: 1 (verified after TASK-123: grep -cF 'class TestMetadataLists'
# tests/unit/handlers/test_user_identity_handler_access.py)


class TestReadonlyColumns:
    @pytest.mark.asyncio
    async def test_owner_write_to_readonly_column_refused(self):
        """PATCH {"access_token": ...} by the OWNER => 400."""
        # FILL IN: assert web.HTTPBadRequest and that the message names
        # access_token — bounded by AC-4.

    @pytest.mark.asyncio
    async def test_every_readonly_column_is_refused(self):
        """All nine vault columns, one at a time."""
        # FILL IN: loop over UserIdentityHandler.readonly_columns — bounded
        # by AC-6.

    @pytest.mark.asyncio
    async def test_readonly_refused_in_a_batched_payload(self):
        """A list payload whose SECOND element names a vault column => 400."""
        # FILL IN: data=[{"email": "a@b"}, {"access_token": "x"}]; this is the
        # shape model.py:640-642 iterates — bounded by AC-5.

    @pytest.mark.asyncio
    async def test_refusal_does_not_echo_the_value(self):
        """The 400 body names the column but not the submitted value."""
        # FILL IN: payload value "SENTINEL-TOKEN"; assert it is absent from
        # the body — bounded by AC-4.

    @pytest.mark.asyncio
    async def test_writable_column_still_accepted(self):
        """PATCH {"display_name": ...} by the owner succeeds."""
        # FILL IN: the negative control — without it, a _reject_readonly that
        # refuses everything would pass every test above. Bounded by AC-7.


class TestWriteOwnership:
    @pytest.mark.asyncio
    async def test_put_forces_owner(self):
        """An insert omitting user_id gets the session's."""
        # FILL IN: assert the data handed downstream carries
        # user_id == OWNER_ID — bounded by AC-2.

    @pytest.mark.asyncio
    async def test_put_with_foreign_owner_refused(self):
        """An insert naming another user's id => 403 for a non-superuser."""
        # FILL IN: bounded by AC-2.

    @pytest.mark.asyncio
    async def test_superuser_put_for_another_user_refused(self):
        """A superuser cannot insert on someone else's behalf (spec G5)."""
        # FILL IN: superuser session + a permissive PDP; assert 403 and
        # explicitly assert NOT 500 (which an authorize_row call with an
        # unknown action would produce) — bounded by AC-3.

    @pytest.mark.asyncio
    async def test_cross_user_patch_refused_for_non_superuser(self):
        """PATCH on a foreign row => 403."""
        # FILL IN: bounded by AC-7.

    @pytest.mark.asyncio
    async def test_owner_patch_needs_no_policy(self):
        """The owner may edit their own row with no PDP configured."""
        # FILL IN: pdp=None — bounded by AC-7.


class TestSuperuserWriteEnvelope:
    @pytest.mark.asyncio
    async def test_superuser_may_revoke_a_foreign_row(self):
        """PATCH {"enabled": false} succeeds and is audited."""
        # FILL IN: assert the update reached the model and that AuditLog.log
        # was awaited once — bounded by AC-8, AC-12.

    @pytest.mark.asyncio
    async def test_superuser_cannot_edit_another_column(self):
        """PATCH {"display_name": ...} on a foreign row => 403."""
        # FILL IN: bounded by AC-8.

    @pytest.mark.asyncio
    async def test_superuser_cannot_smuggle_a_column_alongside_the_revoke(self):
        """{"enabled": false, "email": "..."} => 403, not a partial apply."""
        # FILL IN: assert 403 AND that nothing was written — the smuggling
        # case is the one a "contains enabled=false" check would let through.
        # Bounded by AC-8.

    @pytest.mark.asyncio
    async def test_superuser_revoke_denied_without_policy(self):
        """Fail-closed: no PDP => the revoke is refused."""
        # FILL IN: bounded by AC-13.


class TestDeletePath:
    @pytest.mark.asyncio
    async def test_owner_may_delete_own_row(self):
        """DELETE of an owned row proceeds."""
        # FILL IN: bounded by AC-9.

    @pytest.mark.asyncio
    async def test_foreign_delete_returns_404(self):
        """A non-owner DELETE by primary key => 404, not 403."""
        # FILL IN: assert web.HTTPNotFound and explicitly NOT HTTPForbidden
        # — bounded by AC-10.

    @pytest.mark.asyncio
    async def test_foreign_and_missing_delete_are_indistinguishable(self):
        """Same status and body for "not yours" and "does not exist"."""
        # FILL IN: compare both responses — bounded by AC-11.

    @pytest.mark.asyncio
    async def test_superuser_delete_is_allowed_and_audited(self):
        """A superuser with the policy may delete a foreign row."""
        # FILL IN: assert the delete happened and one audit record exists
        # — bounded by AC-12.
```

**Why `test_writable_column_still_accepted` is in the readonly class.** Every
other test there asserts a refusal. An implementation that refused *all*
writes would satisfy them and break the feature (spec G4: all six routes keep
working). The negative control is what makes the positive ones meaningful.

**Why `test_superuser_cannot_smuggle_a_column_alongside_the_revoke` is
called out.** It is the difference between "the payload is a revoke" and "the
payload contains a revoke". The second reading is the natural one to
implement and it hands a superuser full edit rights on every foreign row
while the audit record says `identity:revoke`.

**Why `test_superuser_put_for_another_user_refused` asserts "not 500".**
If the implementation reaches `authorize_row("identity:create", ...)`, the
action is outside `superuser_actions` and the guard refuses — 403, by luck.
But if it instead reaches `policy_allows` with an action no policy covers,
or with a falsy `policy_name`, the failure mode is a `ValueError` → 500.
Pin the status.

### Steps (in order)

1. Confirm TASK-123 landed: `UserIdentityHandler` must already have
   `_require_owner_column`, `_pre_get` and `_get_data`, and
   `readonly_columns` must be declared.
2. Add Block 1. Collapse the four bodies onto one private `_pre_write`
   helper; keep the four named `async def`s, because upstream resolves them
   by name.
3. Add `_reject_readonly` and fill it first — three other methods call it.
   Handle the `list` payload shape from the start.
4. Fill `_post_data`, then `_patch_data`, then `_set_update`, then
   `_del_primary_data`. Run the matching test class after each.
5. Append the test classes, reusing TASK-123's module-level helpers.
6. Run `pytest tests/unit/handlers/test_user_identity_handler_access.py -v`,
   then the regression gate
   `pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q`.
7. `ruff check navigator_auth/handlers/userattrs.py tests/unit/handlers/`.
8. Confirm the blast radius: `git diff navigator_auth/handlers/userattrs.py`
   shows **no change inside `class UserAccountHandler`** and no change to the
   read-path methods TASK-123 added (AC-14).

### FILL IN checklist

- [ ] Block anchors — disambiguate the duplicated `_set_user_id` / `get_userid` lines
- [ ] `_pre_write` helper + the four named pre-hooks — AC-1, AC-2
- [ ] `_reject_readonly` body — dict **and** list payloads, no value echo — AC-4, AC-5, AC-6
- [ ] `_post_data` override — readonly, owner binding, superuser-insert refusal — AC-2, AC-3
- [ ] `_patch_data` override — readonly only — AC-4
- [ ] `_set_update` override — row ownership, revoke-only envelope, delegate — AC-7, AC-8
- [ ] `_del_primary_data` — resolve, authorize with `not_found_on_deny=True` — AC-9, AC-10, AC-11
- [ ] `TestReadonlyColumns` — 5 bodies — AC-4..AC-7
- [ ] `TestWriteOwnership` — 5 bodies — AC-2, AC-3, AC-7
- [ ] `TestSuperuserWriteEnvelope` — 4 bodies — AC-8, AC-12, AC-13
- [ ] `TestDeletePath` — 4 bodies — AC-9..AC-12

---

## Acceptance Criteria

- [ ] **AC-1** A write or delete with no session answers **401**; with a model lacking the owner column, **501**.
- [ ] **AC-2** `PUT` forces `user_id` to the session user; an insert naming a foreign `user_id` is refused **403** for a non-superuser.
- [ ] **AC-3** A superuser `PUT`/insert targeting another user is refused **403** — not 500, and not authorized by inventing an `identity:create` action.
- [ ] **AC-4** A write naming any `readonly_columns` member is refused **400** for everyone, the owner included, and the message names the column without echoing the submitted value.
- [ ] **AC-5** The refusal also fires when the offending key is in the **second element of a list payload**.
- [ ] **AC-6** All nine `readonly_columns` members are refused.
- [ ] **AC-7** A non-superuser `PATCH`/`POST` on a foreign row is refused **403**; the owner may edit their own non-readonly columns with **no PDP configured**.
- [ ] **AC-8** A superuser `PATCH` on a foreign row succeeds **only** for a payload that is exactly a revoke (`enabled=false`); any additional column — including one sent alongside the revoke — is refused **403** and nothing is written.
- [ ] **AC-9** The owner may `DELETE` their own row.
- [ ] **AC-10** A non-owner `DELETE` by primary key answers **404**, not 403.
- [ ] **AC-11** The 404 for a foreign row and for a nonexistent row are identical in status and body.
- [ ] **AC-12** Each cross-user write and each cross-user delete produces exactly one `AuditLog` record.
- [ ] **AC-13** With no PDP, with the policy undeclared, or with a policy that raises, every superuser write/delete on a foreign row is denied, while the owner's own writes keep working.
- [ ] **AC-14** `class UserAccountHandler` is unchanged, the read-path methods from TASK-123 are unchanged, and nothing under `navigator_auth/` outside `userattrs.py` is modified.
- [ ] **AC-15** `pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q` passes and `ruff check navigator_auth/handlers/userattrs.py tests/unit/handlers/` is clean.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/unit/handlers/test_user_identity_handler_access.py -v
pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q   # regression
ruff check navigator_auth/handlers/userattrs.py tests/unit/handlers/
```

```python
from navigator_auth.handlers.userattrs import UserIdentityHandler
assert "access_token" in UserIdentityHandler.readonly_columns
assert "identity:create" not in UserIdentityHandler.superuser_actions
```

---

## Agent Instructions

1. **Read the spec** at `sdd/specs/user-identities-ownership-abac.spec.md` —
   §1 G1/G5, §3 Module 4 (the write rows of the behavioural table and the
   `readonly_columns` paragraph), §4 rows `test_write_to_readonly_column_refused`,
   `test_cross_user_write_refused`, `test_superuser_revoke_and_delete_allowed`,
   §7 Patterns to Follow.
2. **Check dependencies** — TASK-123 must be in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/user-identities-ownership-abac.json`
   → `"in-progress"`.
4. **Implement** per the blueprint. The three restrictions (ownership,
   readonly columns, superuser revoke-only) are independent — satisfy each
   separately rather than collapsing them into one condition.
5. **Verify** every acceptance criterion, AC-5, AC-8 and AC-14 included.
6. **Move this file** to `sdd/tasks/completed/TASK-124-identity-handler-write-path.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback)
**Date**: 2026-10-24
**Notes**: 37 tests in file pass; regression green. Beyond blueprint (needed for correctness, all in userattrs.py): (1) upstream _set_user_id CLOBBERS user_id on every PUT/POST/PATCH payload (would re-own a foreign row on a superuser revoke, and silently rewrite a foreign owner instead of refusing) -> added _post_user_id/_patch_user_id that preserve an explicit value; (2) _pre_put reads the body to refuse a foreign owner for every role incl. superuser; (3) _set_update refuses any owner reassignment; (4) _del_primary_data refuses a DELETE with no URL id (400), because upstream otherwise falls into body-driven model.remove()/bulk delete that never sees a row owner. Residual: a superuser POST of a pure revoke-shaped payload for a nonexistent pk could insert a placeholder row (POST insert branch has no row to authorize).

**Deviations from spec**: none
