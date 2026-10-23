# TASK-126: Harden `UserAccountHandler` with the same guard

**Feature**: FEAT-105 — Owner-or-Superuser ABAC Ownership for the Auth Model CRUD Surfaces
**Spec**: `sdd/specs/user-identities-ownership-abac.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-121, TASK-125
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 5**. `auth.user_accounts` has the identical
unrestricted-CRUD shape as `auth.user_identities`: `UserAccountHandler`
(`handlers/userattrs.py:20`) sits on the same `ModelView` base, is mounted at
`/api/v1/user_accounts/{id:.*}` and `/api/v1/user_accounts{meta}`
(`handlers/__init__.py:39-46`), and has no ownership check — only a
`_set_user_id` that *fills* `user_id` on writes that omit it
(`userattrs.py:28`).

`UserAccount` holds **no token material**, so there is no credential
redaction and no `readonly_columns` here. What it does hold is PII —
`provider`, `uid`, `address`, the `account` dict — and the ownership hole is
identical: any session can read, edit or delete another user's social
accounts, or list the whole table with `?user_id=<victim>`.

Spec §3 Module 5: *"Behaviour mirrors Module 4's table, minus the credential
rows (this model has none) and with `account:*` actions."*

**Why this is one task where Module 4 took three.** The three hard parts of
Module 4 are gone here: no credential columns to redact, no vault-managed
columns to refuse, and no `masked()` shape to match. What remains is the same
ownership/policy/filter wiring with a different, smaller column set — and the
mechanics were resolved and verified in TASK-123/124/125, which this task
copies. Spec §3's delegation table says exactly this: *"Module 5 —
**Yes**, after Module 4 — same pattern as Module 4 plus a mechanical
parameterization; column sets given."*

**The `_set_address` parameterization (spec G9) is NOT here — TASK-121 did
it.** Spec §3 Module 5 bundles the two, but the injection fix is independent
of the guard and lands first so the sink closes sooner.

> **Environment drift (read this).** Spec §6's upstream `navigator` table was
> recorded against `navigator-api` **3.2.2**; `.venv` has **4.0.1**. The
> upstream anchors you need are all re-verified in TASK-123/124/125's
> contracts — read them rather than the spec's §6 table.

---

## Scope

- Make `UserAccountHandler` inherit `OwnerOrSuperuserGuard` **before**
  `ModelHandler` and declare the guard attributes for this surface.
- Mirror TASK-123/124/125's wiring with the `account:*` actions: the owner-
  column gate, the read-path ownership binding, the four write/delete
  pre-hooks and interception points, the allowlist projection, the `:meta` /
  `:sample` / `head()` column set, and `_filtering` → `safe_filter`.
- Add `tests/unit/handlers/test_user_account_handler_access.py`.

**NOT in scope**:
- `social_network` / `_set_address` — **TASK-121**. Those lines are already
  parameterized when this task starts; leave them exactly as TASK-121 left
  them, and do not re-test them (TASK-121 owns
  `test_user_account_set_address.py`).
- `class UserIdentityHandler` in the same file — do not touch it.
- `PartnerKeyHandler` — TASK-127.
- `readonly_columns`. `UserAccount` has no vault-managed column; declaring an
  empty set is fine, inventing members is not.
- A `masked()`-shape projection. There is no second `user_accounts` surface
  to stay parity with, and no token material to summarize into booleans. The
  projection here is a plain allowlist.
- Changing `guards.py`, `redaction.py`, `decorators.py`,
  `handlers/handler.py` or `handlers/model.py`.
- The hardcoded `auth.` schema prefix in `social_network` (TASK-121's
  out-of-scope note).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/userattrs.py` | MODIFY | Rewrite the `UserAccountHandler` class body (guard + hooks) |
| `tests/unit/handlers/test_user_account_handler_access.py` | CREATE | Access, write, redaction and filter tests |

---

## Codebase Contract

> Re-verified on `dev` @ `62fd419` against installed `navigator-api` **4.0.1**
> (2026-10-23).

### `UserAccountHandler` today (verified: `navigator_auth/handlers/userattrs.py:20-51`)

```python
class UserAccountHandler(ModelHandler):
    model: Any = UserAccount
    name: str = "User Account"
    pk: str = "account_id"
    social_network: str = """
    SELECT social_url FROM auth.social_networks WHERE social_network = '{provider}'
    """

    async def _set_user_id(self, value, column, data):
        return await self.get_userid(session=self._session)

    async def _set_address(self, value, column, data):
        try:
            userid = data['uid']
        except KeyError:
            return self.error(
                reason=f"Invalid User ID for {self.name}", status=410
            )
        try:
            provider = data['provider']
        except KeyError:
            provider = None
        if provider:
            try:
                async with await self.handler(request=self.request) as conn:
                    qry = self.social_network.format(provider=provider)
                    result = await conn.fetchval(qry, column='social_url')
                    if result:
                        return result.format(uid=userid)
            except DriverError:
                pass
        return None
```

**By the time this task runs, TASK-121 has changed `social_network` to use
`$1` and the two statement lines inside `_set_address`.** Re-read the file
before anchoring; do not re-apply TASK-121's edit and do not revert it.

Note `UserAccountHandler` has **no `model_name`** (unlike
`UserIdentityHandler`, which carries `AUTH_USER_IDENTITY_MODEL`). So the
model is not swappable by configuration here — but keep the owner-column gate
anyway, for symmetry and because `Meta.pk` can still redirect the primary key
(`navigator_auth/handlers/model.py:32-33` does this for the local base).

### `UserAccount` — the model (verified: `navigator_auth/models.py:295-313`)

```python
class UserAccount(Model):
    """Social Accounts from User"""
    account_id: UUID = Column(
        required=False, primary_key=True, db_default="auto", repr=False
    )
    user_id: User = Column(required=True)
    provider: str = Column(required=True)
    uid: str = Column(required=False)
    address: str = Column(required=False, repr=False)
    account: Optional[dict] = Column(required=False, default_factory=dict)
    created_at: datetime = Column(required=False, default=datetime.now, repr=False)

    class Meta:
        name = "user_accounts"
        schema = AUTH_DB_SCHEMA
        strict = True
        connection = None
        frozen = False
```

Seven columns, all seven in `public_columns`. **No column declares
`secret=True`**, so upstream's `_hidden` is empty here too
(`.venv/.../navigator/views/model.py:178`) — the same reason the allowlist
override is required.

There is **no** `enabled` and **no** `revoked` column on `UserAccount`. See
the `account:revoke` note below.

### The guard configuration for this surface (spec §2 Data Models)

| Attribute | Value |
|---|---|
| `owner_column` | `"user_id"` |
| `credential_columns` | `frozenset()` — this model has none |
| `public_columns` | `account_id`, `user_id`, `provider`, `uid`, `address`, `account`, `created_at` |
| `policy_name` | `"user_accounts_admin_access"` |
| `superuser_actions` | `account:read`, `account:revoke`, `account:delete` |

Every name verified against `navigator_auth/models.py:297-308`. The policy
name and the three actions must match TASK-120's pack exactly.

### CRITICAL — `account:revoke` has no column to set

Spec §3 Module 5 gives `superuser_actions` as
`{account:read, account:revoke, account:delete}`, mirroring Module 4. But
`UserAccount` has **no `enabled` and no `revoked` column** (verified above),
so there is nothing for a superuser to flip. Consequences:

- Keep `account:revoke` in `superuser_actions` and in the policy — it is the
  spec's declared envelope and TASK-120's pack already ships it.
- A superuser `PATCH`/`POST` on a **foreign** account therefore has no
  permitted payload: every column is a plain attribute, none is a revocation
  flag. **Refuse every cross-user write with 403** and let `account:delete`
  be the superuser's only mutating power on a foreign row (AC-8).
- `# FILL IN: confirm this reading against spec §3 Module 5's "Behaviour
  mirrors Module 4's table" before implementing, and record the conclusion
  in the Completion Note.` If the intended reading is instead that a
  superuser may edit a foreign account, that is a spec question, not an
  implementation choice — **ESCALATE** rather than deciding it in code.

### The wiring to mirror — read these three task files, not the spec's §6

| Concern | Mechanism and verified anchors |
|---|---|
| owner-column gate (501) | `_require_owner_column()` — TASK-123 blueprint |
| read ownership | override `_get_data(qp, args)`; the `_filter_<column>` hook cannot carry the superuser case (`NotSet` → `**None`, and the `filter(**qp, **_filter)` duplicate-key collision at `.venv/.../navigator/views/model.py:413-414, 446`) — TASK-123 contract |
| `?user_id=` sanitation | `await self.sanitize_query(qp, fields)` in `_pre_get` — TASK-122 |
| PK miss → 404 | upstream answers 204 `no_content` for a GET (`.venv/.../navigator/views/model.py:587-592`); shape it — TASK-123 |
| write pre-hooks | `_pre_put` `:1015`, `_pre_patch` `:800`, `_pre_post` `:1170`, `_pre_delete` `:1508`, each the first statement, pre-parse; **raise** via `self.error()` (`.venv/.../navigator/views/base.py:201-243`) rather than return falsy (which yields 412) — TASK-124 |
| body interception | `_post_data` `:609` (PUT/POST), `_patch_data` `:756` (PATCH); both iterate **list** payloads (`:640-644`) — TASK-124 |
| row interception | `_set_update(model, data)` `:732`, called after `self.model.get(**objid)` — TASK-124 |
| delete target | `_del_primary_data(args)`, called only if defined (`:1516-1517`); upstream already 404s a missing row — TASK-124 |
| projection | override `_model_response` `:237`; upstream's `_visible_columns` `:203` is driven by the empty `_hidden` — TASK-125 |
| `:meta` / `:sample` | `_get_meta_info` (`.venv/.../navigator/views/abstract.py:470-519`) returns the raw schema, bypassing `_model_response` — TASK-125 |
| `head()` `X-Columns` | `.venv/.../navigator/views/abstract.py:449-467` — TASK-125 |
| `?_filter=` | override `_filtering` `:479` → `self.safe_filter(expr)`; must return `None` when no `_filter` (`:568-570`) — TASK-122/125 |

### `redact_schema` and the cached schema

`UserAccount.schema(as_dict=True)` is memoized and shared exactly as
`UserIdentity`'s is (same `__computed_schema__` mechanism). With
`credential_columns = frozenset()`, `redact_schema(schema, frozenset())`
strips nothing — which is correct, and is why the `:meta` override here is
about the **`public_columns` column set**, not about credentials.
`# FILL IN: decide whether :meta should be narrowed to public_columns on this
surface (all seven columns are public, so it is a no-op today) or left to
redact_schema with an empty credential set — bounded by AC-9; either is
defensible, pick one and say why.`

### `_set_user_id` and `_set_address` must keep working

`_set_user_id` (`userattrs.py:28`) is reached through `_post_data` /
`_patch_data`'s `_set_<column>` lookup (`.venv/.../navigator/views/model.py:618`,
`:765`). `_set_address` (`userattrs.py:31`, post-TASK-121) is reached the same
way. If the `_post_data` override calls `super()._post_data(...)` first — as
TASK-124's blueprint does — both still run. **Do not skip the `super()` call**
(AC-11).

### Existing test helpers to reuse

`tests/unit/handlers/test_user_identity_handler_access.py` (TASK-123) defines
module-level `FakeSession`, `_session`, `_patch_sessions` and `_handler`.
Those are private to that module; **copy** the pattern rather than importing
across test modules — the existing suite does the same
(`tests/unit/identity/test_identity_handlers.py:12-60` re-declares its own).
The session patch targets are `navigator_auth.decorators.get_session` and
`navigator_auth.handlers.guards.get_session`.

### Does NOT Exist (do not reference)

- `_pre_get` / `_pre_put` / `_pre_patch` / `_pre_post` / `_pre_delete` /
  `_get_data` / `_set_update` / `_del_primary_data` / `_model_response` /
  `_get_meta_info` / `_filtering` / `_require_owner_column` on
  `UserAccountHandler` today — only `_set_user_id` and `_set_address` exist
  (`userattrs.py:28`, `:31`).
- An `enabled` or `revoked` column on `UserAccount` — see the
  `account:revoke` note.
- `credential_columns` members for this surface. The model has none. Do not
  put `address` or `account` in it just because they are PII: that would
  remove them from every response and break spec G4 (routes keep working).
- A `model_name` / `AUTH_USER_ACCOUNT_MODEL` setting. `navigator_auth/conf.py`
  has `AUTH_USER_IDENTITY_MODEL` (`:150`) and no account equivalent.
- `tests/unit/handlers/test_user_account_set_address.py` — TASK-121 owns it.
  Do not add cases to it, and do not duplicate its cases here.
- `VwUserIdentity` — unrelated to this surface (it is the identity view).

---

## Implementation Blueprint

### `navigator_auth/handlers/userattrs.py` — MODIFY (two blocks)

**Block 1 — the class declaration and configuration:**

```python
# AFTER — replace the `class UserAccountHandler(ModelHandler):` line and the
# three attribute lines beneath it (NOT `social_network`, which TASK-121 owns)
# anchor (verified: navigator_auth/handlers/userattrs.py:20-23)
# occurrences: 1 (verified: grep -cF 'class UserAccountHandler(ModelHandler):' navigator_auth/handlers/userattrs.py)

class UserAccountHandler(OwnerOrSuperuserGuard, ModelHandler):
    """Owner-or-superuser CRUD over ``auth.user_accounts`` (FEAT-105).

    Same guard as ``UserIdentityHandler``, different column set. This model
    carries no token material, so ``credential_columns`` is empty and the
    projection is a plain allowlist — the ownership binding, the policy-gated
    admin path, the parameterized ``_filter`` and the audit trail are
    identical.
    """

    model: Any = UserAccount                    # verified: navigator_auth/models.py:297
    name: str = "User Account"
    pk: str = "account_id"

    owner_column: str = "user_id"
    #: No token material on this model — see spec §2 Data Models.
    credential_columns = frozenset()
    public_columns = frozenset({
        "account_id", "user_id", "provider", "uid", "address", "account",
        "created_at"})
    policy_name: str = "user_accounts_admin_access"
    superuser_actions = frozenset({
        "account:read", "account:revoke", "account:delete"})

    # Per-subclass copies. Harmless on navigator-api 4.0.1 (already per
    # instance: navigator/views/model.py:141,180-182) and protective on
    # 3.2.2, where ModelView mutated these CLASS-level lists in place.
    # Never RELY on _hidden: no column on UserAccount declares secret=True.
    _hidden: list = []
    _required: list = []
    _primaries: list = []

    # NOTE: `social_network` and `_set_address` follow, parameterized by
    # TASK-121 ($1 bound). Leave them untouched.
```

**Why `credential_columns` is declared empty rather than omitted.** The
mixin already defaults it to `frozenset()` (TASK-122), so this line changes
nothing at runtime. It is there as documentation: a reader comparing the
three surfaces sees that the emptiness is a verified property of the model,
not an oversight. The comment carries the reason.

**Why `address` and `account` stay in `public_columns` though they are PII.**
Spec G4 requires all six routes to keep working with no client-visible
breakage beyond the removal of credential columns. `address` is the whole
point of `_set_address`; removing it from responses would break the surface
while hiding nothing that is not already the owner's own data.

**Block 2 — the hooks:**

```python
# AFTER — append inside `class UserAccountHandler`, below `_set_address`
# anchor: the `return None` that ends _set_address
# occurrences: FILL IN — verify with
#   grep -cF '        return None' navigator_auth/handlers/userattrs.py
# and if it is > 1, disambiguate by quoting the `except DriverError:` /
# `pass` / `return None` trio that ends _set_address.

    # Mirror TASK-123/124/125's implementations with this surface's actions.
    # The mechanics, anchors and reasoning are in those three task files;
    # what changes here is only the action strings and the column set.

    def _require_owner_column(self) -> str:
        """Return the owner column, or refuse the request with 501."""
        # FILL IN: as TASK-123 — AC-10.

    async def _pre_get(self, *args, **kwargs) -> bool:
        """Gate the read path: 501, 401, foreign-owner-param refusal."""
        # FILL IN: as TASK-123 — AC-1, AC-4, AC-10.

    async def _get_data(self, qp: dict, args: dict):
        """Bind every read to an owner; widen + authorize for a superuser."""
        # FILL IN: as TASK-123, with action "account:read"; shape a bound PK
        # miss to 404 — AC-2, AC-3, AC-5, AC-6, AC-7.

    async def _pre_put(self, *args, **kwargs) -> bool: ...
    async def _pre_patch(self, *args, **kwargs) -> bool: ...
    async def _pre_post(self, *args, **kwargs) -> bool: ...
    async def _pre_delete(self, *args, **kwargs) -> bool: ...
        # FILL IN: as TASK-124 — one shared private helper holding the 501 and
        # 401 gates, four named `async def`s because upstream resolves them by
        # name — AC-1, AC-10.

    async def _post_data(self, *args, **kwargs):
        """Bind the owner on insert/upsert. Covers PUT and POST."""
        # FILL IN: as TASK-124, MINUS the readonly refusal (no vault columns
        # here). MUST call super()._post_data(...) first so _set_user_id and
        # _set_address still run — AC-2, AC-11.

    async def _set_update(self, model, data) -> None:
        """Authorize the update against the fetched row, then delegate."""
        # FILL IN: as TASK-124, with one difference — there is no revocation
        # column on UserAccount, so a cross-user write has NO permitted
        # payload: refuse every non-owner PATCH/POST with 403. See the
        # `account:revoke` note in the contract, and ESCALATE if that reading
        # is wrong rather than guessing — AC-7, AC-8.

    async def _del_primary_data(self, args: dict):
        """Resolve and authorize the delete target; 404 on deny."""
        # FILL IN: as TASK-124, action "account:delete",
        # not_found_on_deny=True — AC-12, AC-13.

    async def _model_response(
        self, response: Any, fields: list = None,
        headers: dict = None, status: int = 200,
    ):
        """Project through ``public_columns``, then delegate.

        Required even on navigator-api 4.0.1: upstream's projection is driven
        by ``_hidden`` (navigator/views/model.py:203-229), derived from
        ``secret=True`` columns only (:178) — and no column on
        ``UserAccount`` declares it, so upstream returns the full row.
        """
        # FILL IN: as TASK-125 but with NO masked()-shape reshape — a plain
        # safe_fields + redact_rows, then super() with fields=None — AC-14,
        # AC-15.

    async def _get_meta_info(self, meta: str, fields: list):
        """Bound the ``:meta`` / ``:sample`` column set; ``None`` otherwise."""
        # FILL IN: as TASK-125. Never mutate the schema payload: it is the
        # model's CACHED dict — AC-9.

    async def head(self):
        """Keep ``X-Columns`` to the allowlisted column set."""
        # FILL IN: as TASK-125 — AC-16.

    async def _filtering(self, queryparams: dict):
        """Route ``?_filter=`` through the guard's parameterized safe filter.

        Required even on navigator-api 4.0.1, whose ``_filtering``
        (model.py:479-547) is parameterized but allowlists "a real column not
        in ``_hidden``" (empty here) and applies no ownership predicate.
        """
        # FILL IN: as TASK-125 — return None when no `_filter`, else
        # safe_filter(expr) through _model_response — AC-17, AC-18, AC-19.
```

**Why this blueprint points at the other task files instead of restating
their bodies.** The mechanics were established and verified there; copying
them into prose here would create two sources of truth that drift in review.
What this surface genuinely decides — the column set, the three action
strings, the empty `credential_columns`, the absence of a revocation column
and of a `masked()` shape — is stated explicitly above. Read TASK-123,
TASK-124 and TASK-125 before starting; they are in
`sdd/tasks/completed/` by the time this runs.

**Why `super()._post_data(...)` must be called.** `_set_user_id` and
`_set_address` are invoked by upstream's `_post_data` through its
`_set_<column>` lookup (`.venv/.../navigator/views/model.py:618`). An
override that reads `self.json_data()` itself would silently stop filling
`user_id` and stop resolving `address` — breaking the surface while every
access-control test still passes.

### `tests/unit/handlers/test_user_account_handler_access.py` — CREATE

```python
"""Access control and redaction on UserAccountHandler (FEAT-105, TASK-126).

Spec §4's Module-5 rows. `_set_address`'s parameterization is TASK-121's and
is tested in test_user_account_set_address.py — do not duplicate it here.
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
PUBLIC = frozenset({
    "account_id", "user_id", "provider", "uid", "address", "account",
    "created_at",
})


class FakeSession(dict):
    def decode(self, key):
        return self.get(key)


def _session(user_id=OWNER_ID, groups=("users",)):
    # FILL IN: mirror TASK-123's helper.

def _patch_sessions(session):
    # FILL IN: patch navigator_auth.decorators.get_session AND
    # navigator_auth.handlers.guards.get_session.

def _handler(method="GET", path="/api/v1/user_accounts/abc", match_info=None,
             pdp=None):
    # FILL IN: mirror TASK-123's helper for UserAccountHandler.


class TestConfiguration:
    def test_guard_precedes_the_base_in_the_mro(self):
        """OwnerOrSuperuserGuard must win over ModelView."""
        # FILL IN: compare __mro__ indexes — bounded by AC-1.

    def test_credential_columns_is_empty(self):
        """This model carries no token material."""
        # FILL IN: assert UserAccountHandler.credential_columns == frozenset()
        # — bounded by AC-15.

    def test_public_columns_covers_every_model_column(self):
        """All seven columns are public — nothing silently disappears."""
        # FILL IN: assert set(UserAccount.get_columns()) == PUBLIC. This is
        # the guard against an allowlist typo quietly dropping a column from
        # every response (spec G4) — bounded by AC-15.

    def test_policy_name_and_actions_match_the_pack(self):
        """Names agree with TASK-120's auth_model_admin_access.yaml."""
        # FILL IN: assert the policy name and the three account:* actions
        # — bounded by AC-20.

    def test_hidden_lists_are_per_subclass(self):
        """_hidden is not shared with ModelView."""
        # FILL IN: bounded by AC-21.


class TestReadPath:
    @pytest.mark.asyncio
    async def test_unauthenticated_read_is_401(self): ...
        # FILL IN — AC-1
    @pytest.mark.asyncio
    async def test_get_forces_owner_filter(self): ...
        # FILL IN — AC-2
    @pytest.mark.asyncio
    async def test_get_foreign_row_returns_404(self): ...
        # FILL IN — AC-6
    @pytest.mark.asyncio
    async def test_foreign_and_missing_are_indistinguishable(self): ...
        # FILL IN — AC-7
    @pytest.mark.asyncio
    async def test_get_foreign_user_id_param_refused(self): ...
        # FILL IN: assert 403 and explicitly NOT 400 — AC-4
    @pytest.mark.asyncio
    async def test_superuser_may_read_a_foreign_row_and_is_audited(self): ...
        # FILL IN — AC-3, AC-5
    @pytest.mark.asyncio
    async def test_superuser_denied_without_policy_but_owner_is_not(self): ...
        # FILL IN — AC-3
    @pytest.mark.asyncio
    async def test_model_without_owner_column_fails_closed(self): ...
        # FILL IN — AC-10


class TestWritePath:
    @pytest.mark.asyncio
    async def test_put_forces_owner(self): ...
        # FILL IN — AC-2
    @pytest.mark.asyncio
    async def test_put_with_foreign_owner_refused(self): ...
        # FILL IN — AC-2
    @pytest.mark.asyncio
    async def test_set_user_id_and_set_address_still_run(self):
        """The _post_data override must delegate to super()."""
        # FILL IN: assert user_id was filled AND that _set_address was
        # invoked (patch it and check). Without this, an override that stops
        # calling super() passes every access test and breaks the feature
        # — bounded by AC-11.
    @pytest.mark.asyncio
    async def test_cross_user_patch_refused(self): ...
        # FILL IN — AC-7, AC-8
    @pytest.mark.asyncio
    async def test_superuser_cross_user_patch_refused(self):
        """No revocation column exists, so a superuser cannot write either."""
        # FILL IN: superuser + permissive PDP; assert 403 — bounded by AC-8.
    @pytest.mark.asyncio
    async def test_owner_patch_needs_no_policy(self): ...
        # FILL IN — AC-7
    @pytest.mark.asyncio
    async def test_owner_may_delete_own_row(self): ...
        # FILL IN — AC-12
    @pytest.mark.asyncio
    async def test_foreign_delete_returns_404(self): ...
        # FILL IN: assert 404 and NOT 403 — AC-13
    @pytest.mark.asyncio
    async def test_superuser_delete_allowed_and_audited(self): ...
        # FILL IN — AC-12, AC-5


class TestProjectionAndFilter:
    @pytest.mark.asyncio
    async def test_response_is_restricted_to_public_columns(self):
        """A row carrying an extra attribute does not leak it."""
        # FILL IN: give the row double a column outside PUBLIC and assert it
        # is absent — this is what proves the allowlist is applied at all,
        # given that nothing on this model is secret. Bounded by AC-14.
    @pytest.mark.asyncio
    async def test_fields_param_is_intersected(self): ...
        # FILL IN — AC-14
    @pytest.mark.asyncio
    async def test_meta_is_bounded(self): ...
        # FILL IN — AC-9
    @pytest.mark.asyncio
    async def test_meta_does_not_mutate_the_cached_schema(self):
        """UserAccount.schema(as_dict=True) is memoized and shared."""
        # FILL IN — AC-9
    @pytest.mark.asyncio
    async def test_head_x_columns_is_bounded(self): ...
        # FILL IN — AC-16
    @pytest.mark.asyncio
    async def test_filter_on_unknown_column_is_400(self): ...
        # FILL IN — AC-18
    @pytest.mark.asyncio
    async def test_filter_on_public_column_is_parameterized(self): ...
        # FILL IN: "$1" in the SQL, the value bound — AC-19
    @pytest.mark.asyncio
    async def test_filter_ands_owner_predicate(self): ...
        # FILL IN — AC-19
    @pytest.mark.asyncio
    async def test_filtering_returns_none_without_the_parameter(self): ...
        # FILL IN: a non-None return would make EVERY GET answer with the
        # filter response (model.py:568-570) — AC-17
    @pytest.mark.asyncio
    async def test_upstream_filtering_is_unreachable(self):
        """ModelView._filtering is never called from this handler."""
        # FILL IN: patch it to raise and assert not called — spec §5
        # criterion 8. Bounded by AC-22.
```

**Why `test_public_columns_covers_every_model_column` is here and not on the
identity surface.** On `UserAccount` the allowlist is supposed to equal the
full column set, so equality is the assertion. On `UserIdentity` it
deliberately does not (four credential columns are excluded), so there the
assertion is about the exclusions. Same idea, opposite shape — and here it
catches a typo that would silently drop a column from every response.

**Why `test_response_is_restricted_to_public_columns` uses an *extra*
column.** Nothing on this model is secret, so a redaction test over the real
columns can pass with no redaction at all. Giving the row double a column
outside the allowlist is the only way to observe that the allowlist is
applied.

**Why `test_set_user_id_and_set_address_still_run` is load-bearing.** It is
the single test that distinguishes "the override delegates to `super()`"
from "the override reimplemented the body". The second passes every
access-control assertion and breaks `address` resolution and owner filling
for every write on this surface.

### Steps (in order)

1. Confirm both dependencies landed: `social_network` must already contain
   `$1` (TASK-121), and `UserIdentityHandler` must already carry the full
   guard wiring (TASK-125).
2. **Read TASK-123, TASK-124 and TASK-125** in `sdd/tasks/completed/`. This
   task is their pattern with a different column set; do not re-derive the
   mechanics.
3. Apply Block 1. Verify the MRO:
   `python -c "from navigator_auth.handlers.userattrs import UserAccountHandler as H; print(H.__mro__[:3])"`.
4. Resolve the `account:revoke` question (contract note) **before** writing
   `_set_update`. If the reading is unclear, ESCALATE — do not guess.
5. Apply Block 2 in the TASK-123 → 124 → 125 order: gate, read path, write
   path, projection, `:meta`/`head`, filter. Run the matching test class
   after each group.
6. Create the test module; fill the three helpers first.
7. Run `pytest tests/unit/handlers -v`, then the regression gate
   `pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q`.
8. `ruff check navigator_auth/handlers/userattrs.py tests/unit/handlers/`.
9. Confirm the blast radius: `git diff navigator_auth/handlers/userattrs.py`
   shows **no change inside `class UserIdentityHandler`**, and
   `social_network` / `_set_address` are exactly as TASK-121 left them
   (AC-23).

### FILL IN checklist

- [ ] Block 2 anchor — verify the `return None` occurrence count and disambiguate
- [ ] `account:revoke` reading resolved (or ESCALATED) before `_set_update`
- [ ] `_require_owner_column` — AC-10
- [ ] `_pre_get` + `_get_data` — AC-1..AC-7
- [ ] shared write gate + the four named pre-hooks — AC-1, AC-10
- [ ] `_post_data` (delegating to `super()`) — AC-2, AC-11
- [ ] `_set_update` — AC-7, AC-8
- [ ] `_del_primary_data` — AC-12, AC-13
- [ ] `_model_response` (plain allowlist, no reshape) — AC-14, AC-15
- [ ] `_get_meta_info` + the `:meta` scope decision — AC-9
- [ ] `head` — AC-16
- [ ] `_filtering` — AC-17, AC-18, AC-19
- [ ] test helpers `_session` / `_patch_sessions` / `_handler`
- [ ] `TestConfiguration` — 5 bodies — AC-1, AC-15, AC-20, AC-21
- [ ] `TestReadPath` — 8 bodies — AC-1..AC-7, AC-10
- [ ] `TestWritePath` — 9 bodies — AC-2, AC-5, AC-7, AC-8, AC-11..AC-13
- [ ] `TestProjectionAndFilter` — 10 bodies — AC-9, AC-14, AC-16..AC-19, AC-22

---

## Acceptance Criteria

- [ ] **AC-1** `UserAccountHandler` inherits `OwnerOrSuperuserGuard` **before** `ModelHandler`; a request with no session answers **401**.
- [ ] **AC-2** `GET` lists only the acting user's rows; `PUT` forces `user_id`; an insert naming a foreign `user_id` is refused **403** for a non-superuser.
- [ ] **AC-3** A superuser whose policy allows `account:read` may read another user's rows; with no PDP, an undeclared policy, or a policy that raises, the admin read is denied while the owner's own read keeps working.
- [ ] **AC-4** `?user_id=<other>` as a non-superuser answers **403** — not 400, not 500 — and issues no query.
- [ ] **AC-5** Each cross-user read and each cross-user delete produces exactly one `AuditLog` record.
- [ ] **AC-6** A non-owner `GET` by `account_id` answers **404**.
- [ ] **AC-7** The 404s for "foreign" and "nonexistent" are identical in status and body; a non-superuser `PATCH`/`POST` on a foreign row answers **403**; the owner may edit their own row with **no PDP configured**.
- [ ] **AC-8** A **superuser** `PATCH`/`POST` on a foreign row is also refused **403** (there is no revocation column on `UserAccount`), and the reading is recorded in the Completion Note.
- [ ] **AC-9** `:meta` and `:sample` are bounded to the allowlisted column set, and `UserAccount.schema(as_dict=True)` is not mutated by serving them.
- [ ] **AC-10** With a model lacking the owner column, every verb answers **501**.
- [ ] **AC-11** `_set_user_id` still fills `user_id` and `_set_address` still runs on writes — i.e. `_post_data` delegates to `super()`.
- [ ] **AC-12** The owner may `DELETE` their own row; a superuser with the policy may delete a foreign row, audited.
- [ ] **AC-13** A non-owner `DELETE` answers **404**, not 403.
- [ ] **AC-14** Responses are restricted to `public_columns`; `?fields=` is intersected with it, never unioned.
- [ ] **AC-15** `credential_columns` is empty and `public_columns` equals `UserAccount`'s full column set.
- [ ] **AC-16** `HEAD`'s `X-Columns` is bounded to the allowlisted column set.
- [ ] **AC-17** `_filtering` returns `None` when no `_filter` parameter is present.
- [ ] **AC-18** `?_filter=<unknown or non-allowlisted column>=…` answers **400** and issues no query.
- [ ] **AC-19** `?_filter=<public column>=<value>` executes a statement containing `$1` with the value bound, and ANDs the owner predicate for a non-superuser.
- [ ] **AC-20** `policy_name` and the three `account:*` actions match TASK-120's policy pack exactly.
- [ ] **AC-21** `UserAccountHandler._hidden is not ModelView._hidden`.
- [ ] **AC-22** `ModelView._filtering` is never called from this handler — asserted by patching it to raise.
- [ ] **AC-23** `class UserIdentityHandler` is unchanged, `social_network` / `_set_address` are exactly as TASK-121 left them, and nothing under `navigator_auth/` outside `userattrs.py` is modified.
- [ ] **AC-24** `pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q` passes and `ruff check navigator_auth/handlers/userattrs.py tests/unit/handlers/` is clean.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/unit/handlers/test_user_account_handler_access.py -v
pytest tests/unit/handlers -v
pytest tests/unit tests/test_check_superuser.py tests/test_check_access.py -q   # regression
ruff check navigator_auth/handlers/userattrs.py tests/unit/handlers/
```

```python
from navigator_auth.handlers.userattrs import UserAccountHandler
from navigator_auth.models import UserAccount
assert UserAccountHandler.credential_columns == frozenset()
assert set(UserAccount.get_columns()) == UserAccountHandler.public_columns
```

---

## Agent Instructions

1. **Read the spec** at `sdd/specs/user-identities-ownership-abac.spec.md` —
   §1 Problem Statement B, §2 Data Models, §3 Module 5, §4 the Module-5 rows,
   §7 Patterns to Follow.
2. **Read TASK-123, TASK-124 and TASK-125** in `sdd/tasks/completed/` — this
   task is their pattern with a different column set.
3. **Check dependencies** — TASK-121 and TASK-125 must both be completed.
4. **Update status** in `sdd/tasks/index/user-identities-ownership-abac.json`
   → `"in-progress"`.
5. **Implement** per the blueprint. Resolve or ESCALATE the `account:revoke`
   question before writing `_set_update`.
6. **Verify** every acceptance criterion, AC-11 and AC-23 included.
7. **Move this file** to `sdd/tasks/completed/TASK-126-account-handler-guard.md`.
8. **Update index** → `"done"`.
9. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
