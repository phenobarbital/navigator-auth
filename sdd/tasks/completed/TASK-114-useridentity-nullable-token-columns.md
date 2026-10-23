# TASK-114: Make the UserIdentity credential columns nullable

**Feature**: FEAT-104 — Identity-Link Failure: Non-Nullable Token Columns and Unsafe Error Headers
**Spec**: `sdd/specs/bug-identity.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 1**. This is the defect that actually breaks the
**Link Github** button in `examples/identity_vault_server.py`.

`UserIdentity` declares its three ciphered credential columns as bare `bytes`
on a `strict = True` model. `required=False` only makes a field optional *to
supply* — `datamodel` still runs the `bytes` converter over the resulting
`None` and fails with `Cannot convert None to bytes`. The DB columns are
plain nullable `BYTEA`, so the model is stricter than the table it maps.

Two distinct breakages follow, and the second is the reason **all three**
columns are widened rather than just the two in the traceback (spec §8 Q3,
resolved 2026-10-23):

1. **Insert path.** `IdentityStore.save_linked_identity` passes `None` for a
   provider that issues no refresh/id token (`store.py:155-160` → `store.py:194`).
   GitHub OAuth Apps issue neither. The `existing`-row branch
   (`store.py:179-193`) pops those keys, so *re-linking* works — only the
   **first** link fails, which is why the bug looks intermittent.
2. **Hydration path.** The model cannot be constructed at all without all
   three columns, so `UserIdentity.get()` / `.filter()` raise the same error
   for any row with `NULL` token columns. `auth.user_identities` predates the
   Identity Vault — migrations `001`/`002` `ADD COLUMN` onto an existing
   table, and `004_identity_base_columns.sql` exists precisely because legacy
   databases lacked even the model's base columns. Profile-only rows are
   therefore real, and `list_for_user`, `get_one` and `get_by_provider` fail
   on them today, independently of any link attempt.

**Why this shipped:** every existing identity test builds a
`FakeUserIdentity` stub, never the real model
(`test_identity_vault_v2.py:114,132,143,155,169`,
`tests/test_identity_id_token.py:184,209,237,250`). The store logic was
covered; the model contract never was. **A test that uses the stub proves
nothing about this fix** — the tests below must import the real model.

---

## Scope

- Widen `access_token`, `refresh_token` and `id_token` on
  `navigator_auth.models.UserIdentity` from `bytes` to `Optional[bytes]`.
- Add a new unit-test module that exercises the **real** `UserIdentity`
  model (not a stub) for the null, bare and bytes cases.
- Add two store-level tests covering the insert branch with a GitHub-shaped
  `TokenResponse` and a regression guard on the existing-row branch.

**NOT in scope**:
- Any change to `navigator_auth/identity/store.py`. It already passes `None`
  correctly; the model is what rejects it. Making `save_linked_identity` pop
  the keys on the insert branch too is the tempting shortcut and is
  **explicitly rejected** — it would hide the defect while leaving hydration
  of legacy rows broken, and would mean a re-link could never clear a stale
  token.
- Any DDL change or new file under `navigator_auth/identity/sql/`. The table
  is already correct.
- A write-path guard requiring a non-empty `access_token`. Considered and
  declined in spec §8 Q3.
- `VwUserIdentity` (`models.py:119`) — it has no token columns.
- Anything in `navigator_auth/backends/` — that is TASK-115/116/117.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/models.py` | MODIFY | Three column annotations → `Optional[bytes]` |
| `tests/unit/identity/test_user_identity_model.py` | CREATE | Real-model unit tests (null / bare / bytes) |
| `tests/unit/identity/test_identity_store.py` | MODIFY | Two store tests: insert without refresh/id token, and the existing-row regression guard |

---

## Codebase Contract

> Verified on `dev` @ `b222064` (2026-10-23).

### Verified signatures

```python
# navigator_auth/models.py
from typing import Optional                                  # line 7 — ALREADY IMPORTED

class UserIdentity(Model):                                   # line 77
    identity_id: UUID = Column(required=False, primary_key=True, db_default="auto", repr=False)  # 78-80
    user_id: User = Column(required=True, fk="user_id|username", api="users", label="User")      # 88-90
    auth_provider: str = Column(required=False)               # 91
    auth_data: Optional[dict] = Column(required=False, repr=False)    # 92
    attributes: Optional[dict] = Column(required=False, repr=False)   # 93
    provider_user_id: str = Column(required=False, repr=False)        # 96
    scopes: Optional[list] = Column(required=False, default_factory=list, repr=False)  # 97-99
    access_token: bytes = Column(required=False, repr=False)          # 100  <-- CHANGE
    refresh_token: bytes = Column(required=False, repr=False)         # 101  <-- CHANGE
    id_token: bytes = Column(required=False, repr=False)              # 102  <-- CHANGE
    token_type: str = Column(required=False, repr=False)              # 103
    expires_at: datetime = Column(required=False, repr=False)         # 104
    refreshed_at: datetime = Column(required=False, repr=False)       # 105
    enabled: bool = Column(required=False, default=True)              # 106
    key_version: int = Column(required=False, repr=False)             # 107

    class Meta:
        name = "user_identities"     # 113
        schema = AUTH_DB_SCHEMA      # 114
        strict = True                # 115  <-- why None is rejected
        frozen = False               # 117
```

```python
# navigator_auth/identity/store.py
class IdentityStore:                                          # 71
    def __init__(self, db_pool: Any, cipher: Optional[IdentityCipher] = None)   # 74
    async def save_linked_identity(                           # 134
        self, user_id: Any, provider: str,
        token: TokenResponse, userinfo: Optional[dict] = None,
    ) -> UserIdentity
# key lines: "refresh_token": ... else None   # 155-159
#            "id_token": ... else None        # 160
#            if existing:                     # 179   (pops at 184 / 187)
#            identity = UserIdentity(...)     # 194   <-- raises today
#            return await identity.insert()   # 199
```

```python
# navigator_auth/identity/types.py
@dataclass
class TokenResponse:
    access_token: str
    token_type: str = "Bearer"
    refresh_token: Optional[str] = None     # already Optional — no change
    id_token: Optional[str] = None          # already Optional — no change
    expires_in: Optional[int] = None
    expires_at: Optional[datetime] = None
    scopes: list = field(default_factory=list)
    provider_user_id: Optional[str] = None
    raw: dict = field(default_factory=dict)
```

### Verified test helpers (`tests/unit/identity/test_identity_store.py`)

```python
MASTER_KEYS = {1: b"\x00" * 32}                  # line 17
def _make_pool()                                 # line 20 -> (pool, conn)
def _store()                                     # line 33 -> IdentityStore(pool, cipher=IdentityCipher(master_keys=MASTER_KEYS))
def _enc(store, value, field, user_id=1, provider="github", puid="99")   # line 38
# imports already present at lines 1-14:
#   from navigator_auth.identity.crypto import IdentityCipher
#   from navigator_auth.identity.store import IdentityStore, cache_credential, ...
```

### Verified reproduction (current behaviour on `dev`)

```
$ python -c "from navigator_auth.models import UserIdentity; UserIdentity(user_id=1, auth_provider='g')"
ValidationError: UserIdentity: There are errors in Model.
payload: {'access_token':  '... Cannot convert None to bytes',
          'refresh_token': '... Cannot convert None to bytes',
          'id_token':      '... Cannot convert None to bytes'}
```

Confirmed fix shape:
```
Model with `a: Optional[bytes] = Column(required=False, repr=False)` and strict=True:
  T(a=None).a   -> None       (was: ValidationError)
  T(a=b'xx').a  -> b'xx'      (unchanged)
```

### Does NOT Exist (do not reference)

- There is **no** `navigator_auth/identity/models.py`. `UserIdentity` lives in
  `navigator_auth/models.py` only.
- `UserIdentity` has **no** `has_refresh_token` attribute. That key exists only
  in the dict returned by `IdentityStore.masked()` (`store.py:375`).
- `IdentityStore` has **no** `save_identity`, `upsert_identity` or
  `create_identity`. The only write entry point is `save_linked_identity`.
- `TokenResponse` has **no** `refresh()` or `is_expired()`. It has
  `is_expiring(leeway=0)`.
- There is no `FakeUserIdentity` in `tests/unit/identity/conftest.py` — the
  stubs are defined locally inside `test_identity_vault_v2.py` and
  `tests/test_identity_id_token.py`. **Do not import or extend them for this
  task**; this task's tests must use the real model.
- `tests/unit/identity/conftest.py` provides only `FakeFlowStore`,
  the `flow_store` fixture and `make_backend(...)` — no DB or model fixtures.

---

## Implementation Blueprint

### `navigator_auth/models.py` — MODIFY

```python
# BEFORE — replace these three lines (verified: navigator_auth/models.py:100-102)
# occurrences: 1 each (verified: grep -cF '<line>' navigator_auth/models.py)
#   access_token: bytes = Column(required=False, repr=False)
#   refresh_token: bytes = Column(required=False, repr=False)
#   id_token: bytes = Column(required=False, repr=False)

# AFTER
    access_token: Optional[bytes] = Column(required=False, repr=False)
    refresh_token: Optional[bytes] = Column(required=False, repr=False)
    id_token: Optional[bytes] = Column(required=False, repr=False)
```

**Why**: `strict = True` (`models.py:115`) makes `datamodel` run the declared
converter over every field including unsupplied ones, and the `bytes`
converter rejects `None`. `Optional[bytes]` tells it `None` is a legal value —
matching the nullable `BYTEA` columns. Do **not** change the `Column(...)`
arguments: `repr=False` is what keeps ciphertext out of logs and tracebacks,
and dropping it would leak token material into the very error messages this
feature is cleaning up.

`Optional` is already imported at `models.py:7` and already used on this same
class at lines 92, 93 and 97 — **add no import**. Change only the type
annotation on each of the three lines; indentation, spacing and the
`Column(...)` call stay byte-identical.

### `tests/unit/identity/test_user_identity_model.py` — CREATE

```python
"""Contract tests for the real `UserIdentity` model (FEAT-104, TASK-114).

These deliberately use `navigator_auth.models.UserIdentity` itself rather
than the `FakeUserIdentity` stubs used elsewhere in the identity suite. The
stubs are why FEAT-104 shipped: they covered the store logic and never the
model's column contract.
"""
import pytest

from navigator_auth.models import UserIdentity


class TestUserIdentityNullableTokens:
    def test_bare_construction(self):
        """A profile-only identity (legacy pre-vault row) hydrates."""
        # FILL IN: construct UserIdentity with only user_id + auth_provider,
        # assert access_token / refresh_token / id_token are all None
        # — bounded by AC-2 and the hydration path in spec §1 Defect A.

    def test_accepts_null_refresh_and_id_token(self):
        """The GitHub shape: an access token, no refresh token, no id token."""
        # FILL IN: access_token=b"sealed", refresh_token=None, id_token=None
        # — bounded by AC-1.

    def test_still_accepts_bytes(self):
        """No regression on the sealed path: bytes round-trip unchanged."""
        # FILL IN: all three set to distinct bytes values, assert read-back
        # — bounded by AC-3.
```

**Why**: a separate module, not an addition to `test_identity_vault_v2.py`,
because that file's local `FakeUserIdentity` is in scope there and an
executor adding tests to it will reach for the stub by reflex. Isolating the
real-model tests makes the distinction impossible to miss.

These are plain synchronous tests — the model constructor is not async and
touches no database (`Meta.connection` is only set by `IdentityStore`). Do
**not** add `@pytest.mark.asyncio` and do **not** build a pool.

### `tests/unit/identity/test_identity_store.py` — MODIFY

```python
# AFTER — append a new class at end of file
# anchor: the final line of the module
# occurrences: 1 (verified: grep -cF 'def _enc(store, value, field' tests/unit/identity/test_identity_store.py)
# Reuse the module's existing helpers — do not redefine them:
#   MASTER_KEYS (line 17), _make_pool() (line 20), _store() (line 33), _enc() (line 38)

class TestSaveLinkedIdentityNullTokens:
    @pytest.mark.asyncio
    async def test_insert_without_refresh_or_id_token(self):
        """The GitHub insert branch: no existing row, no refresh/id token."""
        # FILL IN: build TokenResponse(access_token="at", refresh_token=None,
        # id_token=None, provider_user_id="99"); make UserIdentity.get raise
        # NoDataFound so the insert branch at store.py:194 is taken; assert the
        # constructed identity has refresh_token is None and id_token is None
        # and that insert() was awaited — bounded by AC-4.

    @pytest.mark.asyncio
    async def test_update_keeps_previously_vaulted_tokens(self):
        """Regression guard on store.py:179-193 — a re-save must not clobber."""
        # FILL IN: existing row carrying a sealed refresh_token; re-save with
        # TokenResponse(refresh_token=None); assert the existing ciphertext
        # survives — bounded by AC-5.
```

**Why**: `test_insert_without_refresh_or_id_token` is the test that would have
caught this bug, and it only works against the **insert** branch — the
`existing` branch pops the keys and never reaches the failing constructor. The
second test exists because widening the model makes it newly possible for a
`None` to reach the database and wipe a stored token; `store.py:179-193`
already prevents that, and this pins the behaviour so a later refactor of the
store cannot silently remove it.

`NoDataFound` is imported in `store.py` from `asyncdb.exceptions`; import it
the same way in the test rather than catching a bare `Exception`.

### Steps (in order)

1. Edit the three annotations in `navigator_auth/models.py` — nothing else in
   that file. Verify nothing else changed: `git diff --stat navigator_auth/models.py`
   must report `1 file changed, 3 insertions(+), 3 deletions(-)`.
2. Run the reproduction one-liner from the Codebase Contract. It must now
   print nothing instead of raising. Do this **before** writing tests, so you
   know the fix landed and a later test failure means a bad test, not a bad fix.
3. Create `tests/unit/identity/test_user_identity_model.py` and fill the three
   bodies. Run it. It must import the real model.
4. Append the store test class and fill both bodies. Follow the existing
   `_make_pool()` / `_store()` idiom — do not invent a new fixture style.
5. Run the full identity suite (AC-7): regressions here are more likely than
   failures in the new tests, because widening a type changes what other code
   is allowed to pass.
6. Run `ruff check navigator_auth/models.py tests/unit/identity/`.

### FILL IN checklist

- [ ] `test_bare_construction` body — AC-2
- [ ] `test_accepts_null_refresh_and_id_token` body — AC-1
- [ ] `test_still_accepts_bytes` body — AC-3
- [ ] `test_insert_without_refresh_or_id_token` body — AC-4
- [ ] `test_update_keeps_previously_vaulted_tokens` body — AC-5

---

## Acceptance Criteria

- [ ] **AC-1** `UserIdentity(user_id=1, auth_provider="github", access_token=b"x", refresh_token=None, id_token=None)` constructs without raising, using the **real** model.
- [ ] **AC-2** `UserIdentity(user_id=1, auth_provider="github")` constructs without raising and all three token attributes are `None`.
- [ ] **AC-3** Supplying `bytes` to all three columns still round-trips unchanged.
- [ ] **AC-4** `IdentityStore.save_linked_identity` completes the **insert** branch for a `TokenResponse` with `refresh_token=None` and `id_token=None`.
- [ ] **AC-5** The `existing`-row branch still preserves a previously vaulted `refresh_token` / `id_token` on a re-save (`store.py:179-193` unchanged in behaviour).
- [ ] **AC-6** `navigator_auth/identity/store.py` is **not** modified: `git diff --name-only` does not list it.
- [ ] **AC-7** `pytest tests/unit/identity/ tests/test_identity_id_token.py -v` passes with no new failures.
- [ ] **AC-8** No file added or changed under `navigator_auth/identity/sql/`.
- [ ] **AC-9** `ruff check navigator_auth/models.py tests/unit/identity/` is clean.

---

## Test Specification

```bash
pytest tests/unit/identity/test_user_identity_model.py -v
pytest tests/unit/identity/test_identity_store.py -v
pytest tests/unit/identity/ tests/test_identity_id_token.py -q
```

```python
# tests/unit/identity/test_user_identity_model.py — the import that matters
from navigator_auth.models import UserIdentity   # the REAL model, never a stub
```

---

## Agent Instructions

1. **Read the spec** at `sdd/specs/bug-identity.spec.md` — §1 Defect A, §3
   Module 1, §6 Codebase Contract, §8 Q3.
2. **Check dependencies** — none.
3. **Update status** in `sdd/tasks/index/bug-identity.json` → `"in-progress"`.
4. **Implement** per the blueprint. Three production lines; the rest is tests.
5. **Verify** every acceptance criterion, including AC-6 (store untouched).
6. **Move this file** to `sdd/tasks/completed/TASK-114-useridentity-nullable-token-columns.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: sdd-worker (sequential fallback)
**Date**: 2026-10-23
**Notes**: Optional[bytes] on 3 token columns; real-model tests + 2 store tests. 182 identity tests pass.

**Deviations from spec**: none
