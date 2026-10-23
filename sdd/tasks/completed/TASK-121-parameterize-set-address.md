# TASK-121: Parameterize the `_set_address` `social_networks` lookup (SQL injection sink)

**Feature**: FEAT-105 — Owner-or-Superuser ABAC Ownership for the Auth Model CRUD Surfaces
**Spec**: `sdd/specs/user-identities-ownership-abac.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Implements **spec §1 G9** and the `social_network` half of **spec §3
Module 5**. `UserAccountHandler._set_address` builds a SQL statement with
`str.format` from `data['provider']` — a value that arrives in the request
body on every `PUT`/`PATCH`/`POST` to `/api/v1/user_accounts*`:

```python
    social_network: str = """
    SELECT social_url FROM auth.social_networks WHERE social_network = '{provider}'
    """
    ...
            qry = self.social_network.format(provider=provider)
            result = await conn.fetchval(qry, column='social_url')
```

(verified: `navigator_auth/handlers/userattrs.py:24-26` and `:45-46`)

This is a live, first-order SQL injection: the value is interpolated inside
a quoted literal, so `provider = "x' OR 1=1 --"` closes the quote and
rewrites the statement. Unlike the `?_filter=` sink described in spec §1, no
upstream `TypeError` stands in the way — `_set_address` runs this query
itself, directly.

**Why this is a separate task.** It is the one piece of FEAT-105 that is
independent of the whole guard/redaction stack: a two-line parameterization
with its own acceptance criterion (spec §5 criterion 9) and its own test. It
can land first, on its own, and shorten the window the sink is open —
whereas folding it into the `UserAccountHandler` hardening (TASK-125) would
hold a live injection fix behind five other tasks.

It shares a file with TASK-124/125/126, so it is not parallel-safe, but it
has no code dependency on any of them. **Do it first.**

---

## Scope

- Rewrite the `social_network` class attribute on `UserAccountHandler` to use
  a `$1` placeholder.
- Rewrite the query execution in `_set_address` to bind `provider` as a
  parameter.
- Add `tests/unit/handlers/test_user_account_set_address.py` proving the
  hostile value reaches the driver as an argument and never as statement
  text.

**NOT in scope**:
- The ownership guard, redaction, `_filtering`, `_pre_*` hooks or
  `public_columns` on `UserAccountHandler`. All of that is TASK-125. This
  task changes **only** `social_network` and the body of `_set_address`.
- `UserIdentityHandler` — do not touch it, even though it is in the same
  file.
- `result.format(uid=userid)` at `userattrs.py:48`. That is **not SQL**: the
  value read out of `auth.social_networks.social_url` is a URL template such
  as `https://twitter.com/{uid}`, and formatting it with the account's `uid`
  is the function's entire purpose. Leave it exactly as it is. Spec §5
  criterion 9's "no `str.format` on SQL remains" refers to statement
  construction, not to this.
- The `auth.social_networks` table itself, or the hardcoded `auth.` schema
  prefix in the query. (The rest of the file's models use
  `AUTH_DB_SCHEMA`; this literal predates the task and changing it would
  alter behaviour for anyone whose schema is not `auth`. Out of scope —
  noted here so it is a decision, not an oversight.)

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/userattrs.py` | MODIFY | `social_network` → `$1`; bind the parameter in `_set_address` |
| `tests/unit/handlers/test_user_account_set_address.py` | CREATE | Injection-payload test |
| `tests/unit/handlers/__init__.py` | CREATE | New test package (empty; likely already created by TASK-118/120) |

---

## Codebase Contract

> Every fact below was re-verified on `dev` @ `62fd419` (2026-10-23).

### `navigator_auth/handlers/userattrs.py` — the complete current file (60 lines)

```python
from typing import Any
from asyncdb.exceptions import (
    NoDataFound
)
from asyncdb.exceptions import DriverError
from navigator_session import (
    get_session,
    AUTH_SESSION_OBJECT
)
from ..models import (
    UserAccount, UserIdentity, VwUserIdentity
)
from ..conf import (
    AUTH_USER_IDENTITY_MODEL
)
# from .model import ModelHandler
from .handler import ModelHandler


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


class UserIdentityHandler(ModelHandler):
    model: Any = UserIdentity
    model_name: str = AUTH_USER_IDENTITY_MODEL
    name: str = "User Identity"
    pk: str = "identity_id"

    async def _set_user_id(self, value, column, data):
        return await self.get_userid(session=self._session)
```

Exact line numbers in the live file: `class UserAccountHandler` at `:20`,
`social_network` at `:24-26`, `_set_user_id` at `:28`, `_set_address` at
`:31-51`, the vulnerable `.format` at `:45`, the `fetchval` at `:46`, the
legitimate `result.format(uid=...)` at `:48`, `class UserIdentityHandler` at
`:53`.

### `conn.fetchval` — the signature to bind against

Verified `.venv/lib/python3.11/site-packages/asyncdb/drivers/pg.py:1052`:

```python
    async def fetchval(self, sentence: str, *args, column: int = 0, **kwargs):
        ...
        result = await self._connection.fetchval(sentence, column=column, *args, **kwargs)
```

So positional `*args` after the statement are the **bound query parameters**,
and `column=` is forwarded to asyncpg as the result-column selector. The
existing `column='social_url'` works because an asyncpg `Record` accepts a
string key; keep it, it is not part of this defect.

### The repo's established parameterized idiom

Verified `navigator_auth/passkey/store.py:44-47`:

```python
            row = await conn.fetch_one(
                f"SELECT * FROM {_CREDENTIALS} WHERE credential_id = $1",
                credential_id,
            )
```

Verified `navigator_auth/middlewares/strategies.py:87-91`:

```python
                payload = await conn.fetch_one(
                    "SELECT user_id, name from public.api_keys "
                    "WHERE token = $1 "
                    "AND (expiration >= extract(epoch from now()) or expiration = 0)",
                    token,
                )
```

`$1` is the paramstyle, the value is a positional argument.

### `self.handler(request=...)` — the connection acquirer

`_set_address` already uses `async with await self.handler(request=self.request) as conn`
(`userattrs.py:44`). This comes from the upstream base and is unchanged by
this task; the test patches it (see the blueprint).

### Does NOT Exist (do not reference)

- A query-builder or escaping helper in `navigator_auth/` for this. There is
  none, and none should be written: the fix is a bound parameter, not an
  escaper. Do not add `quote_literal`, `escape_sql` or similar.
- `AUTH_DB_SCHEMA` interpolation in this query today — the schema is the
  hardcoded literal `auth.`. Do not "while I'm here" change it (out of
  scope above).
- `asyncpg` as a direct import in `navigator_auth/handlers/`. Everything goes
  through `asyncdb`; `DriverError` is already imported at
  `userattrs.py:5`.
- `conn.fetchval(qry, provider=provider)` — asyncpg binds **positionally**
  (`$1`), not by keyword. A keyword would land in `**kwargs` and be
  forwarded to asyncpg as an unexpected argument.
- `tests/unit/handlers/test_user_account_handler_access.py` — that file
  belongs to TASK-125 (the guard wiring). This task's test is the separate
  `test_user_account_set_address.py`, so the two tasks never touch the same
  test file.
- Any `_set_address` on `UserIdentityHandler` — it has only `_set_user_id`
  (`userattrs.py:59`).

---

## Implementation Blueprint

### `navigator_auth/handlers/userattrs.py` — MODIFY (two blocks)

```python
# BEFORE -> AFTER — replace the `social_network` class attribute
# anchor (verified: navigator_auth/handlers/userattrs.py:24-26)
# occurrences: 1 (verified: grep -cF 'SELECT social_url FROM auth.social_networks' navigator_auth/handlers/userattrs.py)

# --- replace these three lines:
#     social_network: str = """
#     SELECT social_url FROM auth.social_networks WHERE social_network = '{provider}'
#     """
# --- with:
    #: G9: the provider is bound as $1, never interpolated. The previous form
    #: inlined it inside a quoted literal, so a provider of ``x' OR 1=1 --``
    #: rewrote the statement.
    social_network: str = (
        "SELECT social_url FROM auth.social_networks "
        "WHERE social_network = $1"
    )
```

```python
# AFTER — replace the two statement lines inside `_set_address`
# anchor (verified: navigator_auth/handlers/userattrs.py:45-46)
# occurrences: 1 (verified: grep -cF 'qry = self.social_network.format(provider=provider)' navigator_auth/handlers/userattrs.py)

# --- replace these two lines:
#                     qry = self.social_network.format(provider=provider)
#                     result = await conn.fetchval(qry, column='social_url')
# --- with:
                    result = await conn.fetchval(
                        self.social_network, provider, column='social_url'
                    )
```

**Why the `qry` local disappears entirely.** Leaving `qry = self.social_network`
would keep a variable whose only historical purpose was to hold the formatted
string, and the next reader would wonder what it is for. More practically: as
long as a local holds the statement, someone can reintroduce a `.format` on
it. Pass the class attribute straight to the driver.

**Why `fetchval` is kept rather than switching to the `fetch_one` idiom.**
`fetch_one` returns a `Record` and would require a `row['social_url']` read
plus a `None` check, changing three more lines and the `if result:` branch
below. This task is a security fix; the smaller the diff, the easier it is to
review and to backport. `fetchval` with a bound `$1` is just as
parameterized.

**Why `column='social_url'` stays.** It is forwarded to asyncpg, whose
`Record` accepts a string key, and it is orthogonal to the injection. It is
pre-existing behaviour; changing it would mean re-verifying the return shape
for no security gain.

**Why the statement becomes an implicit-concatenation tuple rather than
staying a triple-quoted block.** The `"""…"""` form carries leading newlines
and indentation into the statement text. That is harmless to the driver but
makes the test assertion `"$1" in sql` read against a string full of
whitespace, and it is how the `{provider}` placeholder came to look
innocuous inside a quoted literal. The two-line concatenated form is the
shape `middlewares/strategies.py:87-91` already uses.

**Why nothing else in `_set_address` changes.** The `data['uid']` /
`data['provider']` reads, the `DriverError` swallow and the `return None`
fall-through are pre-existing behaviour with their own semantics (an unknown
provider yields no address). Spec §3 Module 5 keeps the method and
parameterizes it; it does not redesign it.

### `tests/unit/handlers/__init__.py` — CREATE

```python
# empty — marks tests/unit/handlers as a package, like
# tests/unit/identity/__init__.py and tests/unit/middlewares/__init__.py
```

TASK-118 and TASK-120 also create this file, with identical empty content.
Create it only if absent.

### `tests/unit/handlers/test_user_account_set_address.py` — CREATE

```python
"""`_set_address` binds the provider as a parameter (FEAT-105 G9, TASK-121).

Spec §4 row `test_set_address_uses_bound_parameter`. The assertion that
matters is not "the result is correct" but "the hostile value never appears
in the statement text" — a test that only checked the return value would
pass against the injectable implementation too.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from navigator_auth.handlers.userattrs import UserAccountHandler

PAYLOAD = "x'; DROP TABLE auth.users; --"


class RecordingConn:
    """Captures (sentence, args, kwargs) so parameterization is assertable."""

    def __init__(self, value="https://example.com/{uid}"):
        self.calls = []
        self._value = value

    async def fetchval(self, sentence, *args, **kwargs):
        self.calls.append((sentence, args, kwargs))
        return self._value

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _handler(conn):
    """A UserAccountHandler whose `handler()` yields `conn`.

    Built without going through __init__ so no aiohttp request, session or
    database is needed — `_set_address` touches only `self.handler`,
    `self.request` and `self.name`.
    """
    # FILL IN: instance = UserAccountHandler.__new__(UserAccountHandler);
    # set instance.request = MagicMock(); make instance.handler an AsyncMock
    # returning `conn` (note _set_address does
    # `async with await self.handler(request=...)`, so handler() must be
    # awaitable and its result an async context manager — RecordingConn is
    # both). Bounded by AC-1.


class TestSetAddressParameterization:
    @pytest.mark.asyncio
    async def test_statement_uses_a_placeholder(self):
        """The executed statement contains `$1` and no interpolated value."""
        # FILL IN: conn = RecordingConn(); await handler._set_address(
        # value=None, column=None, data={"uid": "u1", "provider": PAYLOAD});
        # assert exactly one call; assert "$1" in sentence and PAYLOAD not in
        # sentence — bounded by AC-2, AC-3.

    @pytest.mark.asyncio
    async def test_payload_arrives_as_a_bound_argument(self):
        """The hostile provider is passed to the driver positionally."""
        # FILL IN: assert args == (PAYLOAD,) for the recorded call
        # — bounded by AC-4.

    @pytest.mark.asyncio
    async def test_no_brace_placeholder_survives_in_the_statement(self):
        """`{provider}` is gone, so `.format` cannot be reintroduced silently."""
        # FILL IN: assert "{provider}" not in sentence and "'" not in the
        # fragment around social_network = ... — bounded by AC-3.

    @pytest.mark.asyncio
    async def test_result_template_is_still_formatted_with_uid(self):
        """The returned social_url template is still filled with the uid."""
        # FILL IN: RecordingConn("https://x.test/{uid}");
        # assert the return value == "https://x.test/u1" — this guards the
        # LEGITIMATE result.format at userattrs.py:48 against being removed
        # along with the SQL one. Bounded by AC-5.

    @pytest.mark.asyncio
    async def test_missing_provider_issues_no_query(self):
        """No provider in the payload => no statement executed, returns None."""
        # FILL IN: data={"uid": "u1"}; assert conn.calls == [] and the result
        # is None — bounded by AC-6.

    @pytest.mark.asyncio
    async def test_driver_error_is_still_swallowed(self):
        """A DriverError keeps yielding None rather than a 500."""
        # FILL IN: a conn whose fetchval raises
        # asyncdb.exceptions.DriverError; assert the call returns None and
        # does not raise — bounded by AC-7.


class TestClassAttribute:
    def test_social_network_declares_a_placeholder(self):
        """Static guard: the class attribute itself carries `$1`."""
        # FILL IN: assert "$1" in UserAccountHandler.social_network and
        # "{provider}" not in it — bounded by AC-3.
```

**Why `test_result_template_is_still_formatted_with_uid` is in this file.**
The acceptance criterion is "no `str.format` on SQL remains in
`navigator_auth/handlers/`", and `result.format(uid=userid)` at
`userattrs.py:48` is a `str.format` in that directory that must **stay**. A
reviewer grepping for `.format(` will find it. This test states, executably,
that it is load-bearing — so removing it fails a test instead of silently
returning a template string with a literal `{uid}` in it to the database.

**Why `test_missing_provider_issues_no_query` and
`test_driver_error_is_still_swallowed` are here.** They pin the two
pre-existing behaviours the diff passes through. Without them, a
"parameterization" that also restructured the control flow would look
correct.

**Why the handler is built with `__new__` rather than instantiated.**
`ModelView.__init__` requires an aiohttp request and reaches for the app's
database; `_set_address` needs none of that. Constructing the object
without `__init__` keeps the test a unit test of the one method — the same
reason `tests/unit/identity/test_identity_handlers.py` patches `get_session`
rather than standing up an app.

### Steps (in order)

1. Replace the `social_network` class attribute (block 1). Run
   `python -c "from navigator_auth.handlers.userattrs import UserAccountHandler as H; print(H.social_network)"`
   and confirm you see `$1` and no `{provider}`.
2. Replace the two statement lines inside `_set_address` (block 2). The
   surrounding `async with`, the `if result:` branch and the
   `except DriverError: pass` are untouched.
3. `grep -n '\.format(' navigator_auth/handlers/userattrs.py` — there must be
   **exactly one** hit left, `result.format(uid=userid)` at the line that was
   `:48`. If there are two, block 2 was not applied.
4. Create `tests/unit/handlers/__init__.py` if absent.
5. Create the test module; fill `_handler` first (every test depends on it),
   then the seven bodies.
6. Run `pytest tests/unit/handlers/test_user_account_set_address.py -v`, then
   `ruff check navigator_auth/handlers/userattrs.py tests/unit/handlers/`.
7. Confirm the blast radius: `git diff --name-only` lists only
   `navigator_auth/handlers/userattrs.py` plus the new test files, and
   `git diff navigator_auth/handlers/userattrs.py` shows **no change inside
   `class UserIdentityHandler`**.

### FILL IN checklist

- [ ] `_handler` test helper — awaitable `handler()` returning an async CM — AC-1
- [ ] `test_statement_uses_a_placeholder` — AC-2, AC-3
- [ ] `test_payload_arrives_as_a_bound_argument` — AC-4
- [ ] `test_no_brace_placeholder_survives_in_the_statement` — AC-3
- [ ] `test_result_template_is_still_formatted_with_uid` — AC-5
- [ ] `test_missing_provider_issues_no_query` — AC-6
- [ ] `test_driver_error_is_still_swallowed` — AC-7
- [ ] `test_social_network_declares_a_placeholder` — AC-3

---

## Acceptance Criteria

- [ ] **AC-1** `_set_address` still resolves an address for a known provider: the recorded driver call happens exactly once per invocation with a provider.
- [ ] **AC-2** The executed statement text contains `$1`.
- [ ] **AC-3** `UserAccountHandler.social_network` contains no `{provider}` and no single-quoted placeholder; the hostile payload never appears in the statement text.
- [ ] **AC-4** `provider` reaches the driver as a positional bound argument — `args == (PAYLOAD,)`.
- [ ] **AC-5** `result.format(uid=...)` at the former `userattrs.py:48` is **unchanged** and still fills the `social_url` template with the account `uid`.
- [ ] **AC-6** A payload without `provider` issues no query and returns `None`.
- [ ] **AC-7** A `DriverError` from the driver still yields `None` instead of propagating.
- [ ] **AC-8** `grep -n '\.format(' navigator_auth/handlers/userattrs.py` returns exactly one line, the `result.format(uid=userid)` one. No `str.format`-built SQL remains in `navigator_auth/handlers/`.
- [ ] **AC-9** `class UserIdentityHandler` in the same file is byte-for-byte unchanged.
- [ ] **AC-10** `pytest tests/unit/handlers/test_user_account_set_address.py -v` passes and `ruff check navigator_auth/handlers/userattrs.py tests/unit/handlers/` is clean.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/unit/handlers/test_user_account_set_address.py -v
grep -n '\.format(' navigator_auth/handlers/userattrs.py   # expect exactly 1 hit
ruff check navigator_auth/handlers/userattrs.py tests/unit/handlers/
```

```python
from navigator_auth.handlers.userattrs import UserAccountHandler
assert "$1" in UserAccountHandler.social_network
```

---

## Agent Instructions

1. **Read the spec** at `sdd/specs/user-identities-ownership-abac.spec.md` —
   §1 Problem Statement B, §1 G9, §3 Module 5 (`social_network` and
   `_set_address` only), §5 criterion 9.
2. **Check dependencies** — none. This task is intended to land **first**.
3. **Update status** in `sdd/tasks/index/user-identities-ownership-abac.json`
   → `"in-progress"`.
4. **Implement** per the blueprint. Two small blocks; resist every temptation
   to start the guard wiring (TASK-125) in the same commit.
5. **Verify** every acceptance criterion, AC-5, AC-8 and AC-9 included.
6. **Move this file** to `sdd/tasks/completed/TASK-121-parameterize-set-address.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: sdd-worker (sequential fallback)
**Date**: 2026-10-24
**Notes**: 7 tests pass. ruff reports 4 pre-existing unused-import errors in userattrs.py (not introduced here; left untouched).

**Deviations from spec**: none
