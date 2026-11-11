# TASK-200: `IdentityStoreUnavailable` — `user_from_id` separates a missing user from a store outage

**Feature**: FEAT-108 — OAuth2 3LO examples work end-to-end — auth paths fail closed on misconfiguration and unknown users
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Spec §2 (identity-store paragraph, D6), §3 Module 6, AC16a, §2 New Public Interfaces item 3.
`IdentityProvider.user_from_id` wraps **every** storage error as `UserNotFound`
(`idp/__init__.py:141-142`). FEAT-108's owner checks must treat a confirmed missing/disabled user
(→ `invalid_grant`, refresh-chain revocation) differently from an outage (→ generic 503, no
revocation, retry later). This task adds the public `IdentityStoreUnavailable` exception and the
split; TASK-203/204/205 consume it. It also creates the feature's owner-check test file.

---

## Scope

- Add `IdentityStoreUnavailable(AuthException)` (status 503, generic message) to `navigator_auth/exceptions.py`.
- In `IdentityProvider.user_from_id`: keep `UserNotFound` for `NoDataFound` and empty results, keep
  re-raising `ValidationError`, re-raise any `AuthException` as is, and raise
  `IdentityStoreUnavailable` (original chained, details only in the server log) for every other error.
  Define `search` **before** the `try` (today a failing `self.app["authdb"]` makes the handler hit an
  unbound `search`).
- Create `tests/test_oauth2_unknown_resource_owner.py` with the `user_from_id` tests.

**NOT in scope**: the provider call sites (TASK-203/204/205); `get_user` (unchanged); CHANGELOG (TASK-207).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/exceptions.py` | MODIFY | New public `IdentityStoreUnavailable` |
| `navigator_auth/backends/idp/__init__.py` | MODIFY | Import it; split errors in `user_from_id` |
| `tests/test_oauth2_unknown_resource_owner.py` | CREATE | `user_from_id` outcome tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `61d424b` AND `feat-FEAT-106-basicauth-otp-2fa` @ `0b80d88` (2026-11-11).
> FEAT-106 adds classes to `exceptions.py` (lines shift +4) and `dev` already moved `idp/__init__.py`
> (refresh helper); anchors are textual.

### Verified Imports
```python
from navigator_auth.exceptions import AuthException, UserNotFound   # verified: exceptions.py:3, :32 (dev)
from asyncdb.exceptions import NoDataFound                          # verified: navigator_auth/backends/idp/__init__.py:11
from datamodel.exceptions import ValidationError                    # verified: navigator_auth/backends/idp/__init__.py:12
from navigator_auth.backends.idp import IdentityProvider            # verified: tests/test_oauth2_3lo_session_binding.py:24
```

### Existing Signatures to Use
```python
# navigator_auth/exceptions.py
class AuthException(Exception):                       # :3  (message, status=400, **kwargs)
class UserNotFound(AuthException):                    # dev :32 / 106 :35 (status 404)
class Unauthorized(AuthException):                    # dev :37 / 106 :41  ← insert the new class above this

# navigator_auth/backends/idp/__init__.py
from ...exceptions import UserNotFound, ConfigError, InvalidAuth, FailedAuth, AuthExpired, AuthException  # :35
class IdentityProvider:                                # :39
    async def user_from_id(self, uid: int) -> Identity:   # dev :126 / 106 :124
        #  user = None
        #  try:
        #      db = self.app["authdb"]
        #      async with await db.acquire() as conn:
        #          search = {self.userid_attribute: uid}
        #          self.user_search.Meta.connection = conn
        #          user = await self.user_search.get(**search)
        #  except NoDataFound as ex: raise UserNotFound(...) from ex
        #  except ValidationError as ex: log; raise
        #  except Exception as e: raise UserNotFound(f"Error getting User {search!s}: {e!s}") from e   # dev :141-142
        #  if not user: raise UserNotFound(...)
        #  return user
```

### Callers whose behaviour changes (run their tests; no code change here)
- `backends/exchange.py:168` and `backends/passkey.py:449`, `:568` catch only `UserNotFound`: an outage now
  propagates as `IdentityStoreUnavailable` (503) instead of reading as "no such user" — intended (spec §2 item 3).
- `backends/abstract.py:280` (`validate_user`), `auth.py:424`, `oauth2/backend.py:2230`, `:2487` catch broadly — unchanged.

### Does NOT Exist
- ~~`IdentityStoreUnavailable`~~, ~~`IdentityStoreError`~~, ~~`StorageUnavailable`~~ — new here; no `UnknownResourceOwner` exception either (spec §6).
- No unit test of `IdentityProvider.user_from_id` exists today.
- `user_from_id` never checks `is_active` — that stays the resolver's job (TASK-203).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/exceptions.py", "action": "MODIFY"},
    {"path": "navigator_auth/backends/idp/__init__.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_unknown_resource_owner.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/exceptions.py#AuthException",
    "sym:navigator_auth/exceptions.py#UserNotFound",
    "sym:navigator_auth/backends/idp/__init__.py#IdentityProvider",
    "sym:navigator_auth/backends/idp/__init__.py#IdentityProvider.user_from_id"
  ]
}
```

---

## Implementation Notes

- The exception's default message is generic ("Identity store unavailable."); never put the DB error
  text into `message` — responses built from it would leak it. Log the detail with `self.logger.error`.
- Order of `except` clauses: `NoDataFound` → `ValidationError` → `AuthException` (re-raise) → `Exception`.

---

## Implementation Blueprint

### Steps (in order)
1. Add the exception class — *why*: public contract for custom IdPs (spec §2 New Public Interfaces).
2. Import it in the IdP and rewrite the `except` chain of `user_from_id` — *why*: D6 / AC16a.
3. Create the test file; run it plus the passkey/exchange suites that call `user_from_id`.

### `navigator_auth/exceptions.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'class Unauthorized(AuthException):' navigator_auth/exceptions.py)
# BEFORE — insert above `class Unauthorized(AuthException):` (verified: dev :37 / FEAT-106 :41)
class IdentityStoreUnavailable(AuthException):
    """The identity store could not be queried (FEAT-108).

    Raised for infrastructure failures (pool, connection or query errors) so that callers
    never confuse an outage with a confirmed missing user (:class:`UserNotFound`).
    Custom IdPs must raise ``UserNotFound`` only for a confirmed missing user and this
    exception for infrastructure failures. The message stays generic; chain the original
    exception (``raise IdentityStoreUnavailable() from err``) and log details server-side.
    """

    def __init__(self, message: str = None, status=503):
        super().__init__(message or "Identity store unavailable.", status=status)

```

### `navigator_auth/backends/idp/__init__.py` (MODIFY) — import
```python
# occurrences: 1 (verified: grep -c 'from ...exceptions import UserNotFound, ConfigError, InvalidAuth, FailedAuth, AuthExpired, AuthException' navigator_auth/backends/idp/__init__.py)
# REPLACE (verified: :35) WITH:
from ...exceptions import (
    UserNotFound,
    ConfigError,
    InvalidAuth,
    FailedAuth,
    AuthExpired,
    AuthException,
    IdentityStoreUnavailable,
)
```

### `navigator_auth/backends/idp/__init__.py` (MODIFY) — `user_from_id`
```python
# occurrences: 1 (verified: grep -c 'async def user_from_id(self, uid: int) -> Identity:' navigator_auth/backends/idp/__init__.py)
# REPLACE the whole method body (verified: dev :126-146 / FEAT-106 :124-144) WITH:
    async def user_from_id(self, uid: int) -> Identity:
        """Return the user record for ``uid``.

        Raises:
            UserNotFound: confirmed missing user (``NoDataFound`` or an empty result).
            ValidationError: the stored record does not fit the user model.
            IdentityStoreUnavailable: any other storage failure (FEAT-108); the original
                exception is chained and only logged, never put in the message.
        """
        user = None
        search = {self.userid_attribute: uid}
        try:
            db = self.app["authdb"]
            async with await db.acquire() as conn:
                self.user_search.Meta.connection = conn
                user = await self.user_search.get(**search)
        except NoDataFound as ex:
            raise UserNotFound(f"Invalid credentials for User {search!s}") from ex
        except ValidationError as ex:
            self.logger.error(f"Invalid User Information {search!s}: {ex}")
            self.logger.warning(f"Error on User Model = {ex.payload!r}")
            raise
        except AuthException:
            raise
        except Exception as err:  # pylint: disable=W0703
            self.logger.error(f"IdP: user lookup failed for {search!s}: {err!s}")
            raise IdentityStoreUnavailable() from err
        if not user:
            raise UserNotFound(f"Invalid credentials for User {search!s}")
        return user
```
**Why**: `search` moves above the `try` so the outage branch can always log it.

### `tests/test_oauth2_unknown_resource_owner.py` (CREATE)
```python
"""FEAT-108 M6 — unknown or disabled resource owners fail closed; store outages answer 503.

TASK-200 adds the IdentityProvider.user_from_id tests; TASK-203/204 append provider tests.
"""
from unittest.mock import AsyncMock, MagicMock

import pytest
from asyncdb.exceptions import NoDataFound
from datamodel.exceptions import ValidationError

from navigator_auth.backends.idp import IdentityProvider
from navigator_auth.exceptions import IdentityStoreUnavailable, UserNotFound


def _idp(*, get=None, acquire_error=None) -> IdentityProvider:
    """IdentityProvider over a fake pool: `async with await db.acquire() as conn`."""
    idp = IdentityProvider()
    conn_ctx = MagicMock()
    conn_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    conn_ctx.__aexit__ = AsyncMock(return_value=False)
    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=conn_ctx, side_effect=acquire_error)
    idp.app = {"authdb": pool}
    idp.user_search = MagicMock()
    idp.user_search.get = get or AsyncMock(return_value=None)
    return idp


class TestUserFromId:
    @pytest.mark.asyncio
    async def test_found(self):
        user = MagicMock()
        assert await _idp(get=AsyncMock(return_value=user)).user_from_id(1) is user

    @pytest.mark.asyncio
    async def test_no_data_found_is_user_not_found(self):
        with pytest.raises(UserNotFound):
            await _idp(get=AsyncMock(side_effect=NoDataFound("none"))).user_from_id(1)

    @pytest.mark.asyncio
    async def test_empty_result_is_user_not_found(self):
        with pytest.raises(UserNotFound):
            await _idp(get=AsyncMock(return_value=None)).user_from_id(1)

    @pytest.mark.asyncio
    async def test_validation_error_is_reraised(self):
        # FILL IN: build a datamodel ValidationError with the args its __init__ needs (it exposes .payload)
        #          and assert it propagates unchanged — bounded by spec §2 ("retain ValidationError").
        pass

    @pytest.mark.asyncio
    @pytest.mark.parametrize("where", ["acquire", "query", "no_pool"])
    async def test_store_outage_is_identity_store_unavailable(self, where):
        # FILL IN: acquire → _idp(acquire_error=ConnectionError("pool")); query → get raising RuntimeError;
        #          no_pool → idp.app = {}. Assert IdentityStoreUnavailable, status 503, __cause__ is the
        #          original error, and str(exc) does not contain the original message — bounded by AC16a.
        pass
```
**Why this shape**: TASK-203 and TASK-204 append their classes to this file — keep the module docstring
and the `_idp` helper name.

### FILL IN checklist
- [ ] `test_validation_error_is_reraised` — real `ValidationError` construction.
- [ ] `test_store_outage_is_identity_store_unavailable` — three outage shapes; generic message; AC16a.

---

## Acceptance Criteria

- [ ] `IdentityStoreUnavailable` is importable from `navigator_auth.exceptions`, subclasses `AuthException`, default status 503, generic message.
- [ ] `user_from_id`: `NoDataFound` / empty → `UserNotFound`; `ValidationError` re-raised; acquire/query/missing-pool errors → `IdentityStoreUnavailable` with the cause chained and no DB detail in the message (AC16a, first clause).
- [ ] Existing suites still pass: `tests/test_oauth2_introspection.py`, `tests/test_oauth2_3lo_session_binding.py` (its 3 `TestDecodeTokenAudience` failures are pre-existing locally: a 6-byte `AUTH_SECRET_KEY` in `env/.env` + `filterwarnings=error`; they are not regressions).
- [ ] `ruff check` clean on the three files.

---

## Validation Commands

- `pytest tests/test_oauth2_unknown_resource_owner.py -q`
- `pytest tests/test_oauth2_introspection.py -q`

---

## Test Specification

`TestUserFromId` in the CREATE block (spec §4 `test_owner_store_outage`, the IdP half).

---

## Agent Instructions

When you pick up this task:

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug oauth2-3lo-issues --feature-id FEAT-108`).
   The spec requires the worktree to be created from `origin/dev` **after FEAT-106 (PR #633) merges**.
2. **Read the spec** at the path listed above for full context.
3. **Check dependencies** — every `Depends-on` task must be `"done"` in `sdd/tasks/index/oauth2-3lo-issues.json`.
4. **Verify the Codebase Contract** — re-run each `grep -c` in the blueprint before editing; a changed
   count means the anchor moved (re-locate it), a `0` means drift (stop and report).
5. **Update status** in the index → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** from the Implementation Blueprint; complete every `# FILL IN:`; never change a fixed signature or path.
7. **Verify** — run the Validation Commands.
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`).
9. **Close the task** with `parrot sdd task close TASK-200 oauth2-3lo-issues verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none
