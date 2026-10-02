# TASK-91: `is_active` enforcement — `open_session`, `BasicAuth.authenticate`, OAuth2 `auth_login`

**Feature**: FEAT-101 — Passkey (WebAuthn) Authentication Backend
**Spec**: `sdd/specs/passkey-support-backend.spec.md` (Module 4, §2.6, §2.8, §7 R2/R3, AC9, Q-F1)
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Today no login path rejects disabled accounts. U2 and G6 fix this in `BasicAuth.open_session`,
so Basic, TokenExchange and Passkey all inherit the check. Q-F1 was resolved as "folded into
Module 4": the OAuth2 login page's password POST (`Oauth2Provider.auth_login`) gets the same check.

One shared helper, `user_is_active`, keeps the rule in one place. This task also adds `mfa` and
`amr` to the JWT extras (G5/Q6), which TASK-95 relies on.

---

## Scope

- Add module-level `user_is_active(user) -> bool` to `navigator_auth/backends/abstract.py`.
  - It handles a `Mapping` (`.get`) and any other object (`getattr`).
  - It returns `False` **only** when `is_active` is present and false. A missing field, or a
    `None` value, counts as active.
- `BasicAuth.open_session`:
  - **before** `remember()`, raise `FailedAuth("User account is disabled", status=403)` when
    `not user_is_active(user)`, so no session is created;
  - log the rejection at warning level with the user id, never the username or password.
- `BasicAuth._JWT_EXTRA_KEYS` gains `"mfa"` and `"amr"`, and the `open_session` docstring is updated.
- `BasicAuth.authenticate`: let `FailedAuth` and `InvalidAuth` from `open_session` propagate. Any
  other exception keeps today's `return False` path (R3).
- `Oauth2Provider.auth_login` POST: after the `authenticate_credentials` try block and before
  building the redirect and session, raise
  `web.HTTPForbidden(reason="Auth: User account is disabled.")` when `not user_is_active(user)`.
- Tests: the unit and live tests named in spec §4 for Module 4.
- `CHANGELOG.md` "Unreleased": add a breaking-behaviour note (R2).

**NOT in scope**:
- `TokenExchangeAuth`. It calls `open_session` directly (`exchange.py:216`), so it inherits the
  check. Only verify that its 403 surfaces cleanly (R3).
- Any change to `auth.py`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/abstract.py` | MODIFY | `user_is_active` helper |
| `navigator_auth/backends/basic.py` | MODIFY | Check, JWT extras, exception propagation |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | Q-F1 check in `auth_login` |
| `tests/unit/test_user_is_active.py` | CREATE | Helper unit tests |
| `tests/test_basic_open_session.py` | MODIFY | Inactive, missing-field, `mfa`/`amr`, propagation tests |
| `tests/test_oauth2_auth_login_inactive.py` | CREATE | Q-F1 tests with a mocked provider |
| `CHANGELOG.md` | MODIFY | R2 behaviour-change note |

---

## Codebase Contract (Anti-Hallucination)

> Verified 2026-10-02 against `dev` @ `564c440`.

### Verified Imports
```python
from collections.abc import Callable, Iterable          # abstract.py:2  (add Mapping here)
from .abstract import BaseAuthBackend                   # basic.py:17
from ..abstract import BaseAuthBackend                  # oauth2/backend.py:107
from ..exceptions import (AuthException, FailedAuth, UserNotFound, InvalidAuth)   # basic.py:20-25 (already imported)
from aiohttp import web                                 # basic.py:10, oauth2/backend.py:40
```

### Existing Signatures to Use
```python
# backends/abstract.py
class BaseAuthBackend(ABC):                              # :42   ← add user_is_active ABOVE this
# backends/basic.py
class BasicAuth(BaseAuthBackend):                        # :43
    _JWT_EXTRA_KEYS = ("auth_method", "auth_origin", "external_expires_at")   # :154
    async def open_session(self, request, user: dict, extra=None, expiration=None) -> dict:  # :171
        userdata = self.get_userdata(user=user)          # :199  (first statement after the docstring)
        ...
        ### saving User data into session:              # :212
        session = await self.remember(request, username, userdata, usr)   # :213
    async def authenticate(self, request):               # :292
            try:
                return await self.open_session(request, user)   # :311
            except Exception as err:  # pylint: disable=W0703  # :312
                self.logger.exception(f"BasicAuth: Authentication Error: {err}")
                return False
# backends/oauth2/backend.py
async def auth_login(self, request: web.Request):        # :1696
    elif request.method == "POST":
        username, password, data = await self.get_login_form(request)
        try:
            user = await self._idp.authenticate_credentials(login=username, password=password)  # :1716
        except (FailedAuth, UserNotFound) as exc: raise web.HTTPBadRequest(...)
        except (ValidationError, InvalidAuth) as exc: raise web.HTTPBadRequest(...)
        except Exception as exc: raise web.HTTPBadRequest(...)
        location = request.app.router["nav_oauth2_authorize"].url_for()   # :1724  ← insert ABOVE
```
- `user` in `open_session` is the IdP model (`validate_user`) or a dict (tests,
  `TokenExchangeAuth`). `user` in `auth_login` is the IdP `user_search` model (`idp/__init__.py:146`).
- `FailedAuth(message=None, status=403)` (`exceptions.py:47`).
- Test patterns:
  - `tests/test_basic_open_session.py`: a live app plus a `/_test/open_session` route that calls
    `open_session` with `_fake_user()`. That dict has `"enabled": True` and **no** `is_active`,
    so it exercises the missing-field case.
  - `tests/test_oauth2_upstream_idp.py:52-66`: `Oauth2Provider(user_model=MagicMock(), identity=MagicMock())` and a MagicMock request.

### Does NOT Exist
- Any `is_active` check in a login path today, a `user_is_active` helper, or `BasicAuth._is_active`.
- `web.HTTPForbidden` handling around `auth_login` POST. The new raise must sit **outside** the
  `try` whose bare `except Exception` turns everything into `HTTPBadRequest`.

---

## Implementation Blueprint

### Steps (in order)
1. Add `Mapping` to the `collections.abc` import and define `user_is_active` above
   `class BaseAuthBackend`. Module level means OAuth2 can import it without a `BasicAuth` instance.
2. `basic.py`:
   - import `user_is_active` next to `BaseAuthBackend`;
   - extend `_JWT_EXTRA_KEYS`;
   - add the check as the **first** statement of `open_session`, before `get_userdata`. Rejecting
     before any work means nothing is written to the session, and no callbacks fire (AC9);
   - add an `except (FailedAuth, InvalidAuth): raise` clause before the generic `except` in `authenticate`.
3. `oauth2/backend.py`: import the helper, and insert the check between the `try/except` block and `location = ...`.
4. Write the tests, run the existing Basic, open_session, token-exchange and OAuth2 suites, and add the CHANGELOG line.

### `navigator_auth/backends/abstract.py` — MODIFY
```python
# REPLACE `from collections.abc import Callable, Iterable` (verified: abstract.py:2; occurrences: 1) with:
from collections.abc import Callable, Iterable, Mapping

# BEFORE — insert above `class BaseAuthBackend(ABC):` (verified: abstract.py:42; occurrences: 1)
def user_is_active(user) -> bool:
    """Return whether a user record may log in.

    ``False`` only when the record explicitly carries a false ``is_active``;
    a missing field (custom ``AUTH_USER_VIEW``) or ``None`` counts as active.

    Args:
        user: User record — a mapping or a model/object.

    Returns:
        bool: ``True`` unless ``is_active`` is present and false.
    """
    if isinstance(user, Mapping):
        value = user.get("is_active", None)
    else:
        value = getattr(user, "is_active", None)
    # FILL IN: return True when value is None; otherwise bool(value) — bounded by
    #          test_user_is_active_dict_and_model (0/False → inactive, missing/None → active).
```

### `navigator_auth/backends/basic.py` — MODIFY
```python
# REPLACE `from .abstract import BaseAuthBackend` (verified: basic.py:17; occurrences: 1) with:
from .abstract import BaseAuthBackend, user_is_active

# REPLACE (verified: basic.py:154; occurrences: 1)
    _JWT_EXTRA_KEYS = ("auth_method", "auth_origin", "external_expires_at", "mfa", "amr")

# open_session — insert as the FIRST statement. `userdata = self.get_userdata(user=user)` occurs
# 2 times in basic.py (:199 open_session, :333 another method), so anchor on this unique 3-line
# context (verified: basic.py:196-199) and insert between the docstring close and :199:
#         ``authenticate()``, which logs and returns ``False``).
#         """
#         userdata = self.get_userdata(user=user)
        if not user_is_active(user):
            self.logger.warning(
                f"BasicAuth: rejected login for disabled user {user[self.userid_attribute]}"
            )
            raise FailedAuth("User account is disabled", status=403)

# authenticate — REPLACE the block (verified: basic.py:310-314; `return await self.open_session(request, user)` occurrences: 1)
            try:
                return await self.open_session(request, user)
            except (FailedAuth, InvalidAuth):
                raise
            except Exception as err:  # pylint: disable=W0703
                self.logger.exception(f"BasicAuth: Authentication Error: {err}")
                return False
```
Also update the `open_session` docstring: add the `mfa`/`amr` keys and a `Raises: FailedAuth (403) when the user is inactive` line.
**Why**: `AuthHandler._backend_auth` (`auth.py:386`) maps `FailedAuth` to a 403 with `err.status`.
Swallowing it into `False` would turn a precise "disabled" into a generic failure (R3).

### `navigator_auth/backends/oauth2/backend.py` — MODIFY
```python
# REPLACE `from ..abstract import BaseAuthBackend` (verified: oauth2/backend.py:107; occurrences: 1) with:
from ..abstract import BaseAuthBackend, user_is_active

# BEFORE — insert above `location = request.app.router["nav_oauth2_authorize"].url_for()`
#   (verified: oauth2/backend.py:1724; occurrences: 1), at the same indentation:
            if not user_is_active(user):
                self.logger.warning("Oauth2: rejected login for a disabled user")
                raise web.HTTPForbidden(reason="Auth: User account is disabled.")
```
**Why**: Q-F1. The check runs after the credentials verify, so an attacker cannot use it to probe
whether an account is disabled without the password. It also runs before `_create_user_session`,
so no cookie is issued.

### `tests/unit/test_user_is_active.py` — CREATE
```python
"""FEAT-101 TASK-91 — user_is_active helper."""
from types import SimpleNamespace

import pytest

from navigator_auth.backends.abstract import user_is_active


@pytest.mark.parametrize(
    "user, expected",
    [
        ({"is_active": True}, True),
        ({"is_active": False}, False),
        ({"enabled": True}, True),          # field missing → active
        ({"is_active": None}, True),
        (SimpleNamespace(is_active=False), False),
        (SimpleNamespace(), True),
    ],
)
def test_user_is_active_dict_and_model(user, expected):
    assert user_is_active(user) is expected
```

### Tests to add (bodies are FILL IN)
- `tests/test_basic_open_session.py`:
  - `test_open_session_rejects_inactive`: needs a variant route or a parameter that sets `is_active=False` → 403 and no session cookie;
  - `test_open_session_missing_is_active_is_active`;
  - `test_open_session_jwt_mfa_amr`: `extra={"mfa": True, "amr": ["hwk","user"]}` lands in the decoded JWT;
  - `test_basic_authenticate_propagates_failedauth`: monkeypatch `validate_user` to return an inactive user and call `authenticate`.
- `tests/test_oauth2_auth_login_inactive.py`: `test_oauth2_auth_login_rejects_inactive`.
  - Use a mocked provider: `_idp.authenticate_credentials` is an `AsyncMock` returning `{"is_active": False, ...}`, and `get_login_form` is patched.
  - Assert `HTTPForbidden`, and that `_create_user_session` was not awaited.
  - The active-user case still reaches the redirect path.

### FILL IN checklist
- [ ] `user_is_active` return expression.
- [ ] Four open_session/authenticate tests and the OAuth2 test.
- [ ] CHANGELOG note under "Unreleased" (R2): inactive users now get 403 on Basic, TokenExchange, Passkey and the OAuth2 login page.

---

## Acceptance Criteria

- [ ] AC9: `open_session` rejects `is_active=False` with 403 and creates no session. Users without the field are unaffected. The `auth_login` password POST rejects inactive users with 403 before any session.
- [ ] `pytest tests/unit/test_user_is_active.py tests/test_oauth2_auth_login_inactive.py tests/test_basic_auth.py tests/test_basic_open_session.py tests/test_token_exchange_backend.py tests/test_oauth2_upstream_idp.py -v` passes. The live suites need Postgres and Redis.
- [ ] `ruff check` shows no new findings on the touched files.

---

## Test Specification

See above (spec §4, Module 4 rows).

---

## Agent Instructions

1. Read the spec (Module 4, §2.8, R2, R3, Q-F1).
2. This task has no task dependencies. It runs in parallel with TASK-92 after stage S0.
3. Set this task to `"in-progress"` in `sdd/tasks/index/passkey-support-backend.json`.
4. Implement inside `.worktrees/feat-FEAT-101-passkey-support-backend`.
5. Verify the acceptance criteria.
6. Move this file to `sdd/tasks/completed/`, set the index entry to `"done"`, and fill in the Completion Note.

---

## Completion Note

**Completed by**:
**Date**:
**Notes**:
**Deviations from spec**: none
