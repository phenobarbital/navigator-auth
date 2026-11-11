# TASK-139: `auth.py` — `MfaSignal` at the three `authenticate()` call sites + `finalize_login()` extraction

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-129
**Assigned-to**: unassigned

> **NOT delegation-eligible** (spec §3 delegation table: "the `except` clause
> must precede the generic handlers at all three sites, and the response must
> carry no token"; §7 R2). Thinking model only. Reviewers must check clause
> order and the outer response boundary by reading the diff.

---

## Context

Implements the `auth.py` half of **spec §3 Module 10** and the R2 mitigation.
TASK-138 makes `BasicAuth.authenticate()` end every second-factor outcome in an
`MfaSignal` (`MFARequired` or `MFARefused`, contract D1). That is only safe if
**every** caller of `authenticate()` lets the signal through untouched and
turns it into an HTTP response in exactly one place.

### The correctness argument (R2)

`authenticate()` is called at three sites (verified):

| Site | Line | Generic handler that would swallow the signal |
|---|---|---|
| `_login_token` | `auth.py:369` | `except Exception as err: raise self.auth_error(...)` (`:375-376`) — wraps it into an opaque HTTP error |
| `_backend_auth` | `auth.py:380` | `except AuthException as err: raise self.ForbiddenAccess(...)` (`:389-391`) — 403 with no challenge |
| `api_login` loop | `auth.py:487` | `except (AuthException, UserNotFound, InvalidAuth, FailedAuth): continue` (`:490-491`) — **tries the next backend** |

The third is the bypass: `MfaSignal` *is* an `AuthException`, so without an
earlier clause the loop moves on and a second backend that accepts the same
credentials mints a session with no second factor — 2FA defeated by backend
iteration order. The first two are not bypasses but they destroy the
challenge envelope (the client never learns a factor is owed) — AC32 requires
the explicit-backend path to answer exactly like the loop.

Therefore:

1. Each helper (`_login_token`, `_backend_auth`) gets `except MfaSignal: raise`
   as its **first** `except` clause. Helpers re-raise and **never return a
   Response** — `api_login` assigns their return value to `userdata`, and a
   Response there would flow into `JSONResponse(userdata)` + `load_session`
   (spec §3 M10 note, §7 R2 last paragraph).
2. The loop gets `except MfaSignal: raise` **before** the tuple clause.
3. `api_login` wraps all three branches in one outer
   `try … except MfaSignal as err: return JSONResponse(err.payload(), status=err.status)`
   — the **only** place an `MfaSignal` becomes HTTP, and it is reached before
   any `userdata` serialization, `load_session()` or post-processing.

### `finalize_login()`

TASK-140's `MfaHandler.verify` must finish a second-factor login through the
same session/cookie/refresh-token/vault code as `api_login` ("open_session alone
is not the complete HTTP flow" — spec M10). This task extracts that tail
(`auth.py:500-538`) into `AuthHandler.finalize_login(request, userdata)`, with
**no behaviour change**, plus one addition: it pops the transient
`MFA_DEVICE_TOKEN_KEY` (`"_mfa_trusted_device"`) from the login dict *before*
anything serializes or persists it, and sets the trusted-device cookie
(contract D14).

---

## Scope

- Import `MfaSignal` and the trusted-device constants into `auth.py`.
- Add `except MfaSignal: raise` as the first `except` clause in `_login_token`
  and `_backend_auth`.
- Restructure `api_login`: outer `try/except MfaSignal`, inner loop clause
  before the tuple, then `finalize_login()`.
- Extract `finalize_login(self, request, userdata) -> web.Response` (verbatim
  tail + device-token pop + cookie).
- Write `tests/test_mfa_auth_login_integration.py`.

**NOT in scope**:
- Raising the signals (TASK-138) — tests here use fake backends.
- MFA HTTP routes and `MfaHandler` (TASK-140).
- Any change to `api_logout`, `api_refresh_token`, `auth_startup` or route
  registration in `auth.py` (MFA routes are registered from
  `handlers/__init__.py` by TASK-140).
- Changing the existing quirks of the helpers (e.g. `_login_token` wrapping its
  own `ForbiddenAccess` via `except Exception`) — leave them byte-identical.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/auth.py` | MODIFY | imports, three call sites, `finalize_login()` |
| `tests/test_mfa_auth_login_integration.py` | CREATE | R2 regression + finalize_login tests |

---

## Codebase Contract

> Re-verified on `dev` @ `b10a3a3` (2026-11-11).

### Verified Imports

```python
# existing in auth.py, verified
from typing import Union                                    # auth.py:13  (this task adds Any)
from aiohttp import hdrs, web                               # auth.py:19
from navigator_session import SESSION_KEY, SessionHandler, get_session, SESSION_ID   # auth.py:21
from .vault.integration import load_vault_for_session, VAULT_KEYRING_APP_KEY, VAULT_SESSION_KEY  # auth.py:31-37
from .exceptions import (AuthException, AuthExpired, ConfigError, FailedAuth,
                         Forbidden, InvalidAuth, UserNotFound)  # auth.py:61-69
from .responses import JSONResponse                         # auth.py:74 (signature: JSONResponse(content, status=200, headers=None, reason=None, content_type="application/json"), responses.py:75)
# created by TASK-129
from .exceptions import MfaSignal
from .mfa.types import MFA_DEVICE_TOKEN_KEY, TRUSTED_COOKIE, trusted_cookie_kwargs
# tests
from aiohttp.test_utils import make_mocked_request
from unittest.mock import AsyncMock
```

### Existing code (verified verbatim)

```python
# auth.py:365-376
    async def _login_token(self, request: web.Request):
        # Using TrocToken or other backend on list with auth
        if backend := self.get_token_backend():
            try:
                userdata = await backend.authenticate(request)
                if not userdata:
                    raise self.ForbiddenAccess(reason="User was not authenticated")
                return userdata
            except UserNotFound as err:
                raise self.Unauthorized(reason="Invalid credentials", exception=err)
            except Exception as err:
                raise self.auth_error(reason=f"Auth Exception: {err}", exception=err)

# auth.py:378-393
    async def _backend_auth(self, request: web.Request, backend):
        try:
            userdata = await backend.authenticate(request)
            if not userdata:
                raise self.ForbiddenAccess(reason="User was not Authenticated")
            return userdata
        except UserNotFound as err:
            raise self.Unauthorized(reason="Invalid Credentials", exception=err)
        except (InvalidAuth, Forbidden, FailedAuth) as err:
            self.logger.error(str(err))
            raise self.ForbiddenAccess(reason=f"{err.message}", status=err.status)
        except AuthException as err:
            logging.exception(err)
            raise self.ForbiddenAccess(reason=f"{err.message}", exception=err, status=err.status)
        except Exception as err:
            raise self.auth_error(reason=f"Auth Exception: {err}", exception=err)

# auth.py:470-538 (api_login) — branches :478-493, tail :494-538
        userdata = None
        qs = {key: val for (key, val) in request.query.items()}
        if backend := self.get_auth_backend(request):                       # :478
            userdata = await self._backend_auth(request, backend)           # :479
        elif "auth" in qs:
            userdata = await self._login_token(request)                     # :481
        else:
            for _, backend in self.backends.items():                        # :484
                try:
                    userdata = await backend.authenticate(request)          # :487
                    if userdata:
                        break
                except (AuthException, UserNotFound, InvalidAuth, FailedAuth):   # :490
                    continue
                except Exception as err:
                    raise self.auth_error(reason=f"Auth Exception: {err}", exception=err)
        # if not userdata, then raise an not Authorized                     # :494
        if not userdata:
            raise self.ForbiddenAccess(reason="Access Denied")
        else:
            if isinstance(userdata, web.HTTPFound):
                return userdata
            # at now: create the user-session                               # :500
            try:
                response = JSONResponse(userdata, status=200)
                await self._session.storage.load_session(request, userdata, response=response)
            except Exception as err:
                raise self.Unauthorized(reason=f"Error Creating User Session: {err.message}", exception=err) from err
            # Load vault for the authenticated session (non-blocking)
            try:
                session = await get_session(request, new=False)
                user_id = userdata.get("user_id") if isinstance(userdata, dict) else getattr(userdata, "user_id", None)
                if session and user_id:
                    db_pool = request.app.get("authdb")
                    redis = request.app.get("redis")
                    refresh_token = (
                        userdata.get("refresh_token")
                        if isinstance(userdata, dict)
                        else getattr(userdata, "refresh_token", None)
                    )
                    if refresh_token and redis:
                        try:
                            # 3 months = 90 days = 7776000 seconds
                            await redis.setex(f"auth:refresh_token:{refresh_token}", 7776000, str(user_id))
                        except Exception as e:
                            self.logger.error(f"Failed to save refresh token to redis: {e}")

                    if db_pool:
                        vault = await load_vault_for_session(
                            session,
                            user_id=user_id,
                            db_pool=db_pool,
                            redis=redis,
                            keyring=request.app.get(VAULT_KEYRING_APP_KEY),
                        )
                        if vault:
                            session[VAULT_SESSION_KEY] = vault
            except Exception:
                pass  # Vault failure must not block login
            return response                                                 # :538
```

`self.ForbiddenAccess` / `self.Unauthorized` / `self.auth_error` return
`web.HTTPError` instances (`auth.py:765,838,841`) — they are not `MfaSignal`,
so the outer clause never intercepts them. `self.backends` keys are the class
names (`auth.py:240-250`); `get_token_backend()` returns `self.backends["TrocToken"]`
(`:351`); `get_auth_backend()` reads `X-Auth-Method` (`:342-348`).

### Dependency contract (TASK-129)

```python
class MfaSignal(AuthException): def payload(self) -> dict
class MFARequired(MfaSignal): __init__(challenge, providers, preferred, expires_in, status=401)
class MFARefused(MfaSignal):  __init__(code, message=None, status=403)
MFA_DEVICE_TOKEN_KEY = "_mfa_trusted_device"     # value: {"token": str, "max_age": int}
TRUSTED_COOKIE = "nav_mfa_device"
def trusted_cookie_kwargs(max_age: int) -> dict  # {"max_age", "httponly": True, "secure": True, "samesite": "Lax", "path": "/"}
```

### Does NOT Exist (do not reference)

- ~~`AuthHandler.finalize_login`~~ — created by this task.
- ~~`except MFARequired` only~~ — catch the base **`MfaSignal`** (D1): `MFARefused` must stop iteration too.
- ~~a helper returning `JSONResponse(err.payload())`~~ — forbidden; helpers re-raise (AC32).
- ~~MFA route registration in `auth.py`~~ — TASK-140 registers from `handlers/__init__.py`.

---

## Implementation Blueprint

### `navigator_auth/auth.py` — MODIFY (block 1: imports)

```python
# REPLACE `from typing import Union` (verified: auth.py:13)
# occurrences: 1 (verified: grep -cF 'from typing import Union' navigator_auth/auth.py)
from typing import Any, Union

# AFTER `    UserNotFound,` inside `from .exceptions import (` (verified: auth.py:68)
# occurrences: 1 (verified: grep -cF '    UserNotFound,' navigator_auth/auth.py)
    MfaSignal,

# AFTER `from .responses import JSONResponse` (verified: auth.py:74)
# occurrences: 1 (verified: grep -cF 'from .responses import JSONResponse' navigator_auth/auth.py)
from .mfa.types import MFA_DEVICE_TOKEN_KEY, TRUSTED_COOKIE, trusted_cookie_kwargs
```

**Why it is safe to import `mfa.types` here.** `mfa/types.py` is pure (enums,
frozen models, constants — TASK-129) and does no I/O; with 2FA disabled the
names are unused at runtime except a `dict.pop` of an absent key.

### `navigator_auth/auth.py` — MODIFY (block 2: the two helpers)

```python
# _login_token — BEFORE (unique 2-line context, verified: auth.py:373-374):
#             except UserNotFound as err:
#                 raise self.Unauthorized(reason="Invalid credentials", exception=err)
# occurrences: 1 (verified: grep -cF '                raise self.Unauthorized(reason="Invalid credentials", exception=err)' navigator_auth/auth.py)
            except MfaSignal:
                # FEAT-106 R2: a second-factor outcome is terminal. Re-raise
                # untouched — api_login alone turns it into a response.
                raise

# _backend_auth — BEFORE (unique 2-line context, verified: auth.py:384-385):
#         except UserNotFound as err:
#             raise self.Unauthorized(reason="Invalid Credentials", exception=err)
# occurrences: 1 (verified: grep -cF '            raise self.Unauthorized(reason="Invalid Credentials", exception=err)' navigator_auth/auth.py)
# NOTE: the bare 8-space line `        except UserNotFound as err:` matches 2 lines as a
# substring (:373 and :384) — anchor on the Unauthorized line below it, as above.
        except MfaSignal:
            # FEAT-106 R2: MUST precede `except AuthException` below, which would
            # turn the challenge into a 403 with no envelope (AC32).
            raise
```

**Why first and not just "before AuthException".** In `_login_token` the
swallowing clause is `except Exception`; in `_backend_auth` it is
`except AuthException` (and `except (InvalidAuth, Forbidden, FailedAuth)` —
`MfaSignal` is none of those, but placing it first makes the rule
uniform and reviewable: "the first `except` after `authenticate()` is
`MfaSignal`").

### `navigator_auth/auth.py` — MODIFY (block 3: api_login body, replaces :475-538)

```python
# REPLACE the body of api_login from `        # first: getting header for an existing backend`
# through the final `            return response` (verified: auth.py:475-538; the line
# `            return response` occurs 2 times (:337, :538) — replace by method, not by that line).
# anchor occurrences: `        if backend := self.get_auth_backend(request):` → 1 (verified: grep -cF)
        # first: getting header for an existing backend
        userdata = None
        qs = {key: val for (key, val) in request.query.items()}
        try:
            if backend := self.get_auth_backend(request):
                userdata = await self._backend_auth(request, backend)
            elif "auth" in qs:
                userdata = await self._login_token(request)
            else:
                # second: if no backend declared, will iterate over all backends
                for _, backend in self.backends.items():
                    try:
                        # check credentials for all backends
                        userdata = await backend.authenticate(request)
                        if userdata:
                            break
                    except MfaSignal:
                        # FEAT-106 R2: BEFORE the tuple below, which would
                        # `continue` and let the NEXT backend mint a session
                        # with no second factor.
                        raise
                    except (AuthException, UserNotFound, InvalidAuth, FailedAuth):
                        continue
                    except Exception as err:
                        raise self.auth_error(reason=f"Auth Exception: {err}", exception=err)
        except MfaSignal as err:
            # The ONLY place a second-factor outcome becomes HTTP (AC32): before
            # any userdata serialization, load_session() or vault loading.
            # no-store: the body carries a bearer challenge token.
            return JSONResponse(err.payload(), status=err.status, headers={"Cache-Control": "no-store"})
        # if not userdata, then raise an not Authorized
        if not userdata:
            raise self.ForbiddenAccess(reason="Access Denied")
        if isinstance(userdata, web.HTTPFound):
            return userdata
        return await self.finalize_login(request, userdata)
```

**Why one outer clause instead of three local returns.** It makes the
invariant checkable at a glance: no `userdata` assignment can ever hold a
Response produced from a signal, and nothing below the `try` runs for a
signal. Explicit-backend, token-backend and iteration all produce the *same*
envelope (AC32).

**Why `Cache-Control: no-store`.** The challenge token is a short-lived bearer
credential for the second step; it must not be cached by intermediaries. This
is an addition to the spec's `JSONResponse(err.payload(), status=401)`, not a
change of body or status.

### `navigator_auth/auth.py` — MODIFY (block 4: `finalize_login`, new method right after `api_login`)

```python
# AFTER api_login, BEFORE `    ### Auth Methods:` (verified: auth.py:540)
# occurrences: 1 (verified: grep -cF '    ### Auth Methods:' navigator_auth/auth.py)
    async def finalize_login(self, request: web.Request, userdata: Any) -> web.Response:
        """Turn an authenticated login result into the HTTP response.

        Extracted unchanged from ``api_login`` (FEAT-106) so a second-factor
        login (``MfaHandler.verify``) completes through the same session,
        refresh-token and vault code. Additionally pops the transient
        trusted-device token (contract D14) BEFORE anything serializes or
        persists ``userdata``, and sets it as a Secure/HttpOnly cookie.

        Args:
            request: The login request.
            userdata: The dict returned by a backend's ``authenticate()`` /
                ``open_session()``.

        Returns:
            The JSON login response with the session loaded.
        """
        device = userdata.pop(MFA_DEVICE_TOKEN_KEY, None) if isinstance(userdata, dict) else None
        # at now: create the user-session
        try:
            response = JSONResponse(userdata, status=200)
            await self._session.storage.load_session(request, userdata, response=response)
        except Exception as err:
            raise self.Unauthorized(reason=f"Error Creating User Session: {err.message}", exception=err) from err
        if device:
            response.set_cookie(TRUSTED_COOKIE, device["token"], **trusted_cookie_kwargs(device["max_age"]))
        # FILL IN: paste the original vault/refresh-token block (auth.py:506-537) VERBATIM here,
        #   re-indented one level LESS (it was inside `else:`), then `return response`.
        #   — bounded by AC-6: no behaviour change; `git diff -w` of that block must show only the dedent.
```

**Why pop before `JSONResponse` and before `load_session`.** `load_session`
persists `userdata` into the Redis session; `JSONResponse` would echo it to the
client body. The raw device token must exist only in the `Set-Cookie` header
(spec AC14: "device tokens in Secure/HttpOnly cookies"). Popping first makes
both impossible regardless of what the backend put in the dict.

**Why the cookie is set after `load_session`.** If session creation fails the
method raises and no device cookie leaves the server.

### `tests/test_mfa_auth_login_integration.py` — CREATE

```python
"""FEAT-106 TASK-139 — R2 regression: MfaSignal is terminal at every authenticate() call site.

Uses a real AuthHandler (BasicAuth configured, no server started) whose
``backends`` mapping is replaced by fakes, and a spy on load_session.
"""
import json
import warnings
from unittest.mock import AsyncMock

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.exceptions import MFARefused, MFARequired
from navigator_auth.mfa.types import MFA_DEVICE_TOKEN_KEY, TRUSTED_COOKIE
from navigator_auth.responses import JSONResponse

pytestmark = [
    pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
    pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning"),
]


class SignalBackend:
    """authenticate() raises the signal given at construction; records calls."""
    # FILL IN: __init__(self, exc); self.calls = 0; async authenticate(self, request): self.calls += 1; raise self.exc


class AcceptBackend:
    """authenticate() would mint a session — must NEVER be reached after a signal."""
    # FILL IN: self.calls = 0; async authenticate(...) -> {"user_id": 1, "token": "minted"}


# FILL IN fixture `auth_app`: set conf.AUTHENTICATION_BACKENDS = ("navigator_auth.backends.BasicAuth",)
#   (restore after), build web.Application(), AuthHandler(secure_cookies=False).setup(app) inside
#   warnings.catch_warnings(); monkeypatch auth._session.storage.load_session = AsyncMock();
#   return (app, auth). Pattern: tests/test_basic_open_session.py:58-80.

CHALLENGE = MFARequired(challenge="opaque-challenge", providers=["email"], preferred="email", expires_in=300)


@pytest.mark.asyncio
async def test_api_login_mfa_required_does_not_try_next_backend(auth_app):
    """AC7: loop stops at the signal; the next backend is never called; 401 + envelope."""
    # FILL IN: auth.backends = {"Signal": SignalBackend(CHALLENGE), "Accept": AcceptBackend()}


@pytest.mark.asyncio
async def test_api_login_mfa_refused_does_not_try_next_backend(auth_app):
    """D1: MFARefused('mfa_unavailable', 503) is terminal too — 503, next backend untouched."""
    # FILL IN


@pytest.mark.asyncio
async def test_api_login_mfa_required_creates_no_session(auth_app):
    """AC6: load_session never awaited; body has no token/refresh_token/session_id; no-store header."""
    # FILL IN


@pytest.mark.asyncio
async def test_explicit_backend_mfa_response(auth_app):
    """AC32: X-Auth-Method path and ?auth= (TrocToken) path return the SAME 401 envelope as the loop."""
    # FILL IN: headers={"X-Auth-Method": "Signal"}; then backends["TrocToken"] = SignalBackend(...) with path "/api/v1/login?auth=1"


@pytest.mark.asyncio
async def test_helpers_reraise_mfa_signal(auth_app):
    """AC32: _backend_auth and _login_token raise the signal itself — never a Response/HTTP error."""
    # FILL IN: with pytest.raises(MFARequired): await auth._backend_auth(req, SignalBackend(CHALLENGE))


@pytest.mark.asyncio
async def test_finalize_login_sets_trusted_cookie_and_strips_token(auth_app):
    """D14/AC14: token only in Set-Cookie (HttpOnly, Secure, SameSite=Lax); absent from body and load_session arg."""
    # FILL IN


@pytest.mark.asyncio
async def test_finalize_login_without_device_is_unchanged(auth_app):
    """AC20: no device key ⇒ body bytes equal JSONResponse(userdata).body; no nav_mfa_device cookie."""
    # FILL IN
```

**Why a real `AuthHandler` with fake backends.** The bug class (R2) lives in
`AuthHandler`'s control flow, so that must be the real code; the backends are
the variable, so they are fakes that make "was the next backend reached?"
directly observable.

### Steps (in order)

1. Confirm TASK-129 is done: `python -c "from navigator_auth.exceptions import MfaSignal, MFARequired, MFARefused; from navigator_auth.mfa.types import MFA_DEVICE_TOKEN_KEY, TRUSTED_COOKIE, trusted_cookie_kwargs"`.
2. Block 1 (imports).
3. Block 2 — both helpers. Re-read each: the first `except` after
   `authenticate()` is `except MfaSignal: raise`.
4. Block 4 first (add `finalize_login` with the verbatim tail), then block 3
   (rewrite `api_login` to call it). Doing it in this order keeps the file
   importable between steps.
5. `git diff -w navigator_auth/auth.py` — the vault/refresh block must show no
   change other than location/indentation.
6. Write and fill the tests; run them.
7. Run the regression gate and ruff.

### FILL IN checklist

- [ ] `finalize_login` — verbatim tail pasted, dedented, `return response` — AC-6
- [ ] `SignalBackend` / `AcceptBackend` fakes
- [ ] `auth_app` fixture (+ restore `AUTHENTICATION_BACKENDS`)
- [ ] 7 test bodies — AC-1…AC-6

---

## Acceptance Criteria

- [ ] **AC-1** In `api_login`'s loop, an `MfaSignal` raised by a backend stops iteration; no later backend's `authenticate()` is called (spec AC7, D1 — for both `MFARequired` and `MFARefused`).
- [ ] **AC-2** `_backend_auth` and `_login_token` re-raise `MfaSignal` unchanged (first `except` clause) and never return a Response (spec AC32).
- [ ] **AC-3** All three paths (explicit `X-Auth-Method`, `?auth=`, iteration) return the identical `JSONResponse(err.payload(), status=err.status)` envelope with `Cache-Control: no-store` (spec AC32).
- [ ] **AC-4** For a signal, `load_session` is never awaited, no session cookie is set, and the body contains no `token`, `refresh_token` or session id (spec AC6 — handler half).
- [ ] **AC-5** `finalize_login` pops `_mfa_trusted_device` before serialization and persistence; the raw token appears only in a `nav_mfa_device` cookie with `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, `Max-Age=<max_age>` (spec AC14, D14).
- [ ] **AC-6** For a login dict without the device key, `finalize_login`'s response body is byte-identical to `JSONResponse(userdata, status=200).body`, and the refresh-token/vault behaviour is unchanged (`git diff -w` shows only relocation) (spec AC20).
- [ ] **AC-7** `pytest tests/test_mfa_auth_login_integration.py -v` passes; regression `pytest tests/test_basic_auth.py tests/test_login.py tests/test_passkey_signin.py tests/test_basic_open_session.py -q` passes unchanged (spec AC3); `ruff check navigator_auth/auth.py tests/test_mfa_auth_login_integration.py` is clean.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_auth_login_integration.py -v
pytest tests/test_basic_auth.py tests/test_login.py tests/test_passkey_signin.py tests/test_basic_open_session.py -q   # AC3 regression
ruff check navigator_auth/auth.py tests/test_mfa_auth_login_integration.py
```

Spec §4 rows owned here: `test_api_login_mfa_required_does_not_try_next_backend`
(R2 regression), `test_api_login_mfa_required_creates_no_session`,
`test_explicit_backend_mfa_response`.

---

## Agent Instructions

1. **Read the spec** `sdd/specs/basicauth-otp-2fa.spec.md`: §2 Overview
   ("Signalling the challenge is ordering-sensitive"), §3 M10 skeleton comments,
   §7 R2 in full; FEAT-106 contract D1 and D14.
2. **Check dependencies** — TASK-129 in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint; do not "tidy" the surrounding handlers.
5. **Verify** AC-1…AC-7; read the final `api_login` and both helpers once more
   with only one question: "can any `MfaSignal` reach a generic handler or a
   `userdata` assignment?".
6. **Move this file** to `sdd/tasks/completed/TASK-139-mfa-auth-call-sites.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
