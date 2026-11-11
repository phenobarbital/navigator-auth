# TASK-185: Durable OAuth credential generation: stamp and enforce

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-171, TASK-172, TASK-175, TASK-179, TASK-184
**Assigned-to**: unassigned

---

## Context

Spec §3 **Module 4 — "Durable recovery and token revocation contract"** (G9): after an admin
`password_reset` or a recovery completion, every OAuth artifact minted before the change —
authorization codes, device-flow carriers, access tokens and refresh chains, including legacy
ones with no generation — must stop working, without relying on a Redis JTI index. The
mechanism is a per-user **credential generation** stored in `{schema}.oauth_user_generation`
(table + store helpers created by TASK-175). Reset (TASK-179) and recovery (TASK-180) increment
it in their transaction; **this task stamps it on every user OAuth artifact and enforces
equality at every validation point**, serializing issuance with reset under the same per-user
advisory lock (TASK-171).

Implements: the generation half of AC30, AC24 ("at generation 0 the 2FA-off token payload keys
match `origin/dev`; after a reset the generation claim is present"), and the token-rejection
half of AC28 (enforcement; the increment itself is TASK-179/180).

---

## Scope

- Add `generation: int = Field(default=0)` to `OauthAuthorizationCode` and `OauthRefreshToken`, and
  a module-level predicate `is_oauth_user_token(payload)` in `backends/oauth2/models.py`.
- Add provider seams `_auth_pool(request)`, `_user_generation(request, user_id)` (async CM:
  `advisory_user_lock` + `current_generation`, yields `(conn, generation)`) and
  `_generation_ok(request, user_id, presented)` (`generation_matches`).
- `_token_session_claims(request, user_id, *, conn=None)`: pass `conn` to `user_from_id` when given
  (no nested pool acquire under the lock — G3).
- **Stamp under the lock**: `_issue_code` (authorize + consent paths) and `_approve_device_code`
  (device carrier) read the generation inside `_user_generation` and store it on the carrier.
- **Exchange / refresh under the lock**: `_handle_authorization_code` (also reached by the device
  grant) and `_handle_refresh_token` re-read the generation inside `_user_generation`; mismatch →
  `invalid_grant` (code deleted / chain revoked, nothing minted); match → mint access token with
  `stamp_generation(token_data, gen)`, copy the carrier's generation onto the issued/rotated
  `OauthRefreshToken`, call `_token_session_claims(..., conn=conn)`.
- **Enforce at validation**: `Oauth2Provider.authenticate`, `userinfo`, `introspect` (access AND
  refresh tokens) and `AuthHandler._auth_middleware` (excluded-path best-effort branch and main
  branch — the main-branch check precedes session recreation, covering it).
- Lookup failure fails closed everywhere: token endpoint 503 `temporarily_unavailable`;
  introspection `{"active": false}`; userinfo 503; `authenticate` raises; middleware 503 (main
  branch) / unauthenticated (excluded branch).
- Add the generation seam stub to the provider factories of the existing OAuth2 unit suites that
  now reach these paths (mock providers have no `authdb`).
- Write `tests/test_mfa_review_fixes_oauth2_tokens.py` (generation tests).

**NOT in scope**: incrementing the generation (TASK-179 `password_reset`, TASK-180 recovery);
`mfa`/`amr` on codes/tokens and the browser-event validation (TASK-186); ABAC bearer context
(TASK-187); the tables and store helpers themselves (TASK-175); `client_credentials` (no user —
unchanged).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | imports, generation seams, `_token_session_claims(conn=)`, stamping in `_issue_code`/`_approve_device_code`, lock + recheck in code exchange/refresh, enforcement in `authenticate`/`userinfo`/`introspect` |
| `navigator_auth/backends/oauth2/models.py` | MODIFY | `generation` fields; `is_oauth_user_token()` |
| `navigator_auth/auth.py` | MODIFY | `_oauth_generation_ok()`; checks in both `_auth_middleware` branches |
| `tests/test_mfa_review_fixes_oauth2_tokens.py` | CREATE | AC30 / AC24 / AC28 generation tests |
| `tests/test_oauth2_access_gate.py` | MODIFY | generation seam stub in the `provider` fixture |
| `tests/test_oauth2_introspection.py` | MODIFY | generation seam stub in `_make_provider` |
| `tests/test_oauth2_introspection_device_integration.py` | MODIFY | generation seam stub in `_make_provider` |
| `tests/test_oauth2_mcp_conformance.py` | MODIFY | generation seam stub in the `provider` fixture |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `0b80d88` (branch `feat-FEAT-106-basicauth-otp-2fa`, worktree
> `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa`). **Line numbers in `backend.py` are
> pre-TASK-184**: TASK-184 inserts methods above several anchors, so re-run `grep -n`; the
> occurrence counts below are unaffected by TASK-184.

### Verified Imports
```python
# backend.py — already imported:
from typing import Optional, Any                                  # verified: backend.py:29
from collections.abc import Awaitable                             # verified: backend.py:30 (extend to AsyncIterator)
from aiohttp import web                                           # verified: backend.py:40
from navigator_session import get_session, SESSION_ID             # verified: backend.py:93-96
from ...exceptions import FailedAuth, UserNotFound, InvalidAuth   # verified: backend.py:102-106
from ...responses import JSONResponse                             # verified: backend.py:107
from .models import OauthUser, OauthRefreshToken, OauthGrant, OauthAccessTokenRecord  # verified: backend.py:109-114
# backend.py — new:
from contextlib import asynccontextmanager                        # stdlib
from collections.abc import AsyncIterator                         # stdlib
from ...mfa.exceptions import MfaStorageError                     # verified: navigator_auth/mfa/exceptions.py:8
from ...mfa.security import advisory_user_lock                    # created by TASK-171
from ...security_state.store import (                             # created by TASK-175
    SecurityStateError, current_generation, generation_matches, generation_of, stamp_generation,
)
from .models import is_oauth_user_token                           # created by THIS task (models.py)
# models.py — already imported:
from typing import Optional, Union                                # verified: models.py:21
from pydantic import BaseModel, ConfigDict, Field, field_validator  # verified: models.py:26 (pydantic v2, NOT datamodel)
# models.py — new:
from collections.abc import Mapping                               # stdlib
from typing import Any                                            # stdlib
# auth.py — already imported:
from typing import Any, Union                                     # verified: auth.py:13 (add Optional)
from aiohttp import hdrs, web                                     # verified: auth.py:19
from .backends.idp import IdentityProvider                        # verified: auth.py:39
# auth.py — new:
from .backends.oauth2.models import is_oauth_user_token           # created by THIS task
from .security_state.store import SecurityStateError, generation_matches, generation_of  # created by TASK-175
```

### Existing Signatures to Use
```python
# navigator_auth/backends/oauth2/models.py
class OauthAuthorizationCode(BaseModel):          # line 209; last field `used_at: Optional[datetime] = Field(default=None)` line 238
class OauthRefreshToken(BaseModel):               # line 245; last field `revoked_reason: Optional[str] = Field(default=None)` line 267
# "# OauthGrant — durable consent record (TASK-027)" banner — line 271
# Storage is Redis JSON: AuthorizationCodeStorage.get_code -> OauthAuthorizationCode(**json.loads(data)) (code_backend.py:82),
# RefreshTokenStorage.get_token -> OauthRefreshToken(**json.loads(data)) (code_backend.py:163). Pydantic default
# extra handling ignores unknown keys and fills `generation=0` for legacy payloads. code_backend.py needs NO change.

# navigator_auth/backends/oauth2/backend.py
class Oauth2Provider(BaseAuthBackend):            # line 258
    async def _token_session_claims(self, request: web.Request, user_id: int) -> dict   # line 688; user_from_id at 698
    async def validate_client(self, client_id, redirect_uri=None, request=None)          # line 712 (insert seams above it)
    async def _gate_permits(self, request, client, user_id) -> bool                      # line 922 (Redis; stays OUTSIDE the lock)
    async def _issue_code(self, request, client, user_obj, redirect_uri, scope, state,
                          code_challenge=None, code_challenge_method=None, resource=None)  # line 1478; code_obj 1494; save 1507
    async def _handle_authorization_code(self, payload, request)  # line 1743; mark_used 1811-1813; token_data 1822-1830 (1st
                                                                  # `**await self._token_session_claims(request, user_id),` at 1829);
                                                                  # rt 1873; save access record 1885-1895; return 1906
    async def _handle_refresh_token(self, payload, request)       # line 1973; user_id 2032; token_data 2040-2047 (2nd occurrence
                                                                  # at 2046); new_rt 2082; revoke rotated 2094; return 2099
    async def _handle_device_code(self, payload, request)         # line 2105 — delegates to _handle_authorization_code (2188)
    async def userinfo(self, request)                             # line 2194; jti check 2213-2217; `scope = payload.get("scope", "")` 2219
    async def introspect(self, request: web.Request)              # line 2359; access/refresh activity 2423-2443; `if not active:` 2445
    async def _approve_device_code(self, dc, user_obj, scopes, client, request)  # line 2757; carrier 2775-2786; save 2787
    async def authenticate(self, request: web.Request)            # line 2833; jti check 2855-2864; get_session 2867
# self._idp.user_from_id(uid) — IdentityProvider.user_from_id (backends/idp/__init__.py:124); TASK-172 adds `*, conn=None`.

# navigator_auth/auth.py
class AuthHandler:                                                # line 89
    def Unauthorized(self, reason, **kwargs) -> web.HTTPError     # line 883
    async def _token_is_revoked(self, payload: dict) -> bool      # line 1044
    @web.middleware                                               # line 1067 (auth_middleware wraps only HTTPUnauthorized)
    async def _auth_middleware(self, request, handler)            # line 1089
        # excluded-path best effort: `if payload and not await self._token_is_revoked(payload):` line 1105 (inside try/except: pass)
        # main branch: `if payload and await self._token_is_revoked(payload):` line 1132 / raise line 1133;
        #   session lookup 1139, recreation 1144-1188, existing session 1190-1216 — all AFTER 1132.

# Dependencies (fixed by the plan):
# TASK-171: @asynccontextmanager async def advisory_user_lock(db_pool, user_id, *, timeout=None) -> AsyncIterator[conn]
#           (ONE pooled conn, ONE transaction, pg_advisory_xact_lock; timeout -> MfaStorageError; publishes LOCK_CONNECTION)
# TASK-172: IdentityProvider.user_from_id(uid, *, conn=None)
# TASK-175: GENERATION_CLAIM = "gen"; class SecurityStateError(Exception)
#           generation_of(payload) -> int (missing/None -> 0); stamp_generation(payload, generation) -> dict (claim only when > 0)
#           async current_generation(conn, user_id) -> int; async generation_matches(db_pool, user_id, presented) -> bool
#           (raises SecurityStateError on lookup failure)
# TASK-184: _create_user_session(request, user, response=None, extra=None) — token sessions keep passing NO extra.
```

### Does NOT Exist
- ~~`navigator_auth/handlers/auth.py`~~ — does not exist (spec M4 path drift). The bearer middleware is
  `AuthHandler._auth_middleware` in `navigator_auth/auth.py:1089`.
- ~~`OauthAuthorizationCode.generation`~~, ~~`OauthRefreshToken.generation`~~, ~~`is_oauth_user_token`~~,
  ~~`Oauth2Provider._user_generation`~~, ~~`_generation_ok`~~, ~~`_auth_pool`~~, ~~`AuthHandler._oauth_generation_ok`~~ — created by THIS task.
- ~~`OauthAuthorizationCode.mfa/.amr`~~, ~~`Oauth2Provider._session_auth_context`~~ — TASK-186.
- ~~a Postgres tier for codes / refresh tokens~~ — all Redis (`code_backend.py:498-527`); no DDL here.
- ~~`self.app` on `Oauth2Provider`~~ — use `request.app` (the IdP has its own `.app`; do not reach into it).
- ~~an OIDC `id_token`~~ — not issued; nothing to stamp.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/backends/oauth2/backend.py", "action": "MODIFY"},
    {"path": "navigator_auth/backends/oauth2/models.py", "action": "MODIFY"},
    {"path": "navigator_auth/auth.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_review_fixes_oauth2_tokens.py", "action": "CREATE"},
    {"path": "tests/test_oauth2_access_gate.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_introspection.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_introspection_device_integration.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_mcp_conformance.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/oauth2/models.py#OauthAuthorizationCode",
    "sym:navigator_auth/backends/oauth2/models.py#OauthRefreshToken",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._token_session_claims",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._issue_code",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._handle_authorization_code",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._handle_refresh_token",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._handle_device_code",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.userinfo",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.introspect",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._approve_device_code",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.authenticate",
    "sym:navigator_auth/backends/idp/__init__.py#IdentityProvider.user_from_id",
    "sym:navigator_auth/auth.py#AuthHandler._token_is_revoked",
    "sym:navigator_auth/auth.py#AuthHandler._auth_middleware",
    "sym:navigator_auth/auth.py#AuthHandler.Unauthorized",
    "sym:navigator_auth/mfa/exceptions.py#MfaStorageError"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
- Lock + recheck: `security_transition` / `MfaSecurity.user_lock` (`mfa/events.py:47-89`, `mfa/security.py:54-76`) —
  the DB work happens on the yielded connection; Redis work inside the scope is fine; no second `acquire()`.
- Fail-closed Redis checks already in the provider: `_gate_permits` (backend.py:922-940).

### Key Constraints
- **OAuth user token** = payload with `client_id` AND `user_id` AND `jti` (`is_oauth_user_token`).
  BasicAuth JWTs (no `client_id`) and `client_credentials` tokens (no `user_id`) are never checked.
- **Generation encoding** (spec M9 "Generation encoding"): 0 ⇒ claim absent (`stamp_generation`), so at
  generation 0 access-token payload keys equal today's (AC24). Validation reads `generation_of(payload)`
  (missing ⇒ 0). Models default to 0, so legacy codes/refresh tokens are generation 0.
- **Never replace a carrier's generation with the current one**: issue/rotate only after equality holds,
  copying the carrier's (== current) value.
- **Serialize with reset**: code exchange and refresh re-read the generation INSIDE
  `_user_generation(...)` (same advisory lock namespace/key as `MfaSecurity.user_lock`, which TASK-179/180's
  transitions hold while incrementing) and mint inside that scope.
- **G3 — no nested acquire under the lock**: inside `_user_generation` the only DB access is on the yielded
  `conn` (`current_generation`, `_token_session_claims(..., conn=conn)` → `user_from_id(uid, conn=conn)`).
  Client lookup, PKCE and `_gate_permits` stay BEFORE the lock.
- `_token_session_claims` calls `user_from_id(user_id)` (no kwarg) when `conn is None`, so existing
  2-argument test stubs keep working (`tests/test_oauth2_3lo_session_binding.py:110-131`).
- **Fail closed**: `SecurityStateError` / `MfaStorageError` / missing `authdb` never authorize. Token endpoint →
  `self._error_response("temporarily_unavailable", ..., status=503)`; introspection → `{"active": false}`;
  userinfo → 503 `temporarily_unavailable`; `authenticate` → raise; middleware main branch →
  `web.HTTPServiceUnavailable`; excluded-path branch → stay unauthenticated (its `except Exception: pass`).
- **Keep source-inspection guards green**: `invalid_target` and `_resource_audience` must stay in
  `_handle_authorization_code`'s own source (`tests/test_oauth2_conformance.py:334-341`); `_merge_basic_auth` in
  `introspect` (`:217-226`); `_enforce_access_gate` in `authorize`, `consent`, `device_verification`
  (`tests/test_oauth2_access_gate.py:426-450`). Do not reference `_issue_code` from any new method.
- Secret-free logs (no tokens, codes or generations tied to tokens); Google docstrings + type hints; `self.logger`.

### References in Codebase
- `navigator_auth/backends/oauth2/backend.py:1743-1906, 1973-2099` — the two grants rewritten here.
- `tests/test_oauth2_mcp_conformance.py:262-297` — memory-storage provider harness (pattern for the new tests).

---

## Implementation Blueprint

### Steps (in order)
1. `models.py`: add the two `generation` fields and `is_oauth_user_token` — *why*: everything else reads them.
2. `backend.py` imports + the three seams — *why*: one place owns pool lookup, locking and fail-closed mapping;
   tests stub two attributes instead of a database.
3. `_token_session_claims(conn=)` — *why*: called inside the lock; must not acquire.
4. Stamp in `_issue_code` and `_approve_device_code` — *why*: carriers record the generation read under the lock.
5. Lock + recheck + stamp in the code exchange and the refresh grant — *why*: AC30 concurrency.
6. Enforce in `authenticate`, `userinfo`, `introspect` — *why*: AC30 "fail at every validation endpoint".
7. `auth.py` middleware — *why*: the middleware authenticates OAuth bearer requests without calling the provider.
8. Stub the seams in the four existing suites, write the new tests, run the Validation Commands.

### `navigator_auth/backends/oauth2/models.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '    used_at: Optional[datetime] = Field(default=None)' navigator_auth/backends/oauth2/models.py)
# AFTER — insert below `    used_at: Optional[datetime] = Field(default=None)` (verified: models.py:238)
    # FEAT-106 review fix (M4): per-user OAuth credential generation read under the user lock when
    # this code (or device carrier) was minted. 0 for legacy payloads; must equal the current
    # generation at exchange time.
    generation: int = Field(default=0)

# occurrences: 1 (verified: grep -c '    revoked_reason: Optional[str] = Field(default=None)' navigator_auth/backends/oauth2/models.py)
# AFTER — insert below `    revoked_reason: Optional[str] = Field(default=None)` (verified: models.py:267)
    # FEAT-106 review fix (M4): copied from the carrier / parent token, never re-read.
    generation: int = Field(default=0)

# occurrences: 1 (verified: grep -c '# OauthGrant — durable consent record (TASK-027)' navigator_auth/backends/oauth2/models.py)
# BEFORE — insert above the `# ----…` line preceding `# OauthGrant — durable consent record (TASK-027)` (verified: models.py:270-271)
def is_oauth_user_token(payload: Mapping[str, Any]) -> bool:
    """Return True for an access-token payload minted for a user by this provider.

    A user OAuth token carries ``client_id``, ``user_id`` and ``jti``; BasicAuth JWTs have no
    ``client_id`` and ``client_credentials`` tokens no ``user_id``, so neither is generation-checked.
    """
    return bool(payload) and all(payload.get(key) not in (None, "") for key in ("client_id", "user_id", "jti"))
```
**Why**: models stay pure data; the predicate lives here so `auth.py` and `backend.py` share it without a
new module. Add `from collections.abc import Mapping` and `Any` to the imports (models.py:21).

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — imports + seams + `_token_session_claims`
```python
# occurrences: 1 (verified: grep -c 'from collections.abc import Awaitable' navigator_auth/backends/oauth2/backend.py)
# REPLACE `from collections.abc import Awaitable` (verified: backend.py:30) with:
from collections.abc import AsyncIterator, Awaitable
from contextlib import asynccontextmanager

# occurrences: 1 (verified: grep -c '    OauthAccessTokenRecord,' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below `    OauthAccessTokenRecord,` inside `from .models import (` (verified: backend.py:113)
    is_oauth_user_token,
# and below that import block (before `from .client_backend import ...`, backend.py:115):
from ...mfa.exceptions import MfaStorageError
from ...mfa.security import advisory_user_lock
from ...security_state.store import (
    SecurityStateError,
    current_generation,
    generation_matches,
    generation_of,
    stamp_generation,
)

# occurrences: 1 (verified: grep -c 'async def _token_session_claims(self, request: web.Request, user_id: int) -> dict:' navigator_auth/backends/oauth2/backend.py)
# REPLACE the signature line (verified: backend.py:688) with:
    async def _token_session_claims(self, request: web.Request, user_id: int, *, conn: Any = None) -> dict:
# and, disambiguated (`user = await self._idp.user_from_id(user_id)` has 3 occurrences: 698, 2230, 2487) —
# REPLACE only the one inside _token_session_claims, i.e. the line directly above
# `            self.logger.warning(f"Oauth2: cannot bind a session to the token for user_id={user_id}: {exc}")`
# (occurrences: 1, verified: backend.py:700):
            if conn is None:
                user = await self._idp.user_from_id(user_id)
            else:
                user = await self._idp.user_from_id(user_id, conn=conn)  # inside the user lock: no pool acquire (G3)

# occurrences: 1 (verified: grep -c '    async def validate_client(self, client_id, redirect_uri=None, request=None):' navigator_auth/backends/oauth2/backend.py)
# BEFORE — insert above `    async def validate_client(self, client_id, redirect_uri=None, request=None):` (verified: backend.py:712)
    def _auth_pool(self, request: web.Request) -> Any:
        """Return ``app["authdb"]``; raise ``SecurityStateError`` when it is not configured (fail closed)."""
        app = getattr(request, "app", None)
        pool = app.get("authdb") if app is not None else None
        if pool is None:
            raise SecurityStateError("authdb is not configured")
        return pool

    @asynccontextmanager
    async def _user_generation(self, request: web.Request, user_id: int) -> AsyncIterator[tuple[Any, int]]:
        """Hold the per-user advisory lock and yield ``(conn, current generation)``.

        Raises:
            SecurityStateError: no ``authdb`` or the generation read failed.
            MfaStorageError: the lock could not be taken within ``AUTH_MFA_LOCK_TIMEOUT``.
        """
        async with advisory_user_lock(self._auth_pool(request), int(user_id)) as conn:
            yield conn, await current_generation(conn, int(user_id))

    async def _generation_ok(self, request: web.Request, user_id: int, presented: int) -> bool:
        """Compare ``presented`` with the authoritative generation (own pooled read, no lock).

        Raises:
            SecurityStateError: lookup failure — callers fail closed.
        """
        return await generation_matches(self._auth_pool(request), int(user_id), int(presented))
```
**Why this shape**: the seams are the only DB entry points of the provider, so mocked unit suites stub
`_user_generation` / `_generation_ok` and everything else stays storage-agnostic.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — stamp carriers (`_issue_code`, `_approve_device_code`)
```python
# occurrences: 1 (verified: grep -c 'code_obj = OauthAuthorizationCode(' navigator_auth/backends/oauth2/backend.py)
# REPLACE backend.py:1493-1507 (`auth_code = secrets.token_urlsafe(32)` … `await self.code_storage.save_code(code_obj)`;
#   `await self.code_storage.save_code(code_obj)` occurrences: 1) with:
        auth_code = secrets.token_urlsafe(32)
        try:
            async with self._user_generation(request, user_obj.user_id) as (_conn, generation):
                code_obj = OauthAuthorizationCode(
                    # FILL IN: the existing keyword arguments of backend.py:1495-1505 unchanged
                    generation=generation,
                )
                await self.code_storage.save_code(code_obj)
        except (SecurityStateError, MfaStorageError) as err:
            self.logger.error(f"Oauth2: cannot read the credential generation: {type(err).__name__}")
            raise web.HTTPServiceUnavailable(reason="Authorization temporarily unavailable.") from err
        # (unchanged) payload = {"code": auth_code, "state": state} … self.redirect(uri)

# occurrences: 1 (verified: grep -c 'carrier = OauthAuthorizationCode(' navigator_auth/backends/oauth2/backend.py)
# REPLACE backend.py:2775-2787 (`carrier = OauthAuthorizationCode(` … `await self.code_storage.save_code(carrier)`;
#   `await self.code_storage.save_code(carrier)` occurrences: 1) with:
        try:
            async with self._user_generation(request, user_obj.user_id) as (_conn, generation):
                carrier = OauthAuthorizationCode(
                    # FILL IN: the existing keyword arguments of backend.py:2776-2785 unchanged
                    generation=generation,
                )
                await self.code_storage.save_code(carrier)
        except (SecurityStateError, MfaStorageError) as err:
            self.logger.error(f"Oauth2: cannot read the credential generation: {type(err).__name__}")
            return self._error_response("temporarily_unavailable", "Device approval temporarily unavailable.", status=503)
        # (unchanged) "# Stamp device record." … must stay AFTER the carrier is saved
```
**Why**: spec M4 "Read it under the user lock at … carrier creation". The redirect / device-record stamping
stays outside the lock (Redis/HTTP only).

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — code exchange under the lock
```python
# occurrences: 1 (verified: grep -c '# B5: mark code as used + delete from storage.' navigator_auth/backends/oauth2/backend.py)
# REPLACE backend.py:1811-1895 (from `# B5: mark code as used + delete from storage.` through the
#   `await self.access_token_storage.save(rec)` that follows `# TASK-027: persist access token jti.`).
# The response building (1897-1906) stays after the block, unchanged.
        user_id = auth_code.user_id  # TASK-024 (moved up: the lock key)
        try:
            async with self._user_generation(request, user_id) as (conn, generation):
                if auth_code.generation != generation:
                    await self.code_storage.delete_code(code)
                    return self._error_response("invalid_grant", "Authorization code is no longer valid.")
                # B5: mark code as used + delete from storage.
                await self.code_storage.mark_used(code)
                await self.code_storage.delete_code(code)
                scope = auth_code.scope
                jti = str(uuid4())
                token_data = stamp_generation(
                    {
                        "user_id": user_id,
                        "client_id": client.client_id,
                        "scope": scope,
                        "jti": jti,
                        **await self._token_session_claims(request, user_id, conn=conn),
                    },
                    auth_code.generation,
                )
                # FILL IN: move backend.py:1832-1895 here UNCHANGED (RFC 8707 resource checks with their
                #          `invalid_target` returns, create_token, expires_in, refresh token, access record),
                #          adding `generation=auth_code.generation` to the `OauthRefreshToken(` call
                #          (`            rt = OauthRefreshToken(` occurrences: 1, backend.py:1873) — bounded by AC30
        except (SecurityStateError, MfaStorageError) as err:
            self.logger.error(f"Oauth2: token issuance unavailable: {type(err).__name__}")
            return self._error_response("temporarily_unavailable", "Token issuance temporarily unavailable.", status=503)
```
**Why**: the recheck and every mint share one lock scope, so a reset committing in between is impossible
(AC30). Keeping the resource checks in this method keeps `tests/test_oauth2_conformance.py:334-341` green.
Disambiguation: this replaces the FIRST `**await self._token_session_claims(request, user_id),` (backend.py:1829,
the one after `# TASK-027: mint jti.`); the refresh-grant occurrence is handled below.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — refresh grant under the lock
```python
# occurrences: 1 (verified: grep -c '# TASK-024: user_id always from the refresh token.' navigator_auth/backends/oauth2/backend.py)
# REPLACE backend.py:2032-2094 (from `# TASK-024: user_id always from the refresh token.` through
#   `await self.refresh_token_storage.revoke_token(refresh_token, "rotated")`); the `else:` branch and the
#   return (2096-2099) follow unchanged. This contains the SECOND
#   `**await self._token_session_claims(request, user_id),` occurrence (backend.py:2046, after `# Same session binding…`).
        user_id = rt.user_id  # TASK-024: user_id always from the refresh token.
        try:
            async with self._user_generation(request, user_id) as (conn, generation):
                if rt.generation != generation:
                    await self.refresh_token_storage.revoke_chain(refresh_token)
                    return self._error_response("invalid_grant", "Refresh token is no longer valid.")
                # FILL IN: move backend.py:2034-2094 here unchanged, with three edits — bounded by AC30, AC25-compat:
                #   1. token_data = stamp_generation({... , **await self._token_session_claims(request, user_id, conn=conn)}, rt.generation)
                #   2. `new_rt = OauthRefreshToken(` (occurrences: 1, backend.py:2082) gains `generation=rt.generation`
                #   3. the scope-widening `return self._error_response("invalid_scope", ...)` stays inside (no mint happened)
        except (SecurityStateError, MfaStorageError) as err:
            self.logger.error(f"Oauth2: token refresh unavailable: {type(err).__name__}")
            return self._error_response("temporarily_unavailable", "Token refresh temporarily unavailable.", status=503)
```
**Why**: "refresh cannot mint a replacement" after a reset (AC30) — the chain is revoked on mismatch.
`response` is built inside the scope and returned after it; `OAUTH_REFRESH_ROTATION=False` returns the same token.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — enforcement (`authenticate`, `userinfo`, `introspect`)
```python
# --- authenticate ---
# occurrences: 1 (verified: grep -c 'session = await get_session(request, payload, new=False)' navigator_auth/backends/oauth2/backend.py)
# BEFORE — insert above `        try:` that precedes `session = await get_session(request, payload, new=False)` (verified: backend.py:2866-2867)
        if is_oauth_user_token(payload):
            try:
                current = await self._generation_ok(request, int(payload["user_id"]), generation_of(payload))
            except (SecurityStateError, ValueError, TypeError) as err:
                self.logger.error(f"Oauth2: credential generation check failed: {type(err).__name__}")
                raise InvalidAuth("Oauth2: authentication temporarily unavailable.", status=503) from err
            if not current:
                raise InvalidAuth("Oauth2: access token is no longer valid.", status=401)

# --- userinfo ---
# occurrences: 1 (verified: grep -c 'scope = payload.get("scope", "")' navigator_auth/backends/oauth2/backend.py)
# BEFORE — insert above `        scope = payload.get("scope", "")` (verified: backend.py:2219)
        if is_oauth_user_token(payload):
            try:
                if not await self._generation_ok(request, int(payload["user_id"]), generation_of(payload)):
                    return self._error_response("invalid_token", "Token is no longer valid.", status=401)
            except (SecurityStateError, ValueError, TypeError):
                return self._error_response("temporarily_unavailable", "Userinfo temporarily unavailable.", status=503)

# --- introspect ---
# occurrences: 1 (verified: grep -c 'if not active:' navigator_auth/backends/oauth2/backend.py)
# BEFORE — insert above `        if not active:` (verified: backend.py:2445)
        if active:
            try:
                if is_access and token_payload and is_oauth_user_token(token_payload):
                    active = await self._generation_ok(
                        request, int(token_payload["user_id"]), generation_of(token_payload)
                    )
                elif not is_access and rt is not None:
                    active = await self._generation_ok(request, int(rt.user_id), rt.generation)
            except (SecurityStateError, ValueError, TypeError):
                active = False  # RFC 7662: unknown truth is inactive (fail closed)
```
**Why**: each validation point re-reads the authoritative value (no cache), as spec M4 requires.

### `navigator_auth/auth.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'from .backends.idp import IdentityProvider' navigator_auth/auth.py)
# AFTER — insert below `from .backends.idp import IdentityProvider` (verified: auth.py:39)
from .backends.oauth2.models import is_oauth_user_token
from .security_state.store import SecurityStateError, generation_matches, generation_of

# occurrences: 1 (verified: grep -c '    @web.middleware' navigator_auth/auth.py)
# BEFORE — insert above `    @web.middleware` (verified: auth.py:1067), i.e. right after _token_is_revoked
    async def _oauth_generation_ok(self, request: web.Request, payload: Optional[dict]) -> bool:
        """Return False when ``payload`` is a user OAuth token from an older credential generation.

        Non-OAuth tokens (BasicAuth, client_credentials) always pass.

        Raises:
            SecurityStateError: no ``authdb`` or the generation lookup failed (callers fail closed).
        """
        if not payload or not is_oauth_user_token(payload):
            return True
        pool = request.app.get("authdb") if request.app is not None else None
        if pool is None:
            raise SecurityStateError("authdb is not configured")
        return await generation_matches(pool, int(payload["user_id"]), generation_of(payload))

# occurrences: 1 (verified: grep -c 'if payload and not await self._token_is_revoked(payload):' navigator_auth/auth.py)
# REPLACE (verified: auth.py:1105) — excluded-path branch; errors fall into its existing `except Exception: pass`:
                    if (
                        payload
                        and not await self._token_is_revoked(payload)
                        and await self._oauth_generation_ok(request, payload)
                    ):

# occurrences: 1 (verified: grep -c 'raise self.Unauthorized(reason="Token has been revoked")' navigator_auth/auth.py)
# AFTER — insert below `            raise self.Unauthorized(reason="Token has been revoked")` (verified: auth.py:1133)
        if payload:
            try:
                generation_ok = await self._oauth_generation_ok(request, payload)
            except (SecurityStateError, ValueError, TypeError) as err:
                self.logger.error(f"Auth Middleware: credential generation check failed: {type(err).__name__}")
                raise web.HTTPServiceUnavailable(reason="Authentication temporarily unavailable") from err
            if not generation_ok:
                raise self.Unauthorized(reason="Token has been revoked")
```
**Why**: the check sits before session lookup/recreation (auth.py:1139-1188), so a recreated session can never
revive a stale token (spec M4 "including any middleware session recreation"). `auth.py:13` reads
`from typing import Any, Union` — change it to `from typing import Any, Optional, Union` (verified: `Optional` is absent today).

### Existing suites (MODIFY) — generation seam stub
```python
# Add these lines to each provider factory listed below (identical text in all four files):
#   from contextlib import asynccontextmanager   (module imports)
#
#   @asynccontextmanager
#   async def _no_generation(request, user_id):
#       yield None, 0
#
#   <prov>._user_generation = _no_generation
#   <prov>._generation_ok = AsyncMock(return_value=True)
#
# tests/test_oauth2_access_gate.py — AFTER `    prov.client_access_storage = storage` (occurrences: 1, :50)
#   (the `consent_provider` fixture at :339 builds on `provider`, so it inherits the stub)
# tests/test_oauth2_introspection.py — AFTER `    provider.grant_storage = MagicMock()` (occurrences: 1, :76) in _make_provider
# tests/test_oauth2_introspection_device_integration.py — AFTER `    provider.grant_storage = grant_store` (occurrences: 1, :200)
# tests/test_oauth2_mcp_conformance.py — AFTER `    prov._token_session_claims = AsyncMock(return_value={})` (occurrences: 1, :295)
```
**Why**: these mock providers have no `authdb`; without the stub the fail-closed paths (correctly) refuse.
The stub keeps their original intent (generation 0 everywhere). Add a one-line comment above each stub naming
FEAT-106 review fixes TASK-185. `AsyncMock` is already imported in all four files.

### `tests/test_mfa_review_fixes_oauth2_tokens.py` (CREATE)
See **Test Specification** below.

### FILL IN checklist
- [ ] `_issue_code` / `_approve_device_code` — carry the existing kwargs into the stamped carrier — bounded by AC30
- [ ] code exchange — move 1832-1895 inside the lock, `generation=` on `rt` — bounded by AC30, conformance source guards
- [ ] refresh grant — move 2034-2094 inside the lock with the 3 edits — bounded by AC30
- [ ] Test bodies — bounded by AC24, AC28 (enforcement), AC30

---

## Acceptance Criteria

- [ ] **AC30** — after `increment_generation` (simulating reset/recovery), pre-change access tokens, authorization codes,
      device carriers and refresh tokens — including legacy payloads without a generation — fail at code exchange,
      refresh (no replacement minted), `Oauth2Provider.authenticate`, `AuthHandler._auth_middleware`, introspection
      (inactive) and userinfo; new carriers minted afterwards work.
- [ ] **AC30 (concurrency)** — a code exchange or refresh racing an increment held under `advisory_user_lock`
      never yields a token that still validates after the increment commits.
- [ ] **AC30 (fail closed)** — a failing generation lookup gives 503 at the token endpoint and userinfo,
      `{"active": false}` at introspection, a refusal in `authenticate` and 503 in the middleware.
- [ ] **AC24 (generation)** — at generation 0 the access-token payload keys equal today's (no `gen` claim);
      at generation ≥ 1 the `gen` claim is present.
- [ ] **AC28 (enforcement half)** — tokens minted before the generation increment are rejected afterwards.
- [ ] **AC28 (end to end)** — `test_password_reset_rejects_pre_reset_oauth_tokens`: mint an OAuth access token
      and refresh token, call the REAL `password_reset` handler from TASK-179
      (`navigator_auth/handlers/users/session.py`) — do not call `increment_generation` directly in this test —
      then assert the access token is refused by `authenticate` and the middleware, and the refresh grant mints
      nothing. This is why the task depends on TASK-179: it is the only test that proves the increment
      (TASK-179) and the enforcement (this task) meet.
- [ ] Inside `_user_generation` no second `acquire()` happens (`single_connection_authdb` from TASK-171).
- [ ] Existing OAuth2 suites listed in Validation Commands pass (with the seam stubs where listed).

---

## Validation Commands

- `pytest tests/test_mfa_review_fixes_oauth2_tokens.py -q`
- `pytest tests/test_oauth2_refresh.py -q`
- `pytest tests/test_oauth2_introspection.py -q`
- `pytest tests/test_oauth2_userinfo_logout.py -q`
- `pytest tests/test_oauth2_access_gate.py -q`
- `pytest tests/test_oauth2_introspection_device_integration.py -q`
- `pytest tests/test_oauth2_mcp_conformance.py -q`
- `pytest tests/test_oauth2_conformance.py -q`
- `pytest tests/test_oauth2_3lo_session_binding.py -q`

---

## Test Specification

```python
# tests/test_mfa_review_fixes_oauth2_tokens.py
"""FEAT-106 review fixes — OAuth credential generation (spec M4 durable revocation contract).

TASK-186 (amr) and TASK-187 (ABAC) extend this module; keep generation tests in their own section.
"""
import asyncio

import pytest
import pytest_asyncio

from navigator_auth.backends.oauth2.models import OauthAuthorizationCode, OauthRefreshToken, is_oauth_user_token
from navigator_auth.mfa.security import advisory_user_lock            # TASK-171
from navigator_auth.security_state.migrations import ensure_security_state_tables   # TASK-175
from navigator_auth.security_state.store import GENERATION_CLAIM, increment_generation  # TASK-175
from tests.fixtures.mfa import mfa_db, mfa_user_factory, single_connection_authdb  # noqa: F401


@pytest_asyncio.fixture
async def gen_provider(mfa_db):
    """Memory-storage Oauth2Provider (pattern: tests/test_oauth2_mcp_conformance.py:262-297) whose requests carry
    ``app = {"authdb": mfa_db}`` so the real generation seams run against live Postgres."""
    await ensure_security_state_tables(mfa_db)
    # FILL IN


def test_is_oauth_user_token_shapes():
    """client_id+user_id+jti -> True; BasicAuth (no client_id) / client_credentials (no user_id) -> False."""


def test_models_default_generation_zero_for_legacy_payloads():
    """OauthAuthorizationCode/OauthRefreshToken built without `generation` deserialize to 0."""


@pytest.mark.asyncio
async def test_generation_claim_absent_at_zero_present_after_increment(gen_provider, mfa_user_factory):
    """AC24: gen 0 -> no GENERATION_CLAIM in the access-token payload; gen 1 -> claim == 1."""


@pytest.mark.asyncio
async def test_oauth_reset_generation(gen_provider, mfa_user_factory):
    """AC30/AC28: code, device carrier, refresh token and access token (incl. legacy gen-0) all fail after
    increment_generation at exchange, refresh (chain revoked, nothing minted), authenticate, middleware,
    introspection (inactive) and userinfo; a carrier minted afterwards works."""


@pytest.mark.asyncio
async def test_exchange_vs_reset_race_never_yields_usable_old_token(gen_provider, mfa_user_factory):
    """AC30: run exchange and an increment held under advisory_user_lock concurrently (both orders);
    afterwards no issued token passes authenticate."""


@pytest.mark.asyncio
async def test_generation_lookup_failure_fails_closed(gen_provider, monkeypatch):
    """AC30: generation_matches / current_generation raising -> 503 token endpoint & userinfo, inactive
    introspection, refused authenticate, 503 middleware."""


@pytest.mark.asyncio
async def test_token_session_claims_uses_lock_connection(gen_provider, single_connection_authdb):
    """G3/AC10: a code exchange with authdb capped at one connection completes; no acquire inside the lock."""
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the stacked feature worktree** `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa-review-fixes` (branch
   `feat-FEAT-106-basicauth-otp-2fa-review-fixes`, stacked on `feat-FEAT-106-basicauth-otp-2fa`; ships in PR #633) — never on `dev`.
2. **Read the spec** at the path listed above (§3 M4 "Durable recovery and token revocation contract", M9
   "Generation encoding", §5 AC24, AC28, AC30).
3. **Check dependencies** — TASK-171, TASK-172, TASK-175 and TASK-184 must be `"done"` in
   `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json`.
4. **Verify the Codebase Contract** — re-run every `grep -c` above (line numbers moved after TASK-184); confirm
   `advisory_user_lock` (`navigator_auth/mfa/security.py`), the `security_state.store` helpers and
   `user_from_id(..., conn=)` exist with the plan's signatures. If anything changed, update the contract FIRST.
5. **Update status** in the per-spec index → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** from the blueprint, completing every `# FILL IN:`; never change a fixed signature or path.
7. **Verify** all acceptance criteria — run the Validation Commands.
8. **Commit the code** — stage only the files listed above.
9. **Close the task** with `parrot sdd task close TASK-185 basicauth-otp-2fa-review-fixes verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any

---

## Completion Note

Implemented by seats gpt-5.6-luna x2 (task-tier: 8 failures) then gpt-5.6-terra (attempt 3 accepted). Merge-tier validation: 231 passed, 4 failed — all 4 are baseline reds (test_oauth2_3lo_session_binding x3, test_oauth2_mcp_conformance google e2e; short AUTH_SECRET_KEY env issue), gate reported pass. File fidelity checked. Closed via `parrot sdd task close`.
