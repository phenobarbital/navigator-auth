# TASK-184: OAuth2 password form enforces the second factor (M6)

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-173, TASK-181
**Assigned-to**: unassigned

---

## Context

Review finding **#1** (high): `Oauth2Provider.auth_login` checks only the password and opens a
session, so an enforced tenant's 2FA is bypassed whenever the OAuth2 provider is enabled. Spec
§3 **Module 6** makes the OAuth2 password form go through the shared `SecondFactorGate`
(TASK-181) exactly like BasicAuth, using BasicAuth's MFA slot (D4) through the lease API of
TASK-173. It also introduces the **browser authentication event** that TASK-186 (M9) later
validates: an opaque, expiring handle recorded at login so assurance never lives in the
identity-shared OAuth2 session (spec §3 M9 "Browser event isolation", §7 risk "One session per
user identity").

Implements: G1, D1, D4; AC1–AC6; the `/oauth2/login` and `/oauth2/login/mfa` rows of AC10.

---

## Scope

- Add `OAUTH2_EVENT_COOKIE` / `OAUTH2_EVENT_KEY_PREFIX` module constants.
- Extend `_create_user_session(request, user, response=None, extra=None)`: `extra is None` keeps
  today's behaviour byte for byte (AC5); a dict records a browser authentication event via the
  new `_issue_auth_event(...)` after the session exists.
- Add `_issue_auth_event(request, response, session, user, extra)` and
  `_load_auth_event(request) -> Optional[dict]` (load only — NO validation; TASK-186 validates).
- Extract `_authorize_redirect(request, data) -> web.HTTPFound` verbatim from `auth_login`
  (backend.py:1648-1671); `auth_login` keeps using it on both branches.
- `auth_login` POST: 2FA off → unchanged. 2FA on → after `authenticate_credentials` +
  `user_is_active`: `mfa_services_lease(request.app)`; `None` or `not services.available` → 503,
  no session (AC6); otherwise `SecondFactorGate.decide(...)` with an issuer that creates the
  session on the redirect (`extra` always a dict: `{**extra, "auth_method": "oauth2"}`).
  Session → redirect (+ `nav_mfa_device` cookie when `GateResult.device`); challenge → render
  `oauth/mfa.html` (200, `Cache-Control: no-store`, no session cookie).
- Add `auth_login_mfa` (`POST {login_uri}/mfa`, route `nav_oauth2_login_mfa`, appended to
  `AUTH_EXCLUDE_LIST_KEY`): `SecondFactorGate.verify(...)`; success → session on the redirect
  (+ trusted cookie); `VerifyRefused` mapping per spec §3 M6.
- Create `templates/oauth/mfa.html` (layout of `oauth/login.html`, every echoed value escaped).
- Add an error slot to `templates/oauth/login.html` (needed for AC3 "return to the login page
  with an error").
- Write `tests/test_mfa_review_fixes_oauth2.py` (AC1–AC6 + AC10 OAuth rows).

**NOT in scope**: validating the auth event at authorize/consent/device and propagating
`mfa`/`amr` into codes and tokens (TASK-186); OAuth credential generation (TASK-185); ABAC
bearer context (TASK-187); the gate itself (TASK-181); BasicAuth / `/auth/mfa/verify` adapters
(TASK-182).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | constants, `_create_user_session(extra)`, `_issue_auth_event`, `_load_auth_event`, `_authorize_redirect`, 2FA branch of `auth_login`, `auth_login_mfa`, route + exclude list |
| `templates/oauth/mfa.html` | CREATE | second-factor form (escaped), hidden authorize parameters |
| `templates/oauth/login.html` | MODIFY | escaped `error` slot (AC3) |
| `tests/test_mfa_review_fixes_oauth2.py` | CREATE | AC1–AC6, AC10 (`/oauth2/login`, `/oauth2/login/mfa`) |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `0b80d88` (branch `feat-FEAT-106-basicauth-otp-2fa`, worktree
> `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa`). Code is identical to the spec's `3f14b3c`.

### Verified Imports
```python
# navigator_auth/backends/oauth2/backend.py — already imported there:
from typing import Optional, Any                                   # verified: backend.py:29
import secrets                                                      # verified: backend.py:36
from aiohttp import web                                             # verified: backend.py:40
from navigator_session.conf import SESSION_OBJECT, SESSION_REQUEST_KEY, SESSION_STORAGE  # verified: backend.py:97-101
from ...conf import AUTH_EXCLUDE_LIST_KEY, PREFERRED_AUTH_SCHEME   # verified: backend.py:53-54 (inside the block at :47)
from ...exceptions import FailedAuth, UserNotFound, InvalidAuth     # verified: backend.py:102-106
from ..abstract import BaseAuthBackend, user_is_active             # verified: backend.py:108
# new in backend.py (all verified to exist):
import hashlib                                                      # stdlib
from navigator_session.conf import SESSION_TIMEOUT                  # verified: site-packages navigator_session/conf.py:24
from ... import conf as auth_conf                                   # same style as backends/basic.py:15 (`from .. import conf as auth_conf`)
from ...exceptions import MFARefused                                # verified: navigator_auth/exceptions.py:108
from ...mfa.types import TRUSTED_COOKIE, trusted_cookie_kwargs      # verified: navigator_auth/mfa/types.py:14,152
# created by dependencies (fixed signatures, see plan):
from ...mfa.login import SecondFactorGate, VerifyRefused            # created by TASK-181
from ...mfa.services import mfa_services_lease                      # created by TASK-173
# tests:
from tests.fixtures.mfa import mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory, frozen_totp_clock, otp_callback_spy  # verified: tests/fixtures/mfa.py:23,37,60,77,151,177
from tests.fixtures.mfa import single_connection_authdb             # created by TASK-171
from navigator_auth.backends.oauth2.client_backend import MemoryClientStorage  # verified: client_backend.py:76
from navigator_auth.backends.oauth2.models import OAuthClient       # verified: models.py (used by tests/test_oauth2_refresh.py:14)
```

### Existing Signatures to Use
```python
# navigator_auth/backends/oauth2/backend.py
BASIC_SECRET_ALT_KEY: str = "_basic_client_secret_decoded"          # line 155 (insert constants after it)
class Oauth2Provider(BaseAuthBackend):                              # line 258
    self.login_uri: str = "/oauth2/login"                           # line 281
    self._flow_store = None                                         # line 303
    def configure(self, app):                                       # line 321
        router.add_route("*", self.login_uri, self.auth_login, name="nav_oauth2_login")   # line 328
        app[AUTH_EXCLUDE_LIST_KEY].append(self.login_uri)          # line 329
    async def get_payload(self, request)                            # line 502 (form/json for POST, query for GET)
    def _session_storage(self, request: web.Request)                # line 622
    async def _create_user_session(self, request, user, response: web.StreamResponse = None)  # line 632; returns SessionData|None; session.session_id
    async def _token_session_claims(self, request, user_id: int) -> dict   # line 688 (calls _create_user_session WITHOUT extra — must stay so)
    @property
    def flow_store(self)                                            # line 1103 -> IdentityFlowStore over REDIS_AUTH_URL
    async def get_login_form(self, request)                         # line 1590 -> (username, password, data)
    async def auth_login(self, request: web.Request)                # line 1616; authorize payload 1648-1670; HTTPFound 1671; session 1677
    async def token_request(self, request)                          # line 1694 (banner comment 1690-1692)
# BaseAuthBackend class attributes: password_attribute="password", userid_attribute="user_id"  (backends/abstract.py:67-70)
# self._parser.view(filename, params=None, content_type="text/html", charset="utf-8", status=200) -> web.Response  (navigator_auth/templates.py:138)
#   Jinja Environment has NO autoescape (templates.py:8-11,62) — templates must escape explicitly.

# navigator_auth/identity/flow_store.py
class IdentityFlowStore:                                            # line 18
    async def set(self, key: str, payload: dict, ttl: int) -> None  # line 24 (JSON, redis-py setex(name, ttl, value))
    async def get(self, key: str) -> Optional[dict]                 # line 28
    async def delete(self, key: str) -> None                        # line 39

# navigator_auth/mfa/types.py
TRUSTED_COOKIE = "nav_mfa_device"                                   # line 14
def trusted_cookie_kwargs(max_age: int) -> dict                     # line 152 (raises ValueError when max_age <= 0)

# navigator_auth/exceptions.py
class FailedAuth(AuthException)                                      # line 53 (.status)
class MFARefused(MfaSignal): code: str; payload() -> {"error", "message"}  # line 108

# navigator_auth/conf.py
AUTH_BASIC_2FA_ENABLED = config.getboolean("AUTH_BASIC_2FA_ENABLED", fallback=False)  # line 659 — read as auth_conf.<NAME> at call time
AUTH_OTP_CHALLENGE_TTL                                               # line 666

# Dependencies (fixed by the plan; do NOT redefine):
# TASK-173: @asynccontextmanager async def mfa_services_lease(app) -> AsyncIterator[Optional[MfaServices]]
# TASK-181: SecondFactorGate(services, *, userid_attribute="user_id", password_attribute="password")
#   async def decide(request, user, issue) -> GateResult[T]   (raises FailedAuth 403/401 "credentials_changed", MFARefused)
#   async def verify(request, token, provider, code, issue, *, remember_device=False, device_label="") -> GateResult[T]
#   GateResult(session, challenge: LoginChallenge|None, device: {"token","max_age"}|None)
#   LoginChallenge(token, providers: tuple[str,...], preferred, expires_in)
#   VerifyRefused(code, status, extra)  codes: invalid_request|invalid_challenge|stale_challenge|invalid_code|
#                                       rate_limited|account_disabled|mfa_unavailable|<MfaSignal code>
#   The gate passes extra {} (no factor owed) or {"mfa": True, "amr": [...]}; it never sets auth_method.
```

### Does NOT Exist
- ~~an MFA second factor anywhere in `navigator_auth/backends/oauth2/`~~ — none today (the #1 bypass).
- ~~`Oauth2Provider._authorize_redirect`~~, ~~`Oauth2Provider.auth_login_mfa`~~, ~~`Oauth2Provider._issue_auth_event`~~,
  ~~`Oauth2Provider._load_auth_event`~~, ~~`OAUTH2_EVENT_COOKIE`~~, ~~`templates/oauth/mfa.html`~~, ~~route `nav_oauth2_login_mfa`~~ — created by THIS task.
- ~~`Oauth2Provider._session_auth_context`~~ — created by TASK-186 (do not add it here).
- ~~`OauthAuthorizationCode.mfa/.amr/.generation`~~ — TASK-185/186.
- ~~autoescaping in `TemplateParser`~~ — off; do not change `navigator_auth/templates.py` (other templates depend on it).
- ~~an `error` variable rendered by `oauth/login.html`~~ — absent today; this task adds it.
- ~~`navigator_auth/handlers/auth.py`~~ — does not exist (spec M4 path drift; irrelevant here).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/backends/oauth2/backend.py", "action": "MODIFY"},
    {"path": "templates/oauth/mfa.html", "action": "CREATE"},
    {"path": "templates/oauth/login.html", "action": "MODIFY"},
    {"path": "tests/test_mfa_review_fixes_oauth2.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.configure",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.get_payload",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._session_storage",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._create_user_session",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._token_session_claims",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.flow_store",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.get_login_form",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.auth_login",
    "sym:navigator_auth/identity/flow_store.py#IdentityFlowStore.set",
    "sym:navigator_auth/identity/flow_store.py#IdentityFlowStore.get",
    "sym:navigator_auth/mfa/types.py#trusted_cookie_kwargs",
    "sym:navigator_auth/templates.py#TemplateParser.view",
    "sym:navigator_auth/backends/abstract.py#user_is_active",
    "sym:navigator_auth/exceptions.py#MFARefused",
    "sym:navigator_auth/exceptions.py#FailedAuth"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
- Browser-cookie pattern: `_start_upstream_login` (backend.py:1148-1158) — `response.set_cookie(name, value, max_age=..., httponly=True, samesite="Lax", secure=(PREFERRED_AUTH_SCHEME == "https"), path=...)`.
- Redis JSON with TTL: `self.flow_store.set(key, payload, ttl=...)` / `.get(key)` (backend.py:1135, identity/flow_store.py:24-31).
- Live HTTP harness: `tests/test_mfa_e2e.py:369-457` (`_patch_settings`, `_start`, `_stop`, `live`), adding
  `"navigator_auth.backends.Oauth2Provider"` to the `AuthHandler(backends=...)` tuple.

### Key Constraints
- **AC5 is byte-for-byte**: with `auth_conf.AUTH_BASIC_2FA_ENABLED` false the POST branch must call
  `_create_user_session(request, user, response=response)` exactly as today (no `extra` kwarg) and
  produce the same status, `Location`, session keys and cookies. `_token_session_claims` keeps
  calling `_create_user_session(request, user)` without `extra` (token-endpoint sessions never get
  an auth event).
- **OAuth adapter `extra` rule** (refines the plan's adapter rule for this backend): with 2FA on the
  issuer ALWAYS passes a dict — `{**extra, "auth_method": "oauth2"}` — even for the no-factor-owed
  path (`extra == {}` → `{"auth_method": "oauth2"}`), because TASK-186 requires a valid auth event
  for every 2FA-on browser authorization. The event then records `mfa: False, amr: None`, so no
  token claims appear (AC24).
- Assurance (`mfa`, `amr`) is stored ONLY in the auth-event record, never in the identity-keyed
  session data (spec §7 "One session per user identity"; AC29 relies on it).
- No session cookie on the challenge page (AC1): `_create_user_session` must not run unless the gate
  returns `GateResult.session`.
- The gate runs the issuer **inside the user lock** (D1). The issuer only touches Redis
  (`_create_user_session`, `_issue_auth_event`) — never acquire a DB connection in it (G3/AC10).
- Hold `mfa_services_lease(request.app)` for the whole gate call (TASK-173 contract).
- Every echoed value in `oauth/mfa.html` is attacker-controlled (authorize parameters): wrap the whole
  template body in `{% autoescape true %}…{% endautoescape %}` (Jinja built-in) — the parser has no autoescape.
- Secret-free logs: never log the challenge token, the event handle, codes or cookies.
- `_authorize_redirect` key list must stay identical to backend.py:1650-1665
  (`client_id`, `redirect_uri`, `response_type`, `state`, `scope`, `code_challenge`,
  `code_challenge_method`, `nonce`, `prompt`) — AC2 asserts them exactly as submitted.
- Google-style docstrings + type hints on every new method; `self.logger`.

### References in Codebase
- `navigator_auth/backends/basic.py:357-402` — the BasicAuth second-factor branch this mirrors.
- `navigator_auth/handlers/mfa.py:88-107` — `/auth/mfa/verify` (VerifyRefused codes come from it).
- `navigator_auth/auth.py:522-547` — `finalize_login` sets `TRUSTED_COOKIE` with `trusted_cookie_kwargs`.

---

## Implementation Blueprint

### Steps (in order)
1. Add the imports and the two module constants — *why*: every later block uses them; constants are
   imported by TASK-186.
2. Register `POST {login_uri}/mfa` in `configure` and exclude it from auth — *why*: the MFA form is
   posted by an unauthenticated browser, like `/oauth2/login` (spec M6).
3. Add `extra` to `_create_user_session` and the two event helpers — *why*: the event is the only
   place assurance lives; `None` keeps AC5.
4. Extract `_authorize_redirect` and rewrite the POST tail of `auth_login` with the 2FA branch — *why*:
   both the password POST and the MFA POST must build the same redirect.
5. Add `auth_login_mfa` — *why*: completes the challenge (AC2–AC4).
6. Create `oauth/mfa.html` and the `login.html` error slot — *why*: AC1 (form), AC3 (error page).
7. Write the tests; run the Validation Commands — *why*: AC1–AC6, AC10.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — imports and constants
```python
# occurrences: 1 (verified: grep -c 'from ..abstract import BaseAuthBackend, user_is_active' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below `from ..abstract import BaseAuthBackend, user_is_active` (verified: backend.py:108)
from ... import conf as auth_conf
from ...exceptions import MFARefused
from ...mfa.login import SecondFactorGate, VerifyRefused
from ...mfa.services import mfa_services_lease
from ...mfa.types import TRUSTED_COOKIE, trusted_cookie_kwargs

# occurrences: 1 (verified: grep -c 'import secrets' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below `import secrets` (verified: backend.py:36)
import hashlib

# occurrences: 1 (verified: grep -c '    SESSION_STORAGE,' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below `    SESSION_STORAGE,` inside `from navigator_session.conf import (` (verified: backend.py:100)
    SESSION_TIMEOUT,

# occurrences: 1 (verified: grep -c 'BASIC_SECRET_ALT_KEY: str = "_basic_client_secret_decoded"' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below `BASIC_SECRET_ALT_KEY: str = "_basic_client_secret_decoded"` (verified: backend.py:155)

#: FEAT-106 review fix #1 (M6): opaque handle of one browser authentication event.
#: The record (Redis, keyed by sha256 of the handle) carries the login's assurance so it
#: never lives in the identity-shared OAuth2 session. Validated by TASK-186.
OAUTH2_EVENT_COOKIE: str = "nav_oauth2_event"
OAUTH2_EVENT_KEY_PREFIX: str = "oauth2:event:"
```
**Why this shape**: `auth_conf` is read at call time (same as `backends/basic.py:115,345`) so tests can
monkeypatch `navigator_auth.conf.AUTH_BASIC_2FA_ENABLED`. Constants are module-level so TASK-186 imports them.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — route registration
```python
# occurrences: 1 (verified: grep -c 'app[AUTH_EXCLUDE_LIST_KEY].append(self.login_uri)' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below `app[AUTH_EXCLUDE_LIST_KEY].append(self.login_uri)` (verified: backend.py:329)
        # FEAT-106 review fix #1 (M6): second-factor step of the OAuth2 password form.
        router.add_route("POST", f"{self.login_uri}/mfa", self.auth_login_mfa, name="nav_oauth2_login_mfa")
        app[AUTH_EXCLUDE_LIST_KEY].append(f"{self.login_uri}/mfa")
```
**Why**: spec M6 fixes the route name and path; the browser posting it holds no session yet.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — `_create_user_session(extra)`
```python
# occurrences: 1 (verified: grep -c 'response: web.StreamResponse = None,' navigator_auth/backends/oauth2/backend.py)
# REPLACE — the parameter line `        response: web.StreamResponse = None,` of `async def _create_user_session(` (verified: backend.py:636)
        response: web.StreamResponse = None,
        extra: Optional[dict] = None,

# Docstring: add under "Args:" —
#     extra: ``None`` (2FA off, token-endpoint sessions) keeps the pre-FEAT-106 behaviour.
#         A dict (2FA on, browser login) additionally records a browser authentication
#         event carrying the login's assurance; it never enters the shared session data.

# occurrences of `        return session`: 2 (lines 533, 686) — FILL IN: disambiguate with context:
# REPLACE the tail of _create_user_session (verified: backend.py:683-686):
#         if not session:
#             self.logger.error("Oauth2: unable to create the User session.")
#             return None
#         return session
        if not session:
            self.logger.error("Oauth2: unable to create the User session.")
            return None
        if extra is not None:
            await self._issue_auth_event(request, response, session, user, extra)
        return session
```
**Why**: the session data dict (backend.py:674-677) is untouched, so 2FA-off sessions are identical (AC5).

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — event helpers
```python
# occurrences: 1 (verified: grep -c 'async def _token_session_claims(self, request: web.Request, user_id: int) -> dict:' navigator_auth/backends/oauth2/backend.py)
# BEFORE — insert above `    async def _token_session_claims(self, request: web.Request, user_id: int) -> dict:` (verified: backend.py:688)
    async def _issue_auth_event(
        self,
        request: web.Request,
        response: Optional[web.StreamResponse],
        session: Any,
        user: Any,
        extra: dict,
    ) -> None:
        """Record one browser authentication event and bind it to the browser.

        Args:
            request: The login request.
            response: The redirect carrying the session cookie; receives the event cookie.
            session: The ``SessionData`` just created for ``user``.
            user: The authenticated resource owner.
            extra: ``{"auth_method": ..., "mfa"?: True, "amr"?: [...]}`` from the gate adapter.

        Raises:
            web.HTTPServiceUnavailable: the event could not be stored (fail closed: an
                unrecorded event would later be indistinguishable from a forged one).
        """
        handle = secrets.token_urlsafe(32)
        record = {
            "user_id": int(user[self.userid_attribute]),  # FILL IN: tolerate attribute-style users like _create_user_session (backend.py:657-660)
            "session_id": session.session_id,
            "mfa": bool(extra.get("mfa", False)),
            "amr": list(extra["amr"]) if extra.get("amr") else None,
            "auth_method": extra.get("auth_method", "oauth2"),
            "issued_at": int(datetime.now(timezone.utc).timestamp()),
        }
        ttl = SESSION_TIMEOUT  # FILL IN: prefer the session's own max_age when set — bounded by "TTL = session TTL" (plan TASK-184)
        key = OAUTH2_EVENT_KEY_PREFIX + hashlib.sha256(handle.encode("utf-8")).hexdigest()
        try:
            await self.flow_store.set(key, record, ttl=ttl)
        except Exception as err:  # pylint: disable=W0703
            self.logger.error(f"Oauth2: cannot record the login event: {type(err).__name__}")
            raise web.HTTPServiceUnavailable(reason="Auth: login temporarily unavailable.") from err
        if response is not None:
            response.set_cookie(
                OAUTH2_EVENT_COOKIE,
                handle,
                max_age=ttl,
                httponly=True,
                samesite="Lax",
                secure=(PREFERRED_AUTH_SCHEME == "https"),
                path="/oauth2",
            )

    async def _load_auth_event(self, request: web.Request) -> Optional[dict]:
        """Return the raw event record named by the browser's event cookie, if any.

        Load only: TASK-186's ``_session_auth_context`` validates it against the current
        session. ``None`` when the cookie is missing, unknown, expired or unreadable.
        """
        handle = request.cookies.get(OAUTH2_EVENT_COOKIE)
        if not handle:
            return None
        key = OAUTH2_EVENT_KEY_PREFIX + hashlib.sha256(handle.encode("utf-8")).hexdigest()
        try:
            record = await self.flow_store.get(key)
        except Exception as err:  # pylint: disable=W0703
            self.logger.warning(f"Oauth2: cannot read the login event: {type(err).__name__}")
            return None
        return record if isinstance(record, dict) else None
```
**Why this shape**: the handle is unguessable and only its digest is a Redis key (no raw secret at rest);
`flow_store` already targets `REDIS_AUTH_URL` with JSON+TTL (redis-py `setex` order handled inside).
`datetime`/`timezone` are already imported (backend.py:28).

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — `_authorize_redirect` + `auth_login` 2FA branch
```python
# occurrences: 1 (verified: grep -c 'location = request.app.router["nav_oauth2_authorize"].url_for()' navigator_auth/backends/oauth2/backend.py)
# REPLACE — backend.py:1648-1686 (from `location = request.app.router["nav_oauth2_authorize"].url_for()`
#           through the first `            return response` after `# Establish the browser session...`) with:
            response = self._authorize_redirect(request, data)
            if not auth_conf.AUTH_BASIC_2FA_ENABLED:
                # FILL IN: paste backend.py:1673-1686 here UNCHANGED (session on `response`, then `return response`) — bounded by AC5
                ...
            return await self._oauth2_second_factor(request, user, data, response)

# NEW methods — insert directly above `    async def auth_login(self, request: web.Request):` (occurrences: 1, verified: backend.py:1616)
    def _authorize_redirect(self, request: web.Request, data: dict) -> web.HTTPFound:
        """Build the redirect back to ``/oauth2/authorize`` carrying the authorize request.

        Extracted verbatim from ``auth_login`` (backend.py:1648-1671); the key list is fixed.
        """
        # FILL IN: move backend.py:1648-1671 here verbatim and `return web.HTTPFound(url)` — bounded by AC2 key list

    async def _oauth2_second_factor(self, request: web.Request, user: Any, data: dict, response: web.HTTPFound):
        """2FA-on tail of the password POST: decide through the shared gate (spec M6, D4)."""
        async with mfa_services_lease(request.app) as services:
            if services is None or not services.available:
                raise web.HTTPServiceUnavailable(reason="Auth: second factor temporarily unavailable.")  # AC6
            gate = SecondFactorGate(
                services, userid_attribute=self.userid_attribute, password_attribute=self.password_attribute
            )

            async def _issue(fresh: Any, extra: dict) -> web.HTTPFound:
                session = await self._create_user_session(
                    request, fresh, response=response, extra={**extra, "auth_method": "oauth2"}
                )
                if not session:
                    raise web.HTTPBadRequest(reason="Auth: unable to create the User session.")
                return response

            try:
                result = await gate.decide(request, user, _issue)
            except (FailedAuth, MFARefused) as err:
                # FILL IN: FailedAuth -> 403 (inactive) / 401 (credentials_changed); MFARefused -> its status
                #          (503 mfa_unavailable, 403 no_factor_available); render oauth/login.html with an
                #          error and that status — bounded by "no session on any refusal" (AC6, AC17)
                raise
        if result.session is not None:
            if result.device:
                response.set_cookie(TRUSTED_COOKIE, result.device["token"], **trusted_cookie_kwargs(result.device["max_age"]))
            return response
        return await self._render_mfa_page(request, data, result.challenge)
```
**Why**: the split keeps `auth_login` readable and makes the 2FA-off path a literal copy of today's code.
`_render_mfa_page` is defined in the next block.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — `auth_login_mfa` + page renderer
```python
# occurrences: 1 (verified: grep -c '    # token_request' navigator_auth/backends/oauth2/backend.py)
# BEFORE — insert above the banner `    # ------------------------------------------------------------------` /
#          `    # token_request` (verified: backend.py:1690-1692)
    _MFA_FORM_KEYS = ("client_id", "redirect_uri", "response_type", "state", "scope",
                      "code_challenge", "code_challenge_method", "nonce", "prompt")

    async def _render_mfa_page(self, request, data: dict, challenge: Any, *, error: Optional[str] = None,
                               attempts_remaining: Optional[int] = None, status: int = 200) -> web.Response:
        """Render ``oauth/mfa.html`` (no-store) carrying the challenge and the authorize request."""
        params = {key: data.get(key) or "" for key in self._MFA_FORM_KEYS}
        params.update(
            action_url=str(request.app.router["nav_oauth2_login_mfa"].url_for()),
            challenge=challenge.token if challenge is not None else data.get("challenge", ""),
            providers=list(challenge.providers) if challenge is not None else [],  # FILL IN: on re-render keep the submitted providers list — bounded by AC3
            preferred=challenge.preferred if challenge is not None else data.get("provider"),
            expires_in=challenge.expires_in if challenge is not None else None,
            error=error,
            attempts_remaining=attempts_remaining,
        )
        page = await self._parser.view(filename="oauth/mfa.html", params=params, status=status)
        page.headers["Cache-Control"] = "no-store"
        return page

    async def auth_login_mfa(self, request: web.Request) -> web.StreamResponse:
        """POST {login_uri}/mfa — complete an OAuth2 password login's second factor (spec M6)."""
        if not auth_conf.AUTH_BASIC_2FA_ENABLED:
            raise web.HTTPNotFound()  # no new surface with 2FA off (AC5)
        data = await self.get_payload(request)
        response = self._authorize_redirect(request, data)
        async with mfa_services_lease(request.app) as services:
            if services is None or not services.available:
                raise web.HTTPServiceUnavailable(reason="Auth: second factor temporarily unavailable.")
            gate = SecondFactorGate(
                services, userid_attribute=self.userid_attribute, password_attribute=self.password_attribute
            )

            async def _issue(fresh: Any, extra: dict) -> web.HTTPFound:
                # FILL IN: identical to _oauth2_second_factor._issue (extract a shared helper if you prefer)
                ...

            try:
                result = await gate.verify(
                    request, str(data.get("challenge") or ""), str(data.get("provider") or ""),
                    str(data.get("code") or ""), _issue,
                    remember_device=bool(data.get("remember_device")),
                    device_label=str(data.get("device_label") or "")[:128],
                )
            except VerifyRefused as err:
                # FILL IN: invalid_code -> _render_mfa_page(error, attempts_remaining=err.extra.get(...), status=401);
                #          invalid_challenge / stale_challenge -> oauth/login.html with an error (status 401);
                #          rate_limited -> _render_mfa_page(status=429); mfa_unavailable -> 503;
                #          account_disabled / MfaSignal codes -> login page with error + err.status — bounded by AC3, spec M6
                raise
        if result.device:
            response.set_cookie(TRUSTED_COOKIE, result.device["token"], **trusted_cookie_kwargs(result.device["max_age"]))
        return response
```
**Why**: the gate owns ordering, rate limits and replay protection (TASK-181); this method only maps
outcomes to HTML. `str(...)` coercion keeps the gate's shape check meaningful for missing fields.

### `templates/oauth/mfa.html` (CREATE)
```html
{% autoescape true %}
<!DOCTYPE html>
<html>
<head><title>Second factor</title></head>
<body>
  <div><h1><span>Verify it's you</span></h1></div>
  {% if error %}<div role="alert" id="mfa-error">{{ error }}{% if attempts_remaining is not none %} ({{ attempts_remaining }} attempts remaining){% endif %}</div>{% endif %}
  <form name="mfaForm" action="{{ action_url }}" method="post" autocomplete="off">
    <!-- FILL IN: provider choice (radio per entry of `providers`, `preferred` checked) — bounded by AC1 -->
    Code:<br>
    <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required>
    <br>
    <label><input type="checkbox" name="remember_device" value="1"> Remember this device</label>
    <input type="text" name="device_label" maxlength="128" placeholder="Device name (optional)">
    <input type="hidden" name="challenge" value="{{ challenge }}">
    <input type="hidden" name="response_type" value="{{ response_type }}">
    <input type="hidden" name="client_id" value="{{ client_id }}">
    <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
    <input type="hidden" name="scope" value="{{ scope }}">
    <input type="hidden" name="state" value="{{ state }}">
    <input type="hidden" name="code_challenge" value="{{ code_challenge }}">
    <input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">
    <input type="hidden" name="nonce" value="{{ nonce }}">
    <input type="hidden" name="prompt" value="{{ prompt }}">
    <input type="submit" value="Verify">
  </form>
</body>
</html>
{% endautoescape %}
```
**Why**: `{% autoescape true %}` escapes every echoed authorize parameter (spec §7 risk). The 9 hidden
inputs mirror `login.html:29-37` and must equal `_authorize_redirect`'s key list (`_MFA_FORM_KEYS`).

### `templates/oauth/login.html` (MODIFY)
```html
<!-- occurrences: 1 (verified: grep -c '<div><span>Using your Navigator Account:</span></div>' templates/oauth/login.html) -->
<!-- AFTER — insert below `<div><span>Using your Navigator Account:</span></div>` (verified: login.html:18) -->
    {% if error %}<div role="alert" id="login-error">{{ error|e }}</div>{% endif %}
```
**Why**: AC3 returns invalid/stale challenges to the login page "with an error"; `|e` because this template
is not autoescaped.

### `tests/test_mfa_review_fixes_oauth2.py` (CREATE)
See **Test Specification** below (whole-file starting point).

### FILL IN checklist
- [ ] `_issue_auth_event` — attribute-style `user_id` read; TTL from the session when set — bounded by plan TASK-184
- [ ] `auth_login` 2FA-off tail — literal copy of backend.py:1673-1686 — bounded by AC5
- [ ] `_authorize_redirect` — verbatim move of backend.py:1648-1671 — bounded by AC2
- [ ] `_oauth2_second_factor` refusal mapping (FailedAuth / MFARefused → HTML + status, no session) — bounded by AC6, AC17
- [ ] `_render_mfa_page` providers on re-render — bounded by AC3
- [ ] `auth_login_mfa` issuer + `VerifyRefused` mapping — bounded by AC2, AC3, spec M6
- [ ] `oauth/mfa.html` provider choice — bounded by AC1
- [ ] Test bodies — bounded by AC1–AC6, AC10

---

## Acceptance Criteria

- [ ] **AC1** — 2FA on, factor owed: `POST /oauth2/login` with a valid password → 200 HTML second-factor form,
      `Cache-Control: no-store`, no session `Set-Cookie`, no redirect; an email-preferred user receives exactly one OTP email.
- [ ] **AC2** — `POST /oauth2/login/mfa` with a valid code → 302 to `/oauth2/authorize` carrying the 9 authorize
      parameters exactly as submitted; the auth-event record has `mfa: true`, `amr: ["pwd", <otp|totp|backup>]`;
      replaying the same challenge fails.
- [ ] **AC3** — invalid code re-renders the MFA page with `attempts_remaining` and no session; exhausted attempts or a
      stale challenge return to the login page with an error.
- [ ] **AC4** — a valid `nav_mfa_device` cookie skips the challenge, is rotated, and the event `amr` is
      `["pwd","trusted_device"]`; `remember_device` on the MFA form sets the cookie with `trusted_cookie_kwargs`.
- [ ] **AC5** — 2FA off: `auth_login` GET/POST status, `Location`, session keys and cookies unchanged; no auth event.
- [ ] **AC6** — 2FA on, MFA slot missing or unavailable: the password POST returns 503 and creates no session.
- [ ] **AC10 (OAuth rows)** — `/oauth2/login` and `/oauth2/login/mfa` complete within 10 s against `single_connection_authdb`,
      with no `acquire()` while `LOCK_CONNECTION` is set.
- [ ] Existing suites `tests/test_oauth2_auth_login_inactive.py` and `tests/test_oauth2_login_page_passkey.py` still pass.
- [ ] No linting errors (`ruff check navigator_auth/backends/oauth2/backend.py` if ruff is configured).

---

## Validation Commands

- `pytest tests/test_mfa_review_fixes_oauth2.py -q`
- `pytest tests/test_oauth2_auth_login_inactive.py -q`
- `pytest tests/test_oauth2_login_page_passkey.py -q`

---

## Test Specification

```python
# tests/test_mfa_review_fixes_oauth2.py
"""FEAT-106 review fix #1 (spec M6): the OAuth2 password form enforces the second factor."""
import pytest
import pytest_asyncio

import navigator_auth.conf as conf
from navigator_auth.backends.oauth2.backend import OAUTH2_EVENT_COOKIE
from navigator_auth.backends.oauth2.client_backend import MemoryClientStorage
from navigator_auth.backends.oauth2.models import OAuthClient
from tests.fixtures.mfa import (  # noqa: F401
    frozen_totp_clock, mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory, otp_callback_spy,
    single_connection_authdb,
)

AUTHORIZE_PARAMS = {
    "client_id": "mfa-oauth-client", "redirect_uri": "https://app.example/cb", "response_type": "code",
    "state": "s-123", "scope": "default", "code_challenge": "x" * 43, "code_challenge_method": "S256",
    "nonce": "n-1", "prompt": "login",
}


@pytest_asyncio.fixture
async def oauth2_client():
    """A registered public PKCE client in memory storage (spec §4 fixture)."""
    # FILL IN: OAuthClient(client_id=..., client_type="public", redirect_uris=[...], default_scopes=[...])


@pytest_asyncio.fixture
async def oauth_live(monkeypatch, mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory, frozen_totp_clock, oauth2_client):
    """AuthHandler(BasicAuth + Oauth2Provider) on live Postgres + Redis with 2FA on (pattern: tests/test_mfa_e2e.py:369-457)."""
    # FILL IN: _patch_settings-equivalent; swap provider.client_storage for MemoryClientStorage holding oauth2_client


@pytest.mark.asyncio
async def test_oauth2_login_factor_owed_renders_mfa_page(oauth_live):
    """AC1."""
    # FILL IN: 200 HTML, Cache-Control no-store, no session Set-Cookie, no Location; email user -> exactly one OTP


@pytest.mark.asyncio
async def test_oauth2_login_mfa_success_redirects_with_pkce(oauth_live):
    """AC2: 302 with the 9 parameters exactly; event record mfa/amr; replay fails."""


@pytest.mark.asyncio
async def test_oauth2_login_mfa_invalid_and_stale(oauth_live):
    """AC3: invalid code -> MFA page + attempts_remaining, no session; exhausted/stale -> login page + error."""


@pytest.mark.asyncio
async def test_oauth2_login_trusted_device(oauth_live):
    """AC4: trusted cookie skips + rotates; amr pwd+trusted_device; remember_device sets the cookie."""


@pytest.mark.asyncio
async def test_oauth2_login_2fa_disabled_unchanged(monkeypatch):
    """AC5: status, Location, session keys and cookies equal the pre-change behaviour; no OAUTH2_EVENT_COOKIE."""


@pytest.mark.asyncio
async def test_oauth2_login_mfa_unavailable_503(monkeypatch):
    """AC6: slot missing or services.available False -> 503 and _create_user_session never awaited."""


@pytest.mark.asyncio
async def test_oauth2_login_single_connection_pool(single_connection_authdb):
    """AC10: /oauth2/login and /oauth2/login/mfa finish < 10 s with max_size=1; no acquire inside the lock."""


def test_mfa_template_escapes_authorize_parameters():
    """Spec §7 risk: a `"><script>` state value is rendered escaped in oauth/mfa.html."""
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the stacked feature worktree** `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa-review-fixes` (branch
   `feat-FEAT-106-basicauth-otp-2fa-review-fixes`, stacked on `feat-FEAT-106-basicauth-otp-2fa`; ships in PR #633) — never on `dev`.
2. **Read the spec** at the path listed above (§3 M6, §7 D1/D4, §5 AC1–AC6, AC10).
3. **Check dependencies** — TASK-173 and TASK-181 must be `"done"` in
   `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json`.
4. **Verify the Codebase Contract** — re-run the `grep -c` of every anchor above; confirm
   `SecondFactorGate`/`VerifyRefused` (`navigator_auth/mfa/login.py`) and `mfa_services_lease`
   (`navigator_auth/mfa/services.py`) exist with the plan's signatures. If anything changed, update the contract FIRST.
5. **Update status** in the per-spec index → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** from the blueprint, completing every `# FILL IN:`; never change a fixed signature or path.
7. **Verify** all acceptance criteria — run the Validation Commands.
8. **Commit the code** — stage only the files listed above.
9. **Close the task** with `parrot sdd task close TASK-184 basicauth-otp-2fa-review-fixes verified`.
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

Implemented by native sonnet; orchestrator ran the 3 test modules (16 passed, 1 skipped) and committed. DEVIATION: the live-Postgres AC10 single_connection_authdb test and live email-OTP/replay checks from the task Test Specification were not written (coder had no working Bash); tests are mock-based. Follow-up needed. Merge-tier validation (chunk 5): 83 passed, 1 skipped. File fidelity checked. Closed via `parrot sdd task close`.
