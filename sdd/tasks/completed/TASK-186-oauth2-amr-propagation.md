# TASK-186: mfa/amr through codes, refresh chains, introspection and userinfo (M9)

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-184, TASK-185
**Assigned-to**: unassigned

---

## Context

Spec §3 Module 9 (G8, D8, D9). After TASK-184, an OAuth2 password login with 2FA on records the login's
assurance in an **authentication-event-specific** browser record (`_issue_auth_event` / `_load_auth_event`,
cookie `nav_oauth2_event`), never in the identity-shared session. After TASK-185, every user code, carrier
and token carries the OAuth credential `generation`.

This task carries the second-factor outcome of that **validated browser event** through:
authorization code (`_issue_code`) → device-flow carrier (`_approve_device_code`) → code exchange
(access-token claims `mfa`/`amr` + the issued `OauthRefreshToken`) → refresh rotation (copied from the
parent refresh token, never re-derived — D8) → introspection and userinfo echo.

It also enforces **browser-event isolation**: the assurance used for a code must belong to the event bound
to the current browser session and user; a later login elsewhere must not upgrade an older event; a stale
or foreign event must send the browser back to login instead of borrowing assurance (AC29 browser part).

Request-local ABAC assurance for bearer requests is TASK-187 — not here.

---

## Scope

- Add `mfa: bool = False` and `amr: Optional[list[str]] = None` to `OauthAuthorizationCode` and
  `OauthRefreshToken` (spec §2 Data Models).
- Add `Oauth2Provider._session_auth_context(request) -> dict` built on TASK-184's `_load_auth_event`, with
  session/user binding validation.
- Validate the event (2FA on) in `authorize`, `consent` (POST approve) and `device_verification` (POST),
  before any code/carrier is minted.
- `_issue_code` and `_approve_device_code`: build the carrier with `**await self._session_auth_context(request)`.
- Code exchange (`_handle_authorization_code`): when `auth_code.mfa`, add `mfa`/`amr` to `token_data` and copy
  both onto the issued `OauthRefreshToken`.
- Refresh grant (`_handle_refresh_token`): same, sourced from the presented `rt`; rotation copies `rt.mfa`/`rt.amr`.
- Introspection: echo `amr` + `mfa: true` for an MFA'd access token (from its payload) or refresh token
  (from the stored `rt`); omit otherwise.
- userinfo: echo `amr` when the access-token payload carries it (not scope-gated).
- Write the AC23–AC26 tests and the browser-event part of AC29 in
  `tests/test_mfa_review_fixes_oauth2_tokens.py` (created by TASK-185).

**NOT in scope**: request-local bearer assurance and ABAC (`abac/*.py`, `AuthHandler._auth_middleware`
assurance — TASK-187); generation stamping/enforcement (TASK-185); the login form, `auth_login_mfa`,
`_create_user_session(extra)` and the event record itself (TASK-184); `client_credentials` (no user — unchanged);
OIDC `id_token` / `acr` (non-goals).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `_session_auth_context`, event checks in authorize/consent/device, carriers, exchange, refresh, introspect, userinfo |
| `navigator_auth/backends/oauth2/models.py` | MODIFY | `mfa` / `amr` on `OauthAuthorizationCode` and `OauthRefreshToken` |
| `tests/test_mfa_review_fixes_oauth2_tokens.py` | MODIFY | AC23–AC26 and AC29 (browser-event isolation) tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `0b80d88` (branch `feat-FEAT-106-basicauth-otp-2fa`; code identical to the spec's `3f14b3c`).
> Line numbers are pre-TASK-184/185; those tasks edit the same two files first, so **re-locate every anchor by
> its text** (counts below) before editing.

### Verified Imports
```python
# already imported in navigator_auth/backends/oauth2/backend.py — do not re-add:
import hmac                                                # verified: backend.py:33
import secrets                                             # verified: backend.py:36
from aiohttp import web                                    # verified: backend.py:40
from navigator_session import get_session, SESSION_ID      # verified: backend.py:93-96
from ...exceptions import FailedAuth, UserNotFound, InvalidAuth   # verified: backend.py:102-106
from ...identities import AuthUser                         # verified: backend.py:46 (anchor for the conf alias below)

# add to backend.py ONLY if TASK-184 did not already add it (grep first):
from ... import conf as auth_conf                          # pattern verified: navigator_auth/backends/basic.py:15 (`from .. import conf as auth_conf`)
# auth_conf.AUTH_BASIC_2FA_ENABLED                         # verified: navigator_auth/conf.py:659 — read at call time so tests can patch it

# already imported in navigator_auth/backends/oauth2/models.py:
from typing import Optional, Union                         # verified: models.py:21
from datetime import datetime, timedelta                   # verified: models.py:22
from pydantic import BaseModel, ConfigDict, Field, field_validator   # verified: models.py:26

# tests
from navigator_auth.mfa.types import AMR_PASSWORD, AMR_TRUSTED_DEVICE, AMR_BY_PROVIDER, PROVIDER_TOTP  # verified: mfa/types.py:10-12
```

### Existing Signatures to Use
```python
# navigator_auth/backends/oauth2/backend.py
class Oauth2Provider(BaseAuthBackend):                                   # line 258
    async def check_session(self, request)                               # line 523 — returns session["user"] blob or None
    def _decode_session_user(self, encoded_user) -> Optional[OauthUser]  # line 538 — .user_id int
    def _session_storage(self, request: web.Request)                     # line 622
    async def _token_session_claims(self, request: web.Request, user_id: int) -> dict   # line 688 (TASK-185 adds kw-only conn=)
    async def authorize(self, request: web.Request)                      # line 1343; `# Check user session.` 1422,
                                                                         #   no-session redirect 1424-1428, access gate 1430
    async def _issue_code(self, request, client, user_obj: OauthUser, redirect_uri: str, scope: str, state: str,
                          code_challenge=None, code_challenge_method=None, resource=None)   # line 1478; OauthAuthorizationCode(...) 1494-1506
    async def consent(self, request: web.Request)                        # line 1516; POST approve resolves user 1539-1545
    async def _handle_authorization_code(self, payload, request)         # line 1743; token_data 1822-1830; create_token 1855;
                                                                         #   OauthRefreshToken(...) 1873-1881; save_token(rt) 1882
    async def _handle_refresh_token(self, payload, request)              # line 1973; `rt = await self.refresh_token_storage.get_token(...)` 1995;
                                                                         #   token_data 2040-2047; new_rt = OauthRefreshToken(...) 2082-2091
    async def userinfo(self, request)                                    # line 2194; claims = {"sub": str(user_id)} 2222; `# Scope-gated claims.` 2244
    async def introspect(self, request: web.Request)                     # line 2359; token_payload / rt resolved 2408-2443; claims dict 2468-2482
    async def device_verification(self, request: web.Request)            # line 2604; `# --- Require authenticated session ---` 2684-2697
    async def _approve_device_code(self, dc, user_obj, scopes, client, request)   # line 2757; carrier = OauthAuthorizationCode(...) 2775-2786
    def redirect(self, uri: str, location: bool = False)                 # line 489 — raises the redirect
    def _error_response(self, error: str, description: str, status: int = 400)   # line 495

# navigator_auth/backends/oauth2/models.py  (pydantic BaseModel — NOT datamodel)
class OauthAuthorizationCode(BaseModel):     # line 209; last field `used_at: Optional[datetime] = Field(default=None)` line 238
class OauthRefreshToken(BaseModel):          # line 245; last field `revoked_reason: Optional[str] = Field(default=None)` line 267
# navigator_auth/backends/oauth2/code_backend.py — model_dump_json() on save (69, 141); Model(**json.loads(data)) on read (82, 163):
#   a stored code/token without mfa/amr deserializes with the defaults (no migration needed).

# navigator_auth/mfa/types.py
AMR_PASSWORD, AMR_TRUSTED_DEVICE = "pwd", "trusted_device"               # line 11
AMR_BY_PROVIDER = {"email": "otp", "totp": "totp", "backup": "backup"}   # line 12
```

**Created by dependencies (fixed signatures — verify they landed before you start):**
```python
# TASK-184 — navigator_auth/backends/oauth2/backend.py
OAUTH2_EVENT_COOKIE = "nav_oauth2_event"
async def _create_user_session(self, request, user, response=None, extra: Optional[dict] = None)
async def _issue_auth_event(self, request, response, session, user, extra: dict) -> None
    # Redis record under "oauth2:event:" + sha256(handle): {user_id, session_id, mfa, amr, auth_method, issued_at}
async def _load_auth_event(self, request) -> Optional[dict]   # cookie -> record; None when missing/expired/malformed; NO validation
# TASK-185 — models.py: OauthAuthorizationCode.generation / OauthRefreshToken.generation: int = Field(default=0);
#   navigator_auth/security_state/store.py: GENERATION_CLAIM = "gen", stamp_generation(payload, generation)
#   tests/test_mfa_review_fixes_oauth2_tokens.py exists (created by TASK-185) — extend it, do not recreate it.
```

### Does NOT Exist
- ~~`Oauth2Provider._session_auth_context`~~ — created by THIS task.
- ~~`OauthAuthorizationCode.mfa` / `.amr`~~, ~~`OauthRefreshToken.mfa` / `.amr`~~ — created by THIS task.
- ~~`auth_conf` alias in `backends/oauth2/backend.py` at `0b80d88`~~ — the module only has `from ...conf import (...)`
  (backend.py:47); TASK-184 may add `from ... import conf as auth_conf` — grep before adding.
- ~~`AUTH_BASIC_2FA_ENABLED` imported in backend.py at `0b80d88`~~ — not imported there; read it through `auth_conf` at call time.
- ~~datamodel `BaseModel` in `oauth2/models.py`~~ — spec §6 says "datamodel BaseModel, Field"; the models are **pydantic** (models.py:26).
- ~~an OIDC `id_token` / `acr` claim~~ — not issued by this provider; non-goal.
- ~~`AUTH_BEARER_CONTEXT_KEY`, `bearer_context_from_claims`, `effective_userinfo`~~ — TASK-187.
- ~~`navigator_auth/handlers/auth.py`~~ — does not exist (spec M4 path list drift).
- ~~an `amr` claim on `client_credentials` tokens~~ — never (no user).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/backends/oauth2/backend.py", "action": "MODIFY"},
    {"path": "navigator_auth/backends/oauth2/models.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_review_fixes_oauth2_tokens.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.check_session",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._decode_session_user",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._token_session_claims",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.authorize",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._issue_code",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.consent",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._handle_authorization_code",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._handle_refresh_token",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.userinfo",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.introspect",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.device_verification",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._approve_device_code",
    "sym:navigator_auth/backends/oauth2/models.py#OauthAuthorizationCode",
    "sym:navigator_auth/backends/oauth2/models.py#OauthRefreshToken",
    "sym:navigator_auth/conf.py#AUTH_BASIC_2FA_ENABLED",
    "sym:navigator_auth/mfa/types.py#AMR_BY_PROVIDER"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
```python
# The carrier already receives every field by keyword; the assurance dict is spread in, so the
# keys of _session_auth_context's return value MUST be exactly the model field names ("mfa", "amr").
code_obj = OauthAuthorizationCode(client=client, user_id=user_obj.user_id, ..., resource=resource,
                                  **await self._session_auth_context(request))
```

### Key Constraints
- **D8**: `amr` describes the original authentication event. Refresh rotation copies it from the parent `rt`;
  never recompute it from a session. Claims appear only when the login actually passed MFA (`mfa` True AND a
  non-empty `amr`); a missing claim means "not MFA'd" to every consumer.
- **AC24 / AC5**: with 2FA off, or no factor owed, token payloads have **no** `mfa`/`amr` keys — at generation 0
  the 2FA-off payload key set must equal `origin/dev`'s. Never write `mfa: False` into a JWT.
- **Isolation (spec M9 "Browser event isolation", AC29)**: never fall back to the identity-shared session's
  `AUTH_SESSION_OBJECT` / `mfa` for a code. Compare identifiers with `hmac.compare_digest` on `str`.
- TASK-185 stamps `generation` at the same construction sites; keep both — do not drop its edits.
- Every new method: Google-style docstring + type hints; log with `self.logger`, never log the event handle,
  cookie value, codes or tokens.
- Do not touch `client_credentials` (`token_data` at backend.py:1929).

### References in Codebase
- `navigator_auth/backends/oauth2/backend.py:1422-1428` — the no-session redirect to reuse for "login again".
- `navigator_auth/backends/oauth2/backend.py:2684-2693` — device-flow login redirect to reuse.
- `tests/conftest.py:251-310` — `memory_oauth_storages`, `public_client`, `confidential_client` fixtures.
- `tests/test_mfa_e2e.py:93,123-133` — `FRESH_FACTORS`, `requires_fresh_factor` (used by TASK-187, not here).

---

## Implementation Blueprint

> **CRITICAL — Executor-ready starting point.** Write each block below to its declared
> path nearly verbatim, then complete every `# FILL IN:` marker. Blocks were derived
> from the spec's Interface Skeletons and re-verified against the Codebase Contract
> above when this task was written. This is NOT the full implementation:
> business-logic branches, edge cases and test bodies are `FILL IN` stubs by design.
> Never change a signature, class name, or file path the blueprint fixes.

### Steps (in order)
1. Confirm TASK-184/185 landed: `grep -n "_load_auth_event\|OAUTH2_EVENT_COOKIE" navigator_auth/backends/oauth2/backend.py`
   and `grep -n "generation" navigator_auth/backends/oauth2/models.py` — *why*: this task builds on both; stop if absent.
2. Add the `mfa`/`amr` fields to both models — *why*: carriers and refresh tokens must persist the assurance across
   Redis round-trips (`model_dump_json` / `Model(**json)`), and old stored records must still load (defaults).
3. Add `_session_auth_context` — *why*: one place decides which assurance a browser event may contribute.
4. Validate the event up-front in `authorize`, `consent` (POST approve) and `device_verification` (POST) — *why*: a stale
   or foreign event must send the browser to login BEFORE consent-skip or carrier minting (spec M9 isolation).
5. Spread `**await self._session_auth_context(request)` into both `OauthAuthorizationCode(...)` constructions — *why*:
   spec M9 "the three places that mint authorization-code carriers copy it onto the carrier".
6. Propagate in the code exchange, refresh, introspection and userinfo — *why*: AC23, AC25, AC26.
7. Extend `tests/test_mfa_review_fixes_oauth2_tokens.py` and run the Validation Commands — *why*: AC23–AC26, AC29.

### `navigator_auth/backends/oauth2/models.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'used_at: Optional[datetime] = Field(default=None)' navigator_auth/backends/oauth2/models.py)
# AFTER — insert below `    used_at: Optional[datetime] = Field(default=None)` (verified: models.py:238), inside
# OauthAuthorizationCode. If TASK-185 put `generation` directly below it, insert below `generation` instead.
    # FEAT-106 review fixes (M9, D8): second-factor outcome of the approving browser
    # authentication event. ``amr`` is None when that login did not pass MFA.
    mfa: bool = Field(default=False)
    amr: Optional[list[str]] = Field(default=None)
```
```python
# occurrences: 1 (verified: grep -c 'revoked_reason: Optional[str] = Field(default=None)' navigator_auth/backends/oauth2/models.py)
# AFTER — insert below `    revoked_reason: Optional[str] = Field(default=None)` (verified: models.py:267), inside
# OauthRefreshToken (same placement rule relative to TASK-185's `generation`).
    # FEAT-106 review fixes (M9, D8): copied from the authorization code at exchange and
    # from the parent token on rotation — never re-derived.
    mfa: bool = Field(default=False)
    amr: Optional[list[str]] = Field(default=None)
```
**Why this shape**: spec §2 Data Models fixes the names, types and defaults. Defaults keep every stored code and
refresh token readable by `code_backend.py:82,163` without a migration.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — `_session_auth_context`
```python
# occurrences: 1 (verified: grep -c '    async def validate_client(self, client_id, redirect_uri=None, request=None):' navigator_auth/backends/oauth2/backend.py)
# BEFORE — insert above `    async def validate_client(self, client_id, redirect_uri=None, request=None):` (verified: backend.py:712),
# i.e. right after `_token_session_claims`.
    async def _session_auth_context(self, request: web.Request) -> dict:
        """Return the second-factor assurance of the validated browser authentication event.

        Built on ``_load_auth_event`` (TASK-184). The event must belong to the CURRENT
        browser session and its user; the identity-shared session is never consulted
        for assurance, and a later login elsewhere never upgrades this event.

        Returns:
            ``{"mfa": True, "amr": [...]}`` for an MFA'd event; ``{}`` for a valid event
            without a second factor, and always ``{}`` when 2FA is disabled (AC5/AC24).

        Raises:
            InvalidAuth: (401) 2FA is enabled and the event is stale, malformed, or bound
                to another session or user. Callers send the browser back to login.
        """
        if not auth_conf.AUTH_BASIC_2FA_ENABLED:
            return {}
        record = await self._load_auth_event(request)
        if record is None:
            # FILL IN: missing event with 2FA on — see FILL IN checklist item 1 (ESCALATED decision).
            #   Bounded by: never return assurance without a validated event (D9, AC29); must not
            #   loop passkey / upstream-IdP browser sessions back to login (they never get an event:
            #   _create_user_session is only called by auth_login and _token_session_claims).
            return {}
        # FILL IN: load the current browser session with
        #   `await get_session(request, None, new=False, ignore_cookie=False)` and its user via
        #   `self._decode_session_user(session.get("user"))`; require
        #   hmac.compare_digest(str(record.get("session_id")), str(session.session_id)) and
        #   hmac.compare_digest(str(record.get("user_id")), str(user.user_id)); any miss or exception
        #   -> raise InvalidAuth("Oauth2: login required.", status=401) — bounded by spec M9 isolation, AC29.
        if not record.get("mfa"):
            return {}
        amr = record.get("amr")
        # FILL IN: amr must be a non-empty list of str; otherwise raise InvalidAuth (malformed event) —
        #   bounded by D8 ("claims appear only when the login actually passed MFA").
        return {"mfa": True, "amr": [str(value) for value in amr]}
```
**Why this shape**: the return keys equal the model field names so call sites can spread it into
`OauthAuthorizationCode(...)`. Raising `InvalidAuth` (already imported) lets each caller map "login again" onto
its existing no-session handling (redirect for browser hops, 401 JSON for consent POST).

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — event check in `authorize`
```python
# occurrences: 1 (verified: grep -c '        # FEAT-095 TASK-042: ACCESS GATE — after login, BEFORE consent.' navigator_auth/backends/oauth2/backend.py)
# BEFORE — insert above `        # FEAT-095 TASK-042: ACCESS GATE — after login, BEFORE consent.` (verified: backend.py:1430),
# i.e. after the `if not session:` redirect block (1424-1428).
        # FEAT-106 review fixes (M9): a stale or foreign browser event never lends assurance.
        try:
            await self._session_auth_context(request)
        except InvalidAuth:
            location = request.app.router["nav_oauth2_login"].url_for()
            payload = {"action_url": str(location), **data}
            self.redirect(location.with_query(**payload), location=True)
```

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — event check in `consent` and `device_verification`
```python
# occurrences: 1 (verified: grep -c 'return self._error_response("access_denied", "Cannot resolve user from session.", status=401)' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below that line (verified: backend.py:1545) — consent POST approve, 16-space indent.
                try:
                    await self._session_auth_context(request)
                except InvalidAuth:
                    return self._error_response("access_denied", "User not authenticated.", status=401)
```
```python
# occurrences: 1 (verified: grep -c 'return self._error_response("access_denied", "Cannot resolve session user.", status=401)' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below that line (verified: backend.py:2697) — device_verification POST, 8-space indent.
        try:
            await self._session_auth_context(request)
        except InvalidAuth:
            location = request.app.router["nav_oauth2_login"].url_for()
            raise web.HTTPFound(location.with_query(action_url=str(location), device_user_code=raw_user_code))
```
**Why**: spec M9 "validate it at authorization and consent and bind device approval to the approving event".
Both reuse the response each path already gives an unauthenticated browser.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — carriers
```python
# occurrences: 1 (verified: grep -c '# RFC 8707: carried through the code to the token exchange.' navigator_auth/backends/oauth2/backend.py)
# AFTER — the `resource=resource,` line that follows `# RFC 8707: carried through the code to the token exchange.`
# (verified: backend.py:1504-1505), inside `code_obj = OauthAuthorizationCode(` in _issue_code.
            # FEAT-106 review fixes (M9): assurance of the validated browser event.
            **await self._session_auth_context(request),
```
```python
# occurrences: 1 (verified: grep -c 'expires_at=now + timedelta(seconds=OAUTH_DEVICE_CODE_TTL),' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below that line (verified: backend.py:2785), inside `carrier = OauthAuthorizationCode(` in _approve_device_code.
            # FEAT-106 review fixes (M9): the approving event's assurance (AC23 device flow).
            **await self._session_auth_context(request),
```

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — code exchange
```python
# occurrences: 1 (verified: grep -c '# FEAT-095 TASK-044 (RFC 8707): a `resource` on the token request must' navigator_auth/backends/oauth2/backend.py)
# BEFORE — insert above that comment (verified: backend.py:1832), i.e. right after the `token_data = {...}`
# dict (and after any TASK-185 generation stamping on token_data).
        # FEAT-106 review fixes (M9, D8): assurance follows the code into the access token.
        if auth_code.mfa and auth_code.amr:
            token_data["mfa"] = True
            token_data["amr"] = list(auth_code.amr)
```
```python
# occurrences: 1 (verified: grep -c 'absolute_expires_at=now + absolute_ttl,' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below that line (verified: backend.py:1880), inside `rt = OauthRefreshToken(`.
                mfa=bool(auth_code.mfa and auth_code.amr),
                amr=list(auth_code.amr) if auth_code.mfa and auth_code.amr else None,
```

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — refresh grant
```python
# occurrences: 1 (verified: grep -c "# TASK-029: audience = 'user'." navigator_auth/backends/oauth2/backend.py)
# BEFORE — insert above `        # TASK-029: audience = 'user'.` (verified: backend.py:2049), after the refresh `token_data` dict.
        # FEAT-106 review fixes (M9, D8): copied from the presented refresh token, never re-derived.
        if rt.mfa and rt.amr:
            token_data["mfa"] = True
            token_data["amr"] = list(rt.amr)
```
```python
# occurrences: 1 (verified: grep -c 'absolute_expires_at=rt.absolute_expires_at,  # copy from chain root' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below that line (verified: backend.py:2090), inside `new_rt = OauthRefreshToken(`.
                mfa=rt.mfa,
                amr=list(rt.amr) if rt.amr else None,
```

### `navigator_auth/backends/oauth2/backend.py` (MODIFY) — introspection and userinfo
```python
# occurrences: 1 (verified: grep -c 'claims["jti"] = jti_claim' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below `            claims["jti"] = jti_claim` (verified: backend.py:2482), dedented to the `if jti_claim:` level (8 spaces).
        # FEAT-106 review fixes (M9): echo the authentication-method references (AC26).
        presented_amr = token_payload.get("amr") if token_payload else (rt.amr if rt is not None and rt.mfa else None)
        if presented_amr:
            claims["amr"] = list(presented_amr)
            claims["mfa"] = True
```
```python
# occurrences: 1 (verified: grep -c '        # Scope-gated claims.' navigator_auth/backends/oauth2/backend.py)
# BEFORE — insert above `        # Scope-gated claims.` (verified: backend.py:2244) in userinfo.
        # FEAT-106 review fixes (M9): amr describes the authentication, not the profile —
        # not scope-gated (spec M9 userinfo).
        if payload.get("amr"):
            claims["amr"] = list(payload["amr"])
```
**Why**: spec M9 bullets "Introspection" and "userinfo"; refresh-token introspection reads the stored `rt`
because opaque refresh tokens have no payload.

### `tests/test_mfa_review_fixes_oauth2_tokens.py` (MODIFY — created by TASK-185)
```python
# APPEND at the end of the module. Reuse the module's existing imports/fixtures from TASK-185 and the
# OAuth2+BasicAuth 2FA app builder from tests/test_mfa_review_fixes_oauth2.py (TASK-184) by import;
# FILL IN: if that builder is not importable, copy the minimal builder here — bounded by tests/fixtures/mfa.py fixtures.


@pytest.mark.asyncio
async def test_oauth2_token_carries_amr_after_mfa_login():
    """AC23: TOTP OAuth2 login -> code exchange -> access token mfa=true, amr=["pwd","totp"]; device carrier too."""
    # FILL IN: drive /oauth2/login -> /oauth2/login/mfa (TOTP, frozen clock) -> /oauth2/authorize (PKCE)
    #   -> /oauth2/token; decode the JWT; assert claims; repeat via device flow and assert the carrier's mfa/amr.


@pytest.mark.asyncio
async def test_oauth2_token_without_mfa_has_no_amr():
    """AC24: no factor owed, and 2FA off: no mfa/amr claim; 2FA-off generation-0 payload keys match origin/dev."""
    # FILL IN: assert "mfa" not in claims and "amr" not in claims; compare the 2FA-off key set with the
    #   pre-change baseline set written as a literal in this test.


@pytest.mark.asyncio
async def test_oauth2_refresh_preserves_amr():
    """AC25: refresh keeps the original amr; the rotated refresh token keeps it; trusted-device chain keeps its amr."""
    # FILL IN: two refreshes in a row; assert stored new_rt.mfa/.amr and the access-token claims each time.


@pytest.mark.asyncio
async def test_oauth2_introspect_and_userinfo_echo_amr():
    """AC26: introspection echoes amr+mfa for MFA'd access/refresh tokens and omits them otherwise; userinfo echoes amr."""
    # FILL IN


@pytest.mark.asyncio
async def test_oauth_browser_event_isolation():
    """AC29 (browser part): a later TOTP login in another browser never upgrades an older event; a foreign or
    stale event cookie sends authorize back to login; consent POST answers 401."""
    # FILL IN
```

### FILL IN checklist
- [ ] `backend.py::_session_auth_context` — **missing event with 2FA on (ESCALATED)**: the spec says "missing … require
      login", but passkey and upstream-IdP browser sessions never get an event (only `auth_login` calls
      `_create_user_session`). Default: return `{}` (no assurance) for a missing event and raise only for a present-but-invalid
      one. Switch to "raise" only if the operator confirms, or if TASK-184 issues an event for every OAuth2 browser session
      created while 2FA is on. Record the choice in the Completion Note. Bounded by D9/AC29 and
      `tests/test_oauth2_login_page_passkey.py` / `tests/test_oauth2_upstream_idp.py` staying green.
- [ ] `backend.py::_session_auth_context` — session/user binding check; bounded by spec M9 isolation, AC29.
- [ ] `backend.py::_session_auth_context` — amr shape validation; bounded by D8.
- [ ] Tests — the five test bodies above; bounded by AC23–AC26, AC29.

---

## Acceptance Criteria

- [ ] **AC23**: after a TOTP OAuth2 login, the exchanged access token has `mfa: true` and `amr: ["pwd","totp"]`; the device-flow carrier preserves the approving event's assurance.
- [ ] **AC24**: a login with no factor owed, or with 2FA off, yields tokens with no `mfa`/`amr` claim; at generation 0 the 2FA-off payload keys match `origin/dev`.
- [ ] **AC25**: a refresh from an MFA'd chain keeps the original `amr`, and the rotated refresh token keeps it; a trusted-device chain keeps `["pwd","trusted_device"]`.
- [ ] **AC26**: `/oauth2/introspect` returns `amr` (and `mfa: true`) for MFA'd access and refresh tokens and omits them otherwise; `/oauth2/userinfo` returns `amr` for an MFA'd access token.
- [ ] **AC29 (browser part)**: a separate browser event cannot inherit another event's MFA; a stale/foreign event requires login again.
- [ ] `client_credentials` tokens are byte-for-byte unchanged.
- [ ] Existing OAuth2 suites below pass unchanged.
- [ ] No linting errors (`ruff check navigator_auth/backends/oauth2/`).

## Validation Commands

- `pytest tests/test_mfa_review_fixes_oauth2_tokens.py -q`
- `pytest tests/test_oauth2_integration.py -q`
- `pytest tests/test_oauth2_introspection_device_integration.py -q`
- `pytest tests/test_oauth2_refresh.py -q`
- `pytest tests/test_oauth2_login_page_passkey.py -q`

---

## Test Specification

```python
# tests/test_mfa_review_fixes_oauth2_tokens.py — unit-level helpers worth adding alongside the live tests
from navigator_auth.backends.oauth2.models import OauthAuthorizationCode, OauthRefreshToken


def test_models_default_to_no_assurance(public_client):
    """Stored records without mfa/amr load with mfa=False, amr=None (Redis round-trip compatibility)."""
    rt = OauthRefreshToken(client=public_client, user_id=1, refresh_token="x", scope="openid")
    assert rt.mfa is False and rt.amr is None
    again = OauthRefreshToken(**{k: v for k, v in rt.model_dump().items() if k not in ("mfa", "amr")})
    assert again.mfa is False and again.amr is None
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the stacked feature worktree** `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa-review-fixes` (branch
   `feat-FEAT-106-basicauth-otp-2fa-review-fixes`, stacked on `feat-FEAT-106-basicauth-otp-2fa`; ships in PR #633) — never on `dev`.
2. **Read the spec** at the path listed above (§3 Module 9, §2 Data Models, AC23–AC29).
3. **Check dependencies** — TASK-184 and TASK-185 must be `"done"` in
   `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json`.
4. **Verify the Codebase Contract** — re-run every `grep -c` above; TASK-184/185 moved line numbers.
5. **Update status** in the index → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** from the Implementation Blueprint; complete every `# FILL IN:`.
7. **Verify** — run the Validation Commands.
8. **Commit the code** — stage only the files listed above.
9. **Close the task** with `parrot sdd task close TASK-186 basicauth-otp-2fa-review-fixes verified`.
10. **Fill in the Completion Note** below (record the missing-event decision), then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any

---

## Completion Note

Implemented by seat gpt-5.6-luna (codex), 1 attempt. Merge-tier validation: 31 passed (others cached green). File fidelity checked. Closed via `parrot sdd task close`.
