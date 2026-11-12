# TASK-187: Request-local bearer assurance for ABAC (M9)

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-186
**Assigned-to**: unassigned

---

## Context

Spec §3 Module 9, bullet **ABAC**, decision **D9**, goal **G8**, AC27 and AC29. OAuth2 sessions are keyed by
user identity: every token minted for a user shares one session (backend.py:640-642), and a BasicAuth/passkey
login for the same user writes `mfa`/`amr` into that shared session's `AUTH_SESSION_OBJECT`. ABAC today reads
assurance from that session (`abac/decorators.py:50`, `abac/guardian.py:54,248`, `abac/pdp.py:401,498,526,559,626`,
`navigator_auth/decorators.py:1068`) — so a password-only OAuth token can borrow a later TOTP login's assurance.

This task makes assurance for **bearer** requests come only from the **validated presented token**: after
signature, expiry, revocation, audience and generation validation (TASK-185), the bearer middleware and
`Oauth2Provider.authenticate` publish an immutable request-local copy of the token's `mfa`/`amr`/`auth_method`
and identity. ABAC removes session-derived assurance and applies that copy. Cookie-only requests keep today's
session behaviour. Missing claims deny fresh-factor rules. Nothing is written back into the shared session.

---

## Scope

- Add `AUTH_BEARER_CONTEXT_KEY = "auth_bearer_context"` to `navigator_auth/conf.py` after the `AUTH_MECHANISM_*` block.
- Add `bearer_context_from_claims(payload)` and `effective_userinfo(request, userinfo)` to `navigator_auth/abac/context.py`
  and apply `effective_userinfo` at the top of `EvalContext.__init__` — the single choke point used by `pdp.py` (4 sites)
  and `navigator_auth/decorators.py:1076`.
- Publish the context in `AuthHandler._auth_middleware` at each of the 3 places that set
  `request[AUTH_MECHANISM_KEY] = AUTH_MECHANISM_BEARER`, and in `Oauth2Provider.authenticate`.
- Apply `effective_userinfo` in `abac/decorators.py::_get_userinfo` and in `abac/guardian.py` (`Guardian.get_user`
  userinfo fallback and `Guardian.filter_resources`, which builds a context via `EvalContext.__new__`).
- Write AC27 and AC29 tests in `tests/test_mfa_review_fixes_oauth2_tokens.py`.

**NOT in scope**: token claims themselves (TASK-186), generation validation (TASK-185), persisting token assurance in a
shared session (explicit non-goal), `Guardian.has_scope` / `PEP.check` (they read only scopes/groups/roles — no assurance),
`navigator_auth/abac/pdp.py` and `navigator_auth/decorators.py` (covered through `EvalContext.__init__`; do not edit them).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/conf.py` | MODIFY | `AUTH_BEARER_CONTEXT_KEY` constant |
| `navigator_auth/auth.py` | MODIFY | publish the bearer context in `_auth_middleware` (3 sites) |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | publish the bearer context in `Oauth2Provider.authenticate` |
| `navigator_auth/abac/context.py` | MODIFY | `bearer_context_from_claims`, `effective_userinfo`; overlay in `EvalContext.__init__` |
| `navigator_auth/abac/decorators.py` | MODIFY | `_get_userinfo` uses `effective_userinfo` |
| `navigator_auth/abac/guardian.py` | MODIFY | `get_user` fallback and `filter_resources` use `effective_userinfo` |
| `tests/test_mfa_review_fixes_oauth2_tokens.py` | MODIFY | AC27, AC29 tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `0b80d88` (branch `feat-FEAT-106-basicauth-otp-2fa`; code identical to the spec's `3f14b3c`).
> TASK-185 edits `auth.py` and `backend.py` and TASK-186 edits `backend.py` before this task — re-locate anchors by text.

### Verified Imports
```python
# navigator_auth/conf.py — constants this task reads
AUTH_MECHANISM_KEY = "auth_mechanism"          # verified: conf.py:106
AUTH_MECHANISM_COOKIE = "cookie"               # verified: conf.py:107
AUTH_MECHANISM_BEARER = "bearer"               # verified: conf.py:108
AUTH_MECHANISM_DJANGO = "django"               # verified: conf.py:112 (last line of the block — insertion anchor)
from navigator_auth.conf import AUTH_SESSION_OBJECT   # verified: abac/decorators.py:15, abac/guardian.py:7

# navigator_auth/auth.py — existing conf import block
from .conf import (                            # verified: auth.py:42
    AUTH_MECHANISM_KEY,                        # verified: auth.py:43
    AUTH_MECHANISM_BEARER,                     # verified: auth.py:44
)
from .abac.middleware import abac_middleware   # verified: auth.py:83 — the abac package is already imported by auth.py,
                                               # so a module-level `from .abac.context import ...` adds no import cycle

# navigator_auth/backends/oauth2/backend.py — existing conf import block
from ...conf import (                          # verified: backend.py:47
    AUTH_MECHANISM_BEARER,                     # verified: backend.py:48
)

# navigator_auth/abac/context.py — existing imports (conf is imported LAZILY there to avoid a cycle: context.py:6-21)
from typing import Any, Optional               # verified: context.py:1
from collections.abc import MutableMapping, Iterator   # verified: context.py:2
from aiohttp import web                        # verified: context.py:3

# stdlib additions (context.py)
from collections.abc import Mapping
from types import MappingProxyType

# guardian / decorators already import EvalContext from context.py:
from .context import EvalContext               # verified: abac/guardian.py:10
from navigator_auth.abac.context import EvalContext   # verified: abac/decorators.py:18

# tests
from tests.test_mfa_e2e import requires_fresh_factor, FRESH_FACTORS   # verified: tests/test_mfa_e2e.py:93,123
from navigator_auth.mfa.types import AMR_PASSWORD, AMR_TRUSTED_DEVICE   # verified: mfa/types.py:11
```

### Existing Signatures to Use
```python
# navigator_auth/auth.py
class AuthHandler:                                                   # line 89
    async def _token_is_revoked(self, payload: dict) -> bool         # line 1044
    async def _auth_middleware(self, request, handler)               # line 1089
    #   excluded-path best-effort branch: 1101-1114 (sets mechanism bearer at 1112, no request["userdata"])
    #   session recreated from token: 1146-1181 (userdata 1178, mechanism 1180)
    #   existing session: 1190-1212 (userdata 1210, mechanism 1212)
    #   cookie fallback: 1217-1231 (AUTH_MECHANISM_COOKIE — must stay untouched)

# navigator_auth/backends/oauth2/backend.py
class Oauth2Provider(BaseAuthBackend):
    async def authenticate(self, request: web.Request)               # line 2833; request["userdata"] = payload 2879;
                                                                     #   self._set_user_request(request, user, mechanism=AUTH_MECHANISM_BEARER) 2881

# navigator_auth/backends/abstract.py
    def _set_user_request(self, request, user, mechanism=None)       # line 483 — writes request[AUTH_MECHANISM_KEY]

# navigator_auth/abac/context.py
class EvalContext(dict, MutableMapping):                             # line 82
    def __init__(self, request, user, userinfo, session, *args, org_id=None, client_id=None, **kwargs)  # line 89
    #   self.store = {} 101; store["user"] 117; store["userinfo"] 126; store["auth_method"]/["mfa"] from userinfo 136-141

# navigator_auth/abac/decorators.py
async def _get_userinfo(request: web.Request) -> tuple               # line 41; userinfo = session[AUTH_SESSION_OBJECT] 50; return 53

# navigator_auth/abac/guardian.py
class Guardian:                                                      # line 16
    async def get_user(self, request: web.Request) -> tuple          # line 33; fallback userinfo = session[AUTH_SESSION_OBJECT] 54-55
    async def has_scope(self, request: web.Request, scopes: list) -> bool   # line 65 (unchanged — scopes only)
    async def authorize(self, request: web.Request)                  # line 102 — delegates to pdp.authorize (EvalContext.__init__)
    async def filter_resources(...)                                  # line 209; userinfo = session[AUTH_SESSION_OBJECT] 248;
                                                                     #   lightweight ctx via EvalContext.__new__ 255-261
class PEP(BaseHandler):                                              # line 304 (check() 418 merges groups/roles only — unchanged)

# EvalContext constructions covered by the __init__ overlay (do NOT edit these files):
# navigator_auth/abac/pdp.py:407, 531, 564, 631    navigator_auth/decorators.py:1076

# tests/test_mfa_e2e.py
FRESH_FACTORS = {"otp", "totp", "backup"}                            # line 93
def requires_fresh_factor(ctx) -> bool                               # line 123 — mfa and amr∩FRESH_FACTORS and no trusted_device
```

**Created by dependencies (verify they landed):** TASK-185 — generation validation in `_auth_middleware` and
`Oauth2Provider.authenticate` (the context must be published only AFTER it passes); TASK-186 — `mfa`/`amr` claims on
OAuth2 access tokens; `tests/test_mfa_review_fixes_oauth2_tokens.py` and its OAuth2 2FA app helpers.

### Does NOT Exist
- ~~`AUTH_BEARER_CONTEXT_KEY`~~, ~~`navigator_auth.abac.context.bearer_context_from_claims`~~,
  ~~`navigator_auth.abac.context.effective_userinfo`~~ — created by THIS task.
- ~~request-local OAuth bearer assurance~~ — absent today (spec §6 "Does NOT Exist").
- ~~a first-class `amr` key on `EvalContext`~~ — `amr` is read from `ctx.userinfo` (tests/test_mfa_e2e.py:126-133).
- ~~`navigator_auth/handlers/auth.py`~~ — does not exist; the bearer middleware is `navigator_auth/auth.py:1089`.
- ~~`requires_fresh_factor` in the `navigator_auth` package~~ — it is a test helper in `tests/test_mfa_e2e.py:123`.
- ~~a module-level `navigator_auth.conf` import in `abac/context.py`~~ — conf is imported lazily inside functions there
  (context.py:6-21); keep that pattern.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/conf.py", "action": "MODIFY"},
    {"path": "navigator_auth/auth.py", "action": "MODIFY"},
    {"path": "navigator_auth/backends/oauth2/backend.py", "action": "MODIFY"},
    {"path": "navigator_auth/abac/context.py", "action": "MODIFY"},
    {"path": "navigator_auth/abac/decorators.py", "action": "MODIFY"},
    {"path": "navigator_auth/abac/guardian.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_review_fixes_oauth2_tokens.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/conf.py#AUTH_MECHANISM_KEY",
    "sym:navigator_auth/conf.py#AUTH_MECHANISM_BEARER",
    "sym:navigator_auth/auth.py#AuthHandler._auth_middleware",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.authenticate",
    "sym:navigator_auth/backends/abstract.py#BaseAuthBackend._set_user_request",
    "sym:navigator_auth/abac/context.py#EvalContext",
    "sym:navigator_auth/abac/context.py#EvalContext.__init__",
    "sym:navigator_auth/abac/decorators.py#_get_userinfo",
    "sym:navigator_auth/abac/guardian.py#Guardian.get_user",
    "sym:navigator_auth/abac/guardian.py#Guardian.filter_resources",
    "sym:tests/test_mfa_e2e.py#requires_fresh_factor"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
```python
# context.py already resolves conf lazily (context.py:13-21) — do the same for the new constants:
def _bearer_keys() -> tuple[str, str, str]:
    from navigator_auth.conf import AUTH_BEARER_CONTEXT_KEY, AUTH_MECHANISM_KEY, AUTH_MECHANISM_BEARER  # noqa: PLC0415
    return AUTH_BEARER_CONTEXT_KEY, AUTH_MECHANISM_KEY, AUTH_MECHANISM_BEARER
```

### Key Constraints
- Publish the context **only after** the token passed decode (signature/expiry), `_token_is_revoked`, and TASK-185's
  generation check; never from unvalidated JWT data or client headers (spec M9 ABAC).
- The context is immutable (`MappingProxyType`, `amr` as a tuple) and lives on the request only — never write it into
  `session`, `AUTH_SESSION_OBJECT` or `request.user` (spec non-goal: no persisted token assurance).
- Strip `mfa`, `amr` and `auth_method` from session-derived userinfo for bearer requests **before** applying token
  claims; a bearer request without a published context gets no assurance at all. Cookie-only requests: unchanged.
- `effective_userinfo` returns a **new** dict; the session's `AUTH_SESSION_OBJECT` must be untouched (assert in tests).
- Known consequence: bearer tokens from backends whose JWT omits `auth_method` lose session-derived `auth_method`
  in ABAC (fail-closed for `auth_method` policies). Record it in the Completion Note; do not widen the overlay to
  keep session values.
- Google-style docstrings, type hints, module logger; never log token claims beyond user id.

### References in Codebase
- `navigator_auth/backends/basic.py:184` — `_JWT_EXTRA_KEYS = ("auth_method", "auth_origin", "external_expires_at", "mfa", "amr")`:
  BasicAuth JWTs already carry the same assurance as their session, so BasicAuth bearer behaviour is preserved.
- `tests/test_mfa_e2e.py:136-150` — `_evalctx_view` pattern for a test route exposing the built `EvalContext`.

---

## Implementation Blueprint

> **CRITICAL — Executor-ready starting point.** Write each block below to its declared
> path nearly verbatim, then complete every `# FILL IN:` marker. Blocks were derived
> from the spec's Interface Skeletons and re-verified against the Codebase Contract
> above when this task was written. This is NOT the full implementation:
> business-logic branches, edge cases and test bodies are `FILL IN` stubs by design.
> Never change a signature, class name, or file path the blueprint fixes.

### Steps (in order)
1. Add `AUTH_BEARER_CONTEXT_KEY` to conf.py — *why*: one request key shared by the middleware, the OAuth2 backend and ABAC.
2. Add the two helpers to `abac/context.py` and call `effective_userinfo` at the top of `EvalContext.__init__` — *why*:
   every PDP path builds its context through `__init__`, so one overlay covers pdp.py and navigator_auth/decorators.py.
3. Publish the context at the 3 bearer sites in `_auth_middleware` and in `Oauth2Provider.authenticate` — *why*: those
   are the only places that mark a request `AUTH_MECHANISM_BEARER` (grep verified).
4. Apply `effective_userinfo` in `_get_userinfo` and the two Guardian sites — *why*: they read session userinfo directly
   or build a context with `EvalContext.__new__`, bypassing `__init__`.
5. Write the AC27/AC29 tests; run the Validation Commands — *why*: prove grant for TOTP tokens, denial for trusted-device and
   password-only tokens, and isolation across mint order and session recreation.

### `navigator_auth/conf.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'AUTH_MECHANISM_DJANGO = "django"' navigator_auth/conf.py)
# AFTER — insert below `AUTH_MECHANISM_DJANGO = "django"` (verified: conf.py:112), the last AUTH_MECHANISM_* line.
# FEAT-106 review fixes (M9, D9): request key holding the immutable, request-local
# assurance (mfa/amr/auth_method) and identity of the VALIDATED bearer token. ABAC
# uses it instead of the identity-shared session for bearer requests.
AUTH_BEARER_CONTEXT_KEY = "auth_bearer_context"
```

### `navigator_auth/abac/context.py` (MODIFY) — helpers
```python
# occurrences: 1 (verified: grep -c 'class EvalContext(dict, MutableMapping):' navigator_auth/abac/context.py)
# BEFORE — insert above `class EvalContext(dict, MutableMapping):` (verified: context.py:82).
# Add `from collections.abc import Mapping` and `from types import MappingProxyType` to the imports at the top.
ASSURANCE_KEYS = ("mfa", "amr", "auth_method")


def bearer_context_from_claims(payload: Mapping[str, Any]) -> MappingProxyType:
    """Return the immutable request-local assurance of a VALIDATED bearer token.

    Args:
        payload: Decoded claims of a token that already passed signature, expiry,
            revocation and generation checks.

    Returns:
        A read-only mapping with ``user_id``, ``mfa`` (bool), ``amr`` (tuple or None)
        and ``auth_method`` (str or None). Missing claims mean "no fresh factor".
    """
    amr = payload.get("amr")
    return MappingProxyType(
        {
            "user_id": payload.get("user_id"),
            "mfa": bool(payload.get("mfa", False)),
            "amr": tuple(str(value) for value in amr) if isinstance(amr, (list, tuple)) and amr else None,
            "auth_method": payload.get("auth_method"),
        }
    )


def effective_userinfo(request: Any, userinfo: Any) -> Any:
    """Return the userinfo ABAC must evaluate for this request.

    Cookie-only and non-bearer requests: ``userinfo`` unchanged. Bearer requests: a NEW
    dict holding the session userinfo minus ``ASSURANCE_KEYS``, plus the token's own
    ``mfa``/``amr``/``auth_method`` from ``request[AUTH_BEARER_CONTEXT_KEY]``; a bearer
    request without a published context gets no assurance. Never mutates the session.
    """
    from navigator_auth.conf import (  # noqa: PLC0415 — lazy, like _load_tenant_conf
        AUTH_BEARER_CONTEXT_KEY,
        AUTH_MECHANISM_BEARER,
        AUTH_MECHANISM_KEY,
    )

    getter = getattr(request, "get", None)
    if getter is None:
        return userinfo
    context = getter(AUTH_BEARER_CONTEXT_KEY)
    if context is None and getter(AUTH_MECHANISM_KEY) != AUTH_MECHANISM_BEARER:
        return userinfo
    # FILL IN: copy `userinfo` into a new dict without ASSURANCE_KEYS (Mapping -> dict comprehension; a non-Mapping
    #   object -> dict of its public attributes; None -> {}) — bounded by "never mutate the session" and spec M9 ABAC.
    base: dict = {}
    if context is None:
        return base
    # FILL IN: if both context["user_id"] and base's user id are present and differ (str compare), return base
    #   without assurance — bounded by AC29 (never lend assurance across identities).
    if context["mfa"]:
        base["mfa"] = True
    if context["amr"] is not None:
        base["amr"] = list(context["amr"])
    if context["auth_method"]:
        base["auth_method"] = context["auth_method"]
    return base
```
**Why this shape**: D9 — assurance for bearer requests comes from the validated token only. Putting the overlay in
`context.py` (already imported by every ABAC module) keeps one implementation; the lazy conf import follows the
module's existing cycle-avoidance pattern.

### `navigator_auth/abac/context.py` (MODIFY) — `EvalContext.__init__`
```python
# occurrences: 1 (verified: grep -c '        self.store = {}' navigator_auth/abac/context.py)
# AFTER — insert below `        self.store = {}` (verified: context.py:101), the first statement of EvalContext.__init__.
        # FEAT-106 review fixes (M9, D9): bearer requests evaluate the validated token's
        # assurance, never the identity-shared session's.
        effective = effective_userinfo(request, userinfo)
        if user is userinfo and effective is not userinfo:
            user = effective  # PDP fallback passes userinfo as the user (pdp.py:405)
        userinfo = effective
```

### `navigator_auth/auth.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '    AUTH_MECHANISM_BEARER,' navigator_auth/auth.py)
# AFTER — insert below `    AUTH_MECHANISM_BEARER,` (verified: auth.py:44) inside `from .conf import (`.
    AUTH_BEARER_CONTEXT_KEY,
```
```python
# occurrences: 1 (verified: grep -c 'from .abac.middleware import abac_middleware' navigator_auth/auth.py)
# AFTER — insert below `from .abac.middleware import abac_middleware` (verified: auth.py:83).
from .abac.context import bearer_context_from_claims
```
```python
# occurrences: 3 (verified: grep -c 'request[AUTH_MECHANISM_KEY] = AUTH_MECHANISM_BEARER' navigator_auth/auth.py)
# FILL IN: disambiguate — insert the line below IMMEDIATELY AFTER each of the 3 occurrences, at that occurrence's
# indentation. Each is unique with this context:
#   (a) excluded-path branch (32-space indent, verified auth.py:1110-1112):
#         request.user = user
#         request["authenticated"] = True
#         request[AUTH_MECHANISM_KEY] = AUTH_MECHANISM_BEARER        <- after this
#       (only line with that indent: grep -c '                                request["authenticated"] = True' -> 1)
#   (b) session recreated from token (24-space indent, verified auth.py:1177-1180), the block that follows
#         self.logger.error(f"Error saving user in new session: {ex}")   (count 1, auth.py:1175)
#   (c) existing session (24-space indent, verified auth.py:1209-1212), the block that follows
#         reason="Unable to resolve user object from session or token payload.",   (count 1, auth.py:1207)
request[AUTH_BEARER_CONTEXT_KEY] = bearer_context_from_claims(payload)
```
**Why**: these are the only middleware lines that mark a request bearer-authenticated. After TASK-185 the generation check
precedes them, so the context is published only for fully validated tokens. Do not touch the cookie branch (1217-1231).

### `navigator_auth/backends/oauth2/backend.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '    AUTH_MECHANISM_BEARER,' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below `    AUTH_MECHANISM_BEARER,` (verified: backend.py:48) inside `from ...conf import (`.
    AUTH_BEARER_CONTEXT_KEY,
```
```python
# occurrences: 1 (verified: grep -c '        request["userdata"] = payload' navigator_auth/backends/oauth2/backend.py)
# AFTER — insert below `        request["userdata"] = payload` (verified: backend.py:2879) in Oauth2Provider.authenticate.
        from ...abac.context import bearer_context_from_claims  # noqa: PLC0415 — lazy: oauth2 must not import abac at load

        request[AUTH_BEARER_CONTEXT_KEY] = bearer_context_from_claims(payload)
```

### `navigator_auth/abac/decorators.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '    return session, userinfo' navigator_auth/abac/decorators.py)
# REPLACE — `    return session, userinfo` (verified: decorators.py:53) in _get_userinfo.
    return session, effective_userinfo(request, userinfo)
```
Change the import at decorators.py:18 to `from navigator_auth.abac.context import EvalContext, effective_userinfo`
(`occurrences: 1 (verified: grep -c 'from navigator_auth.abac.context import EvalContext' navigator_auth/abac/decorators.py)`).

### `navigator_auth/abac/guardian.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '                if isinstance(userinfo, dict) and userinfo:' navigator_auth/abac/guardian.py)
# BEFORE — insert above that line (verified: guardian.py:55) in Guardian.get_user (fallback branch, 16-space indent).
                userinfo = effective_userinfo(request, userinfo)
```
```python
# occurrences: 2 (verified: grep -c 'userinfo = session[AUTH_SESSION_OBJECT]' navigator_auth/abac/guardian.py)
# FILL IN: disambiguate — use the filter_resources occurrence (verified guardian.py:245-250), unique with context:
#         # Extract userinfo from session          (count 1, guardian.py:245)
#         try:
#             from navigator_auth.conf import AUTH_SESSION_OBJECT
#             userinfo = session[AUTH_SESSION_OBJECT]
#         except (KeyError, TypeError):
#             userinfo = {}
# AFTER that try/except (8-space indent), insert:
        userinfo = effective_userinfo(request, userinfo)
```
Change the import at guardian.py:10 to `from .context import EvalContext, effective_userinfo`
(`occurrences: 1 (verified: grep -c 'from .context import EvalContext' navigator_auth/abac/guardian.py)`).

### `tests/test_mfa_review_fixes_oauth2_tokens.py` (MODIFY)
```python
# APPEND. Reuse this module's OAuth2 2FA app/login helpers (TASK-185/186).
from types import MappingProxyType

from navigator_auth.abac.context import EvalContext, bearer_context_from_claims, effective_userinfo
from navigator_auth.conf import AUTH_BEARER_CONTEXT_KEY, AUTH_MECHANISM_BEARER, AUTH_MECHANISM_COOKIE, AUTH_MECHANISM_KEY
from tests.test_mfa_e2e import requires_fresh_factor


def test_bearer_context_is_immutable_and_strips_session_assurance():
    """Unit: the overlay drops session mfa/amr/auth_method and never mutates the session dict."""
    session_userinfo = {"user_id": 7, "groups": ["g"], "mfa": True, "amr": ["pwd", "totp"], "auth_method": "basic"}
    request = {AUTH_MECHANISM_KEY: AUTH_MECHANISM_BEARER,
               AUTH_BEARER_CONTEXT_KEY: bearer_context_from_claims({"user_id": 7})}
    result = effective_userinfo(request, session_userinfo)
    assert "mfa" not in result and "amr" not in result and result["groups"] == ["g"]
    assert session_userinfo["mfa"] is True
    assert isinstance(request[AUTH_BEARER_CONTEXT_KEY], MappingProxyType)
    # FILL IN: cookie request -> unchanged object; bearer without context -> no assurance.


@pytest.mark.asyncio
async def test_abac_fresh_factor_grants_mfa_oauth2_token():
    """AC27: TOTP-login OAuth2 token -> requires_fresh_factor True; trusted-device and no-MFA tokens -> False."""
    # FILL IN: mint the three tokens via the OAuth2 2FA flow; call a test route that builds EvalContext like the PDP
    #   (pattern: tests/test_mfa_e2e.py::_evalctx_view) with each bearer token.


@pytest.mark.asyncio
async def test_oauth_assurance_isolation():
    """AC29: a password-only / trusted-device token stays denied after a later TOTP login and token mint for the same
    user, in either mint order and after session recreation; the TOTP token stays granted."""
    # FILL IN: include deleting the Redis session so _auth_middleware recreates it from the token.
```

### FILL IN checklist
- [ ] `context.py::effective_userinfo` — userinfo copy for Mapping / object / None; bounded by "never mutate the session".
- [ ] `context.py::effective_userinfo` — identity mismatch drops assurance; bounded by AC29.
- [ ] `auth.py` — insert at all 3 bearer sites (disambiguated above); bounded by spec M9 "after … generation validation".
- [ ] `guardian.py` — filter_resources occurrence; bounded by the quoted context.
- [ ] Tests — AC27, AC29 bodies plus the unit cases.

---

## Acceptance Criteria

- [ ] **AC27**: with the FEAT-106 policy pack and `requires_fresh_factor`, a request bearing an OAuth2 access token from a TOTP-verified login is granted; tokens from a trusted-device login and from a no-MFA login are denied.
- [ ] **AC29**: a password-only or trusted-device OAuth token stays denied by fresh-factor ABAC after a later TOTP login and token mint for the same user, in either mint order and after session recreation; the TOTP token stays granted.
- [ ] Cookie-only requests evaluate exactly as before (`tests/test_auth_middleware_mechanism.py` green).
- [ ] The shared session's `AUTH_SESSION_OBJECT` is never modified by ABAC evaluation.
- [ ] `navigator_auth/abac/pdp.py` and `navigator_auth/decorators.py` are not edited.
- [ ] No linting errors (`ruff check navigator_auth/abac navigator_auth/auth.py`).

## Validation Commands

- `pytest tests/test_mfa_review_fixes_oauth2_tokens.py -q`
- `pytest tests/test_auth_middleware_mechanism.py -q`
- `pytest tests/test_mfa_policy_pack.py -q`
- `pytest tests/test_mfa_e2e.py -q`
- `pytest tests/test_scope_abac.py -q`

---

## Test Specification

```python
# Minimum cases (in tests/test_mfa_review_fixes_oauth2_tokens.py):
# 1. bearer + context(mfa, amr=[pwd,totp])        -> EvalContext.mfa True, requires_fresh_factor True
# 2. bearer + context(mfa, amr=[pwd,trusted_device]) -> requires_fresh_factor False
# 3. bearer + context(no claims) over a session that says mfa=True -> mfa False (no borrowing)
# 4. bearer + NO context                          -> no assurance
# 5. cookie mechanism                              -> userinfo object returned unchanged
# 6. session dict identity/contents unchanged after every case
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the stacked feature worktree** `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa-review-fixes` (branch
   `feat-FEAT-106-basicauth-otp-2fa-review-fixes`, stacked on `feat-FEAT-106-basicauth-otp-2fa`; ships in PR #633) — never on `dev`.
2. **Read the spec** at the path listed above (§3 Module 9 "ABAC", D9, AC27, AC29).
3. **Check dependencies** — TASK-186 must be `"done"` in `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json`.
4. **Verify the Codebase Contract** — re-run every `grep -c`; TASK-185/186 moved lines in `auth.py`/`backend.py`.
5. **Update status** in the index → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** from the Implementation Blueprint; complete every `# FILL IN:`.
7. **Verify** — run the Validation Commands.
8. **Commit the code** — stage only the files listed above.
9. **Close the task** with `parrot sdd task close TASK-187 basicauth-otp-2fa-review-fixes verified`.
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

Implemented by native sonnet; orchestrator ran the 5 validation modules (12/7/5/21/40 passed), committed and merged. Merge-tier: 143 passed, 1 baseline red (google e2e), gate pass. Coder deviation: no real end-to-end OAuth token-minting test (unit-level with fake request); `_fresh_factor` re-implemented locally in tests. Bearer JWT without `auth_method` loses session auth_method in ABAC (deliberate, fail-closed). Closed via `parrot sdd task close`.
