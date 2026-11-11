---
# SDD flow type and base branch (FEAT-145).
type: feature
base_branch: dev
projects: [oauth2, backends, decorators, examples]
tags: [oauth2, 3lo, pkce, session-binding, is-authenticated, examples]
docs:
  policy: required
  pages: []
  api_modules: [navigator_auth.decorators, navigator_auth.backends.api, navigator_auth.backends.oauth2.backend]
---

# Feature Specification: OAuth2 3LO examples work end-to-end — auth paths fail closed on misconfiguration and unknown users

**Feature ID**: FEAT-108
**Date**: 2026-11-11
**Author**: Jesus Lara
**Status**: draft
**Target version**: 0.30.0
**Proposal**: `sdd/proposals/oauth2-3lo-issues.proposal.md` (research state `sdd/state/FEAT-108/`)
**Merge after**: FEAT-106 (PR #633, including the `basicauth-otp-2fa-review-fixes` modules) — see Worktree Strategy

---

## 1. Motivation & Business Requirements

### Problem Statement

Running the two OAuth2 examples produced seven failures (proposal §0):

| # | Symptom | Root cause (proposal evidence) |
|---|---|---|
| S1 | `GET /api/v1/me` with a valid 3LO bearer → **500** `TypeError: 'bool' object is not subscriptable` (`api.py:154`) | `@is_authenticated()` tries every backend; `APIKeyAuth.authenticate` indexes the `False` that `check_token_info` returns for a JWT without `device_id` (F005, F006) |
| S2 | `GET /api/v1/me` without credentials → **200** "Hello Anonymous …" instead of 401 | `NoAuth.authenticate` returns a truthy guest result and the loop accepts the first truthy result (F005, F007) |
| S3 | "List my grants" → **401** "Not authenticated." for a valid bearer | the `allow_hosts` exempt branch of `AuthHandler._auth_middleware` never sets `request["userdata"]`, and the token has no bound session (F004, F008) |
| S4 | `/oauth2/userinfo` → `{"sub":"35","username":"",…}` | `user_from_id(35)` fails; every profile claim defaults to `""` (F008) |
| S5 | `cannot bind a session to the token for user_id=35` on every code and refresh grant | `/oauth2/authorize` took the resource owner from an existing browser session the demo IdP cannot resolve; `_token_session_claims` swallows the failure and still issues a session-less token (F001, F002) |
| S6 | Backends the example never asked for (Azure, ADFS, TrocToken, NoAuth, APIKeyAuth) run; HMAC key is 6 bytes | `examples/oauth2_3lo_server.py` builds `AuthHandler(enable_authdb=False)` without `backends=`/`authz_backends=`, so the developer's `settings/settings.py` (star-imported last by `conf.py`) and `env/.env` decide the configuration (F003, F011). `examples/oauth2_server.py:55` has the same defect (`AuthHandler()`). |
| S7 | `examples/oauth2_server.py` 3LO walk-through → `invalid_grant: code_verifier required.` | the provider correctly enforces RFC 7636, but `oauth2_index.html` / `callback.html` never generate, store or send a PKCE pair and the startup hint prints a `<S256_hash>` placeholder (F017) |

S6 and S7 are example bugs. S1–S5 expose four library defects that are not recent regressions and have no tests (F009, F013):
fixing only the examples would turn the 500 into a 401 and hide them again.

### Goals
- **G1** — Both OAuth2 examples run with exactly the backends they declare (`Oauth2Provider`) and no authorization backends, regardless of the developer's `settings/settings.py` / `env/.env`. `oauth2_3lo_server.py` warns at startup when the effective `AUTH_SECRET_KEY` is shorter than 32 bytes.
- **G2** — The `examples/oauth2_server.py` browser walk-through completes the authorization-code + PKCE (S256) flow: the index page generates the pair and a random `state`, the callback page checks `state` and sends the verifier.
- **G3** — `APIKeyAuth` declines (returns `None` / `False`) a bearer that is not an API key instead of raising.
- **G4** — `@is_authenticated()` (function and method wrappers) never authenticates a request through an anonymous backend, and a backend's unexpected (non-`AuthException`) error is logged and skipped instead of turning the request into a 500. Anonymous access stays available only through the exclude list and `request.allow_anonymous`.
- **G5** — When the `allow_hosts`/`allowed_ips` exempt branch of `AuthHandler._auth_middleware` resolves a bearer, it publishes the decoded claims as `request["userdata"]`, as the main path does.
- **G6** — The OAuth2 provider never issues a code or token for a resource owner its IdP cannot resolve or that is disabled: `/oauth2/authorize`, the consent POST and device verification re-check the session user; the authorization-code and refresh grants answer `invalid_grant` instead of minting a session-less token.
- **G7** — `/oauth2/userinfo` omits the profile claims it cannot supply instead of returning empty strings.
- **G8** — Every fix has a regression test, and an app-level test drives the fixed 3LO example and asserts the outcomes of its six buttons.

### Non-Goals (explicitly out of scope)
- Changing the developer's `env/.env` or `settings/settings.py`, or the precedence rules in `navigator_auth/conf.py`; the examples opt out through existing `AuthHandler` arguments instead.
- The TrocToken and TokenAuth middlewares: they only pass the 3LO bearer through (F011).
- The same "first truthy backend wins" loop in `AuthHandler.api_login` (wiki lesson `mem-b8bff584423d`): a separate change.
- `navigator_session` (wheel install, cannot be patched in-repo).
- Making the `is_authenticated` loop dispatch on the request's auth mechanism instead of trying each backend (proposal §6 alternative; not chosen).
- The existing `logout` defect at `backend.py:2263` (`await session.invalidate(request)` on a sync, argument-less method; the `TypeError` is swallowed): recorded in §7 as a follow-up.
- Refactoring `examples/static/oauth2_3lo_app.html`; it is the PKCE reference and stays untouched.
- Anything FEAT-106 owns: `mfa`/`amr` propagation, `MfaSignal`, the second-factor login route.

---

## Governing Decisions

<!-- GENERATED by `parrot sdd spec consequences <spec> --render` — do not edit by hand. -->

---

## 2. Architectural Design

### Overview

Seven independent fixes in three layers. No new public API, no configuration flag, no data model change.

**Examples (G1, G2).** Both examples pass `backends=[…Oauth2Provider]` and `authz_backends=[]` to
`AuthHandler`, the documented way to make an application's backend list independent of
`settings.settings` (`auth.py:116-126` docstring; pattern `examples/identity_vault_server.py:722`).
`oauth2_3lo_server.py` logs a warning at startup when `navigator_auth.conf.SECRET_KEY` is under 32
bytes (the 6-byte key in the report comes from `env/.env`, which the example cannot override,
because `conf` binds `SECRET_KEY` at import). The `oauth2_server.py` pages do PKCE in the browser
with the same technique as `oauth2_3lo_app.html` (`crypto.subtle` S256, verifier and `state` in
`sessionStorage`), inlined in each page. The startup hint points at the page instead of printing a
`<S256_hash>` placeholder.

**Request authentication (G3, G4, G5).**
- `APIKeyAuth.authenticate` gets the `if not data` guard that `check_credentials` already has, and
  `check_token_info` returns `False` for an empty payload instead of raising `TypeError`.
- Both `@is_authenticated()` wrappers delegate to one new private helper,
  `_authenticate_with_backends(auth, request)`, so the two loops cannot drift again. The helper:
  - skips any backend whose class sets `_anonymous_auth = True` **before** calling it, so NoAuth
    never runs and never creates a guest session for an unauthenticated caller;
  - keeps FEAT-106's `except MfaSignal: break`;
  - keeps `except AuthException: continue`;
  - adds `except Exception: logger.exception(…); continue`;
  - returns the first truthy, non-redirect result.
- The `allow_hosts` exempt branch of `_auth_middleware` sets `request["userdata"] = payload` next to
  `request.user`, exactly as the main path does at `auth.py:1139-1142`.

**OAuth2 provider (G6, G7).** A new private
`Oauth2Provider._resolve_resource_owner(user_id)` resolves the user through `self._idp.user_from_id`
and enforces `user_is_active`. It raises `UserNotFound` (unknown user, or `ValidationError`) or
`FailedAuth` (disabled). It is called:
- **`authorize`**, right after the session check. On failure the browser is redirected to
  `nav_oauth2_login` with the full authorization request, the same redirect used today when there
  is no session. The shared session is **not** invalidated (decision D3).
- **The consent POST.** On failure it answers 401 `access_denied` and issues no code.
- **`device_verification`.** On failure it redirects to login with `device_user_code` and does not
  approve the device code.
- **`_token_session_claims`**, which no longer swallows the failure. The code grant turns the
  exception into `invalid_grant`; the code is already consumed. The refresh grant also revokes the
  presented refresh token's chain.

`_token_session_claims` still returns `{}` when the session itself cannot be created (storage
unavailable): that is an infrastructure state, not an unknown owner.
`userinfo` sets a profile/email claim only when it has a non-empty value.

### Decisions taken in this spec

| ID | Decision | Rationale |
|---|---|---|
| D1 | Anonymous backends are recognised by a class flag `_anonymous_auth: bool` (False on `BaseAuthBackend`, True on `NoAuth`) checked **before** `authenticate()` | `request.user.is_authenticated` is unusable: `BaseAuthBackend.remember()` sets it to True (`abstract.py:300`). Inspecting the result after the call would leave NoAuth's guest session behind. `_service_name == "anonymous"` is overridden by tests. The flag follows the `_external_auth` precedent (`abstract.py:79`, read at `auth.py:358`). |
| D2 | Unexpected backend errors are logged with `logger.exception` and the loop continues; 401 if nothing succeeds | User decision (spec Q&A). Safe because anonymous backends are skipped (D1), so continuing can only reach a backend that authenticates a real credential. |
| D3 | An unknown/disabled session owner at `/oauth2/authorize` triggers the login redirect **without invalidating the session** | Sessions live in the shared Redis store keyed by cookie. Invalidating one created by another Navigator app on the same host would log the user out of that app. `auth_login` already replaces this browser's session and cookie through `_create_user_session` (`backend.py:632`). This refines the proposal's "drop it": the session is dropped *for this authorization*, not destroyed. |
| D4 | `is_active` is enforced together with existence in `_resolve_resource_owner` | Today it is checked only in `auth_login` (`backend.py:1644`), so a user disabled after login keeps getting codes and tokens through the session cookie. This is the same fail-closed rule as G6. |
| D5 | `device_verification` gets the same owner check | Third consumer of the session user (`backend.py:2685-2697`); an approved device code yields tokens for that `user_id`. |
| D6 | The refresh grant revokes the presented token's chain when the owner cannot be resolved | Failing at `backend.py:2046` happens before rotation (`:2080`/`:2094`), so the old refresh token would stay live. `revoke_chain` is already used at `:2005`/`:2015`. |
| D7 | Error texts: `invalid_grant` / "The resource owner of this grant cannot be resolved." (token grants); `access_denied` / "Unknown or disabled resource owner." (consent, 401) | Matches the existing `_error_response` vocabulary; reveals no account detail. |

### Component Diagram
```
browser ──/oauth2/authorize──→ Oauth2Provider.authorize ──→ _resolve_resource_owner ──→ self._idp.user_from_id
   │                                   │ unknown/disabled → 302 nav_oauth2_login (session kept)
   │──/oauth2/token (code|refresh)──→ _handle_* ──→ _token_session_claims ──→ _resolve_resource_owner
   │                                   │ UserNotFound/FailedAuth → 400 invalid_grant (+ revoke_chain on refresh)
   │──/api/v1/me (Bearer)──→ AuthHandler._auth_middleware ─┬─ main path: userdata + user (unchanged)
   │                                                        └─ allow_hosts exempt: + request["userdata"]  (G5)
   │                                   └──→ @is_authenticated ──→ _authenticate_with_backends
   │                                            skip _anonymous_auth · MfaSignal→stop · AuthException→next
   │                                            other Exception→log+next · none→401
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `AuthHandler.__init__(…, backends=, authz_backends=)` | uses | Examples pin their configuration (`auth.py:95-103`, `:132`, `:158-160`) |
| `BaseAuthBackend` | extends (class attribute) | New `_anonymous_auth: bool = False` next to `_external_auth` (`abstract.py:79`) |
| `NoAuth` | modifies (class attribute) | `_anonymous_auth: bool = True` (`noauth.py:28`) |
| `is_authenticated` | modifies | Both wrappers call the new helper (`decorators.py:215-229`, `:259-270`) |
| `APIKeyAuth` | modifies | Guards in `authenticate` (`api.py:152-154`) and `check_token_info` (`api.py:185`) |
| `AuthHandler._auth_middleware` | modifies | Exempt branch publishes `userdata` (`auth.py:1072-1074`) |
| `Oauth2Provider` | modifies | New `_resolve_resource_owner`; `authorize`, `consent`, `device_verification`, `_token_session_claims`, both grants, `userinfo` |
| `RefreshTokenStorage.revoke_chain` | uses | `code_backend.py:194`, already called at `backend.py:2005`/`:2015` |
| FEAT-106 `MfaSignal` | preserves | `except MfaSignal: break` stays first in the backend loop |

### Data Models
No new or changed data model.

### New Public Interfaces
None. Everything new is private (`_`-prefixed) or example code. Two **public behaviour changes** are documented in `CHANGELOG.md` (§10):
1. `@is_authenticated()` no longer admits a request through `NoAuth`; anonymous routes must use the exclude list or `allow_anonymous`.
2. The OAuth2 token endpoint answers `invalid_grant` instead of issuing a session-less token when the resource owner cannot be resolved.

---

## 3. Module Breakdown

#### Delegation-eligible modules

| Module | Eligible? | Decided patterns / exact contracts | Why not (if no) |
|---|---|---|---|
| M1: 3LO example wiring | yes | `AuthHandler(backends=_BACKENDS, authz_backends=[], enable_authdb=False)`; `_warn_on_short_secret()` at startup; README warning mirrored from `examples/README.md:141-148` | — |
| M2: oauth2_server.py PKCE walk-through | yes | Inline JS copied from `oauth2_3lo_app.html:172-188, 200-238`; `sessionStorage` key `nav_oauth2_index_pkce`; state check; pinned `AuthHandler` | — |
| M3: APIKeyAuth declines non-API-key bearers | yes | `if not data: return None` after `api.py:152`; `if not payload: return False` at top of `check_token_info` | — |
| M4: is_authenticated backend loop | yes | Skeleton below; D1, D2; MfaSignal order | — |
| M5: exempt branch publishes userdata | yes | one line mirroring `auth.py:1140` | — |
| M6: OAuth2 unknown resource owner fails closed | yes | Skeleton below; D3–D7; exact call sites | — |
| M7: userinfo omits unknown claims | yes | set a claim only when value not in `(None, "")` | — |
| M8: app-level 3LO example test | no | — | Fixture design (load the example via `importlib`, Redis-backed sessions, drive login + consent forms through `TestClient`) needs judgement |

### Module 1: 3LO example wiring
- **Path**: `examples/oauth2_3lo_server.py`, `examples/README.md` (3LO section)
- **Responsibility**: The example runs exactly `Oauth2Provider` with no authorization backends, whatever the local settings say, and warns about a short secret key. README explains why (mirrors the identity-vault warning).
- **Depends on**: existing `AuthHandler` arguments only.
- **Interface Skeleton**:
  ```python
  # examples/oauth2_3lo_server.py  (modifies examples/oauth2_3lo_server.py:46-54, :218)
  #: Passed to AuthHandler(backends=...) — NOT only exported as AUTHENTICATION_BACKENDS,
  #: because navigator_auth.conf ends with ``from settings.settings import *`` (conf.py:944).
  _BACKENDS: list[str] = ["navigator_auth.backends.oauth2.Oauth2Provider"]

  def _warn_on_short_secret() -> None:
      """Log a warning when navigator_auth.conf.SECRET_KEY is shorter than 32 bytes.

      The key comes from navconfig (env/.env wins over os.environ.setdefault), so the
      example cannot override it; it tells the operator which variable to fix.
      """

  def make_app() -> web.Application:   # verified: examples/oauth2_3lo_server.py:214
      """... auth = AuthHandler(backends=_BACKENDS, authz_backends=[], enable_authdb=False) ..."""
  ```

### Module 2: oauth2_server.py PKCE walk-through
- **Path**: `examples/oauth2_server.py`, `examples/static/oauth2_index.html`, `examples/static/callback.html`, `examples/README.md` (oauth2_server section)
- **Responsibility**:
  - pin the backends (same defect as M1, at `oauth2_server.py:55`);
  - the index page generates verifier, S256 challenge and a random `state`, stores them, and starts `/oauth2/authorize` with `code_challenge` + `code_challenge_method=S256`;
  - the callback page checks `state` against the stored value, then posts `code_verifier`;
  - the startup hint points at `http://localhost:5000/login`.
- **Depends on**: none.
- **Interface Skeleton**:
  ```python
  # examples/oauth2_server.py  (modifies :55, :172-182)
  auth = AuthHandler(
      backends=["navigator_auth.backends.oauth2.Oauth2Provider"], authz_backends=[]
  )  # was: AuthHandler()  — verified: examples/oauth2_server.py:55
  # 3LO hint: "open http://localhost:5000/login and press Authorize — the page
  # generates the PKCE pair"; the raw-URL form explains code_challenge =
  # BASE64URL(SHA256(code_verifier)) instead of printing <S256_hash>.
  ```
  ```js
  // examples/static/oauth2_index.html  (replaces the static link at :53-54 and the
  // "without PKCE" note at :48-52). Helpers copied from oauth2_3lo_app.html:172-184.
  const STORE = 'nav_oauth2_index_pkce';
  function b64url(bytes) {}               // same body as oauth2_3lo_app.html:172
  function randomString(size = 32) {}     // oauth2_3lo_app.html:177
  async function s256(verifier) {}        // oauth2_3lo_app.html:181
  async function startAuthorize() {}      // save {verifier, state}; redirect with code_challenge, S256, state

  // examples/static/callback.html  (modifies exchangeToken at :30)
  async function exchangeToken() {}       // load STORE; state mismatch → abort with a message;
                                          // POST adds code_verifier; clear STORE after success
  ```

### Module 3: APIKeyAuth declines non-API-key bearers
- **Path**: `navigator_auth/backends/api.py`
- **Responsibility**: A bearer that is not an API key (no `device_id`, empty payload) makes `authenticate` return `None` and `check_token_info` return `False`, never raise.
- **Depends on**: none.
- **Interface Skeleton**:
  ```python
  # navigator_auth/backends/api.py
  class APIKeyAuth(BaseAuthBackend):                       # verified: api.py:38
      async def check_token_info(self, request, payload):  # verified: api.py:185
          """... Returns False when payload is empty (None/{}), as for a missing key."""
      async def authenticate(self, request):               # verified: api.py:143
          """... Returns None when get_token_info yields nothing usable (not an API key),
          mirroring check_credentials (api.py:217-219). InvalidAuth for a dict missing
          attributes is unchanged."""
  ```

### Module 4: is_authenticated backend loop
- **Path**: `navigator_auth/decorators.py`, `navigator_auth/backends/abstract.py`, `navigator_auth/backends/noauth.py`
- **Responsibility**: One helper drives the backend loop for both wrappers (D1, D2), preserving FEAT-106's `MfaSignal` stop.
- **Depends on**: FEAT-106 merged (`MfaSignal` import in `decorators.py`).
- **Interface Skeleton**:
  ```python
  # navigator_auth/backends/abstract.py  (modifies abstract.py:79)
  class BaseAuthBackend(ABC):                     # verified: abstract.py:64
      _external_auth: bool = False                # verified: abstract.py:79
      #: True for backends that authenticate *anyone* (a guest). @is_authenticated never
      #: calls them; anonymous access goes through the exclude list / allow_anonymous.
      _anonymous_auth: bool = False

  # navigator_auth/backends/noauth.py  (modifies noauth.py:28)
  class NoAuth(BaseAuthBackend):                  # verified: noauth.py:21
      _service_name: str = "anonymous"            # verified: noauth.py:28
      _anonymous_auth: bool = True

  # navigator_auth/decorators.py  (new private helper; both wrappers call it at :215 / :259)
  async def _authenticate_with_backends(auth: Any, request: web.Request) -> Optional[Any]:
      """Try each configured backend in order (FEAT-108).

      - backend with ``_anonymous_auth`` → skipped, never called;
      - ``MfaSignal`` (FEAT-106) → stop, return None;
      - other ``AuthException`` → next backend;
      - any other exception → ``logger.exception`` (backend name, no credential) → next backend;
      - falsy result or ``web.StreamResponse`` (IdP redirect) → next backend;
      returns the first remaining truthy result, else None (the wrappers then raise the
      existing 401 at decorators.py:234-240 / :275-281).
      """
  ```

### Module 5: Exempt branch publishes the token claims
- **Path**: `navigator_auth/auth.py`
- **Responsibility**: In `_auth_middleware`'s `verify_exceptions` branch, a resolved bearer also sets `request["userdata"] = payload`.
- **Depends on**: none.
- **Interface Skeleton**:
  ```python
  # navigator_auth/auth.py  (modifies the exempt branch, auth.py:1070-1074)
  # if user:
  #     request.user = user                       # verified: auth.py:1072
  #     request["userdata"] = payload             # NEW — mirrors auth.py:1140 / :1172
  #     request["authenticated"] = True           # verified: auth.py:1073
  #     request[AUTH_MECHANISM_KEY] = AUTH_MECHANISM_BEARER   # verified: auth.py:1074
  ```

### Module 6: OAuth2 provider fails closed on an unknown resource owner
- **Path**: `navigator_auth/backends/oauth2/backend.py`, `tests/test_oauth2_3lo_session_binding.py`
- **Responsibility**: D3–D7. One resolver; four call paths; the two token grants answer `invalid_grant`.
- **Depends on**: FEAT-106 merged (`_token_session_claims` gains `extra=` in its M9).
- **Interface Skeleton**:
  ```python
  # navigator_auth/backends/oauth2/backend.py
  class Oauth2Provider(BaseAuthBackend):                      # verified: backend.py:258
      async def _resolve_resource_owner(self, user_id: Any) -> Any:
          """Return the IdP user for ``user_id`` (FEAT-108).

          Raises UserNotFound when self._idp.user_from_id raises UserNotFound or
          datamodel ValidationError; FailedAuth when user_is_active(user) is False
          (user_is_active verified: abstract.py:43, imported backend.py:108).
          """

      async def _token_session_claims(
          self, request: web.Request, user_id: int, extra: Optional[dict] = None
      ) -> dict:                                              # verified: backend.py:688 (extra= added by FEAT-106 M9)
          """... Raises UserNotFound / FailedAuth from _resolve_resource_owner (no longer
          swallowed). Still returns {} when the session cannot be created (unchanged)."""

      def _redirect_to_login(self, request: web.Request, data: dict) -> NoReturn:
          """Raise HTTPFound to nav_oauth2_login carrying the authorization request — the
          block now inlined at backend.py:1425-1428 (sync, like self.redirect at :489),
          extracted so the no-session and unknown-owner paths share it."""

      # authorize (backend.py:1343): after `session = await self.check_session(request)` (:1423),
      #   decode the owner and call _resolve_resource_owner; on None/UserNotFound/FailedAuth →
      #   _redirect_to_login(request, data). No session invalidation (D3).
      # consent POST (backend.py:1516): after the `user_obj` checks (:1541-1545) →
      #   on UserNotFound/FailedAuth return _error_response("access_denied",
      #   "Unknown or disabled resource owner.", status=401).
      # device_verification (backend.py:2604): after `user_obj` (:2695-2697) → on failure the
      #   same login redirect as its no-session branch (:2688-2692, with device_user_code).
      # _handle_authorization_code (backend.py:1743): compute the session claims before
      #   token_data (:1829); UserNotFound/FailedAuth → _error_response("invalid_grant",
      #   "The resource owner of this grant cannot be resolved.").
      # _handle_refresh_token (backend.py:1973): same at :2046, plus
      #   await self.refresh_token_storage.revoke_chain(refresh_token) before returning (D6).
  ```

### Module 7: userinfo omits claims it cannot supply
- **Path**: `navigator_auth/backends/oauth2/backend.py`, `tests/test_oauth2_userinfo_logout.py`
- **Responsibility**: `username`, `given_name`, `family_name` and `email` are set only when a non-empty value exists (token payload first, then the IdP user). Scope gating is unchanged, and so is FEAT-106's `amr` echo.
- **Depends on**: none (shares `backend.py` with M6 → serialized).
- **Interface Skeleton**:
  ```python
  # navigator_auth/backends/oauth2/backend.py — userinfo (verified: backend.py:2194)
  #   claims["username"] = str(_claim("username"))      # verified: backend.py:2246 → set only if non-empty
  #   claims["email"] = str(_claim("email"))            # verified: backend.py:2250 → set only if non-empty
  # tests/test_oauth2_userinfo_logout.py::TestUserinfoClaims._build_claims (verified: :53)
  #   mirrors the old logic → update it to the new rule (or replace it with a handler-level test).
  ```

### Module 8: App-level 3LO example test
- **Path**: `tests/test_oauth2_3lo_example.py` (new)
- **Responsibility**: Load `examples/oauth2_3lo_server.py` with `importlib.util.spec_from_file_location`. Assert its backend wiring. Drive the 3LO flow with `aiohttp` `TestClient`: login form → authorize/consent → code → token (PKCE) → `/api/v1/me` with and without bearer, grants, userinfo.
- **Depends on**: M1, M4, M5, M6 (asserts their combined behaviour).
- **Interface Skeleton**:
  ```python
  # tests/test_oauth2_3lo_example.py  (new)
  def _load_example() -> ModuleType:
      """Import examples/oauth2_3lo_server.py by path (no package); its os.environ.setdefault
      side effects are expected. Secrets used in the test are >= 32 bytes (filterwarnings=error)."""
  @pytest_asyncio.fixture
  async def example_client() -> TestClient: ...
  ```

---

## 4. Test Specification

### Unit Tests
| Test | Module | Description |
|---|---|---|
| `test_example_pins_oauth2_backend_only` | M1 | `make_app()` → `set(app["auth"].backends) == {"Oauth2Provider"}` and no authorization backends, while `settings/settings.py` lists 8 (skip if absent) |
| `test_example_warns_on_short_secret` / `..._quiet_on_long_secret` | M1 | `_warn_on_short_secret()` logs a warning naming `AUTH_SECRET_KEY` for a < 32-byte key, nothing for ≥ 32 |
| `test_index_page_sends_pkce_challenge` | M2 | `oauth2_index.html` contains `code_challenge_method` / `crypto.subtle` and no static `/oauth2/authorize?` link without a challenge (content assertions) |
| `test_callback_page_sends_verifier_and_checks_state` | M2 | `callback.html` posts `code_verifier` and compares `state` (content assertions) |
| `test_oauth2_server_pins_backends` | M2 | `oauth2_server.py` source builds `AuthHandler(backends=[…Oauth2Provider], authz_backends=[])` (AST/source check; the module runs at import) |
| `test_authenticate_declines_non_apikey_bearer` | M3 | `get_payload` → `["bearer", "jwt"]`, `get_token_info` → `False` / `None` / `{}` ⇒ `authenticate` returns `None` |
| `test_authenticate_missing_attributes_still_invalid` | M3 | dict without `device_id` ⇒ `InvalidAuth` (unchanged) |
| `test_check_token_info_empty_payload` | M3 | `check_token_info(request, None)` ⇒ `False` |
| `test_anonymous_backend_is_never_called` | M4 | backend with `_anonymous_auth=True` and an `AsyncMock.authenticate` ⇒ not awaited; request without credentials ⇒ 401 |
| `test_noauth_class_flag` | M4 | `NoAuth._anonymous_auth is True`, `BaseAuthBackend._anonymous_auth is False` |
| `test_unexpected_error_is_logged_and_skipped` | M4 | first backend raises `TypeError`, second returns a dict ⇒ handler runs, `logger.exception` called once |
| `test_unexpected_error_only_backend_gives_401` | M4 | the only backend raises `TypeError` ⇒ `HTTPUnauthorized`, never 500 |
| `test_mfa_signal_still_stops_the_loop` | M4 | first backend raises `MfaSignal`, second would succeed ⇒ 401, second not awaited |
| `test_method_wrapper_same_semantics` | M4 | the three cases above on a class-based `web.View` |
| `test_exempt_branch_publishes_userdata` | M5 | `verify_exceptions` → True, bearer resolves a session user ⇒ `request["userdata"] == payload`, plus `user`, `authenticated` and the mechanism |
| `test_exempt_branch_invalid_token_unchanged` | M5 | invalid bearer ⇒ handler runs unauthenticated, no `userdata` |
| `test_resolve_resource_owner_*` | M6 | found & active ⇒ user; `UserNotFound` / `ValidationError` ⇒ `UserNotFound`; inactive ⇒ `FailedAuth` |
| `test_authorize_unknown_owner_redirects_to_login` | M6 | session user unresolvable ⇒ `HTTPFound` to `nav_oauth2_login` whose query keeps `client_id`, `redirect_uri`, `state`, `code_challenge`; no code issued; storage `invalidate` not called |
| `test_authorize_disabled_owner_redirects_to_login` | M6 | `is_active=False` ⇒ same |
| `test_consent_unknown_owner_401` | M6 | consent POST approve ⇒ 401 `access_denied`, `code_storage` empty |
| `test_device_verification_unknown_owner_redirects` | M6 | ⇒ login redirect with `device_user_code`; device code not approved |
| `test_code_grant_unknown_owner_invalid_grant` | M6 | ⇒ 400 `invalid_grant`, no `access_token`, code consumed |
| `test_refresh_grant_unknown_owner_revokes_chain` | M6 | ⇒ 400 `invalid_grant`; `revoke_chain(refresh_token)` awaited once |
| `test_unknown_user_raises` (replaces `test_unknown_user_degrades_without_raising`) | M6 | `_token_session_claims(request, 404)` with `user_from_id` raising ⇒ `UserNotFound` |
| `test_session_storage_unavailable_still_returns_empty` | M6 | resolvable owner, no session storage ⇒ `{}` (unchanged) |
| `test_userinfo_omits_unknown_claims` | M7 | `user_from_id` fails ⇒ body is `{"sub": "35"}` (plus `amr` only if in the token) |
| `test_userinfo_full_profile` | M7 | resolvable user ⇒ `username`, `given_name`, `family_name`, `email` present |

### Integration Tests
| Test | Description |
|---|---|
| `test_3lo_me_with_bearer_200` | M8: after the code exchange, `/api/v1/me` with `Authorization: Bearer` ⇒ 200, `user.username == "demo"`, `token_claims.client_id == "nav_example_spa"` and `jti`/`scope` non-null |
| `test_3lo_me_without_credentials_401` | M8: no header, no cookie ⇒ 401 |
| `test_3lo_list_grants_200` | M8: `GET /api/v1/oauth2/grants` with bearer ⇒ 200 listing `nav_example_spa` |
| `test_3lo_userinfo_profile` | M8: `/oauth2/userinfo` ⇒ `sub == "1"`, `username == "demo"`, `email == "demo@example.com"` |
| `test_3lo_refresh_binds_session` | M8: refresh grant ⇒ new access token that `/api/v1/me` accepts; no "cannot bind" warning logged |
| `test_3lo_foreign_session_forces_login` | M8: a pre-existing session for a user the demo IdP does not know ⇒ `/oauth2/authorize` redirects to the login form (S5 regression) |

### Validation Contract

tests:
- tests/test_oauth2_3lo_example.py
- tests/test_oauth2_examples_wiring.py
- tests/test_apikey_authenticate_bearer.py
- tests/test_is_authenticated_backend_loop.py
- tests/unit/test_is_authenticated_exclude.py
- tests/test_auth_middleware_exempt_userdata.py
- tests/test_auth_middleware_mechanism.py
- tests/test_oauth2_unknown_resource_owner.py
- tests/test_oauth2_3lo_session_binding.py
- tests/test_oauth2_userinfo_claims.py
- tests/test_oauth2_userinfo_logout.py
- tests/test_oauth2_access_gate.py
- tests/test_oauth2_refresh.py
- tests/test_oauth2_pkce.py
markers: none

### Test Data / Fixtures
```python
# Patterns to reuse (verified by the contract lanes):
# - provider fixture / make_request: tests/test_oauth2_3lo_session_binding.py:81-100
# - consent / refresh providers: tests/test_oauth2_access_gate.py:316-370 (_consent_provider,
#   consent_provider) and :683+ (refresh_provider, _refresh at :722-737)
# - decorator mock request: tests/unit/test_is_authenticated_exclude.py:17-31 (_make_request);
#   add req.app["auth"] = MagicMock(backends={...}) to drive the loop
# - backend construction: tests/unit/identity/conftest.py:40 (make_backend)
# - real app + TestClient: tests/test_auth_middleware_mechanism.py:48-100 (needs Redis)
# pyproject [tool.pytest.ini_options]: filterwarnings = ["error", ...] → secrets >= 32 bytes;
# no asyncio_mode → @pytest.mark.asyncio on async tests.
```

---

## 5. Acceptance Criteria

> This feature is complete when ALL of the following are true:

- [ ] **AC1** `examples/oauth2_3lo_server.py` builds `AuthHandler(backends=["navigator_auth.backends.oauth2.Oauth2Provider"], authz_backends=[], enable_authdb=False)`; its app's `auth.backends` holds only `Oauth2Provider` even when `settings/settings.py` lists other backends.
- [ ] **AC2** At startup the 3LO example logs one warning naming `AUTH_SECRET_KEY` when `navigator_auth.conf.SECRET_KEY` is shorter than 32 bytes, and none otherwise.
- [ ] **AC3** `examples/oauth2_server.py` builds `AuthHandler` with the same pinned `backends` and `authz_backends=[]`.
- [ ] **AC4** The `oauth2_server.py` walk-through (`/login` → Authorize → callback → Get Token) returns an `access_token`. The index page sends `code_challenge` (S256) and a random `state`; the callback page refuses a mismatched `state` and sends `code_verifier`. The startup hint no longer prints `<S256_hash>` for the 3LO flow.
- [ ] **AC5** `APIKeyAuth.authenticate` returns `None` for a bearer whose token info is `False`/`None`/`{}`; `check_token_info(request, None)` returns `False`; a dict missing `device_id` still raises `InvalidAuth`.
- [ ] **AC6** `@is_authenticated()` never calls a backend whose class sets `_anonymous_auth = True`; `NoAuth` sets it. With backends `[Oauth2Provider, NoAuth]`, a request without credentials gets 401 and NoAuth creates no session.
- [ ] **AC7** A non-`AuthException` raised by one backend is logged with `logger.exception` (backend name only, no credential) and the loop continues; when no backend succeeds the response is 401, never 500. This holds for function handlers and class-based views.
- [ ] **AC8** `MfaSignal` from a backend still stops the loop with 401 (FEAT-106 behaviour preserved).
- [ ] **AC9** The exclude list and `allow_anonymous` still admit anonymous callers (`tests/unit/test_is_authenticated_exclude.py` passes unchanged).
- [ ] **AC10** In `_auth_middleware`'s exempt branch, a bearer that resolves a session user sets `request["userdata"]` to the decoded payload, besides `request.user`, `request["authenticated"]` and the bearer mechanism.
- [ ] **AC11** `/oauth2/authorize` with a session whose user is unknown (`UserNotFound` or `ValidationError` from `user_from_id`) or disabled answers 302 to `nav_oauth2_login`, carrying the whole authorization request (`client_id`, `redirect_uri`, `state`, `scope`, `code_challenge`, `code_challenge_method`). No code is issued and the session is not invalidated in the store.
- [ ] **AC12** The consent POST (`action=approve`) for such a session answers 401 `access_denied` "Unknown or disabled resource owner." and stores no code.
- [ ] **AC13** `device_verification` for such a session redirects to login with `device_user_code` and leaves the device code pending.
- [ ] **AC14** The authorization-code grant answers 400 `invalid_grant` "The resource owner of this grant cannot be resolved." when the owner cannot be resolved; no access token is returned and the code remains consumed.
- [ ] **AC15** The refresh grant answers the same `invalid_grant` and awaits `refresh_token_storage.revoke_chain(<presented refresh token>)` once.
- [ ] **AC16** `_token_session_claims` raises `UserNotFound` / `FailedAuth` instead of returning `{}` for an unresolvable owner, and still returns `{}` when the session cannot be created. `test_unknown_user_degrades_without_raising` is replaced by `test_unknown_user_raises`.
- [ ] **AC17** `/oauth2/userinfo` never returns an empty-string claim: when the user cannot be loaded the body contains `sub` (and FEAT-106's `amr` only if the token carries it). With a resolvable user, the profile and email claims are present as today.
- [ ] **AC18** With the fixed 3LO example, after login as `demo` / `demo123`:
  - `/api/v1/me` with a bearer answers 200 with `token_claims.client_id`, `scope` and `jti` non-null;
  - without credentials it answers 401;
  - `GET /api/v1/oauth2/grants` answers 200 and lists `nav_example_spa`;
  - `/oauth2/userinfo` returns the demo profile;
  - a refresh grant logs no "cannot bind a session" warning.
- [ ] **AC19** All files in the §4 Validation Contract pass (`source .venv/bin/activate && pytest <files> -q`); `ruff check` is clean on every changed Python file.
- [ ] **AC20** `CHANGELOG.md` records the two behaviour changes (§2 New Public Interfaces) and how to keep anonymous access (exclude list / `allow_anonymous`); `examples/README.md` documents the pinned backends and the PKCE walk-through.

---

## 6. Codebase Contract

> **CRITICAL — Anti-Hallucination Anchor.** Verified against `dev` @ `1d06621` (2026-11-11). FEAT-106
> (PR #633) is not merged yet and changes `decorators.py`, `auth.py` and (per its approved review-fix
> spec) `oauth2/backend.py`. **`/sdd-task` must re-verify every anchor after FEAT-106 lands on `dev`.**

### Verified Imports
```python
from navigator_auth.exceptions import AuthException            # verified: navigator_auth/exceptions.py:3 (decorators.py:10)
from navigator_auth.exceptions import UserNotFound, FailedAuth, InvalidAuth  # verified: exceptions.py:32, :47, :42; imported in backend.py:102-106
from datamodel.exceptions import ValidationError               # verified: backend.py:41
from navigator_auth.backends.abstract import BaseAuthBackend, user_is_active  # verified: backend.py:108; abstract.py:64, :43
from navconfig.logging import logger                           # verified: decorators.py:9
from navigator_auth import AuthHandler                         # verified: examples/oauth2_3lo_server.py:61
from typing import NoReturn                                    # stdlib; NOT yet imported in backend.py — add for _redirect_to_login
from navigator_auth.conf import SECRET_KEY                     # verified: navigator_auth/conf.py:328
# After FEAT-106 merges (not on dev yet — re-verify):
from navigator_auth.exceptions import MfaSignal                # FEAT-106 branch: exceptions.py:72 (class MfaSignal(AuthException))
```

### Existing Class Signatures
```python
# navigator_auth/auth.py
class AuthHandler:
    def __init__(self, app_name: str = "auth", secure_cookies: bool = True,
                 enable_authdb: bool = True, backends: Iterable[str] = None,
                 authz_backends: Iterable[str] = None, **kwargs) -> None:          # :95-103
    self._backend_list: tuple = tuple(backends) if backends is not None else AUTHENTICATION_BACKENDS  # :132
    def get_backends(self, **kwargs):                                              # :241
    async def verify_exceptions(self, request: web.Request) -> bool:               # :951
    async def _auth_middleware(self, request, handler) -> web.StreamResponse:      # :1051 (exempt branch :1060-1077)

# navigator_auth/backends/abstract.py
def user_is_active(user) -> bool:                                                 # :43 (False only when is_active is explicitly false)
class BaseAuthBackend(ABC):                                                       # :64
    _external_auth: bool = False                                                  # :79
    # remember() sets request.user and user.is_authenticated = True               # :290-313 (:300)
    self._idp = identity                                                          # :134

# navigator_auth/backends/noauth.py
class AnonymousUser(AuthUser):                                                    # :17
class NoAuth(BaseAuthBackend):                                                    # :21
    _service_name: str = "anonymous"                                              # :28
    async def authenticate(self, request):                                        # :54 (creates a session via remember, returns truthy dict)

# navigator_auth/backends/api.py
class APIKeyAuth(BaseAuthBackend):                                                # :38
    async def get_payload(self, request):                                         # :54 → [mech, token]
    async def get_token_info(self, request: web.Request, mech: str, token: str) -> dict:  # :95 (ends: return await self.check_token_info(request, payload) :141)
    async def authenticate(self, request):                                        # :143 (data = … :152; data["device_id"] :154)
    async def check_token_info(self, request, payload):                           # :185 (KeyError → False :186-190)
    async def check_credentials(self, request: web.Request):                      # :211 (guard :217-219)

# navigator_auth/decorators.py
def get_auth(app):                                                                # :35
def is_authenticated(content_type: str = "application/json") -> Callable[[F], F]: # :179
#   function wrapper loop :215-229, 401 :234-240; method wrapper loop :259-270, 401 :275-281

# navigator_auth/backends/oauth2/backend.py
class Oauth2Provider(BaseAuthBackend):                                            # :258
    def redirect(self, uri: str, location: bool = False):                         # :489 (always raises HTTPFound)
    def _error_response(self, error: str, description: str, status: int = 400):  # :495
    async def check_session(self, request):                                       # :523 (returns encoded user blob or None)
    def _decode_session_user(self, encoded_user) -> Optional[OauthUser]:          # :538
    def _session_storage(self, request: web.Request):                             # :622
    async def _create_user_session(self, request, user, response=None):           # :632
    async def _token_session_claims(self, request: web.Request, user_id: int) -> dict:  # :688 (FEAT-106 M9 adds extra=)
    async def authorize(self, request: web.Request):                              # :1343 (session check :1423, gate_user :1433)
    async def consent(self, request: web.Request):                                # :1516 (POST user checks :1540-1545)
    async def auth_login(self, request: web.Request):                             # :1616 (is_active :1644)
    async def _handle_authorization_code(self, payload, request):                 # :1743 (code consumed :1812-1813; token_data :1829)
    async def _handle_refresh_token(self, payload, request):                      # :1973 (user_id :2033; token_data :2046; rotation :2080/:2094)
    async def userinfo(self, request):                                            # :2194 (claims :2222; _claim :2234; profile :2245-2248; email :2250)
    async def logout(self, request):                                              # :2258 (out-of-scope bug at :2263)
    async def device_verification(self, request: web.Request):                    # :2604 (session :2685; user_obj :2695-2697)
    def _get_request_user_id(self, request) -> Optional[int]:                     # :2801
    async def authenticate(self, request: web.Request):                           # :2833

# navigator_auth/backends/oauth2/code_backend.py
    async def revoke_chain(self, refresh_token: str) -> None:                     # :194

# navigator_auth/backends/idp/__init__.py
    async def user_from_id(self, uid: int) -> Identity:                           # :124 (UserNotFound :134/:143, wraps DB errors :140; re-raises ValidationError :135-138)
```

### Integration Points
| New Component | Connects To | Via | Verified At |
|---|---|---|---|
| `_authenticate_with_backends` | `auth.backends` (dict, configured order) | iteration | `decorators.py:215`, `auth.py:241` |
| `_authenticate_with_backends` | `BaseAuthBackend._anonymous_auth` | `getattr(backend, "_anonymous_auth", False)` | new (next to `abstract.py:79`) |
| `_resolve_resource_owner` | `self._idp.user_from_id` | await | `backend.py:698` (current call), `idp/__init__.py:124` |
| `_resolve_resource_owner` | `user_is_active` | call | `abstract.py:43`, `backend.py:108` |
| `_redirect_to_login` | `request.app.router["nav_oauth2_login"]` | `url_for().with_query(**payload)` | `backend.py:1425-1428` |
| refresh failure | `self.refresh_token_storage.revoke_chain(refresh_token)` | await | `backend.py:2005`, `code_backend.py:194` |
| exempt branch | `request["userdata"]` | assignment | `auth.py:1140`, `:1172` (mirror) |
| examples | `AuthHandler(backends=…, authz_backends=[])` | constructor | `auth.py:95-103`; pattern `examples/identity_vault_server.py:722` |

### Does NOT Exist (Anti-Hallucination)
- ~~`BaseAuthBackend._anonymous_auth`~~, ~~`is_anonymous`~~, ~~`allow_guest=`~~ — no anonymous marker or `is_authenticated` kwarg exists yet (`is_authenticated` takes only `content_type`).
- ~~`_authenticate_with_backends`~~, ~~`_try_backends`~~ — no shared loop helper; the two loops are duplicated today.
- ~~`Oauth2Provider._resolve_resource_owner`~~, ~~`_validate_session_user`~~, ~~`_session_owner`~~, ~~`_redirect_to_login`~~ — new in M6.
- ~~`forget_session`~~, ~~`invalidate_session`~~, ~~`_drop_session`~~ — no provider/backend session-drop helper (and D3 needs none).
- ~~`OAUTH_REQUIRE_KNOWN_OWNER`~~ or any config flag for the new behaviour; no ~~`UnknownResourceOwner`~~ exception.
- ~~`is_active` check outside `auth_login`~~ (only `backend.py:1644`).
- No `code_verifier` / `code_challenge` in `examples/static/callback.html` or `oauth2_index.html`; no shared PKCE JS file under `examples/static/`; no `/client-config` route in `oauth2_server.py`.
- No secret-key length check or warning anywhere in `navigator_auth/` or `examples/`.
- No test imports or boots an example module; no test calls `APIKeyAuth.authenticate()`.
- `SessionData.invalidate()` is **sync and takes no arguments**; `AbstractStorage.invalidate(request, session)` is async (navigator_session wheel). Do not copy `logout`'s `await session.invalidate(request)`.

### Edit Sites (Blueprint Anchors)

Verified against: `1d06621` (re-verify after FEAT-106 merges).

| File | Action | Verbatim anchor line | Verified at | Occurrences |
|---|---|---|---|---|
| `examples/oauth2_3lo_server.py` | MODIFY | `auth = AuthHandler(enable_authdb=False)` | `:218` | 1 |
| `examples/oauth2_3lo_server.py` | MODIFY | `os.environ.setdefault("AUTH_SECRET_KEY", "example-only-secret-key-change-me")` | `:54` | 1 |
| `examples/oauth2_server.py` | MODIFY | `auth = AuthHandler()` | `:55` | 1 |
| `examples/oauth2_server.py` | MODIFY | `print("3LO flow (public client + PKCE S256):")` (the placeholder line after it, `:181`, also occurs at `:189` in the device hint — edit only the one preceded by `"&state=test_state"`) | `:173` | 1 |
| `examples/static/oauth2_index.html` | MODIFY | `href="/oauth2/authorize?client_id=nav_public_client` | `:54` | 1 |
| `examples/static/oauth2_index.html` | MODIFY | `This page starts the flow <em>without</em> PKCE` | `:49` | 1 |
| `examples/static/callback.html` | MODIFY | `async function exchangeToken() {` | `:30` | 1 |
| `examples/README.md` | MODIFY | `### Example-only shortcuts` | `:58` | 1 |
| `examples/README.md` | MODIFY | ``## `oauth2_server.py` — OAuth2 client registrations reference`` | `:163` | 1 |
| `navigator_auth/backends/api.py` | MODIFY | `device_id = str(data["device_id"])` (guard goes after `:152` `data = await self.get_token_info(request, mech, token)`, which also occurs at `:217`) | `:154` | 1 |
| `navigator_auth/backends/api.py` | MODIFY | `async def check_token_info(self, request, payload):` | `:185` | 1 |
| `navigator_auth/backends/abstract.py` | MODIFY | `_external_auth: bool = False` | `:79` | 1 |
| `navigator_auth/backends/noauth.py` | MODIFY | `_service_name: str = "anonymous"` | `:28` | 1 |
| `navigator_auth/decorators.py` | MODIFY | `for _, backend in auth.backends.items():` — function wrapper (preceded by `userdata = None`, followed by `try:` / `result = await backend.authenticate(request)`) and method wrapper | `:215`, `:259` | 2 |
| `navigator_auth/decorators.py` | MODIFY | `from .exceptions import AuthException` (FEAT-106 makes it `…, MfaSignal`) | `:10` | 1 |
| `navigator_auth/auth.py` | MODIFY | `pass  # Best-effort: if token is invalid, proceed unauthenticated` — insert `request["userdata"] = payload` after the `request.user = user` at `:1072` inside this `try` (that line also occurs at `:1139`, `:1171`) | `:1076` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `async def _token_session_claims(self, request: web.Request, user_id: int) -> dict:` | `:688` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `self.logger.warning(f"Oauth2: cannot bind a session to the token for user_id={user_id}: {exc}")` | `:700` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `gate_user = self._decode_session_user(session)` | `:1433` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `return self._error_response("access_denied", "Cannot resolve user from session.", status=401)` | `:1545` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `**await self._token_session_claims(request, user_id),` — code grant (after `"jti": jti,` + comment "Bind the token to a session…") and refresh grant (after comment "Same session binding as the authorization_code grant.") | `:1829`, `:2046` | 2 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `return self._error_response("access_denied", "Cannot resolve session user.", status=401)` | `:2697` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `claims["username"] = str(_claim("username"))` | `:2246` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `claims["email"] = str(_claim("email"))` | `:2250` | 1 |
| `tests/test_oauth2_3lo_session_binding.py` | MODIFY | `async def test_unknown_user_degrades_without_raising(self, provider):` | `:128` | 1 |
| `tests/test_oauth2_userinfo_logout.py` | MODIFY | `def _build_claims(self, payload: dict) -> dict:` | `:53` | 1 |
| `CHANGELOG.md` | MODIFY | `# Unreleased` (add entries under it; FEAT-107's BREAKING entry is the first item) | `:1` | 1 |
| `tests/test_oauth2_examples_wiring.py` | CREATE | — | — | — |
| `tests/test_apikey_authenticate_bearer.py` | CREATE | — | — | — |
| `tests/test_is_authenticated_backend_loop.py` | CREATE | — | — | — |
| `tests/test_auth_middleware_exempt_userdata.py` | CREATE | — | — | — |
| `tests/test_oauth2_unknown_resource_owner.py` | CREATE | — | — | — |
| `tests/test_oauth2_userinfo_claims.py` | CREATE | — | — | — |
| `tests/test_oauth2_3lo_example.py` | CREATE | — | — | — |

---

## 7. Implementation Notes & Constraints

### Patterns to Follow
- Example wiring: copy `examples/identity_vault_server.py:108-119` (`_BACKENDS` + the comment explaining the `settings.settings` override) and `:715-722` (`authz_backends=[]` comment + constructor).
- Class flag on backends: same shape as `_external_auth: bool = False` (`abstract.py:79`, read with `getattr` at `auth.py:358`).
- Error responses: `self._error_response(error, description, status)` (`backend.py:495`); login redirect: the block at `backend.py:1425-1428`.
- Chain revocation: `await self.refresh_token_storage.revoke_chain(refresh_token)` as at `backend.py:2005`.
- Browser PKCE: `oauth2_3lo_app.html:172-188` (helpers, storage) and `:200-238` (authorize + exchange with the state check).
- Logging: module `logger` in `decorators.py`, `self.logger` in backends; never log a token, a code or the `Authorization` header.
- Tests: `@pytest.mark.asyncio` on async tests; ≥ 32-byte secrets (`filterwarnings = ["error"]`); Redis is needed only for M8 and `test_auth_middleware_mechanism.py`.

### Known Risks / Gotchas
- **Behaviour change for apps relying on NoAuth + `@is_authenticated()`.** They now get 401. Mitigation: CHANGELOG entry with the migration (exclude list or `allow_anonymous`); `verify_exceptions`' `allow_anonymous` handling (`auth.py` ~993-996) is untouched.
- **FEAT-106 overlap.** It edits the same loop (`except MfaSignal: break` at both loops), `auth.py`, and plans `_token_session_claims(extra=)`, `amr` in `token_data`/`userinfo`. Implement on top of the merged FEAT-106: keep `MfaSignal` first, pass `extra` through, keep the `amr` echo. Anchors in §6 move.
- **Swallowing backend errors could hide bugs.** `logger.exception` keeps the traceback; tests assert the log call.
- **Shared Redis sessions (D3).** Invalidating would log the user out of other apps; the redirect is enough because `auth_login` replaces this browser's cookie.
- **Refresh failure before rotation (D6).** Without `revoke_chain` the old refresh token would stay valid.
- **`crypto.subtle`** needs a secure context: `http://localhost` qualifies, a LAN IP does not. Document it in the README.
- **Line drift.** FEAT-107 already moved `conf.py`/`auth.py` lines once since the proposal; anchors are textual for this reason.
- **Follow-ups found during research (out of scope):**
  - `logout` never invalidates the session (`backend.py:2263`, swallowed `TypeError`);
  - `AuthHandler.api_login` has the same backend-loop semantics;
  - U1: the user-35 session most likely came from `examples/oauth2_server.py`, which logs in against the real user table (its placeholder resource owner is `user_id=35`, `oauth2_server.py:83-88`) on the same `localhost:5000` and Redis.

### External Dependencies
| Package | Version | Reason |
|---|---|---|
| — | — | No new dependency (aiohttp, navigator_session, PyJWT already present) |

---

## Worktree Strategy

- **Isolation**: one feature worktree, `.claude/worktrees/feat-FEAT-108-oauth2-3lo-issues`, created from `origin/dev` **after FEAT-106 is merged**; the `sdd-coder` engine gives each task its own sub-worktree inside it.
- **Module dependency graph**:
  - M8 → M1: imports the example's `make_app`.
  - M8 → M4, M5, M6: asserts their behaviour end-to-end.
  - M1, M2, M3, M4, M5, M6, M7 have no edges between them and can run concurrently, apart from the shared files below.
- **Shared files** (their tasks are serialized):
  - `navigator_auth/backends/oauth2/backend.py` (M6, M7);
  - `examples/README.md` (M1, M2);
  - `CHANGELOG.md` (whichever modules record the behaviour changes, M4 and M6).
- **Exclusive resources**: M8 and `tests/test_auth_middleware_mechanism.py` use the local Redis for sessions; no migration, no lockfile change, no native rebuild.
- **Cross-feature dependencies**: **FEAT-106** (`basicauth-otp-2fa` + `basicauth-otp-2fa-review-fixes`, PR #633) must be merged into `dev` first:
  - its branch already changes both `is_authenticated` loops and `auth.py`;
  - its approved review fixes change `_token_session_claims`, both token-grant call sites, `_create_user_session`, `auth_login` and the `userinfo` claims.

---

## 8. Open Questions

- [x] Should `@is_authenticated()` reject anonymous results from its backend loop? — *Resolved in proposal (U2)*: "Reject anonymous (Recommended)"; the exclude list and `allow_anonymous` stay the opt-ins. → G4, D1, AC6, AC9.
- [x] What should the provider do when the resource owner cannot be resolved? — *Resolved in proposal (U3)*: "Validate at authorize (Recommended)": `/oauth2/authorize` re-checks the session user and sends an unknown user to login; the token grants fail with `invalid_grant` instead of issuing a session-less token. → G6, D3–D7, AC11–AC16.
- [x] When one backend raises an unexpected (non-`AuthException`) error, what does the loop do? — *Resolved at spec time*: "Log and continue (Recommended)"; 401 if no backend succeeds. → D2, AC7.
- [x] Is the unknown owner's session destroyed? — *Decided at spec time (D3), review at approval*: no; the authorization redirects to login and `auth_login` replaces this browser's session, so the shared store entry used by other apps survives.
- [x] Are `device_verification` and `is_active` in scope? — *Decided at spec time (D4, D5), review at approval*: yes, same fail-closed rule.
- [ ] Where did the user-35 session come from? — *Owner: Jesus Lara*. Non-blocking (G6 covers every source). New lead: `examples/oauth2_server.py` logs in against the real user table on the same `localhost:5000` + Redis, and its placeholder resource owner is `user_id=35` (`oauth2_server.py:83-88`).

---

## 9. Design Research Cross-Check

> Model: `gpt-5.6-luna` · Status: skipped (exploration doc `sdd/proposals/oauth2-3lo-issues.proposal.md` has `status: discussion`, not `accepted`) · Transcript: none

| # | Suggestion (kind) | Disposition | Reason | Landed in |
|---|---|---|---|---|

Summary: **0** confirmed · **0** rejected · **0** escalated.

---

## 10. Documentation

- **Policy**: `required`
- **Pages**: no `wiki/` tree exists in this repository. Deliver instead:
  - `examples/README.md` — update: 3LO section explains the pinned backends, `authz_backends=[]` and the short-key warning (mirrors the identity-vault warning at `:141-148`); `oauth2_server.py` section describes the PKCE walk-through.
  - `CHANGELOG.md` — update: the two behaviour changes in §2 and the anonymous-access migration.
- **API modules** (docstring completeness): `navigator_auth.decorators`, `navigator_auth.backends.api`, `navigator_auth.backends.oauth2.backend`.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-11-11 | Jesus Lara | Initial draft from `sdd/proposals/oauth2-3lo-issues.proposal.md` (FEAT-108) |
