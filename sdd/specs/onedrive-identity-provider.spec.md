---
type: feature
base_branch: dev
projects: [navigator-auth]
tags: [onedrive, microsoft-graph, identity-link, oauth2, session-vault]
---

# Feature Specification: OneDrive Link-Only Identity Provider

**Feature ID**: FEAT-100
**Date**: 2026-09-30
**Author**: Jesus Lara (spec drafted by Claude Code, Opus 5.5)
**Status**: draft
**Target version**: navigator-auth 0.29.0

> **Cross-repo origin.** This is the external prerequisite **P1** of querysource
> **FEAT-159** (`../querysource/sdd/specs/onedrive-multiqs-source.spec.md`, §2).
> querysource's `OneDriveSource` delegated mode reads the linked `onedrive`
> identity through this package. querysource's M9 enables this backend and raises
> its pin to the release that ships this spec.

---

## 1. Motivation & Business Requirements

### Problem Statement

A user needs to link **their own Microsoft account** (personal OneDrive or
OneDrive for Business) once, through a UI. The resulting access and refresh
tokens must be stored ciphered in `auth.user_identities` and cached in the
user's session vault, so that querysource can read that user's OneDrive
files, including from scheduled jobs.

The Identity Vault link flow already exists (`/api/v1/user/identities/link/{provider}`,
`/manage`, `/{provider}/credential`, and
`IdentityProvider.get_user_identity_credential`), but no backend can serve
OneDrive:

- `AzureAuth` (`_service_name = "azure"`) is the **corporate SSO login**. It is
  bound to `AZURE_ADFS_TENANT_ID`/`AZURE_ADFS_CLIENT_ID` and one global
  `AZURE_IDENTITY_SCOPES`. Reusing it would turn on corporate login wherever
  OneDrive is needed, widen the corporate app's consented scopes, and force
  that app registration to accept personal Microsoft accounts.
- Any `ExternalAuth` subclass also becomes a **login method**:
  - `configure()` registers login, logout and check-credentials routes
    (`backends/external.py:114-168`);
  - the login middleware calls `authenticate()` on **every** backend when no
    method is named (`auth.py:484-490`);
  - `auth_methods` lists every backend that is not `hidden` (`auth.py:564-567`).

### Goals

- G1 — A new `OneDriveAuth(ExternalAuth)` backend with
  `_service_name = "onedrive"` and **link-only** behaviour:
  - it registers only the identity-link callback route;
  - `authenticate()` never authenticates anyone;
  - it is `hidden` from `auth_methods`;
  - it still appears in `external_backends()`, so the identities `/manage`
    UI offers it.
- G2 — It has its own app registration and settings (`ONEDRIVE_CLIENT_ID`,
  `ONEDRIVE_CLIENT_SECRET`, `ONEDRIVE_TENANT`, default `common`, and
  `ONEDRIVE_IDENTITY_SCOPES`), completely separate from `AZURE_ADFS_*`.
- G3 — Authorization, code exchange and refresh work against the Microsoft
  identity platform v2 endpoints for work **and** personal accounts, with
  offline access. Rotated refresh tokens are persisted by the existing
  `update_tokens` paths.
- G4 — A public, read-only `AuthHandler.identity_provider` property returns
  the `IdentityProvider`, so in-process consumers (querysource) stop reaching
  into `AuthHandler._idp`.

### Non-Goals (explicitly out of scope)

- Changes to `AzureAuth` or the corporate SSO flow.
- A generic "link-only" framework flag for every backend. Making link-only a
  first-class `ExternalAuth` option is a possible follow-up. Here it is
  implemented by overrides in `OneDriveAuth`, using the existing `hidden`
  precedent (FEAT-097).
- MSAL. The generic `ExternalAuth` HTTP flow (`token_request`) is enough, and
  `AzureAuth`'s MSAL path stays AzureAuth-only.
- querysource code. That is FEAT-159.

---

## 2. Architectural Design

### Overview

`OneDriveAuth` subclasses `ExternalAuth` and relies on its generic identity
flow: `authorize_identity` → `exchange_code_for_tokens` →
`finish_identity_link` → `IdentityStore.save_linked_identity` +
`cache_credential`. It overrides only what OneDrive needs:

- **Endpoints**:
  - `authorize_uri = https://login.microsoftonline.com/{ONEDRIVE_TENANT}/oauth2/v2.0/authorize`
  - `_token_uri = …/oauth2/v2.0/token`
  - `userinfo_uri = https://graph.microsoft.com/v1.0/me`
  - `ONEDRIVE_TENANT` defaults to `common`, which accepts work/school and
    personal accounts. `consumers` or a tenant GUID restrict it.
- **Identity hooks**:
  - `identity_scopes()` returns `ONEDRIVE_IDENTITY_SCOPES`, default
    `Files.Read,User.Read,offline_access`;
  - `identity_authorize_params()` returns `{"prompt": "select_account",
    "response_mode": "query"}`;
  - `get_identity_client()` returns `(ONEDRIVE_CLIENT_ID, ONEDRIVE_CLIENT_SECRET)`;
  - `get_identity_userid()` returns `userinfo["id"]`.
- **Token grants**: `exchange_code_for_tokens` and `refresh_identity_tokens`
  are overridden only to add `scope=" ".join(identity_scopes())` to the
  token-endpoint form. The Microsoft v2 token endpoint expects `scope` on the
  `refresh_token` grant. The generic implementations send no scope
  (`external.py:552-595`). Refresh-token rotation is kept exactly as the
  generic code does it: if Microsoft does not rotate, the old token is kept.
- **Link-only**:
  - `configure()` registers **only** `GET /auth/onedrive/callback/` →
    `self._auth_callback_dispatch`, and adds it to `AUTH_EXCLUDE_LIST_KEY`.
    It does **not** call `ExternalAuth.configure`; it calls
    `BaseAuthBackend.configure(self, app)` so `self._app` is still set.
  - `authenticate(request)` returns `None`. It has no side effects and no
    redirect, so the login loop moves to the next backend.
  - `auth_callback(request)` is reached only when the callback's `state`
    matches no pending identity-link flow. It returns
    `failed_redirect(request, error="IDENTITY_LINK_ONLY", …)` and never logs
    a user in.
  - `hidden = True` keeps it out of `auth_methods`.
  - `_external_auth = True` (inherited) keeps it in `external_backends()` and
    resolvable by `get_external_backend("onedrive")`.
- **Public accessor**: `AuthHandler.identity_provider` is a `@property`
  returning `self._idp`.

### Component Diagram

```
Browser (logged in via BasicAuth/any)          querysource (FEAT-159)
  │ GET /api/v1/user/identities/link/onedrive     │ app["auth"].identity_provider
  ▼                                               │   .get_user_identity_credential(uid, "onedrive")
IdentityLinkHandler → OneDriveAuth.authorize_identity ─302─► login.microsoftonline.com/common/v2.0/authorize
                                                         (Files.Read User.Read offline_access)
  ◄──────────── GET /auth/onedrive/callback/?code&state ─┘
OneDriveAuth._auth_callback_dispatch → flow_store.consume_link(state)
   → finish_identity_link → exchange_code_for_tokens (+scope) → GET graph /v1.0/me (id)
   → IdentityStore.save_linked_identity (auth.user_identities, ciphered)
   → cache_credential(session, "onedrive")  (session vault identity:onedrive)
Refresh: IdentityCredentialHandler / IdentityProvider → OneDriveAuth.refresh_identity_tokens (+scope)
         → store.update_tokens (rotation persisted)
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `ExternalAuth` (`backends/external.py:80`) | extends | generic identity flow reused; `configure`, `authenticate`, `auth_callback` and the two token grants overridden |
| `BaseAuthBackend.configure` (`backends/abstract.py:185`) | calls | sets `self._app` |
| `AuthHandler.get_external_backend` (`auth.py:354`) | used by | resolves `"onedrive"` for link and refresh |
| `AuthHandler.external_backends` (`auth.py:365-371`) | used by | the identities UI lists OneDrive |
| `AuthHandler.auth_methods` (`auth.py:551-580`) | respects | `hidden = True` |
| Login loop (`auth.py:484-490`) | respects | `authenticate()` → `None` |
| `IdentityLinkHandler` / `IdentityCredentialHandler` / `IdentitiesManageView` | uses (unchanged) | provider `onedrive` |
| `IdentityProvider.get_user_identity_credential` (`backends/idp/__init__.py:84`) | uses (unchanged) | sessionless read + refresh for querysource |
| `backends/__init__.py` | modifies | export `OneDriveAuth` |
| `conf.py` (`:627-651` identity block) | modifies | `ONEDRIVE_*` settings |

### Data Models

No schema change. Rows go into the existing `auth.user_identities` with
`auth_provider = 'onedrive'` and `provider_user_id` = the Graph `/me` `id`.

### New Public Interfaces

```python
from navigator_auth.backends import OneDriveAuth      # AUTHENTICATION_BACKENDS: "navigator_auth.backends.OneDriveAuth"
AuthHandler.identity_provider -> IdentityProvider     # read-only property
```

Settings (navconfig):

| Key | Default | Meaning |
|---|---|---|
| `ONEDRIVE_CLIENT_ID` | — (required) | Entra app (client) id, registered for "any org directory + personal accounts" |
| `ONEDRIVE_CLIENT_SECRET` | — (required) | client secret |
| `ONEDRIVE_TENANT` | `common` | authority segment: `common` \| `consumers` \| `organizations` \| tenant GUID |
| `ONEDRIVE_IDENTITY_SCOPES` | `Files.Read,User.Read,offline_access` | comma-separated delegated scopes |

The app registration's redirect URI is `{domain}/auth/onedrive/callback/`
(`ExternalAuth.get_redirect_uri`, `external.py:239-246`).

---

## 3. Module Breakdown

#### Delegation-eligible modules

| Module | Eligible? | Decided patterns / exact contracts | Why not (if no) |
|---|---|---|---|
| M1: OneDriveAuth backend | yes | skeleton below; Google identity hooks as the pattern (`google.py:178-196`) | — |
| M2: Settings + export | yes | keys/defaults in §2 | — |
| M3: `AuthHandler.identity_provider` | yes | one read-only property | — |
| M4: Tests + docs | yes | test list §4 | — |

### Module 1: OneDriveAuth backend
- **Path**: `navigator_auth/backends/onedrive.py` (new)
- **Responsibility**: the link-only Microsoft identity provider described in §2.
- **Depends on**: M2 (settings)
- **Interface Skeleton**:
  ```python
  # navigator_auth/backends/onedrive.py  (new)
  from .external import ExternalAuth           # verified: backends/external.py:80
  from .abstract import BaseAuthBackend        # verified: backends/abstract.py (configure :185)

  class OneDriveAuth(ExternalAuth):
      """Link-only Microsoft (OneDrive) identity provider — never a login method."""
      user_attribute: str = "user"
      userid_attribute: str = "id"
      _service_name: str = "onedrive"
      _description: str = "Microsoft OneDrive (identity link)"
      hidden: bool = True                      # precedent: backends/saml/idp.py:46

      def __init__(self, user_attribute: str = None, userid_attribute: str = None,
                   password_attribute: str = None, **kwargs) -> None:
          """Set authorize/token URIs from ONEDRIVE_TENANT and userinfo_uri=/v1.0/me."""
      def configure(self, app) -> None:
          """Register ONLY GET /auth/onedrive/callback/ → self._auth_callback_dispatch (+exclude
          list); BaseAuthBackend.configure(self, app). No login/logout/check_credentials routes."""
      async def authenticate(self, request: web.Request) -> None:
          """Always None — link-only backends never authenticate a request."""
      async def auth_callback(self, request: web.Request) -> web.Response:
          """Callback without a pending identity-link flow → failed_redirect IDENTITY_LINK_ONLY."""
      def identity_scopes(self) -> list: ...           # ONEDRIVE_IDENTITY_SCOPES
      def identity_authorize_params(self) -> dict: ... # {"prompt": "select_account", "response_mode": "query"}
      def get_identity_client(self) -> tuple: ...      # (ONEDRIVE_CLIENT_ID, ONEDRIVE_CLIENT_SECRET); AuthException if unset
      def get_identity_userid(self, userinfo: dict) -> Optional[str]: ...  # str(userinfo["id"])
      async def exchange_code_for_tokens(self, request: web.Request, flow: dict) -> TokenResponse:
          """Generic grant (external.py:552) + scope form field."""
      async def refresh_identity_tokens(self, refresh_token: str) -> TokenResponse:
          """Generic grant (external.py:576-594) + scope; keeps old refresh token if not rotated."""
  ```

### Module 2: Settings + export
- **Paths**: `navigator_auth/conf.py` (identity block, after `:642-651`),
  `navigator_auth/backends/__init__.py` (import + `__all__`)
- **Depends on**: —

### Module 3: `AuthHandler.identity_provider`
- **Path**: `navigator_auth/auth.py` (next to `self._idp = IdentityProvider()`, `:137`)
- **Interface Skeleton**:
  ```python
  @property
  def identity_provider(self) -> IdentityProvider:
      """The app's IdentityProvider (in-process linked-identity access)."""
  ```

### Module 4: Tests + docs
- **Paths**: `tests/unit/identity/test_onedrive_backend.py` (new),
  `docs/` (identity-link page: OneDrive app registration, redirect URI, settings)
- **Depends on**: M1–M3

---

## 4. Test Specification

### Unit Tests
| Test | Module | Description |
|---|---|---|
| `test_configure_registers_only_callback` | M1 | the router has `/auth/onedrive/callback/` and **no** `/auth/onedrive/login`, `/api/v1/auth/onedrive/`, logout or check_credentials route |
| `test_authenticate_returns_none` | M1 | no redirect, no exception, no side effects |
| `test_hidden_from_auth_methods` | M1 | the `GET /api/v1/auth/methods` response has no `onedrive` key |
| `test_listed_in_external_backends` | M1 | `external_backends()` and `get_external_backend("onedrive")` both include or resolve it |
| `test_callback_without_link_flow_rejected` | M1 | an unknown `state` → `failed_redirect` with `IDENTITY_LINK_ONLY`; nobody is logged in |
| `test_authorize_identity_url` | M1 | the 302 goes to `…/{ONEDRIVE_TENANT}/oauth2/v2.0/authorize` with client_id, scopes, `prompt=select_account` and state stored in the flow store |
| `test_exchange_sends_scope` / `test_refresh_sends_scope` | M1 | the token form carries `scope`; the refresh keeps the old token when none is rotated |
| `test_identity_userid_from_me` | M1 | `/me` `id` → `provider_user_id` |
| `test_missing_client_config` | M1 | an unset `ONEDRIVE_CLIENT_ID` → `AuthException` on link start (501 via `IdentityLinkHandler`) |
| `test_settings_defaults` | M2 | tenant `common`; scopes default list |
| `test_identity_provider_property` | M3 | `auth.identity_provider is auth._idp` |

### Integration Tests
| Test | Description |
|---|---|
| `test_onedrive_link_end_to_end_mocked` | link → mocked token and `/me` endpoints → `auth.user_identities` row `auth_provider='onedrive'` + vault `identity:onedrive` |
| `test_onedrive_credential_autorefresh` | an expiring stored token → `IdentityProvider.get_user_identity_credential(uid, "onedrive")` refreshes and persists the rotated token |

---

## 5. Acceptance Criteria

- [ ] `OneDriveAuth` is importable from `navigator_auth.backends` and enabled with `AUTHENTICATION_BACKENDS=…,navigator_auth.backends.OneDriveAuth`.
- [ ] With it enabled, no OneDrive login, logout or check-credentials route exists. `auth_methods` does not list it, and the login middleware loop is unaffected.
- [ ] `/api/v1/user/identities/link/onedrive` completes the Microsoft flow for a work account **and** a personal account (checked manually against a real app registration). The row lands in `auth.user_identities` and the credential in the session vault as `identity:onedrive`.
- [ ] `/api/v1/user/identities/onedrive/credential` and `IdentityProvider.get_user_identity_credential(uid, "onedrive")` refresh expiring tokens and persist rotation.
- [ ] `AuthHandler.identity_provider` exists and returns the handler's `IdentityProvider`.
- [ ] `AzureAuth` behaviour and settings are unchanged, and the existing identity tests pass.
- [ ] Released as navigator-auth **0.29.0**. querysource FEAT-159 M9 pins `navigator-auth>=0.29.0`.

---

## 6. Codebase Contract

> Verified against navigator-auth `dev` @ **48a11c3** (version 0.28.3) on 2026-09-30.

### Verified Imports
```python
from navigator_auth.backends.external import ExternalAuth          # backends/external.py:80
from navigator_auth.backends.abstract import BaseAuthBackend       # backends/abstract.py
from navigator_auth.identity.types import TokenResponse            # identity/types.py
from navigator_auth.conf import IDENTITY_LINK_TTL, IDENTITY_REFRESH_LEEWAY   # conf.py:627, :629
```

### Existing Class Signatures
```python
# navigator_auth/backends/external.py
class ExternalAuth(BaseAuthBackend):                               # :80
    _service_name: str = "service"                                 # :89
    _external_auth: bool = True                                    # :93
    def __init__(self, user_attribute=None, userid_attribute=None, password_attribute=None, **kwargs)  # :95-112 (base_url, authorize_uri, userinfo_uri, _token_uri)
    def configure(self, app):                                      # :114-168 (login :119-137, callback→_auth_callback_dispatch :139-145, logout :147-158, check_credentials :160-167)
    async def on_startup(self, app):                               # :170 (creates self._flow_store)
    def get_redirect_uri(self, request) -> str:                    # :239-246 → {domain}/auth/{service}/callback/
    def failed_redirect(self, request, error="ERROR_UNKNOWN", message="ERROR_UNKNOWN"):  # :342
    @abstractmethod async def authenticate(self, request)          # :349-351
    @abstractmethod async def auth_callback(self, request)         # :353-355
    async def _auth_callback_dispatch(self, request):              # :368-393 (consume_link → finish_identity_link, else auth_callback)
    def identity_scopes(self) -> list:                             # :500
    def identity_authorize_params(self) -> dict:                   # :504
    def get_identity_client(self) -> tuple:                        # :509 (raises AuthException by default)
    def get_identity_userid(self, userinfo: dict) -> Optional[str]:  # :515
    async def authorize_identity(self, request, user_id, finish_redirect):  # :523
    async def exchange_code_for_tokens(self, request, flow) -> TokenResponse:  # :552 (no scope sent)
    async def refresh_identity_tokens(self, refresh_token) -> TokenResponse:   # :576-594 (no scope; keeps old RT if not rotated)
    async def get_identity_userinfo(self, token) -> dict:          # :596
    async def finish_identity_link(self, request, flow):           # :611 (save_linked_identity + cache_credential)

# navigator_auth/auth.py
self._idp = IdentityProvider()                                     # :137
def get_external_backend(self, service: str):                      # :354
def external_backends(self) -> list:                               # :365-371 (_external_auth only; hidden not filtered)
# login loop over all backends calling authenticate():             # :484-490
async def auth_methods(self, request):                             # :551 (skips hidden :564-567, :573-575)

# navigator_auth/backends/saml/idp.py — `hidden: bool = True` precedent  # :46
# navigator_auth/backends/google.py — identity hooks pattern          # :178-196
```

### Does NOT Exist (Anti-Hallucination)
- ~~Any OneDrive backend or `ONEDRIVE_*` setting~~ in navigator-auth: grep finds none.
- ~~`AuthHandler.identity_provider`~~ at 48a11c3: added by M3.
- ~~A generic link-only flag on `ExternalAuth`~~: out of scope (see Non-Goals).
- ~~`scope` in the generic token grants~~: not sent today (`external.py:552-594`).

### Edit Sites (Blueprint Anchors)

Verified against: **48a11c3**

| File | Action | Verbatim anchor line | Verified at | Occurrences |
|---|---|---|---|---|
| `navigator_auth/backends/onedrive.py` | CREATE | — | — | — |
| `navigator_auth/backends/__init__.py` | MODIFY | `from .azure import AzureAuth` | `backends/__init__.py:14` | 1 |
| `navigator_auth/conf.py` | MODIFY | `IDENTITY_REFRESH_LEEWAY = config.getint("IDENTITY_REFRESH_LEEWAY", fallback=120)` | `conf.py:629` | 1 |
| `navigator_auth/auth.py` | MODIFY | `        self._idp = IdentityProvider()` | `auth.py:137` | 1 |
| `tests/unit/identity/test_onedrive_backend.py` | CREATE | — | — | — |

---

## 7. Implementation Notes & Constraints

### Patterns to Follow
- Copy the Google identity-hook pattern (`google.py:178-196`) and the
  `hidden` precedent (`saml/idp.py:46`).
- Settings go through navconfig in `conf.py`. No secrets in code, and tokens
  are never logged.

### Known Risks / Gotchas
- **`common` authority and `iss` validation.** The link flow does not
  validate an id_token issuer (it calls `/me` with the access token), so the
  multi-tenant `iss` problem `AzureAuth` handles does not apply. Keep it that
  way: no id_token verification in this backend.
- **`scope` on the token grants.** Microsoft v2 expects `scope` on
  `refresh_token` grants. Confirm the exact requirement for code redemption
  against Microsoft's docs during implementation. Sending it on both is harmless.
- **Personal accounts** need the app registration's supported account types
  set to "any org directory + personal Microsoft accounts". `Files.Read` on a
  personal account needs no admin consent.
- **Callback shared with a non-existent login.** A stray callback (a replayed
  state or a direct hit) must never create a session. `auth_callback`
  rejects it.

### External Dependencies
None new. The generic flow uses the existing aiohttp `token_request`/`get` helpers.

---

## 8. Open Questions

- [x] Reuse `AzureAuth` or a new provider? — *Resolved in querysource FEAT-178 proposal (U6)*: "if no [Azure identity link enabled], we need a new provider in navigator-auth". Research showed it is not enabled and is the corporate SSO, so a new provider.
- [x] Link-only or login-capable? — *Resolved in querysource FEAT-159 design research (S1)*: link-only.
- [ ] **Q1 — Release version**: 0.29.0 is proposed (0.28.3 on `dev`). Confirm at release. — *Owner: Jesus Lara*
- [ ] **Q2 — Promote link-only to an `ExternalAuth` flag** (for example `link_only: bool`) in a follow-up, so future providers don't repeat these overrides? — *Owner: Jesus Lara*

---

## Worktree Strategy

- One worktree `feat-100-onedrive-identity-provider` off `dev`.
- Dependency graph: M1 → M2 (settings imported); M4 → M1–M3; M3 has no
  edges. M2 ∥ M3, then M1, then M4.
- Shared files: none between modules.
- Cross-feature: **querysource FEAT-159** consumes this release (its M9).

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-09-30 | Jesus Lara / Claude Code | Initial draft — follow-up (P1) of querysource FEAT-159 |
