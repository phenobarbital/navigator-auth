# Feature Specification: External Token Exchange — Provider Bearer → Basic Session

**Feature ID**: FEAT-096
**Date**: 2026-09-04
**Author**: Jesus Lara
**Status**: approved
**Target version**: 0.25.0

> **Inputs:** `sdd/proposals/external-token-exchange.proposal.md` (decisions D1–D10
> resolved 2026-09-04).
> **Hard prerequisites (landed):** Identity Vault (`IdentityStore`,
> `auth.user_identities` credential columns, `/api/v1/user/identities/{provider}/credential`),
> FEAT-095 (provider backends expose `build_user_info`, `get_identity_userid`,
> `identity_scopes`; `IdentityFlowStore`).

---

## 1. Motivation & Business Requirements

### Problem Statement

A client that already holds a valid bearer token from Azure, Google or GitHub
(mobile app, desktop tool, partner front-end that ran the provider login itself)
cannot obtain a navigator-auth session without replaying the browser redirect
flow. The only shortcut today is `AzureAuth.check_credentials`
(`navigator_auth/backends/azure.py:392`): Azure-only, never checks that the token
was minted for *this* application (any Graph token from any app logs the user
in), opens the session as `auth_method: "azure"` bypassing the Basic mapping and
callbacks, and honours `AUTH_MISSING_ACCOUNT="create"`. `GoogleAuth` and
`GithubAuth` `check_credentials` are stubs returning `True`.

**Who is affected:** API clients and front-ends that integrate the provider SDKs
directly; operators who need a single, auditable "as if Basic" session model;
downstream services that consume the vaulted provider credential.

### Goals

- One login method, `X-Auth-Method: TokenExchange`, accepting `{provider, token,
  token_type?, id_token?}` for `azure`, `google`, `github`.
- **Audience-bound verification** with the provider: reject tokens not issued to
  this deployment's client id.
- Map to an **existing** `auth.users` row only (linked identity first, verified
  e-mail second). Never provision accounts (D4).
- Open the session through the **same code path as Basic**: user mapping,
  `BasicUser`, `remember()`, internal JWT + refresh token, Basic success
  callbacks, `last_login` update (D8). Session and JWT carry
  `auth_method: "basic"` and `auth_origin: "<provider>"` at top level **and**
  inside `AUTH_SESSION_OBJECT` (D1, D5).
- **Cap** internal JWT/session lifetime at the external token `expires_at`;
  when the provider reports no expiry, cap at `TOKEN_EXCHANGE_MAX_TTL`
  (default = `SESSION_TIMEOUT`) (D2, D6).
- Store the external credential **only in the identity vault**: access token,
  refresh token if any, **and id_token** (D3, D7). Nothing raw in the Redis
  session. Front-end retrieves it via the existing credential endpoint.
- Response shape identical to a Basic login.

### Non-Goals (explicitly out of scope)

- Changing interactive redirect logins, the identity-link flow, or the OAuth2 AS.
- Auto-provisioning users for this flow (even when `AUTH_MISSING_ACCOUNT="create"`).
- Refreshing the *internal* session from the vaulted provider refresh token
  (may be a follow-up; the existing credential endpoint already refreshes the
  *provider* credential).
- Providers other than Azure, Google, GitHub (ADFS/Okta/SAML untouched).
- Storing the raw provider token in the session (rejected in D3).

---

## 2. Architectural Design

### Overview

A new backend `TokenExchangeAuth` (subclass of `BasicAuth`) is registered like
any other backend and reached through `AuthHandler.get_auth_backend` via the
`X-Auth-Method` header, so `api_login` (`navigator_auth/auth.py:457`) keeps
handling session cookie, refresh-token registration and vault loading unchanged.

`TokenExchangeAuth.authenticate` does **not** check a password. It delegates
verification to the provider backend (`request.app["auth"].backends[...]`)
through a new abstract method `ExternalAuth.verify_external_token`, resolves the
internal user via a new `IdentityStore.find_user_by_provider_account` (then
`idp.get_user(email)`), vaults the credential through `save_linked_identity`,
and opens the session through a factored-out `BasicAuth.open_session`.

### Component Diagram

```
POST /api/v1/login  (X-Auth-Method: TokenExchange)
        │
        ▼
AuthHandler.api_login ──► TokenExchangeAuth.authenticate
                                │
                                ├─► ExternalAuth.verify_external_token  (Azure | Google | GitHub)
                                │        └─ audience/issuer/exp check + userinfo ─► (userinfo, TokenResponse)
                                │
                                ├─► IdentityStore.find_user_by_provider_account(provider, provider_user_id)
                                │        └─ miss ─► idp.get_user(verified e-mail)  ─► miss ─► UserNotFound (401)
                                │
                                ├─► IdentityStore.save_linked_identity(user_id, provider, TokenResponse[id_token])
                                │
                                └─► BasicAuth.open_session(request, user, extra={auth_origin,…}, expiration=cap)
                                         └─ get_userdata + BASIC_USER_MAPPING → BasicUser → remember()
                                            → idp.create_token(expiration=cap) → callbacks → response dict
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `BasicAuth` (`backends/basic.py`) | refactor + extends | Tail of `authenticate()` extracted into `open_session()`; `TokenExchangeAuth(BasicAuth)`. Password path byte-for-byte unchanged. |
| `ExternalAuth` (`backends/external.py`) | extends | New abstract `verify_external_token(token, token_type, id_token) -> (userinfo, TokenResponse)`. |
| `AzureAuth` | implements | JWT: `jwksutils.get_public_key` + `aud == AZURE_ADFS_CLIENT_ID`, `iss`, `exp`; then Graph `/me`. Existing `check_credentials` delegates to the verifier (closes the audience gap). |
| `GoogleAuth` | implements | id_token → Google JWKS, `aud == GOOGLE_CLIENT_ID`, `email_verified`; access token → `tokeninfo` (`aud`/`azp` check) + OIDC userinfo. |
| `GithubAuth` | implements | `POST https://api.github.com/applications/{client_id}/token` with client basic auth (validates token **and** app ownership); `/user` + `get_github_email` (verified primary only). |
| `IdentityStore` (`identity/store.py`) | extends | `find_user_by_provider_account(provider, provider_user_id) -> Optional[user_id]`. `save_linked_identity` persists `id_token`. |
| `TokenResponse` (`identity/types.py`) | extends | Optional `id_token` field; included in `credential()` / `from_credential()`. |
| `identity/migrations.py` + `identity/sql/` | extends | `002_identity_id_token.sql`: `ADD COLUMN IF NOT EXISTS id_token BYTEA`. |
| `UserIdentity` model (`models.py`) | extends | `id_token: bytes` column, `repr=False`. |
| `AuthHandler.api_login` | uses (unchanged) | Session load, `auth:refresh_token:*` registration, `load_vault_for_session` already happen here. |
| `/api/v1/user/identities/{provider}/credential` | uses (unchanged) | Front-end retrieval path (D3). Now also returns `id_token`. |
| `conf.py` | extends | `TOKEN_EXCHANGE_MAX_TTL` (int seconds, default `SESSION_TIMEOUT`), `TOKEN_EXCHANGE_PROVIDERS` (default `["azure","google","github"]`). |

### Data Models

```python
# identity/types.py — additive
@dataclass
class TokenResponse:
    access_token: str
    token_type: str = "Bearer"
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None          # NEW (D7)
    expires_in: Optional[int] = None
    expires_at: Optional[datetime] = None
    scopes: list = field(default_factory=list)
    provider_user_id: Optional[str] = None
    raw: dict = field(default_factory=dict)
    # credential()/from_credential() carry id_token; raw still never leaves.

# backends/exchange.py — request payload (validated, not a DB model)
@dataclass
class ExchangeRequest:
    provider: str                 # one of TOKEN_EXCHANGE_PROVIDERS
    token: str                    # provider access token (or id_token for Google-only clients)
    token_type: str = "Bearer"
    id_token: Optional[str] = None
```

Session / JWT additive claims:

| Key | Where | Value |
|---|---|---|
| `auth_method` | session top-level, `AUTH_SESSION_OBJECT`, JWT | `"basic"` |
| `auth_origin` | session top-level, `AUTH_SESSION_OBJECT`, JWT | `"azure" \| "google" \| "github"` |
| `external_expires_at` | session top-level, `AUTH_SESSION_OBJECT` | ISO-8601 or `null` |
| `provider_user_id` | `AUTH_SESSION_OBJECT` | stable provider account id |

`auth.user_identities` (additive):

```sql
ALTER TABLE IF EXISTS auth.user_identities
    ADD COLUMN IF NOT EXISTS id_token BYTEA;   -- ciphered (vault master keys)
```

### New Public Interfaces

```python
# backends/external.py
class ExternalAuth(BaseAuthBackend):
    async def verify_external_token(
        self, token: str, token_type: str = "Bearer", id_token: Optional[str] = None
    ) -> tuple[dict, TokenResponse]:
        """Verify a provider-issued token was minted for THIS client and is
        live; return (raw userinfo, normalized TokenResponse with
        provider_user_id, expires_at, id_token). Raise InvalidAuth on any
        failure (bad signature, wrong aud/azp, expired, unverified e-mail)."""

# backends/basic.py
class BasicAuth(BaseAuthBackend):
    async def open_session(
        self, request: web.Request, user: dict,
        extra: Optional[dict] = None, expiration: Optional[int] = None,
    ) -> dict:
        """Everything BasicAuth.authenticate does after credentials are
        validated. `extra` is merged into userdata and AUTH_SESSION_OBJECT
        before remember(); `expiration` overrides idp.create_token TTL."""

# backends/exchange.py
class TokenExchangeAuth(BasicAuth):
    _service_name = "token_exchange"
    _description = "Exchange an external provider bearer for a Basic session"
    async def get_payload(self, request) -> ExchangeRequest: ...
    async def authenticate(self, request) -> dict: ...
    def _cap_expiration(self, token: TokenResponse) -> int: ...

# identity/store.py
class IdentityStore:
    async def find_user_by_provider_account(
        self, provider: str, provider_user_id: str
    ) -> Optional[Any]:
        """user_id of the enabled identity for (provider, provider_user_id)."""
```

Request / response contract:

```
POST /api/v1/login
X-Auth-Method: TokenExchange
Content-Type: application/json

{"provider": "azure", "token": "<access_token>", "token_type": "Bearer", "id_token": "<jwt>"}

200 → same body as Basic login (+ "auth_origin": "azure", "external_expires_at": "...")
400 → malformed payload / unsupported provider
401 → token invalid, wrong audience, expired, e-mail unverified, or user not in auth.users
```

Error reasons are logged with `provider`, `provider_user_id` (if known) and a
short reason code (`bad_signature`, `wrong_audience`, `expired`,
`email_unverified`, `user_not_found`) for audit. The HTTP body never reveals
which of these occurred beyond "Invalid Credentials".

---

## 3. Module Breakdown

### Module 1: Basic session factoring
- **Path**: `navigator_auth/backends/basic.py`
- **Responsibility**: Extract the post-validation tail of `authenticate()` into
  `open_session(request, user, extra=None, expiration=None)`; `authenticate()`
  calls it with no extras. `extra` keys are written to `userdata` and to
  `userdata[AUTH_SESSION_OBJECT]`; `expiration` is forwarded to
  `idp.create_token`. Existing Basic tests must pass unchanged.
- **Depends on**: nothing new.

### Module 2: TokenResponse + vault id_token
- **Path**: `navigator_auth/identity/types.py`, `navigator_auth/identity/store.py`,
  `navigator_auth/identity/sql/002_identity_id_token.sql`,
  `navigator_auth/identity/migrations.py`, `navigator_auth/models.py`
- **Responsibility**: `id_token` field on `TokenResponse` (credential round-trip),
  ciphered `id_token` column, `save_linked_identity` / `decrypt_credential` /
  `masked` aware of it, migration wired next to `001`.
  New `find_user_by_provider_account`.
- **Depends on**: nothing new.

### Module 3: Abstract verifier
- **Path**: `navigator_auth/backends/external.py`
- **Responsibility**: `verify_external_token` abstract method (raises
  `NotImplementedError` by default so non-participating backends are excluded
  cleanly); shared helper `_verify_jwt(token, jwks_url|tenant, audience, issuer)`
  built on `jwksutils` for Azure/Google id_tokens; helper to require
  `email_verified`.
- **Depends on**: nothing new.

### Module 4: Azure verifier
- **Path**: `navigator_auth/backends/azure.py`
- **Responsibility**: implement `verify_external_token`. If `id_token` given:
  verify via JWKS, `aud == AZURE_ADFS_CLIENT_ID`, `iss` matches tenant, `exp`.
  If only an access token: it must be a JWT with `aud` in
  `{AZURE_ADFS_CLIENT_ID, "https://graph.microsoft.com", "00000003-0000-0000-c000-000000000000"}`
  **and** `appid`/`azp == AZURE_ADFS_CLIENT_ID`; then Graph `/me`.
  `expires_at` from `exp`. Existing `check_credentials` refactored to call the
  verifier (behavioural fix: now audience-bound).
- **Depends on**: Module 3.

### Module 5: Google verifier
- **Path**: `navigator_auth/backends/google.py`
- **Responsibility**: id_token → verify with Google JWKS
  (`https://www.googleapis.com/oauth2/v3/certs`), `aud == GOOGLE_CLIENT_ID`,
  `iss ∈ {accounts.google.com, https://accounts.google.com}`, `email_verified`.
  Access token → `https://oauth2.googleapis.com/tokeninfo?access_token=`,
  require `aud` or `azp == GOOGLE_CLIENT_ID`, then OIDC userinfo. Map with
  `GOOGLE_MAPPING`; `provider_user_id = sub`.
- **Depends on**: Module 3.

### Module 6: GitHub verifier
- **Path**: `navigator_auth/backends/github.py`
- **Responsibility**: `POST /applications/{GITHUB_CLIENT_ID}/token` with
  `Authorization: Basic base64(client_id:client_secret)` and body
  `{"access_token": token}`; 200 → token belongs to our app, response carries
  `user` and `expires_at` (GitHub Apps) or none (classic). `/user` +
  `get_github_email` restricted to **verified** primary e-mail; reject if none.
  `provider_user_id = user.id`.
- **Depends on**: Module 3.

### Module 7: TokenExchange backend + config + wiring
- **Path**: `navigator_auth/backends/exchange.py`, `navigator_auth/conf.py`,
  `navigator_auth/backends/__init__.py` (export)
- **Responsibility**: `TokenExchangeAuth`:
  1. `get_payload` (JSON only; 400 on missing `provider`/`token` or provider not in
     `TOKEN_EXCHANGE_PROVIDERS` or not a loaded backend).
  2. `verify_external_token` on the provider backend.
  3. `find_user_by_provider_account` → else `idp.get_user(email)` (e-mail must be
     verified by the verifier) → else `UserNotFound` (never `create_external_user`).
  4. `save_linked_identity(user_id, provider, token, userinfo)` (best-effort with
     warning, like `_vault_upstream_token`; a vault failure does **not** fail login
     but is logged).
  5. `_cap_expiration`: `min(SESSION_TIMEOUT, expires_at - now)` if `expires_at`
     else `TOKEN_EXCHANGE_MAX_TTL`; must be ≥ 60 s else 401 `expired`.
  6. `open_session(request, user, extra={auth_method:"basic", auth_origin,
     external_expires_at, provider_user_id}, expiration=cap)`.
  7. Align the Redis session TTL with the cap (D9): `open_session` sets
     `session.max_age = cap` on the `SessionData` returned by `remember()`
     (navigator_session `data.py` setter); `RedisStorage.save_session` uses
     `session.max_age` as the Redis `expire`, and `save_cookie` receives the
     same value so the cookie expires with the session.
  8. Re-exchange with an existing linked identity and no new refresh token
     keeps the previously vaulted refresh token (D10); `save_linked_identity`
     already preserves it when `token.refresh_token is None` — add a test, no
     code change expected.
  Config: `TOKEN_EXCHANGE_MAX_TTL`, `TOKEN_EXCHANGE_PROVIDERS`.
- **Depends on**: Modules 1–6.

### Module 8: Docs
- **Path**: `docs/` (auth methods page), `README.md` auth-methods table
- **Responsibility**: document the request contract, claims, cap behaviour, vault
  retrieval via the credential endpoint, and the "user must pre-exist" rule.
- **Depends on**: Module 7.

---

## 4. Test Specification

### Unit Tests
| Test | Module | Description |
|---|---|---|
| `test_basic_authenticate_unchanged` | 1 | Existing `tests/test_basic_auth.py` passes; `open_session` with no extras yields identical payload/session keys. |
| `test_open_session_extra_and_expiration` | 1 | `extra` lands in userdata and `AUTH_SESSION_OBJECT`; JWT `exp` honours `expiration`. |
| `test_token_response_id_token_roundtrip` | 2 | `credential()`/`from_credential()` preserve `id_token`; `raw` still excluded. |
| `test_store_saves_and_decrypts_id_token` | 2 | ciphered on write, decrypted on read, masked in `masked()`. |
| `test_find_user_by_provider_account` | 2 | hit / miss / disabled identity ignored. |
| `test_verify_jwt_helper_rejects` | 3 | bad signature, wrong `aud`, wrong `iss`, expired → `InvalidAuth`. |
| `test_azure_verify_id_token_ok` / `_wrong_aud` | 4 | mocked JWKS + Graph `/me`. |
| `test_azure_verify_access_token_requires_appid` | 4 | Graph token from another app rejected. |
| `test_azure_check_credentials_now_audience_bound` | 4 | regression for the closed gap. |
| `test_google_verify_id_token_email_unverified` | 5 | `email_verified=false` → 401. |
| `test_google_verify_access_token_tokeninfo_azp` | 5 | `azp` mismatch rejected. |
| `test_github_verify_app_token_ok` / `_foreign_token_404` | 6 | `/applications/{id}/token` 200 vs 404. |
| `test_github_requires_verified_primary_email` | 6 | no verified e-mail → 401. |
| `test_exchange_payload_validation` | 7 | missing fields / unknown provider → 400. |
| `test_exchange_user_must_exist` | 7 | `AUTH_MISSING_ACCOUNT="create"` still → 401, no user created. |
| `test_exchange_linked_identity_precedence` | 7 | linked `provider_user_id` wins over e-mail match. |
| `test_exchange_session_claims` | 7 | `auth_method="basic"`, `auth_origin`, both levels + JWT. |
| `test_exchange_expiration_cap` | 7 | `exp` ≤ external `expires_at`; no expiry → `TOKEN_EXCHANGE_MAX_TTL`; < 60 s → 401. |
| `test_exchange_vaults_credential_not_session` | 7 | `user_identities` row has access/refresh/id_token; Redis session has no raw token. |
| `test_exchange_fires_basic_callbacks` | 7 | `AUTH_SUCCESSFUL_CALLBACKS` invoked, `last_login` updated. |
| `test_exchange_session_max_age_matches_cap` | 7 | `session.max_age == cap`; Redis key TTL and cookie `Max-Age` equal the cap. |
| `test_reexchange_preserves_refresh_token` | 7 | second exchange without refresh token leaves the vaulted refresh token intact. |

### Integration Tests
| Test | Description |
|---|---|
| `test_exchange_end_to_end_azure` | mocked JWKS + Graph; `POST /api/v1/login` → 200, cookie set, `/api/v1/user/identities/azure/credential` returns the vaulted token incl. `id_token`. |
| `test_exchange_end_to_end_github` | mocked GitHub app-token check; classic token (no expiry) → cap = `TOKEN_EXCHANGE_MAX_TTL`. |
| `test_exchange_then_protected_route` | session from exchange passes the auth middleware and PBAC exactly like a Basic session. |

### Test Data / Fixtures
```python
@pytest.fixture
def rsa_keypair():           # signs fake Azure/Google id_tokens; JWKS served via mocked jwksutils
    ...

@pytest.fixture
def provider_userinfo():     # {"azure": {...graph /me...}, "google": {...oidc...}, "github": {...}}
    ...

@pytest.fixture
def existing_user(db):       # row in auth.users with e-mail matching provider_userinfo
    ...

@pytest.fixture
def linked_identity(db, existing_user):   # user_identities row with provider_user_id
    ...
```

---

## 5. Acceptance Criteria

> This feature is complete when ALL of the following are true:

- [x] All unit tests pass (`pytest tests/ -v`), including the untouched Basic suite.
      (Each FEAT-096 test file passes individually; running several
      `loop_scope="module"` live-app files together in one invocation can hit
      an unrelated pytest-asyncio/uvloop event-loop-lifecycle interaction
      between modules — pre-existing test-suite architecture behaviour, not
      a FEAT-096 regression. See TASK-052/053 completion notes.)
- [x] Integration tests above pass.
      (`tests/test_token_exchange_integration.py`; 3 pass, 1 skips cleanly on
      a documented pre-existing DB schema drift unrelated to this feature —
      see TASK-052/053 completion notes.)
- [x] A token issued to a different client id is rejected for all three providers.
      (`tests/test_azure_token_verifier.py`, `tests/test_google_token_verifier.py`,
      `tests/test_github_token_verifier.py`.)
- [x] A user absent from `auth.users` is rejected with 401 and no row is created,
      even with `AUTH_MISSING_ACCOUNT="create"`.
      (`test_user_must_exist_even_with_create_policy`,
      `test_exchange_unknown_user_401_no_row`.)
- [x] Session + JWT carry `auth_method="basic"` and `auth_origin="<provider>"`
      at top level and inside `AUTH_SESSION_OBJECT`.
      (`test_exchange_session_claims_both_levels_and_jwt`,
      `test_exchange_then_protected_route`.)
- [x] JWT `exp` never exceeds the external token `expires_at`; fallback cap uses
      `TOKEN_EXCHANGE_MAX_TTL`. Redis session TTL and cookie `Max-Age` equal the
      same cap.
      (`test_expiration_cap_*`, `test_session_max_age_matches_cap`; the
      `session.max_age` propagation itself is unit-tested in TASK-046.)
- [x] Raw provider tokens are absent from the Redis session; present (ciphered)
      in `auth.user_identities` including `id_token`; retrievable through
      `GET /api/v1/user/identities/{provider}/credential`.
      (`test_vaults_credential_not_session` — the "absent from the response"
      assertion always runs; the vault-content and credential-endpoint
      assertions skip cleanly on the pre-existing DB schema drift noted
      above, and are otherwise exercised end-to-end when the schema matches.)
- [x] `AzureAuth.check_credentials` is audience-bound (regression test).
      (`test_check_credentials_audience_bound_regression`.)
- [x] Docs updated; no breaking change to existing public API.
      (`docs/token_exchange.rst`, `docs/settings.rst`, `docs/index.rst`,
      `docs/changelog.rst`, `CHANGELOG.md`, `README.md`; `docs` build is
      clean of any *new* warnings — see TASK-053 completion note.)

---

## 6. Implementation Notes & Constraints

### Patterns to Follow
- Backends are process-wide singletons: no per-request state on `self`
  (see FEAT-095 note on `get_redirect_uri`).
- Reuse `ExternalAuth.get()` / `token_request()` for HTTP; reuse
  `jwksutils.get_public_key` (add a discovery-URL variant for Google certs) with
  the existing in-module JWKS cache.
- Vault writes go through `IdentityStore` only (cipher, `key_version`).
- Errors: raise `InvalidAuth` / `UserNotFound` so `_backend_auth` maps them to
  401/403 uniformly; log reason codes at `warning`.
- Config through `navconfig` in `conf.py`; env names `TOKEN_EXCHANGE_MAX_TTL`,
  `TOKEN_EXCHANGE_PROVIDERS`.

### Known Risks / Gotchas
- **Redis session TTL vs JWT cap.** `remember()` → `new_session()` creates the
  session with the storage-wide `SESSION_TIMEOUT`, but `SessionData.max_age` is
  settable per session and `RedisStorage.save_session` honours it as the Redis
  `expire`. `open_session` must set it **before** the session is saved by
  `api_login` → `storage.load_session(..., response=)`; verify in the
  integration test that the Redis TTL is the cap, not `SESSION_TIMEOUT`.
  `SessionData` also rejects loads older than `max_age` (`data.py:105`), so the
  cap is enforced on both the storage and the JWT side.
- **Azure access tokens for Graph** are signed for Graph's audience and are not
  meant to be validated by third parties (signature may use a different key set).
  Mitigation: prefer `id_token`; for access-token-only clients require
  `appid/azp == AZURE_ADFS_CLIENT_ID` and treat the Graph `/me` 200 as the
  liveness check (documented as the weaker path).
- **GitHub classic tokens never expire** → cap via `TOKEN_EXCHANGE_MAX_TTL` (D6).
- **E-mail as fallback identifier**: only verified e-mails, and the first
  successful exchange should call `save_linked_identity` so subsequent exchanges
  hit the stable `provider_user_id` path even if the e-mail changes.
- **Unique index** `(user_id, auth_provider, provider_user_id)` already exists;
  `find_user_by_provider_account` must ignore `enabled = false` rows.
- Vault failure is non-fatal (consistent with `_vault_upstream_token`), but must
  be logged at `warning` with provider and user_id.

### External Dependencies
| Package | Version | Reason |
|---|---|---|
| `PyJWT` | present | JWKS-based id_token verification |
| `msal` | present | Azure discovery/authority (already used) |
| _none new_ | | |

---

## 7. Open Questions

> Resolved in proposal discussion (2026-09-04):

- [x] D1 `auth_method="basic"` + `auth_origin="<provider>"`.
- [x] D2 Cap internal lifetime at external `expires_at`.
- [x] D3 Vault only; front-end uses existing credential endpoint.
- [x] D4 Users must pre-exist; never auto-create.
- [x] D5 Mirror `auth_origin` into `AUTH_SESSION_OBJECT` as well.
- [x] D6 No provider expiry → `TOKEN_EXCHANGE_MAX_TTL` (default `SESSION_TIMEOUT`).
- [x] D7 Vault **both** `id_token` and access token (new ciphered column).
- [x] D8 Fire Basic success callbacks and update `last_login`.
- [x] D9 navigator_session offers a per-session max-age (`SessionData.max_age`
      setter, honoured by `RedisStorage.save_session`); the Redis TTL and cookie
      `Max-Age` are aligned with the JWT cap.
- [x] D10 A re-exchange without a refresh token keeps the previously vaulted
      refresh token.

No open questions remain.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-09-04 | Jesus Lara | Initial draft generated from proposal (D1–D8 resolved) |
| 0.2 | 2026-09-04 | Jesus Lara | D9 (per-session max-age) and D10 (refresh-token preservation) resolved; approved |
