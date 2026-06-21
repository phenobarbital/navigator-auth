# Brainstorm: OAuth2 Token Introspection (RFC 7662) + Device Authorization Grant (RFC 8628)

**Date**: 2026-06-22
**Author**: Jesus Lara
**Status**: accepted
**Recommended Option**: A

> **Naming note:** the invocation slug `device-authorization-grant-rfc7662` conflates two
> distinct specs. **RFC 7662 = OAuth 2.0 Token Introspection**; **RFC 8628 = OAuth 2.0 Device
> Authorization Grant**. Both were explicit **Non-Goals** of FEAT-093
> (`sdd/specs/oauth2-3lo-implementation.spec.md` §1, lines 61–62). This brainstorm covers
> *both*, in one scope, as the natural follow-on once FEAT-093 lands.

---

## Problem Statement

FEAT-093 turns `navigator-auth`'s OAuth2 surface into a real 3LO server (owner-binding, PKCE
S256, refresh rotation, `client_uid`, `jti` tracking, `OauthGrant` consent records, ABAC scope
composition). It deliberately deferred two RFC surfaces that production OAuth2 deployments
expect:

1. **Token Introspection (RFC 7662)** — resource servers (and gateways/proxies) need a
   standard `POST /oauth2/introspect` to ask the authorization server *"is this token still
   valid, and what does it authorize?"*. Today the only validation path is each resource server
   decoding the JWT itself (`APIKeyAuth.decode_token`) plus a per-request `jti` revocation check
   — there is **no standard, language-agnostic endpoint** a third-party or non-Python resource
   server can call. Without it, external/polyglot resource servers cannot participate in
   revocation, and there is no canonical introspection contract.

2. **Device Authorization Grant (RFC 8628)** — input-constrained clients (CLI tools, IoT,
   smart-TV, headless agents) cannot run a browser redirect flow. They need
   `POST /oauth2/device_authorization` → show the user a short `user_code` + `verification_uri`
   → poll `POST /oauth2/token` until the user approves on a second device. Today there is **no
   way to authenticate such clients**; they are forced into `client_credentials` (which under
   FEAT-093 is a *service principal*, not a real user) or into embedding browser flows they
   cannot host.

**Who is affected:** resource-server authors and platform/gateway operators (introspection);
CLI/IoT/TV integrators and their end users (device grant).

**Why now:** FEAT-093 establishes exactly the primitives both features need (`client_uid`,
`AccessTokenStorage`+`jti`, `RefreshTokenStorage` with rotation/revoke, `GrantStorage` for
consent-skip, owner-binding, the `OAUTH2_CLIENT_STORAGE` storage factory). Building these now,
on top of that foundation, is cheap and consistent; building them before/around it would mean
rework.

---

## Constraints & Requirements

- **Hard prerequisite on FEAT-093 (target state).** Introspection and device grant build on
  FEAT-093's `client_uid` (opaque public id), `AccessTokenStorage` (`jti` tracking + revocation
  truth), `RefreshTokenStorage` (rotation/reuse/`revoke_chain`), `GrantStorage` (consent + skip),
  owner-binding (`user_id` from the authenticated session, never `client.user`), and the
  `get_token_storages(backend)` factory honoring `OAUTH2_CLIENT_STORAGE`. **Do not merge until
  FEAT-093 has landed** (its tasks TASK-023…030 are currently in `sdd/tasks/active/`).
- **No new runtime dependency.** Like FEAT-093, use stdlib only: `secrets` (user_code /
  device_code generation, `secrets.compare_digest`), `hashlib`/`hmac`, `uuid`; persistence via
  existing `asyncdb`/`redis`; JWT via existing `pyjwt`. (QR for `verification_uri_complete` is a
  *string* the client renders — no server-side QR library.)
- **RFC 7662 §2.2 / §4 privacy:** `/introspect` callers MUST be authenticated; an inactive or
  unknown token MUST return `200 {"active": false}` and leak nothing else; a confidential client
  may only introspect tokens **issued to itself** (per Round-2 decision).
- **RFC 8628 §3.2/§3.5 semantics:** correct `device_code`/`user_code`/`verification_uri`/
  `verification_uri_complete`/`expires_in`/`interval`; token endpoint returns
  `authorization_pending`, `slow_down`, `access_denied`, `expired_token` per §3.5.
- **Owner-binding preserved.** The device grant MUST bind the issued token to the *user who
  authenticated and consented at `verification_uri`*, with the same `user_id` discipline as the
  auth-code flow — never `client.user`.
- **Consistency with FEAT-093 patterns:** storage ABC + memory/redis/postgres tiers + factory;
  Pydantic v2 models in `oauth2/models.py`; asyncdb `Model`/`Column` with `class Meta: schema =
  "auth"`; `OAUTH_*` config keys in `conf.py`; async-first; `self.logger`; no secrets logged;
  constant-time comparisons.
- **Security hardening (device):** RFC default `device_code` TTL 600s, `interval` 5s, `slow_down`
  on too-fast polling; human-legible `user_code` from an unambiguous alphabet
  (`BCDFGHJKLMNPQRSTVWXZ`, no vowels/look-alikes), with rate-limiting + lockout on `user_code`
  entry to resist brute force.

---

## Options Explored

### Option A: Incremental in-place extension (mirror FEAT-093 Option A)

Add the two endpoints directly to `Oauth2Provider` and add **one** new storage
(`DeviceCodeStorage`) following the existing storage-factory pattern. Introspection is a thin
read path over what FEAT-093 already built; the device grant reuses the existing login/consent
machinery and the existing `authorization_code` token-issuance path.

- **Introspection** (`POST /oauth2/introspect`): authenticate the caller as a confidential
  client (`client_id`+`client_secret`, reusing FEAT-093's confidential-client check). Decode the
  presented token via `IdentityProvider.decode_token`; if it's an access token, verify `jti` is
  not revoked via `AccessTokenStorage` (real-time, no cache — this endpoint *is* the revocation
  authority); if it's a refresh token, look it up in `RefreshTokenStorage` (rotated/revoked ⇒
  inactive). Enforce "same client only": the token's `client_id`(uid) must equal the
  authenticated caller's. Return `{"active": false}` for anything invalid/expired/revoked/
  foreign; nothing else.
- **Device grant**: `POST /oauth2/device_authorization` issues `device_code`+`user_code`, stores
  a pending `OauthDeviceCode` (bound to client + requested scopes). User visits
  `verification_uri`(`_complete`), authenticates via the existing `/oauth2/login`, and approves
  via the existing `/oauth2/consent` (reusing `GrantStorage` for consent-skip). Approval stamps
  the device record with `user_id` + granted scopes. The client's polling
  `grant_type=urn:ietf:params:oauth:grant-type:device_code` at `/oauth2/token` reuses the same
  token-minting code path as `authorization_code` (owner-bound token, refresh iff
  `offline_access`).

✅ **Pros:**
- Maximum reuse of FEAT-093 primitives; smallest new surface; consistent with the just-merged
  architecture and its review history.
- Stdlib-only; no new dependency; no framework refactor.
- Device flow inherits owner-binding, PKCE-grade rigor, consent-skip, and refresh rotation *for
  free* by routing through existing code.
- Introspection is mostly read-only glue — low risk, easy to test in isolation.

❌ **Cons:**
- Adds more responsibility to the already-large `backend.py` (`Oauth2Provider`).
- Tightly coupled to FEAT-093 internals — must wait for it to land (accepted constraint).

📊 **Effort:** Medium

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| *(none new)* | — | `secrets` (codes + `compare_digest`), `hashlib`/`hmac`, `uuid` stdlib; `redis`/`asyncdb` existing; `pyjwt` existing |

🔗 **Existing Code to Reuse:**
- `navigator_auth/backends/oauth2/backend.py` — `Oauth2Provider.configure` (route registration + `AUTH_EXCLUDE_LIST_KEY`), `token_request`, `consent`, `auth_login`, `get_payload`, `auth_error`, `prepare_url`.
- `navigator_auth/backends/oauth2/code_backend.py` — storage ABC + `get_token_storages` factory (FEAT-093) as the template for `DeviceCodeStorage`; `RefreshTokenStorage`/`AccessTokenStorage` for introspection lookups.
- `navigator_auth/backends/oauth2/client_backend.py` — `ClientStorage.get_client(client_uid)` for caller/client resolution.
- `navigator_auth/backends/oauth2/models.py` — `OAuthClient`, `OauthAccessTokenRecord`, `OauthRefreshToken`, `OauthGrant` patterns for the new `OauthDeviceCode` model.
- `navigator_auth/backends/idp/__init__.py` — `create_token` (4-tuple, `jti` via `data`, additive `audience`), `decode_token` (introspection decode).
- `navigator_auth/backends/oauth2/ddl.sql` — extend with `auth.oauth_device_codes`.
- `navigator_auth/conf.py` — `OAUTH_*` config pattern.

---

### Option B: Adopt a spec-compliant OAuth library (Authlib)

Replace hand-rolled endpoint logic with [`authlib`](https://authlib.org)'s
`AuthorizationServer`, using its built-in `IntrospectionEndpoint` and `DeviceAuthorizationEndpoint`
/ `DeviceCodeGrant`.

✅ **Pros:**
- RFC 7662 / RFC 8628 correctness maintained by an established library.
- Future RFCs (token revocation, token exchange) available from the same toolkit.

❌ **Cons:**
- **Severe impedance mismatch** with FEAT-093's custom `IdentityProvider`, `client_uid`,
  `AccessTokenStorage`/`jti`, `GrantStorage`, owner-binding, and ABAC composition — Authlib would
  want to own token minting, client model, and storage, duplicating/fighting what FEAT-093 just
  built.
- New runtime dependency (violates the project's stdlib-only stance for OAuth2).
- Authlib is framework-oriented (Flask/Django/Starlette integrations); the aiohttp path is
  thinner and would still need substantial glue.
- Large blast radius for two endpoints; high regression risk against FEAT-093's security tests.

📊 **Effort:** High

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `Authlib` | RFC 7662/8628 endpoints + grants | `~=1.3`; mature, but aiohttp integration is not first-class |

🔗 **Existing Code to Reuse:**
- Little — this option largely *replaces* `backend.py`/`idp` token logic rather than reusing it.

---

### Option C: Extract a pluggable grant-handler + endpoint framework

Refactor `Oauth2Provider` into a small internal framework: a registry of `GrantHandler`s
(`authorization_code`, `client_credentials`, `refresh_token`, **`device_code`**) and
`ProtocolEndpoint`s (`token`, `authorize`, **`introspect`**, **`revoke`**, **`device_authorization`**),
each a self-contained, independently testable unit. Then implement introspection and device grant
as plugins.

✅ **Pros:**
- Clean extensibility for *future* surfaces (CIBA, token exchange, DCR) — the FEAT-093 non-goals
  list keeps growing.
- Shrinks the monolithic `backend.py`; better unit isolation per grant/endpoint.

❌ **Cons:**
- Over-engineered for two endpoints; the abstraction must be *retrofitted* onto FEAT-093's
  freshly written, non-pluggable code, risking churn and merge contention on hot files.
- Higher upfront effort with no immediate functional payoff; speculative generality.
- Larger review surface; competes with the just-stabilized FEAT-093 architecture.

📊 **Effort:** High

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| *(none new)* | — | Pure internal refactor |

🔗 **Existing Code to Reuse:**
- All of `backends/oauth2/*` — but *re-shaped*, not extended in place.

---

### Option D (unconventional): Introspection as a thin `decode_token` wrapper + device grant via auth-code translation

Lean on two observations to write almost no new flow code:

1. **Access tokens are already self-contained JWTs with `jti` tracking.** So introspection for
   access tokens is just: `decode_token` → check `jti` not revoked in `AccessTokenStorage` →
   project the JWT claims into the RFC 7662 response. No new storage, no new validation engine —
   introspection becomes a ~40-line read endpoint reusing the resource-server logic
   `APIKeyAuth` already runs per request.
2. **An approved device authorization is structurally an authorization code.** So instead of a
   parallel device token path, when the user approves at `verification_uri`, mint a normal
   internal `OauthAuthorizationCode` (owner-bound, scopes set) and store it keyed by the
   `device_code`. The polling `device_code` token request then **delegates to the existing
   `authorization_code` exchange verbatim** (single-use, owner-binding, refresh-iff-offline,
   rotation) — the device grant becomes a thin adapter, not a duplicate grant.

✅ **Pros:**
- Least new code of any option; device grant inherits *every* auth-code guarantee automatically,
  eliminating drift between two token paths.
- Introspection reuses the exact resource-server validation already trusted in production.
- Still stdlib-only; smallest test/security surface.

❌ **Cons:**
- "device_code wraps an auth-code" is a clever indirection that future maintainers must
  understand (mitigated by a focused docstring + tests); slightly leaky abstraction (a stored
  auth-code with no `redirect_uri`).
- Refresh-token introspection still needs a `RefreshTokenStorage` lookup (not pure decode), so
  the "pure wrapper" elegance is partial.

📊 **Effort:** Low–Medium

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| *(none new)* | — | stdlib + existing infra |

🔗 **Existing Code to Reuse:**
- `OauthAuthorizationCode` + `AuthorizationCodeStorage` (auth-code path) — *reused as the device
  approval carrier*; `decode_token` + `AccessTokenStorage` (introspection); `APIKeyAuth` resource-
  server validation logic.

---

## Recommendation

**Option A** is recommended, **tactically adopting Option D's two shortcuts**:

- Implement introspection as a thin read path over `decode_token` + `AccessTokenStorage`/
  `RefreshTokenStorage` (D-1), rather than a new validation engine.
- Implement the device grant's token issuance by **reusing the existing `authorization_code`
  exchange** once the user approves (D-2), rather than a fully parallel token path — but keep a
  dedicated `DeviceCodeStorage` + `OauthDeviceCode` model for the *pending/polling* state (the
  part auth-code has no equivalent for: `user_code`, polling `interval`, `slow_down`, lockout).

This mirrors FEAT-093's own choice (Option A "incremental in-place hardening, stdlib-only,
isolate pure helpers") and so stays architecturally consistent with the code these features
depend on. We reject **B** (new dependency + impedance mismatch with the custom IdP/ABAC stack
FEAT-093 just built), and **C** (speculative framework refactor whose churn on hot files
outweighs its payoff for two endpoints — revisit only if CIBA/token-exchange/DCR actually get
scheduled). The trade-off we accept: `backend.py` grows further and we stay coupled to FEAT-093
internals — acceptable because the alternative (a generic framework or an external library)
costs more in refactor risk and review surface than two well-scoped endpoints justify.

---

## Feature Description

### User-Facing Behavior

**Token Introspection (RFC 7662):**
- A resource server authenticates as a confidential client and calls
  `POST /oauth2/introspect` with `token=<access-or-refresh-token>` and optional
  `token_type_hint`.
- Response is always `200`. For a valid token issued to *that* client:
  `{"active": true, "scope": "...", "client_id": "<client_uid>", "username": "...",
  "token_type": "Bearer", "exp": ..., "iat": ..., "sub": ..., "aud": ...}`.
- For anything invalid, expired, revoked (`jti`/refresh chain), or **issued to a different
  client**: `{"active": false}` and nothing else.

**Device Authorization Grant (RFC 8628):**
- A CLI/IoT/TV client calls `POST /oauth2/device_authorization` with `client_id` (+ `scope`).
- It receives `device_code`, a short human `user_code` (e.g. `BCDF-GHJK`), `verification_uri`
  (e.g. `https://host/oauth2/device`), `verification_uri_complete` (same URL with `?user_code=…`
  for a QR/deeplink), `expires_in` (default 600s), and `interval` (default 5s).
- The device shows the user the `user_code` + URL (and/or a QR of `verification_uri_complete`).
- The user opens the URL on a phone/laptop, logs in via the existing `/oauth2/login`, and
  approves/denies the requested scopes via the existing consent screen.
- Meanwhile the device polls `POST /oauth2/token` with
  `grant_type=urn:ietf:params:oauth:grant-type:device_code` + `device_code` + `client_id`.
  Responses: `authorization_pending` (not yet approved), `slow_down` (polling too fast),
  `access_denied` (user denied), `expired_token` (TTL elapsed), or finally the normal token
  response (owner-bound access token; refresh token iff `offline_access` granted).

### Internal Behavior

- **Introspection:** authenticate caller (confidential client check, reused from FEAT-093) →
  `decode_token` → branch on token type → access: real-time `jti` revocation check via
  `AccessTokenStorage` (no cache; this endpoint is the authority); refresh: `RefreshTokenStorage`
  lookup (rotated/revoked ⇒ inactive) → enforce caller==token `client_id`(uid) → project claims
  or `{"active": false}`. New route registered in `configure`; added to `AUTH_EXCLUDE_LIST_KEY`.
- **Device authorization request:** validate client + filter `scope` to client allow-list →
  generate `device_code` (high-entropy `secrets`) and `user_code` (unambiguous alphabet) →
  persist `OauthDeviceCode{status=pending, client_id, scopes, expires_at, interval,
  last_polled_at}` via `DeviceCodeStorage` → return the RFC 8628 payload with
  `verification_uri_complete`.
- **Verification (user side):** `GET/POST /oauth2/device` accepts/normalizes `user_code`
  (case-insensitive, hyphen-stripped) under rate-limit/lockout → requires authenticated session
  (reuse `/oauth2/login`) → reuse `/oauth2/consent` (with `GrantStorage` consent-skip) → on
  approval stamp the device record `status=approved, user_id, granted_scopes` (Option-D: also
  mint an internal owner-bound auth-code carrier); on denial `status=denied`.
- **Device token polling:** look up `device_code` → enforce `interval` (`slow_down` if too soon,
  update `last_polled_at`) → branch on status: `pending`→`authorization_pending`,
  `denied`→`access_denied`, expired→`expired_token`, `approved`→ **delegate to the existing
  authorization_code issuance** (owner-bound token, refresh iff `offline_access`), then mark the
  device_code consumed (single-use).
- **Config:** new `OAUTH_DEVICE_*` keys (`OAUTH_DEVICE_CODE_TTL=600`,
  `OAUTH_DEVICE_POLL_INTERVAL=5`, `OAUTH_DEVICE_USER_CODE_LENGTH=8`,
  `OAUTH_DEVICE_VERIFICATION_URI`, rate-limit/lockout thresholds) and any introspection toggles,
  following FEAT-093's `conf.py` pattern.

### Edge Cases & Error Handling

- **Introspection:** missing/duplicate `token` param ⇒ `400 invalid_request`; unauthenticated or
  bad client creds ⇒ `401 invalid_client` (`WWW-Authenticate`); valid token but foreign client ⇒
  `{"active": false}` (no leak); expired-but-not-revoked ⇒ `{"active": false}`; refresh token
  whose chain was reuse-revoked ⇒ `{"active": false}`; never log the raw token.
- **Device:** unknown/expired `device_code` ⇒ `expired_token`/`invalid_grant`; polling faster than
  `interval` ⇒ `slow_down` (and bump the required interval per §3.5); `user_code` brute force ⇒
  rate-limit + temporary lockout, generic error (don't reveal validity); `user_code` collision at
  generation ⇒ regenerate; user approves then `device_code` reused after success ⇒ rejected
  (single-use); scope requested outside client allow-list ⇒ `invalid_scope`; refresh requested
  without `offline_access` ⇒ access-only (no refresh), consistent with FEAT-093 D5.
- **Cross-cutting:** all new endpoints excluded from global auth middleware where appropriate;
  constant-time comparisons for `device_code`/`user_code`/`client_secret`; storage tier honors
  `OAUTH2_CLIENT_STORAGE` (tests use `memory`).

---

## Capabilities

### New Capabilities
- `oauth2-token-introspection`: RFC 7662 `POST /oauth2/introspect` endpoint, confidential-client
  authenticated, same-client-only, real-time revocation truth, `{active:false}` for invalid.
- `oauth2-device-authorization-grant`: RFC 8628 `POST /oauth2/device_authorization` +
  `/oauth2/device` verification + `device_code` polling grant on `/oauth2/token`, owner-bound,
  consent-driven, `verification_uri_complete`, anti-brute-force.

### Modified Capabilities
- `oauth2-3lo-implementation` (FEAT-093): extended (not changed) — adds two endpoints + one
  storage; reuses `client_uid`, `AccessTokenStorage`/`jti`, `RefreshTokenStorage`, `GrantStorage`,
  owner-binding, the storage factory, and the auth-code issuance path.

---

## Impact & Integration

| Affected Component | Impact Type | Notes |
|---|---|---|
| `Oauth2Provider` (`backends/oauth2/backend.py`) | modifies | New routes (`/oauth2/introspect`, `/oauth2/device_authorization`, `/oauth2/device`); new `device_code` branch in `token_request`; reuse `consent`/`auth_login`/issuance |
| `oauth2/models.py` | modifies | New `OauthDeviceCode` (Pydantic v2); reuse `OauthAccessTokenRecord`/`OauthRefreshToken`/`OauthGrant` for introspection lookups |
| `oauth2/code_backend.py` | extends | New `DeviceCodeStorage` ABC + memory/redis/postgres tiers; register in `get_token_storages` factory |
| `IdentityProvider` (`backends/idp/__init__.py`) | depends on | `decode_token` (introspection); `create_token` 4-tuple with `jti`/`audience` (device issuance) — no signature change |
| `ClientStorage` trio (`oauth2/client_backend.py`) | depends on | `get_client(client_uid)` for caller/client resolution |
| `Client` model + `oauth2/ddl.sql` | extends | New `auth.oauth_device_codes` table (device_code, user_code, client_id FK→PK, user_id, scopes, status, timestamps, poll state) |
| `conf.py` | extends | `OAUTH_DEVICE_*` keys + introspection toggles |
| `examples/oauth2_server.py` | modifies | Demonstrate device flow + introspection with the test client |
| `documentation/oauth.md` | modifies | Document `/introspect` + device grant |
| `tests/` | extends | Unit + integration (introspection active/inactive/foreign-client; device pending/slow_down/approve/deny/expire/brute-force; owner-binding regression) |

---

## Open Questions

- [ ] Should `/introspect` also accept **bearer** auth from a service token (scope `introspect`)
      in addition to client_credentials, for resource servers that don't have their own client
      secret? Round-1 chose client_credentials; confirm whether a bearer fallback is needed. — *Owner: Jesus Lara*
- [ ] Device verification screen: build a **dedicated `/oauth2/device` page** (user_code entry +
      confirmation), or redirect into the existing consent UI with `user_code` pre-filled via
      `verification_uri_complete`? — *Owner: Jesus Lara*
- [ ] Exact **rate-limit/lockout policy** for `user_code` entry (attempts, window, lockout
      duration) and where counters live (Redis vs in-process). — *Owner: Jesus Lara*
- [ ] Does the device grant require **PKCE** (RFC 8628 allows it for public clients)? FEAT-093
      mandates PKCE S256 for public clients on auth-code — mirror it here? — *Owner: Jesus Lara*
- [ ] Should introspection responses include FEAT-093 **ABAC scope** detail (effective scopes)
      or stay strictly RFC 7662 claims? — *Owner: Jesus Lara*

---

## Parallelism Assessment

- **Internal parallelism:** *Moderate.* The two features are largely independent surfaces and
  could in principle be split into two worktrees: introspection touches mostly read paths
  (`backend.py` route + `decode_token`/storage reads), while the device grant adds a model +
  storage + routes + a `token_request` branch. They overlap on `backend.py` `configure()` (route
  registration) and `code_backend.py` (storage factory).
- **Cross-feature independence:** **Hard dependency on FEAT-093** — both consume `client_uid`,
  `AccessTokenStorage`/`jti`, `RefreshTokenStorage`, `GrantStorage`, owner-binding, and the
  storage factory. Must not start integration until FEAT-093 merges. No other in-flight spec
  conflicts (FEAT-092 per-tenant scoping is merged; ABAC files are untouched by this feature
  except indirectly via the open ABAC-scope question).
- **Recommended isolation:** `per-spec` (one worktree, sequential). Despite moderate internal
  parallelism, both features edit the same hot files (`backend.py`, `code_backend.py`,
  `models.py`, `ddl.sql`, `conf.py`); two worktrees would collide on `configure()` and the
  storage factory. Sequence introspection first (smaller, read-only, low risk) then device grant.
- **Rationale:** Shared hot files + a common hard prerequisite make merge contention the
  dominant cost; sequential execution in one worktree, committing per surface (introspection →
  device authorization request → verification → device token polling), is cleaner than parallel
  isolation here.
