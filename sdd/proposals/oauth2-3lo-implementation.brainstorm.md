# Brainstorm: Production-grade 3LO (Three-Legged OAuth2) for `navigator-auth`

**Date**: 2026-06-22
**Author**: Jesus Lara
**Status**: exploration
**Recommended Option**: A

---

## Problem Statement

`navigator-auth` already exposes an OAuth2 Authorization Server (`Oauth2Provider` in
`navigator_auth/backends/oauth2/backend.py`) with the full `authorize → login → consent →
code → token` surface and `authorization_code` / `client_credentials` / `refresh_token`
grants. It *looks* three-legged but is **not a valid 3LO server**:

- **The resource owner is never bound to the grant.** Tokens derive the user from
  `client.user` (`backend.py:506` for `client_credentials`, `backend.py:549` —
  `user = rt.client_id.user` — for refresh). The token therefore represents *the client's
  static owner*, not *whoever logged in and consented*. This is the central security defect
  (spec §1): any user of a client receives a token bound to a different user.
- **Validation gaps (B1–B5):** `expires_in` is returned as an absolute UTC timestamp
  instead of seconds (`create_token` returns an absolute `exp`); the auth-code branch never
  checks `client_secret` for confidential clients; `redirect_uri` is membership-checked but
  not exact-match-guarded against open redirect; `response_type` is unvalidated; the
  `used`/`used_at` single-use flags on authorization codes exist but are never enforced.
- **Refresh handling is unsafe:** no rotation, no reuse detection, no absolute lifetime;
  refresh tokens are Redis-only with a 365-day default and carry no owner.
- **Stubs:** `userinfo`, `logout`, `finish_logout` are `pass`.
- **Scopes are decorative:** captured and echoed but never filtered to a client allow-list,
  never enforced at the resource server, and never composed with the existing ABAC engine —
  so a token's delegated authority can silently exceed what the user could do unaided.

**Who is affected:** end users (their identity is mis-bound to tokens — a real
authorization vulnerability), third-party/app developers integrating via OAuth2 (broken
PKCE, no rotation, no revocation, no `userinfo`), and platform/security operators (no
per-app revocation surface, no audit trail of grants).

**Why now:** the project is moving toward Atlassian-style delegated access where issued
tokens must encode and be verifiable against the **(resource owner + client + granted
scopes)** triple, and scopes must **compose with ABAC** (effective permission =
`granted_scopes ∩ user_ABAC_permissions`).

---

## Constraints & Requirements

- **Correctness target (non-negotiable):** every access/refresh token MUST encode and be
  verifiable against `user_id` (authenticated owner), `client_id`, and granted `scopes`.
  `user_id` MUST originate from the session user who logged in at `/oauth2/login`, **never**
  from `client.user`.
- **Keep the IdP contract stable.** `IdentityProvider` (`backends/idp/__init__.py`) is
  shared. Note: `create_token(data, issuer=None, expiration=None)` actually returns a
  **4-tuple** `(jwt_token, refresh_token_str, exp, scheme)` where `exp` is an absolute UTC
  timestamp — the spec assumed a 3-tuple. Do not break existing callers.
- **Pydantic v2** models (`model_dump`/`model_validate`); persistence via `asyncdb`
  `Model`/`Column` with `class Meta: schema = "auth"`.
- **Storage selection reuses `OAUTH2_CLIENT_STORAGE`** (memory/redis/postgres). Grants and
  refresh tokens persist durably via the same setting; authorization codes stay Redis-only
  (short TTL) but MUST now carry `user_id`, `code_challenge`, `code_challenge_method`. A
  **memory** implementation of grant/refresh/code storage is required so tests run without
  external deps.
- **PKCE: S256 only for public clients** (`OAUTH_REQUIRE_PKCE_PUBLIC=True` ⇒ reject
  `plain`). Confidential clients authenticate with `client_secret`.
- **jti access-token tracking is in scope.** Every OAuth2-issued token carries a `jti`;
  `{jti, user_id, client_id, scopes, expires_at, revoked}` is persisted, and the
  resource-server bearer backend checks revocation **on every request** (mitigated by a
  short-TTL in-process cache).
- **No production data migration needed** — OAuth2 is not yet live with real tokens; enforce
  the new schema going forward (hard requirement of `user_id`).
- **ABAC cache-key fix is global.** `PolicyEvaluator._make_cache_key`
  (`abac/policies/evaluator.py`) must include normalized `scopes` + `client_id` for **all**
  evaluations (session users get `scopes=frozenset()`, `client_id=None` — stable, no
  collision). This sits on the hot path for every ABAC decision in the system.
- **Constant-time comparison** (`hmac.compare_digest`) for `client_secret` and PKCE; no
  secrets in logs.
- **Scope.** Full spec, P0–P5, delivered as one feature in a single per-spec worktree
  (shared contention on `backend.py`, `models.py`, `evaluator.py` makes parallel worktrees
  risky).
- **Non-goals (do not build):** OIDC/`id_token`, RFC 7662 introspection, Device grant,
  DPoP/mTLS, Dynamic Client Registration.

---

## Options Explored

### Option A: Incremental in-place hardening (hand-rolled, phased P0–P5)

Extend the existing modules directly, following the spec's phase order. Add `user_id` to
`OauthAuthorizationCode` and `OauthRefreshToken`; thread it session → consent → code →
token → refresh. Fix B1–B5 in place. Add PKCE S256 verification using only the stdlib
(`hashlib`, `base64`, `hmac`). Mirror the existing `ClientStorage` ABC to add
`GrantStorage`, an extended `RefreshTokenStorage`, an access-token (`jti`) store, and a
**memory** code store, all selected by `OAUTH2_CLIENT_STORAGE`. Append DDL to
`ddl.sql`. Implement `userinfo`/`logout`/`revoke`/grants API. For P5, surface scopes into
`EvalContext`, add `@scope_required`/`Guardian.has_scope`, add `Policy.scopes` across all
policy types, and fix the decision cache key.

This is the spec authored as-is: the spec already names every file, symbol, and line and
maps each change to an existing pattern.

✅ **Pros:**
- Lowest integration risk — every change lands on a pattern that already exists
  (`ClientStorage` ABC, Redis storages, asyncdb models, IdP token minting, ABAC decorators).
- No new runtime dependency; PKCE/jti/rotation are all stdlib (`hashlib`, `hmac`, `secrets`,
  `uuid`). Smallest supply-chain and audit surface for security-critical code.
- Phase boundaries (P0→P5) map cleanly to SDD tasks; each phase is independently testable
  and the bound-`user_id`-survives-refresh regression test gates correctness early.
- Full control over the ABAC composition (`scopes ∩ ABAC`, cache key, `client_credentials`
  service principals) — no impedance mismatch with a third-party token model.

❌ **Cons:**
- We own RFC correctness ourselves (PKCE, rotation/reuse detection, RFC 7009 revoke). Must
  be covered by an explicit, adversarial test matrix (spec §10) rather than trusting a
  vetted library.
- More hand-written code than adopting a library; long-tail RFC edge cases are our risk.

📊 **Effort:** High (but lowest-risk High — it is mostly disciplined extension)

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| stdlib `hashlib` + `base64` + `hmac` | PKCE S256 verify, constant-time secret compare | No dep; `hmac.compare_digest` already required by spec §9 |
| stdlib `secrets` | Refresh-token entropy | Already used by `IdentityProvider.create_refresh_token()` |
| stdlib `uuid` | `jti`, `grant_id` | Pydantic v2 `UUID` fields already in models |
| `pydantic` v2 | Model validation | Already the project standard |
| `asyncdb` | Postgres grant/refresh/jti persistence | Already used by `PostgresClientStorage` / `ModelPolicy` |
| `redis` (existing client) | Auth-code + redis storage tier | Already used in `code_backend.py` |

🔗 **Existing Code to Reuse:**
- `navigator_auth/backends/oauth2/client_backend.py` — `ClientStorage` ABC + memory/redis/pg
  trio is the exact template for `GrantStorage` and the extended token stores.
- `navigator_auth/backends/oauth2/code_backend.py` — `AuthorizationCodeStorage` /
  `RefreshTokenStorage` to extend (add `user_id`, rotation, revoke/`revoke_chain`, memory tier).
- `navigator_auth/backends/idp/__init__.py` — `create_token` (extend to emit `jti`/`aud` and
  expose `expires_in` seconds), `create_refresh_token`, `authenticate_credentials`,
  `decode_token`.
- `navigator_auth/backends/api.py` — `APIKeyAuth` bearer path (`get_token_info`,
  `check_credentials`, `auth_middleware`) is where `userinfo['scopes']`/`client_id` get
  populated and where the per-request `jti` revocation check goes.
- `navigator_auth/abac/decorators.py` — `groups_protected` is the template for
  `@scope_required`; `navigator_auth/abac/guardian.py` `get_user`/`_get_userinfo` for
  `has_scope`.
- `navigator_auth/abac/policies/policy.py` + `obj.py` — `groups_condition` is the template
  for `scope_condition`; `evaluator.py` `_make_cache_key` for the cache-key fix;
  `storages/pg.py` `ModelPolicy` for the `scopes` column.
- `tests/conftest.py` — `EvalContext`/userinfo fixtures and `build_evaluator_from_dicts`
  for the ABAC+scope tests.

---

### Option B: Replace the engine with Authlib

Swap the hand-rolled provider for [Authlib](https://docs.authlib.org)'s
`AuthorizationServer` + grant classes (`AuthorizationCodeGrant`, `RefreshTokenGrant`,
`CodeChallenge` for PKCE) and `ResourceProtector` for the resource server. Implement
Authlib's storage hooks (`query_client`, `save_authorization_code`, `save_token`,
`authenticate_refresh_token`, etc.) on top of our existing storages, and bridge token
minting to `IdentityProvider`.

✅ **Pros:**
- Battle-tested RFC 6749/7636/7009 compliance: PKCE, rotation hooks, revocation, and grant
  validation are maintained upstream and widely audited.
- Less hand-written security-critical code; long-tail RFC edge cases handled for us.

❌ **Cons:**
- **Heavy impedance mismatch.** Authlib expects its own request/response, client, and token
  models; we have aiohttp, jsonpickle-encoded session users (`session['user']`), asyncdb
  models, and a bespoke `IdentityProvider` JWT path. The adapter layer to reconcile these is
  large and itself becomes the bug surface — we'd still hand-write the riskiest glue.
- **ABAC composition still custom.** Authlib does not know about `EvalContext`, the decision
  cache, `client_credentials` service principals, or `scopes ∩ ABAC`. P5 (the most novel,
  highest-value part) gets *no* help from the library.
- New runtime + supply-chain dependency for the most security-sensitive subsystem; upgrades
  and CVEs become our concern.
- Larger conceptual rewrite contradicts the user's "single per-spec worktree, full P0–P5"
  framing and the spec's "keep public signatures stable" guidance.

📊 **Effort:** High (and higher-risk — most effort is in glue that the spec didn't design for)

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `Authlib` (>=1.3) | OAuth2 server framework: grants, PKCE, revoke | Mature, but aiohttp integration is DIY (Authlib ships Flask/Django/Starlette, not aiohttp) |
| `cryptography` (transitive) | JOSE/crypto backend | Already likely present via JWT stack |

🔗 **Existing Code to Reuse:**
- Storages (`client_backend.py`, `code_backend.py`) become Authlib storage-hook backends.
- `IdentityProvider.create_token` wrapped as Authlib's token generator.
- ABAC subsystem unchanged by the library — P5 reuses the same modules as Option A.

---

### Option C: Hand-rolled endpoints + extracted pure-core security engine (unconventional)

Keep aiohttp endpoints and storages hand-rolled (as Option A), but **extract the
security-critical logic into a dependency-light, framework-agnostic pure-Python core**: a
`grant_engine` module holding the PKCE verifier, the refresh rotation/reuse state machine,
the token-claim assembler (`user_id`/`client_id`/`scope`/`jti`/`aud`), and the
`scopes ∩ ABAC` composition rule. Endpoints become thin adapters that call the core; the
core has zero aiohttp/asyncdb imports and is exhaustively unit-tested in isolation. Optionally
borrow `oauthlib`'s parameter validators for request parsing only, not for state.

✅ **Pros:**
- The riskiest logic (rotation chains, reuse detection, PKCE, scope composition) becomes
  pure functions over plain data — trivially and exhaustively unit-testable without a server,
  Redis, or DB. Highest confidence on the parts that matter most for security.
- Clean seam for future reuse (e.g. a second transport, or the planned non-goals like
  introspection) without touching endpoint code.
- Keeps Option A's low dependency/integration risk while improving testability and the
  blast-radius isolation of security logic.

❌ **Cons:**
- Up-front refactor cost: defining the core's data contracts and rewiring endpoints as
  adapters is more design work than extending in place, with no new external behavior to
  show for it initially.
- Risk of over-abstraction for a single transport — the indirection only pays off if the
  core boundary is drawn correctly the first time.
- Larger initial diff than Option A; slightly harder to map 1:1 onto the spec's
  file-by-file instructions.

📊 **Effort:** High (Option A's surface plus an internal refactor)

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| stdlib `hashlib`/`hmac`/`secrets`/`uuid` | Same primitives as Option A, inside the core | No dep |
| `oauthlib` (>=3.2, optional) | Request-parameter validation only | Avoid using it for token/grant *state* — keep that in our core |
| `pydantic` v2 | Core data contracts (frozen models) | Project standard |

🔗 **Existing Code to Reuse:**
- Same reuse set as Option A; additionally, the new `grant_engine` core is *called by*
  `backend.py` endpoints and the `api.py` resource-server path rather than embedding logic
  in them.

---

## Recommendation

**Option A** is recommended.

The spec is unusually prescriptive: it already names every file, symbol, and line, and maps
each change onto a pattern that exists in the codebase today (the `ClientStorage` ABC, the
Redis storage tier, asyncdb models, the IdP token path, the ABAC decorator/policy/evaluator
trio). Option A executes that design with the least integration risk and **zero new runtime
dependency for security-critical code** — PKCE, rotation, reuse detection, and `jti` are all
stdlib (`hashlib`, `hmac`, `secrets`, `uuid`). That keeps the audit and supply-chain surface
minimal, which matters most precisely for the auth subsystem.

Option B is rejected because Authlib ships no aiohttp integration and assumes its own
request/client/token models; reconciling them with our jsonpickle session users, asyncdb
models, and bespoke `IdentityProvider` would force us to hand-write a large adapter that
*is itself* the bug surface — and it gives **no** help with P5 (scope↔ABAC composition, the
decision-cache fix, `client_credentials` service principals), which is the highest-value,
most novel part of the work. We'd take on a dependency and still write the hard parts.

Option C is the strongest *future* shape and its core-extraction idea is worth keeping as a
follow-up refactor — but doing it now front-loads abstraction cost and diverges from the
spec's file-by-file map, raising the chance of drawing the core boundary wrong under time
pressure. **The trade-off we accept with A is owning RFC correctness ourselves**; we buy it
back with the adversarial test matrix the spec already mandates (§10/§11.7) — reused-code,
PKCE-mismatch, refresh-reuse→chain-revoke, absolute-expiry, scope-ceiling, and the cache
regression test. Concretely: build Option A, and **adopt Option C's discipline tactically**
by isolating the PKCE verifier and the rotation/reuse state machine into small pure-function
helpers (even within the existing modules) so they are unit-testable without a server.

---

## Feature Description

### User-Facing Behavior

**End user (resource owner):** Visiting a third-party app's "Connect" button lands on
`/oauth2/authorize`. If not logged in, they authenticate at `/oauth2/login`. They then see a
**consent screen** naming the app and the *exact, client-allowed* scopes requested. On
approve, they're redirected to the app's registered `redirect_uri` with `code` and the
original `state`. If they've already granted these scopes to this app (an unrevoked
`OauthGrant` covers them) and the app didn't send `prompt=consent`, the consent screen is
skipped. They can later list their authorized apps (`GET /api/v1/oauth2/grants`) and revoke
any one (`DELETE /api/v1/oauth2/grants/{client_id}`), which immediately kills that app's
live refresh tokens (and access tokens, via `jti`).

**App developer (client):** Exchanges the code at `/oauth2/token`. Public clients **must**
present a PKCE `code_verifier` (S256); confidential clients **must** present
`client_secret`. They receive `access_token`, `token_type`, `expires_in` **in seconds**,
`scope`, and — only if `offline_access` was granted — a `refresh_token`. Refresh tokens
**rotate on every use**: each refresh returns a new refresh token and invalidates the old
one; replaying an old (rotated) token revokes the entire chain. They can call
`/oauth2/userinfo` with the bearer token for scope-gated claims, `/oauth2/revoke` (RFC 7009)
to revoke a token, and `/oauth2/logout` to end the session.

**Resource-server / API consumer:** Protected endpoints enforce scopes via
`@scope_required(...)` / `Guardian.has_scope`, returning `403 insufficient_scope` when the
token lacks them — *before* full ABAC runs. Final access = `granted_scopes ∩
user_ABAC_permissions` (both gates must pass; DENY always wins).

### Internal Behavior

- **authorize:** validate `response_type == "code"` (B4) → resolve client (B2 unknown ⇒
  `invalid_client`) → **exact-match** `redirect_uri` against `client.redirect_uris`, render
  an error page on mismatch (never redirect, B3) → parse `scope`, compute
  `granted = requested ∩ client.default_scopes`, reject unknown scopes (`invalid_scope`) →
  preserve `state` → no session ⇒ redirect to login carrying the query → session present ⇒
  consent-skip if an unrevoked grant covers `granted` and no `prompt=consent`, else redirect
  to consent. Persist `code_challenge`/method when present.
- **consent (approve):** resolve the authenticated `user_id` from the jsonpickle session
  `'user'` (401 if absent) → upsert `OauthGrant(user_id, client_id, scopes)` → build
  `OauthAuthorizationCode` **including `user_id`**, filtered `scope`, `redirect_uri`,
  `state`, PKCE fields, short TTL → redirect with `code` + `state`. (deny ⇒
  `error=access_denied` + `state`.)
- **token (authorization_code):** load code (missing/used/expired ⇒ `invalid_grant`) →
  match `client_id` and `redirect_uri` → authenticate client (secret for confidential,
  PKCE S256 for public; constant-time) → verify PKCE when a challenge was stored → mark
  `used`, delete code → assemble payload from the **code's** `user_id` + `client_id` +
  granted `scope` + fresh `jti` + `aud='user'` → mint access token → issue+persist refresh
  token **only if** `offline_access` granted (`parent_token=None`, `absolute_expires_at`) →
  persist `jti` record → respond with correct `expires_in` (B1).
- **token (refresh_token):** validate client → load token (missing/revoked/expired/absolute
  passed ⇒ `invalid_grant`) → match `client_id` → **read `user_id` from the refresh token**
  → rotate: mint new access+refresh, set `parent_token`, copy `absolute_expires_at`, mark old
  `revoked(reason=rotated)`; **reuse detection** — replay of an already-`rotated` token ⇒
  `revoke_chain` + `invalid_grant`. Scope narrowing only.
- **token (client_credentials):** unchanged 2LO; apply B1; `aud='app'`; bound to client
  identity legitimately.
- **userinfo:** decode bearer via IdP → check `jti` not revoked → return claims allowed by
  token scopes; 401 on invalid/expired/revoked.
- **revoke / logout / grants API:** RFC 7009 revoke (always 200); session teardown +
  redirect to `AUTH_LOGOUT_REDIRECT_URI`; grants list + per-app revoke cascading to tokens.
- **Resource server (`api.py`):** after decoding the JWT, copy `payload['scope'].split()`,
  `client_id`, and `aud` into `userinfo`; call `ctx.set('scopes', ...)` /
  `ctx.set('client_id', ...)`; **check `jti` revocation on every request** (short-TTL cache).
- **ABAC:** `Policy.scopes` evaluated as an extra AND condition across `Policy`/`ObjectPolicy`
  (and the `ResourcePolicy`/evaluator path); `_make_cache_key` augmented with
  `frozenset(scopes)` + `client_id`; `client_credentials` tokens evaluated against
  `client_id` as a service principal; action→scope resolution via `OAUTH_SCOPE_ACTIONS`.

### Edge Cases & Error Handling

- `redirect_uri` mismatch ⇒ **never redirect**; render an error page (anti open-redirect).
- Unknown/disallowed scope ⇒ `invalid_scope` at authorize.
- Reused/used/expired auth code ⇒ `invalid_grant`; code deleted after first exchange.
- PKCE: missing `code_verifier` for public client, or `plain` when S256 required, or hash
  mismatch ⇒ `invalid_grant`.
- Confidential client with wrong/missing secret ⇒ client auth failure.
- Refresh past `absolute_expires_at`, or replay of a rotated token ⇒ `invalid_grant`
  (+ full chain revocation on replay).
- `offline_access` absent ⇒ **no** refresh token issued.
- Revoked `jti` ⇒ 401 at `userinfo` and on every resource-server request.
- Scope present but ABAC DENY ⇒ denied; ABAC ALLOW but scope absent ⇒
  `403 insufficient_scope` (scope is a ceiling).
- **Cache correctness:** two tokens for the same user with different scopes must not collide
  in the decision cache (the regression that proves §11.4).
- Session user un-decodable / absent at consent ⇒ 401, never mint a code.

---

## Capabilities

### New Capabilities
- `oauth2-3lo-core`: bind `user_id` (authenticated owner) through consent → code → token →
  refresh; fix B1–B5; eliminate `client.user` derivation. *(P0)*
- `oauth2-pkce`: S256 PKCE capture at authorize and verification at token (public-client
  required, constant-time). *(P1)*
- `oauth2-refresh-rotation`: rotation on every use, reuse detection + chain revocation,
  sliding + absolute expiry, durable refresh storage (memory/redis/postgres) + DDL. *(P2)*
- `oauth2-grants`: `OauthGrant` consent records, consent-skip, `GrantStorage`. *(P3)*
- `oauth2-revocation`: RFC 7009 `/oauth2/revoke`, `jti` access-token tracking + store,
  per-app grants API with token cascade. *(P3)*
- `oauth2-userinfo-logout`: implement `userinfo`, `logout`, `finish_logout`. *(P4)*
- `oauth2-config`: `OAUTH_ACCESS_TOKEN_TTL`, `OAUTH_REFRESH_TOKEN_TTL`,
  `OAUTH_REFRESH_ABSOLUTE_TTL`, `OAUTH_REFRESH_ROTATION`, `OAUTH_REQUIRE_PKCE_PUBLIC`,
  `OAUTH_SCOPES`, `OAUTH_SCOPE_ACTIONS`; replace hardcoded durations. *(P4)*
- `oauth2-resource-server`: extend `APIKeyAuth` bearer path to populate
  `userinfo['scopes']`/`client_id`/`token_type` and check `jti` revocation per request. *(P5)*
- `scope-abac-integration`: surface scopes into `EvalContext`, `@scope_required` /
  `Guardian.has_scope`, `client_credentials` service-principal evaluation, action→scope
  registry. *(P5)*

### Modified Capabilities
- `abac-policy-evaluation`: add `Policy.scopes` (and `ObjectPolicy`/`ResourcePolicy`) as an
  AND condition; **fix `_make_cache_key`** to include normalized scopes + `client_id`;
  `auth.policies.scopes` column + PDP loader passthrough.
- `bearer-token-auth`: `backends/api.py` `APIKeyAuth` extended for OAuth2 access tokens.

---

## Impact & Integration

| Affected Component | Impact Type | Notes |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | modifies | Core endpoint rewrite (authorize/consent/token/userinfo/logout) + new revoke/grants; highest contention file |
| `navigator_auth/backends/oauth2/models.py` | modifies | Add `user_id` to AuthCode + RefreshToken; add `parent_token`/`absolute_expires_at`; new `OauthGrant`; drop `client.user` reliance |
| `navigator_auth/backends/oauth2/code_backend.py` | extends | Extend RefreshTokenStorage (rotate/revoke/revoke_chain/list); add memory tier; `user_id` on codes |
| `navigator_auth/backends/oauth2/client_backend.py` | depends on | `ClientStorage` ABC pattern is the template for new `GrantStorage` + jti store |
| `navigator_auth/backends/oauth2/ddl.sql` | extends | `auth.oauth_grants`, `auth.oauth_refresh_tokens`, `auth.oauth_access_tokens`; `auth.policies.scopes` |
| `navigator_auth/backends/idp/__init__.py` | modifies | Emit `jti`/`aud`; expose `expires_in` seconds (B1); keep 4-tuple callers working |
| `navigator_auth/backends/api.py` | modifies | Resource-server bearer path: populate scopes/client_id, per-request `jti` revocation check |
| `navigator_auth/abac/context.py` | extends | `userinfo['scopes']`/`client_id`; `ctx.set(...)` (already supports) |
| `navigator_auth/abac/guardian.py` | extends | `has_scope()` |
| `navigator_auth/abac/decorators.py` | extends | `@scope_required` (mirrors `groups_protected`) |
| `navigator_auth/abac/policies/policy.py`, `obj.py` | modifies | `scope_condition` in `evaluate()` |
| `navigator_auth/abac/policies/evaluator.py` | modifies | **Cache-key fix** — hot path, affects all ABAC decisions |
| `navigator_auth/abac/storages/pg.py` | modifies | `ModelPolicy.scopes`; loader passthrough; **shared with in-flight FEAT-092 tenant scoping** |
| `navigator_auth/conf.py` | extends | New `OAUTH_*` settings; replace hardcoded durations |
| `examples/oauth2_server.py` | depends on | Reference server may need updated test client (PKCE, scopes) |
| `documentation/oauth.md` | modifies | Document revoke, grants API, offline_access, PKCE, rotation |
| `tests/` | extends | New OAuth2 3LO + scope↔ABAC test suites (memory storages) |

**Breaking changes:** authorization codes and refresh tokens now **require** `user_id`
(schema-breaking, but no production data per the cutover decision); `_make_cache_key`
signature changes (all call sites updated). No public endpoint signatures change.

---

## Parallelism Assessment

- **Internal parallelism:** Low. The work concentrates on `backend.py`, `models.py`,
  `code_backend.py`, and (for P5) `evaluator.py`/`policy.py` — all heavily shared. Phases are
  also dependency-ordered (P5 depends on P0 minting `user_id`/`scope`/`client_id`; P2/P3
  depend on the P0 model fields). Splitting into separate worktrees would create constant
  merge contention on the same hot files.
- **Cross-feature independence:** The ABAC P5 work touches `abac/storages/pg.py`,
  `abac/policies/evaluator.py`, and the `auth.policies` table — the **same files/table as
  in-flight tenant-scoping work (FEAT-092)**. Sequence P5 against that effort or coordinate
  on `ModelPolicy`/`_make_cache_key`/`auth.policies` DDL to avoid collisions.
- **Recommended isolation:** **`per-spec`** (single worktree, all tasks sequential) — as
  chosen.
- **Rationale:** Shared-file contention + strict phase dependencies mean parallel worktrees
  would cost more in conflict resolution than they save. A single worktree with small
  per-phase commits (P0→P5), running the full suite at each boundary, is the safest path; the
  bound-`user_id`-survives-refresh regression gates correctness before later phases build on
  it.

---

## Open Questions

_All seven open questions were resolved against the code on 2026-06-22 (decisions below).
None remain blocking for `/sdd-spec`._

- [x] **Q1 — `create_token` shape (B1).** Confirmed 4-tuple
  `(jwt_token, refresh_token, exp, scheme)`, `exp` absolute UTC timestamp
  (`idp/__init__.py:292,304`). **Decision:** compute
  `expires_in = int(exp - datetime.now(timezone.utc).timestamp())` at the OAuth2 token call
  site; **do not change the IdP signature** (shared by all backends). The `refresh_token`
  element returned by `create_token` is ignored by the OAuth2 path, which mints/persists its
  own via the rotation store.
- [x] **Q2 — `aud` claim & `jti` emission.** Finding: `create_token` **deletes `aud`** from
  incoming `data` (`idp:282`) and never re-adds it ⇒ tokens carry no `aud` today; `jti` is
  *not* deleted, so it survives via `**data`. `decode_token` returns the full payload, so any
  minted `scope`/`jti`/`aud` is readable resource-server-side. **Decision:** inject
  `jti=str(uuid4())` through the `data` dict (no IdP change); add one minimal,
  backward-compatible `audience: str = None` kwarg to `create_token` (sets `payload['aud']`
  only when provided). OAuth2 passes `audience='user'` (3LO) / `'app'` (client_credentials);
  existing callers default to no-aud. Do **not** enforce `aud` verification in `decode_token`
  (propagate only).
- [x] **Q3 — per-request `jti` revocation cost.** **Decision:** in-process TTL cache
  (jti→revoked), **default TTL 30s** via new config `OAUTH_REVOCATION_CACHE_TTL`. `/revoke`
  and per-app grant revoke **evict the affected jti immediately** (instant in-process,
  ≤TTL cross-process). Durable store is source of truth; cache absorbs repeat hits. Exposure
  bounded to 30s against ~1h access tokens.
- [x] **Q4 — auth-code storage tier.** Confirmed `AuthorizationCodeStorage` /
  `RefreshTokenStorage` are **Redis-only, no ABC, no memory tier** (`code_backend.py`).
  **Decision:** add `Memory*` implementations for code/refresh/grant/jti stores plus a small
  factory honoring `OAUTH2_CLIENT_STORAGE` (mirrors the `ClientStorage` selector). Tests run
  `OAUTH2_CLIENT_STORAGE=memory`; prod keeps codes in Redis (short TTL), grants/refresh/jti
  in the durable tier.
- [x] **Q5 — FEAT-092 coordination.** **Resolved: completed, not in-flight** — TASK-016…022
  live in `sdd/tasks/completed/`. Two carryovers for P5: (1) `_make_cache_key`
  (`evaluator.py:327`) already includes `org_id`/`client_id` **tenant ints** — a *different*
  concept from the OAuth2 requesting-app `client_id` (string); the §11.4 fix must add a
  **distinct** `scope_key=frozenset(scopes)` + OAuth `client_id`, not overload the tenant
  param (one call site, `evaluator.py:433`). (2) `ModelPolicy` is `strict=True` and
  `load_policies` uses **two explicit SELECT column lists** (`pg.py:35-42`, `47-51`) — adding
  `Policy.scopes` requires the field on `ModelPolicy`, `scopes` in **both** SELECTs, and the
  `auth.policies.scopes` DDL column.
- [x] **Q6 — `OAUTH_SCOPES` semantics.** **Decision (reject, per spec §5.1 step 4):** a
  requested scope outside `client.default_scopes` ⇒ `invalid_scope`. When `OAUTH_SCOPES` is
  **non-empty** it is the authoritative registry — any requested scope not in it ⇒
  `invalid_scope`. When **empty** (default), skip the registry check and validate only
  against the client allow-list. `offline_access` must be in the client's `default_scopes`
  to be grantable.
- [x] **Q7 — `AUTH_LOGOUT_REDIRECT_URI`.** **Resolved: already exists** (`conf.py:120`,
  fallback `/oauth2/logout/complete`), imported at `backend.py:19`, used as
  `self.logout_redirect_uri` at `backend.py:70`. No new config — just implement teardown +
  redirect.
