# Feature Specification: Production-grade 3LO (Three-Legged OAuth2)

**Feature ID**: FEAT-093
**Date**: 2026-06-22
**Author**: Jesus Lara
**Status**: draft
**Target version**: 1.2.0

> **Inputs:** `sdd/proposals/oauth2-3lo-implementation.brainstorm.md` (Recommended Option A)
> and `sdd/proposals/SPEC_oauth2_3lo.md` (the detailed source spec; section refs `§N` below
> point to it). This spec is the SDD-structured, decision-resolved version of that source.

---

## 1. Motivation & Business Requirements

### Problem Statement

`navigator-auth` exposes an OAuth2 Authorization Server (`Oauth2Provider`,
`navigator_auth/backends/oauth2/backend.py`) with the full `authorize → login → consent →
code → token` surface and `authorization_code` / `client_credentials` / `refresh_token`
grants. It *looks* three-legged but is **not a valid 3LO server**:

- **The resource owner is never bound to the grant.** Tokens derive the user from
  `client.user` (`backend.py:506`, and `user = rt.client_id.user` at `backend.py:549`), so a
  token represents *the client's static owner*, not *whoever authenticated and consented*.
  This is a real authorization vulnerability (source §1).
- **Validation gaps (B1–B5):** `expires_in` is returned as an absolute timestamp instead of
  seconds; the auth-code branch never checks `client_secret`; `redirect_uri` is not
  exact-match-guarded (open redirect); `response_type` is unvalidated; the single-use
  `used`/`used_at` flags are never enforced.
- **Unsafe refresh:** no rotation, no reuse detection, no absolute lifetime; Redis-only with
  a 365-day default; owner-less.
- **Stubs:** `userinfo`, `logout`, `finish_logout` are `pass`.
- **Decorative scopes:** captured and echoed but never filtered to a client allow-list, never
  enforced at the resource server, and never composed with ABAC.
- **Identifier overload:** the wire OAuth `client_id` is currently the integer **DB primary
  key** (enumerable, DB-coupled), bridged by a lossy `int(client_id)` cast.

### Goals

- Bind every access/refresh token to the **(resource owner + client + granted scopes)**
  triple; `user_id` MUST originate from the session user who authenticated at
  `/oauth2/login`, **never** from `client.user`.
- Fix B1–B5 with isolated, test-covered changes.
- Enforce **PKCE S256** for public clients; authenticate confidential clients by secret.
- Harden refresh tokens: rotation on every use, reuse detection + chain revocation, sliding
  + absolute lifetime; durable storage.
- Add durable consent records (`OauthGrant`), consent-skip, RFC 7009 revocation, `jti`
  access-token tracking, and a per-app revocation surface.
- Implement `userinfo` / `logout`; move hardcoded durations into config.
- Compose scopes with ABAC: **effective permission = `granted_scopes ∩ user_ABAC`**;
  surface scopes into `EvalContext`, add a PEP scope gate, make `scopes` a first-class
  `Policy` attribute, and **fix the decision cache key**.
- **Disambiguate `client_id`:** introduce an opaque public `client_uid`, keeping the integer
  PK internal.

### Non-Goals (explicitly out of scope)

- OpenID Connect (`id_token`, discovery, `nonce` semantics beyond storage).
- Token introspection endpoint (RFC 7662).
- Device Authorization grant.
- DPoP / mTLS sender-constrained tokens.
- Dynamic Client Registration.
- Enforcing `aud` **verification** in `decode_token` (we propagate `aud`, not verify it).

---

## 2. Architectural Design

### Overview

Recommended Option **A — incremental in-place hardening** (brainstorm): extend the existing
modules, following the source spec's phase order, on patterns that already exist
(`ClientStorage` ABC, Redis storages, asyncdb models, IdP token minting, ABAC
decorator/policy/evaluator trio). **No new runtime dependency** — PKCE, rotation, reuse
detection, and `jti` are stdlib (`hashlib`, `hmac`, `secrets`, `uuid`). Tactically adopt the
discipline of Option C: isolate the PKCE verifier and the rotation/reuse state machine as
pure, unit-testable helpers.

The work splits into a foundational identifier change, then phases P0–P5, then the
resource-server + ABAC composition.

### Component Diagram

```
                      ┌────────────────────── Authorization Server ──────────────────────┐
  Browser/App  ──▶ authorize ─▶ login ─▶ consent ─▶ /token ─▶ (access JWT + refresh)
                      │            │         │          │
                      │            │         ▼          ▼
                      │            │     GrantStorage  IdP.create_token (jti, aud, scope, user_id)
                      │            ▼                    │
                      │      session['user']            ├─▶ RefreshTokenStorage (rotation chain)
                      ▼      (jsonpickle)               └─▶ AccessTokenStorage (jti tracking)
                ClientStorage.get_client(client_uid) ───────────┘
                      │
                      ▼  resolves client_uid(str) ─▶ client_pk(int, FK)

  ┌──────────────────── Resource Server (per request) ────────────────────┐
  Bearer JWT ─▶ APIKeyAuth.decode_token ─▶ userinfo{scopes, client_id(=uid), token_type}
                       │                         │
                       ▼                         ▼
             AccessTokenStorage (jti revoked?)   EvalContext.set('scopes'/'client_id')
                                                 │
                                                 ▼
                @scope_required / Guardian.has_scope (403 insufficient_scope)
                                                 │
                                                 ▼
                PolicyEvaluator (Policy.scopes AND-condition; cache key incl. scopes+client_uid)
                                                 │
                          effective = granted_scopes ∩ user_ABAC   (DENY wins)
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `Oauth2Provider` (`backends/oauth2/backend.py`) | modifies | Rewrites authorize/consent/token/userinfo/logout; adds revoke + grants API |
| `OAuthClient`/`OauthAuthorizationCode`/`OauthRefreshToken`/`OauthToken` (`oauth2/models.py`) | modifies | `user_id`, PKCE/rotation fields, `OauthGrant`; `client_uid`/`client_pk`; rename nested `client_id`→`client` |
| `ClientStorage` trio (`oauth2/client_backend.py`) | modifies | Look up by `client_uid` (drop `int()`); template for new `GrantStorage` + jti store |
| `AuthorizationCodeStorage`/`RefreshTokenStorage` (`oauth2/code_backend.py`) | extends | `user_id` on codes; rotation/revoke/chain; add memory tier + factory |
| `IdentityProvider` (`backends/idp/__init__.py`) | modifies | Emit `jti` via `data`; add `audience=None` kwarg; keep 4-tuple signature |
| `APIKeyAuth` (`backends/api.py`) | modifies | Resource-server bearer: populate `userinfo[scopes/client_id]`, per-request `jti` revocation check |
| `Client` model (`navigator_auth/models.py`) | modifies | Add `client_uid` unique column |
| `EvalContext` (`abac/context.py`) | extends | `userinfo['scopes']`/`client_id`; `ctx.set(...)` (already supported) |
| `Guardian` (`abac/guardian.py`) | extends | `has_scope()` |
| ABAC decorators (`abac/decorators.py`) | extends | `@scope_required` (mirrors `groups_protected`) |
| `Policy`/`ObjectPolicy` (`abac/policies/policy.py`,`obj.py`) | modifies | `scope_condition` AND-term |
| `PolicyEvaluator` (`abac/policies/evaluator.py`) | modifies | **Cache-key fix** — add scopes + `client_uid` |
| `pgStorage`/`ModelPolicy` (`abac/storages/pg.py`) | modifies | `scopes` field + both SELECT column lists |
| `conf.py` | extends | New `OAUTH_*` settings; replace hardcoded durations |
| `ddl.sql` | extends | `client_uid`; `oauth_grants`/`oauth_refresh_tokens`/`oauth_access_tokens`; `auth.policies.scopes` |
| `examples/oauth2_server.py` | modifies | Register test client with string `client_uid`, PKCE, scopes |

### Data Models

```python
# oauth2/models.py — key changes (Pydantic v2)

class OAuthClient(BaseModel):
    client_id: str        # PUBLIC opaque identifier (= auth.clients.client_uid)
    client_pk: Optional[int] = None   # internal surrogate PK (FK target); None for memory/redis
    client_type: str = "public"       # 'public' | 'confidential'
    client_secret: Optional[str] = None
    redirect_uris: list = []
    default_scopes: list = []
    allowed_grant_types: list = []
    # ... existing metadata; `user` retained but NEVER used to derive token owner

class OauthAuthorizationCode(BaseModel):
    client: OAuthClient               # RENAMED from client_id (held the object)
    user_id: int                      # NEW (required) — authenticated resource owner
    code: str
    redirect_uri: str
    response_type: str = "code"
    scope: str
    state: str
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None   # 'S256' enforced for public clients
    expires_at: datetime              # short TTL (~2 min)
    used: bool = False
    used_at: Optional[datetime] = None

class OauthRefreshToken(BaseModel):
    client: OAuthClient               # RENAMED from client_id
    user_id: int                      # NEW (required)
    refresh_token: str
    scope: str
    parent_token: Optional[str] = None            # rotation chain link
    issued_at: datetime
    expires_at: datetime              # sliding TTL
    absolute_expires_at: datetime     # rotation-chain hard stop
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None          # e.g. 'rotated', 'revoked', 'reuse_detected'

class OauthGrant(BaseModel):          # NEW — durable consent record (source §3.3)
    grant_id: UUID = Field(default_factory=uuid4)
    user_id: int
    client_id: str                    # the public client_uid
    scopes: list[str]
    granted_at: datetime = Field(default_factory=datetime.now)
    revoked: bool = False
    revoked_at: Optional[datetime] = None

class OauthAccessTokenRecord(BaseModel):   # NEW — jti tracking (source §3.4)
    jti: UUID
    user_id: int
    client_id: str                    # public client_uid
    scope: str
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False
```

### New Public Interfaces

```python
# oauth2/code_backend.py — storage ABCs + factory (mirror ClientStorage pattern)
class GrantStorage(ABC):
    async def get_grant(self, user_id: int, client_id: str) -> Optional[OauthGrant]: ...
    async def save_grant(self, grant: OauthGrant) -> bool: ...
    async def revoke_grant(self, user_id: int, client_id: str) -> bool: ...
    async def list_grants(self, user_id: int) -> list[OauthGrant]: ...

class RefreshTokenStorage(ABC):       # extended
    async def revoke_token(self, refresh_token: str, reason: str) -> bool: ...
    async def revoke_chain(self, refresh_token: str) -> bool: ...
    async def list_tokens(self, user_id: int) -> list[OauthRefreshToken]: ...

class AccessTokenStorage(ABC):        # NEW — jti tracking
    async def save(self, rec: OauthAccessTokenRecord) -> bool: ...
    async def is_revoked(self, jti: str) -> bool: ...
    async def revoke(self, jti: str) -> bool: ...

def get_token_storages(backend: str) -> tuple[...]:   # honors OAUTH2_CLIENT_STORAGE

# abac/decorators.py
def scope_required(*scopes): ...      # 403 insufficient_scope before full ABAC

# abac/guardian.py
class Guardian:
    async def has_scope(self, request: web.Request, scopes: list) -> bool: ...

# New endpoints on Oauth2Provider
#   POST /oauth2/revoke                         (RFC 7009)
#   GET  /api/v1/oauth2/grants                  (list current user's authorized apps)
#   DELETE /api/v1/oauth2/grants/{client_id}    (revoke grant + cascade tokens)
```

---

## 3. Module Breakdown

> Modules are ordered by dependency and map 1:1 to Phase-2 tasks. M1 is foundational; P0
> (M2) gates all later phases; M8 (scope↔ABAC) depends on M2 emitting `user_id`/`scope`/
> `client_uid`.

### Module 1: Client identifier disambiguation (`client_uid`)
- **Path**: `oauth2/ddl.sql`, `navigator_auth/models.py`, `oauth2/models.py`,
  `oauth2/client_backend.py`, `examples/oauth2_server.py`
- **Responsibility**: Add `auth.clients.client_uid VARCHAR(255) NOT NULL UNIQUE` (opaque,
  generated at registration) + backfill. `OAuthClient.client_id` = public `client_uid`; add
  `OAuthClient.client_pk:int`. Storage looks up by `client_uid` (remove `int(client_id)`
  cast); map `client_id`↔`client_pk`. Update example/test client to a fixed string
  `client_uid`.
- **Depends on**: none (foundational).

### Module 2: P0 Correctness — owner binding + B1–B5
- **Path**: `oauth2/models.py`, `oauth2/backend.py`, `oauth2/code_backend.py`,
  `backends/idp/__init__.py`
- **Responsibility**: Add `user_id` to `OauthAuthorizationCode`/`OauthRefreshToken`; rename
  nested `client_id`→`client`. Thread `user_id` session→consent→code→token→refresh; **never**
  read `client.user`. B1: `expires_in = int(exp - now)` at call site. B2: verify
  `client_secret` (confidential) on token. B3: exact-match `redirect_uri`, render error (no
  redirect) on mismatch. B4: validate `response_type == "code"`. B5: enforce single-use
  (`used`/`used_at` + delete). `decode_token` already returns full payload.
- **Depends on**: Module 1.

### Module 3: P1 — PKCE (S256)
- **Path**: `oauth2/backend.py`, `oauth2/models.py`, pure helper (e.g. `oauth2/pkce.py`)
- **Responsibility**: Capture `code_challenge`/method at authorize; verify at token —
  `S256` → `BASE64URL(SHA256(verifier)) == challenge`, `plain` → equality. Public clients
  **require** PKCE S256 (`OAUTH_REQUIRE_PKCE_PUBLIC=True` ⇒ reject `plain`). Use
  `hmac.compare_digest`. Verifier helper is a pure function (unit-testable).
- **Depends on**: Module 2.

### Module 4: P2 — Refresh hardening + durable storage
- **Path**: `oauth2/code_backend.py`, `oauth2/models.py`, `oauth2/ddl.sql`,
  `oauth2/backend.py`
- **Responsibility**: Add `parent_token`/`absolute_expires_at`. Rotation on every use (new
  access + refresh, `parent_token` set, `absolute_expires_at` copied, old marked
  `revoked(reason=rotated)`); **reuse detection** → `revoke_chain` + `invalid_grant`. Sliding
  + absolute expiry. Refresh issued **only if** `offline_access` granted; scope narrowing
  only. Add memory/redis/postgres `RefreshTokenStorage` + DDL (`auth.oauth_refresh_tokens`,
  FK `client_id INTEGER`→PK). Rotation/reuse logic as a pure state machine helper.
- **Depends on**: Module 2.

### Module 5: P3 — Grants, consent-skip, revocation, jti tracking, per-app revoke
- **Path**: `oauth2/code_backend.py`, `oauth2/models.py`, `oauth2/backend.py`,
  `oauth2/ddl.sql`, `backends/idp/__init__.py`
- **Responsibility**: `OauthGrant` + `GrantStorage` (memory/redis/pg) + DDL
  (`auth.oauth_grants`, unique `(user_id,client_id)`). Consent upserts a grant; authorize
  skips consent when an unrevoked grant covers `granted` and no `prompt=consent`. `jti`
  emitted into the token via `data` (uuid4); `AccessTokenStorage` + DDL
  (`auth.oauth_access_tokens`). `POST /oauth2/revoke` (RFC 7009, always 200) revoking refresh
  chain and/or `jti`. `GET /api/v1/oauth2/grants` + `DELETE /api/v1/oauth2/grants/{client_id}`
  (revoke grant + cascade refresh tokens + access `jti`).
- **Depends on**: Modules 2, 4.

### Module 6: P4 — userinfo / logout / config
- **Path**: `oauth2/backend.py`, `conf.py`
- **Responsibility**: Implement `userinfo` (decode bearer, check `jti` not revoked, return
  scope-gated claims, 401 on invalid/expired/revoked). Implement `logout`/`finish_logout`
  (session teardown + redirect to existing `AUTH_LOGOUT_REDIRECT_URI`). Add config keys
  (§8) including `audience` plumbing and `OAUTH_REVOCATION_CACHE_TTL`; replace hardcoded
  durations (`timedelta(days=30/365)`, `minutes=2`, the "2 hours" TODO,
  `OAUTH_DEFAULT_TOKEN_EXPIRATION_DAYS`).
- **Depends on**: Modules 2, 5.

### Module 7: IdP `audience` + resource-server bearer backend
- **Path**: `backends/idp/__init__.py`, `backends/api.py`
- **Responsibility**: Add backward-compatible `audience: str = None` kwarg to `create_token`
  (sets `payload['aud']` only when provided; existing callers unaffected). OAuth2 passes
  `audience='user'`/`'app'`. `APIKeyAuth` (resource server): after decode, copy
  `payload['scope'].split()`, `client_id`(=client_uid), `aud`→`token_type` into `userinfo`;
  `ctx.set('scopes'/'client_id')`; **check `jti` revocation on every request** via an
  in-process TTL cache (`OAUTH_REVOCATION_CACHE_TTL`, default 30s) over `AccessTokenStorage`,
  evicted on revoke.
- **Depends on**: Modules 2, 5.

### Module 8: P5 — Scope ↔ ABAC composition
- **Path**: `abac/decorators.py`, `abac/guardian.py`, `abac/policies/policy.py`,
  `abac/policies/obj.py`, `abac/policies/evaluator.py`, `abac/storages/pg.py`,
  `oauth2/ddl.sql`, `conf.py`
- **Responsibility**: `@scope_required(*scopes)` + `Guardian.has_scope` (403
  `insufficient_scope`, `issubset` = all required). `Policy.scopes` AND-term (`scope_condition`
  parallel to `groups_condition`) across `Policy`/`ObjectPolicy` (+ evaluator path);
  `ModelPolicy.scopes` + `scopes` in **both** `load_policies` SELECTs + `auth.policies.scopes`
  DDL. **Fix `_make_cache_key`**: add `scope_key=frozenset(scopes)` and the public
  `client_uid` as **separate** components (distinct from the FEAT-092 tenant `client_id` int);
  update the call site at `evaluator.py:433`. `client_credentials` tokens evaluated against
  `client_uid` as a service principal (no user groups/subject required). Action→scope
  resolution via `OAUTH_SCOPE_ACTIONS`; `OAUTH_SCOPES` as the valid-scope registry.
- **Depends on**: Modules 2, 7.

### Module 9: Tests, docs, example
- **Path**: `tests/`, `documentation/oauth.md`, `examples/oauth2_server.py`
- **Responsibility**: Full async pytest suite (§4); update docs for `/oauth2/revoke`,
  grants API, `offline_access`, PKCE, rotation, `client_uid`.
- **Depends on**: all.

---

## 4. Test Specification

### Unit Tests
| Test | Module | Description |
|---|---|---|
| `test_client_lookup_by_uid` | M1 | `get_client` resolves opaque `client_uid`; non-numeric id no longer fails |
| `test_client_pk_vs_uid_mapping` | M1 | `client_id`(uid str) vs `client_pk`(int) mapped correctly from DB row |
| `test_expires_in_is_seconds` | M2 | B1 — token response `expires_in` = seconds, not absolute ts |
| `test_redirect_uri_exact_match` | M2 | B3 — mismatch renders error page, never redirects |
| `test_response_type_validation` | M2 | B4 — non-`code` ⇒ `unsupported_response_type` |
| `test_auth_code_single_use` | M2 | B5 — reused/used/expired code ⇒ `invalid_grant`, deleted |
| `test_confidential_client_secret` | M2 | B2 — missing/wrong secret rejected |
| `test_pkce_s256_verify` | M3 | S256 hash match passes; mismatch ⇒ `invalid_grant` |
| `test_pkce_public_requires_s256` | M3 | public client w/o PKCE or with `plain` rejected |
| `test_refresh_rotation` | M4 | new refresh issued, old `revoked(reason=rotated)` |
| `test_refresh_reuse_revokes_chain` | M4 | replay of rotated token ⇒ chain revoked + `invalid_grant` |
| `test_refresh_absolute_expiry` | M4 | past `absolute_expires_at` ⇒ `invalid_grant` |
| `test_no_offline_access_no_refresh` | M4 | `offline_access` absent ⇒ no refresh token |
| `test_grant_consent_skip` | M5 | unrevoked grant covering scopes skips consent (no `prompt=consent`) |
| `test_revoke_endpoint_200` | M5 | RFC 7009 always 200; token revoked |
| `test_per_app_revoke_cascade` | M5 | DELETE grant revokes refresh chain + access `jti` |
| `test_userinfo_scope_gated` | M6 | claims limited by scope; 401 on revoked/expired |
| `test_audience_kwarg_backcompat` | M7 | `create_token` w/o `audience` ⇒ no `aud` (existing behavior) |
| `test_jti_revocation_check` | M7 | revoked `jti` ⇒ 401 on resource-server request |
| `test_scope_required_403` | M8 | missing scope ⇒ 403 `insufficient_scope` (issubset) |
| `test_policy_scope_condition` | M8 | `Policy.scopes` enforced as AND-term across policy types |
| `test_cache_key_includes_scopes` | M8 | same user, different scopes ⇒ no cache collision |
| `test_client_credentials_principal` | M8 | policy keyed on `client_uid`+scope allows; user-keyed not matched |

### Integration Tests
| Test | Description |
|---|---|
| `test_full_3lo_pkce_s256` | authorize→consent→code→token (user_id bound)→userinfo→refresh(rotated)→revoke |
| `test_user_id_survives_refresh` | **Regression proving §1/B-fix** — bound `user_id` persists across rotation |
| `test_scope_is_ceiling` | token w/o scope ⇒ 403 even though user's ABAC would ALLOW |
| `test_scope_and_abac_compose` | scope present but ABAC DENY ⇒ denied (AND composition) |
| `test_cache_regression_two_tokens` | token A (scope, allow) then token B (same user, no scope) ⇒ B denied, not cached |

### Test Data / Fixtures
```python
@pytest.fixture
def memory_oauth_storages(monkeypatch):
    # OAUTH2_CLIENT_STORAGE=memory ⇒ Memory client/code/refresh/grant/jti stores
    ...

@pytest.fixture
def public_client():   # client_type='public', S256 PKCE, opaque client_uid, offline_access
    ...

@pytest.fixture
def confidential_client():   # client_secret set
    ...
# Reuse tests/conftest.py EvalContext/userinfo fixtures + build_evaluator_from_dicts
```

---

## 5. Acceptance Criteria

> Complete when ALL hold (security checklist, source §9 / §11.8):

- [ ] Token `user_id` always originates from the authenticated owner, never `client.user`.
- [ ] `redirect_uri` exact-match against the allow-list; no redirect on mismatch.
- [ ] Scope filtered to the client-allowed set; unknown scope rejected (`invalid_scope`).
- [ ] Confidential clients authenticated with secret on `/token`; public clients require
      PKCE **S256**; PKCE verified when a challenge was stored (`hmac.compare_digest`).
- [ ] Auth codes single-use, short-TTL, deleted after exchange.
- [ ] Refresh rotation + reuse detection (chain revoke) + absolute lifetime; refresh only on
      `offline_access`.
- [ ] `state` preserved end-to-end; `expires_in` reported in seconds.
- [ ] `jti` minted on OAuth2 tokens, tracked, and checked on every resource-server request;
      revocation effective within `OAUTH_REVOCATION_CACHE_TTL`.
- [ ] `OauthGrant` consent records power consent-skip and per-app revocation (cascade to
      tokens). `/oauth2/revoke` (RFC 7009) returns 200.
- [ ] `userinfo`, `logout`, `finish_logout` implemented (no stubs).
- [ ] `client_uid` is the opaque public id; integer PK never on the wire; `int()` cast
      removed; nested-model field renamed `client_id`→`client`.
- [ ] `scopes`/`client_id`(uid) on `ctx.userinfo`; `@scope_required`/`Guardian.has_scope`
      enforce 403; `Policy.scopes` AND-evaluated across all policy types.
- [ ] **Decision cache key includes normalized scopes + `client_uid`** (distinct from tenant
      `client_id`); two same-user different-scope tokens do not collide.
- [ ] `client_credentials` path evaluates against `client_uid` as a service principal.
- [ ] Action→scope resolution driven by `OAUTH_SCOPE_ACTIONS`; no hardcoded scope names.
- [ ] No secrets logged; constant-time comparisons used.
- [ ] All unit + integration tests pass (`pytest tests/ -v`); `documentation/oauth.md`
      updated.

---

## 6. Implementation Notes & Constraints

### Patterns to Follow
- Extend existing ABCs (`ClientStorage`) and the `OAUTH2_CLIENT_STORAGE` factory; mirror
  `groups_protected`/`groups_condition` for scope equivalents.
- Pydantic v2 (`model_dump`/`model_validate`); asyncdb `Model`/`Column` with
  `class Meta: schema = "auth"`.
- Async-first; `self.logger`; `uv` + active venv for any commands.
- Keep the IdP `create_token` **4-tuple** signature stable (compute `expires_in` at call
  site; inject `jti` via `data`; add only the additive `audience` kwarg).
- Isolate PKCE verification and refresh rotation/reuse as **pure functions** for unit testing
  without a server/Redis/DB.

### Known Risks / Gotchas
- **`create_token` strips `aud` from `data`** (`idp:282`) and never sets it ⇒ use the new
  `audience` kwarg; `jti` is *not* stripped, so it passes through `**data`.
- **Three+ meanings of `client_id`** must stay distinct: surrogate PK (int, FK target),
  public `client_uid` (str — wire/claim/userinfo/ABAC principal/cache key), and FEAT-092
  tenant `client_id` (int, cache key). Do **not** overload the tenant param.
- `load_policies` uses **two explicit SELECT column lists** — add `scopes` to both.
- `_make_cache_key` is on the hot path for **all** ABAC decisions; non-token users get
  `scopes=frozenset()`, `client_uid=None` (stable, no collision).
- FEAT-092 (per-tenant scoping) is **completed/merged**, not in-flight — coordination is just
  respecting the shared `ModelPolicy`/`_make_cache_key`/`auth.policies` contract above.

### Configuration Keys (navigator_auth.conf)
| Setting | Default | Meaning |
|---|---|---|
| `OAUTH_ACCESS_TOKEN_TTL` | `3600` | Access-token lifetime (s) |
| `OAUTH_REFRESH_TOKEN_TTL` | `2592000` (30d) | Refresh sliding TTL (s) |
| `OAUTH_REFRESH_ABSOLUTE_TTL` | `7776000` (90d) | Refresh absolute lifetime (s) |
| `OAUTH_REFRESH_ROTATION` | `True` | Rotation + reuse detection |
| `OAUTH_REQUIRE_PKCE_PUBLIC` | `True` | Require PKCE (S256) for public clients |
| `OAUTH_REVOCATION_CACHE_TTL` | `30` | In-process jti-revocation cache TTL (s) |
| `OAUTH_SCOPES` | `[]` | Valid-scope registry (empty ⇒ validate vs client allow-list only) |
| `OAUTH_SCOPE_ACTIONS` | `{}` | Map `action/resource → [scopes]` for PEP gate + evaluator |
| `AUTH_LOGOUT_REDIRECT_URI` | *(exists)* | `conf.py:120`, fallback `/oauth2/logout/complete` |

### External Dependencies
| Package | Version | Reason |
|---|---|---|
| *(none new)* | — | PKCE/jti/rotation use stdlib `hashlib`/`hmac`/`secrets`/`uuid`; persistence via existing `asyncdb`/`redis`; JWT via existing `pyjwt` |

---

## 7. Resolved Decisions

> All resolved against the code on 2026-06-22 (see brainstorm). None block implementation.

- **D1 — `create_token`/B1:** compute `expires_in = int(exp - now_utc)` at the OAuth2 call
  site; do not change the IdP 4-tuple signature.
- **D2 — `aud`/`jti`:** inject `jti=str(uuid4())` via `data`; add additive `audience=None`
  kwarg to `create_token` (`'user'`/`'app'`); propagate, do not verify `aud`.
- **D3 — jti revocation:** per-request check via in-process TTL cache
  (`OAUTH_REVOCATION_CACHE_TTL`, default 30s), evicted on revoke; durable store is truth.
- **D4 — storage tiers:** add Memory impls for code/refresh/grant/jti + factory honoring
  `OAUTH2_CLIENT_STORAGE`; grants/refresh/jti default to the same durable tier; codes stay
  Redis (short TTL); tests use `memory`.
- **D5 — scope validity:** requested scope outside `client.default_scopes` ⇒ `invalid_scope`;
  non-empty `OAUTH_SCOPES` is authoritative; empty ⇒ client-allow-list only;
  `offline_access` must be in the client's `default_scopes`.
- **D6 — cache key:** add `scope_key=frozenset(scopes)` + public `client_uid` as **separate**
  components, distinct from FEAT-092 tenant `client_id` (int).
- **D7 — client identifier:** new opaque `auth.clients.client_uid VARCHAR UNIQUE`
  (`OAuthClient.client_id`); integer PK stays internal (`OAuthClient.client_pk`, FK target);
  rename nested-model `client_id`→`client`; storage looks up by `client_uid` (drop `int()`).
  New token tables FK on the integer PK. No production data ⇒ backfill + example update only.
- **D8 — logout:** `AUTH_LOGOUT_REDIRECT_URI` already exists — implement teardown + redirect.

---

## Worktree Strategy

- **Isolation unit:** `per-spec` (all tasks sequential in one worktree).
- **Rationale:** Work concentrates on heavily shared hot files (`backend.py`, `models.py`,
  `code_backend.py`, and for P5 `evaluator.py`/`policy.py`), and phases are strictly
  dependency-ordered (M1 foundational; M2/P0 gates all; M8 depends on M2 emitting
  `user_id`/`scope`/`client_uid`). Parallel worktrees would cost more in merge contention
  than they save. Commit per module (M1→M9), running the full suite at each boundary; the
  `test_user_id_survives_refresh` regression gates correctness before later modules build on
  it.
- **Cross-feature dependencies:** FEAT-092 (per-tenant policy scoping) is already merged — no
  ordering dependency, but the P5 changes must respect the shared `ModelPolicy` /
  `_make_cache_key` / `auth.policies` contract (add scopes as *additional* components/columns,
  never overload the tenant `client_id`).

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-06-22 | Jesus Lara | Initial draft from brainstorm (Option A) + source SPEC; all 8 decisions resolved |
