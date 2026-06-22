# Specification — Production-grade 3LO (Three-Legged OAuth2) for `navigator-auth`

> **Audience:** Claude Code, working directly against the `navigator-auth` repository.
> **Goal:** Turn the current *preliminary* Authorization-Code provider into a correct,
> Atlassian-style **3LO** authorization server, where every issued token is bound to a
> specific **(resource owner + client + granted scopes)** triple and the flow is hardened
> for production.

---

## 0. Context & current state

`navigator-auth` already acts as an OAuth2 **Authorization Server** via the
`Oauth2Provider` backend. It exposes `authorize → login → consent → code → token` and
supports `authorization_code`, `client_credentials` and `refresh_token` grants. This is
structurally three-legged but **not** a valid 3LO implementation: the resource owner is
never bound to the grant, several validations are missing, and refresh handling is unsafe.

### Files in scope (verify before editing)

| Path | Symbol(s) | Role |
|------|-----------|------|
| `navigator_auth/backends/oauth2/backend.py` | `Oauth2Provider` | Endpoints: `authorize`, `auth_login`, `consent`, `token_request`, `userinfo`, `logout`, `finish_logout` |
| `navigator_auth/backends/oauth2/models.py` | `OauthUser`, `OAuthClient`, `OauthAuthorizationCode`, `OauthRefreshToken`, `OauthToken` | Pydantic v2 models |
| `navigator_auth/backends/oauth2/client_backend.py` | `ClientStorage` (ABC), `MemoryClientStorage`, `RedisClientStorage`, `PostgresClientStorage` | Client persistence |
| `navigator_auth/backends/oauth2/code_backend.py` | `AuthorizationCodeStorage`, `RefreshTokenStorage` | Code/refresh persistence (Redis-only today) |
| `navigator_auth/backends/oauth2/ddl.sql` | — | DDL for `auth.clients` |
| `navigator_auth/backends/idp/__init__.py` | `IdentityProvider` | Token minting & credential auth |
| `navigator_auth/models.py` | `Client` (asyncdb `Model`, schema `auth`, table `clients`) | DB model |
| `navigator_auth/conf.py` | config constants | Settings |
| `examples/oauth2_server.py` | — | Reference runnable server |

### Known IdP contract (do not break)

- `IdentityProvider.create_token(data: dict, issuer=None, expiration=None) -> (jwt_token: str, exp: float, scheme: str)`
  — **`exp` is an absolute UTC timestamp**, not seconds. (See Bug B1.)
- `IdentityProvider.create_refresh_token() -> str` returns `secrets.token_urlsafe(32)`.
- `IdentityProvider.create_ephemeral_token(data, expiration=1800)`.
- `IdentityProvider.authenticate_credentials(login, password)` — used in `auth_login`.
- `self.authorization_codes: dict` exists in the IdP with a `TODO: migrate to Redis`. The
  OAuth2 provider already uses `AuthorizationCodeStorage` instead; do **not** reintroduce
  the in-memory dict path.

### Models use pydantic v2

Use `model_dump()` / `model_dump_json()` / `model_validate()`. DB layer uses `asyncdb`
`Model`/`Column` with `class Meta: schema = "auth"`.

---

## 1. Non-negotiable correctness target

A valid 3LO access/refresh token MUST encode and be verifiable against:

1. the **resource owner** who authenticated and consented (`user_id`),
2. the **client** that requested access (`client_id`),
3. the **granted scopes** (subset actually approved).

Today `OauthRefreshToken` derives the user from `client.user` (`rt.client_id.user`). That is
the central defect and MUST be eliminated. The user is whoever logged in at
`/oauth2/login` for this authorization, not a static field on the client.

---

## 2. Bugs to fix along the way

- **B1 — `expires_in` is wrong.** `token_request` returns the absolute `exp` timestamp as
  `expires_in`. Per RFC 6749 §5.1, `expires_in` is **seconds until expiry**. Compute
  `int(exp - now_utc_timestamp)` (or change `create_token` to also return seconds). Keep
  this change isolated and covered by a test.
- **B2 — auth-code branch never checks `client_secret`.** Confidential clients MUST be
  authenticated on the token endpoint (see §5.3).
- **B3 — no `redirect_uri` allow-list check** in `authorize` (open redirect / code theft).
- **B4 — `response_type` not validated** in `authorize` (only `code` is supported for 3LO).
- **B5 — `used`/`used_at` flags on `OauthAuthorizationCode` are never enforced.**

---

## 3. Data model changes

### 3.1 `OauthAuthorizationCode` (models.py)

Add resource-owner binding and make PKCE/usage first-class:

- `user_id: int` **(required)** — the authenticated resource owner.
- Keep existing `code_challenge`, `code_challenge_method` (already present) and **enforce**
  them in §5.
- Ensure `used: bool` is honored; on successful exchange set `used=True`, `used_at=now`,
  then delete from storage.

### 3.2 `OauthRefreshToken` (models.py)

- Add `user_id: int` **(required)**.
- Add `parent_token: Optional[str]` (previous refresh token in a rotation chain).
- Add `absolute_expires_at: datetime` (rotation chain hard stop; see §6).
- Stop relying on `client_id.user`. The token-issuing code must read `user_id` from the
  authorization code (auth-code grant) or from the prior refresh token (refresh grant).

### 3.3 New model — `OauthGrant` (consent record)

Represents a durable "user X granted client Y scopes Z" decision.

```python
class OauthGrant(BaseModel):
    grant_id: UUID = Field(default_factory=uuid4)
    user_id: int
    client_id: str
    scopes: list[str]
    granted_at: datetime = Field(default_factory=datetime.now)
    revoked: bool = False
    revoked_at: Optional[datetime] = None
```

Purpose: skip the consent screen when an unrevoked grant already covers the requested
scopes, and power per-app revocation (§7).

### 3.4 Access-token tracking (optional but recommended)

Persist issued access tokens (or at least their `jti`) so revocation can invalidate live
access tokens, not only refresh tokens. If implemented, add a `jti` (UUID) claim in
`create_token`'s payload for OAuth2-issued tokens and store `{jti, user_id, client_id,
scopes, expires_at, revoked}`.

---

## 4. Storage changes

The current code/refresh storage is **Redis-only**. 3LO needs durable persistence for
grants and refresh tokens (for dashboards, audit, rotation chains).

### 4.1 New storage interfaces (mirror existing `ClientStorage` ABC pattern)

- `GrantStorage`: `get_grant(user_id, client_id)`, `save_grant(grant)`,
  `revoke_grant(user_id, client_id)`, `list_grants(user_id)`.
- Extend `RefreshTokenStorage` with: `revoke_token(refresh_token, reason)`,
  `revoke_chain(refresh_token)` (revoke an entire rotation lineage),
  `list_tokens(user_id)`.

Provide **memory / redis / postgres** implementations selected by the existing
`OAUTH2_CLIENT_STORAGE` setting (or a new `OAUTH2_TOKEN_STORAGE` if you want to decouple —
default to the same value).

### 4.2 DDL (append to `navigator_auth/backends/oauth2/ddl.sql`)

Match the `auth` schema and existing style. Suggested tables:

```sql
CREATE TABLE IF NOT EXISTS auth.oauth_grants (
    grant_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       INTEGER NOT NULL REFERENCES auth.users(user_id) ON DELETE CASCADE,
    client_id     INTEGER NOT NULL REFERENCES auth.clients(client_id) ON DELETE CASCADE,
    scopes        JSONB NOT NULL DEFAULT '[]'::jsonb,
    granted_at    TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
    revoked       BOOLEAN DEFAULT FALSE,
    revoked_at    TIMESTAMP WITHOUT TIME ZONE,
    UNIQUE (user_id, client_id)
);

CREATE TABLE IF NOT EXISTS auth.oauth_refresh_tokens (
    refresh_token        VARCHAR(255) PRIMARY KEY,
    client_id            INTEGER NOT NULL REFERENCES auth.clients(client_id) ON DELETE CASCADE,
    user_id              INTEGER NOT NULL REFERENCES auth.users(user_id) ON DELETE CASCADE,
    scope                VARCHAR(1024),
    parent_token         VARCHAR(255),
    issued_at            TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
    expires_at           TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    absolute_expires_at  TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    revoked              BOOLEAN DEFAULT FALSE,
    revoked_at           TIMESTAMP WITHOUT TIME ZONE,
    revoked_reason       VARCHAR(255)
);

-- Optional access-token tracking for revocation
CREATE TABLE IF NOT EXISTS auth.oauth_access_tokens (
    jti         UUID PRIMARY KEY,
    client_id   INTEGER NOT NULL,
    user_id     INTEGER NOT NULL,
    scope       VARCHAR(1024),
    issued_at   TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
    expires_at  TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    revoked     BOOLEAN DEFAULT FALSE
);
```

Authorization codes can stay Redis-only (short TTL), but they MUST now carry `user_id`,
`code_challenge`, `code_challenge_method`. Keep them out of Postgres unless a memory/pg
fallback is needed for tests.

---

## 5. Endpoint behavior (the core of the work)

### 5.1 `GET/POST /oauth2/authorize`

Validate **before** showing login/consent:

1. `response_type == "code"` else `error=unsupported_response_type` (B4).
2. `client = client_storage.get_client(client_id)`; unknown → `error=invalid_client`.
3. `redirect_uri` MUST be an **exact** member of `client.redirect_uris` (B3). On mismatch,
   do **not** redirect — render an error page (never bounce to an unvalidated URI).
4. Parse requested `scope` (space-delimited). Compute
   `granted = requested ∩ allowed`, where `allowed = client.default_scopes`
   (treat empty `default_scopes` as "all configured server scopes" only if you add a
   server scope registry; otherwise reject unknown scopes with `error=invalid_scope`).
5. `state` is preserved and echoed back unchanged.
6. If no session → redirect to `/oauth2/login` carrying the full query (already done).
7. If a session exists:
   - If an unrevoked `OauthGrant` already covers `granted` scopes **and** the client did
     not send `prompt=consent` → skip consent, issue code immediately (§5.2 step 2+).
   - Else → redirect to `/oauth2/consent` with `client_name`, the **filtered** scope list,
     and (if PKCE) the `code_challenge`/`code_challenge_method`.

PKCE capture: if `code_challenge` is present, persist it (and method, default `plain`,
prefer `S256`) so the token endpoint can verify it.

### 5.2 `POST /oauth2/consent` (action=approve)

1. Resolve the authenticated user from the session. The session stores the user under
   `'user'` (jsonpickle-encoded in `auth_login`). Decode it and extract `user_id`. If no
   authenticated user → 401, never mint a code.
2. Create/refresh the `OauthGrant(user_id, client_id, scopes)` record.
3. Build `OauthAuthorizationCode` **including `user_id`**, the filtered `scope`,
   `redirect_uri`, `state`, and PKCE fields. Save with short TTL (keep current ~2 min).
4. Redirect to `redirect_uri?code=...&state=...`.

`action=deny` → `redirect_uri?error=access_denied&state=...` (preserve `state`).

### 5.3 `POST /oauth2/token` — `grant_type=authorization_code`

1. Load code; missing/`used`/expired → `error=invalid_grant`.
2. `auth_code.client_id.client_id == client_id` else `invalid_grant`.
3. `auth_code.redirect_uri == redirect_uri` (already present).
4. **Authenticate the client (B2):** for confidential clients
   (`client.client_type != 'public'`) require and verify `client_secret`. For public
   clients, require PKCE instead.
5. **PKCE verification:** if a `code_challenge` was stored, require `code_verifier` and
   verify: `S256` → `BASE64URL(SHA256(code_verifier)) == code_challenge`; `plain` →
   equality. Failure → `invalid_grant`.
6. Mark code `used=True` and delete it (single use, B5).
7. Build token payload from the **code's** `user_id`, `client_id`, granted `scope`, plus a
   fresh `jti`. Mint access token via `create_token`.
8. Issue a refresh token **only if** `offline_access` ∈ granted scopes (§6). Persist it
   with `user_id`, `scope`, `parent_token=None`, `absolute_expires_at`.
9. Respond with `access_token`, `token_type`, correct `expires_in` (B1), `scope`, and
   `refresh_token` when issued.

### 5.4 `POST /oauth2/token` — `grant_type=refresh_token`

1. Validate client (secret for confidential clients).
2. Load refresh token; missing/revoked/expired/`absolute_expires_at` passed →
   `invalid_grant`.
3. `rt.client_id.client_id == client_id` else `invalid_grant`.
4. **Read `user_id` from the refresh token**, not from `client.user`.
5. **Rotate (§6):** mint a new access token AND a new refresh token; set the new token's
   `parent_token` to the old one and copy `absolute_expires_at`; mark the old token
   `revoked` (reason `rotated`). **Reuse detection:** if a token that is already revoked
   with reason `rotated` is presented again, revoke the entire chain
   (`revoke_chain`) and return `invalid_grant`.
6. Optionally allow scope **narrowing** only (never widening).

### 5.5 `POST /oauth2/token` — `grant_type=client_credentials`

Keep as 2LO (machine-to-machine). It legitimately uses the client-bound identity. Leave as
is but apply B1 (`expires_in`) and confirm `client_secret` is checked (it is).

### 5.6 `GET /oauth2/userinfo` (currently `pass`)

Implement: read bearer token, decode via the IdP, return claims allowed by the token's
scopes (e.g. `sub`/`user_id`, `username`, `email`, `given_name`, `family_name`). 401 on
invalid/expired/revoked token.

### 5.7 `POST /oauth2/revoke` — new (RFC 7009)

Accept `token` + `token_type_hint`. Revoke the refresh token (and its chain) and/or the
access token (`jti`) if access-token tracking is enabled. Always return `200` per spec.

### 5.8 `/oauth2/logout`, `/oauth2/finish_logout` (currently `pass`)

Implement session teardown + redirect to `AUTH_LOGOUT_REDIRECT_URI`. Out of the strict
3LO critical path but should not stay stubs.

---

## 6. Refresh-token policy (Atlassian-aligned)

- Refresh tokens issued **only** when `offline_access` scope is granted.
- **Rotation on every use**; old token invalidated; reuse → chain revocation.
- **Sliding expiry** per token (`expires_at`, e.g. 30 days) bounded by an **absolute
  expiry** (`absolute_expires_at`, e.g. 90 days) carried across the rotation chain.
- Access-token lifetime short (target ~1h). Add config (§8) instead of hardcoding.

---

## 7. Per-app revocation surface

Add minimal handlers (can be JSON API under the existing model/handler conventions):

- `GET /api/v1/oauth2/grants` → list the current user's authorized apps + scopes.
- `DELETE /api/v1/oauth2/grants/{client_id}` → revoke the grant **and** revoke all live
  refresh tokens for `(user_id, client_id)` (and access tokens if tracked).

---

## 8. Configuration (add to `conf.py`)

| Setting | Default | Meaning |
|---------|---------|---------|
| `OAUTH_ACCESS_TOKEN_TTL` | `3600` | Access-token lifetime (s) |
| `OAUTH_REFRESH_TOKEN_TTL` | `2592000` (30d) | Refresh sliding TTL (s) |
| `OAUTH_REFRESH_ABSOLUTE_TTL` | `7776000` (90d) | Refresh absolute lifetime (s) |
| `OAUTH_REFRESH_ROTATION` | `True` | Enable rotation + reuse detection |
| `OAUTH_REQUIRE_PKCE_PUBLIC` | `True` | Require PKCE for public clients |
| `OAUTH_SCOPES` | `[]` | Optional server scope registry |
| `OAUTH_SCOPE_ACTIONS` | `{}` | Map `scope -> [actions/resources]` consumed by the PEP gate and the ABAC evaluator (see §11.7) |

Replace existing hardcoded durations (`timedelta(days=30)`, the `# TODO: 2 hours` comment,
etc.) with these.

---

## 9. Security checklist (must all hold)

- [ ] Token's `user_id` always originates from the authenticated owner, never `client.user`.
- [ ] `redirect_uri` exact-match against client allow-list; no redirect on mismatch.
- [ ] Scope filtered to client-allowed set; unknown scope rejected.
- [ ] Confidential clients authenticated with secret on `/token`.
- [ ] PKCE enforced for public clients and verified when a challenge was stored.
- [ ] Auth codes single-use, short-TTL, deleted after exchange.
- [ ] Refresh rotation + reuse detection + absolute lifetime.
- [ ] `state` preserved end-to-end.
- [ ] `expires_in` reported in seconds.
- [ ] Token `scope` claim surfaced into the ABAC `EvalContext`; access = scopes ∩ ABAC.
- [ ] ABAC decision cache key includes `scopes` + `client_id` (see §11.5).
- [ ] No secrets logged; constant-time comparison for `client_secret` and PKCE
      (`hmac.compare_digest`).

---

## 10. Testing requirements

Add `pytest` (async) coverage under the existing tests layout. Use `MemoryClientStorage`
and memory grant/refresh storages to avoid external deps.

Happy path:
- Full 3LO with PKCE S256: authorize → consent → code → token (user_id bound) →
  userinfo → refresh (rotated) → revoke.

Must-fail cases:
- `redirect_uri` not in allow-list.
- Unknown / disallowed scope.
- Reused authorization code.
- PKCE verifier mismatch.
- Confidential client without/with wrong secret.
- Refresh token reuse after rotation → chain revoked.
- Refresh past `absolute_expires_at`.
- `offline_access` absent → no refresh token issued.

Assert the bound `user_id` survives a refresh (the regression that proves B-fix and §1).

---

## 11. Scope ↔ ABAC integration

OAuth2 scopes and ABAC policies answer **different** questions and must **compose**, not
replace each other.

- **Scope** = what the *user authorized the client/app to do on their behalf* (delegated
  authority — a ceiling).
- **ABAC** = what the *user themselves* may do, plus contextual/environmental constraints
  (groups, time, IP, resource).

> **Effective permission = `granted_scopes ∩ user_ABAC_permissions`.**
> A request must pass **both** gates. A present scope grants nothing if ABAC denies; an
> ABAC `ALLOW` grants nothing if the required scope is absent. This mirrors Atlassian: the
> token scope can never exceed what the user could do unaided. The ABAC engine already
> implements "DENY wins"; an insufficient scope is simply an additional DENY evaluated up
> front.

### 11.1 Surfacing scopes into the `EvalContext`

`EvalContext` (`navigator_auth/abac/context.py`) is built from
`(request, user, userinfo, session)`, where `userinfo = session[AUTH_SESSION_OBJECT]`.
Policies already read `ctx.userinfo['groups']`, `ctx.userinfo['username']`,
`ctx.userinfo.get('roles', [])`. Scopes flow through the **same** channel.

The **resource-server-side bearer-token backend** (the auth backend that validates an
incoming OAuth2 access token and constructs `userinfo`) MUST copy the token claims into
`userinfo` after decoding the JWT via the IdP:

```python
userinfo['scopes'] = payload.get('scope', '').split()
userinfo['client_id'] = payload.get('client_id')
userinfo['token_type'] = payload.get('aud', 'user')  # 'user' (3LO) vs 'app' (2LO)
```

`EvalContext` already exposes `.set(key, value)`; also call
`ctx.set('scopes', userinfo['scopes'])` and `ctx.set('client_id', userinfo['client_id'])`
so policies can reference them via `conditions`/`context`. The `scope` claim is already
emitted by the token (§5.3 step 7) — this phase only **propagates** it, it does not mint it.

### 11.2 Mechanism 1 — PEP fast gate (mandatory, cheap)

Add a per-endpoint scope gate that runs before full ABAC evaluation: a set-membership
check that returns `403 insufficient_scope` when the token lacks the required scope.

- New decorator `@scope_required(*scopes)` in `navigator_auth/abac/decorators.py`,
  mirroring the existing `@groups_protected(groups=[...])`.
- New method on `Guardian` (`navigator_auth/abac/guardian.py`):

```python
async def has_scope(self, request: web.Request, scopes: list) -> bool:
    self.is_authenticated(request=request)
    _, userinfo = await self._get_userinfo(request)   # from session[AUTH_SESSION_OBJECT]
    token_scopes = set(userinfo.get('scopes', []))
    if not set(scopes).issubset(token_scopes):
        raise AccessDenied(reason="insufficient_scope")  # 403
    return True
```

Semantics: **all** listed scopes required (`issubset`). This gates endpoints without
needing a policy per route.

### 11.3 Mechanism 2 — Declarative scope on `Policy`

Make scope a first-class policy attribute so policies can require scopes the same way they
require groups.

- Add `scopes: list` to the `Policy` model (`navigator_auth/abac/policies/policy.py`) and
  to `ModelPolicy` (`navigator_auth/abac/storages/pg.py`), plus the `auth.policies` table.
- In `Policy.evaluate()`, add a `scope_condition` parallel to `groups_condition` and
  include it in the final `and`:

```python
scope_condition = True
if self.scopes:
    token_scopes = set(ctx.userinfo.get('scopes', []))
    scope_condition = set(self.scopes).issubset(token_scopes)
...
if (groups_condition and environment_condition
        and context_condition and subject_condition and scope_condition):
    return PolicyResponse(effect=self.effect, ...)
```

Mirror the same addition in `ObjectPolicy`/`FilePolicy` (`obj.py`) and, if the newer
`ResourcePolicy`/`PolicyEvaluator` path is used, in `evaluate_conditions`.

DDL (append to `navigator_auth/backends/oauth2/ddl.sql`, or wherever `auth.policies` is
managed):

```sql
ALTER TABLE auth.policies ADD COLUMN IF NOT EXISTS scopes JSONB DEFAULT '[]'::jsonb;
```

The PDP loader (`PDP._load_policies`) reads rows into `Policy(**policy)`; ensure `scopes`
is passed through (defaulting to `[]` when null), matching the existing handling of
`resource`/`actions`/`groups`.

### 11.4 CRITICAL — fix the decision cache key

`PolicyEvaluator._make_cache_key` (`navigator_auth/abac/policies/evaluator.py`) currently
keys on `user_id, user_groups, resource_type, resource_name, action` and **omits scopes and
client_id**. Once decisions depend on scope, two tokens for the **same user** with
**different scopes** would collide and receive a stale/incorrect cached decision — a silent
authorization bug.

Fix: include a normalized scope set and `client_id` in the cache key. Normalize to keep the
hit-rate high (sub-ms target):

```python
scope_key = frozenset(ctx.userinfo.get('scopes', []))
client_key = ctx.userinfo.get('client_id')
cache_key = self._make_cache_key(user_id, user_groups, scope_key, client_key,
                                 resource_type, resource_name, action)
```

Update `_make_cache_key`'s signature and all call sites accordingly.

### 11.5 2LO / `client_credentials` tokens

Machine tokens carry `aud: 'app'` and have **no delegated user**. For these:

- Evaluate ABAC against the **client identity** (`client_id`) as a service principal, not a
  user. Allow policies to target `client_id` (the `context`/`conditions` mechanism already
  supports arbitrary attribute matching; `client_id` is now in `userinfo`).
- The scope gate (§11.2) still applies unchanged.
- Do not require `groups`/`subject` user attributes for app tokens; a policy intended for
  service principals should rely on `client_id` + `scopes`.

### 11.6 Action → scope registry

Provide a single place to declare which scope an action/resource requires, consumed by both
the PEP gate (§11.2) and the evaluator. Use the `OAUTH_SCOPE_ACTIONS` config (§8), e.g.
`{"write:jira-work": ["jira:work:create", "jira:work:update"]}`. The gate resolves the
required scope(s) for the requested action from this map instead of hardcoding scope names
at each call site. Keep `OAUTH_SCOPES` as the authoritative list of valid scope strings
(reject unknown scopes at authorize time, §5.1 step 4).

### 11.7 Tests

- Same user, token **with** required scope → ABAC `ALLOW` ⇒ access granted.
- Same user, token **without** required scope → `403 insufficient_scope` even though the
  user's ABAC policies would allow (proves scope is a ceiling).
- Token has the scope but ABAC `DENY` ⇒ denied (proves AND composition).
- **Cache regression:** evaluate user+resource+action with token A (scope present, allow),
  then immediately with token B (same user, scope absent) ⇒ second call denied, NOT served
  from cache. This proves §11.4.
- `client_credentials` token: policy keyed on `client_id` + scope ⇒ allowed; user-keyed
  policy ⇒ not erroneously matched.

### 11.8 Acceptance criteria

- [ ] `scopes` and `client_id` available on `ctx.userinfo` for token-authenticated requests.
- [ ] `@scope_required` / `Guardian.has_scope` enforce `insufficient_scope` (403).
- [ ] `Policy.scopes` evaluated as an additional AND condition across all policy types.
- [ ] Decision cache key includes normalized scopes + `client_id`.
- [ ] `client_credentials` path evaluates against `client_id`, not a user.
- [ ] Action→scope resolution driven by `OAUTH_SCOPE_ACTIONS`, no hardcoded scope names.

---

## 12. Phased delivery (suggested order for Claude Code)

- **P0 — Correctness:** §3.1–3.2 model fields, bind `user_id` through consent → code →
  token → refresh; fix B1, B2, B3, B4, B5. Tests for the bound-user regression.
- **P1 — PKCE:** §5.1/§5.3 capture + verify (S256 + plain).
- **P2 — Refresh hardening:** §6 rotation, reuse detection, absolute lifetime; durable
  refresh storage (§4) + DDL.
- **P3 — Grants & consent skip & revocation:** §3.3, §5.2 step 2, §5.7, §7.
- **P4 — userinfo / logout / config polish:** §5.6, §5.8, §8.
- **P5 — Scope ↔ ABAC integration:** §11. Surface scopes into `EvalContext`, add
  `@scope_required`/`Guardian.has_scope`, add `Policy.scopes` + DDL, **fix the decision
  cache key (§11.4)**, handle `client_credentials` service principals, and wire the
  action→scope registry. Depends on P0 (token carries `user_id`/`scope`/`client_id`).

Each phase: keep existing public signatures stable where possible, run the full test suite,
and update `documentation/oauth.md` to reflect new endpoints (`/oauth2/revoke`,
`/api/v1/oauth2/grants`), `offline_access`, PKCE, and rotation semantics.

---

## 13. Explicit non-goals (do not implement now)

- OpenID Connect (`id_token`, discovery, `nonce` semantics beyond storage).
- Token introspection endpoint (RFC 7662).
- Device Authorization grant.
- DPoP / mTLS sender-constrained tokens.
- Dynamic Client Registration.

Flag any of these if a chosen design makes them cheap, but do not build them under this spec.
