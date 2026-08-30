# Feature Specification: OAuth 2.1 for MCP Agents — DCR, Discovery, Upstream IdP Proxy, Access Gate, JWKS

**Feature ID**: FEAT-095
**Date**: 2026-08-30
**Author**: Jesus Lara
**Status**: draft
**Target version**: 1.4.0

> **Inputs:** `sdd/proposals/oauth2-for-mcp-agents.proposal.md` (decisions D1–D4 resolved
> 2026-08-30) and ai-parrot `sdd/proposals/sdd-brainstorm_agent-methods-as-mcp-tools.md`
> (this feature closes its spike gate **S1**).
> **Hard prerequisites (both merged):** FEAT-093 (`oauth2-3lo-implementation`) and FEAT-094
> (`oauth2-introspection-device-grant`). This feature is the **delta** that makes the existing
> AS reachable by Claude's MCP connector infrastructure — it adds no new grant machinery.
> **Reference (wire contract only, do not port logic):** ai-parrot
> `packages/ai-parrot-server/src/parrot/mcp/oauth_server.py` — its RFC 8414 document shape and
> RFC 7591 request/response shape are proven against Claude's client; its AS is a dev-only
> fixture (auto-approve, no PKCE verify in the mixin, in-memory, no refresh tokens).

---

## 1. Motivation & Business Requirements

### Problem Statement

Claude Web/Desktop custom connectors authenticate **only** via OAuth 2.1
(authorization_code + PKCE, bearer tokens), discover the AS through
`/.well-known/oauth-authorization-server`, and by default self-register through Dynamic
Client Registration. navigator-auth's AS (FEAT-093/094) implements the grant machinery but
is not *discoverable or reachable* by such clients:

- **No DCR (RFC 7591).** `/oauth2/register` does not exist (explicit Non-Goal of both prior
  specs). Claude cannot obtain a `client_id` without manual out-of-band registration.
- **No AS metadata (RFC 8414) / protected-resource metadata (RFC 9728).** The only
  `.well-known` strings in the codebase are *outbound* consumption of Microsoft discovery
  (`backends/jwksutils.py:63`, `backends/adfs.py:69`). Additionally `AUTH_TOKEN_ISSUER`
  defaults to the URN `urn:Navigator` — not a valid RFC 8414 issuer identifier (must be an
  https URL matching the metadata location).
- **The AS login step is local-password only.** `Oauth2Provider.auth_login`
  (`oauth2/backend.py:684`) authenticates via `self._idp.authenticate_credentials` against
  `auth.users` and renders `templates/oauth/login.html`. Corporate users authenticate with
  Google/Microsoft; the existing `GoogleAuth`/`AzureAuth` backends are never reachable from
  the AS authorize flow.
- **No activation gate.** With `AUTH_MISSING_ACCOUNT="create"` (the default), any Google
  login auto-provisions an account; nothing in the login path checks `User.is_active` or any
  allowlist. For MCP exposure, token issuance must be gated on explicit per-user activation.
- **Symmetric tokens only.** HS256 with a shared `SECRET_KEY`; no `jwks_uri`, so third-party
  or polyglot resource servers can only validate via `/oauth2/introspect`.

**Who is affected:** ai-parrot (its "Agent Methods as MCP Tools" feature is blocked on S1),
Claude Web/Desktop users of MCP connectors, platform operators controlling who may reach
agent tools, and third-party resource servers wanting offline token validation.

### Goals

- **RFC 7591 DCR**, `POST /oauth2/register`, **open registration** (D1): anonymous clients
  may register; the access gate at `/authorize` is the actual access control. Policy knob
  `OAUTH_DCR_POLICY = open | allowlist | disabled`; Redis-backed rate limiting.
- **RFC 8414** `/.well-known/oauth-authorization-server` and **RFC 9728**
  `/.well-known/oauth-protected-resource`, plus a reusable metadata builder so external
  resource servers (ai-parrot MCP mounts) can emit their own PRM pointing at this AS.
  Introduce `AUTH_ISSUER_URL` (https) as the canonical issuer.
- **Upstream IdP proxy** (D2): `auth_login` offers the configured `ExternalAuth` backends
  (Google, Azure); the pending authorize request survives the upstream hop via
  `IdentityFlowStore` and resumes into consent/code issuance on callback. Upstream tokens
  persist to the Identity Vault (`auth.user_identities`).
- **Per-client access gate** (D3): `auth.client_access` checked at `/oauth2/authorize` (and
  device verification) before consent; non-activated users get `access_denied` and never a
  token; deactivation cascades grant + refresh-chain + `jti` revocation for that
  (user, client) pair.
- **Asymmetric signing + JWKS** (D4): optional RS256/ES256 signing with `kid` headers,
  `GET /oauth2/jwks`, key rotation (multiple verification keys); HS256 stays the default.
- **OAuth 2.1 / Claude conformance:** `/token` accepts `application/x-www-form-urlencoded`
  (JSON body ⇒ 415); 401 challenges carry
  `WWW-Authenticate: Bearer resource_metadata="…"`; discovery/registration/token respond
  well inside Claude's ≤10 s budget (≤30 s refresh); conformance tests replay Claude's
  observed client behavior for both DCR and static clients.

### Non-Goals (explicitly out of scope)

- OIDC `id_token` issuance, DPoP/mTLS, Token Exchange, CIBA (still deferred).
- Re-litigating FEAT-093/094 mechanics (owner-binding, PKCE, rotation, introspection,
  device grant) — consumed as-is.
- Full RFC 8707 multi-resource audience restriction — **minimal support only**: accept and
  validate the `resource` parameter, reflect the canonical resource into the token `aud`
  claim when provided (see OQ1 for anything beyond).
- A PBAC shadow/dry-run mode. **Note for ai-parrot D11:** `enforcing: false` on policies
  means "non-short-circuiting ordinary policy" (`abac/policies/abstract.py:81`), *not*
  audit-only; a real shadow mode would be separate work on `abac/pdp.py`/`audit.py`.
- ai-parrot's half: `resolve_principal`, MCP tool exposure, PRM served by MCP mounts
  (navigator-auth ships the builder; ai-parrot serves its own document).
- Deleting the ai-parrot dev fixture (its repo, its cleanup).

---

## 2. Architectural Design

### Overview

Extend `Oauth2Provider` in place (the FEAT-093/094 pattern), with the genuinely new logic
isolated in small pure modules: `oauth2/metadata.py` (RFC 8414/9728 document builders),
`oauth2/dcr.py` (RFC 7591 metadata validation/mapping), `oauth2/client_access.py` (gate
storage), and `backends/idp/keys.py` (signing-key registry). The upstream-IdP hop reuses the
`ExternalAuth` flow wholesale: the AS parks the pending authorize request in
`IdentityFlowStore`, sends the browser through the chosen backend's normal
`/auth/{service}/login` → `/auth/{service}/callback/` round-trip, and a resume hook returns
the now-authenticated session to `/oauth2/authorize` where FEAT-093 takes over (gate check →
consent → code). No change to code/token semantics anywhere.

### Component Diagram

```
Claude (connector infra)
  │ GET /.well-known/oauth-authorization-server ──▶ metadata.py builder (issuer=AUTH_ISSUER_URL,
  │                                                  endpoints, S256, jwks_uri iff asymmetric)
  │ POST /oauth2/register  (RFC 7591 JSON) ───────▶ dcr.py validate/map ─▶ ClientStorage.save_client
  │                                                  (client_uid exists; rate-limit; policy knob)
  │ GET /oauth2/authorize (code+PKCE, client_uid)
  │        │
  │        ├─ no session ─▶ auth_login: local form + [Google] [Azure] buttons
  │        │                     │ (provider chosen)
  │        │                     ▼
  │        │   IdentityFlowStore.set(oauth2_pending_{flow_id}, authorize params)
  │        │                     ▼
  │        │   ExternalAuth backend authenticate() ─▶ Google / Microsoft ─▶ callback
  │        │        validate_user_info → auto-provision (AUTH_MISSING_ACCOUNT) → remember(session)
  │        │        upstream tokens ─▶ IdentityStore (auth.user_identities)
  │        │                     ▼
  │        │   resume: 302 → /oauth2/authorize?flow=… (params restored from flow store)
  │        │
  │        ├─ ACCESS GATE: client_access.check(user_id, client_uid)  ── denied ─▶ access_denied
  │        ▼
  │   FEAT-093 consent → code ─▶ redirect https://claude.ai/api/mcp/auth_callback?code=…
  │
  │ POST /oauth2/token (form-urlencoded; PKCE verify; rotated refresh)   [FEAT-093, unchanged]
  ▼
ai-parrot MCP server ─ bearer ─▶ /oauth2/introspect (FEAT-094)  or  offline verify via /oauth2/jwks
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `Oauth2Provider` (`oauth2/backend.py`) | modifies | New routes in `configure()`: `/.well-known/*` (root-level), `/oauth2/register`, `/oauth2/jwks`; `auth_login` provider branch + resume; gate check in `authorize` + device verification; all public paths appended to `AUTH_EXCLUDE_LIST_KEY` |
| `ClientStorage` trio (`oauth2/client_backend.py`) | extends | DCR persistence; RFC 7591 field mapping; `client_uid` generation already exists (`save_client`, `secrets.token_urlsafe(18)`) |
| `Client` model (`models.py:318`) + `oauth2/ddl.sql` | extends | `+token_endpoint_auth_method`, `+registration_source` (`dcr`/`static`), `+enforce_access_gate BOOL`; new table `auth.client_access` |
| `ExternalAuth` (`backends/external.py`) | extends | Resume hook: after `validate_user_info`/`remember`, if an `oauth2_pending` flow marker is present, redirect back to `/oauth2/authorize` instead of `home_redirect` |
| `GoogleAuth` / `AzureAuth` | depends on | Used as-is via `AuthHandler.get_external_backend(service)` (`auth.py:341`); fix the `azure.py:180` shared-singleton `self.redirect_uri` mutation by switching to `get_redirect_uri()` (`external.py:211`) |
| `IdentityFlowStore` (`identity/flow_store.py`) | uses | Carries pending authorize params across the upstream hop (TTL ~600 s) |
| `IdentityStore` / `TokenResponse` (`identity/`) | uses | Persist upstream Google/Azure tokens on AS-initiated login (same as identity-link flow) |
| `IdentityProvider` (`backends/idp/__init__.py`) | extends | Signing-key registry; `create_token`/`decode_token` honor `kid` + configured algorithm; HS256 path byte-identical when asymmetric off |
| `AccessTokenStorage` / `RefreshTokenStorage` / `GrantStorage` (FEAT-093) | depends on | Gate-deactivation cascade: revoke grants, refresh chains, `jti`s for (user, client) |
| `AuthHandler` (`auth.py`) | modifies | 401 responses add `WWW-Authenticate: Bearer resource_metadata="…"`; `.well-known` paths in the global exclude list |
| `handlers/` | extends | `ClientAccessHandler` management API |
| `conf.py` | extends | New `AUTH_ISSUER_URL`, `OAUTH_DCR_*`, `OAUTH_UPSTREAM_IDP_*`, `OAUTH_ACCESS_GATE_*`, `OAUTH_JWT_*` keys |

### Data Models

```python
# oauth2/models.py — DCR request/response (RFC 7591 field names, Pydantic v2)
class ClientRegistrationRequest(BaseModel):
    redirect_uris: list[str]                          # required; https or claude callbacks
    client_name: Optional[str] = None
    grant_types: list[str] = ["authorization_code", "refresh_token"]
    response_types: list[str] = ["code"]
    token_endpoint_auth_method: str = "client_secret_post"   # or "none" (public client)
    scope: Optional[str] = None
    client_uri: Optional[str] = None
    logo_uri: Optional[str] = None

class ClientRegistrationResponse(BaseModel):
    client_id: str                                    # = client_uid
    client_secret: Optional[str] = None               # absent for public clients
    client_id_issued_at: int
    client_secret_expires_at: int = 0                 # non-expiring per RFC 7591
    # + echo of registered metadata

# models.py — access gate
class ClientAccess(Model):                            # auth.client_access
    access_id: uuid.UUID                              # PK
    user_id: int                                      # FK auth.users
    client_id: int                                    # FK auth.clients (internal PK)
    client_uid: str                                   # denormalized wire id
    status: str = "active"                            # active | revoked | pending
    granted_by: Optional[int] = None
    granted_at: datetime
    revoked_at: Optional[datetime] = None

# backends/idp/keys.py — signing key registry
class SigningKey(BaseModel):
    kid: str
    algorithm: str                                    # HS256 | RS256 | ES256
    private_key: Optional[SecretStr] = None           # signing (active key only)
    public_key: Optional[str] = None                  # verification (all keys)
    active: bool = False                              # exactly one active signing key
```

### New Public Interfaces

```python
# oauth2/metadata.py — pure builders (no aiohttp imports; unit-testable)
def build_as_metadata(issuer: str, *, dcr_enabled: bool, jwks: bool,
                      grant_types: list[str], scopes: list[str]) -> dict: ...   # RFC 8414
def build_protected_resource_metadata(resource: str, auth_servers: list[str],
                                      scopes: list[str]) -> dict: ...           # RFC 9728
# The PRM builder is importable by external resource servers (ai-parrot MCP mounts).

# oauth2/dcr.py — pure validation/mapping
def validate_registration(req: dict, policy: str, allowlist: list[str]) -> ClientRegistrationRequest: ...
def to_oauth_client(reg: ClientRegistrationRequest) -> OAuthClient: ...

# oauth2/client_access.py — storage ABC + memory/redis/postgres (FEAT-093 factory pattern)
class ClientAccessStorage(ABC):
    async def check(self, user_id: int, client_uid: str) -> bool: ...
    async def grant(self, user_id: int, client_uid: str, granted_by: int) -> ClientAccess: ...
    async def revoke(self, user_id: int, client_uid: str) -> bool: ...   # triggers cascade
    async def list_for_client(self, client_uid: str) -> list[ClientAccess]: ...

# New endpoints on Oauth2Provider
#   GET  /.well-known/oauth-authorization-server      (RFC 8414; also under /oauth2/ alias)
#   GET  /.well-known/oauth-protected-resource        (RFC 9728)
#   POST /oauth2/register                             (RFC 7591; open per D1; rate-limited)
#   GET  /oauth2/jwks                                 (JWK Set; asymmetric keys only)
#   GET/POST /api/v1/oauth2/clients/{client_uid}/access   (gate management; admin-only)
```

---

## 3. Module Breakdown

> Dependency-ordered. M1 is foundational config; M2/M3 are independent of M4/M5; M6 (JWKS)
> is independent of everything except M2's conditional `jwks_uri`.

### Module 1: Issuer identity + configuration foundation
- **Path**: `conf.py`, `oauth2/backend.py`
- **Responsibility**: `AUTH_ISSUER_URL` (https; when unset, derived from request
  scheme/host honoring `X-Forwarded-Proto`/`Host` — reverse-proxy safe). Full `OAUTH_DCR_*`
  / `OAUTH_ACCESS_GATE_*` / `OAUTH_UPSTREAM_IDP_*` / `OAUTH_JWT_*` config block (§6). A
  single `issuer_url(request)` helper used by every new endpoint.
- **Depends on**: FEAT-093.

### Module 2: Discovery documents (RFC 8414 + RFC 9728)
- **Path**: `oauth2/metadata.py` (new), `oauth2/backend.py`, `auth.py`
- **Responsibility**: pure builders + `GET` routes at root (`/.well-known/…` must live at
  the origin root per RFC 8414 §3; also alias under the AS path). AS metadata: `issuer`,
  `authorization_endpoint`, `token_endpoint`, `registration_endpoint` (iff DCR enabled),
  `introspection_endpoint`, `revocation_endpoint`, `device_authorization_endpoint`,
  `response_types_supported: ["code"]`, `grant_types_supported`,
  `code_challenge_methods_supported: ["S256"]`,
  `token_endpoint_auth_methods_supported: ["client_secret_post","client_secret_basic","none"]`,
  `scopes_supported` (from `OAUTH_SCOPES` when non-empty), `jwks_uri` (iff M6 active).
  PRM: `resource`, `authorization_servers: [issuer]`, `scopes_supported`,
  `bearer_methods_supported: ["header"]`. Both paths in the exclude list; responses cached
  in-process. Wire-contract parity with the ai-parrot fixture's `_handle_discovery`.
- **Depends on**: Module 1 (issuer); reads M6 config for `jwks_uri`.

### Module 3: Dynamic Client Registration (RFC 7591)
- **Path**: `oauth2/dcr.py` (new), `oauth2/backend.py`, `oauth2/client_backend.py`,
  `models.py`, `oauth2/ddl.sql`
- **Responsibility**: `POST /oauth2/register` (JSON body; exclude list). **Open policy
  default (D1)**; `OAUTH_DCR_POLICY=allowlist` restricts registrable `redirect_uris` to
  `OAUTH_DCR_REDIRECT_ALLOWLIST` (glob patterns; Claude callbacks
  `https://claude.ai/api/mcp/auth_callback` and `https://claude.com/api/mcp/auth_callback`
  shipped as defaults); `disabled` ⇒ `400 {"error":"registration_not_supported"}`.
  Validation: `redirect_uris` required, https-only (localhost exempt for dev),
  `token_endpoint_auth_method=none` ⇒ `client_type=public`, **no secret issued**, PKCE
  consequently mandatory (FEAT-093 `OAUTH_REQUIRE_PKCE_PUBLIC`); confidential ⇒
  `client_secret = secrets.token_urlsafe(32)`. Map `grant_types`→`allowed_grant_types`,
  `scope`→`default_scopes` (default `OAUTH_DCR_DEFAULT_SCOPES`). Persist via
  `ClientStorage.save_client` (all three tiers); `registration_source='dcr'`,
  `enforce_access_gate` from `OAUTH_DCR_GATE_NEW_CLIENTS` (default **True** — DCR clients
  are born gated). Response: 201 with RFC 7591 fields (`client_id`=`client_uid`,
  `client_id_issued_at`, `client_secret_expires_at: 0`); errors as
  `{"error":"invalid_client_metadata","error_description":…}`. Anti-abuse: Redis
  rate-limit per source IP (`OAUTH_DCR_RATE_LIMIT`, default 10/hour) + TTL reaper for DCR
  clients that never completed a token exchange (`OAUTH_DCR_UNUSED_TTL`, default 30 d).
- **Depends on**: Modules 1–2.

### Module 4: Upstream IdP proxy login (D2)
- **Path**: `oauth2/backend.py`, `backends/external.py`, `backends/azure.py`,
  `templates/oauth/login.html`
- **Responsibility**: `auth_login` renders provider buttons for
  `OAUTH_UPSTREAM_IDP_BACKENDS` (e.g. `["google","azure"]`; empty list ⇒ current
  local-only behavior, fully backward compatible). On provider selection:
  generate `flow_id`, persist the **complete pending authorize request** (client_uid,
  redirect_uri, scope, state, code_challenge(+method), resource) in `IdentityFlowStore`
  under `oauth2_pending_{flow_id}` (TTL 600 s), then redirect into the backend's
  `authenticate()` carrying `{"oauth2_flow": flow_id}` through the backend's own
  state-keyed flow record. On callback, `ExternalAuth._auth_callback_dispatch` (extended):
  after `validate_user_info` creates the session (auto-provisioning per
  `AUTH_MISSING_ACCOUNT`, upstream tokens → `IdentityStore` exactly as the identity-link
  flow), detect `oauth2_flow` and 302 back to `/oauth2/authorize?flow={flow_id}` instead of
  `home_redirect`; `authorize` restores parameters from the flow store (single-use
  `getdel`) and proceeds (gate → consent → code). Fix `azure.py:180` to use
  `get_redirect_uri()` instead of mutating the singleton. Expired/missing flow ⇒ restart
  authorize cleanly with `invalid_request` messaging (never a broken redirect).
- **Depends on**: Module 1; `IdentityFlowStore`/`IdentityStore` (existing).

### Module 5: Per-client access gate (D3)
- **Path**: `oauth2/client_access.py` (new), `models.py`, `oauth2/ddl.sql`,
  `oauth2/backend.py`, `handlers/client_access.py` (new), `conf.py`
- **Responsibility**: `ClientAccessStorage` ABC + memory/redis/postgres tiers registered in
  the FEAT-093 storage factory; `auth.client_access` DDL (unique `(user_id, client_id)`,
  indexed by `client_uid`). Gate check in `authorize` (after login, **before consent**) and
  in FEAT-094 device verification: enforced when `OAUTH_ACCESS_GATE_ENABLED` (global,
  default **False**) *or* the client's `enforce_access_gate` flag is set; failure ⇒
  standard `access_denied` error redirect (with `state`) — the user never reaches consent,
  never gets a code. Deactivation (`revoke`): cascade via existing primitives — revoke the
  `OauthGrant`s, `revoke_chain` on refresh tokens, revoke live `jti`s for that
  (user, client); effective ≤ access-token TTL (FEAT-093 acceptance model). Management
  API `GET/POST/DELETE /api/v1/oauth2/clients/{client_uid}/access` (admin/superuser only,
  behind existing auth middleware + ABAC). Optional `status=pending` rows recorded on
  denied attempts when `OAUTH_ACCESS_GATE_QUEUE=True` (OQ3) so admins see who requested.
- **Depends on**: Modules 1, 4 (ordering inside `authorize`); FEAT-093/094 storages.

### Module 6: Asymmetric signing + JWKS (D4)
- **Path**: `backends/idp/keys.py` (new), `backends/idp/__init__.py`, `oauth2/backend.py`,
  `conf.py`
- **Responsibility**: key registry loaded from `OAUTH_JWT_KEYS` (list of PEM file paths or
  inline; each with `kid`, algorithm, `active` flag — exactly one active signer; inactive
  keys verify only, enabling rotation). `create_token`: when `OAUTH_JWT_SIGNING_ALG` is
  RS256/ES256, sign with the active private key and set the `kid` header; **HS256 default
  path byte-identical to today** (no behavior change when unconfigured). `decode_token`:
  select verification key by `kid` header, fall back to `SECRET_KEY` HS256 (mixed-token
  migration). `GET /oauth2/jwks` serves the public JWK Set (public keys only, `use: sig`);
  exclude list; M2 advertises `jwks_uri` iff a key registry is loaded. The 4-tuple
  `create_token` signature is unchanged.
- **Depends on**: Module 1. Independent of M3–M5.

### Module 7: OAuth 2.1 / Claude conformance hardening
- **Path**: `oauth2/backend.py`, `backends/api.py`, `auth.py`
- **Responsibility**: `/oauth2/token` rejects non-form-urlencoded bodies with **415**
  (Claude sends form-urlencoded; JSON-only servers fail with 415 on Claude's side —
  invert that: we accept form, refuse JSON). Accept `client_secret_basic` in addition to
  `client_secret_post` at token/introspect/revoke (RFC 8414 advertises both). Accept the
  RFC 8707 `resource` parameter at authorize+token: validate it is an absolute URI without
  fragment, persist through the code, reflect the canonical resource into `aud` alongside
  the FEAT-093 `'user'`/`'app'` marker (list-valued `aud`). Bearer 401s (resource-server
  path, `backends/api.py` + `auth.py` middleware) add
  `WWW-Authenticate: Bearer resource_metadata="{issuer}/.well-known/oauth-protected-resource"`.
- **Depends on**: Modules 1–3.

### Module 8: Tests, docs, examples
- **Path**: `tests/`, `documentation/oauth.md`, `documentation/mcp-connector.md` (new),
  `examples/oauth2_mcp_server.py` (new)
- **Responsibility**: full suite (§4) including a **Claude-replay conformance test** that
  drives discovery → DCR → authorize (PKCE) → token → refresh → introspect exactly as
  Claude's client does (both DCR and static-client variants; assert each leg well under the
  10 s/30 s budgets). Example server wiring GoogleAuth+AzureAuth as upstream IdPs with the
  gate enabled. Documentation: connector setup guide (what URL to paste into Claude Web),
  gate administration, key rotation runbook.
- **Depends on**: all.

---

## 4. Test Specification

### Unit Tests
| Test | Module | Description |
|---|---|---|
| `test_as_metadata_document` | M2 | RFC 8414 fields; issuer == `AUTH_ISSUER_URL`; S256 only; `registration_endpoint` present iff DCR enabled; `jwks_uri` present iff keys loaded |
| `test_prm_document` | M2 | RFC 9728 fields; `authorization_servers` = [issuer]; builder importable standalone |
| `test_issuer_derivation_proxy` | M1 | `X-Forwarded-Proto`/`Host` honored when `AUTH_ISSUER_URL` unset; https enforced |
| `test_dcr_register_public_client` | M3 | `token_endpoint_auth_method=none` ⇒ public, no secret, 201, RFC 7591 response shape |
| `test_dcr_register_confidential` | M3 | secret issued, `client_secret_expires_at: 0`, persisted via ClientStorage (memory tier) |
| `test_dcr_policy_allowlist` | M3 | non-matching redirect_uri rejected under `allowlist`; Claude callbacks pass by default |
| `test_dcr_policy_disabled` | M3 | `registration_not_supported` |
| `test_dcr_invalid_metadata` | M3 | missing redirect_uris / http URI / bad grant_type ⇒ `invalid_client_metadata` |
| `test_dcr_rate_limit` | M3 | >N registrations/hour from one source ⇒ 429 |
| `test_dcr_client_born_gated` | M3 | DCR client gets `enforce_access_gate=True` when `OAUTH_DCR_GATE_NEW_CLIENTS` |
| `test_upstream_flow_park_resume` | M4 | authorize params parked in flow store, restored single-use after callback; consent proceeds |
| `test_upstream_flow_expired` | M4 | expired/missing flow ⇒ clean `invalid_request` restart, no broken redirect |
| `test_upstream_identity_vault` | M4 | upstream tokens land ciphered in `auth.user_identities` via IdentityStore |
| `test_local_login_unchanged` | M4 | empty `OAUTH_UPSTREAM_IDP_BACKENDS` ⇒ current password flow byte-identical |
| `test_gate_blocks_before_consent` | M5 | non-activated user ⇒ `access_denied` redirect with `state`; no consent, no code |
| `test_gate_disabled_by_default` | M5 | gate off globally + client flag off ⇒ FEAT-093 behavior unchanged |
| `test_gate_revoke_cascade` | M5 | deactivate ⇒ grants revoked, refresh chain revoked, `jti`s revoked; next `tools`-style call 401 |
| `test_gate_device_flow` | M5 | gate also enforced at FEAT-094 device verification |
| `test_jwks_document` | M6 | public keys only, `kid`/`use: sig`; no private material ever serialized |
| `test_rs256_sign_verify_kid` | M6 | RS256 token carries `kid`; decode selects key by `kid`; rotation: old key verifies, only active signs |
| `test_hs256_default_unchanged` | M6 | unconfigured ⇒ HS256 tokens identical to pre-feature output |
| `test_token_endpoint_415_json` | M7 | JSON body at `/oauth2/token` ⇒ 415; form-urlencoded ⇒ normal |
| `test_client_secret_basic` | M7 | Authorization: Basic accepted at token/introspect/revoke |
| `test_resource_param_aud` | M7 | `resource=` validated (absolute URI, no fragment) and reflected into `aud` |
| `test_www_authenticate_challenge` | M7 | bearer 401 carries `resource_metadata` challenge |

### Integration Tests
| Test | Description |
|---|---|
| `test_claude_replay_dcr` | **S1 closure** — discovery → DCR → authorize (PKCE S256) → gate-activated user consents → code → form-urlencoded token → refresh rotation → introspect active; each leg < budget |
| `test_claude_replay_static_client` | Same flow with a pre-registered static client (no DCR) |
| `test_upstream_google_end_to_end` | authorize → provider button → mocked Google callback → auto-provision → gate → consent → owner-bound token; upstream tokens in vault |
| `test_gate_lifecycle` | activate → full flow works → deactivate → refresh fails (`invalid_grant`), introspect inactive, new authorize ⇒ `access_denied` |
| `test_asymmetric_e2e` | RS256 configured ⇒ metadata advertises jwks_uri; third-party validation using only the JWK Set (no introspection call) |

### Test Data / Fixtures
```python
@pytest.fixture
def memory_oauth_storages(monkeypatch):
    # OAUTH2_CLIENT_STORAGE=memory ⇒ client/code/refresh/grant/jti/device + ClientAccess stores
    ...

@pytest.fixture
def claude_like_client_metadata():
    # RFC 7591 body as Claude sends it: client_name="Claude",
    # redirect_uris=["https://claude.ai/api/mcp/auth_callback"], token_endpoint_auth_method=none
    ...

@pytest.fixture
def mock_external_backend(monkeypatch):
    # Fakes GoogleAuth authenticate()/auth_callback() without network; drives the resume hook
    ...

@pytest.fixture
def rsa_keypair(tmp_path):
    # Generates a throwaway RS256 keypair; loads it into the key registry with kid="test-1"
    ...
```

---

## 5. Acceptance Criteria

> This feature is complete when ALL of the following are true:

- [ ] `GET /.well-known/oauth-authorization-server` serves a valid RFC 8414 document at the
      origin root with an https issuer; `GET /.well-known/oauth-protected-resource` serves
      RFC 9728; both unauthenticated and < 1 s.
- [ ] A client POSTing Claude-shaped RFC 7591 metadata to `/oauth2/register` receives 201
      with `client_id` (=`client_uid`), correct public/confidential handling, and can
      immediately run the full authorize+PKCE+token flow (DCR is **open** per D1, rate-limited).
- [ ] `OAUTH_DCR_POLICY` supports `open` (default) / `allowlist` / `disabled` with the Claude
      callback URLs allowlisted out of the box.
- [ ] With `OAUTH_UPSTREAM_IDP_BACKENDS=["google","azure"]`, `/oauth2/authorize` for an
      unauthenticated user offers Google/Microsoft login; the pending authorize request
      survives the hop and resumes into consent; upstream tokens are vaulted; with the
      setting empty, behavior is byte-identical to FEAT-093.
- [ ] A non-activated user on a gated client receives `access_denied` (with `state`) and
      never a code or token; activating via the management API unblocks; deactivating
      cascades revocation with effect ≤ access-token TTL. Gate defaults off globally;
      DCR-registered clients are born gated (`OAUTH_DCR_GATE_NEW_CLIENTS=True`).
- [ ] With RS256/ES256 configured: tokens carry `kid`, `/oauth2/jwks` serves the public set,
      metadata advertises `jwks_uri`, old keys verify during rotation, and a third party can
      validate offline. Unconfigured: HS256 output unchanged.
- [ ] `/oauth2/token` accepts form-urlencoded (415 on JSON), supports `client_secret_basic`,
      and accepts + reflects the RFC 8707 `resource` parameter into `aud`.
- [ ] Bearer 401s carry the `WWW-Authenticate: Bearer resource_metadata=…` challenge.
- [ ] The two Claude-replay conformance tests pass with every leg inside the 10 s/30 s
      budgets (S1 closed).
- [ ] No breaking changes: FEAT-093/094 test suites pass unmodified; all new behavior is
      opt-in via config.
- [ ] All unit + integration tests pass (`pytest tests/ -v`); `documentation/oauth.md`,
      the new connector guide, and `examples/oauth2_mcp_server.py` updated.

---

## 6. Implementation Notes & Constraints

### Patterns to Follow
- Extend FEAT-093's storage ABC + memory/redis/postgres + factory pattern for
  `ClientAccessStorage`; Pydantic v2; asyncdb `Model`/`Column` with
  `class Meta: schema = "auth"`; async-first; `self.logger`; constant-time comparisons;
  never log secrets, tokens, or private keys.
- Keep new logic in **pure, framework-free modules** (`metadata.py`, `dcr.py`,
  `idp/keys.py`) mirroring the FEAT-093/094 helper discipline (`pkce.py`, `devicecode.py`).
- `create_token` keeps its 4-tuple signature; `IdentityProvider` behavior with default
  config must be bit-for-bit unchanged.
- `uv` + activated venv for all commands.

### Known Risks / Gotchas
- **`.well-known` root mounting.** RFC 8414 requires the document at the origin root, but
  deployments may mount navigator-auth under a path prefix or behind a proxy. Ship both the
  root route and an explicit `AUTH_ISSUER_URL`; document the reverse-proxy rewrite. Wrong
  issuer ⇒ Claude shows "Disconnected" with no useful error (per ai-parrot §4 findings).
- **Open DCR abuse (D1).** Registration is open by design; mitigations are rate limiting,
  the unused-client reaper, no privileges attached to registration (the gate is the
  control), and `registration_source='dcr'` for auditability. Revisit `allowlist` as
  default if abuse observed.
- **Flow-store state across the upstream hop.** The authorize request (incl.
  `code_challenge`) must round-trip **exactly**; losing `state` or the challenge breaks
  PKCE or CSRF protection. Single-use `getdel`, TTL 600 s, and the
  `test_upstream_flow_park_resume` test gate this.
- **Shared-singleton backends.** `azure.py:180` mutates `self.redirect_uri` on the
  process-wide backend; must move to `get_redirect_uri()` before the AS drives it
  concurrently.
- **Three meanings of `client_id`** persist (FEAT-093): internal int PK (FK target —
  `auth.client_access.client_id`), public `client_uid` (wire), FEAT-092 tenant id. Keep the
  discipline; the gate table carries both int FK and denormalized `client_uid`.
- **HS256→RS256 migration.** During rotation both algorithms verify (`kid`-based dispatch,
  HS256 fallback); never advertise `jwks_uri` without keys loaded; JWKS must never
  serialize private material (dedicated test).
- **Device flow parity.** The gate must cover FEAT-094's `/oauth2/device` verification too,
  or the gate is bypassable via the device grant.
- **PyJWT asymmetric support** requires the `cryptography` package — verify it is already a
  transitive dependency before adding anything to `pyproject.toml`.

### Configuration Keys (navigator_auth.conf)
| Setting | Default | Meaning |
|---|---|---|
| `AUTH_ISSUER_URL` | *(derived from request)* | Canonical https issuer for RFC 8414/9728 and token `iss` on the OAuth2 path |
| `OAUTH_DCR_POLICY` | `open` | `open` / `allowlist` / `disabled` (D1) |
| `OAUTH_DCR_REDIRECT_ALLOWLIST` | Claude callbacks | Glob patterns for `allowlist` mode |
| `OAUTH_DCR_DEFAULT_SCOPES` | `[]` | Scopes granted to DCR clients when none requested |
| `OAUTH_DCR_GATE_NEW_CLIENTS` | `True` | DCR clients born with `enforce_access_gate` |
| `OAUTH_DCR_RATE_LIMIT` | `10/hour` | Per-source registration rate limit (Redis) |
| `OAUTH_DCR_UNUSED_TTL` | `2592000` | Reap DCR clients with zero token exchanges (s) |
| `OAUTH_UPSTREAM_IDP_BACKENDS` | `[]` | ExternalAuth service names offered at AS login (D2) |
| `OAUTH_UPSTREAM_FLOW_TTL` | `600` | Pending-authorize flow-store TTL (s) |
| `OAUTH_ACCESS_GATE_ENABLED` | `False` | Enforce the gate for **all** clients (D3) |
| `OAUTH_ACCESS_GATE_QUEUE` | `False` | Record `pending` rows on denied attempts (OQ3) |
| `OAUTH_JWT_SIGNING_ALG` | `HS256` | `HS256` / `RS256` / `ES256` (D4) |
| `OAUTH_JWT_KEYS` | `[]` | Key registry: `{kid, algorithm, private_key_file/public_key_file, active}` |

### External Dependencies
| Package | Version | Reason |
|---|---|---|
| *(none new expected)* | — | DCR/discovery/gate: stdlib + existing asyncdb/redis. RS256/ES256: `pyjwt` + `cryptography` — confirm `cryptography` already present (transitive) before touching `pyproject.toml` |

---

## 7. Open Questions

- [ ] **OQ1 — RFC 8707 beyond minimal.** M7 accepts + reflects `resource` into `aud`.
      Should resource servers *enforce* audience match (reject tokens minted for another
      resource)? Defer to ai-parrot integration testing. — *Owner: Jesus Lara*
- [ ] **OQ2 — PRM ownership for ai-parrot mounts.** navigator-auth ships
      `build_protected_resource_metadata`; confirm ai-parrot serves its own
      `/.well-known/oauth-protected-resource` per MCP mount and consumes the builder.
      — *Owner: Jesus Lara (ai-parrot side)*
- [ ] **OQ3 — Activation UX.** Admin API only, or approval queue
      (`OAUTH_ACCESS_GATE_QUEUE` records `pending` rows an admin can approve)? Queue is
      spec'd as optional/off; decide before M5 lands whether it ships in v1.
      — *Owner: Jesus Lara*

---

## Worktree Strategy

- **Isolation unit:** `per-spec` (one worktree, sequential tasks), with **M6 (JWKS) as the
  one safely parallelizable module** if a second worktree is wanted — it touches only
  `backends/idp/` + one route, no contention with M2–M5.
- **Rationale:** M1–M5, M7 all edit `oauth2/backend.py` (`configure()`, `authorize`,
  `auth_login`, `token_request`) plus shared `conf.py`/`ddl.sql`/`models.py` — the same
  hot-file contention that drove FEAT-093/094 to per-spec isolation. Sequence:
  M1 → M2 → M3 (Claude can connect with gate off) → M4 → M5 → M6 → M7 → M8, committing per
  module and running the FEAT-093/094 suites at each boundary as a regression gate.
- **Cross-feature dependencies:** FEAT-093 and FEAT-094 are **merged** (verified: all tasks
  in `sdd/tasks/completed/`). ai-parrot's MCP feature depends on this spec (S1) but nothing
  here depends on ai-parrot.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-08-30 | Jesus Lara | Initial draft from `oauth2-for-mcp-agents.proposal.md`; D1–D4 folded in (open DCR, auth_login delegation, per-client gate table, JWKS in scope); OQ1–OQ3 carried |
