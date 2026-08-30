# Feature Proposal: OAuth 2.1 for MCP Agents (DCR + Discovery + Upstream IdP Proxy)

**Date**: 2026-08-30
**Author**: Jesus Lara
**Status**: accepted
**Spec**: sdd/specs/oauth2-for-mcp-agents.spec.md
**Feature ID (reserved)**: FEAT-095
**Depends on**: FEAT-093 (`oauth2-3lo-implementation`, landed), FEAT-094 (`oauth2-introspection-device-grant`, landed)
**Driven by**: ai-parrot `sdd/proposals/sdd-brainstorm_agent-methods-as-mcp-tools.md` — spike gate **S1** ("Does a minimal AS connect from claude.ai without 'Disconnected'?") blocks that feature's proposal stage.

---

## Why

ai-parrot wants to expose decorated agent methods as MCP tools consumable from
Claude Web/Desktop/Code with **per-user identity** and PBAC enforcement. Claude's
custom connectors speak **only OAuth 2.1** (authorization_code + PKCE, bearer
tokens), support Dynamic Client Registration (RFC 7591), and require the standard
discovery documents. Users authenticate with their corporate Google or Microsoft
accounts — navigator-auth must act as the Authorization Server while **proxying
resource-owner authentication to the existing Google/Azure backends** and gating
token issuance on a manual activation list.

navigator-auth is already most of the way there. FEAT-093/FEAT-094 delivered a
real 3LO AS (`Oauth2Provider`, `navigator_auth/backends/oauth2/`): PKCE S256
(required for public clients, `plain` rejected), owner-bound authorization codes,
`/oauth2/token` with `authorization_code` / `refresh_token` / `client_credentials`
/ device-code grants, **rotated refresh tokens with reuse detection and chain
revocation**, consent + grant records, RFC 7662 introspection, RFC 7009
revocation, scope-gated `/oauth2/userinfo`, and `jti` revocation checked on every
resource-server request. This proposal is the **delta** that makes that AS
reachable and usable by Claude's connector infrastructure — not a new OAuth stack.

An OAuth AS also exists in ai-parrot (`parrot/mcp/oauth_server.py`:
`OAuthAuthorizationServer`, `ClientRegistry`, `OAuthRoutesMixin`) but it is a
**dev-only fixture**: `_handle_authorize` auto-approves with no user
authentication or consent, the mixin's token handler never verifies PKCE or code
expiry, storage is in-memory (clients/tokens vanish on restart), and there are no
refresh tokens. It stays as a **wire-contract reference** (its RFC 8414 metadata
and RFC 7591 request/response shapes are proven against Claude's client) and as a
local-dev harness; production authentication moves to navigator-auth. ai-parrot's
`ExternalOAuthValidator` (RFC 7662 client with audience check + TTL cache)
becomes the production consumption path, pointed at navigator-auth's
`/oauth2/introspect`.

**Why now:** ai-parrot FEAT "Agent Methods as MCP Tools" is explicitly blocked on
this (its S1 spike gate and decision D4: "OAuth 2.1 AS propio en navigator-auth;
Google como upstream IdP").

## What Changes

From the perspective of a Claude Web user / connector administrator:

1. **A Claude custom connector can register itself** against navigator-auth
   (RFC 7591 DCR) or use a pre-registered static client, discover the AS via
   `/.well-known/oauth-authorization-server` (RFC 8414), and complete the
   authorization_code + PKCE flow end-to-end within Claude's timing budgets
   (≤10 s discovery/registration/token, ≤30 s refresh).
2. **Users log in with Google or Microsoft, not a local password.** The AS
   `/oauth2/authorize` flow hands resource-owner authentication to the existing
   `GoogleAuth` / `AzureAuth` backends (upstream IdP proxy), then returns to the
   pending OAuth request to issue navigator-auth's own tokens. Upstream tokens
   land in the Identity Vault (`auth.user_identities`) as today.
3. **Access is gated, not open.** Even with `AUTH_MISSING_ACCOUNT="create"`
   auto-provisioning, a user must be **activated** (per-client allowlist) before
   `/oauth2/authorize` will issue a code; non-activated users get
   `access_denied` and never receive a token. Deactivation revokes within the
   access-token TTL (jti revocation already enforces this).
4. **Resource servers get a discovery story**: RFC 9728 protected-resource
   metadata support so an MCP resource server (ai-parrot) can point clients at
   this AS.

What is explicitly NOT changing: the FEAT-093/094 grant machinery, token
formats, storage tiers, introspection/revocation contracts, and the ABAC/scope
composition. No OIDC `id_token` issuance, no DPoP/mTLS, no token exchange.

## Capabilities

### New Capabilities

- `oauth2-dcr`: RFC 7591 `POST /oauth2/register`, **open registration by
  default** (decision 2026-08-30: anonymous DCR allowed; the `/authorize`
  activation gate is the real access control). Persists through the existing
  `ClientStorage` trio (memory/redis/postgres) into `auth.clients`;
  `client_uid` generation already exists (`PostgresClientStorage.save_client`,
  `secrets.token_urlsafe(18)`). Adds RFC 7591 metadata field mapping
  (`client_name`, `redirect_uris`, `grant_types`,
  `token_endpoint_auth_method`, `client_id_issued_at`,
  `client_secret_expires_at`) and an `OAUTH_DCR_POLICY` knob
  (`open` default / `allowlist` restricting registrable redirect URIs /
  `disabled` for static-client-only deployments), plus basic anti-abuse
  (rate limiting, cap on unused registered clients).
- `oauth2-as-metadata`: RFC 8414 `/.well-known/oauth-authorization-server`
  (issuer, endpoints, `code_challenge_methods_supported: ["S256"]`,
  grant types, `token_endpoint_auth_methods_supported`). Requires a proper
  **https issuer URL** setting — `AUTH_TOKEN_ISSUER` is currently the URN
  `urn:Navigator`, which RFC 8414 does not allow as issuer identifier.
- `oauth2-protected-resource-metadata`: RFC 9728
  `/.well-known/oauth-protected-resource` for resources navigator-auth itself
  protects, plus a small reusable helper/contract so external resource servers
  (ai-parrot MCP mounts) can serve their own PRM pointing at this AS.
- `oauth2-upstream-idp-proxy` (decision 2026-08-30: **delegate `auth_login`**):
  the AS login step (`Oauth2Provider.auth_login`, today local
  username/password only) gains a federated path: `oauth/login.html` offers
  the configured `ExternalAuth` backends (Google, Azure; extensible to
  Okta/ADFS), redirects into the chosen backend's interactive flow, carries
  the pending authorize request across the hop via `IdentityFlowStore`, and
  resumes consent/code issuance on callback. Upstream tokens stored via the
  Identity Vault (`IdentityStore` / `TokenResponse`). Local password login
  remains available unless disabled per deployment.
- `oauth2-client-access-gate` (decision 2026-08-30: **per-client table**): new
  `auth.client_access` table (user ↔ client_uid ↔ status, granted_by,
  timestamps) checked at `/oauth2/authorize` (and device verification) before
  consent; management API to activate/deactivate; deactivation triggers grant
  + refresh-chain + jti revocation for that (user, client) pair. Off by
  default globally, per-client opt-in — MCP access does not gate other clients.
- `oauth2-jwks-asymmetric` (decision 2026-08-30: **in scope now**): optional
  asymmetric token signing (RS256, ES256) alongside the existing HS256:
  key-pair configuration with `kid` headers, `/oauth2/jwks` published as
  RFC 8414 `jwks_uri`, key-rotation support (multiple active keys, old keys
  retained for verification until expiry). Lets third-party/polyglot resource
  servers validate tokens offline without calling `/oauth2/introspect`.
  HS256 remains the default for backward compatibility.
- `oauth21-conformance`: tightening pass against OAuth 2.1 + Claude's connector
  requirements: `/token` form-urlencoded enforcement (JSON body ⇒ 415),
  correct `WWW-Authenticate: Bearer resource_metadata=...` challenges on 401,
  and conformance tests replaying Claude's observed client behavior (DCR and
  static-client variants).

### Modified Capabilities

- `oauth2-3lo-core` (FEAT-093): `/oauth2/authorize` gains the activation-gate
  check and the federated-login branch; no change to code/token semantics.
- `bearer-token-auth`: 401 responses on protected resources add the RFC 9728
  `resource_metadata` challenge parameter.

## Impact

- **APIs**: new endpoints `/oauth2/register`, two `.well-known` documents, and
  the client-access management API (likely `/api/v1/oauth2/clients/{uid}/access`).
  New/changed config: `AUTH_ISSUER_URL` (https), `OAUTH_DCR_POLICY`
  (default `open`), `OAUTH_DCR_REDIRECT_ALLOWLIST`,
  `OAUTH_UPSTREAM_IDP_BACKENDS`, `OAUTH_ACCESS_GATE_ENABLED`,
  `OAUTH_JWT_SIGNING_ALG` (default `HS256`) + `OAUTH_JWT_KEYS` (key files /
  kid map) for the asymmetric option, `/oauth2/jwks` endpoint.
- **Code (main touch points)**: `navigator_auth/backends/oauth2/backend.py`
  (authorize/login branch, register endpoint, metadata handlers),
  `client_backend.py` (DCR field mapping), `models.py` (+`ClientAccess`),
  `ddl.sql` (+`auth.client_access`), `conf.py`, `backends/external.py` +
  `google.py` / `azure.py` (resumable AS-initiated flow),
  `auth.py` (`get_external_backend` lookup already exists), templates
  (`oauth/login.html` gains provider buttons).
- **Breaking changes**: none intended. All new surface is additive; the
  activation gate defaults **off** (`OAUTH_ACCESS_GATE_ENABLED=false`) so
  existing OAuth2 deployments are unaffected.
- **Dependencies**: none new — DCR/discovery/gate are stdlib + existing asyncdb/
  redis, consistent with FEAT-093/094's "no new runtime dependency" rule.
- **Other systems**: ai-parrot deletes/demotes its fixture AS, keeps
  `ExternalOAuthValidator` against `/oauth2/introspect`; its MCP mounts serve
  RFC 9728 PRM referencing this AS. Unblocks ai-parrot S1.
- **Correction propagated upstream**: ai-parrot's brainstorm D11 assumes PBAC
  `enforcing: false` is a shadow/dry-run mode. In navigator-auth, `enforcing`
  means "priority short-circuit policy", **not** audit-only — there is no
  shadow mode today. If shadow rollout is wanted, it is separate new work in
  `abac/pdp.py`/`guardian.py` on top of `abac/audit.py` (kept out of scope
  here unless decided otherwise).

## Reference Material

- Working wire-contract example (dev fixture, do not port logic):
  `ai-parrot/packages/ai-parrot-server/src/parrot/mcp/oauth_server.py` —
  RFC 8414 document shape (`_handle_discovery`), RFC 7591 request/response
  shape (`ClientRegistry.register`, `_handle_registration`), and
  `ExternalOAuthValidator` as the RS-side introspection client.
- Claude connector facts (verified 2026-08 in the ai-parrot brainstorm §4):
  OAuth 2.1 only; DCR + static clients; callback
  `https://claude.ai/api/mcp/auth_callback`; Streamable HTTP; ≤10 s
  discovery/registration/token, ≤30 s refresh; refresh rotation required for
  public clients; `/token` must accept form-urlencoded.
- In-repo foundations: `sdd/specs/oauth2-3lo-implementation.spec.md`,
  `sdd/specs/oauth2-introspection-device-grant.spec.md`,
  `documentation/oauth.md`, `documentation/identity-vault.md`.

## Decisions (2026-08-30)

| # | Question | Decision |
|---|---|---|
| D1 | DCR policy default | **Open DCR** — anonymous registration allowed; the `/authorize` activation gate is the access control. `OAUTH_DCR_POLICY` still offers `allowlist`/`disabled`. |
| D2 | Upstream IdP seam | **Delegate `auth_login`** to the `ExternalAuth` backend's interactive flow, pending authorize request carried in `IdentityFlowStore`; identity-link storage (`IdentityStore`/`TokenResponse`) reused for upstream tokens. Provider buttons on `oauth/login.html`. |
| D3 | Activation gate model | **Per-client table** `auth.client_access`; per-client opt-in, cascaded revocation on deactivate. |
| D4 | JWKS / asymmetric signing | **In scope now** — RS256/ES256 option + `/oauth2/jwks` + rotation; HS256 stays the default. |

## Open Questions

1. **RFC 8707 resource indicators** — the 2025-06 MCP authorization spec
   expects clients to send `resource=`; Claude sends it. Accept-and-echo
   (minimal) or full audience-restricted tokens?
2. **Where does PRM live for ai-parrot?** navigator-auth ships the helper and
   its own document; each MCP mount must serve its own
   `/.well-known/oauth-protected-resource`. Confirm ai-parrot owns that half.
3. **Activation UX** — who activates users (admin API only, or an approval
   queue where a login attempt by a non-activated user creates a pending
   request an admin can approve)?
