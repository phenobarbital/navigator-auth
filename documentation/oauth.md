# OAuth2 in Navigator-Auth

`navigator-auth` provides a production-grade OAuth2 Authorization Server supporting
Three-Legged (3LO) Authorization Code flow with PKCE, refresh token rotation,
per-app consent grants, RFC 7009 token revocation, ABAC scope composition,
RFC 7662 Token Introspection, and RFC 8628 Device Authorization Grant.

> **FEAT-093 / FEAT-094 Note** — This document covers the production model.  See
> `examples/oauth2_server.py` for a runnable end-to-end demonstration.

## 1. Client Model — `client_id` vs `client_pk`

In `navigator-auth` a **Client** is the registered application making requests on
behalf of the Resource Owner.

| Field | Type | Description |
|-------|------|-------------|
| `client_id` | `str` | **Public opaque uid** — used on the wire, in JWT claims, and in all API responses. Never an integer. |
| `client_pk` | `int` \| `None` | Internal surrogate PK from `auth.clients.client_id` bigserial.  Used only as FK target in token/grant tables; never exposed to clients. |
| `client_secret` | `str` \| `None` | HMAC-compared with `secrets.compare_digest`. `None` for public clients. |
| `redirect_uris` | `list[str]` | Exact-match whitelist (no trailing slash, no query string). |
| `allowed_grant_types` | `list[str]` | e.g. `["authorization_code", "refresh_token"]`. |
| `default_scopes` | `list[str]` | Scopes the client is allowed to request. |

**Why the distinction matters:** `FEAT-092` tenants use an integer `client_id` in
ABAC cache keys.  The OAuth `client_id` string (uid) is a *separate axis* — the same
cache-key logic keeps them distinct so tenant decisions never bleed into OAuth decisions.

## 2. How OAuth2 works at Navigator-Auth

`navigator-auth` acts as an Authorization Server. It validates the user's credentials
(via `navigator-session` or direct login) and issues Access Tokens and Refresh Tokens.

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth2/authorize` | GET | Start Authorization Code flow (login + consent). |
| `/oauth2/token` | POST | Exchange code → tokens; refresh; client_credentials; device_code poll. |
| `/oauth2/login` | GET/POST | Login page. |
| `/oauth2/consent` | GET/POST | User consent page (skip if prior grant exists). |
| `/oauth2/userinfo` | GET | Scope-gated user profile (RFC 7662-like). |
| `/oauth2/logout` | GET/POST | Session teardown + redirect. |
| `/oauth2/logout/complete` | GET | Post-logout landing page (200 OK). |
| `/oauth2/revoke` | POST | RFC 7009 token revocation (always 200). |
| `/oauth2/grants` | GET | List active per-app consent grants for the user. |
| `/oauth2/grants/{client_uid}` | DELETE | Revoke all tokens for one client app. |
| `/oauth2/introspect` | POST | **RFC 7662** token introspection (confidential clients only). |
| `/oauth2/device_authorization` | POST | **RFC 8628** device authorization request. |
| `/oauth2/device` | GET/POST | **RFC 8628** user-facing device code verification page. |

## 3. How to enable OAuth2 in Navigator-Auth

Settings in your configuration (e.g., `settings.py` or `.env` via `navconfig`):

```python
# Enable OAuth2
OAUTH2_CLIENT_STORAGE = 'redis'  # Options: 'postgres', 'redis', 'memory'

# Customize URIs (Optional - defaults shown)
AUTH_OAUTH2_REDIRECT_URL = '/'
```

In your application code:

```python
from navigator_auth import AuthHandler

auth = AuthHandler()
# ... register auth routes ...
```

The OAuth2 routes are automatically set up by the `Oauth2Provider` backend.

## 4. Backends

Navigator-Auth supports different storage backends for persisting OAuth2 Clients, Authorization Codes, and Refresh Tokens.

-   **Memory**: Best for testing/development. Data is lost on restart.
    -   Config: `OAUTH2_CLIENT_STORAGE = 'memory'`
-   **Redis**: High performance, good for production.
    -   Config: `OAUTH2_CLIENT_STORAGE = 'redis'`
    -   Requires `REDIS_URL` to be configured.
-   **Postgres**: Persistent relational storage.
    -   Config: `OAUTH2_CLIENT_STORAGE = 'postgres'`
    -   Requires `DBHOST`, `DBUSER`, `DBPWD`, etc.

## 5. Authorization Flows

### Authorization Code Flow with PKCE (3LO)

Recommended for all user-facing applications (web, SPA, mobile).
PKCE (S256 method only — `plain` is rejected) is **required** for public clients.

```
GET /oauth2/authorize
  ?response_type=code
  &client_id=<your_client_uid>
  &redirect_uri=https://app.example.com/callback
  &scope=default%20profile%20email%20offline_access
  &state=<random_csrf_token>
  &code_challenge=<S256_hash_of_verifier>
  &code_challenge_method=S256
```

After user login + consent, the server redirects to:
```
https://app.example.com/callback?code=<one_time_code>&state=<csrf_token>
```

Exchange the code for tokens:
```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<one_time_code>
&client_id=<your_client_uid>
&redirect_uri=https://app.example.com/callback
&code_verifier=<original_pkce_verifier>
```

Response:
```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<opaque_string>",
  "scope": "default profile email offline_access"
}
```

> **B-fix guarantee**: The `access_token` JWT binds `user_id` from the authenticated
> session — **never** from `OAuthClient.user`.  This prevents privilege escalation.

### Client Credentials Flow (2LO)

For machine-to-machine communication (daemons, batch jobs).  Token has `aud=app`.

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=<your_client_uid>
&client_secret=<secret>
&scope=default
```

### Refresh Token Flow

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=<opaque_token>
&client_id=<your_client_uid>
&client_secret=<secret_if_confidential>
```

Returns a new `access_token` **and** a new `refresh_token` (rotation).
The old refresh token is immediately revoked.  `offline_access` scope is required.

## 6. Refresh Token Rotation & Security

| Config | Default | Description |
|--------|---------|-------------|
| `OAUTH_ACCESS_TOKEN_TTL` | 3600 s (1 h) | Access token lifetime. |
| `OAUTH_REFRESH_TOKEN_TTL` | 2 592 000 s (30 d) | Sliding refresh token TTL. |
| `OAUTH_REFRESH_ABSOLUTE_TTL` | 7 776 000 s (90 d) | Hard-stop; never extended. |
| `OAUTH_REFRESH_ROTATION` | `True` | Issue a new token on every use. |
| `OAUTH_CODE_TTL` | 600 s (10 min) | Authorization code TTL. |
| `OAUTH_REQUIRE_PKCE_PUBLIC` | `True` | PKCE required for public clients. |
| `OAUTH_REVOCATION_CACHE_TTL` | 30 s | Per-request jti revocation cache. |

**Reuse detection:** If a revoked (already-rotated) refresh token is presented,
the server detects replay, revokes the *entire token chain* for that user+client
pair, and returns `invalid_grant`.

## 7. Token Revocation (RFC 7009)

```http
POST /oauth2/revoke
Content-Type: application/x-www-form-urlencoded

token=<access_or_refresh_token>
&token_type_hint=refresh_token   # optional
&client_id=<your_client_uid>
```

Always returns HTTP 200 (per RFC 7009), regardless of whether the token existed.

## 8. offline_access Scope

The `offline_access` scope controls whether the authorization server issues a
refresh token.  If the scope is not present in the original request, no refresh
token is returned.

## 9. Userinfo Endpoint

```http
GET /oauth2/userinfo
Authorization: Bearer <access_token>
```

Returns scope-gated claims:

| Scope | Claims returned |
|-------|----------------|
| (always) | `sub` (string of `user_id`) |
| `profile` | `username`, `given_name`, `family_name` |
| `email` | `email` |

Returns `401 Unauthorized` for invalid/expired/revoked tokens.

## 10. Consent Grants API

List a user's active per-app grants:
```http
GET /oauth2/grants
Authorization: Bearer <access_token>
```

Revoke all tokens for a specific client (per-app logout):
```http
DELETE /oauth2/grants/<client_uid>
Authorization: Bearer <access_token>
```

## 11. Scope ↔ ABAC Composition

Effective permission = `granted_scopes ∩ user_ABAC`.

-   **Scope ceiling:** even if an ABAC policy allows an action, the request is denied
    if the token does not carry the required scope.
-   **ABAC gate:** even with the right scope, the user must satisfy the ABAC policy
    (groups, subject, context, environment conditions).

Use `@scope_required(*scopes)` decorator on handlers:

```python
from navigator_auth.abac.decorators import scope_required

@scope_required("default", "read")
async def my_handler(request):
    ...  # only reached when token carries BOTH 'default' and 'read'
```

Or check imperatively via `Guardian.has_scope(request, scopes)`:

```python
await guardian.has_scope(request, ["admin"])
# raises AccessDenied(reason='insufficient_scope') if token lacks 'admin'
```

Declare scope requirements directly on ABAC policies:

```python
from navigator_auth.abac.policies.policy import Policy

p = Policy(
    name="write-access",
    groups=["engineering"],
    scopes=["write"],   # token must carry 'write' scope AND user in 'engineering'
)
```

## 12. Valid Scope Registry

Valid scopes are defined by `OAUTH_SCOPES` (env var, comma-separated).  Unknown
scopes are rejected at the `/oauth2/authorize` step.

Default registry: `default, profile, email, offline_access, read, write, admin`

Action → scope mapping is defined by `OAUTH_SCOPE_ACTIONS` (env var):

```
OAUTH_SCOPE_ACTIONS="tool:execute:default+read,kb:query:default"
```

## 13. FAQ

**Q: What is the duration of an Access Token?**
A: Default 3600 seconds (1 hour), controlled by `OAUTH_ACCESS_TOKEN_TTL`.

**Q: What is the duration of a Refresh Token?**
A: Sliding window of 30 days (`OAUTH_REFRESH_TOKEN_TTL`), with an absolute
hard-stop at 90 days (`OAUTH_REFRESH_ABSOLUTE_TTL`).

**Q: Where is user data stored?**
A: In the JWT claims (access token) and Redis (refresh tokens, codes, grants).
The `userinfo` endpoint returns scope-gated claims on demand.

**Q: What happens if the same refresh token is used twice?**
A: The server detects the replay, revokes the entire token chain, and returns
`invalid_grant`. This follows the OAuth 2.0 Security BCP recommendation.

**Q: Does the server support `plain` PKCE?**
A: No. Only `S256` is accepted. `plain` is rejected with `invalid_request`.

---

## 14. Token Introspection (RFC 7662)

Allows a **confidential client** (resource server) to verify whether a token is
currently active and retrieve its claims.

> **Security note:** Only the client that was issued the token may introspect it
> (same-client-only rule).  Public clients cannot call this endpoint.

```http
POST /oauth2/introspect
Content-Type: application/x-www-form-urlencoded
Authorization: (none — credentials in body)

client_id=<your_confidential_client_uid>
&client_secret=<secret>
&token=<access_or_refresh_token>
&token_type_hint=access_token   # optional: access_token | refresh_token
```

**Active token response:**
```json
{
  "active": true,
  "client_id": "your_client_uid",
  "scope": "default read",
  "exp": 1700000000,
  "iat": 1699996400,
  "token_type": "Bearer"
}
```

**Inactive token response** (expired, revoked, unknown, or issued to a different client):
```json
{"active": false}
```

Error codes:

| HTTP | `error` | Cause |
|------|---------|-------|
| 400 | `invalid_request` | Missing `token` parameter |
| 401 | `invalid_client` | Bad / missing `client_secret`, or public client |

> **Real-time revocation:** `jti` revocation is checked on every call — no caching.

### Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `OAUTH_INTROSPECT_INCLUDE_ABAC_SCOPES` | `false` | Include ABAC-derived scopes in response |

---

## 15. Device Authorization Grant (RFC 8628)

For devices with no browser or limited input (smart TVs, CLIs, IoT devices).
The user authenticates on a secondary device (phone/laptop) using a short code.

### Flow overview

```
Device                             Authorization Server           User Agent
  |                                        |                          |
  |-- POST /oauth2/device_authorization -->|                          |
  |<- device_code, user_code, uri ---------|                          |
  |                                        |                          |
  |                                        |<-- GET /oauth2/device ---|
  |                                        |<-- POST /oauth2/device --|
  |                                        |   (user enters user_code)|
  |                                        |   (grants consent)       |
  |                                        |                          |
  |-- POST /oauth2/token (poll) ---------->|                          |
  |<- access_token, refresh_token ---------|                          |
```

### Step 1: Request a device code

```http
POST /oauth2/device_authorization
Content-Type: application/x-www-form-urlencoded

client_id=<device_client_uid>
&scope=default%20offline_access
&code_challenge=<S256_hash_of_verifier>      # required for public clients (D4)
&code_challenge_method=S256
```

**Response:**
```json
{
  "device_code": "<opaque_device_code>",
  "user_code": "BCDF-MNPQ",
  "verification_uri": "https://auth.example.com/oauth2/device",
  "verification_uri_complete": "https://auth.example.com/oauth2/device?user_code=BCDFMNPQ",
  "expires_in": 600,
  "interval": 5
}
```

Display `verification_uri` and `user_code` to the user.

### Step 2: User verifies on a secondary device

The user navigates to `verification_uri`, enters the `user_code` (or scans a QR
code from `verification_uri_complete`), authenticates, and approves consent.

**Anti-brute-force (D3):** After `OAUTH_DEVICE_MAX_USER_CODE_ATTEMPTS` (default 5)
failed entries from the same IP, the endpoint returns `access_denied` for
`OAUTH_DEVICE_LOCKOUT_TTL` (default 300 s) regardless of future input.

### Step 3: Poll for tokens

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code
&device_code=<device_code_from_step1>
&client_id=<device_client_uid>
&code_verifier=<original_pkce_verifier>   # required for public clients
```

**Success (HTTP 200):**
```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<opaque_string>",   # only if offline_access was granted
  "scope": "default offline_access"
}
```

**Polling errors (HTTP 400):**

| `error` | Meaning | Action |
|---------|---------|--------|
| `authorization_pending` | User hasn't approved yet | Wait `interval` seconds and retry |
| `slow_down` | Polling too fast | Wait `interval + OAUTH_DEVICE_SLOW_DOWN_INCREMENT` s and retry |
| `access_denied` | User denied the request | Stop polling; inform user |
| `expired_token` | Device code expired or already used | Start over |

### Owner-binding invariant

The `user_id` in the issued access token is **always** the authenticated user from
the verification session — never `OAuthClient.user`.  This is the same
owner-binding guarantee as the 3LO Authorization Code flow (FEAT-093 B-fix).

### PKCE requirement (D4)

Public clients **must** include `code_challenge` (S256 method) at
`device_authorization` time and `code_verifier` at polling time.  Confidential
clients may omit PKCE.  `plain` method is rejected with `invalid_request`.

### Device grant configuration

| Key | Default | Description |
|-----|---------|-------------|
| `OAUTH_DEVICE_CODE_TTL` | `600` s | Device code lifetime. |
| `OAUTH_DEVICE_POLL_INTERVAL` | `5` s | Initial polling interval. |
| `OAUTH_DEVICE_SLOW_DOWN_INCREMENT` | `5` s | Interval bump on too-fast polls. |
| `OAUTH_DEVICE_USER_CODE_LENGTH` | `8` | Length of the human-readable user code. |
| `OAUTH_DEVICE_USER_CODE_ALPHABET` | `BCDFGHJKLMNPQRSTVWXZ` | Unambiguous alphabet (no vowels, no 0/O/1/I/L). |
| `OAUTH_DEVICE_VERIFICATION_URI` | `""` | Base verification URI shown to the user. |
| `OAUTH_DEVICE_MAX_USER_CODE_ATTEMPTS` | `5` | Failed entries before IP lockout. |
| `OAUTH_DEVICE_LOCKOUT_TTL` | `300` s | IP lockout duration. |

---

# FEAT-095 — OAuth 2.1 for MCP Agents

This section covers the surface added so Claude Web/Desktop custom connectors (and
any other OAuth 2.1 client) can **discover** and **self-register** against this
authorization server. See `documentation/mcp-connector.md` for the
operator-facing setup guide and runbooks.

## Issuer identity

RFC 8414 requires an `https` issuer identifier that matches the location the
metadata is served from. `AUTH_TOKEN_ISSUER` defaults to the URN `urn:Navigator`
and cannot serve that role, so FEAT-095 adds a separate setting.

| Key | Default | Description |
|-----|---------|-------------|
| `AUTH_ISSUER_URL` | *(derived)* | Canonical https issuer for discovery and the OAuth2 surfaces. |

When unset the issuer is derived per request from `X-Forwarded-Proto` /
`X-Forwarded-Host` / `Host`, so it is correct behind a reverse proxy. `https` is
enforced (loopback hosts are exempt for local development). **Set it explicitly
in production** — a wrong issuer makes Claude show "Disconnected" with no useful
error.

`AUTH_TOKEN_ISSUER` keeps its existing meaning for the non-OAuth2 JWT `iss`
claim; nothing about it changed.

## Discovery documents

| Endpoint | RFC | Auth |
|----------|-----|------|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | public |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 | public |

Both are also aliased under `/oauth2/.well-known/...` for deployments mounted
behind a path prefix. Documents are built once per issuer and cached in-process.

`registration_endpoint` appears only when `OAUTH_DCR_POLICY != "disabled"`, and
`jwks_uri` only when a signing-key registry is loaded — the server never
advertises an endpoint it will not serve.

The RFC 9728 builder is importable standalone, so an external resource server
can serve its own document pointing back here:

```python
from navigator_auth.backends.oauth2.metadata import (
    build_protected_resource_metadata,
)

doc = build_protected_resource_metadata(
    resource="https://mcp.example.com",
    auth_servers=["https://auth.example.com"],
    scopes=["default"],
)
```

## Dynamic Client Registration (RFC 7591)

`POST /oauth2/register` — JSON body, unauthenticated, rate-limited.

Registration is **open by default**: anyone may mint a `client_id`. That is
deliberate — registration confers no privileges, and the per-client access gate
below is the actual access control.

| Key | Default | Description |
|-----|---------|-------------|
| `OAUTH_DCR_POLICY` | `open` | `open` / `allowlist` / `disabled`. |
| `OAUTH_DCR_REDIRECT_ALLOWLIST` | Claude callbacks | Glob patterns for `allowlist` mode. |
| `OAUTH_DCR_DEFAULT_SCOPES` | `[]` | Scopes given to clients that request none. |
| `OAUTH_DCR_GATE_NEW_CLIENTS` | `True` | DCR clients are born gated. |
| `OAUTH_DCR_RATE_LIMIT` | `10/hour` | Per-source-IP registration limit. |
| `OAUTH_DCR_UNUSED_TTL` | `2592000` | Reap DCR clients that never exchanged a token (s). |

Request (exactly what Claude sends):

```json
{
  "client_name": "Claude",
  "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"]
}
```

Response — `201 Created`:

```json
{
  "client_id": "rX_GeI5PkYtJwY1PHsFkQbjK",
  "client_id_issued_at": 1788131599,
  "client_secret_expires_at": 0,
  "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
  "client_name": "Claude",
  "token_endpoint_auth_method": "none"
}
```

`token_endpoint_auth_method: "none"` designates a **public** client: no
`client_secret` is issued, and PKCE becomes mandatory through the existing
`OAUTH_REQUIRE_PKCE_PUBLIC` enforcement. Confidential clients get a
`client_secret` that does not expire (`client_secret_expires_at: 0`).

Validation rejects missing `redirect_uris`, non-https URIs (loopback exempt),
fragments, wildcards, and unsupported grant/response types with
`{"error": "invalid_client_metadata", ...}`. `OAUTH_DCR_POLICY=disabled`
returns `{"error": "registration_not_supported"}`. Exceeding the rate limit
returns `429` with `Retry-After`.

New `auth.clients` columns: `token_endpoint_auth_method`, `registration_source`
(`static` | `dcr`), `enforce_access_gate`. Run `backends/oauth2/ddl.sql`.

## Upstream IdP proxy login

With `OAUTH_UPSTREAM_IDP_BACKENDS` set, the AS login page offers the configured
`ExternalAuth` backends instead of only local username/password.

| Key | Default | Description |
|-----|---------|-------------|
| `OAUTH_UPSTREAM_IDP_BACKENDS` | `[]` | e.g. `google,azure`. Empty ⇒ local login only. |
| `OAUTH_UPSTREAM_FLOW_TTL` | `600` | Lifetime of the parked authorize request (s). |

On provider selection the **complete** pending authorize request (including
`state` and the PKCE `code_challenge`) is parked server-side in
`IdentityFlowStore` under `oauth2_pending_{flow_id}`. Only an opaque handle
travels in the browser, in a short-lived HttpOnly cookie. After the provider
callback the user is returned to `/oauth2/authorize?flow=...`, the parked
request is restored **single-use**, and the flow continues into the gate and
consent. Upstream provider tokens are ciphered into `auth.user_identities`.

An expired or missing flow produces a clean `invalid_request`, never a
half-formed redirect.

## Per-client access gate

Decides whether a given user may obtain a token for a given client. Checked at
`/oauth2/authorize` **and** at device verification, after login and **before**
consent — a non-activated user never reaches the consent screen and never
receives a code.

| Key | Default | Description |
|-----|---------|-------------|
| `OAUTH_ACCESS_GATE_ENABLED` | `False` | Enforce the gate for **all** clients. |
| `OAUTH_ACCESS_GATE_QUEUE` | `True` | Record `pending` rows on denied attempts. |

The gate is enforced when the global switch is on **or** the client's
`enforce_access_gate` flag is set. With both off, behaviour is exactly as before
this feature.

Denial returns the standard `access_denied` error redirect carrying the original
`state`. When the queue is on, the attempt upserts a single `pending` row per
(user, client) so an administrator can approve it.

Management API (superuser only):

```
GET    /api/v1/oauth2/clients/{client_uid}/access
GET    /api/v1/oauth2/clients/{client_uid}/access?status=pending
POST   /api/v1/oauth2/clients/{client_uid}/access   {"user_id": 42, "action": "grant"}
POST   ...                                          {"user_id": 42, "action": "approve"}
POST   ...                                          {"user_id": 42, "action": "reject"}
DELETE /api/v1/oauth2/clients/{client_uid}/access?user_id=42
```

Revoking cascades: the consent grant, the refresh-token chain and live access
token `jti`s for that (user, client) are all revoked. Effect is immediate for
refresh and introspection, and within one access-token TTL for tokens already
minted.

New table `auth.client_access` — see `backends/oauth2/ddl.sql`.

## Asymmetric signing and JWKS

Optional RS256/ES256 signing so third-party resource servers can validate
tokens offline, without an introspection round-trip. **HS256 remains the
default and its output is unchanged when this is unconfigured.**

| Key | Default | Description |
|-----|---------|-------------|
| `OAUTH_JWT_SIGNING_ALG` | `HS256` | `HS256` / `RS256` / `ES256`. |
| `OAUTH_JWT_KEYS` | `[]` | JSON key registry (see below). |

```json
[
  {"kid": "2026-q3", "algorithm": "RS256",
   "private_key_file": "/etc/navigator/keys/2026-q3.key",
   "public_key_file":  "/etc/navigator/keys/2026-q3.pub",
   "active": true},
  {"kid": "2026-q2", "algorithm": "RS256",
   "public_key_file":  "/etc/navigator/keys/2026-q2.pub",
   "active": false}
]
```

Exactly one key is `active` (the signer); inactive keys stay published for
verification, which is what makes rotation non-disruptive. Tokens carry the
`kid` header and `decode_token` dispatches on it, falling back to the
`SECRET_KEY` HS256 path for tokens without a known `kid` — so an HS256→RS256
migration verifies both during the overlap.

`GET /oauth2/jwks` serves the public JWK Set (public parameters only, `use:
"sig"`). Inline PEM via `private_key` / `public_key` is also accepted.

See `documentation/mcp-connector.md` for the key generation and rotation
runbook.

## OAuth 2.1 conformance

- `POST /oauth2/token` requires `application/x-www-form-urlencoded`; a JSON body
  returns **415**.
- `client_secret_basic` is accepted alongside `client_secret_post` at
  `/oauth2/token`, `/oauth2/introspect` and `/oauth2/revoke`.
- The RFC 8707 `resource` parameter is accepted at authorize and token,
  validated as an absolute URI without a fragment (`invalid_target` otherwise),
  carried through the authorization code, and reflected into the token `aud`
  alongside the `'user'` / `'app'` marker (making `aud` list-valued). Audience
  **enforcement** is the resource server's job.
- Bearer `401`s carry
  `WWW-Authenticate: Bearer resource_metadata="{issuer}/.well-known/oauth-protected-resource"`.
