# OAuth2 in Navigator-Auth

`navigator-auth` provides a production-grade OAuth2 Authorization Server supporting
Three-Legged (3LO) Authorization Code flow with PKCE, refresh token rotation,
per-app consent grants, RFC 7009 token revocation, and ABAC scope composition.

> **FEAT-093 Note** — This document covers the production model.  See the
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
| `/oauth2/token` | POST | Exchange code → tokens; refresh; client_credentials. |
| `/oauth2/login` | GET/POST | Login page. |
| `/oauth2/consent` | GET/POST | User consent page (skip if prior grant exists). |
| `/oauth2/userinfo` | GET | Scope-gated user profile (RFC 7662-like). |
| `/oauth2/logout` | GET/POST | Session teardown + redirect. |
| `/oauth2/logout/complete` | GET | Post-logout landing page (200 OK). |
| `/oauth2/revoke` | POST | RFC 7009 token revocation (always 200). |
| `/oauth2/grants` | GET | List active per-app consent grants for the user. |
| `/oauth2/grants/{client_uid}` | DELETE | Revoke all tokens for one client app. |

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
