# Identity Vault — Linked External Credentials

The Identity Vault lets an **already-authenticated** user run a secondary
OAuth2 authorization flow against an external provider (Azure, Google,
GitHub, Okta, Odoo) purely to **capture a credential** — bearer token +
refresh token — which is stored **ciphered** in `auth.user_identities`.
Other systems can then use those identities (through the HTTP API or the
IdP) to authenticate to external services (Microsoft Graph / Office 365,
Google APIs, GitHub, Odoo, ...) on the user's behalf.

This is distinct from *login*: the login flow creates a Navigator session;
the identity-link flow saves the provider tokens for later use.

## How it works

1. A logged-in user calls `GET /api/v1/user/identities/link/{provider}`.
2. navigator-auth stores a single-use flow record in Redis
   (`idlink:{state}`, TTL `IDENTITY_LINK_TTL`) binding the random OAuth2
   `state` to the session user, and redirects to the provider's authorize
   endpoint with the provider's *identity scopes* (including offline /
   refresh-token access).
3. The provider redirects back to the **same** callback URL used for
   login (`/auth/{provider}/callback/`). The callback dispatcher
   recognizes the link state (single-use `GETDEL`), exchanges the code,
   fetches the provider userinfo, and upserts the credential — ciphered —
   into `auth.user_identities`.
4. The decrypted credential is cached in the user's **Session Vault**
   (key `identity:{provider}`) so repeated reads avoid the database.

Because the login callback URL is reused, no additional redirect URI has
to be registered at the provider.

## Storage & encryption

Credential columns are added to `auth.user_identities` by an idempotent
startup migration (`navigator_auth/identity/sql/001_identity_credentials.sql`):
`provider_user_id`, `scopes` (jsonb), `access_token` / `refresh_token`
(BYTEA, ciphered), `token_type`, `expires_at`, `refreshed_at`, `enabled`,
`key_version`, plus a partial unique index on
`(user_id, auth_provider, provider_user_id)`.

Encryption reuses the **Session Vault master keys** from
`navigator-session`:

```bash
# base64-encoded 32-byte keys, versioned; same keys as the Session Vault
VAULT_MASTER_KEY_v1=<base64 32 bytes>
VAULT_ACTIVE_KEY_ID=1
```

The 2-byte key id is embedded in each ciphertext, so key rotation follows
the vault's rotation procedure. Without these keys the Identity Vault
endpoints return `501` and everything else (including login) keeps
working.

## HTTP API

All endpoints operate on the authenticated session user's own
identities only.

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/user/identities` | List linked identities (tokens never included) |
| GET | `/api/v1/user/identities/{identity_id}` | One identity (masked) |
| PUT | `/api/v1/user/identities/{identity_id}` | Renew using the stored refresh token |
| DELETE | `/api/v1/user/identities/{identity_id}` | Delete + invalidate the vault cache |
| GET | `/api/v1/user/identities/link/{provider}?redirect_uri=/back` | Start the link flow (302) |
| GET | `/api/v1/user/identities/{provider}/credential` | Decrypted credential; auto-refreshes when expiring |
| GET | `/api/v1/user/identities/manage` | HTML page to manage the vault |

`PUT` returns `409` when the provider issued no refresh token (e.g. GitHub
classic OAuth apps) — re-link instead. The credential endpoint refreshes
automatically when the token expires within `IDENTITY_REFRESH_LEEWAY`
seconds.

In-process consumers (services embedding the IdP) can call:

```python
credential = await idp.get_user_identity_credential(user_id, "google")
# {'access_token': ..., 'token_type': 'Bearer', 'refresh_token': ...,
#  'expires_at': ..., 'scopes': [...], 'provider_user_id': ...}
```

## Provider notes

| Provider | Refresh token | Notes |
|---|---|---|
| Azure | via MSAL token cache | `AZURE_IDENTITY_SCOPES` (default `User.Read`); MSAL adds `offline_access` itself |
| Google | requires `prompt=consent` + `access_type=offline` | Google may omit the refresh token on re-consent; re-link if so |
| GitHub | only GitHub Apps (expiring user tokens) | classic OAuth apps: token doesn't expire, no refresh token |
| Okta | `offline_access` scope | client authenticated with Basic header |
| Odoo | depends on the provider addon | OCA `oauth_provider` conventions; endpoints configurable |

## Configuration

```ini
# flow + cache behavior
IDENTITY_LINK_TTL=600            # seconds a pending link flow stays valid
IDENTITY_CACHE_TTL=3600          # session-vault cache TTL
IDENTITY_REFRESH_LEEWAY=120      # refresh when expiring within N seconds

# per-provider identity scopes (comma-separated)
AZURE_IDENTITY_SCOPES=User.Read
GOOGLE_IDENTITY_SCOPES=openid,email,profile
GITHUB_IDENTITY_SCOPES=read:user,user:email
OKTA_IDENTITY_SCOPES=openid,email,profile,offline_access
ODOO_IDENTITY_SCOPES=profile,email

# Odoo backend (OCA oauth_provider)
ODOO_DOMAIN=https://erp.example.com
ODOO_CLIENT_ID=...
ODOO_CLIENT_SECRET=...
ODOO_AUTHORIZE_PATH=/oauth2/auth
ODOO_TOKEN_PATH=/oauth2/token
ODOO_USERINFO_PATH=/oauth2/userinfo
ODOO_SCOPES=profile,email

# login-flow additions
GITHUB_SCOPES=user:email
OKTA_AUDIENCE=api://default
```

Enable the Odoo backend by adding
`navigator_auth.backends.odoo.OdooAuth` to `AUTHENTICATION_BACKENDS`.

## Manual smoke test

1. Enable a provider backend and log in.
2. Visit `/api/v1/user/identities/manage`, press **Link** on a provider,
   complete the provider's consent screen.
3. Inspect `auth.user_identities`: the row holds BYTEA ciphertext, never
   plaintext tokens.
4. `GET /api/v1/user/identities/{provider}/credential` returns the
   decrypted bearer/refresh tokens (session-vault cached on repeat).
5. `PUT /api/v1/user/identities/{identity_id}` renews via the refresh
   token; `DELETE` removes the identity and its cache entry.

## Login-flow fixes shipped with this feature

- **GitHub**: `client_secret` no longer leaks into the authorize URL;
  CSRF `state` added and verified; token exchange sends
  `Accept: application/json` (previously the form-encoded reply broke
  parsing); private-email accounts resolved via `/user/emails`.
- **Okta**: random per-request `state`/`nonce` (were hardcoded
  constants, never verified); `offline_access` available for identity
  flows; Basic client authentication on the token endpoint.
- **Google**: per-request flow state in Redis (concurrent logins no
  longer clobber each other on the singleton backend); ID-token
  signature verification enabled (`verify=True`); OIDC `sub` mapped into
  the internal user id; `auth_method`/`auth_token` now stamped.
- All external backends share one Redis pool and a pure
  `get_redirect_uri()` (no more per-request mutation of backend
  singletons).
