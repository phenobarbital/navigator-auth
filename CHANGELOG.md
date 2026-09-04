# Unreleased

- **External Token Exchange — `TokenExchangeAuth` (0.25.0).** A client that
  already holds a valid Azure, Google or GitHub bearer token can exchange it
  for a Navigator session via `X-Auth-Method: TokenExchangeAuth` on
  `POST /api/v1/login`, without replaying the browser redirect flow.
  Audience-bound verification per provider (Azure id_token/access-token
  appid check, Google JWKS/tokeninfo azp, GitHub's "check a token"
  endpoint against this app's own client credentials); resolves an
  **existing** `auth.users` row only (linked identity first, then verified
  e-mail — never auto-provisions, regardless of `AUTH_MISSING_ACCOUNT`);
  opens the session through the same code path as Basic
  (`BasicAuth.open_session`, session/JWT carry `auth_method: "basic"` and
  `auth_origin: "<provider>"`); caps the session/JWT lifetime at the
  external token's own expiry (`TOKEN_EXCHANGE_MAX_TTL` fallback when the
  provider reports none); vaults the credential (including `id_token`,
  new ciphered column) in the Identity Vault rather than the session,
  retrievable through the existing credential endpoint. Also closes a
  pre-existing gap in `AzureAuth.check_credentials` (any Graph token from
  any application used to be accepted) and replaces the `GoogleAuth`/
  `GithubAuth` `check_credentials` stubs. See `docs/token_exchange.rst`.

- **Identity Vault — linked external credentials.** An authenticated user can
  run a secondary OAuth2 flow against Azure, Google, GitHub, Okta or the new
  Odoo backend purely to capture a credential (bearer + refresh token), stored
  ciphered in `auth.user_identities` with the Session Vault master keys. New
  endpoints under `/api/v1/user/identities` (list/retrieve/renew/delete, link
  flow, decrypted-credential serving with auto-refresh, HTML management page);
  `IdentityProvider.get_user_identity_credential()` for in-process consumers;
  Session Vault caching avoids repeated database reads. Ships login-flow fixes
  for GitHub (broken token exchange, secret leaked in authorize URL, missing
  CSRF state, private-email accounts), Okta (hardcoded state/nonce, never
  verified) and Google (singleton state race, disabled ID-token verification),
  plus a new Odoo OAuth2 backend targeting OCA `oauth_provider` conventions.
  See `documentation/identity-vault.md`.

- **Audit log — tenant scoping & query API.** `AuditLog.log()` now accepts an
  optional keyword-only `tenant`, threaded to every backend (SQL column,
  document field, influx tag, logger message). New `AuditLog.query(*, tenant, ...)`
  reads entries back, always constrained to one tenant (SQL backends; other
  families degrade to `[]` with a warning). Added the pure `build_select()`
  helper and a `tenant` column/index on the audit table. Backwards-compatible —
  existing PDP callers are unaffected. See `documentation/audit-log.md`.

# v0.0.6

- NoAuth, Basic Authentication
- DjangoAuth (getting user info using Django SessionID)
# v0.0.1

- First Version
- Work with Basic Authentication
