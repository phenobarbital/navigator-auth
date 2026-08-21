# Unreleased

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
