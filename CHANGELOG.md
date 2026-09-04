# Unreleased

- **Abstract SAML 2.0 Backend — SP and IdP roles on `pysaml2` (0.26.0).**
  **Breaking:** `python3-saml`/`xmlsec` are replaced by `pysaml2>=7.5,<8`;
  the `xmlsec1` system binary is now required (was: the `xmlsec`
  Python/libxml2 binding). `navigator_auth/backends/saml.py` is replaced by
  the `navigator_auth/backends/saml/` package: `SAMLCore` (shared engine:
  config building, executor-wrapped `pysaml2` calls, attribute mapping,
  host-validated redirects, replay cache), `AbstractSAMLBackend` (the SP
  role — SP-initiated and unsolicited login, ACS, Single Logout in both
  directions) and `AbstractSAMLIdentityProvider` (the IdP role — env-
  declared SP registry, IdP-initiated SSO, SP-initiated SSO with a parked-
  request/no-session login detour, SLO; never authenticates, hidden from
  `/api/v1/auth/methods`). Security parity with the OIDC backends: random
  single-use `RelayState`, `InResponseTo` validation, an assertion-ID
  replay cache TTL'd to `NotOnOrAfter`, `ALLOWED_HOSTS`-checked redirects
  (the ADFS redirect validator is promoted to
  `BaseAuthBackend.validate_redirect_host`, behavior-preserving),
  persisted `SessionIndex`/`NameID` for SLO, and an audit event per issued
  or rejected assertion. `SAMLAuth`'s import path, routes and
  `SAML_MAPPING` semantics are unchanged; a `SAML_SETTINGS` JSON blob is
  now translated by `translate_legacy_settings` (hard failure, naming
  every key, on anything outside the documented translation table — see
  the migration section in `documentation/saml.md`). See
  `documentation/saml.md` and `docs/settings.rst`.

- **Backend-Based Password Recovery (0.27.0).** A three-step, HMAC-signed
  self-service password recovery flow —
  `POST /api/v1/password-recovery` (request), `GET
  /api/v1/password-recovery/{token}` (validate, mint a confirmation token),
  `POST /api/v1/password-recovery/confirm` (set the new password) — replaces
  the non-functional draft in the old `handlers/recovery.py`. Splits proof
  of mailbox control from authorization to write a password across two
  linked, HMAC-signed, sha256-keyed Redis tokens; navigator-auth never sends
  e-mail itself (`AUTH_RECOVERY_CALLBACK` receives a `NotificationPayload`
  instead). No account enumeration by status, body or latency (padded to a
  ~250ms floor on every path, including rate-limited requests); a step-3
  policy violation (`422`) never consumes either token; a successful reset
  revokes the user's live session and every outstanding JWT `jti`
  (`create_token` now emits one). Legacy `/api/v1/forgot-password` and
  `/api/v1/reset-password` routes are aliased to the new handler;
  `FORGOT_PASSWORD_CALLBACK` is deprecated for one release. Also fixes a
  latent, project-wide `User.password` column-width bug (`max=16` vs a
  77-char PBKDF2 hash). See `docs/password_recovery.rst`.

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
