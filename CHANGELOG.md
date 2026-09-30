# Unreleased

- **Session cookie `Secure` flag fix and CSRF protection (0.28.2).**
  Requires `navigator-session>=1.1.0`.
  - The Redis session cookie was silently missing the `Secure` attribute
    (it showed up as `Secure=False` in the browser regardless of HTTPS) and
    was named `csrf_secure` — a leftover naming bug in `navigator-session`,
    unrelated to CSRF. `AuthHandler.__init__`'s `secure_cookies` flag now
    also drives the cookie's `Secure` attribute; the cookie name comes from
    `navigator-session`'s `SESSION_NAME` setting instead. Deployments
    running without HTTPS should set `secure_cookies=False` explicitly (the
    cookie is silently dropped by browsers otherwise); anything depending
    on the `csrf_secure` cookie name must update to the new name.
  - New CSRF protection: `navigator_auth.middlewares.csrf_middleware`
    (signed double-submit cookie, see `navigator_auth/libs/csrf.py`). Only
    unsafe-method requests (`POST`/`PUT`/`PATCH`/`DELETE`) authenticated
    purely by the session cookie (no `Authorization` header) require a
    matching `X-CSRF-Token` header; bearer/API-key requests are exempt, as
    they can't be forged cross-site. Controlled by `ENABLE_CSRF_PROTECTION`
    (default `True`), `CSRF_COOKIE_NAME` (default `csrf_token`) and
    `CSRF_HEADER_NAME` (default `X-CSRF-Token`).
- **Azure access-token verifier — `AZURE_TRUSTED_APPIDS` (0.28.1).**
  `AzureAuth._verify_access_token` (the access-token-only path of the
  external token exchange / `check_credentials`) now accepts a token whose
  `appid`/`azp` is either our own `AZURE_ADFS_CLIENT_ID` **or** one of the
  application ids listed in the new comma-separated `AZURE_TRUSTED_APPIDS`
  environment variable (e.g. a Teams bridge app calling the backend on
  behalf of users). Empty by default, so existing deployments keep the
  strict "our client id only" behaviour. Audience, expiry and issuer
  checks are unchanged.
- **BREAKING — Vault crypto hardening (FEAT-099, 0.28.0).** Requires
  `navigator-session>=1.0.0` and an offline data migration
  (`navigator-vault migrate`, see navigator-session `docs/vault/migration-runbook.md`).
  All sessions are invalidated by the deploy.
  - Identity credentials are sealed bound to
    `(user_id, auth_provider, provider_user_id, column)`: a token copied to
    another user, provider account or column no longer decrypts. `IdentityCipher`
    takes keyword-only context arguments and `IdentityStore.decrypt_credential`
    raises `IdentityCredentialError`, which the identity endpoints map to
    `409` ("re-link the identity").
  - `GET /api/v1/user/vault[/{key}]` returns **metadata only** (`key`,
    `updated_at`, `key_version`) — secret values never reach the browser.
    `POST` answers with that metadata plus its message; an unreadable secret
    returns `409 vault_integrity_error` and an unavailable vault `503
    vault_unavailable`.
  - Migration `002_vault_crypto_hardening.sql` widens `user_vault_audit.session_id`
    to 64 chars (it now stores an HMAC), allows the `quarantine` and
    `integrity_fail` audit operations, and turns key-version columns into
    `INTEGER`; identity migration `003` does the same for `user_identities`.
    Every statement is conditional, so repeated startups take no locks.
  - `auth.user_identities` is registered as a vault target, so rotation and
    migration cover linked identities.
- **Open-redirect protection — `AUTH_TRUSTED_DOMAINS`.** Every
  frontend-supplied redirect target (`?redirect_uri=` on login routes, SAML
  `RelayState`, Azure/ADFS `internal_redirect`, the identity-link
  `finish_redirect`) now goes through a single gate,
  `navigator_auth.libs.redirect.safe_redirect_url`, before a `302` is
  issued. Relative paths are resolved on the current domain; absolute
  `http(s)` targets are honoured only when their *hostname* is one of
  `AUTH_TRUSTED_DOMAINS` (or a sub-domain of one, or the host serving the
  request); mobile deep-link schemes are accepted (optionally restricted by
  `AUTH_TRUSTED_REDIRECT_SCHEMES`), browser-executable schemes never are.
  Protocol-relative (`//evil.com`), backslash and `user@host` netloc tricks
  that bypassed the previous per-backend checks are rejected; a rejected
  target logs a warning and falls back to `AUTH_REDIRECT_URI` instead of
  breaking the login. Defaults to `localhost` plus `DOMAIN`/`DOMAIN_HOST`,
  so single-domain deployments need no change; multi-app deployments should
  set `AUTH_TRUSTED_DOMAINS` explicitly. `BaseAuthBackend.validate_redirect_host` (ADFS relay, SAML
  RelayState / `redirect_uri`) now delegates to the same gate instead of
  glob-matching the raw netloc against `ALLOWED_HOSTS`. See `documentation/trusted-redirects.md`.
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
