# Unreleased

- **FEAT-106 review fixes (0.30.0).** Fixes every high-severity finding from the
  PR #633 review. The OAuth2 login form now enforces the second factor
  (`POST /oauth2/login/mfa`; `503` when 2FA is on and the MFA services are
  unavailable). MFA seeds move to their own `user_mfa_secrets` table
  (migration `002_mfa_secrets.sql`) with an `mfa` vault target registered under
  `navigator_session.vault_targets`; reinstall the package (`uv pip install -e .`)
  so `navigator-vault` discovers it. Security transitions use one connection and a
  bounded per-user lock (`AUTH_MFA_LOCK_TIMEOUT`), MFA services heal without a
  restart (`AUTH_MFA_RETRY_INTERVAL`), and credential changes are atomic and
  fail-closed (`503 mfa_unavailable`, `409 credentials_changed`). Regenerating
  backup codes needs proof of a strong factor (`403 strong_factor_proof_required`).
  OAuth2 access tokens carry `mfa`/`amr` through refresh, introspection and
  userinfo, and ABAC reads assurance from the presented bearer token.
  `oauth_user_generation` invalidates older OAuth credentials after a password
  reset or recovery, admin `password_reset` now ends the target's sessions and
  tokens, revocation failures are strict (503, password unchanged), and recovery
  confirmations are consumed transactionally in `recovery_confirm_consumptions`.
  See `docs/two_factor_auth.rst`.

- **Two-factor authentication for BasicAuth (FEAT-106, opt-in).** TOTP
  (Google-Authenticator-compatible) and e-mail one-time codes are a second
  factor for username/password logins, enforced per tenant through the new
  `auth.tenant_mfa_policy` table. It is off by default
  (`AUTH_BASIC_2FA_ENABLED`), so the login path is unchanged until enabled.
  An MFA-required login returns the new `401` `mfa_required` challenge envelope;
  `/auth/mfa/*` adds challenge, verification, TOTP enrollment, backup-code, and
  administrative disenrollment routes. This adds six MFA tables, the
  `AUTH_OTP_*`, `AUTH_TOTP_ISSUER`, and `AUTH_MFA_*` settings, the
  `mfa_admin_access.yaml` pack and `mfa:disenroll` action, and
  `scripts/preflight_mfa.py`. The `mfa:` vault namespace is reserved and the
  generic vault API rejects it. See `docs/two_factor_auth.rst`.
- **Behavior change — `PDP.add_policy()` and `PDP(policies=[...])` are enforced
  (FEAT-109).** They used to append to a list `PDP.authorize` never read, so
  programmatic policies were silently ignored (the PBAC example answered 428 for
  `/dashboard/`). Registered policies are now adapted with the new
  `PolicyAdapter.from_policy`, loaded into the `PolicyEvaluator`, and kept across
  `reload_policies()` and per-tenant evaluators; `add_policy` returns the loaded
  `ResourcePolicy` list. It now **raises `ValueError`** instead of accepting a
  policy it cannot enforce: duplicate registered names, invalid resource
  patterns (including `!`-negated ones), and classic `context` / `conditions` /
  `scopes` restrictions (use `subject=[...]` for a username restriction). Classic
  `environment` accepts `day_of_week` as an alias of `dow`; unsupported keys are
  rejected. `Policy(resource="...")` with a single string no longer raises
  `TypeError`.
- **PDP policy registry hardening (FEAT-112).** `PolicyEvaluator.load_policies`
  is now all-or-nothing: a failure (e.g. a policy that cannot be serialized)
  leaves the evaluator unchanged, and `PDP.add_policy` raises `ValueError`
  instead of leaving a half-loaded policy that made `on_startup` skip the
  storage load. `add_policy` also rejects a name already loaded from
  storage/YAML, and a storage/YAML policy named like a registered one logs a
  WARNING on startup and reload (both stay enforced). `PDP(policies=...)`
  accepts any iterable and raises `TypeError` for strings, mappings and
  non-iterables instead of silently ignoring a tuple.
- **`PDP.on_shutdown` no longer crashes with periodic reload on (FEAT-113).**
  It called the nonexistent `asyncio.suppress`, so with
  `ABAC_RELOAD_INTERVAL > 0` shutdown raised `AttributeError` and the policy
  storages were never closed. It now uses `contextlib.suppress`.
- **`PolicyAdapter.from_policy` validates `ObjectPolicy(objects=...)` (FEAT-111).**
  Objects are converted with the policy's `type=` (default `object`) and
  validated like `resource=`. A policy is rejected (`add_policy` raises
  `ValueError`) instead of losing objects silently: `resource=` combined with
  `objects=`, `!`-negated objects, dict-shaped or non-string objects, and
  `objects=` on `Policy` / `FilePolicy`. A `ResourcePolicy` passed to
  `add_policy` now has its `environment` checked too: keys other than `hour`,
  `dow`, `is_business_hours`, `is_weekend`, `day_segment` and `is_manager`, or
  unsupported value shapes, raise `ValueError` instead of being silently
  ignored by the engine (use `dow`, not `day_of_week`, on native policies).
- **`abac_middleware` no longer mishandles unrouted requests (FEAT-109).** The
  404 skip swallowed `HTTPNotFound`, ran the 404 handler twice and logged
  `Access to <path> is not Authenticated.` at WARNING for browser probes
  (`/favicon.ico`, `/.well-known/...`). Unrouted requests now pass through once
  and silently; the unauthenticated pass-through logs at DEBUG.
  `EXCLUDE_DEFAULTS` is unchanged.
- **Startup warning for short HMAC keys (FEAT-109).** `AuthHandler.setup` logs
  one WARNING on `navigator_auth.security` per configured HMAC key shorter than
  32 bytes (`AUTH_SECRET_KEY`, `AUTH_TOKEN_SECRET` / `PARTNER_KEY`, an explicit
  `AUTH_RECOVERY_SECRET`), naming the setting and its length, never the value.
  See "Signing keys" in `docs/settings.rst`.
- **`AUTH_PROBE_IGNORE_IPS`: exclude hosts from the repeated-probe warning.**
  Comma-separated IPs or CIDR ranges whose rejected requests are never
  counted by `protected_paths_middleware`, so a load balancer's health checks
  (e.g. AWS ELB/ALB pinging the server) no longer show up as a scan. Matched
  against the resolved client IP. See `documentation/protected-paths.md`.

- **BREAKING — write envelope on the auth CRUD handlers (FEAT-107, no
  deprecation window).** `/api/v1/users*`, `/api/v1/groups*`,
  `/api/v1/user_groups*`, `/api/v1/usergroups*`, `/api/v1/group_permissions*` and
  `/api/v1/permissions*` were authorized by authentication alone; any session
  could set `is_superuser` / `user_role` / `is_staff`, join any group (including
  `superuser`) or grant any permission. Privileged columns are no longer
  writable through PATCH/PUT/POST; use `POST /api/v1/users/{id}/role` with
  `users:grant_role`, held by `security_admin`. Passwords are no longer settable
  through the user CRUD, including on create; use `password_change` or
  `password_reset`. `username` is no longer updatable; users are created with
  PUT; owners edit with PATCH; reads are gated; and `?_filter=` answers 400 on
  the ModelView routes. Membership or definition of protected groups requires
  `users:grant_role` (`AUTH_PROTECTED_GROUPS`). A user can no longer delete
  their own account through `DELETE /api/v1/users/{id}`. Deploy the new
  `abac/default_policies/auth_crud_admin_access.yaml` pack. Find affected
  callers through the guard's audited 403s. See `docs/auth_crud_authorization.rst`.

- **Owner-or-superuser access control on the auth model CRUD surfaces
  (FEAT-105, client-visible behaviour change).** `/api/v1/user_identity*`,
  `/api/v1/user_accounts*` and `/api/v1/partner/tokens*` were reachable by any
  authenticated session and serialized credential columns. They are now
  ownership-bound (owner, else a policy-governed superuser), answer through an
  explicit column allowlist, and fail closed. `user_identity`/`user_accounts`:
  foreign rows are `404`, `?user_id=<other>` is `403`, vault-managed columns
  are read-only (`400`), superusers get a redacted, audited view limited to
  revoke/delete. `partner/tokens` is superuser-only and returns the token once.
  `?_filter=` is parameterized and allowlisted; `UserAccountHandler`'s
  `social_networks` lookup no longer interpolates the provider (SQL injection).
  New public `navigator_auth.decorators.policy_allows()` and policy pack
  `abac/default_policies/auth_model_admin_access.yaml`. See
  `documentation/identity-vault.md` and `documentation/pdp.md`.

- **A login no longer publishes an already-aged provider token (FEAT-103,
  `issue:3fd80396c685`).** Navigator's `logout` ends only the Navigator
  session, so the next external login is silent at the IdP and Entra answers
  it with the access token it already issued — same `iat`/`exp`, with
  `expires_in` reporting only the remainder. Backends now pass the captured
  grant through the new `ExternalAuth.ensure_fresh_login_grant`, which applies
  the same `IDENTITY_REFRESH_LEEWAY` rule as `get_live_provider_token` and
  refreshes before the grant reaches the Graph call, the session and the
  vault. It never fails a login: when the refresh is impossible the provider's
  credential is published as received, with a warning. The session gains
  `external_issued_at` (the access token's `iat`, when it is a JWT) beside
  `external_expires_at`, and `TokenResponse` gains `issued_at` /
  `age_seconds()`. New opt-in setting `AZURE_LOGIN_PROMPT` (empty by default)
  sends the OIDC `prompt` on the login authorization request; `login` makes
  Entra re-authenticate and issue a new token instead of serving its cache.

- **`expires_in` is now seconds-remaining; new `expires_at` (FEAT-103,
  client-visible behaviour change).** Login, refresh, ephemeral-token and
  external-callback responses published the absolute expiry epoch (a float)
  under the key `expires_in`, which RFC 6749 §4.2.2 defines as a duration.
  `expires_in` is now an integer number of seconds remaining (never below 0)
  and the absolute instant is published alongside as the new integer
  `expires_at`. This extends the existing B1 decision
  (`backends/oauth2/backend.py`: "expires_in is seconds") to the legacy login
  publishers (`external`, `auth` refresh/ephemeral, `basic`, `troc`, `noauth`).
  `IdentityProvider.create_token` is unchanged.
- **`request.user.expires_in` changes the same way (FEAT-103,
  client-visible).** The dynamic user attribute (set by `basic`, `troc`,
  `noauth`, `token`) is now integer seconds remaining and gains
  `request.user.expires_at` (absolute epoch). The attribute is undeclared on
  `Identity`/`AuthUser`, so there is no schema version to bump: any consumer
  that read it as a timestamp must switch to `expires_at`.

- **CSRF: `str` `SECRET_KEY` crash and API-key / partner-token scoping
  (0.28.5).**
  - With `AUTH_SECRET_KEY` set (a `str`; `SECRET_KEY` is `bytes` only for
    the generated fallback) every authenticated request without an
    `Authorization` header — `?apikey=` / `X-API-KEY`, partner tokens,
    cookie sessions — answered 500 once `csrf_middleware` issued the CSRF
    cookie (`hmac.new` requires bytes). `generate_csrf_token` /
    `verify_csrf_token` now accept `bytes | str`; tokens are identical for
    the equivalent bytes key and `conf.SECRET_KEY` is unchanged.
  - The CSRF check is now scoped by the credential that actually
    authenticated the request instead of by the absence of an
    `Authorization` header. Every auth middleware records it under
    `request[AUTH_MECHANISM_KEY]` (`"auth_mechanism"`: `cookie`, `bearer`,
    `apikey`, `partner`, `token`, `django`) and only `cookie` is checked.
    Unsafe requests (`POST`/`PUT`/`PATCH`/`DELETE`) authenticated by API
    key or partner token were answered 403 since 0.28.2 and no longer are,
    and such responses no longer carry a `csrf_token` cookie. A cookie
    session cannot opt out by appending a junk `?apikey=`: the mechanism is
    recorded only when the credential validates. Third-party backends that
    record no mechanism keep the previous header heuristic.
- **Passkey (WebAuthn) authentication backend (FEAT-101).** New
  `navigator_auth.backends.PasskeyAuth` (optional extra
  `navigator-auth[passkey]`, Redis >= 6.2): per-tenant relying parties
  (`PASSKEY_RELYING_PARTIES`), passwordless sign-in through
  `POST /api/v1/login` with `X-Auth-Method: PasskeyAuth`, enrollment and
  credential-management endpoints under `/api/v1/auth/passkey/`, passkey
  sign-in on the OAuth2 login page, and `auth_method` / `mfa` keys in the ABAC
  evaluation context. See `docs/passkey.rst`.
- **Disabled accounts are now rejected at login (FEAT-101, behaviour change).**
  `BasicAuth.open_session` (so Basic, TokenExchange and Passkey) and the
  OAuth2 login page password POST now return 403 when the user record has
  `is_active` false, and create no session. Records without an `is_active`
  field are unaffected. `mfa` and `amr` extras are now mirrored into the JWT.
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

- **Behaviour change — `@is_authenticated()` never admits anonymous backends
  (FEAT-108, behaviour change).** `@is_authenticated()` no longer lets a request
  through `NoAuth` or any backend with `_anonymous_auth = True`, and it rejects a
  restored guest session (`AnonymousUser`) with `401`. A backend's unexpected
  exception is logged and that backend is skipped, so the request answers `401`,
  never `500`. Migration: keep anonymous access for a path by listing it in the
  auth exclude list, or by marking the handler with `@allow_anonymous` (or setting
  `request.allow_anonymous`). Deployments that relied on `NoAuth` to serve public
  pages must make that change.

- **Behaviour change — the OAuth2 token endpoint refuses unknown or disabled resource
  owners (FEAT-108, behaviour change).** When the resource owner of a grant is
  unknown or disabled, the token endpoint answers `400 invalid_grant`
  ("The resource owner of this grant cannot be resolved.") instead of issuing a
  session-less token. The authorization code is consumed, and the refresh grant
  revokes that refresh chain. `/oauth2/authorize` and device verification send such
  a session to the login form; consent answers `401 access_denied`.

- **Behaviour change and contract — identity-store outages answer `503`
  (FEAT-108, behaviour change + contract).** Identity-store failures answer a generic
  `503` (`server_error`) and never revoke refresh chains; an authorization code
  stays redeemable after an outage. `IdentityProvider.user_from_id` raises the new
  public `navigator_auth.exceptions.IdentityStoreUnavailable` (status `503`) for
  infrastructure failures instead of `UserNotFound`. Custom identity providers must
  raise `UserNotFound` only for a confirmed missing user, and
  `IdentityStoreUnavailable` for infrastructure failures.

- **`/oauth2/userinfo` omits the claims it cannot supply (FEAT-108).** Profile and
  email claims that the server cannot resolve are left out of the response instead
  of being returned as `""`.

- **Device login returns to the device verification form (FEAT-108).** After login,
  a device flow resumes the pre-filled device verification form. Approval still
  requires an explicit submit, so logging in alone approves nothing. A
  `device_user_code` that is not a plain code is refused with `400`; no return URL
  is accepted.

- **`APIKeyAuth` declines non-API-key bearers; `allow_hosts` publishes userdata
  (FEAT-108).** `APIKeyAuth` declines a bearer token that is not an API key instead of
  treating it as one. The `allow_hosts` exempt branch now publishes
  `request["userdata"]`.

- **Examples pin their backends and use PKCE (FEAT-108).** Both OAuth2 examples pin
  `backends=[Oauth2Provider]` and `authz_backends=[]`, so an inherited `NoAuth`,
  `APIKeyAuth` or `allow_hosts` setting cannot admit a request without a session. The
  `oauth2_server.py` browser pages perform PKCE with `S256` and a random `state`. See
  `examples/README.md`.

# v0.0.6

- NoAuth, Basic Authentication
- DjangoAuth (getting user info using Django SessionID)
# v0.0.1

- First Version
- Work with Basic Authentication
