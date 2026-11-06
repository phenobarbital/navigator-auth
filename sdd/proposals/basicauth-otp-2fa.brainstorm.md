---
# SDD flow type and base branch (FEAT-145).
type: feature
base_branch: dev
projects: [auth-backends, mfa, handlers, abac, models]
tags: [2fa, otp, totp, email-otp, multi-tenant, security]
---

# Brainstorm: 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement

**Date**: 2026-11-06
**Author**: Jesus Lara
**Status**: exploration
**Recommended Option**: Option A

---

## Problem Statement

`BasicAuth` is single-factor: a valid `user` + `password` pair goes straight from
`validate_user()` to `open_session()` (`navigator_auth/backends/basic.py:307-315`),
so a leaked or guessed password is a complete account takeover. Every stronger
option navigator-auth offers today requires leaving username/password behind
entirely — `PasskeyAuth` (passwordless WebAuthn) or an external IdP (Azure, Okta,
Google, SAML) that enforces MFA on its own.

Deployments that must keep username/password — because their users are not in an
IdP, or because the tenant is not ready to roll out passkeys — have no way to add
a second factor. There is no OTP, TOTP or MFA machinery anywhere in the package:
`AbstractOTPProvider`, `tenant_mfa_policy` and `user_trusted_devices` do not
exist, and `conf.py` has no `AUTH_OTP_*` settings.

**Who is affected**: end users of `BasicAuth` deployments (a second step at
login), operators of multi-tenant installs (they need to require 2FA for one
tenant without touching others), and integrators (a new `mfa_required` branch in
the login response).

**Why now**: the surrounding machinery landed over the last three features and
is sitting unused for this purpose. `open_session()` already mirrors `mfa` and
`amr` into the JWT (`basic.py:153`, FEAT-101), ABAC already exposes `auth_method`
and `mfa` as first-class evaluation keys (`abac/context.py:137-141`, TASK-92), and
FEAT-098 built a complete HMAC-signed, `sha256`-keyed, TTL'd Redis token store
with a rate limiter and a notification-callback hand-off that an OTP challenge
can reuse almost verbatim. The expensive half of this feature is already built
and tested; what is missing is the factor itself.

## Constraints & Requirements

- **No new runtime dependency.** `cryptography` (already a hard dependency) ships
  RFC 6238 TOTP *and* the `otpauth://` provisioning URI. `pyotp`, `qrcode`,
  `aiosmtplib` and `twilio` are absent from the environment and must stay absent.
  SMS is therefore out of scope — it needs an external provider the environment
  does not have.
- **navigator-auth never sends e-mail** (`docs/password_recovery.rst:9`). Code
  delivery hands a payload to a configured callback, exactly as
  `AUTH_RECOVERY_CALLBACK` does.
- **A second factor must never be able to open a session on its own.** This rules
  out modelling the providers as `BaseAuthBackend` subclasses: `authenticate()`'s
  contract *is* "mint a session", so a registered OTP backend would turn the
  second factor into a sufficient factor.
- **The first factor is never skipped.** Nothing in this feature — remember-me
  included — may let a caller past the password step.
- **`BasicAuth` has two subclasses that must not inherit the challenge**:
  `TokenExchangeAuth` (`backends/exchange.py:31`) and `PasskeyAuth`
  (`backends/passkey.py:63`). Both call `open_session()` directly, so the hook
  belongs in `BasicAuth.authenticate()`, never in `open_session()`.
- **Enrolment must not be a precondition for enforcement.** Turning 2FA on for a
  tenant cannot lock its users out while they enrol.
- **Fail-closed.** A Redis or storage outage during challenge verification must
  refuse the login. (Note: FEAT-098's `RateLimiter` is deliberately *fail-open*;
  it cannot be reused unmodified for this.)
- **Backwards compatible.** Tenants that do not opt in see no behavioural change,
  and the existing single-step `POST /api/v1/login` response shape is unchanged
  for users with no second factor.
- Every security-relevant transition (enrol, disenrol, admin disenrol, policy
  change, trusted-device revocation) must be auditable.

---

## Options Explored

### Option A: `AbstractOTPProvider` owned by `BasicAuth`, with a two-tier factor model

A new `navigator_auth/mfa/` package defines `AbstractOTPProvider` and two
implementations, `TOTPProvider` and `EmailOTPProvider`. They are **not**
authentication backends: `BasicAuth` owns them, builds them at `on_startup()`
from the tenant policy, and consults them from `authenticate()`. Only
`BasicAuth.open_session(extra={"mfa": True, "amr": [...]})` ever mints a session.

The two providers are deliberately **asymmetric**, which is the core idea of this
option:

- **Email OTP is a floor, not a choice.** It needs no enrolment, because
  `User.email` already exists. The moment a tenant is switched to `enforced`,
  every user in it has a working second factor on their next login.
- **TOTP is a voluntary upgrade.** Confirming it moves the user to a stronger
  state and **closes the email path** for them, so the mailbox stops being the
  ceiling on their account's security. The same applies symmetrically to a
  registered passkey.

Per-user state is therefore a three-state machine — `none → email → totp` — and
the per-tenant policy lives in a new `auth.tenant_mfa_policy` table (data, not
configuration), with `AUTH_BASIC_2FA_ENABLED` demoted to a global kill switch.

✅ **Pros:**
- The second factor is structurally incapable of opening a session: there is no
  code path from a provider to `remember()` or `create_token()`.
- Enforcement costs almost nothing to roll out. Because email is a zero-enrolment
  floor, there is no user lock, no enrolment grace period, no partial session that
  may only reach the enrolment endpoints — the three things that make "mandatory
  MFA" expensive in most systems.
- Reuses four tested FEAT-098 modules nearly verbatim (token store shape, rate
  limiter, redacted notification payload, password-policy pattern) and the
  FEAT-001 vault for the TOTP seed, which brings AAD binding and key rotation for
  free.
- Zero new dependencies, and the provisioning URI comes from the stdlib-adjacent
  `cryptography` API rather than hand-rolled Base32 string building.
- `mfa` / `amr` already flow to the JWT and to ABAC, so policies can require a
  second factor on day one with no ABAC changes.
- `TokenExchangeAuth` and `PasskeyAuth` are untouched by construction.

❌ **Cons:**
- The weakest factor is universally available in an enforced tenant, so a tenant's
  2FA strength is bounded by its users' mailbox security until they upgrade to
  TOTP. The downgrade-closing rule limits this per user but not tenant-wide.
- A three-state machine with closing/reopening transitions is more logic than a
  single "2FA on/off" flag, and each transition has its own invalidation duties.
- Delivery is only as reliable as the operator's callback; a broken callback is
  an outage for every `email`-state user in an enforced tenant.
- Introduces two new tables plus a vault key, so it is not a code-only change.

📊 **Effort:** Medium-High

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `cryptography` | RFC 6238 TOTP + `otpauth://` provisioning URI | **already a hard dependency** (`>=41` declared; 46.0.7 installed). `hazmat.primitives.twofactor.totp.TOTP` + `get_provisioning_uri()`. No new dependency. |
| `redis.asyncio` | challenge store, rate limiter, TOTP replay guard | already used package-wide (5.2.1) |
| `navigator_session.vault` | seal/open the TOTP seed with AAD + `key_version` | already wired via `identity/crypto.py` |
| `secrets` / `hashlib` / `hmac` (stdlib) | code generation, `sha256` keying, HMAC signing | — |
| ~~`pyotp`~~ | — | **rejected**: redundant with `cryptography`, and absent from the environment |
| ~~`qrcode`~~ | — | **rejected**: the QR is rendered client-side from the `otpauth://` URI |

🔗 **Existing Code to Reuse:**
- `navigator_auth/handlers/recovery/store.py:42` — `RecoveryTokenStore`: `sha256(token)`
  as the only Redis key, HMAC-signed payloads, `setex` to write / `getdel` to
  consume. The challenge store is this shape with a different namespace.
- `navigator_auth/handlers/recovery/limiter.py:28` — `RateLimiter` fixed-window
  counter (`INCR` + `EXPIRE` only on the first hit). Reused **with its fail-open
  branch inverted** for verification.
- `navigator_auth/handlers/recovery/types.py:33` — `NotificationPayload`'s redacted
  `__repr__`, so a stray `repr()` can never put a live code in a log line.
- `navigator_auth/identity/flow_store.py:18` — `IdentityFlowStore`: the pooled
  `setex`/`get`/`getdel` wrapper pattern for short-lived per-request state.
- `navigator_auth/identity/crypto.py` + `navigator_auth/vault/sql/001_create_vault_tables.sql`
  — `auth.user_vault_secrets` as the encrypted home of the TOTP seed.
- `navigator_auth/backends/basic.py` — `open_session(extra=...)` and
  `_JWT_EXTRA_KEYS`; the integration point, unchanged in shape.
- `navigator_auth/passkey/sql/001_passkey_credentials.sql` + `passkey/migrations.py`
  — the migration-file pattern for the two new tables.
- `navigator_auth/abac/context.py:29` — `_resolve_tenant()` for the user's tenant pair.

---

### Option B: Post-authentication step-up middleware

Leave every backend alone and add an aiohttp middleware that inspects each
freshly-created session and, when the tenant policy demands a second factor that
the session's `amr` does not claim, downgrades the response to a challenge.

✅ **Pros:**
- One insertion point covers every current and future backend, so a new backend
  cannot forget to honour the policy.
- `BasicAuth` needs no edit at all, which keeps the most security-sensitive file
  in the package untouched.
- Naturally extends to the external IdPs later, by reading their `amr`/`acr`.

❌ **Cons:**
- It runs **after** the session exists. The JWT has already been minted, the jti
  indexed (`basic.py:239-255`) and the cookie set, so the middleware has to
  retract all of it — a revocation path that is far easier to get wrong than
  simply not creating the session.
- It cannot tell "a backend that legitimately needs no OTP" from "a backend that
  has not implemented it" without a per-backend allowlist, which re-creates the
  coupling it was meant to avoid — and it would catch `TokenExchangeAuth`,
  breaking machine-to-machine flows.
- The challenge/verify endpoints still have to exist, so the middleware is extra
  machinery rather than a replacement for it.

📊 **Effort:** Medium (but high risk)

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `aiohttp` | middleware chain | already the framework |
| `cryptography`, `redis.asyncio` | same as Option A | — |

🔗 **Existing Code to Reuse:**
- `navigator_auth/middlewares/` — existing middleware registration.
- `navigator_auth/auth.py` — `auth_middleware` (`auth.py:1026`) as the pattern.
- `navigator_auth/backends/oauth2/code_backend.py` — `AccessTokenStorage` for the
  retraction path.

---

### Option C: Model the OTP step as an OAuth2 step-up inside `Oauth2Provider`

Express the second factor as an un-promoted authorization code in the existing
OAuth2 subsystem: the password step yields a code that is not yet exchangeable,
and only a successful OTP promotes it. The challenge state machine becomes the
OAuth2 code flow, and the existing login page (`templates/oauth/login.html`,
which already does username-first passkey sign-in) grows a second step.

✅ **Pros:**
- Reuses a state machine that is already single-use, TTL'd, PKCE-bound and
  conformance-tested (`tests/test_oauth2_*`), rather than introducing another one.
- `acr_values` / `amr` are the standards-native way to express "this session was
  stepped up", and the OAuth2 provider already issues both.
- The browser login page is the surface where most of the UX work would land
  anyway, and it is already passkey-aware.

❌ **Cons:**
- Does nothing for the direct API callers of `POST /api/v1/login`
  (`auth.py:675-676`), which is precisely where `BasicAuth` is used most. It would
  need a second, parallel implementation for them — the worst outcome of all.
- Couples a `BasicAuth` concern to the OAuth2 provider, so deployments with
  `enable_authdb=False` or no OAuth2 provider configured get no 2FA.
- The OAuth2 surface is the most conformance-sensitive code in the package;
  bending its code lifecycle for an unrelated concern invites regressions in
  flows (device authorization, DCR, introspection) that have nothing to do with 2FA.

📊 **Effort:** High

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `PyJWT` | already used for provider tokens | existing |
| `cryptography` | TOTP | existing |

🔗 **Existing Code to Reuse:**
- `navigator_auth/backends/oauth2/` — the whole code/token lifecycle.
- `templates/oauth/login.html` — existing two-step-capable login page.

---

### Option D (unconventional): One "authenticator registry" — fold TOTP and email into the passkey credential store

Rather than a new OTP subsystem, generalise what FEAT-101 already built: treat
every second factor as a row in the existing `user_credentials` table, so a
passkey, a TOTP seed and "email is available" are three kinds of the same thing.
The passkey module already exposes credential list / rename / delete endpoints
(`backends/passkey.py:83-88`), which this feature would otherwise duplicate.

✅ **Pros:**
- One management surface and one mental model for users: a single "security
  methods" screen, with the list/rename/delete endpoints already written.
- Makes the "strong factor registered ⇒ close the email path" rule trivial to
  evaluate — it is one query against one table, with no cross-subsystem join.
- Positions a future WebAuthn-as-second-factor step-up as a configuration change
  rather than a new feature.

❌ **Cons:**
- `user_credentials` is modelled for **public** keys (`credential_id`,
  `public_key`, `sign_count`, `aaguid`, `backed_up`). A TOTP seed is a *shared
  secret* with the opposite handling requirements — it must be sealed by the
  vault, never returned, and rotated by `key_version`. Storing both in one table
  means half the columns are always NULL and the most dangerous column needs
  rules the table does not express.
- Couples the OTP feature to the `passkey` optional extra. `webauthn` is **not
  installed** in this environment, so the import surface would have to stay
  optional while the OTP path is mandatory.
- The management endpoints come with WebAuthn-specific authorization and RP-scoping
  assumptions (`rp_id` filtering) that do not apply to a TOTP seed.

📊 **Effort:** Medium (but high coupling)

📦 **Libraries / Tools:**
| Package | Purpose | Notes |
|---|---|---|
| `webauthn` | passkey verification | **optional extra, not installed here** |
| `cryptography` | TOTP | existing |

🔗 **Existing Code to Reuse:**
- `navigator_auth/passkey/store.py` — `PasskeyStore` CRUD.
- `navigator_auth/backends/passkey.py:83-88` — credential management routes.

---

## Recommendation

**Option A** is recommended.

The decisive argument is a structural one, and it is the reason Option B loses
despite its appeal: *a second factor must be incapable of minting a session.*
Option A gets that for free, because the providers are plain objects that return
a boolean and never touch `remember()` or `create_token()`. Option B inverts the
order — it lets the session exist and then takes it back — which turns a property
the type system can guarantee into a revocation path that must be correct at
runtime, under failure, forever. For an authentication package, that trade is not
worth the extensibility it buys.

Option C is rejected on reach rather than on quality: the OAuth2 code flow *is* a
better state machine than anything we would write, but it does not cover
`POST /api/v1/login`, which is the dominant way `BasicAuth` is consumed. A design
that needs a second implementation for the main caller is worse than one honest
implementation.

Option D is the one worth revisiting later. Its instinct is right — users should
see one list of security methods, and we *will* duplicate some credential
management by not doing it — but `user_credentials` is shaped for public keys, and
putting a vault-sealed shared secret in it would make the schema lie about its
most sensitive column. The cost of Option A's separate tables is some duplicated
CRUD; the cost of Option D is a storage model that fights the data. We take the
duplication and leave the unification as a follow-up once there are two strong
factors to unify.

**What Option A trades away, explicitly:**

1. **A tenant's 2FA is only as strong as its mailboxes, until users upgrade.**
   Email-as-floor is what makes enforcement cheap to roll out, and it is also the
   ceiling. The per-user downgrade-closing rule bounds the blast radius but does
   not raise the floor. Accepted deliberately: the alternative (enrolment-gated
   enforcement) costs a lock-out window, a partial-session mode and an enrolment
   grace module, and in practice delays MFA adoption by months.
2. **Email OTP and password recovery share a channel.** A compromised mailbox
   yields both factors *and* the reset path. Acceptable for a fallback factor;
   documented as unacceptable as the only method for a privileged account.
3. **Two new tables and a vault key**, so this ships with a migration rather than
   as a pure code change.
4. **Some credential-management duplication** versus Option D, as argued above.

---

## Feature Description

### User-Facing Behavior

**A user whose tenant has not enabled 2FA, or who has not opted in**: no change
whatsoever. `POST /api/v1/login` returns a token exactly as today.

**A user in the `email` state** (opted in, or in an `enforced` tenant): the login
response carries no token. It reports that a second factor is required, and a
6–8 digit code arrives in their inbox. They post the code with the challenge
reference and receive their session. They are not offered "remember this device"
— that is reserved for strong factors, which is also the nudge toward TOTP.

**A user enrolling TOTP**: from a live session they request enrolment and receive
an `otpauth://` URI, which the front-end renders as a QR code for Google
Authenticator (or any RFC 6238 app). Enrolment only completes once they submit a
working code, so a user who never finished scanning is never left in a broken
state. From then on, the second step asks for the app's code, and the email path
is **closed** for them — if they lose the device, backup codes are the way in,
not the mailbox.

**A user with backup codes**: a one-time list shown at enrolment, each usable
once. They can also be regenerated from a live session, which invalidates the
previous set.

**A user who ticked "remember me for N days"** (available only in the `totp`
state, or with a registered passkey): subsequent logins still require the
password, but no OTP challenge, until the window expires or any invalidating
event fires.

**A user who signs in with a passkey**: no OTP, ever — including in an `enforced`
tenant. WebAuthn with user verification already is possession plus
biometric/PIN, which is what Google and Microsoft rely on when they skip OTP for
passkey sign-ins.

**A user locked out**: an administrator can switch their OTP off and nothing
else. No password reset, no account edit. The user then recovers through the
existing self-service password-recovery flow on their own.

**An operator enabling enforcement for a tenant**: a pre-flight script reports
users who cannot be enforced (no e-mail address, therefore no factor) and exits
non-zero, blocking the activation until the data is fixed.

### Internal Behavior

**Login.** `BasicAuth.authenticate()` validates credentials as today. It then
resolves the user's effective policy — the strictest across the user's
organizations — and asks the provider set whether a challenge is owed. When it
is, the method issues a challenge record and returns the challenge envelope
*instead of* calling `open_session()`. No token, no jti, no cookie: nothing is
created that would have to be retracted. When no challenge is owed (policy off,
user in `none`, or a valid trusted-device token presented), the existing path runs
untouched.

**Challenge.** The challenge record is a short-TTL, single-use, HMAC-signed Redis
value keyed by `sha256(challenge_token)`, carrying the user, the providers
available to that user, the preferred one, and an attempt counter. It is
deliberately **not** a session JWT: that is what keeps the first factor from
being sufficient. For an `email`-state user, issuing the challenge also hands a
redacted payload to the delivery callback; the response is byte-identical whether
delivery succeeded, the address was unknown, or the callback raised.

**Verification.** The verify endpoint consumes the challenge, dispatches to the
named provider, and on success calls `open_session(extra={"mfa": True, "amr": [...]})`
— the one and only session-minting path. `amr` is honest about *how* the factor
was satisfied (`otp`, `totp`, or `trusted_device`), so an ABAC policy can require
a freshly-presented factor rather than a month-old remembered device. Failures
decrement the attempt budget; exhausting it burns the challenge. A storage error
refuses the login.

**TOTP specifics.** The seed is sealed by the vault under a per-user key, bound by
AAD so a seed copied to another user fails to open. Verification walks a ±1 step
window, because the `cryptography` primitive validates exactly one step. Every
accepted step is recorded in Redis for its remaining lifetime, so the same code
cannot be replayed inside its own 30-second window.

**State transitions.** Confirming TOTP (or registering a passkey) closes the email
path. Disenrolling re-opens it, which is a downgrade and therefore requires
password re-authentication, notifies the user, and is audited. Administrative
disenrolment is the same transition under a *separate permission* from user CRUD,
and must additionally revoke every trusted device — otherwise it does nothing
against an attacker who already holds a remember-me cookie.

**Remember-me.** A rotating, `sha256`-stored token in an `HttpOnly` / `Secure` /
`SameSite` cookie, bound to the user and rotated on every use. Re-presenting an
already-rotated token means the chain was stolen, which revokes the whole family.
It is offered only to strong-factor users and only when the tenant's window is
non-zero.

**Policy.** `auth.tenant_mfa_policy` holds mode and remember-window per
organization. Users spanning several organizations get the strictest. The tenant
comes from the authenticated user record, which is why this needs no new tenant
resolution mechanism — unlike the passkey RP-ID case (F015), the password step has
already identified the user by the time the policy is read.

### Edge Cases & Error Handling

| Situation | Behaviour |
|---|---|
| User in an `enforced` tenant with no e-mail address | Login refused (fail-closed). No factor exists, so a single factor must not be accepted. The pre-flight is what prevents this at activation; this branch covers users created afterwards. |
| Delivery callback raises, times out, or is unconfigured | `/challenge` returns the same generic success body. The user cannot log in; the failure is logged at WARNING. An operator outage must not become an enumeration oracle. |
| Redis unavailable during verification | Login refused (fail-closed). Opposite of FEAT-098's `RateLimiter`, which fails open on purpose for a public recovery endpoint. |
| Same TOTP code submitted twice inside its window | Second attempt rejected by the replay guard. |
| Clock drift on the user's phone | ±1 step (±30 s) accepted; beyond that, rejected. |
| Challenge expired or already consumed | Generic failure; the user restarts from the password step. |
| Brute force against a 6-digit code | Per-challenge attempt budget plus per-user and per-IP rate limits. Exhausting the budget burns the challenge, not just the attempt. |
| User has TOTP but lost the device | Backup codes. Exhausted ⇒ administrative OTP disenrolment ⇒ falls back to the email floor ⇒ self-service recovery. |
| Trusted-device cookie stolen | Rotation detection revokes the entire family on first replay of a rotated token. |
| Trusted-device cookie survives a password change or recovery | It must not: both invalidate every trusted device for that user. |
| Tenant switched to `enforced` while sessions are live | Existing sessions are untouched; the policy applies at next login. Trusted devices are revoked, so the next login does present a challenge. |
| `TokenExchangeAuth` / machine-to-machine login | No challenge, by construction: the hook is in `BasicAuth.authenticate()`, which `TokenExchangeAuth` overrides. |
| Passkey sign-in in an `enforced` tenant | No challenge. Caveat: this rests on `PASSKEY_USER_VERIFICATION` defaulting to `required`; a deployment that lowers it to `discouraged` makes its passkeys single-factor and silently weakens this guarantee. |
| User belongs to one `enforced` and one `optional` organization | Strictest wins: enforced. |
| A live code or seed reaching a log line | Structurally prevented: codes are stored only as `sha256`, the notification payload redacts its own `__repr__`, and the seed is only ever handled sealed. |

---

## Capabilities

### New Capabilities
- `basicauth-otp-2fa`: a second factor for `BasicAuth` via two OTP providers
  (TOTP and e-mail), owned by the backend rather than registered as backends.
- `mfa-tenant-policy`: per-organization 2FA mode and remember-me window, with a
  strictest-wins resolution across a user's organizations and a blocking
  pre-flight check before activation.
- `mfa-backup-codes`: single-use recovery codes, and bounded administrative
  disenrolment as the last resort.
- `mfa-trusted-devices`: opt-in, rotating, revocable "remember me for N days"
  that skips only the OTP step and only for strong-factor users.

### Modified Capabilities
- `passkey-support-backend` (FEAT-101): a registered passkey now also satisfies
  tenant 2FA enforcement and closes the e-mail OTP path for that user. No change
  to WebAuthn verification itself.
- `backend-based-password-recovery` (FEAT-098): completing a recovery must now
  revoke the user's trusted devices. Its store/limiter/payload modules are the
  template for this feature's equivalents but are not themselves modified.

---

## Impact & Integration

| Affected Component | Impact Type | Notes |
|---|---|---|
| `navigator_auth/mfa/` | **new** | `AbstractOTPProvider`, `TOTPProvider`, `EmailOTPProvider`, challenge store, fail-closed limiter, state machine, policy resolution. |
| `navigator_auth/backends/basic.py` | modifies | `authenticate()` gains the challenge branch; `on_startup()` builds the provider set. `open_session()` unchanged. |
| `navigator_auth/backends/exchange.py` | **unaffected by design** | Overrides `authenticate()`; must be covered by a regression test proving it never sees a challenge. |
| `navigator_auth/backends/passkey.py` | depends on | Passkey registration becomes a strong-factor signal; passkey sign-in bypasses the challenge. |
| `navigator_auth/auth.py` | modifies | `POST /api/v1/login` gains the `mfa_required` response branch; new MFA routes registered and added to the exclude list. |
| `auth.tenant_mfa_policy` (new table) | **new** | Mode + remember window per org, with activation provenance. |
| `auth.user_mfa` (new table) | **new** | Per-user enrolment state, confirmation and last-use timestamps. |
| `auth.user_mfa_backup_codes` (new table) | **new** | Hashed single-use codes. |
| `auth.user_trusted_devices` (new table) | **new** | Token hashes, labels, expiry, revocation. |
| `auth.user_vault_secrets` | depends on | Holds the sealed TOTP seed under a new key. No schema change. |
| `navigator_auth/conf.py` | modifies | `AUTH_BASIC_2FA_ENABLED` kill switch plus `AUTH_OTP_*` knobs (TTL, attempts, rates, code length, issuer, delivery callback, HMAC secret). |
| `navigator_auth/abac/context.py` | **unaffected** | `mfa` / `auth_method` keys already exist; only the `amr` *values* are new. |
| `scripts/` | **new** | Pre-flight enforcement-readiness check (non-zero exit on blockers). |
| `docs/` + `CHANGELOG.md` | modifies | Operator guide for the callback contract, the state machine, and the shared-mailbox risk. |
| `navigator_auth/handlers/users/user.py` | **out of scope, risk accepted** | See Open Questions: a pre-existing takeover path this feature exposes but must not fix. |

---

## Code Context

### User-Provided Code

No code snippets were pasted during discovery. The user's contributions were
design decisions, recorded in the Recommendation and Feature Description above:
the two-tier email-floor/TOTP-upgrade model, bounded administrative disenrolment,
remember-me, and the passkey-skips-OTP rule.

### Verified Codebase References

<!-- Verified by direct read on 2026-11-06 against branch feat/multiplatform-wheels;
     line numbers cross-checked by an sdd-contract-probe run. -->

#### Classes & Signatures

```python
# From navigator_auth/backends/basic.py:44
class BasicAuth(BaseAuthBackend):
    user_attribute: str = "user"                                       # :47
    pwd_atrribute: str = "password"                                    # :48  (sic — typo is in the code)
    _ident: AuthUser = BasicUser                                       # :49
    _service_name: str = "basic"                                       # :51

    # The integration point. Today: validate, then immediately open_session.
    async def authenticate(self, request):                             # :296
        ...
        user = await self.validate_user(login=user, password=pwd)      # :307
        return await self.open_session(request, user)                  # :315

    async def open_session(
        self,
        request: web.Request,
        user: dict,
        extra: Optional[dict] = None,
        expiration: Optional[int] = None,
    ) -> dict:                                                         # :170
        ...

    async def validate_user(self, login: str = None, password: str = None):  # :86
        ...
```

```python
# From navigator_auth/backends/exchange.py:31  — overrides authenticate(), so it
# must NOT inherit the challenge.
class TokenExchangeAuth(BasicAuth):
    async def authenticate(self, request: web.Request) -> Any:         # :125
        ...
        return await self.open_session(request, user, extra=extra, expiration=cap)  # :216
```

```python
# From navigator_auth/backends/passkey.py:63
class PasskeyAuth(BasicAuth):
    ...
```

```python
# From navigator_auth/models.py:39
class User(Model):
    email: str = Column(required=False, max=254, label="User's Email")  # :49  ← required=False
    password: str = Column(required=False, max=255, secret=True, repr=False)  # :51
    is_active: bool = Column(required=True, default=True)               # :58
    attributes: Optional[dict] = Column(required=False, default_factory=dict)  # :61
```

```python
# From navigator_auth/handlers/users/user.py:11 — OUT OF SCOPE, documented risk.
class UserManager(ModelView):
    def required_by_put(self):
        return ['first_name', 'last_name', 'display_name', 'username', 'email']  # :24
    async def _set_password(self, value, column, **kwargs): ...
    async def _calculate_password(self, value, column, *args, **kwargs): ...
```

```python
# From navigator_auth/handlers/recovery/types.py:33 — the delivery-payload pattern.
@dataclass(frozen=True)
class NotificationPayload:
    email: str
    display_name: str
    username: str
    token: str      # raw token — never in an HTTP response
    url: str
    expires_at: datetime
    found: bool     # False => no such account; the callback decides what to send

    def __repr__(self) -> str:
        # keeps a live token out of any log line reached via repr()/str()
        ...
```

```python
# From navigator_auth/handlers/recovery/store.py — the store shape to clone.
def _hash_token(token: str) -> str:                                    # :37
    """sha256(token) hex digest — the only thing ever used as a Redis key."""

class RecoveryTokenStore:                                              # :42
    def __init__(self, pool: aioredis.ConnectionPool, secret: bytes): ...
    def _sign(self, *parts: str) -> str: ...
    async def issue_recovery(self, user) -> tuple[str, RecoveryPayload]: ...

RECOVERY_KEY_PREFIX = "auth:recovery:"
CONFIRM_KEY_PREFIX = "auth:recovery:confirm:"
```

```python
# From navigator_auth/handlers/recovery/limiter.py — reuse with the fail-open
# branch INVERTED for challenge verification.
class RateLimiter:                                                     # :28
    def __init__(self, pool: aioredis.ConnectionPool, spec: str, prefix: str): ...
    async def check(self, key: str) -> bool:
        """True when the call is allowed. Fail-OPEN on Redis error (by design,
        for the public recovery endpoint) — not acceptable for 2FA verify."""

RATE_KEY_PREFIX = "auth:recovery:rate:"
```

```python
# From navigator_auth/identity/flow_store.py — pooled setex/get/getdel wrapper.
class IdentityFlowStore:                                               # :18
    def __init__(self, pool: aioredis.ConnectionPool): ...
    async def set(self, key: str, payload: dict, ttl: int) -> None: ...
    async def getdel(self, key: str) -> Optional[dict]: ...
```

```python
# From navigator_auth/abac/context.py:29 — already present; no ABAC change needed.
# (EvalContext itself is at :82.)
def _resolve_tenant(
    request: web.Request, userinfo: Any, org_id: Any, client_id: Any,
) -> tuple[int, int]:
    """kwargs → X-Org-Id/X-Client-Id headers (only if ABAC_TENANT_TRUST_HEADERS)
    → userinfo → (1, 1)."""

# In EvalContext.__init__:
self.store["auth_method"] = userinfo.get("auth_method")          # :137
self.store["mfa"] = bool(userinfo.get("mfa", False))             # :138
```

```python
# From navigator_auth/identities.py:39 — organizations are multi-valued per user.
class Organization(BaseModel):
    org_id: str = Column(required=True)
    organization: str = Column(required=True)
    slug: str = Column(required=False)

_ORGANIZATION_FIELDS = ("org_id", "organization", "slug")              # :56
```

#### Verified Imports

```python
# Confirmed to resolve:
from cryptography.hazmat.primitives.twofactor.totp import TOTP   # cryptography 46.0.7
from cryptography.hazmat.primitives.hashes import SHA1
from navigator_auth.backends.oauth2.dcr import parse_rate_limit   # dcr.py:104
from navigator_auth.backends.abstract import BaseAuthBackend, user_is_active
#   BaseAuthBackend → abstract.py:64 · user_is_active → abstract.py:43
from navigator_session.vault import KeyRing, VaultContext, open_value, seal_value
#   guarded by VAULT_CRYPTO_AVAILABLE in identity/crypto.py
```

> **Evidence note on the two `cryptography` imports.** They were verified by
> *executing* them in the project venv (importing `TOTP`, generating a code and a
> provisioning URI, and confirming that `verify()` rejects the adjacent time step).
> A repository-scoped contract probe reports them as `module-missing`, because it
> only inspects git-tracked files and `cryptography` is an external package — that
> result is not a refutation. Any future probe sheet should check these by import
> execution, not by file lookup.

#### Key Attributes & Constants

- `BasicAuth._JWT_EXTRA_KEYS` → `("auth_method", "auth_origin", "external_expires_at", "mfa", "amr")`
  (`navigator_auth/backends/basic.py:153`). **`mfa` and `amr` already reach the
  JWT** — this feature only has to populate them.
- `BasicAuth.JTI_INDEX_PREFIX` → `"auth:user:jti:"` (`basic.py:33`) — per-user live-jti
  index, the existing revocation hook.
- `PASSKEY_USER_VERIFICATION` → default `"required"` (`navigator_auth/conf.py:611`).
  The premise of "a passkey satisfies enforcement"; lowering it silently weakens that.
- `AUTH_RECOVERY_SECRET` (`conf.py:623`), `AUTH_RECOVERY_CALLBACK` (`conf.py:634`),
  `AUTH_RECOVERY_TTL` (`conf.py:629`) — the naming and wiring convention the
  `AUTH_OTP_*` settings should follow.
- `auth.user_vault_secrets` — `(user_id, key, ciphertext_db, key_version, …)` with a
  partial unique index on `(user_id, key) WHERE deleted_at IS NULL`
  (`navigator_auth/vault/sql/001_create_vault_tables.sql:11`). The TOTP seed's home.
- `cryptography`'s `TOTP.get_provisioning_uri(account_name, issuer)` emits
  `otpauth://totp/<issuer>:<account>?digits=6&secret=<base32>&algorithm=SHA1&issuer=<issuer>&period=30`
  — exactly the shape Google Authenticator expects.
- `TOTP.verify(totp: bytes, time: int) -> None` raises `InvalidToken` and validates
  **a single time step**; the ±1 step skew window must be walked by the caller.

### Does NOT Exist (Anti-Hallucination)

- ~~`navigator_auth/mfa/`~~ — no MFA package exists; this feature creates it.
- ~~`AbstractOTPProvider`, `TOTPProvider`, `EmailOTPProvider`~~ — do not exist.
- ~~`auth.tenant_mfa_policy`, `auth.user_mfa`, `auth.user_mfa_backup_codes`,
  `auth.user_trusted_devices`~~ — none of these tables exist.
- ~~`AUTH_OTP_*` / `AUTH_BASIC_2FA_ENABLED` / `AUTH_TOTP_ISSUER`~~ — no such settings
  in `conf.py`.
- ~~`User.email_verified`~~ — **there is no e-mail verification column on `User`**,
  which has `is_new` and `is_active` only. Nothing persists whether an address was
  ever verified. **Careful — the string `email_verified` does occur in the package,
  but only as an external IdP *claim*, never as our own state**: `TokenExchangeAuth._verified_email()`
  rejects a provider userinfo whose `email_verified` is explicitly falsy
  (`navigator_auth/backends/exchange.py:99-111`), and `backends/external.py:1297`
  takes `verified_key: str = "email_verified"` for the same purpose. So an
  IdP-provisioned identity *was* checked at login and the result thrown away, while
  a `BasicAuth` user — exactly the population this feature targets — has never had
  their address verified by anyone. The email-as-floor design depends on address
  trustworthiness that nothing currently establishes or records.
- ~~`pyotp`~~, ~~`qrcode`~~, ~~`aiosmtplib`~~, ~~`twilio`~~, ~~`sendgrid`~~ — not
  installed and not to be added. `webauthn` is an optional extra and is **also not
  installed** in this environment.
- ~~`UserDevices` as a usable trusted-device store~~ — the model exists
  (`navigator_auth/models.py:143`) but is **referenced nowhere in the package**
  except its own definition, and is built for 1460-day device JWTs with a ciphered
  `api_key`. Do not repurpose it; create `auth.user_trusted_devices`.
- ~~A pre-authentication tenant resolver~~ — does not exist (F015). Not needed here,
  because the password step identifies the user before the policy is read.
- ~~SMS/`AUTH_OTP_SMS_*`~~ — explicitly out of scope; no provider in the environment.

---

## Parallelism Assessment

- **Internal parallelism**: moderate, along a clear seam. The two providers,
  the trusted-device subsystem and the policy/pre-flight work are separable once
  the shared contracts land. But everything depends on two foundation pieces —
  `AbstractOTPProvider` + the challenge store, and the `authenticate()` hook — and
  almost every task touches `basic.py`, `conf.py` or the migration set. Splitting
  before the foundation exists would mean three agents editing `basic.py`
  concurrently.
- **Cross-feature independence**: no in-flight spec contends for these files.
  The two neighbours are both **completed**: FEAT-098 (`handlers/recovery/`) is a
  template, not a dependency — only the "recovery revokes trusted devices" hook
  touches it; and FEAT-101 (`passkey/`) is consumed read-only, for the
  strong-factor signal. The live risk is the current branch,
  `feat/multiplatform-wheels`, which touches packaging and the compiled
  extensions — orthogonal in content, but it means the worktree needs its native
  artifacts rebuilt rather than inherited.
- **Recommended isolation**: `per-spec`.
- **Rationale**: the shared surface (`basic.py`, `conf.py`, one migration
  sequence) is exactly where concurrent edits conflict, and the security-critical
  ordering — challenge store before providers, providers before the
  `authenticate()` hook, hook before remember-me — is sequential by nature. The
  parallelism that does exist (two providers, trusted devices, pre-flight script)
  is worth two or three tasks inside the one worktree, not separate trees.

---

## Open Questions

- [x] Flow type and base branch — *Owner: Jesus Lara*: `type: feature`, `base_branch: dev`.
- [x] Should the OTP providers be `BaseAuthBackend` subclasses? — *Owner: Jesus Lara*: No. `authenticate()`'s contract is to mint a session, so a registered OTP backend would make the second factor sufficient on its own. They are `AbstractOTPProvider` objects owned by `BasicAuth`.
- [x] Are both providers active simultaneously? — *Owner: Jesus Lara*: Yes, but asymmetrically — e-mail is a zero-enrolment floor, TOTP is a voluntary upgrade. Per-user state `none → email → totp`.
- [x] Does enabling enforcement require locking a tenant's users? — *Owner: Jesus Lara*: No. The e-mail floor means every user has a working factor at the first login after activation, so there is no lock-out window and no enrolment grace module.
- [x] Once TOTP is confirmed, is e-mail OTP still a valid login factor? — *Owner: Jesus Lara*: No. A confirmed strong factor closes the e-mail path, so the mailbox stops being the ceiling for that user. Backup codes are the recovery path.
- [x] Does a registered passkey close the e-mail path too? — *Owner: Jesus Lara*: Yes, symmetrically with TOTP.
- [x] Does a passkey sign-in satisfy tenant enforcement, or is an OTP still demanded? — *Owner: Jesus Lara*: It satisfies it, with no OTP — as Google and Microsoft do. WebAuthn with user verification is already possession plus biometric/PIN.
- [x] Does enforcement apply to external-IdP logins (Azure, Okta, Google, SAML)? — *Owner: Jesus Lara*: Not in v1. Those deployments delegate MFA to the IdP, which already works; enforcement is scoped to `BasicAuth`.
- [x] Where does the per-tenant policy live? — *Owner: Jesus Lara*: `auth.tenant_mfa_policy` (it is data, not configuration). `AUTH_BASIC_2FA_ENABLED` is demoted to a global kill switch. Strictest-wins across a user's organizations.
- [x] How is the policy administered in v1? — *Owner: Jesus Lara*: SQL/migration. The admin HTTP API is a follow-up.
- [x] What does the pre-flight do when a tenant has users with no e-mail? — *Owner: Jesus Lara*: Blocks the activation and reports them. Delivered as a script under `scripts/` with a non-zero exit on blockers.
- [x] And a user created *after* activation with no e-mail? — *Owner: Jesus Lara*: Login fails closed. No factor exists, so one factor must not be accepted.
- [x] Scope of administrative disenrolment? — *Owner: Jesus Lara*: OTP only. No password reset, no account edit; the user recovers via the existing self-service flow. Separate permission from user CRUD, audited, and it must revoke the user's trusted devices.
- [x] Is "remember me for N days" in scope, and for whom? — *Owner: Jesus Lara*: In scope, strong-factor users only (`totp` or passkey). An `email`-state user types a code every time, which is also the incentive to upgrade. Window per tenant; `0` disables.
- [x] Are backup codes in v1? — *Owner: Jesus Lara*: Yes.
- [x] SMS? — *Owner: Jesus Lara*: Out of scope — it needs an external provider the environment does not have.
- [ ] **`UserManager` is a generic `ModelView` over `User`, which makes bounded administrative disenrolment weaker than it reads.** It allows editing `email` (in `required_by_put`) and setting a password (`_set_password` / `_calculate_password`), and does not use `OwnerOrSuperuserGuard`. That enables: switch a user's OTP off → they drop to the e-mail floor → change their `email` → trigger password recovery → account taken, without ever "resetting a password". **Decided: a separate follow-up spec**, because it is a pre-existing gap this feature merely exposes, and migrating `UserManager` off `ModelView` has its own blast radius. This feature documents the risk and does not fix it. Reusable machinery for that follow-up: `handlers/guards.py:31` `OwnerOrSuperuserGuard`, `handlers/redaction.py:36` `safe_fields()` allowlist, and FEAT-105's write envelope (which already blocks a superuser from editing another user's columns on `user_identities`). — *Owner: Jesus Lara*
- [ ] **E-mail verification — the weakest premise in the design.** E-mail-as-floor assumes the address is trustworthy, but `User` has no `email_verified` column and there is no verification flow, so a stale or mistyped address delivers the second factor to the wrong mailbox. Two findings sharpen this: (a) the *concept* already exists for IdP logins — `TokenExchangeAuth._verified_email()` enforces the provider's `email_verified` claim (`backends/exchange.py:99-111`) but **persists nothing**, so the signal is available and discarded; (b) `BasicAuth` users, who are precisely this feature's population, never had their address verified by anyone at any point. Options: persist the IdP claim when it exists and treat `BasicAuth`-provisioned addresses as unverified; require verification before a tenant can be enforced; or accept unverified addresses and document it. Likely out of v1, but it should be decided explicitly rather than inherited. — *Owner: Jesus Lara*
- [ ] **Shared-mailbox coupling.** E-mail OTP and `AUTH_RECOVERY_CALLBACK` use the same channel, so a compromised mailbox yields both factors *and* the reset path. Should the spec hard-block `email`-only state for privileged accounts (e.g. `is_superuser`), or only document it? — *Owner: Jesus Lara*
- [ ] Backup-code parameters: how many, what length, shown once or re-displayable, and does regeneration require password re-authentication? — *Owner: unassigned*
- [ ] Which permission gates administrative OTP disenrolment, concretely — a new ABAC action, or an existing group? This is what makes the separation of duties real rather than nominal. — *Owner: unassigned*
- [ ] Should a `mode` change on a tenant revoke that tenant's trusted devices wholesale (the Feature Description assumes yes for `→ enforced`), and should relaxing the mode leave them alone? — *Owner: unassigned*
