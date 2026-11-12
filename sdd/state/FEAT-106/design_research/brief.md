<!--
  sdd/templates/design_research.prompt.md — neutral design-research brief (FEAT-545).
  Rendered by /sdd-spec section 3b and piped to `codex exec ... --output-schema
  design_research.schema.json`.
  FORBIDDEN INPUTS: never paste the spec draft, the spec author's reasoning, a preferred
  conclusion, or any text written by the model that will author the spec. The brief carries
  ONLY the accepted exploration document (brainstorm/proposal) and verified code anchors.
  Placeholders (double-curly-brace tokens, deliberately NOT written with literal braces in
  this comment — a renderer that does a naive whole-document string replace must not also
  rewrite this sentence): problem_statement, constraints_and_goals,
  recommended_option_or_scope, code_context_paths, open_questions, question.
-->
# Independent design review — read-only

You are an independent design reviewer for **ai-parrot**, an async-first Python
framework for AI agents (aiohttp, Pydantic v2).
You have read-only access to the repository in your working directory.

## Rules
1. Read the code you cite. Every `affected_paths` entry must be a repo-relative
   path you actually opened; suggestions with unverifiable paths are discarded.
2. Judge the design intent below against what exists in the repository: what is
   missing, what is risky, what would be simpler, what the codebase already
   provides that the intent re-invents.
3. Do not restate the intent, do not praise it, do not write code. Propose at
   most 12 concrete, falsifiable suggestions, each tagged with a kind
   (`architecture` | `api` | `testing` | `risk` | `alternative`), a risk level and
   your confidence.
4. Output exactly ONE JSON object conforming to the schema you were given — no
   markdown fences, no prose before or after.

## Accepted design intent (verbatim from the exploration document)

### Problem statement
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

### Constraints and goals
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

### Recommended option / probable scope
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

### Recommended option body (Option A)

`AbstractOTPProvider` owned by `BasicAuth`, with a two-tier factor model

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

### Verified code anchors (paths only — open them yourself)
navigator_auth/abac/context.py
navigator_auth/abac/default_policies/admin_full_access.yaml
navigator_auth/abac/default_policies/auth_model_admin_access.yaml
navigator_auth/backends/basic.py
navigator_auth/backends/exchange.py
navigator_auth/backends/passkey.py
navigator_auth/conf.py
navigator_auth/handlers/recovery/limiter.py
navigator_auth/handlers/recovery/store.py
navigator_auth/handlers/recovery/types.py
navigator_auth/handlers/users/user.py
navigator_auth/identities.py
navigator_auth/identity/flow_store.py
navigator_auth/models.py
navigator_auth/vault/sql/001_create_vault_tables.sql

### Questions still open in the exploration document
none

## Question
Given this accepted design intent and these verified code anchors, how would you build it? What is missing, risky, or better done another way?
