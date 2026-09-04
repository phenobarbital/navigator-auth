# Feature Specification: Backend-Based Password Recovery (3-Step Signed Flow)

**Feature ID**: FEAT-098
**Date**: 2026-09-04
**Author**: Jesus Lara
**Status**: draft
**Target version**: 0.27.0

> **Inputs:** `sdd/proposals/backend-based-password-recovery.proposal.md`
> (decisions D1–D17 resolved 2026-09-04).
> **Hard prerequisite (NOT yet landed):** **FEAT-096 (`external-token-exchange`)**
> must be merged into `dev` first — its TASK-046 factors
> `BasicAuth.open_session()` out of `authenticate()`, and M5 of this spec writes
> the `jti` record inside that new method. See Worktree Strategy.
> **Ordering note:** FEAT-097 (`saml-backend-abstract`) also lands after FEAT-096
> and also edits `conf.py`; this spec front-loads its `conf.py` keys in M1 to
> keep the contention to one hunk.

---

## 1. Motivation & Business Requirements

### Problem Statement

navigator-auth has no working self-service password recovery. The module that
exists, `navigator_auth/handlers/recovery.py`, is a two-step draft that **cannot
complete a reset**:

- `RecoveryTokenStorage.save_token` (`recovery.py:29`) calls `json_decoder(data)`
  to *encode* a dict on the way into Redis, and `get_token` calls the same
  decoder on the way out — the write path is wrong.
- `ResetPasswordHandler.post` (`recovery.py:131`) hashes through
  `self.request.app['auth']._idp.set_password(...)`, a method that does not
  exist on the IdP. The real hasher is `set_basic_password()` in
  `handlers/users/passwd.py:12`.
- Both handlers build a fresh `redis.from_url()` per request and never close it.
- Both extend `web.View` directly, so they have none of the `BaseHandler`
  response helpers (`json_response`, `error`, `critical`) used everywhere else.
- A **single** token authorizes the password write: whoever holds the e-mailed
  token can set a password. There is no separation between *"you proved you
  opened the mailbox"* and *"you are authorized to write a password"*.

The other reset paths need a session the locked-out user cannot have:
`POST /api/v2/user/set_password` (`handlers/users/session.py:119`) requires the
current password, and `POST /api/v2/user/password_reset/{userid}`
(`session.py:170`) requires a superuser session. Today a user who forgets their
password must ask an administrator.

**Who is affected:** end users locked out of Basic-auth accounts; operators
currently doing manual resets; any front-end that needs a recovery screen.

### Goals

- A **three-step** flow on `navigator.views.BaseHandler`, splitting proof of
  mailbox control from authorization to write a password (D3, D4).
- **navigator-auth never sends e-mail.** Step 1 produces a mail-ready payload
  and hands it to a configured callback; the HTTP response never carries the
  token (D1).
- Step 1 is **POST with a JSON body** — it has side effects and the address must
  not land in access logs, proxy logs or browser history (D2).
- **No account enumeration**: identical body, status and approximately identical
  latency for known and unknown addresses (D9).
- Tokens are **HMAC-signed** and stored under `sha256(token)`, so a Redis dump
  yields nothing usable (D12).
- Step 2 does **not** consume the recovery token; it rotates a short-lived
  confirmation token so refreshes and mail-scanner prefetches do not burn the
  reset (D4, D5).
- Step 3 validates the pair, enforces a **password policy** (D13), writes the
  hash, deletes **both** Redis records, and **revokes the user's sessions and
  outstanding JWTs** (D8).
- **Rate limiting** on step 1, per e-mail and per IP (D6, D14).
- Every active user may recover, including federated-only accounts (D10).

### Non-Goals (explicitly out of scope)

- Sending e-mail, or any SMTP/template concern. The callback owns delivery.
- Changing the login flow, `password_change`/`password_reset` under
  `/api/v2/user/*`, the PBKDF2 hashing scheme, or any provider backend.
- Recovery by SMS, security questions, or any second factor.
- Auto-login after reset (rejected in D15).
- Admin-facing bulk reset or a recovery audit UI.
- A generic app-wide rate-limit middleware — the limiter here is scoped to this
  feature's endpoints.

---

## 2. Architectural Design

### Overview

A rewritten `navigator_auth/handlers/recovery.py` exposes three routes on a
single `PasswordRecoveryHandler(BaseView)`. State lives in Redis across two
linked records with different lifetimes, in a new
`RecoveryTokenStore` modelled directly on `identity/flow_store.py` (pooled
connection, `setex`, `GETDEL` for single-use consumption).

Two independent, reusable modules fall out: a `PasswordPolicy` validator and a
`RateLimiter`. Neither imports the handler; both are unit-testable in isolation.

The revocation half extends `BasicAuth` so that a reset actually kills live
credentials. **The auth middleware needs no change**:
`AuthHandler._token_is_revoked` (`auth.py:985`) already walks every backend
looking for an `access_token_storage` and checks any token carrying a `jti`.
Emitting a `jti` from `create_token` and giving `BasicAuth` that attribute is
sufficient.

### Component Diagram

```
STEP 1   POST /api/v1/password-recovery        {email}
            │
            ├─► RateLimiter.check(email, ip) ──── over limit ─► 429 (generic body)
            ├─► find_user_by_email(email)  ───── miss ─► pad latency ─► 200 generic
            ├─► RecoveryTokenStore.issue_recovery(user)
            │        token = hmac(user_id, username, issued_at, nonce)  [AUTH_RECOVERY_SECRET]
            │        redis SETEX  recovery:{sha256(token)}  ttl=3600
            └─► notify_callback({email, display_name, token, url, expires_at})
                     └─ failure is logged, never changes the response
            ▼
         200 {"message": "<generic>"}                      ← never contains the token

STEP 2   GET  /api/v1/password-recovery/{token}
            │
            ├─► RecoveryTokenStore.validate_recovery(token)   (GET, not GETDEL — D4)
            │        └─ miss/expired/bad-signature ─► 400
            └─► RecoveryTokenStore.issue_confirmation(recovery_token)
                     ├─ deletes any previously issued confirmation (rotation)
                     └─ redis SETEX  confirm:{sha256(ctoken)}  ttl=900
            ▼
         200 {"token": "<confirmation>", "expires_in": 900, "username": "..."}

STEP 3   POST /api/v1/password-recovery/confirm  {password, confirm_password, token}
            │
            ├─► password == confirm_password           ─ mismatch ─► 400
            ├─► RecoveryTokenStore.consume_confirmation(token)   (GETDEL)
            ├─► PasswordPolicy.validate(password, user)  ─ fail ─► 422 {rule, message}
            ├─► user.password = set_basic_password(password);  is_new = False;  update()
            ├─► RecoveryTokenStore.drop_pair(recovery_key, confirm_key)
            └─► SessionRevoker.revoke_user(user)
                     ├─ redis DEL session:{sid}, user:{username}   (navigator_session index)
                     └─ BasicAuth.access_token_storage.revoke(jti) for live jtis
            ▼
         202 {"action": "Password was changed successfully", "status": "OK"}
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `BaseView` (`navigator.views`) | extends | `PasswordRecoveryHandler(BaseView)` — gives `json_response`, `error`, `critical`, `json_data`, `match_parameters`, plus the CORS mixin. Same base as `UserSession`. |
| `handlers/recovery.py` | **rewrite** | `ForgotPasswordHandler`/`ResetPasswordHandler`/`RecoveryTokenStorage` are removed; the module is replaced wholesale (D3). |
| `handlers/__init__.py` | modify | Register the three new routes; repoint `/api/v1/forgot-password` → step 1 and `/api/v1/reset-password` → step 3 as compatibility aliases. |
| `IdentityFlowStore` (`identity/flow_store.py`) | pattern source | `RecoveryTokenStore` copies its shape: `ConnectionPool` held once, `setex`/`get`/`getdel` helpers. Not subclassed — different key namespace and a signing concern. |
| `set_basic_password` (`handlers/users/passwd.py:12`) | uses | The only password writer. Unchanged. |
| `User` model (`models.py:39`) | uses + **fix** | Lookup by `email` (and `alt_email`); writes `password`, `is_new`. **`idp.get_user()` searches by `username_attribute` only** and cannot be reused for e-mail lookup — this feature adds one. Separately, `password` is declared `max=16` against a 77-char hash — corrected to `max=255` in M1 (see Gotchas). |
| `parse_rate_limit` (`backends/oauth2/dcr.py:104`) | reuses | `"<count>/<window>"` parser, already handles a malformed value by disabling the limit rather than failing closed. |
| `IdentityProvider.create_token` (`backends/idp/__init__.py:378`) | modify | Emit a `jti` claim (`secrets.token_urlsafe`). Additive; `aud` precedent at the same site shows the pattern. |
| `BasicAuth.open_session()` (`backends/basic.py`, **from FEAT-096**) | modify | Record the minted `jti` in `access_token_storage`. Writing it here rather than in `authenticate()` means token-exchange sessions inherit revocability for free. |
| `AccessTokenStorage` (`backends/oauth2/code_backend.py:316`) | reuses | Already exactly the needed `save`/`revoke(jti)`/`is_revoked(jti)` Redis store. Attach an instance to `BasicAuth` as `access_token_storage`. |
| `AuthHandler._token_is_revoked` (`auth.py:985`) | **unchanged** | Already backend-agnostic: iterates backends for `access_token_storage`, short-circuits when a token has no `jti`. Pre-upgrade tokens keep working. |
| `navigator_session` Redis storage | uses | Session revocation deletes `session:{session_id}` **and** the `user:{identity}` index key that `new_session` writes (`storages/redis.py:275`). For Basic auth `identity` is the **username** (`backends/basic.py:159`). |
| `conf.py` | extends | New `AUTH_RECOVERY_*` keys (below). Front-loaded in M1 to minimise conflict with FEAT-097. |

### Data Models

```python
# navigator_auth/handlers/recovery/types.py

@dataclass(frozen=True)
class RecoveryPayload:
    """Redis-persisted body of a stage-1 recovery record."""
    user_id: int
    username: str
    email: str
    issued_at: float          # epoch seconds
    nonce: str                # 16 bytes urlsafe, makes each token unique
    signature: str            # HMAC-SHA256 over the four fields above

@dataclass(frozen=True)
class ConfirmationPayload:
    """Redis-persisted body of a stage-2 confirmation record."""
    user_id: int
    username: str
    recovery_key: str         # sha256 of the stage-1 token; links the pair
    issued_at: float
    signature: str

@dataclass(frozen=True)
class NotificationPayload:
    """Hand-off to AUTH_RECOVERY_CALLBACK. The only place a raw token appears."""
    email: str
    display_name: str
    username: str
    token: str                # raw stage-1 token — never in an HTTP response
    url: str                  # AUTH_RECOVERY_URL_TEMPLATE.format(token=token)
    expires_at: datetime
    found: bool               # False => no such account; callback decides what to send

@dataclass(frozen=True)
class PolicyViolation:
    rule: str                 # "min_length" | "needs_letter" | "needs_digit" | "same_as_current"
    message: str
```

### New Public Interfaces

```python
# navigator_auth/handlers/recovery/store.py

class RecoveryTokenStore:
    """Two-stage, HMAC-signed, TTL'd token store.

    Redis is keyed by ``sha256(token)`` and never by the token itself, so a
    dump of the database yields no usable credential (D12).
    """
    def __init__(self, pool: aioredis.ConnectionPool, secret: bytes): ...

    async def issue_recovery(self, user) -> tuple[str, RecoveryPayload]:
        """Mint the stage-1 token; SETEX for AUTH_RECOVERY_TTL."""

    async def validate_recovery(self, token: str) -> Optional[RecoveryPayload]:
        """Read + verify signature. Does NOT consume the record (D4)."""

    async def issue_confirmation(self, token: str) -> tuple[str, ConfirmationPayload]:
        """Mint stage-2 and invalidate any previous stage-2 for this recovery
        (rotation, D4). Stage-1 is left intact."""

    async def consume_confirmation(self, token: str) -> Optional[ConfirmationPayload]:
        """GETDEL — single use."""

    async def drop_pair(self, recovery_key: str, confirm_key: str) -> None:
        """Delete both records so the link cannot be replayed (step 3)."""


# navigator_auth/handlers/recovery/policy.py

class PasswordPolicy:
    """Pure validator. No I/O, no Redis, no HTTP — trivially unit-testable."""
    def __init__(self, min_length: int = 8, require_letter: bool = True,
                 require_digit: bool = True, reject_current: bool = True): ...

    def validate(self, password: str, current_hash: str = None) -> list[PolicyViolation]:
        """Empty list == valid. Returns EVERY violation, not just the first,
        so a front-end can show the full checklist at once."""


# navigator_auth/handlers/recovery/limiter.py

class RateLimiter:
    """Fixed-window Redis counter (INCR + EXPIRE on first hit)."""
    def __init__(self, pool: aioredis.ConnectionPool, spec: str, prefix: str): ...

    async def check(self, key: str) -> bool:
        """True when the call is allowed. A Redis failure returns True
        (fail-open): an unreachable cache must not lock every user out of
        recovery. Failures are logged at WARNING."""


# navigator_auth/handlers/recovery/revoke.py

class SessionRevoker:
    async def revoke_user(self, request, user) -> int:
        """Kill live sessions + JWTs for this user. Returns the count killed.
        Best-effort per record; one failure does not abort the rest."""
```

### Configuration keys (all new, all in `conf.py`)

| Key | Default | Purpose |
|---|---|---|
| `AUTH_RECOVERY_SECRET` | falls back to `SECRET_KEY` | HMAC key for both stages (D12) |
| `AUTH_RECOVERY_TTL` | `3600` | stage-1 lifetime, seconds |
| `AUTH_RECOVERY_CONFIRM_TTL` | `900` | stage-2 lifetime, seconds (D5) |
| `AUTH_RECOVERY_CALLBACK` | `None` | dotted path to the notification callable (D1) |
| `AUTH_RECOVERY_URL_TEMPLATE` | `None` | e.g. `https://app/reset?token={token}` (D16) |
| `AUTH_RECOVERY_RATE_EMAIL` | `"3/hour"` | per-address limit (D14) |
| `AUTH_RECOVERY_RATE_IP` | `"10/hour"` | per-IP limit (D14) |
| `AUTH_RECOVERY_PWD_MIN_LENGTH` | `8` | policy (D13) |
| `AUTH_RECOVERY_PWD_REQUIRE_LETTER` | `True` | policy (D13) |
| `AUTH_RECOVERY_PWD_REQUIRE_DIGIT` | `True` | policy (D13) |
| `FORGOT_PASSWORD_CALLBACK` | — | **deprecated**; honoured for one release with a warning |

---

## 3. Module Breakdown

### Module 1: Config keys + package skeleton
- **Path**: `navigator_auth/conf.py`, `navigator_auth/models.py`, `navigator_auth/handlers/recovery/__init__.py`
- **Responsibility**: All eleven `AUTH_RECOVERY_*` keys with defaults, the
  `FORGOT_PASSWORD_CALLBACK` deprecation shim, and the package skeleton
  (`types.py` dataclasses). Front-loaded so later modules never touch `conf.py`.
  **Also corrects `User.password` from `max=16` to `max=255`** in
  `navigator_auth/models.py:51` — see Gotchas. One line, no migration, no
  behaviour change today.
- **Depends on**: nothing. **Must land first** — every other module imports it.

### Module 2: `PasswordPolicy`
- **Path**: `navigator_auth/handlers/recovery/policy.py`
- **Responsibility**: The pure validator and `PolicyViolation`. Reads its
  defaults from M1.
- **Depends on**: M1. **Fully parallel** with M3/M4/M5 — no I/O, no shared file.

### Module 3: `RecoveryTokenStore`
- **Path**: `navigator_auth/handlers/recovery/store.py`
- **Responsibility**: HMAC signing, `sha256` key derivation, the two-stage
  lifecycle (issue / validate / rotate / consume / drop-pair), pooled Redis.
- **Depends on**: M1. **Fully parallel** with M2/M4/M5.

### Module 4: `RateLimiter`
- **Path**: `navigator_auth/handlers/recovery/limiter.py`
- **Responsibility**: Fixed-window counter reusing `parse_rate_limit`; fail-open
  on Redis error.
- **Depends on**: M1. **Fully parallel** with M2/M3/M5.

### Module 5: `jti` emission + `SessionRevoker`
- **Path**: `navigator_auth/backends/idp/__init__.py`,
  `navigator_auth/backends/basic.py`, `navigator_auth/handlers/recovery/revoke.py`
- **Responsibility**: `create_token` emits `jti`; `BasicAuth` gains
  `access_token_storage` and records the `jti` **inside `open_session()`**;
  `SessionRevoker` deletes `session:{sid}` + `user:{identity}` and revokes live
  jtis.
- **Depends on**: M1, **and FEAT-096 TASK-046 being merged**. This is the one
  blocked module. Parallel with M2/M3/M4 once unblocked.

### Module 6: `PasswordRecoveryHandler` + routes
- **Path**: `navigator_auth/handlers/recovery/handler.py`,
  `navigator_auth/handlers/__init__.py`
- **Responsibility**: The three endpoints, e-mail lookup, the uniform-response
  and latency-padding behaviour, callback invocation, and wiring. Deletes the
  old `recovery.py` contents.
- **Depends on**: M1–M5. Integration point; lands last.

### Module 7: Tests + docs + version bump
- **Path**: `tests/test_password_recovery.py`, `docs/`, `navigator_auth/version.py`
- **Responsibility**: End-to-end tests, the enumeration/timing test, docs for
  the callback contract, bump to `0.27.0`.
- **Depends on**: M6.

---

## 4. Test Specification

### Unit Tests

| Test | Module | Description |
|---|---|---|
| `test_policy_accepts_valid` | M2 | `"abc12345"` passes the default policy |
| `test_policy_min_length` | M2 | 7 chars → `min_length` violation |
| `test_policy_requires_letter_and_digit` | M2 | `"12345678"` → `needs_letter`; `"abcdefgh"` → `needs_digit` |
| `test_policy_rejects_current_password` | M2 | New password matching `current_hash` → `same_as_current` |
| `test_policy_returns_all_violations` | M2 | `"abc"` returns both `min_length` and `needs_digit`, not just the first |
| `test_store_key_is_hashed` | M3 | The Redis key equals `sha256(token)`; the raw token appears **nowhere** in Redis (scan every key and value) |
| `test_store_signature_roundtrip` | M3 | A valid token verifies; a payload tampered in Redis fails signature check |
| `test_store_wrong_secret_rejected` | M3 | A token minted under secret A fails under secret B (rotation invalidates in-flight) |
| `test_store_recovery_survives_validate` | M3 | **D4** — `validate_recovery` twice both succeed; the record still exists |
| `test_store_confirmation_rotates` | M3 | Second `issue_confirmation` invalidates the first token; only the newest works |
| `test_store_confirmation_single_use` | M3 | `consume_confirmation` twice: second returns `None` |
| `test_store_ttls` | M3 | Redis TTL ≈ 3600 for stage-1, ≈ 900 for stage-2 |
| `test_store_expired_returns_none` | M3 | An expired key validates as `None` |
| `test_limiter_allows_under_limit` | M4 | 3 calls under `"3/hour"` all allowed |
| `test_limiter_blocks_over_limit` | M4 | 4th call blocked; window expiry re-allows |
| `test_limiter_fails_open` | M4 | Redis raising → `check()` returns `True` and logs a warning |
| `test_limiter_malformed_spec_disables` | M4 | `"garbage"` → limiting off, never blocks |
| `test_user_password_column_fits_hash` | M1 | A `set_basic_password()` output (77 chars) fits `User.password`; the declared `max` is >= `len(hash)` for the configured digest/dklen |
| `test_create_token_emits_jti` | M5 | `create_token` payload carries a unique `jti` |
| `test_jti_absent_token_still_valid` | M5 | A token minted without `jti` passes `_token_is_revoked` (backward compat) |
| `test_revoker_kills_session_and_index` | M5 | Both `session:{sid}` and `user:{username}` are gone |
| `test_revoker_partial_failure` | M5 | One failing delete does not abort the others |

### Integration Tests

| Test | Description |
|---|---|
| `test_full_recovery_flow` | Steps 1→2→3 end to end; the user then logs in with the new password |
| `test_step1_never_returns_token` | Response body and headers of step 1 contain no token, for a **known** address |
| `test_step1_unknown_email_identical` | Known vs unknown address: identical status, identical body, latency within tolerance (**D9**) |
| `test_step1_invokes_callback_with_url` | Callback receives `NotificationPayload` with `url` built from the template; `found=False` for an unknown address |
| `test_callback_failure_does_not_leak` | A raising callback still yields the generic 200 |
| `test_step2_refresh_is_safe` | **D4** — step 2 called three times; the newest confirmation works, the earlier two do not; step 1 token still live |
| `test_step3_replay_rejected` | Replaying step 3 with the same confirmation token → 400; the password is not changed twice |
| `test_step3_recovery_token_dead_after_success` | The step-1 token no longer validates at step 2 after a completed reset |
| `test_step3_password_mismatch` | `password != confirm_password` → 400, nothing written |
| `test_step3_policy_violation` | Weak password → 422 with the violated rules, tokens **not** consumed so the user can retry |
| `test_step3_revokes_sessions` | A session and JWT issued before the reset are rejected afterwards |
| `test_step3_sets_is_new_false` | **D17** — `is_new` is `False` after a self-service reset |
| `test_no_autologin` | **D15** — step 3 returns no `token`/`refresh_token` |
| `test_federated_user_can_recover` | **D10** — a user with no local password completes the flow |
| `test_rate_limit_per_email` | 4th request for the same address within the hour → 429, generic body |
| `test_legacy_routes_aliased` | `/api/v1/forgot-password` and `/api/v1/reset-password` reach the new handler |
| `test_basic_login_unchanged` | Existing `tests/test_basic_auth.py` and `tests/test_login.py` pass unmodified |

### Test Data / Fixtures

```python
@pytest.fixture
async def recovery_store(redis_pool):
    return RecoveryTokenStore(redis_pool, secret=b"test-secret-key")

@pytest.fixture
def captured_callback():
    """Collects NotificationPayloads instead of sending mail."""
    sent = []
    async def _cb(payload): sent.append(payload)
    return sent, _cb

@pytest.fixture
async def recoverable_user(authdb):
    """Active user, known password, e-mail set — the flow's happy path."""
```

---

## 5. Acceptance Criteria

- [ ] All unit tests pass (`pytest tests/test_password_recovery.py -v`)
- [ ] All integration tests pass (`pytest tests/ -v`)
- [ ] `tests/test_basic_auth.py` and `tests/test_login.py` pass **unmodified** —
      the `jti` change must not alter Basic login behaviour
- [ ] The raw recovery token appears in exactly two places: the callback payload
      and the step-2 request URL. **Never** in a response body, never in Redis
- [ ] Known and unknown e-mail addresses are indistinguishable by status, body
      or latency
- [ ] A completed reset invalidates: both Redis records, the user's sessions,
      and JWTs issued before the reset
- [ ] A JWT minted before the upgrade (no `jti`) still authenticates
- [ ] `User.password` is declared `max=255`, and a real 77-char PBKDF2 hash
      round-trips through the model and the database
- [ ] Documentation covers the callback contract and every `AUTH_RECOVERY_*` key
- [ ] No breaking changes to the public API; legacy routes still resolve
- [ ] Version bumped to `0.27.0`

---

## 6. Implementation Notes & Constraints

### Patterns to Follow

- `BaseView` for the handler; use `self.json_response` / `self.error` /
  `self.critical` rather than raising `web.HTTP*` directly, matching
  `UserSession`.
- One `aioredis.ConnectionPool` created at startup and shared, as
  `ExternalAuth` does (`backends/external.py:165`) — **never** `redis.from_url()`
  per request, the mistake in the current `recovery.py`.
- `json_encoder` to write and `json_decoder` to read (`libs/json.py`) — the
  current module has these backwards.
- Constant-time comparison (`secrets.compare_digest`) for every signature check.
- Async-first, type hints throughout, `self.logger` for logging.

### Known Risks / Gotchas

- **Timing side channel (D9).** A real user lookup hits Postgres; a miss may
  not. Without care, latency alone reveals whether an account exists. Mitigation:
  measure elapsed time and pad to a fixed floor (~250 ms) before responding, on
  **both** paths. The test asserts the delta is within tolerance.
- **Log leakage.** The token must never reach a log line. Keep it out of
  `NotificationPayload.__repr__`, and never log the step-2 path with its `{token}`
  segment at INFO. Verify with a caplog assertion.
- **Rate-limit fail-open is deliberate.** A Redis outage must not lock every
  user out of recovery. The trade-off is that an outage also lifts the throttle;
  logged at WARNING so it is visible.
- **`is_new` semantics are inverted between paths.** Superuser `password_reset`
  sets `is_new = True` (admin picked it, user must replace it); this flow sets
  `False` (D17). Do not "fix" one to match the other.
- **`idp.get_user()` cannot do e-mail lookup** — it searches
  `username_attribute` only (`idp/__init__.py:145`). A dedicated query is
  required, and should consider `alt_email` as well as `email`.
- **Duplicate e-mails.** `User.email` has no unique constraint. If the lookup
  returns more than one row, refuse to guess: log a warning and take the generic
  path as if not found.
- **`jti` blast radius.** Every Basic login gains a Redis write and every
  authenticated request with a `jti` gains a lookup. This affects all Basic
  traffic. `_token_is_revoked` short-circuits on a missing `jti`, so old tokens
  cost nothing and keep working.
- **FEAT-096 conflict.** M5 edits the exact lines TASK-046 is refactoring.
  Writing the `jti` in `authenticate()` instead of `open_session()` would be
  redone and would miss token-exchange sessions. Wait for the merge.
- **`User.password` is declared `max=16` against a 77-character hash.**
  Measured at current defaults, `set_basic_password()` produces
  `pbkdf2_sha256$80000$<12-hex-salt>$<44-char-b64>` = **77 chars**
  (13 + 1 + 5 + 1 + 12 + 1 + 44). The declaration in `models.py:51` says 16.

  Verified: **`max=` is not enforced today** — a 77-char value constructs and
  `is_valid()` returns `True` — and the reference DDL already declares
  `password VARCHAR(255)` (`examples/sql/identity_vault_schema.sql:37`), so the
  *database* is correct and no migration is needed. This is a latent
  declaration bug: the day `max=` starts being enforced, **every password write
  in the project breaks** — Basic login's `password_change`, the superuser
  `password_reset`, and this feature's step 3 alike.

  Fix in M1: `max=16` → **`max=255`**, matching the column and the convention
  of its siblings (`email`/`username` pair `max=254` with `VARCHAR(254)`).
  255 leaves generous headroom for configuration: even sha512 with
  `AUTH_PWD_LENGTH=64` (88-char hash), a 32-char salt and 7-digit iterations
  reaches only ~123.

  Note this is **not** scoped to recovery — it is a project-wide latent bug that
  this feature happens to surface. It can be landed independently at any time;
  it is placed in M1 only so it does not get lost.

### External Dependencies

| Package | Version | Reason |
|---|---|---|
| — | — | **None new.** `redis.asyncio`, `navconfig`, `navigator.views`, `hmac`/`hashlib`/`secrets` (stdlib) are all already in use. |

---

## 7. Open Questions

None. D1–D17 in the proposal resolve every question raised at proposal time
(2026-09-04).

---

## Worktree Strategy

- **Isolation unit:** `mixed`.
  - **Sequential:** M1 lands first (every module imports its config keys), then
    M6 → M7 last (integration).
  - **Parallelizable:** **M2, M3, M4 and M5 can run in four separate worktrees**
    branched after M1. M2/M3/M4 each own one new file under
    `handlers/recovery/` and share nothing. M5 is the only one touching existing
    files (`backends/idp/__init__.py`, `backends/basic.py`), which M2/M3/M4
    never open.
- **Rationale:** front-loading `conf.py` into M1 means no later module edits a
  shared file, which is what makes the four-way fan-out safe. The regression
  gate at each boundary is `tests/test_basic_auth.py` + `tests/test_login.py`,
  since M5 touches the token minting path used by every login.
- **Cross-feature dependencies:**
  - **FEAT-096 (`external-token-exchange`) must be merged into `dev` first**
    (D11, decided 2026-09-04). It is *in progress* as of 2026-09-04 on
    `feat-FEAT-096-external-token-exchange` (TASK-046…053), with no code landed
    yet. **Only M5 is blocked by it** — M1–M4 are ~60 % of the feature and can
    proceed immediately. Do not run `/sdd-task` for M5 until TASK-046 is merged,
    or the task file will reference a `basic.py` shape that no longer exists.
  - **FEAT-097 (`saml-backend-abstract`)** also lands after FEAT-096 and also
    adds `conf.py` keys. No logical dependency in either direction; the only
    contention is that one file, which M1 front-loads into a single hunk.

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-09-04 | Jesus Lara | Initial draft from `backend-based-password-recovery.proposal.md` (D1–D17 resolved). Three-step signed flow on `BaseHandler`; replaces the non-functional `handlers/recovery.py`. FEAT-096 is a hard prerequisite for M5 only. |
| 0.2 | 2026-09-04 | Jesus Lara | M1 also corrects `User.password` `max=16` → `max=255` (measured hash is 77 chars; `max=` currently unenforced, DDL already `VARCHAR(255)`). Project-wide latent bug, landable independently. |
