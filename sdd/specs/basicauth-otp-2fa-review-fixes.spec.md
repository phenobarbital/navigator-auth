---
# SDD flow type and base branch (FEAT-145).
type: feature
base_branch: feat-FEAT-106-basicauth-otp-2fa
# Intentional multi-spec split of one initiative: these fixes ship in the same
# branch and PR (#633) as FEAT-106, so no new FEAT-ID is reserved.
reuse_feature_id: FEAT-106
projects: [auth-backends, mfa, handlers, vault]
tags: [2fa, security, oauth2, vault-rotation, concurrency, review-fixes]
docs:
  policy: required
  pages: []
  api_modules: [navigator_auth.mfa]
---

# Feature Specification: FEAT-106 review fixes — OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions

**Feature ID**: FEAT-106 (reused — see frontmatter `reuse_feature_id`)
**Date**: 2026-11-11
**Author**: Jesus Lara
**Status**: approved
**Target version**: 0.30.0

---

## 1. Motivation & Business Requirements

### Problem Statement

PR #633 (FEAT-106, 2FA for BasicAuth) was reviewed twice before merge:
- a Claude code-review subagent;
- an independent `codex` pass that verified that review's findings and added its own.

Both transcripts are committed under `sdd/state/FEAT-106/pr633-review/`. Both reviewers recommend **not merging** until a set of high-severity defects is fixed. This spec covers every finding that `codex` rated **high**, except the one FEAT-106 already excludes as non-goal R1 (#11, `UserManager`).

| Review # | Defect | Severity | Module | ACs |
|---|---|---|---|---|
| #1 | `Oauth2Provider.auth_login` checks only the password and opens a session. An enforced tenant's 2FA is bypassed whenever the OAuth2 provider is enabled. | high | M5, M6 | AC1–AC6 |
| #2 | TOTP seeds are sealed into `auth.user_vault_secrets` under context `mfa/(user_id, provider, key)`. That table's rotation target `UserVaultTarget` opens rows as `user-vault/(user_id, key)`, so `rotate_master_key` cannot re-seal them. Once the old key is retired, TOTP returns 503. | high | M7 | AC7–AC9 |
| #3 | Code inside `user_lock` acquires more connections from the same pool, while password handlers acquire in the opposite order. At about `max_size` concurrent requests the pool deadlocks. | high | M2, M3, M4, M5 | AC10, AC11 |
| #4 | MFA availability is decided once at startup and never retried. A transient failure refuses every login for the life of the process. Meanwhile `security_transition` yields `None`, so credential changes skip the version bump, device revocation and audit. | high | M1, M3 | AC12, AC13 |
| #5 | The credential write commits on a different connection than the MFA transition. A failure after the write leaves the new password without bump, revocation or audit, and recovery skips session revocation. | high | M3, M4 | AC14, AC15 |
| A2 | Same as #5 for passkeys: `save_credential`/`delete_credential` commit on their own connection inside `security_transition`. | high | M2, M4 | AC16 |
| A1 | Trusted-device login (and the no-factor-owed path) is not serialized with security transitions. A password change landing between the password check and session issuance still lets the old password open a session. | high | M5 | AC17, AC18 |
| #7 | Backup-code regeneration needs only a session plus the password. A stolen session plus the password mints a standing second factor. | high | M8 | AC19 |
| #12 | `disenroll_totp` evaluates its strong-factor guard outside the user lock and races a passkey delete. Pre-lock storage errors return 500. | high | M8 | AC20 |

### Goals
- **G1** — No password login path issues a session for a user who owes a second factor. Both BasicAuth and the OAuth2 login form go through one shared second-factor gate (M5).
- **G2** — MFA seeds survive master-key rotation and v1→v2 migration through their own registered vault target.
- **G3** — Inside a `user_lock` scope, code never acquires a second connection from the pool. The one documented exception, the D16 backup-code consume, runs *before* the lock.
- **G4** — A credential change and its MFA bookkeeping (bump, device revocation, audit) commit or roll back together in one transaction, on one connection.
- **G5** — When 2FA is enabled and MFA is unavailable, credential changes fail closed (503). MFA availability self-heals without a restart.
- **G6** — Session issuance after a password check is serialized with security transitions for the same user.
- **G7** — Minting a new second factor (backup codes) needs fresh proof of an existing strong factor.
- **G8** — An OAuth2 access token minted after an MFA'd OAuth2 login carries `mfa`/`amr`. ABAC evaluates assurance from the validated presented token, isolated from other tokens and browser sessions (§8 Q2).
- **G9** — An admin `password_reset` ends the target user's existing sessions and tokens, as recovery does (§8 Q3).

### Non-Goals (explicitly out of scope)
- Medium- and low-severity review findings: #6 proxy-aware IP limiter, #8 email-issuance flooding, #9 rate-spec parse fail-open, #10 device rotation before cookie delivery, #13 `attempts_remaining`, #14 redundant queries, #15 sync callbacks, A3 limiter on factor-management endpoints, A4 policy-hardening race, and L1–L6. They go to a follow-up spec.
- **#11 — `UserManager` admin password writes.** This remains FEAT-106 non-goal R1 (Q17 → separate follow-up spec).
- OAuth2 `acr`/`acr_values` step-up (FEAT-106 brainstorm Option C), and an `amr` claim in OIDC ID tokens. `amr` propagation into access tokens, introspection and userinfo **is** in scope (M9).
- Persisting token assurance in a shared session is out of scope; the request-local validated token context is authoritative even when middleware recreates a session.
- Revoking other sessions on a self-service `password_change`. Only `password_reset` (G9) and recovery revoke.
- Moving MFA services ownership out of BasicAuth. The OAuth2 login form uses the slot BasicAuth builds (D4).

---

## Governing Decisions

decision audit not configured in this repository

---

## 2. Architectural Design

### Overview

**Shared second-factor gate (M5).** The decision logic in `BasicAuth._second_factor` and the verification core in `MfaHandler._verify_locked` move into one backend-agnostic `SecondFactorGate` in `navigator_auth/mfa/login.py`. The gate never builds a session itself. Each caller passes a `SessionIssuer` callback that the gate invokes **inside the user lock**:
- BasicAuth: `open_session`;
- OAuth2 login form: `_create_user_session` on the redirect response;
- `/auth/mfa/verify`: `services.backend.open_session`.

Holding the lock from decision through issuance gives G6. Under the lock, the gate also re-reads the user on the lock connection. If the password hash differs from the one the caller validated, the login is refused (`credentials_changed`, 401). This closes A1 even for writers that bypass `security_transition`.

**OAuth2 login form (M6).** A POST to `/oauth2/login` with 2FA enabled calls `SecondFactorGate.decide()`:
- **No factor owed, or a valid trusted device:** a session is created and the browser is redirected to `/oauth2/authorize` as today. A trusted device also gets the `nav_mfa_device` cookie and `amr` `["pwd","trusted_device"]`.
- **Factor owed:** the new template `oauth/mfa.html` is rendered (200, `Cache-Control: no-store`), carrying the signed challenge, the providers, and every authorize parameter as hidden fields. No session cookie is set.

The new route `POST /oauth2/login/mfa` (`nav_oauth2_login_mfa`) runs `SecondFactorGate.verify()`. Success creates the session (`mfa=True`, `amr` per provider) and redirects to `/oauth2/authorize`, preserving PKCE, `state`, `nonce`, `scope` and `prompt`. Failure re-renders the page with the error and `attempts_remaining`. An invalid or stale challenge sends the user back to the login page. With 2FA disabled, `auth_login` is unchanged.

**MFA secrets table (M7).** TOTP seeds move from `auth.user_vault_secrets` to a new `{schema}.user_mfa_secrets` table whose identity columns are `(user_id, provider, key)`. Those are exactly the AAD fields of `mfa_seed_context`, so `PostgresTarget.context_for` rebuilds the right context, and moved ciphertext stays valid without re-sealing. A new `MfaSecretTarget` is registered under the `navigator_session.vault_targets` entry point. Migration `002_mfa_secrets.sql` moves existing `mfa:%` rows and hard-deletes them from the vault table. Hard delete is required because `UserVaultTarget` scans every row, soft-deleted ones included.

**Connection discipline (M2).** `user_lock` publishes its connection in a `ContextVar`. Every store call made inside a lock scope takes `conn=`:
- `IdentityProvider.user_from_id`;
- `TOTPProvider.verify` / `_load_seed`;
- `TrustedDeviceStore.consume_and_rotate`;
- `PasskeyStore.save_credential` / `delete_credential`.

`BackupCodeStore.consume` keeps its own connection (D16), so the gate consumes backup codes **before** taking the lock. `user_lock` bounds both the pool acquire and the advisory-lock wait with `AUTH_MFA_LOCK_TIMEOUT`.

**Transactional `security_transition` (M3).** It always yields **one live connection inside one transaction**:
- MFA not configured: a pooled transaction with the same per-user advisory lock, without MFA bookkeeping;
- MFA available: the user-lock connection, followed by bump, revoke, audit and commit on that same connection;
- MFA configured but unavailable after the M1 retry: it raises `MfaUnavailable` before yielding.

A body that raises `TransitionAborted` rolls back without being logged as an error.

**Call sites (M4).** `password_change`, `password_reset`, recovery completion and passkey register/remove become two-phase:
1. Read and validate on a pooled connection, then release it.
2. Enter the transition, re-read the user on its connection, compare the hash captured in phase 1 (`TransitionAborted` → 409 on drift), and write the credential on the transition connection.

Recovery records confirmation consumption transactionally in Postgres, and strictly revokes sessions before commit; a failure rolls back the password and consumption marker. Redis cleanup follows commit. `password_reset` also revokes sessions and advances a durable OAuth credential generation in the same transaction (G9). OAuth validation checks that generation, covering access tokens and refresh chains without relying on a Redis JTI index.

**OAuth2 token `amr` (M9).** The browser session records the login's assurance for authorization-code issuance. Bearer-token middleware constructs a request-local ABAC userinfo copy from the validated token's own claims; it never writes those claims into the identity-shared session. Missing assurance means no fresh factor.

The new `_session_auth_context(request)` reads that pair back. The three places that mint authorization-code carriers copy it onto the carrier (`OauthAuthorizationCode.mfa`/`.amr`):
- `_issue_code` (`backend.py:1494`) — the authorize and consent paths;
- the device-flow carrier (`backend.py:2775`).

The code exchange then copies the pair:
- into `token_data` (claims `mfa`, `amr`);
- into the issued `OauthRefreshToken`;
- into the request-local authorization context when that access token is validated.

A refresh rotation copies the pair from the parent refresh token: `amr` describes the original authentication event. Introspection and userinfo echo `amr` (and `mfa`) when the token carries them.

Codes and tokens minted without MFA carry neither assurance claim. Generation 0 is omitted for legacy payload compatibility; a positive generation is carried after reset or recovery (AC24).

**Availability self-healing (M1).** `MfaServicesSlot.ready()` returns the current services. When they are unavailable for a transient reason, it rebuilds them at most once per `AUTH_MFA_RETRY_INTERVAL`, single-flight under an `asyncio.Lock`. Permanent configuration errors (no `AUTH_OTP_SECRET`, no `authdb`) are flagged `permanent=True` and are not retried.

**Factor management (M8).**
- Backup-code regeneration requires the password **and** `_strong_factor_proof` (a current TOTP code, an unused backup code, or a fresh passkey session). This amends FEAT-106 M5.
- `disenroll_totp` re-evaluates the strong-factor guard on the lock connection, inside the lock.
- Storage errors on the pre-lock checks map to 503.

### Component Diagram
```
 BasicAuth.authenticate ─┐                         ┌─ SessionIssuer (open_session)
 OAuth2 auth_login ──────┼─► SecondFactorGate ─────┼─ SessionIssuer (_create_user_session)
 /auth/mfa/verify ───────┤     .decide / .verify   └─ SessionIssuer (backend.open_session)
 /oauth2/login/mfa ──────┘          │ (inside MfaSecurity.user_lock → ONE connection)
                                    ├─► MfaServicesSlot.ready()  (M1: self-healing)
                                    ├─► user_from_id(conn) / evaluate(conn) / totp.verify(conn)
                                    └─► trusted_devices.consume_and_rotate(conn)

 password_change / password_reset / recovery / passkey ─► security_transition (M3)
        phase 1: pooled read+validate (released)          └─ ONE tx: credential write + bump
        phase 2: write on the yielded connection             + revoke + audit + commit

 navigator-vault rotate ─► discover_targets() ─► UserVaultTarget (no mfa rows any more)
                                              └─► MfaSecretTarget → {schema}.user_mfa_secrets (M7)
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `BasicAuth._second_factor` | replaced by adapter | Delegates to `SecondFactorGate.decide()`, mapping `GateResult` to `open_session` result / `MFARequired`. |
| `MfaHandler.verify` / `_verify_locked` | replaced by adapter | Delegates to `SecondFactorGate.verify()`, mapping `VerifyRefused` to `_error(code, status, **extra)`, then `finalize_login`. |
| `Oauth2Provider.auth_login` | modifies | 2FA branch via the gate. A new `auth_login_mfa` route, plus an `_authorize_redirect` helper extracted from the existing payload code. |
| `Oauth2Provider._create_user_session` | modifies | New `extra: Optional[dict]` records assurance for the isolated browser authentication event. |
| `security_transition` | modifies | Always yields a connection; fail closed on unavailable; `TransitionAborted`. |
| `MfaSecurity.user_lock` | modifies | Timeout and `ContextVar` publication. |
| `OauthAuthorizationCode` / `OauthRefreshToken` | modifies | New optional `mfa: bool = False`, `amr: Optional[list[str]] = None` (M9). Stored codes and tokens deserialize unchanged (`code_backend.py:82,163` use `Model(**json.loads(...))`). |
| OAuth bearer middleware / ABAC / token endpoints | modifies | Validate per-user token generation and use token-local `mfa`/`amr` (M4, M9). |
| `SessionRevoker` / `RecoveryTokenStore` | modifies | Strict revocation and transactional confirmation consumption (M4). |
| `PasswordRecoveryHandler` | modifies | New public `session_revoker()` classmethod returning the existing `_revoker` (M4, G9). |
| `navigator_session.vault.targets.postgres.PostgresTarget` | extends | `MfaSecretTarget`. |
| `navigator_session.vault_targets` entry point | registers | `mfa = "navigator_auth.mfa.targets:factory"`. |

### Data Models
```python
# navigator_auth/mfa/login.py (new)
@dataclass(frozen=True)
class LoginChallenge:
    token: str
    providers: tuple[str, ...]
    preferred: Optional[str]
    expires_in: int

@dataclass(frozen=True)
class GateResult(Generic[T]):
    session: Optional[T]                 # SessionIssuer result when a session was issued
    challenge: Optional[LoginChallenge]  # set when a second factor is owed
    device: Optional[dict]               # {"token": str, "max_age": int} for the trusted-device cookie

class VerifyRefused(Exception):
    code: str          # invalid_request | invalid_challenge | stale_challenge | invalid_code |
                       # rate_limited | account_disabled | mfa_unavailable | <MfaSignal code>
    status: int
    extra: dict        # e.g. {"attempts_remaining": 3}; MfaSignal payload for policy refusals
```

```python
# navigator_auth/backends/oauth2/models.py (modified, M9)
class OauthAuthorizationCode(BaseModel):   # verified: models.py:209
    ...
    mfa: bool = Field(default=False)               # session passed a second factor
    amr: Optional[list[str]] = Field(default=None) # e.g. ["pwd", "totp"]; None when not MFA'd

class OauthRefreshToken(BaseModel):        # verified: models.py:245
    ...
    mfa: bool = Field(default=False)
    amr: Optional[list[str]] = Field(default=None)
```

```sql
-- navigator_auth/mfa/sql/002_mfa_secrets.sql (new)
CREATE TABLE IF NOT EXISTS {schema}.user_mfa_secrets (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       bigint       NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    provider      VARCHAR(32)  NOT NULL,
    key           VARCHAR(255) NOT NULL,
    ciphertext_db BYTEA        NOT NULL,
    key_version   SMALLINT     NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at    TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS user_mfa_secrets_active_unique
    ON {schema}.user_mfa_secrets (user_id, provider, key) WHERE deleted_at IS NULL;
-- Move (idempotent; guarded by to_regclass('auth.user_vault_secrets') IS NOT NULL inside DO $$ … $$):
--   INSERT … SELECT id, user_id, 'totp', key, ciphertext_db, key_version, created_at, updated_at, deleted_at
--     FROM auth.user_vault_secrets WHERE key LIKE 'mfa:%' ON CONFLICT (id) DO NOTHING;
--   DELETE FROM auth.user_vault_secrets WHERE key LIKE 'mfa:%';
```

### New Public Interfaces
```python
# navigator_auth/mfa/login.py
SessionIssuer = Callable[[Any, dict], Awaitable[T]]   # (fresh user, extra claims) -> backend session result

class SecondFactorGate:
    def __init__(self, services: MfaServices, *, userid_attribute: str = "user_id",
                 password_attribute: str = "password") -> None: ...
    async def decide(self, request: web.Request, user: Any, issue: SessionIssuer[T]) -> GateResult[T]: ...
    async def verify(self, request: web.Request, token: str, provider: str, code: str,
                     issue: SessionIssuer[T], *, remember_device: bool = False,
                     device_label: str = "") -> GateResult[T]: ...

# navigator_auth/mfa/services.py
async def get_ready_mfa_services(app: Any) -> Optional[MfaServices]: ...

# navigator_auth/mfa/events.py
class TransitionAborted(Exception): ...

# navigator_auth/mfa/exceptions.py
class MfaUnavailable(MfaStorageError): ...

# navigator_auth/mfa/targets.py
class MfaSecretTarget(PostgresTarget): ...
def factory(resources: Mapping[str, Any]) -> Optional[MfaSecretTarget]: ...
```

---

## 3. Module Breakdown

#### Delegation-eligible modules

| Module | Eligible? | Decided patterns / exact contracts | Why not (if no) |
|---|---|---|---|
| M1: Self-healing MFA services | yes | `MfaServicesSlot.ready()`, `get_ready_mfa_services()`, `MfaServices.permanent`, `AUTH_MFA_RETRY_INTERVAL` (int s, fallback **15**), single-flight `asyncio.Lock`. | — |
| M2: Lock-scoped connection discipline | yes | `user_lock(user_id)` timeout `AUTH_MFA_LOCK_TIMEOUT` (float s, fallback **5.0**) via `asyncio.wait_for` on acquire + `SET LOCAL lock_timeout`; `LOCK_CONNECTION` ContextVar; `conn=` kw-only params listed in §3 M2. | — |
| M3: Transactional security_transition | yes | Always yields a connection; `MfaUnavailable` before yield; `TransitionAborted` rollback; same bump/revoke/audit order as today. | — |
| M4: Credential-change call sites | yes | Two-phase pattern; transactional recovery consumption and OAuth generation; strict session revocation; recovery order fixed in §3 M4. | — |
| M5: SecondFactorGate | yes | Signatures + `GateResult`/`VerifyRefused`; verify step order fixed in §3 M5; D16 backup consume before lock. | — |
| M6: OAuth2 login second factor | yes | Route `POST {login_uri}/mfa` name `nav_oauth2_login_mfa`, excluded from auth; template `templates/oauth/mfa.html`; `_authorize_redirect` key list identical to today's. | — |
| M7: MFA secrets table + rotation target | yes | DDL above; `MfaSecretTarget` mirrors `IdentityTarget` (instance `table`/`name` override); entry point `mfa`. | — |
| M8: Factor-management hardening | yes | `backup_codes` → `_strong_factor_proof` else 403 `strong_factor_proof_required`; disenroll guard under lock; pre-lock `MfaStorageError` → 503. | — |
| M9: OAuth2 token `amr` propagation | yes | Claims follow the validated token into request-local ABAC context; refresh copies from the parent; introspection/userinfo echo. | — |

### Module 1: Self-healing MFA services
- **Path**: `navigator_auth/mfa/services.py`, `navigator_auth/conf.py`
- **Responsibility**: Re-attempt a failed MFA setup without a restart. Distinguish *not configured* (`None`), *transiently unavailable* (retry) and *permanently misconfigured* (no retry).
- **Depends on**: existing `build_mfa_services`
- **Interface Skeleton**:
  ```python
  # navigator_auth/mfa/services.py  (modifies navigator_auth/mfa/services.py:28, :106, :113, :119)
  class MfaServices:  # verified: navigator_auth/mfa/services.py:28
      permanent: bool  # new kw-only __init__ arg, default False; True for missing secret / missing authdb

  class MfaServicesSlot:  # verified: navigator_auth/mfa/services.py:106
      async def ready(self, app: Any) -> Optional[MfaServices]:
          """Return the slot's services, rebuilding them when transiently unavailable.

          None when the slot holds no services (2FA off or no BasicAuth). When
          ``services.available`` is False and not ``permanent``, at most one rebuild per
          AUTH_MFA_RETRY_INTERVAL seconds runs (single-flight under an asyncio.Lock):
          ``build_mfa_services(app, services.backend)``; on success the new object replaces
          the old one; retire its Redis pool only after all in-flight users release it.
          Returns the (possibly still
          unavailable) services; callers fail closed on ``available is False``. Never raises.
          """

  async def get_ready_mfa_services(app: Any) -> Optional[MfaServices]:
      """Async, self-healing counterpart of get_mfa_services (verified: services.py:113)."""
  ```
  `navigator_auth/conf.py`: `AUTH_MFA_RETRY_INTERVAL = config.getint("AUTH_MFA_RETRY_INTERVAL", fallback=15)` next to the `AUTH_OTP_*` block (verified: `conf.py:659-671`).
- Callers hold a service lease for their entire operation; swapping the slot retires the old service and closes it only when its last lease ends. Shutdown drains or cancels outstanding leases before closing pools. A raw reference without a lease must not outlive `ready()`.
- Every MFA decision point switches from `get_mfa_services` to `await get_ready_mfa_services`: the gate (M5), `security_transition` (M3), `MfaHandler._session_user`/`challenge`, and the OAuth2 form (M6).

### Module 2: Lock-scoped connection discipline
- **Path**: `navigator_auth/mfa/security.py`, `navigator_auth/backends/idp/__init__.py`, `navigator_auth/mfa/totp.py`, `navigator_auth/mfa/trusted_devices.py`, `navigator_auth/passkey/store.py`, `navigator_auth/conf.py`
- **Responsibility**: No second pool acquisition while a `user_lock` connection is held. Bounded lock waits.
- **Depends on**: —
- **Interface Skeleton**:
  ```python
  # navigator_auth/mfa/security.py  (modifies navigator_auth/mfa/security.py:55)
  LOCK_CONNECTION: ContextVar[Optional[Any]]  # set to the lock connection for the scope, reset on exit

  @asynccontextmanager
  async def user_lock(self, user_id: int) -> AsyncIterator[Any]:  # verified: security.py:55
      """As today, plus: pool acquire bounded by asyncio.wait_for(…, AUTH_MFA_LOCK_TIMEOUT) and
      ``SET LOCAL lock_timeout`` before pg_advisory_xact_lock; either timeout raises MfaStorageError.
      Publishes the connection in LOCK_CONNECTION for the scope."""

  # navigator_auth/backends/idp/__init__.py  (modifies :124)
  async def user_from_id(self, uid: int, *, conn: Any = None) -> Identity:  # verified: idp/__init__.py:124
      """With ``conn`` the lookup runs on it (no pool acquire); otherwise unchanged."""

  # navigator_auth/mfa/totp.py  (modifies :113, :210)
  async def _load_seed(self, user_id: int, *, conn: Any = None) -> Optional[bytes]: ...
  async def verify(self, request: web.Request, user: Mapping, code: str,
                   challenge: Optional[MfaChallenge] = None, *, conn: Any = None) -> bool:
      """Seed read and last_used touch run on ``conn`` when given."""

  # navigator_auth/mfa/trusted_devices.py  (modifies :71)
  async def consume_and_rotate(self, raw_token: str, user_id: int, *,
                               conn: Any = None) -> Optional[tuple[int, str]]:
      """With ``conn``: run inside the CALLER's transaction (no own transaction/commit/rollback;
      a replay's family revocation is committed by the caller). Without: unchanged."""

  # navigator_auth/passkey/store.py  (modifies :66, :110)
  async def save_credential(self, credential: StoredCredential, *, conn: Any = None) -> None: ...
  async def delete_credential(self, user_id: int, credential_id: bytes, *,
                              keep_last: bool = False, conn: Any = None) -> bool: ...
  ```
  `navigator_auth/conf.py`: `AUTH_MFA_LOCK_TIMEOUT = config.getfloat("AUTH_MFA_LOCK_TIMEOUT", fallback=5.0)`.
- `BackupCodeStore.consume` keeps **no** `conn` parameter (D16; verified `backup_codes.py:132`).

### Module 3: Transactional `security_transition`
- **Path**: `navigator_auth/mfa/events.py`, `navigator_auth/mfa/exceptions.py`
- **Responsibility**: One connection, one transaction for a credential change and its MFA bookkeeping. Fail closed when MFA is configured but down.
- **Depends on**: M1 (`get_ready_mfa_services`), M2 (`user_lock` timeout)
- **Interface Skeleton**:
  ```python
  # navigator_auth/mfa/exceptions.py  (modifies; MfaStorageError verified: exceptions.py:8)
  class MfaUnavailable(MfaStorageError):
      """2FA is enabled but the MFA services are unavailable; callers answer 503 mfa_unavailable."""

  # navigator_auth/mfa/events.py  (modifies navigator_auth/mfa/events.py:25)
  class TransitionAborted(Exception):
      """Raised by a transition body to roll back with a client-facing reason (logged at info)."""
      def __init__(self, reason: str) -> None: ...

  @asynccontextmanager
  async def security_transition(app, user_id, event, *, actor_user_id=None, revoke_devices=True,
                                detail=None, request_id=None) -> AsyncIterator[Any]:
      """Yield ONE live connection inside ONE transaction.

      - get_ready_mfa_services(app) is None → a pooled connection from app["authdb"] in a
        transaction with the same per-user advisory lock; no bump or audit; commit on clean exit.
      - services.available is False → raise MfaUnavailable BEFORE yielding.
      - otherwise → the user_lock connection; after the body: bump_version, revoke_all (when
        revoke_devices), write_audit, commit — all on that connection.
      Any exception from the body (TransitionAborted included) rolls back and re-raises.
      The body MUST write the credential on the yielded connection and MUST NOT acquire another.
      """
  ```

### Module 4: Credential-change call sites
- **Path**: `navigator_auth/handlers/users/session.py`, `navigator_auth/handlers/recovery/{handler,store,revoke}.py`, `navigator_auth/backends/passkey.py`, `navigator_auth/backends/oauth2/{backend,models,code_backend}.py`, `navigator_auth/handlers/auth.py`, and a new SQL migration for the durable state below.
- **Responsibility**: Two-phase credential changes. Atomic with the MFA bookkeeping; no nested acquisition.
- **Depends on**: M3, M2
- **Contract** (no new public signatures):
  - `password_change` (`session.py:131`):
    1. Phase 1, on a pooled connection that is then released: `User.get`, check the old password (403 on mismatch), capture `user.password`.
    2. Phase 2: `async with security_transition(...) as conn:` set `User.Meta.connection = conn`, re-`get`; hash ≠ captured → `TransitionAborted("credentials_changed")` → 409; set the new password, `await user.update()`.
    3. `MfaUnavailable` → 503 `mfa_unavailable`.
  - `password_reset` (`session.py:171`): the same two-phase shape. Phase 1 is only the existence check (404). In phase 2, update the password and increment the OAuth credential generation on `conn`, then call strict `revoke_user` before commit. Failure rolls back both database writes and returns 503.
  - `PasswordRecoveryHandler.session_revoker()` (`recovery/handler.py`, new classmethod): calls `cls._ensure_resources()` (verified `handler.py:139`) and returns `cls._revoker` (verified `handler.py:151`). It is the single process-wide `SessionRevoker`.
  - Recovery completion (`recovery/handler.py:299`):
    1. Phase 1 (pooled, released): `peek_confirmation`, `User.get`, policy validation (422).
    2. Phase 2 (transition connection): re-get user → hash drift → 409; revalidate the signed, unexpired Redis confirmation and its current rotation status; insert its SHA-256 digest into the transactional consumption table below; write the password and increment OAuth generation; strictly revoke sessions; commit. A duplicate consumption marker yields 400. Storage or revocation failure yields 503 and rolls back all database writes.
    3. After commit: `drop_pair`, best effort and logged. Do not call Redis `consume_confirmation` before commit. A leftover Redis record cannot be replayed because the committed digest is authoritative.
  - Passkey register (`passkey.py:320`) / remove (`passkey.py:569`): `async with security_transition(...) as conn:` then `save_credential(stored, conn=conn)` / `delete_credential(..., conn=conn)`. `MfaUnavailable` → 503.

**Durable recovery and token revocation contract:**
- Add migration-managed `{schema}.recovery_confirm_consumptions` with a primary-key SHA-256 confirmation digest and expiry timestamp, and `{schema}.oauth_user_generation` with one row per user, default generation 0. Never store raw confirmation tokens. Insert the marker on the transition connection with a uniqueness constraint; retain it at least until the signed confirmation expires, including clock skew. Both tables are required regardless of the MFA setting and included in startup/migration readiness checks. Concurrent confirmations and confirmation rotation must serialize per user under the same database advisory transaction lock, including with MFA off. Recheck Redis confirmation validity and rotation while holding that lock; rotation must acquire it before changing Redis so it cannot invalidate a confirmation between recheck and commit.
- Make `SessionRevoker.revoke_user(..., strict=True)` propagate underlying session-store, JTI-index and per-token revocation failures, including unavailable required storage; do not convert errors or missing required backends to successful zero counts. Preserve best-effort behavior for existing callers by default. A partial external revocation before rollback is safe but may log users out; it must not be reported as successful password change.
- Stamp each user OAuth authorization code, device-flow carrier, access token and refresh token with the current generation. Read it under the user lock at login/carrier creation and preserve it through code exchange and refresh; never replace an old carrier's generation with the current one. In the reset/recovery transaction increment the generation. Enforce equality against the authoritative database value at code exchange, refresh, access-token authentication, introspection and userinfo; on mismatch reject or mark inactive. A database lookup failure fails closed (503, or inactive where the protocol requires it). No stale cache may authorize a request after commit. Refresh and token issuance must serialize with reset using the same user lock and recheck generation inside that lock, so a race cannot mint a usable token from an old carrier.
- Backward compatibility: a token or stored carrier without a generation is generation 0; absent user rows also mean 0. Thus existing tokens continue to work until the first reset or recovery, after which they fail. `client_credentials` has no user generation and remains unchanged. Validation must cover all user-token paths, including any middleware session recreation, not just the token endpoint.

### Module 5: SecondFactorGate
- **Path**: `navigator_auth/mfa/login.py` (new), `navigator_auth/backends/basic.py`, `navigator_auth/handlers/mfa.py`
- **Responsibility**: The single place that decides, verifies and issues a second-factor login, serialized under the user lock.
- **Depends on**: M1, M2
- **Interface Skeleton**:
  ```python
  # navigator_auth/mfa/login.py  (new)
  class SecondFactorGate:
      async def decide(self, request, user, issue: SessionIssuer[T]) -> GateResult[T]:
          """Call after a successful password check (``user`` carries the validated hash).

          Under services.security.user_lock(uid) → conn:
          1. fresh = idp.user_from_id(uid, conn=conn); inactive → FailedAuth(403);
             fresh[password_attribute] != user[password_attribute] (secrets.compare_digest on str)
             → FailedAuth("credentials_changed", status=401).
          2. evaluation = services.evaluate(fresh, conn=conn); MfaState.NONE →
             GateResult(session=await issue(fresh, {}), …)   # no extra claims: AC4 baseline unchanged
          3. trusted-device cookie allowed by may_offer_trusted_device → consume_and_rotate(raw, uid,
             conn=conn) → GateResult(session=await issue(fresh, {"auth_method": <caller>, "mfa": True,
             "amr": [AMR_PASSWORD, AMR_TRUSTED_DEVICE]}), device={"token", "max_age"})
          4. no providers → MFARefused("no_factor_available", 403); email preferred → challenge();
             store.issue(...) → GateResult(challenge=LoginChallenge(...))
          Raises MFARefused("mfa_unavailable", 503) on any non-signal dependency failure.
          """

      async def verify(self, request, token, provider, code, issue, *, remember_device=False,
                       device_label="") -> GateResult[T]:
          """Fixed step order (raises VerifyRefused on refusal):
          1. shape check → invalid_request 400; preview = store.peek(token) → None → invalid_challenge 401
          2. rate limits (user + ip, Redis) → rate_limited 429
          3. provider not in preview.providers or not in services.providers → _failed (invalid_code)
          4. provider == backup → backup_codes.consume(preview.user_id, code) on its OWN connection
             BEFORE the lock (D16); False → _failed
          5. user_lock(preview.user_id) → conn: re-peek; revalidate (user_from_id(conn=conn),
             evaluate(conn=conn), version + digest compare → stale_challenge 401, discard)
          6. provider not in evaluation.providers → _failed; provider == totp →
             providers[provider].verify(request, user, code, challenge=record, conn=conn);
             provider == email → providers[provider].verify(request, user, code, challenge=record)
             (email verify does not access the DB); False → _failed
          7. store.consume(token) must equal record → else invalid_challenge 401
          8. session = await issue(user, {"auth_method": <caller>, "mfa": True,
             "amr": [AMR_PASSWORD, AMR_BY_PROVIDER[provider]]}); FailedAuth → account_disabled
          9. remember_device → trusted_devices.issue(..., conn=conn) → device
          """
  ```
  `BasicAuth._second_factor` (`basic.py:357`) becomes:
  - `gate.decide(request, user, issue=lambda u, extra: self.open_session(request, u, extra=extra or None))`;
  - map `GateResult.challenge` → `MFARequired`, and `device` → `result[MFA_DEVICE_TOKEN_KEY]`.

  `BasicAuth._trusted_device` (`basic.py:404`) moves into the gate and is deleted.

  `MfaHandler.verify` (`handlers/mfa.py:88`) becomes:
  - `gate.verify(..., issue=lambda u, extra: services.backend.open_session(request, u, extra=extra))`;
  - `VerifyRefused` → `_error(e.code, e.status, **e.extra)`;
  - success → `result[MFA_DEVICE_TOKEN_KEY] = device` when issued → `finalize_login` (after the lock is released).

  `_verify_locked`, `_revalidate` and `_maybe_trust_device` move into the gate.

### Module 6: OAuth2 login second factor
- **Path**: `navigator_auth/backends/oauth2/backend.py`, `templates/oauth/mfa.html` (new)
- **Responsibility**: The OAuth2 password form enforces the same second factor as BasicAuth.
- **Depends on**: M5
- **Interface Skeleton**:
  ```python
  # navigator_auth/backends/oauth2/backend.py
  async def _create_user_session(self, request, user, response=None,
                                 extra: Optional[dict] = None):  # verified: backend.py:632
      """Record browser-login assurance in an authentication-event-specific browser session,
      never in an identity-shared bearer authorization context. None preserves the 2FA-off
      browser behavior (AC5)."""

  def _authorize_redirect(self, request: web.Request, data: dict) -> web.HTTPFound:
      """Extracted verbatim from auth_login (backend.py:1648-1670): client_id, redirect_uri,
      response_type, state, scope, code_challenge, code_challenge_method, nonce, prompt."""

  async def auth_login(self, request: web.Request):  # verified: backend.py:1616
      """2FA off → unchanged. 2FA on → after authenticate_credentials + user_is_active:
      services = await get_ready_mfa_services(app); None or unavailable → 503 (no session).
      gate.decide(request, user, issue=<_create_user_session on the redirect>) →
        session → redirect (+ nav_mfa_device cookie via trusted_cookie_kwargs when device);
        challenge → render oauth/mfa.html (200, Cache-Control: no-store) with challenge,
        providers, preferred, expires_in and every authorize parameter as hidden fields."""

  async def auth_login_mfa(self, request: web.Request) -> web.StreamResponse:
      """POST {login_uri}/mfa — form fields challenge, provider, code, remember_device,
      device_label + authorize parameters. gate.verify(...) → success: session on the redirect
      (_authorize_redirect), trusted cookie when issued. VerifyRefused: invalid_code →
      re-render oauth/mfa.html with error + attempts_remaining; invalid_challenge /
      stale_challenge → re-render oauth/login.html with an error; rate_limited → 429 page;
      mfa_unavailable → 503."""
  ```
  The route is registered in `configure` next to `nav_oauth2_login` (verified `backend.py:328`), as `router.add_route("POST", f"{self.login_uri}/mfa", self.auth_login_mfa, name="nav_oauth2_login_mfa")`. The path is appended to `AUTH_EXCLUDE_LIST_KEY`. The template reuses `oauth/login.html`'s layout and escapes every echoed value.

### Module 7: MFA secrets table and rotation target
- **Path**: `navigator_auth/mfa/sql/002_mfa_secrets.sql` (new), `navigator_auth/mfa/migrations.py`, `navigator_auth/mfa/totp.py`, `navigator_auth/mfa/targets.py` (new), `pyproject.toml`
- **Responsibility**: TOTP seeds live in a table whose rotation target opens them with the right context.
- **Depends on**: —
- **Interface Skeleton**:
  ```python
  # navigator_auth/mfa/totp.py  (modifies :31, :113, :241, :268)
  MFA_SECRETS_TABLE = f"{AUTH_DB_SCHEMA}.user_mfa_secrets"   # replaces VAULT_SECRETS_TABLE (verified :31)
  # _load_seed / _disenroll_on / _install_seed read and write MFA_SECRETS_TABLE; _install_seed
  # inserts provider=PROVIDER_TOTP and upserts ON CONFLICT (user_id, provider, key) WHERE deleted_at IS NULL.

  # navigator_auth/mfa/targets.py  (new; pattern verified: navigator_auth/identity/targets.py:21,60)
  class MfaSecretTarget(PostgresTarget):
      name = "auth.user_mfa_secrets"; table = "auth.user_mfa_secrets"   # instance override to AUTH_DB_SCHEMA
      purpose = MFA_SEED_PURPOSE                                       # "mfa" (verified totp.py:29)
      pk_column = "id"
      identity_columns = ("user_id", "provider", "key")               # == mfa_seed_context fields (totp.py:36)
      encrypted_fields = ("ciphertext_db",)
      include_field_in_context = False
      key_version_column = "key_version"; touch_column = "updated_at"
      state_columns = ("deleted_at", "updated_at")
      quarantine_assignments = "deleted_at = COALESCE(deleted_at, NOW())"
      def context_value(self, column: str, value: Any) -> ContextValue: ...   # user_id → int, else str
      def pk_from_json(self, value: Any) -> Any: ...                          # UUID
      def state_from_json(self, column: str, value: Any) -> Any: ...          # datetime

  def factory(resources: Mapping[str, Any]) -> Optional[MfaSecretTarget]:
      """Entry-point factory: requires ``db_pool``; None when absent."""
  ```
  - `migrations.py`: `_MIGRATION_FILES = ("001_mfa_tables.sql", "002_mfa_secrets.sql")`; `MFA_TABLES` gains `"user_mfa_secrets"`.
  - `pyproject.toml` `[project.entry-points."navigator_session.vault_targets"]` gains `mfa = "navigator_auth.mfa.targets:factory"`.
  - The `001_mfa_tables.sql` header comment (lines 4–5) is updated to point at the new table.

### Module 8: Factor-management hardening
- **Path**: `navigator_auth/handlers/mfa.py`
- **Responsibility**: #7 and #12.
- **Depends on**: M2 (the lock connection used by the guard)
- **Contract**:
  - `backup_codes` (`handlers/mfa.py:436`):
    1. `_fresh_password_ok` → else 403 `invalid_credentials`.
    2. `has_strong_factor` → else 403 `strong_factor_required`.
    3. `await self._strong_factor_proof(request, services, session, record, body)` (verified `handlers/mfa.py:141`) → else 403 `strong_factor_proof_required`.
    4. Generate under the lock as today.
  - `disenroll_totp` (`handlers/mfa.py:385`):
    - Pre-lock calls (`is_enrolled`, proof verification, backup consume) are wrapped so `MfaStorageError` → 503.
    - Inside `user_lock` → conn, before `disenroll(conn=conn)`: `policy` from `_security_context(..., conn)`; `requires_strong_factor(record, policy)` and `passkey_count(uid, conn=conn) == 0` → 409 `strong_factor_required` (rollback).
    - The pre-lock guard (`:395`) is removed.

### Module 9: OAuth2 token `amr` propagation
- **Path**: `navigator_auth/backends/oauth2/backend.py`, `navigator_auth/backends/oauth2/models.py`
- **Responsibility**: Carry the second-factor outcome of an isolated browser authentication event through the code and refresh token to access-token claims, request-local ABAC context, introspection and userinfo (G8).
- **Depends on**: M6 (browser authentication-event context), M4 (generation validation).
- **Interface Skeleton**:
  ```python
  # navigator_auth/backends/oauth2/models.py  (modifies models.py:209, :245) — fields in §2 Data Models

  # navigator_auth/backends/oauth2/backend.py
  async def _session_auth_context(self, request: web.Request) -> dict:
      """Read assurance from the validated, browser-bound authentication event.
      Missing or invalid event requires login; never fall back to another identity's shared session."""

  async def _issue_code(self, request, client, user_obj, redirect_uri, scope, state,
                        code_challenge=None, code_challenge_method=None, resource=None):  # verified: backend.py:1478
      """Unchanged signature; the OauthAuthorizationCode it builds (backend.py:1494) gets
      **await self._session_auth_context(request)."""

  async def _token_session_claims(self, request: web.Request, user_id: int) -> dict:  # verified: backend.py:688
      """Bind identity as today; never put token assurance into an identity-shared session."""
  ```
  - **Device carrier** (`backend.py:2775`): `OauthAuthorizationCode(..., **await self._session_auth_context(request))`.
  - **Code exchange** (`token_data` at `backend.py:1822`):
    - When `auth_code.mfa` is True, set `token_data["mfa"] = True` and `token_data["amr"] = auth_code.amr`.
    - Copy both fields onto the `OauthRefreshToken` (`backend.py:1873`).
  - **Refresh grant** (`token_data` at `backend.py:2040`, rotation at `backend.py:2082`): the same, sourced from the presented refresh token `rt`. The rotated token copies `rt.mfa` / `rt.amr`.
  - **client_credentials** (`token_data` at `backend.py:1929`): no user, so no `mfa`/`amr`. Unchanged.
  - **Introspection** (`claims` dict at `backend.py:2468`): adds `"amr": token_payload["amr"]` and `"mfa": True` when the token payload carries `amr`. For a refresh token, they come from `rt`.
  - **userinfo** (`claims = {"sub": …}` at `backend.py:2222`): adds `"amr"` when the access-token payload carries it. This is not scope-gated, because `amr` describes the authentication rather than the profile.
  - **Browser event isolation**: an MFA login's authorization context must belong to that browser authentication event, not the identity-keyed shared session. Issue an opaque, unguessable, expiring browser-event handle bound to the authenticated browser and user; validate it at authorization and consent and bind device approval to the approving event. A later login must not upgrade an older browser event. If the event context is missing, stale or invalid, require login again rather than borrowing another event's assurance. Keep the existing 2FA-off path unchanged.
  - **ABAC**: after signature, expiry, revocation, audience and generation validation, bearer middleware exposes an immutable request-local copy of the token's `mfa`/`amr` and identity. Update both `abac/decorators.py` and `abac/guardian.py` to use this copy for bearer requests, removing any session-derived assurance before applying token claims. Missing claims deny fresh-factor rules. Cookie-only requests retain their existing session behavior; never trust unvalidated JWT data or client headers.
  - **Generation encoding**: represent generation 0 by an absent claim/field for legacy and 2FA-off payload compatibility; encode positive values explicitly. On validation, missing means 0. Apply this convention to codes, device carriers, access tokens and refresh tokens.

---

## 4. Test Specification

### Unit Tests
| Test | Module | Description |
|---|---|---|
| `test_ready_rebuilds_after_interval` | M1 | Services recover; the retired Redis pool closes only after its final in-flight lease ends. |
| `test_ready_rebuild_inflight` | M1 | Hold an old-service lease across a swap; its Redis operation completes and the pool closes after release. |
| `test_ready_single_flight` | M1 | 20 concurrent `ready()` calls trigger exactly one rebuild. |
| `test_ready_permanent_not_retried` | M1 | Missing secret / authdb → `permanent=True`, no rebuild. |
| `test_user_lock_timeout` | M2 | A held advisory lock makes a second `user_lock` raise `MfaStorageError` after `AUTH_MFA_LOCK_TIMEOUT`. |
| `test_lock_connection_published` | M2 | `LOCK_CONNECTION` is the lock connection inside the scope, `None` after. |
| `test_consume_and_rotate_on_caller_conn` | M2 | With `conn`, rotation and replay revocation commit only with the caller's transaction. |
| `test_transition_unavailable_fails_closed` | M3 | 2FA on + unavailable → `MfaUnavailable` before the body runs. |
| `test_transition_not_configured_yields_tx` | M3 | No slot → transaction and per-user advisory lock; body rollback on exception. |
| `test_transition_aborted_rolls_back` | M3 | `TransitionAborted` → no bump, no audit, no write. |
| `test_mfa_secret_target_context_matches_seed` | M7 | `context_for(row, "ciphertext_db")` == `mfa_seed_context(user_id)`. |
| `test_mfa_target_factory_requires_pool` | M7 | `factory({})` is None. |
| `test_vault_target_entry_point_declared` | M7 | `pyproject.toml` declares `mfa = "navigator_auth.mfa.targets:factory"`. |

### Integration Tests (live Postgres + Redis, as the existing MFA suites)
| Test | Description |
|---|---|
| `test_oauth2_login_factor_owed_renders_mfa_page` | AC1. |
| `test_oauth2_login_mfa_success_redirects_with_pkce` | AC2. |
| `test_oauth2_login_mfa_invalid_and_stale` | AC3. |
| `test_oauth2_login_trusted_device` | AC4. |
| `test_oauth2_login_2fa_disabled_unchanged` | AC5. |
| `test_oauth2_login_mfa_unavailable_503` | AC6. |
| `test_rotate_master_key_rotates_mfa_seeds` | AC7. |
| `test_mfa_secrets_migration_moves_rows` | AC8. |
| `test_no_nested_acquire_single_connection_pool` | AC10. Every listed flow completes against an `authdb` pool capped at one connection, under a 10 s timeout. |
| `test_no_acquire_inside_lock_guard` | AC10. A pool wrapper raises if `acquire()` runs while `LOCK_CONNECTION` is set (backup consume runs before the lock). |
| `test_transition_atomic_on_audit_failure` | AC14. Covers password_change, password_reset and recovery. |
| `test_recovery_revocation_failure_rolls_back` | AC15. |
| `test_passkey_transition_atomic` | AC16. |
| `test_login_refused_when_password_changed_mid_flight` | AC17. |
| `test_trusted_device_session_issued_under_lock` | AC18. |
| `test_backup_regeneration_requires_proof` | AC19. |
| `test_disenroll_guard_under_lock_race` | AC20. |
| `test_oauth2_token_carries_amr_after_mfa_login` | AC23. |
| `test_oauth2_token_without_mfa_has_no_amr` | AC24. |
| `test_oauth2_refresh_preserves_amr` | AC25. |
| `test_oauth2_introspect_and_userinfo_echo_amr` | AC26. |
| `test_abac_fresh_factor_grants_mfa_oauth2_token` | AC27. |
| `test_password_reset_revokes_sessions` | AC28. |
| `test_oauth_assurance_isolation` | AC29. |
| `test_oauth_reset_generation` | AC30. |
| `test_strict_revocation_failures` | AC31. |
| `test_recovery_confirmation_transactional` | AC32. |
| `test_email_gate_verify` | AC33. |

### Validation Contract

tests:
- tests/test_mfa_review_fixes_services.py
- tests/test_mfa_review_fixes_transitions.py
- tests/test_mfa_review_fixes_gate.py
- tests/test_mfa_review_fixes_oauth2.py
- tests/test_mfa_review_fixes_oauth2_tokens.py
- tests/test_mfa_review_fixes_vault.py
- tests/test_mfa_review_fixes_management.py
- tests/test_mfa_verify.py
- tests/test_mfa_basic_auth_hook.py
- tests/test_mfa_security_transitions.py
- tests/test_mfa_enrollment_security.py
- tests/test_mfa_totp_provider.py
- tests/test_mfa_trusted_devices.py
- tests/test_mfa_vault_isolation.py
- tests/test_mfa_e2e.py
markers: none

### Test Data / Fixtures
Reuse `tests/fixtures/mfa.py` (`mfa_db`, `mfa_redis_pool`, `frozen_totp_clock`, vault `KeyRing`). New fixtures:
- `single_connection_authdb` — an asyncdb pool with `max_size=1`, wrapped to record `acquire()` calls together with the `LOCK_CONNECTION` value;
- `two_key_keyring` — `KeyRing({1: k1, 2: k2}, 1)`, then `KeyRing({2: k2}, 2)` after rotation;
- `oauth2_client` — a registered public client with PKCE for the OAuth2 form tests.

---

## 5. Acceptance Criteria

- [ ] **AC1** — 2FA on, user owes a factor: `POST /oauth2/login` with a valid password returns 200 HTML with the second-factor form. The response has `Cache-Control: no-store`, no `Set-Cookie` for the session, and no redirect. An email-preferred user receives exactly one OTP email.
- [ ] **AC2** — `POST /oauth2/login/mfa` with a valid code creates the OAuth2 session with `mfa: true` and `amr` `["pwd", <otp|totp|backup>]`. It answers 302 to `/oauth2/authorize`, carrying `client_id`, `redirect_uri`, `response_type`, `state`, `scope`, `code_challenge`, `code_challenge_method`, `nonce` and `prompt` exactly as submitted. Replaying the same challenge fails.
- [ ] **AC3**:
  - An invalid code re-renders the MFA page with `attempts_remaining` and sets no session.
  - Exhausted attempts or a stale challenge (security version or context drift) return to the login page with an error.
- [ ] **AC4** — A valid `nav_mfa_device` cookie lets the OAuth2 login skip the challenge. It is rotated and the session has `amr` `["pwd","trusted_device"]`. `remember_device` on the MFA form sets the cookie with `trusted_cookie_kwargs`.
- [ ] **AC5** — 2FA off: `auth_login` GET/POST behavior is unchanged: same status, `Location`, session-data keys and cookies as on `origin/dev`.
- [ ] **AC6** — 2FA on and the MFA slot missing or unavailable: the OAuth2 password POST returns 503 and creates no session.
- [ ] **AC7**:
  - With a TOTP-enrolled user, `rotate_master_key([UserVaultTarget(pool), MfaSecretTarget(pool)], 1, 2, keyring)` reports `errors == 0` for both targets, and every MFA seed is now at `key_version == 2`.
  - TOTP verify then succeeds with a keyring that holds only key 2.
- [ ] **AC8**:
  - Applying `002_mfa_secrets.sql` to a database holding `mfa:%` rows in `auth.user_vault_secrets` moves them to `user_mfa_secrets`, with `ciphertext_db`, `key_version` and timestamps byte-identical, and leaves zero `mfa:%` rows in the vault table.
  - Re-running it is a no-op.
  - It succeeds when `auth.user_vault_secrets` does not exist.
- [ ] **AC9** — `pyproject.toml` declares the `mfa` vault-target entry point. `factory()` without `db_pool` returns `None`. `MFA_TABLES` includes `user_mfa_secrets`.
- [ ] **AC10** — With `authdb` capped at one connection, each of these completes within 10 s:
  - BasicAuth login (no factor, challenge, trusted device);
  - `/auth/mfa/verify` (TOTP, email, backup);
  - `/oauth2/login` and `/oauth2/login/mfa`;
  - `password_change`, `password_reset` and recovery completion;
  - passkey register and remove;
  - TOTP disenroll and backup-code regeneration.

  No `acquire()` happens while `LOCK_CONNECTION` is set.
- [ ] **AC11** — `user_lock` waits are bounded by `AUTH_MFA_LOCK_TIMEOUT`. A timeout surfaces as 503 `mfa_unavailable`, never as a hang.
- [ ] **AC12**:
  - Services built unavailable (the tables probe fails) become available without a restart on the first decision point after `AUTH_MFA_RETRY_INTERVAL`, once the database recovers.
  - Concurrent callers trigger one rebuild.
  - Permanent misconfiguration is never retried.
- [ ] **AC13** — 2FA on and MFA unavailable: `password_change`, `password_reset`, recovery completion and passkey register/remove each return 503 `mfa_unavailable` and leave the credential unchanged.
- [ ] **AC14** — A fault injected into `write_audit` (and separately into the commit) during `password_change`, `password_reset` or recovery leaves the stored hash, the security version and the trusted devices unchanged, and the response is 503.
- [ ] **AC15**:
  - A successful recovery changes the password, bumps the version, revokes devices, writes the audit row, consumes the confirmation, and revokes sessions and jtis.
  - A failure inside `revoke_user` rolls the password change back (503).
  - A hash drift between phase 1 and phase 2 answers 409.
- [ ] **AC16** — A fault in `write_audit` during passkey remove leaves the credential present. During register, the credential is not stored.
- [ ] **AC17** — When the user's password changes after the login's password check but before the gate takes the lock, the login is refused 401 `credentials_changed`. No session is issued and no trusted device is rotated.
- [ ] **AC18** — For the trusted-device and no-factor-owed paths, the `SessionIssuer` runs while the user lock is held, asserted via `LOCK_CONNECTION` inside the issuer.
- [ ] **AC19** — `POST /auth/mfa/backup-codes` with password only → 403 `strong_factor_proof_required`. With a current TOTP code or an unused backup code → 201, and the previous set stops working.
- [ ] **AC20**:
  - For an enforced superuser with TOTP and exactly one passkey, a concurrent TOTP disenroll and passkey delete leave at least one strong factor: exactly one succeeds and the other answers 409.
  - A storage error in a pre-lock disenroll check answers 503, not 500.
- [ ] **AC21** — Every existing `tests/test_mfa_*.py` suite passes. Tests updated for intended behavior changes (backup regeneration proof, MFA secrets table) say so in their docstrings.
- [ ] **AC22** — No new runtime dependency. The 2FA-off BasicAuth login is unchanged (FEAT-106 AC4 sweep still green).
- [ ] **AC23** — After a TOTP OAuth2 login, the code exchange returns an access token with `mfa: true` and `amr: ["pwd","totp"]`; the validated request-local ABAC context has the same values. The device-flow carrier preserves the approving event's assurance.
- [ ] **AC24** — An OAuth2 login with no factor owed, or with 2FA off, yields tokens with **no** `mfa`/`amr` claim. At generation 0, 2FA-off token payload keys match `origin/dev`; after a reset or recovery the generation claim is necessarily present.
- [ ] **AC25** — A `refresh_token` grant from an MFA'd chain issues an access token with the original `amr`, and the rotated refresh token keeps it. A trusted-device login's chain keeps `["pwd","trusted_device"]`.
- [ ] **AC26** — `/oauth2/introspect` returns `amr` (and `mfa: true`) for an MFA'd access or refresh token, and omits them otherwise. `/oauth2/userinfo` returns `amr` for an MFA'd access token.
- [ ] **AC27** — With the FEAT-106 policy pack and `requires_fresh_factor`, a request bearing an OAuth2 access token from a TOTP-verified login is **granted**. Tokens from a trusted-device login and from a no-MFA login are **denied**.
- [ ] **AC28** — `password_reset` strictly revokes the target's session and indexed jtis and commits the generation increment with the password. Pre-reset user tokens are rejected afterwards. A revocation failure leaves the password and generation unchanged (503).
- [ ] **AC29** — A password-only or trusted-device OAuth token remains denied by fresh-factor ABAC after a later TOTP login and token mint for the same user, in either mint order and after session recreation. A separate browser event likewise cannot inherit another event's MFA; TOTP token access remains granted.
- [ ] **AC30** — After reset or recovery, pre-change OAuth access tokens, authorization codes, device carriers and refresh tokens (including legacy generation-0 artifacts) fail at every validation endpoint; refresh cannot mint a replacement. New logins work. Concurrent refresh/code exchange versus reset cannot issue a usable old-generation token; unavailable generation storage fails closed.
- [ ] **AC31** — Inject actual session Redis, JTI-index and individual token-storage errors inside strict revocation: reset and recovery return 503 and leave the password and generation unchanged. Cover partial revocation and retry.
- [ ] **AC32** — Inject revocation, audit and commit failures after the recovery marker insertion: password, generation and marker roll back, and the same unexpired confirmation can be retried. Concurrent reuse succeeds exactly once, including with MFA disabled; a committed marker rejects replay even if Redis cleanup fails.
- [ ] **AC33** — Email OTP verifies successfully through both BasicAuth and OAuth2 gate adapters without a `conn` argument; TOTP still uses the lock connection.
- [ ] **AC34** — An in-flight request holding old MFA services survives a successful rebuild; the retired Redis pool closes only after its last lease ends.

---

## 6. Codebase Contract

> Verified against `3f14b3c` (head of `feat-FEAT-106-basicauth-otp-2fa`). `/sdd-task` MUST re-run `grep -c` for every Edit Sites row it uses.

### Verified Imports
```python
from navigator_auth.mfa.services import MFA_APP_KEY, MfaServicesSlot, build_mfa_services, get_mfa_services  # basic.py:32
from navigator_auth.mfa.trusted_devices import may_offer_trusted_device                                 # basic.py:33
from navigator_auth.mfa.types import AMR_PASSWORD, AMR_TRUSTED_DEVICE, AMR_BY_PROVIDER, MFA_DEVICE_TOKEN_KEY, TRUSTED_COOKIE, PROVIDER_TOTP, PROVIDER_EMAIL, PROVIDER_BACKUP, trusted_cookie_kwargs  # types.py:10-15,152
from navigator_auth.mfa.exceptions import MfaStorageError                                                # exceptions.py:8
from navigator_auth.mfa.events import security_transition                                                # events.py:25
from navigator_auth.mfa.totp import mfa_seed_context, MFA_SEED_PURPOSE, TOTP_VAULT_KEY                   # totp.py:26,29,36
from navigator_auth.exceptions import MfaSignal, MFARequired, MFARefused                                 # exceptions.py:72,80,108
from navigator_session.vault.targets.postgres import PostgresTarget        # site-packages navigator_session 1.1.1, postgres.py:89
from navigator_session.vault.targets import UserVaultTarget                # targets/__init__.py:3
from navigator_session.vault import rotate_master_key, KeyRing, VaultContext  # vault/__init__.py:28,30,43
```

### Existing Class Signatures
```python
# navigator_auth/mfa/services.py
class MfaServices:                                                    # line 28
    async def evaluate(self, user: Mapping, *, conn: Any = None) -> MfaEvaluation:  # line 64
class MfaServicesSlot:                                                # line 106
def get_mfa_services(app: Any) -> Optional[MfaServices]:              # line 113
async def build_mfa_services(app: Any, backend: Any) -> MfaServices:  # line 119 (never raises; available=False on failure)

# navigator_auth/mfa/security.py
class MfaSecurity:                                                    # line 43
    async def user_lock(self, user_id: int) -> AsyncIterator[Any]:    # line 55 (@asynccontextmanager)
    async def current_version(self, conn: Any, user_id: int) -> int:  # line 78
    async def bump_version(self, conn: Any, user_id: int) -> int:     # line 94

# navigator_auth/mfa/events.py
async def security_transition(app, user_id, event, *, actor_user_id=None, revoke_devices=True,
                              detail=None, request_id=None)           # line 25; yields None when services None/unavailable (TODAY)

# navigator_auth/mfa/totp.py
TOTP_VAULT_KEY = "mfa:totp"                                           # line 26
MFA_SEED_PURPOSE, MFA_PENDING_PURPOSE = "mfa", "mfa-pending"          # line 29
VAULT_SECRETS_TABLE = "auth.user_vault_secrets"                       # line 31
def mfa_seed_context(user_id, provider=PROVIDER_TOTP, key=TOTP_VAULT_KEY) -> VaultContext  # line 36; fields (user_id, provider, key)
class TOTPProvider:
    async def _load_seed(self, user_id: int) -> Optional[bytes]:      # line 113 (acquires own conn)
    async def verify(self, request, user, code, challenge=None) -> bool  # line 210 (acquires own conn at :222)
    async def _disenroll_on(self, conn: Any, user_id: int) -> None:   # line 241
    async def _install_seed(self, conn: Any, user_id: int, seed: bytes) -> None:  # line 268

# navigator_auth/mfa/backup_codes.py
class BackupCodeStore:
    async def consume(self, user_id: int, code: str) -> bool:         # line 132 — own connection by design (D16)

# navigator_auth/mfa/trusted_devices.py
class TrustedDeviceStore:
    async def issue(self, user_id, days, label, *, conn=None) -> str:                      # line 48
    async def consume_and_rotate(self, raw_token: str, user_id: int) -> Optional[tuple[int, str]]:  # line 71 (own tx)
    async def revoke_all(self, user_id, reason, *, conn=None) -> int:                      # line 126

# navigator_auth/mfa/state.py
class MfaStateMachine:
    async def totp_confirmed(self, user_id, *, conn=None) -> bool     # line 85
    async def passkey_count(self, user_id, *, conn=None) -> int       # line 99
    async def has_strong_factor(self, user, *, conn=None) -> bool     # line 114
    async def requires_strong_factor(self, user, policy) -> bool      # line 121 (no conn)

# navigator_auth/backends/idp/__init__.py
class IdentityProvider:
    async def user_from_id(self, uid: int) -> Identity:               # line 124 (acquires app["authdb"])
    async def authenticate_credentials(self, login=None, password=None)  # line 174

# navigator_auth/backends/basic.py
class BasicAuth:
    def _owns_mfa(self) -> bool                                       # line 113
    async def open_session(self, request, user, extra=None)           # line 201 (Redis only; no DB acquire)
    async def authenticate(self, request)                             # line 327
    async def _second_factor(self, request, user) -> Optional[dict]   # line 357
    async def _trusted_device(self, request, services, evaluation) -> Optional[str]  # line 404

# navigator_auth/handlers/mfa.py
NO_STORE = {"Cache-Control": "no-store"}                              # line 46
class MfaHandler:
    async def verify(self, request) -> web.Response                   # line 88
    async def _session_user(self, request) -> tuple[Any, Any, Any]    # line 109
    async def _strong_factor_proof(self, request, services, session, record, body) -> bool  # line 141
    async def _security_context(self, services, record, conn)         # line 158
    async def _verify_locked(...)                                     # line 171
    async def _revalidate(...)                                        # line 214
    async def _maybe_trust_device(...)                                # line 242
    async def disenroll_totp(self, request)                           # line 385
    async def backup_codes(self, request)                             # line 436

# navigator_auth/backends/oauth2/backend.py
class Oauth2Provider(BaseAuthBackend):                                # line 258
    self.login_uri: str = "/oauth2/login"                             # line 281
    async def _create_user_session(self, request, user, response=None)  # line 632
    async def auth_login(self, request)                               # line 1616; POST builds the authorize payload at 1648-1670

    async def _token_session_claims(self, request, user_id: int) -> dict  # line 688
    async def authorize(self, request)                                # line 1343; check_session at 1423
    async def _issue_code(self, request, client, user_obj, redirect_uri, scope, state,
                          code_challenge=None, code_challenge_method=None, resource=None)  # line 1478; OauthAuthorizationCode(...) at 1494
    async def token_request(self, request)                            # line 1694; token_data at 1822 (code), 1929 (client_credentials), 2040 (refresh)
    #   OauthRefreshToken(...) at 1873 (code exchange) and 2082 (rotation)
    async def userinfo(self, request)                                 # line 2194; claims = {"sub": str(user_id)} at 2222
    async def introspect(self, request)                               # line 2359; claims: dict = {"active": True, ...} at 2468
    #   device-flow carrier OauthAuthorizationCode(...) at 2775

# navigator_auth/backends/oauth2/models.py
class OauthAuthorizationCode(BaseModel)                               # line 209 (datamodel BaseModel, Field)
class OauthRefreshToken(BaseModel)                                    # line 245
# navigator_auth/backends/oauth2/code_backend.py — Redis JSON round-trip: Model(**json.loads(data)) at 82, 163

# ABAC reads userinfo from the session object:
# navigator_auth/abac/decorators.py:50   userinfo = session[AUTH_SESSION_OBJECT]
# navigator_auth/abac/guardian.py:88     userinfo = session.get(AUTH_SESSION_OBJECT, {})
# navigator_auth/abac/context.py:136-141 EvalContext reads userinfo["mfa"] / ["auth_method"]; amr via ctx.userinfo
# navigator_auth/backends/abstract.py:205 BasicAuth-style sessions wrap userdata under AUTH_SESSION_OBJECT;
#   OAuth2 _create_user_session does NOT today (only {session_key_property, "user"}).

# navigator_auth/handlers/recovery/handler.py
class PasswordRecoveryHandler:
    @classmethod
    def _ensure_resources(cls) -> None                                # line 139
    #   cls._revoker = SessionRevoker(cls._pool)                      # line 151

# navigator_auth/passkey/store.py
class PasskeyStore:
    async def save_credential(self, credential: StoredCredential) -> None  # line 66
    async def delete_credential(self, user_id, credential_id, *, keep_last=False) -> bool  # line 110

# navigator_auth/handlers/recovery/revoke.py
class SessionRevoker:                                                 # line 41
    async def revoke_user(self, request, user) -> int                 # line 47 — Redis only (session pool + access_token_storage)

# navigator_session (site-packages 1.1.1)
async def rotate_master_key(targets, old_key_id, new_key_id, keyring, batch_size=100) -> dict  # vault/key_rotation.py:40
class UserVaultTarget(PostgresTarget): purpose="user-vault"; identity_columns=("user_id","key")  # targets/user_vault.py:33
PostgresTarget.context_for(row, field) -> VaultContext(purpose, "db", fields from identity_columns)  # postgres.py:177
PostgresTarget SELECT has no row filter (scans every row incl. soft-deleted)                         # postgres.py:141-145
```

### Integration Points
| New Component | Connects To | Via | Verified At |
|---|---|---|---|
| `SecondFactorGate.decide` | `MfaServices.evaluate(conn=)` | method call | `services.py:64` |
| `SecondFactorGate.verify` | `MfaChallengeStore.peek/consume/discard/register_failure` | method calls | `handlers/mfa.py:98,201,221,237` |
| `SecondFactorGate` | `StrictRateLimiter.check` | method call | `handlers/mfa.py:189` |
| `Oauth2Provider.auth_login_mfa` | router | `add_route("POST", …)` | `backend.py:328` |
| `MfaSecretTarget` | `discover_targets()` | entry point `navigator_session.vault_targets` | `pyproject.toml:76-77` |
| `security_transition` (M3) | `MfaSecurity.user_lock` | context manager | `security.py:55` |

### Does NOT Exist (Anti-Hallucination)
- ~~`BackupCodeStore.consume(..., conn=...)`~~ — deliberately absent (D16); keep it that way.
- ~~`navigator_session.vault.migrate.runner.rotate_master_key`~~ — rotation lives in `navigator_session.vault.key_rotation` (exported from `navigator_session.vault`).
- ~~a row filter / `WHERE` hook on `PostgresTarget`~~ — none; a shared table cannot be partitioned between targets.
- ~~`{schema}.user_mfa_secrets`~~, ~~`navigator_auth/mfa/login.py`~~, ~~`navigator_auth/mfa/targets.py`~~, ~~`templates/oauth/mfa.html`~~ — created by this spec.
- ~~`get_ready_mfa_services`~~, ~~`MfaUnavailable`~~, ~~`TransitionAborted`~~, ~~`LOCK_CONNECTION`~~, ~~`AUTH_MFA_RETRY_INTERVAL`~~, ~~`AUTH_MFA_LOCK_TIMEOUT`~~ — created by this spec.
- ~~an MFA second factor anywhere in `navigator_auth/backends/oauth2/`~~ — none today (the #1 bypass).
- ~~`OauthAuthorizationCode.amr` / `.mfa`~~, ~~`OauthRefreshToken.amr` / `.mfa`~~, ~~`Oauth2Provider._session_auth_context`~~, ~~`PasswordRecoveryHandler.session_revoker`~~ — created by this spec (M9, M4).
- ~~Request-local OAuth bearer assurance~~ — absent today; M9 introduces it without modifying the shared session.
- ~~an OIDC `id_token`~~ — not issued by this provider today; no `amr` in ID tokens (non-goal).

### Edit Sites (Blueprint Anchors)

Verified against: `3f14b3c`

| File | Action | Verbatim anchor line | Verified at | Occurrences |
|---|---|---|---|---|
| `navigator_auth/mfa/services.py` | MODIFY | `class MfaServicesSlot:` | `services.py:106` | 1 |
| `navigator_auth/mfa/services.py` | MODIFY | `def get_mfa_services(app: Any) -> Optional[MfaServices]:` | `services.py:113` | 1 |
| `navigator_auth/mfa/services.py` | MODIFY | `async def build_mfa_services(app: Any, backend: Any) -> MfaServices:` | `services.py:119` | 1 |
| `navigator_auth/conf.py` | MODIFY | `AUTH_OTP_EMAIL_CALLBACK = config.get("AUTH_OTP_EMAIL_CALLBACK")` | `conf.py:671` | 1 |
| `navigator_auth/mfa/security.py` | MODIFY | `async def user_lock(self, user_id: int) -> AsyncIterator[Any]:` | `security.py:55` | 1 |
| `navigator_auth/mfa/events.py` | MODIFY | `async def security_transition(` | `events.py:25` | 1 |
| `navigator_auth/mfa/exceptions.py` | MODIFY | `class MfaStorageError(Exception):` | `exceptions.py:8` | 1 |
| `navigator_auth/backends/idp/__init__.py` | MODIFY | `async def user_from_id(self, uid: int) -> Identity:` | `idp/__init__.py:124` | 1 |
| `navigator_auth/mfa/totp.py` | MODIFY | `VAULT_SECRETS_TABLE = "auth.user_vault_secrets"` | `totp.py:31` | 1 |
| `navigator_auth/mfa/totp.py` | MODIFY | `async def _load_seed(self, user_id: int) -> Optional[bytes]:` | `totp.py:113` | 1 |
| `navigator_auth/mfa/totp.py` | MODIFY | `async def verify(` | `totp.py:210` | 1 |
| `navigator_auth/mfa/totp.py` | MODIFY | `async def _disenroll_on(self, conn: Any, user_id: int) -> None:` | `totp.py:241` | 1 |
| `navigator_auth/mfa/totp.py` | MODIFY | `async def _install_seed(self, conn: Any, user_id: int, seed: bytes) -> None:` | `totp.py:268` | 1 |
| `navigator_auth/mfa/trusted_devices.py` | MODIFY | `async def consume_and_rotate(self, raw_token: str, user_id: int) -> Optional[tuple[int, str]]:` | `trusted_devices.py:71` | 1 |
| `navigator_auth/passkey/store.py` | MODIFY | `async def save_credential(self, credential: StoredCredential) -> None:` | `store.py:66` | 1 |
| `navigator_auth/passkey/store.py` | MODIFY | `async def delete_credential(self, user_id: int, credential_id: bytes, *, keep_last: bool = False) -> bool:` | `store.py:110` | 1 |
| `navigator_auth/handlers/users/session.py` | MODIFY | `async with security_transition(` + next line `request.app, user.user_id, "password_change", actor_user_id=user.user_id` | `session.py:131-132` | 2 (anchor) / 1 (with context) |
| `navigator_auth/handlers/users/session.py` | MODIFY | `async with security_transition(` + next line `request.app, user.user_id, "password_reset", actor_user_id=userinfo.get("user_id")` | `session.py:171-172` | 2 (anchor) / 1 (with context) |
| `navigator_auth/handlers/recovery/handler.py` | MODIFY | `async with security_transition(` | `handler.py:299` | 1 |
| `navigator_auth/backends/passkey.py` | MODIFY | `await self._store.save_credential(stored)` | `passkey.py:323` | 1 |
| `navigator_auth/backends/passkey.py` | MODIFY | `if not await self._store.delete_credential(user.user_id, credential_id, keep_last=guard_last):` | `passkey.py:592` | 1 |
| `navigator_auth/backends/basic.py` | MODIFY | `async def _second_factor(self, request: web.Request, user) -> Optional[dict]:` | `basic.py:357` | 1 |
| `navigator_auth/backends/basic.py` | MODIFY (delete) | `async def _trusted_device(self, request: web.Request, services, evaluation) -> Optional[str]:` | `basic.py:404` | 1 |
| `navigator_auth/handlers/mfa.py` | MODIFY | `async def verify(self, request: web.Request) -> web.Response:` | `handlers/mfa.py:88` | 1 |
| `navigator_auth/handlers/mfa.py` | MODIFY (move out) | `async def _verify_locked(` | `handlers/mfa.py:171` | 1 |
| `navigator_auth/handlers/mfa.py` | MODIFY | `async def _session_user(self, request: web.Request) -> tuple[Any, Any, Any]:` | `handlers/mfa.py:109` | 1 |
| `navigator_auth/handlers/mfa.py` | MODIFY | `async def challenge(self, request: web.Request) -> web.Response:` | `handlers/mfa.py:258` | 1 |
| `navigator_auth/handlers/mfa.py` | MODIFY | `async def disenroll_totp(self, request: web.Request) -> web.Response:` | `handlers/mfa.py:385` | 1 |
| `navigator_auth/handlers/mfa.py` | MODIFY | `async def backup_codes(self, request: web.Request) -> web.Response:` | `handlers/mfa.py:436` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `async def _create_user_session(` | `backend.py:632` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `async def auth_login(self, request: web.Request):` | `backend.py:1616` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `router.add_route("*", self.login_uri, self.auth_login, name="nav_oauth2_login")` | `backend.py:328` | 1 |
| `navigator_auth/mfa/migrations.py` | MODIFY | `_MIGRATION_FILES = ("001_mfa_tables.sql",)` | `migrations.py:13` | 1 |
| `navigator_auth/mfa/migrations.py` | MODIFY | `MFA_TABLES = (` | `migrations.py:14` | 1 |
| `pyproject.toml` | MODIFY | `identity = "navigator_auth.identity.targets:factory"` | `pyproject.toml:77` | 1 |
| `navigator_auth/handlers/recovery/handler.py` | MODIFY (add `session_revoker`) | `def _ensure_resources(cls) -> None:` | `handler.py:139` | 1 |
| `navigator_auth/backends/oauth2/models.py` | MODIFY | `class OauthAuthorizationCode(BaseModel):` | `models.py:209` | 1 |
| `navigator_auth/backends/oauth2/models.py` | MODIFY | `class OauthRefreshToken(BaseModel):` | `models.py:245` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `async def _token_session_claims(self, request: web.Request, user_id: int) -> dict:` | `backend.py:688` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `code_obj = OauthAuthorizationCode(` | `backend.py:1494` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `**await self._token_session_claims(request, user_id),`, the code-exchange occurrence: preceded by `"scope": scope,` / `"jti": jti,` inside the `token_data = {` that starts at 1822 | `backend.py:1829` | 2 (anchor) / 1 (with context: first occurrence, after `# TASK-027: mint jti.`) |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `            rt = OauthRefreshToken(` (12-space indent) | `backend.py:1873` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `**await self._token_session_claims(request, user_id),`, the refresh-grant occurrence (second, after `# TASK-024: user_id always from the refresh token.`) | `backend.py:2046` | 2 (anchor) / 1 (with context) |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `new_rt = OauthRefreshToken(` | `backend.py:2082` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `claims = {"sub": str(user_id)}` | `backend.py:2222` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `claims: dict = {` | `backend.py:2468` | 1 |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `carrier = OauthAuthorizationCode(` | `backend.py:2775` | 1 |
| `navigator_auth/mfa/login.py` | CREATE | — | — | — |
| `navigator_auth/mfa/targets.py` | CREATE | — | — | — |
| `navigator_auth/mfa/sql/002_mfa_secrets.sql` | CREATE | — | — | — |
| `templates/oauth/mfa.html` | CREATE | — | — | — |
| `tests/test_mfa_review_fixes_*.py` (7 files, §4) | CREATE | — | — | — |

---

## 7. Implementation Notes & Constraints

### Decisions
- **D1 — One gate, session issued under the lock.** The gate owns decide and verify. Backends only supply a `SessionIssuer`. `open_session` and `_create_user_session` touch Redis only (verified for `open_session`, `basic.py:201-300`), so running them under the DB lock adds no pool pressure.
- **D2 — Password-hash recheck under the lock.** This closes A1 even for writers outside `security_transition` (e.g. `UserManager`, R1). It is a stronger and simpler guard than comparing security versions, because the password check happens before any version is read.
- **D3 — A separate table, not a row filter.** `PostgresTarget` scans the whole table (`postgres.py:141-145`) and `UserVaultTarget` lives in an external package. The only way to stop it from touching MFA rows is to remove them from its table. Moving them keeps the ciphertext valid, because the AAD carries no table name.
- **D4 — The OAuth2 form uses BasicAuth's MFA slot.** With 2FA on and no BasicAuth configured (no slot), the OAuth2 password form fails closed (503) instead of bypassing.
- **D5 — The backup code is consumed before the lock (D16 preserved).** A backup code consumed by a verify that later fails stays consumed. The FEAT-106 spec requires that ("do not restore consumed backup codes after downstream failures").
- **D6 — Credential changes fail closed when MFA is configured but down.** This extends FEAT-106 G7/S5 ("fail the logins, not the process") to credential changes. Allowing them would skip device revocation.
- **D7 — Backup-code regeneration needs factor proof.** This amends FEAT-106 M5/AC14 and the S8 cross-check row "re-auth on regeneration". The password alone is no longer enough.
- **D8 — `amr` follows the OIDC meaning, across refreshes too.** `amr` records how the user originally authenticated, so refresh rotations copy it unchanged and never re-derive it. The claims appear only when the login actually passed MFA. A missing claim means "not MFA'd" to every consumer, which keeps the deny-by-default posture.
- **D9 — ABAC sees validated OAuth `amr` per request.** Bearer middleware supplies assurance from the validated token to ABAC; shared session data must never upgrade it. Browser login events are independently bound.

### Patterns to Follow
- Keep FEAT-106's fail-closed posture: any dependency error on a security path → 503 `mfa_unavailable`, never a bypass.
- Use JSON envelopes from `handlers/mfa.py` (`_error`, `NO_STORE`) for API routes. OAuth2 form routes answer HTML through `self._parser.view(...)`, as `auth_login` does.
- asyncdb `conn.execute` swallows DB errors. Use `fetchval … RETURNING` for every fail-closed write (project memory `asyncdb-execute-never-raises`).
- asyncdb redis `setex(key, value, timeout)` argument order (project memory `asyncdb-redis-setex-order`).
- Every new function: Google-style docstring and strict type hints. Every log line: secret-free (FEAT-106 sweep `test_no_secret_in_logs`).

### Known Risks / Gotchas
- **`User.Meta.connection` is class-level shared state** (`session.py`, `recovery/handler.py`, `idp/__init__.py`). Two-phase writes set it twice. Set it immediately before each model call and never `await` anything else in between. This is a pre-existing hazard, not introduced here.
- **Multi-statement migration atomicity.** asyncdb `execute` of a multi-statement string runs as one implicit transaction under the simple query protocol. The move (INSERT … SELECT, then DELETE) relies on that. `test_mfa_secrets_migration_moves_rows` must also inject a failure between the two statements and assert that no row was lost.
- **Entry-point discovery reads installed metadata.** The new `mfa` target is visible to `discover_targets()` only after reinstalling the package (`uv pip install -e .`). Tests construct `MfaSecretTarget` directly and assert the pyproject declaration separately.
- **Single-flight rebuild and the old services object.** A swap retires the old object; lease tracking defers pool closure until its last in-flight user releases it.
- **The `LOCK_CONNECTION` guard is a test aid.** Production code must not branch on it except `user_lock` itself. The guard proves G3; it does not enforce it at runtime.
- **One session per user identity (OAuth2).** The shared session cannot be an assurance authority. Bearer requests use validated per-token claims, and browser authorization uses a separate event-bound context, even after session recreation.
- **The OAuth2 MFA page echoes authorize parameters.** Every value must be HTML-escaped by the template engine. The parameters are client-controlled, as they already are in `oauth/login.html`.

### External Dependencies
| Package | Version | Reason |
|---|---|---|
| `navigator-session` | as pinned today (1.1.1 installed) | `PostgresTarget`, `rotate_master_key`, entry-point group — no upgrade needed |

---

## Worktree Strategy

- **Isolation**: a stacked worktree `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa-review-fixes`, created from `origin/feat-FEAT-106-basicauth-otp-2fa` (frontmatter `base_branch`). `/sdd-done` merges it back into `feat-FEAT-106-basicauth-otp-2fa`, so the fixes still ship in PR #633. The `sdd-coder` engine gives each task its own sub-worktree inside it.
- **Module dependency graph** (an edge means "imports or relies on"):
  - M3 → M1 (`get_ready_mfa_services`), M3 → M2 (`user_lock` timeout);
  - M4 → M3 (`TransitionAborted`, `MfaUnavailable`, always-a-connection), M4 → M2 (`PasskeyStore` `conn=`);
  - M5 → M1, M5 → M2 (`user_from_id`/`verify`/`consume_and_rotate` `conn=`);
  - M6 → M5 (`SecondFactorGate`);
  - M8 → M2 (lock connection for the guard);
  - M9 → M6 (browser-event context); M9 → M4 (generation validation).
  - M7 is independent.
- **Shared files** (tasks touching them are serialized):
  - `navigator_auth/handlers/mfa.py` — M5, M8;
  - `navigator_auth/mfa/totp.py` — M2, M7;
  - `navigator_auth/conf.py` — M1, M2;
  - `navigator_auth/backends/oauth2/backend.py` — M4, M6, M9; serialize edits and integrate generation checks with event isolation;
  - `navigator_auth/backends/oauth2/models.py` and `navigator_auth/handlers/auth.py` — M4, M9; serialize shared interface changes;
  - `navigator_auth/handlers/recovery/handler.py` — M4 only (`session_revoker` + recovery transition), so M4 keeps both edits in one task.
- **Exclusive resources**: M7 adds a DDL migration that every live-DB test applies, so its task is `parallel: false`.
- **Cross-feature dependencies**: none beyond FEAT-106 itself (same branch).

---

## 8. Open Questions

- [x] Scope of this spec — *Resolved by the user (2026-11-11)*: only the high-severity review findings, in one spec on the FEAT-106 branch. Medium/low findings go to a follow-up.
- [x] OAuth2 login form handling of a user who owes a factor — *Resolved by the user*: a full second factor in OAuth2 (M5/M6), not a refusal.
- [x] Backup-code regeneration — *Resolved by the user*: require fresh factor proof (M8, D7; amends FEAT-106 M5).
- [x] #11 `UserManager` — *Resolved*: stays FEAT-106 non-goal R1 (follow-up spec).
- [x] **Q1** — Defaults for the new settings — *Resolved by the user (2026-11-11)*: `AUTH_MFA_LOCK_TIMEOUT` = **5 s**, `AUTH_MFA_RETRY_INTERVAL` = **15 s**. Applied in §3 M1 and M2.
- [x] **Q2** — Should tokens minted from an MFA'd OAuth2 session carry `amr`? — *Resolved by the user*: **yes, in this spec.** Applied as G8, Module 9, D8, D9 and AC23–AC27, covering access tokens, refresh chains, introspection and userinfo. ID tokens and `acr` stay non-goals.
- [x] **Q3** — Should an admin `password_reset` revoke the target's sessions? — *Resolved by the user*: **yes, in this spec.** Applied as G9, §3 M4 and AC28. Self-service `password_change` is unchanged.

---

## 9. Design Research Cross-Check

> Model: — · Status: skipped (no accepted exploration document, and `sdd/config.json` sets `reviewer: none`). This spec was derived from an adversarial **PR review**, not a brainstorm: a Claude code-review subagent plus an independent `codex` verification pass (codex-cli 0.167.0, read-only). Transcripts: `sdd/state/FEAT-106/pr633-review/`.

| # | Suggestion (kind) | Disposition | Reason | Landed in |
|---|---|---|---|---|

Summary: **0** confirmed · **0** rejected · **0** escalated (step skipped).

---

## 10. Documentation

- **Policy**: `required`
- **Pages**: no `wiki/` tree exists in this repository. Update the FEAT-106 pages instead (informational for `techwiki check`):
  - `docs/two_factor_auth.rst`. Update it for:
    - the OAuth2 login second factor and the `/oauth2/login/mfa` route;
    - `AUTH_MFA_RETRY_INTERVAL` and `AUTH_MFA_LOCK_TIMEOUT`;
    - the `user_mfa_secrets` table and the `mfa` vault-target entry point (with the reinstall note for `navigator-vault`);
    - backup-code regeneration now needing factor proof;
    - `mfa`/`amr` in OAuth2 access tokens, refresh chains, introspection and userinfo, including request-local assurance isolation;
    - OAuth generation invalidation, transactional recovery confirmation consumption, and strict revocation failure behavior;
    - admin `password_reset` now ending the target's sessions.
  - `CHANGELOG.md` — a 0.30.0 entry for these fixes.
- **API modules**: `navigator_auth.mfa` (`login`, `targets`, `events`, `services`).

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-11-11 | Jesus Lara | Initial draft from the PR #633 review (Claude subagent + codex verification). |
| 0.2 | 2026-11-11 | Jesus Lara | Open questions resolved: defaults 5 s / 15 s; Module 9 (OAuth2 token `amr`); `password_reset` revokes sessions. Added G8, G9, D8, D9 and AC23–AC28. |
| 0.3 | 2026-11-11 | Codex | Resolve review findings: isolate OAuth assurance, revoke OAuth generations, enforce strict revocation, make recovery consumption transactional, fix email provider dispatch, and drain retired services safely. |
