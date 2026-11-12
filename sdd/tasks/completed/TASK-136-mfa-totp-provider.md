# TASK-136: TOTP provider — vault-sealed seed, pending enrollment, ±1 step, replay guard

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-131, TASK-132
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 3** (the TOTP half; the `AbstractOTPProvider` ABC
already landed in TASK-129, decision D3) plus the TOTP-specific parts of the
**§3 Security contracts** "Protected seed namespace" and "Pending enrollment
and replacement".

TOTP is the voluntary *strong* upgrade (spec §2 Overview): confirming it closes
the e-mail path for that user. That makes this module the one place a
long-lived shared secret is created, sealed, stored, read back during
verification and — on disenrolment — retired. Four properties carry the
security argument and each has a test:

1. **The active seed lives only in `auth.user_vault_secrets`, sealed by the
   vault kernel and AAD-bound** to `(user_id, provider, key)`, so a seed copied
   to another user fails to open (AC25-adjacent, `test_totp_seed_sealed_and_aad_bound`).
   Never `User.attributes` (plaintext JSONB, `models.py:61`).
2. **A pending seed never touches the active one.** Start-of-enrollment writes
   only a Redis record (via `MfaChallengeStore.put_enrollment`, TASK-131) sealed
   under a *pending* context bound to user, session hash, security version and
   enrollment-token hash, with a 300 s absolute TTL. Failure, expiry or
   abandonment leave the active factor usable (AC29).
3. **Verification fails CLOSED** (AC25, R5, R12): any vault, Postgres or Redis
   error raises `MfaStorageError`; the caller turns that into a refused login.
   The seed is opened with the `open_value` primitive and a lazily resolved
   `KeyRing` — never through `load_vault_for_session()`, which needs a session
   object that does not exist yet and is fail-open by contract
   (`vault/integration.py:50-99`).
4. **Exactly ±1 step and no replay** (AC13): `cryptography`'s `TOTP.verify()`
   checks a single step (verified by execution in the planning session:
   adjacent step rejected), so the provider walks `t-1, t, t+1` itself and then
   marks the accepted step used through `MfaChallengeStore.mark_totp_step()`.

**What this task does NOT do (D17):** it never takes the per-user lock, never
bumps the security version, never writes the audit row and never revokes
trusted devices. `confirm_enrollment()` and `disenroll()` write their rows on
the **caller's** connection so the handler (TASK-141 / TASK-142) can commit them
together with the bump, audit and revocation in one transaction.

**What this task DOES own — and the handler will NOT repeat.**
`confirm_enrollment()` is the single owner of two confirmation checks; TASK-141's
`confirm_totp` endpoint relies on them and does not re-implement them:

- **The enrolment failure budget** — every wrong code, wrong session or replayed
  step calls `MfaChallengeStore.register_enrollment_failure(token)`, which burns
  the pending record at the fifth failure without extending its TTL.
- **The pending `security_version` vs current-version check** — the pending
  record's version must equal `user_mfa_security.version` read on the caller's
  `conn` (inside the lock); a mismatch burns the pending record and returns
  `False`.

If either check were split across the provider and the handler, one side would
eventually drift; keeping both here means the handler only has to supply the
lock, the live-session check and the rate limit.

**D25 — no `conn.execute()` for DML.** asyncdb's `execute()` returns from inside
`finally` and never raises (verified by execution, see Codebase Contract). Every
write here goes through `fetchval(... RETURNING 1)`, so the seed upsert, the
`user_mfa` upsert and the soft-delete in `disenroll` fail closed (AC25).

---

## Scope

- Create `navigator_auth/mfa/totp.py` with the constants, the two vault
  contexts (`mfa_seed_context`, `pending_seed_context` — each defined once and
  used for both seal and open) and `TOTPProvider` exactly per the contract
  signatures below.
- `start_enrollment()`: generate a 20-byte seed, seal it under the pending
  context, persist it with `put_enrollment()`, return
  `{"enrollment_token", "uri", "secret_b32", "expires_in"}`.
- `confirm_enrollment()`: peek → validate user + session + security version →
  match code → mark step → single-use consume → install the active seed and the
  `user_mfa` row **on the caller's `conn`** → `True`.
- `verify()`: load + open the active seed (fail closed), walk ±1 step, reject a
  replayed step, best-effort `last_used_at` touch.
- `disenroll()`: soft-delete the seed row and disable the `user_mfa` row.
- `is_enrolled()`, `challenge()` (no-op), `match_step()`, lazy `_keyring()`.
- Write `tests/test_mfa_totp_provider.py`.

**NOT in scope**:
- HTTP endpoints, fresh-password / existing-factor proof for enrollment, the
  per-user lock, version bump, audit, trusted-device revocation, backup codes
  in the confirm response — TASK-141 (enroll/confirm/disenroll endpoints) and
  TASK-142 (admin disenrol).
- Rejecting `mfa:` keys in the general vault API and filtering them out of the
  session-vault loader — TASK-143.
- The challenge store, `put_enrollment`, `mark_totp_step` themselves — TASK-131.
- Deciding whether a user is TOTP-confirmed for the state machine — TASK-135
  (`MfaStateMachine.totp_confirmed`, its own SQL over `user_mfa`).
- Any edit to `navigator_auth/mfa/__init__.py` (contract: no later task edits it).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/totp.py` | CREATE | Constants, vault contexts, `TOTPProvider` |
| `tests/test_mfa_totp_provider.py` | CREATE | Unit + live (Redis/Postgres) tests for M3 |

---

## Codebase Contract

> Re-verified on `dev` @ `b10a3a3` (2026-11-11). External-package facts were
> verified by **executing** them in the project venv (see the evidence note in
> spec §6 — a file-lookup probe reports external packages as missing; that is
> not a refutation).

### Verified Imports

```python
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor import InvalidToken
from cryptography.hazmat.primitives.twofactor.totp import TOTP
#   TOTP(key, length, algorithm, time_step, backend=None, enforce_key_length=True)  — executed
#   TOTP.verify(totp: bytes, time: int) -> None, raises InvalidToken; ONE step only  — executed
#   TOTP.get_provisioning_uri(account_name, issuer) ->
#     "otpauth://totp/Navigator:alice?digits=6&secret=<B32>&algorithm=SHA1&issuer=Navigator&period=30"  — executed
from navigator_session.vault import KeyRing, VaultContext, VaultCryptoError, open_value, seal_value
#   seal_value(value, context, keyring, *, session_uuid=None, key_id=None) -> bytes        — executed
#   open_value(blob, context, keyring, *, session_uuid=None) -> Any                         — executed
#   VaultContext(*, purpose: str, layer: Literal["db","session"], fields: tuple[tuple[str, Any], ...])
#   seal_value(os.urandom(20), ctx, kr) round-trips to bytes; opening with another user_id
#   in the context raises VaultIntegrityError (a VaultCryptoError subclass)                 — executed
#   KeyRing(master_keys: Mapping[int, bytes], active_key_id: int, *, cipher_backend="aesgcm", naming_key_id=None)
#   KeyRing.active_key_id (property)                                                        — executed
from navigator_auth.conf import AUTH_DB_SCHEMA                   # conf.py:33
from navigator_auth.conf import AUTH_TOTP_ISSUER                 # created by TASK-129 (fallback "Navigator")
from navigator_auth.vault.integration import VAULT_KEYRING_APP_KEY  # integration.py:26 == "vault_keyring"
from navigator_auth.mfa.abstract import AbstractOTPProvider      # TASK-129
from navigator_auth.mfa.exceptions import MfaStorageError        # TASK-129
from navigator_auth.mfa.store import ENROLLMENT_TTL, MfaChallengeStore, _hash_token, new_opaque_token  # TASK-131
from navigator_auth.mfa.types import EnrollmentAuthorization, MfaChallenge, PROVIDER_TOTP, PendingEnrollment  # TASK-129
```

Stdlib only otherwise: `base64`, `logging`, `os`, `time`, `typing`.
`aiohttp.web` is needed only for the `web.Request` annotation (`from aiohttp import web`, already a hard dependency).

### Contract signatures this task implements (from the shared contract §3, TASK-136)

```python
def mfa_seed_context(user_id: int, provider: str = PROVIDER_TOTP, key: str = TOTP_VAULT_KEY) -> VaultContext
def pending_seed_context(*, user_id: int, session_hash: str, security_version: int, enrollment_hash: str) -> VaultContext
class TOTPProvider(AbstractOTPProvider):    # _provider_name="totp", _is_strong=True
    def __init__(self, *, app: Any, db_pool: Any, store: MfaChallengeStore, issuer: str = AUTH_TOTP_ISSUER, clock: Callable[[], float] = time.time)
    def _keyring(self) -> KeyRing
    async def is_enrolled(self, user) -> bool
    async def start_enrollment(self, user, authorization) -> dict
    async def confirm_enrollment(self, user, code, enrollment_token, session_id, *, conn=None) -> bool
    async def challenge(self, request, user) -> dict
    async def verify(self, request, user, code, challenge=None) -> bool
    async def disenroll(self, user, *, conn=None) -> None
    def match_step(self, seed: bytes, code: str, now: float) -> Optional[int]
```

### Upstream signatures this task calls (TASK-129 / TASK-131 / TASK-130)

```python
# navigator_auth/mfa/abstract.py (TASK-129) — the ABC, D4 extensions included
class AbstractOTPProvider(ABC):
    async def is_enrolled(self, user: Mapping) -> bool
    async def start_enrollment(self, user: Mapping, authorization: EnrollmentAuthorization) -> dict
    async def confirm_enrollment(self, user: Mapping, code: str, enrollment_token: str, session_id: str, *, conn: Any = None) -> bool
    async def challenge(self, request: web.Request, user: Mapping) -> dict
    async def verify(self, request: web.Request, user: Mapping, code: str, challenge: Optional[MfaChallenge] = None) -> bool
    async def disenroll(self, user: Mapping, *, conn: Any = None) -> None

# navigator_auth/mfa/store.py (TASK-131)
ENROLLMENT_TTL = 300
def _hash_token(token: str) -> str                    # sha256 hex
def new_opaque_token() -> str                         # secrets.token_urlsafe(32)
class MfaChallengeStore:
    async def mark_totp_step(self, user_id: int, step: int, ttl: int) -> bool   # SET NX EX; False = replay
    async def put_enrollment(self, token: str, *, user_id: int, session_id: str, security_version: int, sealed_seed: bytes) -> PendingEnrollment
    async def peek_enrollment(self, token: str) -> Optional[PendingEnrollment]
    async def consume_enrollment(self, token: str) -> Optional[PendingEnrollment]
    async def register_enrollment_failure(self, token: str) -> int
    # every Redis error ⇒ MfaStorageError; None only means absent/expired/tampered

# navigator_auth/mfa/types.py (TASK-129)
class EnrollmentAuthorization(MfaModel):  user_id: int; session_id: str (repr=False); security_version: int; context_digest: str; expires_at: datetime
class PendingEnrollment(MfaModel): user_id: int; session_hash: str; security_version: int; sealed_seed: str (repr=False, base64); issued_at: float; signature: str
```

**Cross-task assumption to check first (Step 1):** `put_enrollment()` derives
`PendingEnrollment.session_hash` as `_hash_token(session_id)` and stores
`sealed_seed` as `base64.b64encode(bytes).decode()`. This task builds the
pending context with the same `_hash_token()` and decodes with `b64decode`. If
TASK-131 landed differently, align **here**, not there.

### Tables this task reads/writes

```sql
-- navigator_auth/vault/sql/001_create_vault_tables.sql:11-25 — HARD-CODED to schema `auth`
auth.user_vault_secrets (id uuid PK, user_id INTEGER FK, key VARCHAR(255), ciphertext_db BYTEA,
                         key_version SMALLINT DEFAULT 1, created_at, updated_at, deleted_at TIMESTAMPTZ)
UNIQUE INDEX idx_vault_active_unique ON (user_id, key) WHERE deleted_at IS NULL
-- the vault kernel's own upsert (navigator_session 1.1.1 session_vault.py `_UPSERT_SECRET`):
--   INSERT INTO auth.user_vault_secrets (user_id, key, ciphertext_db, key_version) VALUES ($1,$2,$3,$4)
--   ON CONFLICT (user_id, key) WHERE deleted_at IS NULL
--   DO UPDATE SET ciphertext_db = EXCLUDED.ciphertext_db, key_version = EXCLUDED.key_version, updated_at = NOW()

-- TASK-130 DDL (schema = AUTH_DB_SCHEMA)
{schema}.user_mfa (user_id bigint, provider varchar(16), enabled boolean DEFAULT false,
                   confirmed_at timestamptz, created_at, last_used_at, PRIMARY KEY (user_id, provider))
{schema}.user_mfa_security (user_id bigint PK, version bigint NOT NULL DEFAULT 0, updated_at)
```

The vault table does **not** follow `AUTH_DB_SCHEMA` (the vault kernel and its
migration both hard-code `auth.`), so the seed uses the literal
`auth.user_vault_secrets`; the MFA tables use `AUTH_DB_SCHEMA`.

### asyncdb gotcha — `execute()` never raises (contract D25; verified by execution, 2026-11-11)

`asyncdb.drivers.pg.pg.execute` has `return await self._serializer(...)` inside
`finally:` (`.venv/.../asyncdb/drivers/pg.py:937-973`), which **swallows every
exception**: an INSERT into a missing table returned `[None, UndefinedTableError]`
without raising. `fetchval()` / `fetch_one()` raise (`StatementError`,
`ProviderError`). Every write in this module therefore uses
`conn.fetchval("… RETURNING 1", …)` (or the CTE count idiom
`WITH d AS (UPDATE … RETURNING 1) SELECT count(*) FROM d`) so a failed write
raises and the caller's transaction rolls back — a silently "successful" seed
install would be a factor the user believes they have and the database does
not. `conn.execute(` must not appear in `navigator_auth/mfa/totp.py` at all.
(Also: `fetch_all` returns `None`, not `[]`, when there are no rows — this
module does not use it.)

Pool / connection pattern (verified `navigator_auth/passkey/store.py:44-61`):
`async with await self._db.acquire() as conn:` then `conn.fetch_one(sql, *args)`,
`conn.fetchval(sql, *args)`. Rows support `row["column"]`.

### Lazy keyring — startup ordering (R13)

`AuthHandler.auth_startup()` runs every `backend.on_startup(app)` at
`auth.py:181-186` and only then `setup_vault_keyring(app)` at `auth.py:188`,
which stores the ring under `app["vault_keyring"]` (`integration.py:29-47`, may
be absent when vault keys are not configured). A provider built during
`on_startup` that captured the keyring would hold `None` forever, so
`_keyring()` reads `app.get(VAULT_KEYRING_APP_KEY)` on **every** call.

### Does NOT Exist (Anti-Hallucination)

- ~~`pyotp`~~, ~~`qrcode`~~ — not installed, must not be added (AC4). The QR is rendered client-side from `uri`.
- ~~`TOTP.verify(..., window=…)`~~ / any skew parameter in `cryptography` — it checks exactly one step.
- ~~`load_vault_for_session()` / `SessionVault` for the seed~~ — forbidden (R12): needs a session, fail-open.
- ~~`IdentityCipher` for the seed~~ — it binds `purpose="identity"` contexts for identity tokens; the seed uses its own `purpose="mfa"` context.
- ~~`{schema}.user_vault_secrets`~~ — the vault table is `auth.user_vault_secrets` literally.
- ~~`MfaSecurity` / `TrustedDeviceStore` inside this provider~~ — D17: providers never lock, bump, audit or revoke.
- ~~`User.attributes["totp"]`~~ — never; plaintext JSONB.
- ~~a `delete` of the seed row~~ — retire it with `deleted_at = now()` (the vault's soft-delete convention, partial unique index).

---

## Implementation Blueprint

> **D5 — AC5 grep.** Nothing under `navigator_auth/mfa/` may contain the
> identifiers `open_session`, `create_token` or `remember(` — not even in a
> docstring or comment. `grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/totp.py`
> must print nothing. Say "the session-minting methods" if you need the idea.

### `navigator_auth/mfa/totp.py` — CREATE (four blocks, written in order)

**Block 1 of 4 — module header, constants, contexts, field helper:**

```python
"""TOTP second factor (RFC 6238) for BasicAuth — FEAT-106, spec Module 3.

Google-Authenticator-compatible and fixed at SHA1 / 6 digits / 30 s, because
the app ignores anything else. Built on ``cryptography`` — no new dependency.

The ACTIVE seed is sealed by the vault kernel under ``TOTP_VAULT_KEY`` in
``auth.user_vault_secrets``, AAD-bound to (user_id, provider, key), so a seed
copied to another user fails to open. It is never stored in
``User.attributes``. A PENDING seed lives only in Redis, sealed under a
context bound to the user, the enrolling session, the security version and
the enrollment token, for ``ENROLLMENT_TTL`` seconds.

This module is a factor, not a backend: it answers True/False and holds no
reference to the session-minting methods of any backend.
"""
import base64
import logging
import os
import time
from collections.abc import Mapping
from typing import Any, Callable, Optional

from aiohttp import web
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor import InvalidToken
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from navigator_session.vault import KeyRing, VaultContext, VaultCryptoError, open_value, seal_value

from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_TOTP_ISSUER
from navigator_auth.vault.integration import VAULT_KEYRING_APP_KEY

from .abstract import AbstractOTPProvider
from .exceptions import MfaStorageError
from .store import ENROLLMENT_TTL, MfaChallengeStore, _hash_token, new_opaque_token
from .types import PROVIDER_TOTP, EnrollmentAuthorization, MfaChallenge, PendingEnrollment

logger = logging.getLogger("navigator.mfa")

TOTP_VAULT_KEY = "mfa:totp"
TOTP_DIGITS, TOTP_PERIOD, TOTP_SKEW_STEPS = 6, 30, 1
TOTP_SEED_BYTES = 20
MFA_SEED_PURPOSE = "mfa"
MFA_PENDING_PURPOSE = "mfa-pending"
#: A step stays acceptable while the current counter is step-1..step+1
#: (~90 s); one extra period of margin so a replay can never slip past expiry.
REPLAY_TTL = TOTP_PERIOD * (2 * TOTP_SKEW_STEPS + 2)
#: Hard-coded by the vault kernel and its migration — NOT AUTH_DB_SCHEMA.
VAULT_SECRETS_TABLE = "auth.user_vault_secrets"
USER_MFA_TABLE = f"{AUTH_DB_SCHEMA}.user_mfa"
SECURITY_TABLE = f"{AUTH_DB_SCHEMA}.user_mfa_security"


def mfa_seed_context(user_id: int, provider: str = PROVIDER_TOTP, key: str = TOTP_VAULT_KEY) -> VaultContext:
    """AAD context of an ACTIVE seed. The single definition for seal AND open."""
    return VaultContext(
        purpose=MFA_SEED_PURPOSE,
        layer="db",
        fields=(("user_id", int(user_id)), ("provider", provider), ("key", key)),
    )


def pending_seed_context(
    *, user_id: int, session_hash: str, security_version: int, enrollment_hash: str
) -> VaultContext:
    """AAD context of a PENDING seed: user + session + version + token bound."""
    return VaultContext(
        purpose=MFA_PENDING_PURPOSE,
        layer="db",
        fields=(
            ("user_id", int(user_id)),
            ("session", session_hash),
            ("version", int(security_version)),
            ("enrollment", enrollment_hash),
        ),
    )


def _field(user: Any, name: str, default: Any = None) -> Any:
    """Read a field from a dict OR a datamodel ``Model`` user record."""
    # FILL IN: try user[name], then user.get(name), then getattr(user, name);
    #  return default on KeyError/AttributeError/TypeError — bounded by the
    #  contract note "User records may be dict OR datamodel Model".
```

**Why.** The two context builders are the *only* place a `VaultContext` for
MFA is constructed, so seal and open can never disagree (spec security
contract: "define it once for both seal and open"). `purpose="mfa"` is distinct
from the vault's `"user-vault"` and identity's `"identity"`, which is what makes
the generic session-vault loader unable to open a seed row even if TASK-143's
filter were bypassed. `REPLAY_TTL` is derived, not a magic number: the marker
must outlive the last instant the step could still be accepted.

**Block 2 of 4 — class, lazy keyring, step matching, seed/version reads:**

```python
class TOTPProvider(AbstractOTPProvider):
    """Google-Authenticator-compatible TOTP factor. Strong: closes the e-mail path."""

    _provider_name = PROVIDER_TOTP
    _is_strong = True

    def __init__(
        self,
        *,
        app: Any,
        db_pool: Any,
        store: MfaChallengeStore,
        issuer: str = AUTH_TOTP_ISSUER,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._app = app
        self._db = db_pool
        self._store = store
        self._issuer = issuer
        self._clock = clock
        self.logger = logger

    def _keyring(self) -> KeyRing:
        """Resolve the vault KeyRing LAZILY from ``app[VAULT_KEYRING_APP_KEY]``.

        Never captured at construction: auth_startup() runs every backend's
        startup hook BEFORE setup_vault_keyring(app) (auth.py:181 then :188).
        A missing ring is a storage failure — verification fails CLOSED.
        """
        keyring = self._app.get(VAULT_KEYRING_APP_KEY) if self._app is not None else None
        if keyring is None:
            raise MfaStorageError("vault keyring unavailable")
        return keyring

    @staticmethod
    def _totp(seed: bytes) -> TOTP:
        return TOTP(seed, TOTP_DIGITS, SHA1(), TOTP_PERIOD)

    def match_step(self, seed: bytes, code: str, now: float) -> Optional[int]:
        """Return the accepted step counter for ``code`` in t-1..t+1, else None.

        ``TOTP.verify()`` validates exactly ONE step, so the skew window is
        walked here.
        """
        if not isinstance(code, str):
            return None
        code = code.strip()
        if len(code) != TOTP_DIGITS or not code.isdigit():
            return None
        totp = self._totp(seed)
        counter = int(now) // TOTP_PERIOD
        for step in range(counter - TOTP_SKEW_STEPS, counter + TOTP_SKEW_STEPS + 1):
            try:
                totp.verify(code.encode("ascii"), step * TOTP_PERIOD)
            except InvalidToken:
                continue
            return step
        return None

    async def _load_seed(self, user_id: int) -> Optional[bytes]:
        """Open the ACTIVE seed. None = no active seed. Any failure ⇒ MfaStorageError."""
        try:
            async with await self._db.acquire() as conn:
                row = await conn.fetch_one(
                    f"SELECT ciphertext_db FROM {VAULT_SECRETS_TABLE} "
                    "WHERE user_id = $1 AND key = $2 AND deleted_at IS NULL",
                    user_id,
                    TOTP_VAULT_KEY,
                )
        except Exception as err:  # noqa: BLE001 - fail closed on ANY storage error (AC25)
            raise MfaStorageError(f"totp seed read failed: {type(err).__name__}") from err
        if not row:
            return None
        try:
            seed = open_value(bytes(row["ciphertext_db"]), mfa_seed_context(user_id), self._keyring())
        except VaultCryptoError as err:
            raise MfaStorageError(f"totp seed unusable: {type(err).__name__}") from err
        # FILL IN: reject a non-bytes or wrong-length plaintext with
        #  MfaStorageError (never fall through to "no factor") — bounded by AC25.
        return seed

    async def _current_version(self, conn: Any, user_id: int) -> int:
        """Read ``user_mfa_security.version`` (absent row ⇒ 0, as MfaSecurity seeds it)."""
        version = await conn.fetchval(f"SELECT version FROM {SECURITY_TABLE} WHERE user_id = $1", user_id)
        return int(version or 0)
```

**Why.** `_load_seed` distinguishes **"no active seed"** (`None` → the code is
simply wrong, the attempt is counted) from **"could not find out"**
(`MfaStorageError` → the login is refused). Collapsing the two would turn a
Postgres or keyring outage into "this user has no TOTP", which the state
machine would read as "offer e-mail" — a silent downgrade, i.e. the fail-open
posture R5 forbids. Exception messages carry only the class name: a driver
error string can echo bound parameters.

`_current_version` is a plain read of TASK-130's table with the same
"absent row means 0" semantics `MfaSecurity.current_version()` (TASK-132)
establishes. It is a read, so it does not cross D17's line (providers never
*bump*); constructing an `MfaSecurity` here just to read one integer would
couple the provider to the HMAC secret for nothing.

**Block 3 of 4 — enrollment status, start, challenge, confirm:**

```python
    async def is_enrolled(self, user: Mapping) -> bool:
        """True when TOTP is confirmed AND an active sealed seed exists."""
        # FILL IN: one connection; SELECT enabled AND confirmed_at IS NOT NULL
        #  from USER_MFA_TABLE (provider = PROVIDER_TOTP) and EXISTS an active
        #  VAULT_SECRETS_TABLE row for TOTP_VAULT_KEY; both must hold. Any
        #  storage error ⇒ MfaStorageError, never False — bounded by R5 (an
        #  error read as "not enrolled" would reopen the e-mail path).

    async def start_enrollment(self, user: Mapping, authorization: EnrollmentAuthorization) -> dict:
        """Create a sealed, session-bound PENDING seed. Never touches the active seed."""
        user_id = int(_field(user, "user_id"))
        # FILL IN: refuse (ValueError) when authorization.user_id != user_id or
        #  authorization.expires_at is in the past (tz-aware compare) — the
        #  authorization is built server-side by TASK-141 after fresh password
        #  proof; a mismatch is a programming error, not a client error.
        seed = os.urandom(TOTP_SEED_BYTES)
        token = new_opaque_token()
        context = pending_seed_context(
            user_id=user_id,
            session_hash=_hash_token(authorization.session_id),
            security_version=authorization.security_version,
            enrollment_hash=_hash_token(token),
        )
        sealed = seal_value(seed, context, self._keyring())
        await self._store.put_enrollment(
            token,
            user_id=user_id,
            session_id=authorization.session_id,
            security_version=authorization.security_version,
            sealed_seed=sealed,
        )
        account = str(_field(user, "username") or user_id)
        uri = self._totp(seed).get_provisioning_uri(account, self._issuer)
        secret_b32 = base64.b32encode(seed).decode("ascii").rstrip("=")
        self.logger.info("MFA: TOTP enrollment started for user_id=%s", user_id)
        return {"enrollment_token": token, "uri": uri, "secret_b32": secret_b32, "expires_in": ENROLLMENT_TTL}

    async def challenge(self, request: web.Request, user: Mapping) -> dict:
        """No-op: the authenticator app is the delivery channel."""
        return {}

    async def confirm_enrollment(
        self, user: Mapping, code: str, enrollment_token: str, session_id: str, *, conn: Any = None
    ) -> bool:
        """Install the pending seed — only on a working code, only once.

        MUST run on the caller's connection inside MfaSecurity.user_lock(): the
        seed row and the user_mfa row are written on ``conn`` so they commit or
        roll back with the caller's version bump, audit row and trusted-device
        revocation (D17). Never bumps, audits or revokes here.
        """
        if conn is None:
            raise ValueError("confirm_enrollment requires the caller's lock transaction (conn)")
        # This method OWNS the enrolment failure budget and the pending
        # security_version check; the confirm endpoint (TASK-141) does not repeat them.
        user_id = int(_field(user, "user_id"))
        pending = await self._store.peek_enrollment(enrollment_token)
        if pending is None:
            return False
        if pending.user_id != user_id or pending.session_hash != _hash_token(session_id):
            await self._store.register_enrollment_failure(enrollment_token)
            return False
        if await self._current_version(conn, user_id) != pending.security_version:
            # FILL IN: burn the pending record (consume_enrollment) and return
            #  False — bounded by the spec contract "unchanged security context":
            #  a password change / recovery since start must kill the enrolment.
            ...
        seed = self._open_pending(pending, enrollment_token)
        step = self.match_step(seed, code, self._clock())
        if step is None or not await self._store.mark_totp_step(user_id, step, REPLAY_TTL):
            await self._store.register_enrollment_failure(enrollment_token)
            return False
        consumed = await self._store.consume_enrollment(enrollment_token)
        if consumed is None or consumed != pending:
            return False
        await self._install_seed(conn, user_id, seed)
        self.logger.info("MFA: TOTP enrollment confirmed for user_id=%s", user_id)
        return True
```

**Why — ordering inside `confirm_enrollment`.** Each step is there for a named
contract clause: the session-hash check makes the enrollment token useless
outside the session that started it ("requires the same live session"); the
version check kills an enrolment that predates a password change or recovery;
`mark_totp_step` **before** consume means the code used to confirm can never be
replayed for an immediate login ("Confirmation marks its accepted TOTP step as
used"); `consume_enrollment` + the `consumed != pending` equality is the
single-use gate — under the caller's lock two confirmations are already
serialized, and the GETDEL guarantees only one ever reaches `_install_seed`.
Wrong-session and wrong-code both count against the five-attempt enrolment
budget; the store burns the record at the limit and never extends its TTL.
`secret_b32` and `uri` appear only in the return value (AC14 allows them in the
freshly re-authenticated enrollment response) — never in a log line.

**Block 4 of 4 — verify, disenroll, pending open, seed install:**

```python
    async def verify(
        self, request: web.Request, user: Mapping, code: str, challenge: Optional[MfaChallenge] = None
    ) -> bool:
        """Verify a login code against the ACTIVE seed. Fails CLOSED (raises) on storage errors.

        Needs no session: the seed is opened with the vault primitives and a
        lazily resolved KeyRing, never through the session-vault loader (R12).
        """
        user_id = int(_field(user, "user_id"))
        seed = await self._load_seed(user_id)          # MfaStorageError propagates
        if seed is None:
            return False
        step = self.match_step(seed, code, self._clock())
        if step is None:
            return False
        if not await self._store.mark_totp_step(user_id, step, REPLAY_TTL):   # MfaStorageError propagates
            self.logger.warning("MFA: replayed TOTP step rejected for user_id=%s", user_id)
            return False
        # FILL IN: best-effort `fetchval("UPDATE USER_MFA_TABLE SET last_used_at = now()
        #  WHERE user_id=$1 AND provider=$2 RETURNING 1", …)` on its own pooled
        #  connection (never execute() — D25); log WARNING (class name only) on
        #  error and still return True — telemetry, not a security decision.
        return True

    async def disenroll(self, user: Mapping, *, conn: Any = None) -> None:
        """Retire the active seed (soft delete) and disable the user_mfa row.

        Pass the caller's lock-transaction ``conn`` so the change commits with
        the version bump, audit and revocation (D17). Without ``conn`` a pooled
        connection is used.
        """
        user_id = int(_field(user, "user_id"))
        # FILL IN: on `conn` (or a pooled one when None), with fetchval so
        #  failures RAISE (asyncdb execute() swallows errors):
        #    UPDATE VAULT_SECRETS_TABLE SET deleted_at = now()
        #      WHERE user_id=$1 AND key=TOTP_VAULT_KEY AND deleted_at IS NULL RETURNING 1
        #    UPDATE USER_MFA_TABLE SET enabled = false, confirmed_at = NULL
        #      WHERE user_id=$1 AND provider=PROVIDER_TOTP RETURNING 1
        #  A missing row is not an error (idempotent) — bounded by AC23/AC16
        #  (the caller audits the transition; this method only changes state).

    def _open_pending(self, pending: PendingEnrollment, token: str) -> bytes:
        context = pending_seed_context(
            user_id=pending.user_id,
            session_hash=pending.session_hash,
            security_version=pending.security_version,
            enrollment_hash=_hash_token(token),
        )
        try:
            return open_value(base64.b64decode(pending.sealed_seed), context, self._keyring())
        except (VaultCryptoError, ValueError) as err:   # binascii.Error is a ValueError
            raise MfaStorageError(f"pending seed unusable: {type(err).__name__}") from err

    async def _install_seed(self, conn: Any, user_id: int, seed: bytes) -> None:
        """Seal under the ACTIVE context and upsert seed + confirmed state on ``conn``."""
        keyring = self._keyring()
        ciphertext = seal_value(seed, mfa_seed_context(user_id), keyring)
        await conn.fetchval(
            f"INSERT INTO {VAULT_SECRETS_TABLE} (user_id, key, ciphertext_db, key_version) "
            "VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, key) WHERE deleted_at IS NULL "
            "DO UPDATE SET ciphertext_db = EXCLUDED.ciphertext_db, "
            "key_version = EXCLUDED.key_version, updated_at = NOW() RETURNING 1",
            user_id,
            TOTP_VAULT_KEY,
            ciphertext,
            keyring.active_key_id,
        )
        await conn.fetchval(
            f"INSERT INTO {USER_MFA_TABLE} (user_id, provider, enabled, confirmed_at) "
            "VALUES ($1, $2, true, now()) ON CONFLICT (user_id, provider) "
            "DO UPDATE SET enabled = true, confirmed_at = now() RETURNING 1",
            user_id,
            PROVIDER_TOTP,
        )
```

**Why — `fetchval(... RETURNING 1)` instead of `execute()`.** Verified by
execution: asyncdb's `execute()` returns `[None, UndefinedTableError]` instead
of raising. A swallowed failure in `_install_seed` would let the handler bump
the version, audit "confirmed" and return backup codes for a factor that was
never stored — the user would then be challenged for a TOTP the server cannot
verify, or worse, the state machine would see `user_mfa` confirmed without a
seed. `fetchval` raises, the caller's transaction rolls back, and the pending
record is already consumed, so the user simply restarts enrolment.

The upsert is the vault kernel's own shape (`ON CONFLICT (user_id, key) WHERE
deleted_at IS NULL`), so the partial unique index is honoured and a confirmed
**replacement** overwrites the previous active seed only at this point — the
only point the spec allows ("Never modify the active seed at start or on
failure").

### `tests/test_mfa_totp_provider.py` — CREATE

```python
"""FEAT-106 Module 3 — TOTPProvider (spec §4 M3 rows, AC13, AC25, AC29)."""
import base64
import os
from urllib.parse import parse_qs, urlparse

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from navigator_session.vault import KeyRing, VaultCryptoError, open_value, seal_value

from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.security import MfaSecurity
from navigator_auth.mfa.store import MfaChallengeStore
from navigator_auth.mfa.totp import (
    TOTP_VAULT_KEY, TOTPProvider, mfa_seed_context, pending_seed_context,
)
from navigator_auth.mfa.types import EnrollmentAuthorization
from navigator_auth.vault.integration import VAULT_KEYRING_APP_KEY
from tests.fixtures.mfa import (  # noqa: F401
    frozen_totp_clock, mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory,
)

NOW = 1_700_000_010          # mid-step: counter 56666667, 10 s into the period


@pytest.fixture
def keyring():
    return KeyRing({1: b"\x00" * 32}, 1)


@pytest.fixture
def provider(keyring, mfa_db, mfa_redis_pool, mfa_secret):
    store = MfaChallengeStore(mfa_redis_pool, secret=mfa_secret)
    return TOTPProvider(app={VAULT_KEYRING_APP_KEY: keyring}, db_pool=mfa_db, store=store, clock=lambda: NOW)


def code_at(seed: bytes, t: int) -> str:
    return TOTP(seed, 6, SHA1(), 30).generate(t).decode()

# FILL IN helpers: `enroll(provider, user, security)` that runs start_enrollment
#  with an EnrollmentAuthorization (session_id="s-1", version from
#  MfaSecurity.current_version) and confirm_enrollment inside
#  MfaSecurity(mfa_db, mfa_secret).user_lock(user_id), returning the seed
#  (decode secret_b32 with base64.b32decode + "=" padding).


class TestStepWindow:
    def test_totp_accepts_skew_window(self, provider):
        """Codes for t-30, t, t+30 all verify (AC13)."""
        # FILL IN: seed=os.urandom(20); match_step(seed, code_at(seed, NOW+d), NOW) is not None for d in (-30, 0, 30)

    def test_totp_rejects_outside_window(self, provider):
        """t-60 / t+60 are rejected (AC13: ±2 steps refused)."""
        # FILL IN

    def test_totp_rejects_malformed_codes(self, provider):
        # FILL IN: "", "12345", "1234567", "abcdef", None → None


class TestVerify:
    @pytest.mark.asyncio
    async def test_totp_replay_rejected(self, provider, mfa_user_factory):
        """Same code twice inside its window fails the second time (AC13)."""
        # FILL IN: enroll, verify(code) True, verify(same code) False

    @pytest.mark.asyncio
    async def test_totp_seed_read_without_session(self, provider, mfa_user_factory):
        """Verification opens the seed with no session in existence (AC25)."""
        # FILL IN: verify(request=None, ...) is True after enrolment

    @pytest.mark.asyncio
    async def test_totp_verify_fails_closed_without_keyring(self, mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory):
        """No keyring ⇒ MfaStorageError, never False/True (AC25, R13)."""
        # FILL IN: provider with app={} ; enrolled seed row present ⇒ pytest.raises(MfaStorageError)

    @pytest.mark.asyncio
    async def test_totp_verify_fails_closed_on_redis_error(self, keyring, mfa_db, mfa_secret, mfa_user_factory):
        """Unreachable Redis for the replay guard ⇒ MfaStorageError (AC12)."""
        # FILL IN: store over an unreachable pool (socket_connect_timeout=1)


class TestSeedStorage:
    def test_totp_seed_sealed_and_aad_bound(self, keyring):
        """A seed sealed for user A does not open under user B's context."""
        # FILL IN: seal_value(seed, mfa_seed_context(1), keyring); open_value(..., mfa_seed_context(2), keyring) raises VaultCryptoError

    @pytest.mark.asyncio
    async def test_totp_seed_never_in_user_attributes(self, provider, mfa_db, mfa_user_factory):
        """auth.users.attributes is byte-identical before/after enrolment."""
        # FILL IN

    @pytest.mark.asyncio
    async def test_totp_uri_is_google_authenticator_compatible(self, provider, mfa_user_factory, keyring):
        """otpauth:// carries algorithm=SHA1, digits=6, period=30 and the issuer."""
        # FILL IN: parse_qs(urlparse(uri).query); also secret_b32 has no '=' padding


class TestPendingEnrollment:
    @pytest.mark.asyncio
    async def test_totp_pending_seed_isolated(self, provider, mfa_db, mfa_secret, mfa_user_factory, keyring):
        """Start, failed confirmation and a version change never replace the active seed (AC29)."""
        # FILL IN: enrolled user (seed S1); start a 2nd enrolment (S2); wrong code ⇒ False and
        #  S1 still verifies; bump version via MfaSecurity.bump_version ⇒ confirm with a valid S2
        #  code is False; pending ciphertext does not open under a context with another
        #  session_hash/version (pending_seed_context).

    @pytest.mark.asyncio
    async def test_totp_confirmation_single_use(self, provider, mfa_db, mfa_secret, mfa_user_factory):
        """A consumed enrollment token cannot confirm twice; the accepted step is marked used."""
        # FILL IN: confirm ⇒ True; confirm again with the same token ⇒ False; verify(same code) ⇒ False

    @pytest.mark.asyncio
    async def test_confirm_rejects_other_session(self, provider, mfa_db, mfa_secret, mfa_user_factory):
        # FILL IN: confirm with session_id="other" ⇒ False

    @pytest.mark.asyncio
    async def test_confirm_requires_conn(self, provider, mfa_user_factory):
        # FILL IN: conn=None ⇒ ValueError

    @pytest.mark.asyncio
    async def test_disenroll_retires_seed(self, provider, mfa_db, mfa_secret, mfa_user_factory):
        # FILL IN: after disenroll(conn=…) is_enrolled False and verify False (no row, not an error)
```

**Why live Redis + Postgres.** The properties under test are storage
properties (single-use GETDEL, `SET NX` replay marker, the vault's partial
unique index, AAD binding against real ciphertext). Redis is live at
`REDIS_AUTH_URL` and Postgres at `conf.default_dsn` (both verified
2026-11-11); `mfa_db` skips cleanly when Postgres is unreachable. The fixtures
come from `tests/fixtures/mfa.py` (TASK-130, reached through TASK-132).

### Steps (in order)

1. Confirm TASK-129, TASK-130, TASK-131 and TASK-132 are in
   `sdd/tasks/completed/`. Open `navigator_auth/mfa/store.py` and check the
   cross-task assumption: `put_enrollment` sets `session_hash=_hash_token(session_id)`
   and `sealed_seed=base64.b64encode(...).decode()`. Align `_open_pending` /
   `start_enrollment` if not.
2. Write Block 1, fill `_field`. Run `python -c "import navigator_auth.mfa.totp"`.
3. Write Block 2; fill the `_load_seed` plaintext check.
4. Write Block 3; fill `is_enrolled`, the authorization guard and the
   version-mismatch burn.
5. Write Block 4; fill the `last_used_at` touch and `disenroll`. Use
   `fetchval(... RETURNING 1)` for every write — never `execute()` (asyncdb
   swallows its errors).
6. Run the D5 grep: `grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/totp.py` → nothing;
   and the D25 grep: `grep -n "\.execute(" navigator_auth/mfa/totp.py` → nothing.
7. Write the tests; run them; then `ruff check navigator_auth/mfa/totp.py tests/test_mfa_totp_provider.py`.
8. Confirm no log line contains a seed, URI, code or token:
   `grep -n "logger\.\|self.logger\." navigator_auth/mfa/totp.py` and read every call.

### FILL IN checklist

- [ ] `_field` — dict / `.get` / attribute access with default
- [ ] `_load_seed` — non-bytes / wrong-length plaintext ⇒ `MfaStorageError` (AC25)
- [ ] `is_enrolled` — confirmed AND active seed; storage error raises (R5)
- [ ] `start_enrollment` — authorization user/expiry guard (ValueError)
- [ ] `confirm_enrollment` — version mismatch burns the pending record, returns False
- [ ] `verify` — best-effort `last_used_at`, WARNING on failure, still True
- [ ] `disenroll` — two `fetchval … RETURNING 1` updates, idempotent
- [ ] Test helper `enroll(...)` and every test body above

---

## Acceptance Criteria

- [ ] **AC-1** `navigator_auth/mfa/totp.py` exposes the contract signatures exactly (constants, `mfa_seed_context`, `pending_seed_context`, `TOTPProvider` with `_provider_name="totp"`, `_is_strong=True`).
- [ ] **AC-2** `match_step` accepts codes for t-30, t, t+30 and rejects t±60 and malformed input (closes spec **AC13** skew half).
- [ ] **AC-3** A step accepted once is rejected on reuse within its window, at login and right after confirmation (closes spec **AC13** replay half).
- [ ] **AC-4** The active seed is stored only as `seal_value` ciphertext in `auth.user_vault_secrets` under `mfa:totp`, AAD-bound to `(user_id, "totp", "mfa:totp")`; `auth.users.attributes` is unchanged by enrolment.
- [ ] **AC-5** `verify` works with `request=None` and no session; a missing keyring, a vault integrity error, a Postgres error or a Redis error raises `MfaStorageError` (closes spec **AC25**, contributes to **AC12**).
- [ ] **AC-6** `start_enrollment` writes nothing to Postgres; a failed, expired, version-stale or other-session confirmation leaves the active seed verifying (closes the provider half of spec **AC29**).
- [ ] **AC-7** `confirm_enrollment` refuses `conn=None`, is single-use, and writes the seed + `user_mfa` rows only on the caller's `conn` with raising writes; it performs no bump, audit or revocation (D17).
- [ ] **AC-8** The provisioning URI carries `algorithm=SHA1`, `digits=6`, `period=30` and the issuer; no new dependency (spec **AC4**).
- [ ] **AC-9** `grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/totp.py` prints nothing (D5 / spec **AC5**).
- [ ] **AC-9b** `grep -rn "\.execute(" navigator_auth/mfa/` shows nothing except `navigator_auth/mfa/migrations.py` (D25); every write in `totp.py` is a raising `fetchval … RETURNING`.
- [ ] **AC-9c** `confirm_enrollment` alone enforces the enrolment failure budget and the pending-vs-current `security_version` check (the TASK-141 handler does not repeat them).
- [ ] **AC-10** No seed, URI, code or token appears in any log call (spec **AC14**).
- [ ] **AC-11** `pytest tests/test_mfa_totp_provider.py -v` passes; `ruff check` clean.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_totp_provider.py -v
ruff check navigator_auth/mfa/totp.py tests/test_mfa_totp_provider.py
grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/totp.py   # must print nothing
grep -rn "\.execute(" navigator_auth/mfa/                                      # only mfa/migrations.py (D25)
```

Spec §4 rows owned here: `test_totp_accepts_skew_window`,
`test_totp_rejects_outside_window`, `test_totp_replay_rejected`,
`test_totp_uri_is_google_authenticator_compatible`,
`test_totp_seed_sealed_and_aad_bound`, `test_totp_seed_never_in_user_attributes`,
`test_totp_seed_read_without_session`, `test_totp_pending_seed_isolated`,
`test_totp_confirmation_single_use` (provider half; the handler half — audit,
invalidation, concurrency — is TASK-141). `test_totp_enrollment_requires_fresh_auth`
is TASK-141 (it is an HTTP-level property).

---

## Agent Instructions

1. **Read the spec** `sdd/specs/basicauth-otp-2fa.spec.md` — §3 Module 3, §3
   Security contracts ("Protected seed namespace", "Pending enrollment and
   replacement"), §7 R5, R12, R13, §6 Key constants and facts.
2. **Check dependencies** — TASK-131 and TASK-132 (and transitively TASK-129,
   TASK-130) must be in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint. Do not add locking, version bumps, audit
   or revocation to the provider (D17); do not edit `navigator_auth/mfa/__init__.py`.
5. **Verify** every acceptance criterion, AC-5 and AC-9 included.
6. **Move this file** to `sdd/tasks/completed/TASK-136-mfa-totp-provider.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: gpt-5.6-luna (codex), attempt 3 (terra x2 first: second hit an oversized validation-verdict artifact error)
**Date**: 2026-11-11
**Notes**: MFA TOTP provider delivered; merge-tier green (25 passed, 2 skipped across wave).

**Deviations from spec**: none | describe if any
