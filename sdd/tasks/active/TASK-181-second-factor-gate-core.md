# TASK-181: SecondFactorGate: decide/verify under the user lock (M5 core)

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-171, TASK-172
**Assigned-to**: unassigned

---

## Context

PR #633 review findings #1 (OAuth2 bypass), A1 (trusted-device/no-factor login not serialized with
security transitions) and #3 (nested pool acquisition inside `user_lock`) all trace back to the
second-factor logic being split between `BasicAuth._second_factor` / `BasicAuth._trusted_device`
(`backends/basic.py:357-419`) and `MfaHandler._verify_locked` / `_revalidate` / `_maybe_trust_device`
(`handlers/mfa.py:171-256`). Spec §3 **Module 5** moves that logic into ONE backend-agnostic
`SecondFactorGate` in the new module `navigator_auth/mfa/login.py`. The gate never builds a session: the
caller passes a `SessionIssuer` callback the gate invokes **inside** `MfaSecurity.user_lock`, so session
issuance is serialized with every security transition (G1, G6, D1), and the password hash is rechecked under
the lock (D2, AC17).

This task creates the gate only. Wiring BasicAuth and `/auth/mfa/verify` to it is TASK-182; the OAuth2 form
is TASK-184. Nothing calls the gate yet when this task lands, so no existing behaviour changes.

Spec sections: §2 Overview "Shared second-factor gate", §2 Data Models (`LoginChallenge`, `GateResult`,
`VerifyRefused`), §2 New Public Interfaces, §3 Module 5 (decide steps 1–4, verify steps 1–9 — fixed order),
§7 D1, D2, D5.

---

## Scope

- Create `navigator_auth/mfa/login.py` with `SessionIssuer`, `LoginChallenge`, `GateResult`, `VerifyRefused`
  and `SecondFactorGate` (`decide`, `verify`, and the private helpers `_revalidate`, `_failed`,
  `_trusted_device`, `_maybe_trust_device`).
- Port `BasicAuth._second_factor` + `BasicAuth._trusted_device` into `decide` (password-hash recheck and fresh
  user read on the lock connection added).
- Port `MfaHandler.verify` + `_verify_locked` + `_revalidate` + `_failed` + `_maybe_trust_device` into
  `verify`, re-ordered to the spec's fixed step order (rate limits and the D16 backup consume BEFORE the lock;
  TOTP verify on the lock connection; email verify WITHOUT `conn`).
- Write `tests/test_mfa_review_fixes_gate.py` (AC17, AC18, AC33 gate level, AC11 → 503, step order, D16).

**NOT in scope**:
- Editing `backends/basic.py` or `handlers/mfa.py` (TASK-182 deletes/replaces the old code there).
- The OAuth2 form and `templates/oauth/mfa.html` (TASK-184).
- `mfa_services_lease` / `get_ready_mfa_services` (TASK-173). The gate receives an `MfaServices` the caller
  already leased; it never looks services up itself.
- Changing `BackupCodeStore.consume` (keeps its own connection, D16) or `EmailOTPProvider.verify` (no `conn`).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/login.py` | CREATE | `SecondFactorGate` + data types (spec §3 M5) |
| `tests/test_mfa_review_fixes_gate.py` | CREATE | Gate unit tests + live AC18/AC10-style lock checks |

---

## Codebase Contract (Anti-Hallucination)

> **CRITICAL**: This section contains VERIFIED code references from the actual codebase.
> The implementing agent MUST use these exact imports, class names, and method signatures.
> **DO NOT** invent, guess, or assume any import, attribute, or method not listed here.
> If you need something not listed, VERIFY it exists first with `grep` or `read`.

Verified against `0b80d88` (branch `feat-FEAT-106-basicauth-otp-2fa`, worktree
`.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa`; code identical to the spec's `3f14b3c`).

### Verified Imports
```python
from navigator_auth import conf as auth_conf                       # verified: navigator_auth/mfa/services.py:9 (same form); AUTH_OTP_CHALLENGE_TTL at conf.py:666
from navigator_auth.exceptions import FailedAuth, InvalidAuth, MFARefused, MfaSignal, UserNotFound
#   verified: navigator_auth/exceptions.py:53 (FailedAuth), :47 (InvalidAuth), :108 (MFARefused), :72 (MfaSignal), :35 (UserNotFound)
from navigator_auth.mfa.services import MfaServices                 # verified: navigator_auth/mfa/services.py:28
from navigator_auth.mfa.trusted_devices import may_offer_trusted_device  # verified: navigator_auth/mfa/trusted_devices.py:27
from navigator_auth.mfa.types import (                              # verified: navigator_auth/mfa/types.py:10-15, :24, :53, :137
    AMR_BY_PROVIDER, AMR_PASSWORD, AMR_TRUSTED_DEVICE,
    PROVIDER_BACKUP, PROVIDER_EMAIL, PROVIDER_TOTP, TRUSTED_COOKIE,
    MfaChallenge, MfaEvaluation, MfaState,
)
# stdlib / third-party: logging, secrets, dataclasses.dataclass, typing (Any, Awaitable, Callable, Generic,
# NoReturn, Optional, TypeVar), aiohttp.web  (handlers/mfa.py:9-15 already uses the same set)

# Created by a dependency (use verbatim; verify it landed before starting):
from navigator_auth.mfa.security import LOCK_CONNECTION             # created by TASK-171 (tests only)
```

### Existing Signatures to Use
```python
# navigator_auth/mfa/services.py
class MfaServices:                                                   # line 28
    backend: Any            # the BasicAuth backend; .._idp is its IdentityProvider        line 49
    available: bool                                                  # line 50
    store: MfaChallengeStore; user_limiter / ip_limiter: StrictRateLimiter
    security: MfaSecurity; trusted_devices: TrustedDeviceStore; backup_codes: BackupCodeStore
    providers: dict[str, AbstractOTPProvider]                        # lines 54-62
    async def evaluate(self, user: Mapping, *, conn: Any = None) -> MfaEvaluation:  # line 64

# navigator_auth/mfa/security.py
class MfaSecurity:
    @asynccontextmanager
    async def user_lock(self, user_id: int) -> AsyncIterator[Any]:   # line 55 (TASK-171 adds the timeout +
    #   LOCK_CONNECTION publication; a timeout raises MfaStorageError)

# navigator_auth/mfa/store.py — class MfaChallengeStore
    async def issue(self, user, providers: list[str], preferred: str, *, security_version: int,
                    context_digest: str, email_code_hash: Optional[str] = None) -> tuple[str, MfaChallenge]  # line 115
    async def peek(self, token: str) -> Optional[MfaChallenge]       # line 151
    async def consume(self, token: str) -> Optional[MfaChallenge]    # line 159 (atomic GET+DEL)
    async def discard(self, token: str) -> None                      # line 171
    async def register_failure(self, token: str) -> int              # line 198 (<0 ⇒ challenge burned)

# navigator_auth/mfa/limiter.py
class StrictRateLimiter:
    async def check(self, key: str) -> bool                          # line 34 (Redis; refuses on storage error)

# navigator_auth/mfa/trusted_devices.py
def may_offer_trusted_device(*, has_strong_factor: bool, remember_days: int) -> bool  # line 27
class TrustedDeviceStore:
    async def issue(self, user_id: int, days: int, label: str, *, conn: Any = None) -> str  # line 48
    async def consume_and_rotate(self, raw_token: str, user_id: int, *, conn: Any = None
                                 ) -> Optional[tuple[int, str]]      # line 71 — `conn=` added by TASK-172
    #   (with conn: runs inside the CALLER's transaction; no own commit/rollback)

# navigator_auth/mfa/backup_codes.py
class BackupCodeStore:
    async def consume(self, user_id: int, code: str) -> bool         # line 132 — OWN connection by design (D16)

# navigator_auth/mfa/totp.py
class TOTPProvider:
    async def verify(self, request, user, code, challenge=None, *, conn: Any = None) -> bool  # line 210 — conn= by TASK-172
# navigator_auth/mfa/email_otp.py
class EmailOTPProvider:
    async def challenge(self, request, user) -> dict                 # line 91 → {"code_hash": str}
    async def verify(self, request, user, code, challenge=None) -> bool  # line 106 — NO conn (no DB access)

# navigator_auth/backends/idp/__init__.py
class IdentityProvider:
    async def user_from_id(self, uid: int, *, conn: Any = None) -> Identity  # line 124 — conn= by TASK-172;
    #   raises UserNotFound on miss

# navigator_auth/mfa/types.py
AMR_PASSWORD, AMR_TRUSTED_DEVICE = "pwd", "trusted_device"           # line 11
AMR_BY_PROVIDER = {"email": "otp", "totp": "totp", "backup": "backup"}  # line 12
TRUSTED_COOKIE = "nav_mfa_device"                                    # line 14
class MfaChallenge(MfaModel)   # line 53: user_id, username, providers: tuple[str,...], preferred, issued_at,
                               #   security_version, context_digest, email_code_hash, signature (frozen, ==)
class MfaEvaluation(MfaModel)  # line 137: user_id, policy (.remember_days), state, has_strong_factor,
                               #   providers, preferred, security_version, context_digest

# navigator_auth/exceptions.py
class MfaSignal(AuthException):        def payload(self) -> dict      # line 72
class MFARefused(MfaSignal):  __init__(self, code: str, message: str = None, status: int = 403); .code  # line 108
class FailedAuth(AuthException): __init__(self, message: str = None, status=403)  # line 53

# SOURCE CODE BEING PORTED (read these ranges; they are deleted by TASK-182, not here)
# navigator_auth/backends/basic.py:357-402  BasicAuth._second_factor   (decide steps 2-4)
# navigator_auth/backends/basic.py:404-419  BasicAuth._trusted_device  (decide step 3)
# navigator_auth/handlers/mfa.py:88-107     MfaHandler.verify          (verify steps 1, error envelope)
# navigator_auth/handlers/mfa.py:171-212    MfaHandler._verify_locked  (verify steps 5-8)
# navigator_auth/handlers/mfa.py:214-233    MfaHandler._revalidate     (verify step 5)
# navigator_auth/handlers/mfa.py:235-240    MfaHandler._failed
# navigator_auth/handlers/mfa.py:242-256    MfaHandler._maybe_trust_device (verify step 9)
```

### Does NOT Exist
- ~~`navigator_auth/mfa/login.py`~~, ~~`SecondFactorGate`~~, ~~`GateResult`~~, ~~`LoginChallenge`~~,
  ~~`VerifyRefused`~~, ~~`SessionIssuer`~~ — created by THIS task.
- ~~`BackupCodeStore.consume(..., conn=...)`~~ — deliberately absent (D16). Never pass `conn` to it.
- ~~`EmailOTPProvider.verify(..., conn=...)`~~ — the email provider takes no `conn` (AC33). Passing one raises
  `TypeError`.
- ~~`MfaServices.lease()`~~ / ~~`mfa_services_lease`~~ — TASK-173; the gate does not use them.
- ~~an `auth_method` parameter on `decide`/`verify`~~ — the spec fixes both signatures. The gate never sets
  `extra["auth_method"]`; each adapter's issuer merges it (TASK-182/184).
- ~~`navigator_auth.backends.abstract.user_is_active` in `mfa/login.py`~~ — it exists (`abstract.py:43`) but must
  NOT be imported here: `navigator_auth/backends/__init__.py` imports `basic.py`, which (after TASK-182)
  imports `mfa/login.py` → circular import. Use the local `_field` helper.
- ~~a `request` argument on the gate's `_revalidate`~~ — the old handler signature carried an unused `request`;
  the gate's helper is `_revalidate(conn, token, record)`.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/mfa/login.py", "action": "CREATE"},
    {"path": "tests/test_mfa_review_fixes_gate.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/mfa/services.py#MfaServices",
    "sym:navigator_auth/mfa/services.py#MfaServices.evaluate",
    "sym:navigator_auth/mfa/security.py#MfaSecurity.user_lock",
    "sym:navigator_auth/mfa/store.py#MfaChallengeStore.issue",
    "sym:navigator_auth/mfa/store.py#MfaChallengeStore.peek",
    "sym:navigator_auth/mfa/store.py#MfaChallengeStore.consume",
    "sym:navigator_auth/mfa/store.py#MfaChallengeStore.discard",
    "sym:navigator_auth/mfa/store.py#MfaChallengeStore.register_failure",
    "sym:navigator_auth/mfa/limiter.py#StrictRateLimiter.check",
    "sym:navigator_auth/mfa/trusted_devices.py#may_offer_trusted_device",
    "sym:navigator_auth/mfa/trusted_devices.py#TrustedDeviceStore.issue",
    "sym:navigator_auth/mfa/trusted_devices.py#TrustedDeviceStore.consume_and_rotate",
    "sym:navigator_auth/mfa/backup_codes.py#BackupCodeStore.consume",
    "sym:navigator_auth/mfa/totp.py#TOTPProvider.verify",
    "sym:navigator_auth/mfa/email_otp.py#EmailOTPProvider.challenge",
    "sym:navigator_auth/mfa/email_otp.py#EmailOTPProvider.verify",
    "sym:navigator_auth/backends/idp/__init__.py#IdentityProvider.user_from_id",
    "sym:navigator_auth/mfa/types.py#MfaChallenge",
    "sym:navigator_auth/mfa/types.py#MfaEvaluation",
    "sym:navigator_auth/mfa/types.py#MfaState",
    "sym:navigator_auth/exceptions.py#MfaSignal",
    "sym:navigator_auth/exceptions.py#MFARefused",
    "sym:navigator_auth/exceptions.py#FailedAuth",
    "sym:navigator_auth/exceptions.py#InvalidAuth",
    "sym:navigator_auth/exceptions.py#UserNotFound",
    "sym:navigator_auth/backends/basic.py#BasicAuth._second_factor",
    "sym:navigator_auth/backends/basic.py#BasicAuth._trusted_device",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler.verify",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler._verify_locked",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler._revalidate",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler._failed",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler._maybe_trust_device"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
The two source functions are already correct for their single backend; the port keeps their exact
envelopes and adds three things: (a) the session issuer runs inside `user_lock`, (b) every DB read in the
lock scope runs on the lock connection (`conn=`), (c) the password hash is rechecked under the lock.

### Key Constraints
- **Inside a `user_lock` scope, never acquire a pool connection** (G3). Every call in the scope takes
  `conn=conn` except: Redis calls (store, limiters), `EmailOTPProvider.challenge/verify` (no DB), the issuer
  (Redis-only by D1). `BackupCodeStore.consume` runs **before** the lock (D16, verify step 4).
- Fail closed: any non-signal dependency error → `MFARefused("mfa_unavailable", …, status=503)` in `decide`,
  `VerifyRefused("mfa_unavailable", 503)` in `verify`. A `user_lock` timeout surfaces this way (AC11).
- Never log codes, challenge tokens or device tokens; log only `type(err).__name__` (FEAT-106 sweep).
- `MfaChallenge` is a frozen Pydantic model: `consumed != record` compares field-wise (keep the check).
- Use the module logger `logging.getLogger("navigator.auth.mfa")` (same name as `handlers/mfa.py:43`).
- Google-style docstrings and full type hints on every function; `from __future__ import annotations`.

### References in Codebase
- `navigator_auth/backends/basic.py:357-419` — decide source.
- `navigator_auth/handlers/mfa.py:88-256` — verify source.
- `navigator_auth/mfa/security.py:27-33` — `_user_field` pattern the local `_field` mirrors.
- `tests/test_mfa_verify.py:59-152` — in-memory fakes (`FakeStore`, `FakeSecurity`, `FakeProvider`) to copy
  (do NOT import from another test module).

---

## Implementation Blueprint

> **CRITICAL — Executor-ready starting point.** Write each block below to its declared
> path nearly verbatim, then complete every `# FILL IN:` marker. Blocks were derived
> from the spec's Interface Skeletons and re-verified against the Codebase Contract
> above when this task was written. This is NOT the full implementation:
> business-logic branches, edge cases and test bodies are `FILL IN` stubs by design.
> Never change a signature, class name, or file path the blueprint fixes.

### Steps (in order)
1. Confirm TASK-171 and TASK-172 landed: `grep -n "LOCK_CONNECTION" navigator_auth/mfa/security.py` and
   `grep -n "conn: Any = None" navigator_auth/backends/idp/__init__.py navigator_auth/mfa/totp.py navigator_auth/mfa/trusted_devices.py`
   — *why*: the gate calls `user_from_id/verify/consume_and_rotate` with `conn=`; without TASK-172 those calls raise `TypeError`.
2. Create `navigator_auth/mfa/login.py` from parts 1–3 below (one file; the parts are only split for size) —
   *why*: one backend-agnostic gate is the fix for review #1/A1 (spec D1).
3. Fill the `decide` FILL INs (hash recheck, email challenge issue) — *why*: AC17 and the unchanged challenge envelope.
4. Keep verify's step order exactly as numbered — *why*: the spec fixes it; moving the backup consume under the lock
   re-introduces the single-connection deadlock (AC10), moving rate limits after the lock changes 429 timing.
5. Write `tests/test_mfa_review_fixes_gate.py` and run the Validation Commands — *why*: nothing else exercises the gate until TASK-182.

### `navigator_auth/mfa/login.py` (CREATE — part 1/3: header, types, helpers)
```python
"""Shared second-factor gate for every password login path (FEAT-106 review fixes, spec §3 M5).

The gate decides, verifies and issues a second-factor login under the per-user advisory lock, so
session issuance is serialized with every security transition (G1, G6). It never builds a session:
callers pass a ``SessionIssuer`` that the gate invokes inside the lock. Codes, challenge tokens and
device tokens are never logged.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Generic, NoReturn, Optional, TypeVar

from aiohttp import web

from navigator_auth import conf as auth_conf
from navigator_auth.exceptions import FailedAuth, InvalidAuth, MFARefused, MfaSignal, UserNotFound
from navigator_auth.mfa.services import MfaServices
from navigator_auth.mfa.trusted_devices import may_offer_trusted_device
from navigator_auth.mfa.types import (
    AMR_BY_PROVIDER,
    AMR_PASSWORD,
    AMR_TRUSTED_DEVICE,
    PROVIDER_BACKUP,
    PROVIDER_EMAIL,
    PROVIDER_TOTP,
    TRUSTED_COOKIE,
    MfaChallenge,
    MfaEvaluation,
    MfaState,
)

logger = logging.getLogger("navigator.auth.mfa")

T = TypeVar("T")
SessionIssuer = Callable[[Any, dict], Awaitable[T]]  # (fresh user, extra claims) -> backend session result


@dataclass(frozen=True)
class LoginChallenge:
    """A second factor is owed: the signed challenge handed back to the client."""

    token: str
    providers: tuple[str, ...]
    preferred: Optional[str]
    expires_in: int


@dataclass(frozen=True)
class GateResult(Generic[T]):
    """Outcome of ``decide``/``verify``: exactly one of ``session`` or ``challenge`` is set."""

    session: Optional[T] = None
    challenge: Optional[LoginChallenge] = None
    device: Optional[dict] = None  # {"token": str, "max_age": int} for the trusted-device cookie


class VerifyRefused(Exception):
    """A verification refusal; adapters map it to their own response shape."""

    def __init__(self, code: str, status: int, **extra: Any) -> None:
        """Record the client-facing code, HTTP status and extra envelope fields."""
        super().__init__(code)
        self.code = code
        self.status = status
        self.extra = dict(extra)


def _field(user: Any, name: str, default: Any = None) -> Any:
    """Read a field from a mapping or attribute-based user record (mirrors mfa/security.py:27-33)."""
    try:
        value = user[name]
    except (KeyError, TypeError, AttributeError):
        value = getattr(user, name, default)
    return default if value is None else value


def _remote(request: web.Request) -> str:
    """Return the request's remote address with a safe fallback (mirrors handlers/mfa.py:63-65)."""
    return getattr(request, "remote", None) or "unknown"
```
**Why this shape**: data types are exactly spec §2 Data Models (defaults added so callers build one-field
results). `VerifyRefused(code, status, **extra)` lets the JSON adapter call `_error(e.code, e.status, **e.extra)`
unchanged (spec §3 M5). `_field` replaces `user_is_active` because importing `backends.*` here is circular.

### `navigator_auth/mfa/login.py` (CREATE — part 2/3: class + decide)
```python
class SecondFactorGate:
    """Decide, verify and issue a second-factor login under one user lock (spec §3 M5)."""

    def __init__(
        self, services: MfaServices, *, userid_attribute: str = "user_id", password_attribute: str = "password"
    ) -> None:
        """Bind the gate to already-leased, available MFA services."""
        self._services = services
        self._uid_attr = userid_attribute
        self._pwd_attr = password_attribute

    async def decide(self, request: web.Request, user: Any, issue: SessionIssuer[T]) -> GateResult[T]:
        """Decide a password login; call after a successful password check (``user`` carries the hash).

        Raises:
            FailedAuth: 403 inactive account; 401 ``credentials_changed`` on hash drift (AC17).
            MFARefused: ``no_factor_available`` (403), a propagated policy signal, or ``mfa_unavailable``
                (503) on any non-signal dependency failure, lock timeout included (AC11).
        """
        services = self._services
        uid = int(_field(user, self._uid_attr))
        try:
            async with services.security.user_lock(uid) as conn:
                fresh = await services.backend._idp.user_from_id(uid, conn=conn)  # pylint: disable=W0212
                if not _field(fresh, "is_active", True):
                    raise FailedAuth("User account is disabled", status=403)
                # FILL IN: hash recheck — compare str(_field(fresh, self._pwd_attr, "")) with
                #   str(_field(user, self._pwd_attr, "")) using secrets.compare_digest; on mismatch
                #   raise FailedAuth("credentials_changed", status=401) — bounded by AC17/D2: it MUST run
                #   before evaluate() and before _trusted_device() (no session, no device rotation).
                evaluation = await services.evaluate(fresh, conn=conn)
                if evaluation.state == MfaState.NONE:
                    return GateResult(session=await issue(fresh, {}))
                device_token = await self._trusted_device(request, conn, evaluation)
                if device_token is not None:
                    session = await issue(fresh, {"mfa": True, "amr": [AMR_PASSWORD, AMR_TRUSTED_DEVICE]})
                    device = {"token": device_token, "max_age": evaluation.policy.remember_days * 86400}
                    return GateResult(session=session, device=device)
                if not evaluation.providers:
                    raise MFARefused("no_factor_available", "No second factor is available for this account", status=403)
                # FILL IN: email-preferred delivery + challenge issue — port backends/basic.py:380-391
                #   verbatim with `user` -> `fresh`: code_hash from providers[PROVIDER_EMAIL].challenge(request,
                #   fresh) when evaluation.preferred == PROVIDER_EMAIL, then
                #   token, _record = await services.store.issue(fresh, list(evaluation.providers),
                #   evaluation.preferred, security_version=..., context_digest=..., email_code_hash=code_hash)
                #   — bounded by AC1 (exactly one OTP email) and spec §3 M5 decide step 4 (inside the lock).
        except (MfaSignal, FailedAuth, InvalidAuth):
            raise
        except Exception as err:  # pylint: disable=W0718 -- security dependencies fail closed.
            logger.error("MFA gate: decide refused, dependency failure: %s", type(err).__name__)
            raise MFARefused("mfa_unavailable", "Second factor is temporarily unavailable", status=503) from err
        return GateResult(
            challenge=LoginChallenge(
                token=token,
                providers=tuple(evaluation.providers),
                preferred=evaluation.preferred,
                expires_in=int(auth_conf.AUTH_OTP_CHALLENGE_TTL),
            )
        )
```
**Why this shape**: decide steps 1–4 of spec §3 M5, in order. The issuer receives `{}` for `MfaState.NONE` so
the adapter can pass `extra or None` and keep the 2FA-off/no-factor session byte-identical (AC4/AC5). The
issuer and the trusted-device rotation run on/under the lock connection, which is what AC18 asserts.
`auth_conf.AUTH_OTP_CHALLENGE_TTL` is read through the module (as `basic.py:401` does) so tests can monkeypatch it.

### `navigator_auth/mfa/login.py` (CREATE — part 3/3: verify + helpers)
```python
    async def verify(
        self, request: web.Request, token: str, provider: str, code: str, issue: SessionIssuer[T], *,
        remember_device: bool = False, device_label: str = "",
    ) -> GateResult[T]:
        """Verify a challenge and issue the session under the user lock (spec §3 M5, fixed step order).

        Raises:
            VerifyRefused: invalid_request 400, invalid_challenge 401, stale_challenge 401, invalid_code 401
                (+attempts_remaining), rate_limited 429, account_disabled, a policy signal code, or
                mfa_unavailable 503.
        """
        services = self._services
        if not all(isinstance(value, str) and value for value in (token, provider, code)):
            raise VerifyRefused("invalid_request", 400)
        try:
            preview = await services.store.peek(token)  # step 1
            if preview is None:
                raise VerifyRefused("invalid_challenge", 401)
            if not await services.user_limiter.check(str(preview.user_id)) or not await services.ip_limiter.check(
                _remote(request)
            ):  # step 2
                raise VerifyRefused("rate_limited", 429)
            if provider not in preview.providers or provider not in services.providers:  # step 3
                await self._failed(token)
            if provider == PROVIDER_BACKUP and not await services.backup_codes.consume(preview.user_id, code):
                await self._failed(token)  # step 4: OWN connection, BEFORE the lock (D16, D5)
            async with services.security.user_lock(preview.user_id) as conn:  # step 5
                record = await services.store.peek(token)
                if record is None:
                    raise VerifyRefused("invalid_challenge", 401)
                user, evaluation = await self._revalidate(conn, token, record)
                # step 6. NOTE (spec defect flagged at /sdd-task): a consumed LAST backup code drops "backup"
                # from evaluation.providers (state.py:164); its proof was already checked in step 4.
                if provider not in evaluation.providers and provider != PROVIDER_BACKUP:
                    await self._failed(token)
                if provider == PROVIDER_TOTP:
                    ok = await services.providers[provider].verify(request, user, code, challenge=record, conn=conn)
                elif provider == PROVIDER_EMAIL:
                    ok = await services.providers[provider].verify(request, user, code, challenge=record)
                else:
                    ok = provider == PROVIDER_BACKUP
                if not ok:
                    await self._failed(token)
                consumed = await services.store.consume(token)  # step 7
                if consumed is None or consumed != record:
                    raise VerifyRefused("invalid_challenge", 401)
                try:  # step 8
                    session = await issue(user, {"mfa": True, "amr": [AMR_PASSWORD, AMR_BY_PROVIDER[provider]]})
                except FailedAuth as err:
                    raise VerifyRefused("account_disabled", err.status) from err
                device = await self._maybe_trust_device(conn, evaluation, remember_device, device_label)  # step 9
        except (VerifyRefused, web.HTTPException):
            raise
        except Exception as err:  # pylint: disable=W0718 -- security dependencies fail closed.
            logger.error("MFA gate: verify refused, dependency failure: %s", type(err).__name__)
            raise VerifyRefused("mfa_unavailable", 503) from err
        return GateResult(session=session, device=device)

    async def _revalidate(self, conn: Any, token: str, record: MfaChallenge) -> tuple[Any, MfaEvaluation]:
        """Fresh user + evaluation on the lock connection; discard the challenge on drift (handlers/mfa.py:214-233)."""
        # FILL IN: port handlers/mfa.py:218-233 with these substitutions only — user_from_id(record.user_id,
        #   conn=conn); `return _error("invalid_challenge", 401)` -> raise VerifyRefused("invalid_challenge", 401);
        #   MfaSignal err -> discard, then raise VerifyRefused(getattr(err, "code", "mfa_refused"), err.status,
        #   **{k: v for k, v in err.payload().items() if k != "error"}); stale -> discard + raise
        #   VerifyRefused("stale_challenge", 401); keep secrets.compare_digest — bounded by tests/test_mfa_verify.py
        #   ::test_stale_challenge_rejected / ::test_strong_factor_required_on_verify envelopes (unchanged).

    async def _failed(self, token: str) -> NoReturn:
        """Count an invalid attempt and refuse (handlers/mfa.py:235-240)."""
        remaining = await self._services.store.register_failure(token)
        if remaining < 0:
            raise VerifyRefused("invalid_challenge", 401)
        raise VerifyRefused("invalid_code", 401, attempts_remaining=remaining)

    async def _trusted_device(self, request: web.Request, conn: Any, evaluation: MfaEvaluation) -> Optional[str]:
        """Rotate a trusted-device cookie on the lock connection (backends/basic.py:404-419)."""
        raw = request.cookies.get(TRUSTED_COOKIE)
        if not raw or not may_offer_trusted_device(
            has_strong_factor=evaluation.has_strong_factor, remember_days=evaluation.policy.remember_days
        ):
            return None
        # FILL IN: errors from consume_and_rotate — basic.py:412-416 swallowed them and fell back to a challenge;
        #   on the LOCK connection a failed statement aborts the transaction, so let them propagate (decide maps
        #   them to mfa_unavailable 503) — bounded by spec §7 "fail closed" and G3.
        rotated = await self._services.trusted_devices.consume_and_rotate(raw, evaluation.user_id, conn=conn)
        if rotated is None or rotated[0] != evaluation.user_id:
            return None
        return rotated[1]

    async def _maybe_trust_device(
        self, conn: Any, evaluation: MfaEvaluation, remember_device: bool, device_label: str
    ) -> Optional[dict]:
        """Issue a trusted device only when requested and policy permits (handlers/mfa.py:242-256)."""
        if not remember_device or not may_offer_trusted_device(
            has_strong_factor=evaluation.has_strong_factor, remember_days=evaluation.policy.remember_days
        ):
            return None
        days = evaluation.policy.remember_days
        raw = await self._services.trusted_devices.issue(evaluation.user_id, days, str(device_label or "")[:128], conn=conn)
        return {"token": raw, "max_age": days * 86400}
```
**Why this shape**: verify steps 1–9 exactly as spec §3 M5. The only deliberate deviation from the spec's
literal step 6 is the backup exception: without it a user's last backup code can never verify (the code is
consumed in step 4, so `available_providers` no longer lists `backup` in step 5). The parent `/sdd-task` run
flagged this for review. `_failed` raises (`NoReturn`) so every refusal leaves the lock by exception and rolls
the lock transaction back.

### FILL IN checklist
- [ ] `login.py::SecondFactorGate.decide` — hash recheck with `secrets.compare_digest`; bounded by AC17/D2 (before evaluate and device rotation)
- [ ] `login.py::SecondFactorGate.decide` — email delivery + `store.issue` port of basic.py:380-391; bounded by AC1, decide step 4
- [ ] `login.py::SecondFactorGate._revalidate` — port of handlers/mfa.py:218-233 with the listed substitutions; bounded by the existing verify-test envelopes
- [ ] `login.py::SecondFactorGate._trusted_device` — propagate `consume_and_rotate` errors (no swallow on the lock connection); bounded by fail-closed + G3
- [ ] `tests/test_mfa_review_fixes_gate.py` — every test body below

---

## Acceptance Criteria

- [ ] `from navigator_auth.mfa.login import SecondFactorGate, GateResult, LoginChallenge, VerifyRefused, SessionIssuer` works.
- [ ] **AC17** — a hash change between the caller's password check and the gate's lock ⇒ `FailedAuth` status 401
      `credentials_changed`; the issuer is not awaited and `consume_and_rotate` is not awaited.
- [ ] **AC18** — on the trusted-device and no-factor-owed paths the issuer runs while `LOCK_CONNECTION.get()` is
      the lock connection.
- [ ] **AC33 (gate level)** — email OTP verifies without any `conn` argument; TOTP verify receives the lock connection.
- [ ] **AC11 (gate level)** — a `user_lock` that raises `MfaStorageError` ⇒ `decide` raises `MFARefused` 503
      `mfa_unavailable`, `verify` raises `VerifyRefused("mfa_unavailable", 503)`.
- [ ] D16 — the backup code is consumed before `user_lock` is entered (`LOCK_CONNECTION.get() is None` during
      `consume`), and a refused verify after that leaves it consumed (D5).
- [ ] The last remaining backup code verifies successfully (step-6 backup exception).
- [ ] Refusal codes/statuses match the old handler envelopes (`invalid_request` 400, `invalid_challenge` 401,
      `stale_challenge` 401, `invalid_code` 401 + `attempts_remaining`, `rate_limited` 429, policy signal code).
- [ ] No code, challenge token or device token appears in any log record (caplog check).
- [ ] No new flake8/pylint findings in `navigator_auth/mfa/login.py` beyond the repository's existing config.

---

## Validation Commands

- `pytest tests/test_mfa_review_fixes_gate.py -q`

---

## Test Specification

```python
# tests/test_mfa_review_fixes_gate.py
"""FEAT-106 review fixes — SecondFactorGate core (spec §3 M5; AC11, AC17, AC18, AC33, D16)."""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from navigator_auth.exceptions import FailedAuth, MFARefused
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.login import GateResult, LoginChallenge, SecondFactorGate, VerifyRefused
from navigator_auth.mfa.security import LOCK_CONNECTION  # TASK-171
from navigator_auth.mfa.services import MfaServices
from navigator_auth.mfa.types import MfaChallenge, MfaMode, MfaState, TenantMfaPolicy


class FakeLock:
    """user_lock stand-in that publishes LOCK_CONNECTION like TASK-171's real lock."""

    def __init__(self, fail: bool = False) -> None:
        self.conn = object()
        self.fail = fail

    @asynccontextmanager
    async def user_lock(self, user_id: int):
        # FILL IN: raise MfaStorageError when self.fail; else token = LOCK_CONNECTION.set(self.conn),
        #   yield self.conn, LOCK_CONNECTION.reset(token) in finally — bounded by TASK-171's contract
        yield self.conn


def _services(**over) -> MfaServices:
    """Gate collaborators as in-memory fakes (copy shapes from tests/test_mfa_verify.py:59-152)."""
    # FILL IN: MfaServices(backend=SimpleNamespace(_idp=SimpleNamespace(user_from_id=AsyncMock(...))),
    #   available=True) + store/limiters/security/trusted_devices/backup_codes/providers fakes
    raise NotImplementedError


@pytest.mark.asyncio
async def test_login_refused_when_password_changed_mid_flight():
    """AC17: hash drift ⇒ FailedAuth 401 credentials_changed, no issue, no device rotation."""


@pytest.mark.asyncio
async def test_trusted_device_session_issued_under_lock():
    """AC18: trusted-device issuer sees LOCK_CONNECTION == the lock connection; device dict returned."""


@pytest.mark.asyncio
async def test_no_factor_owed_issued_under_lock_with_empty_extra():
    """AC18 + AC4 baseline: MfaState.NONE ⇒ issue(fresh, {}) inside the lock."""


@pytest.mark.asyncio
async def test_decide_owed_factor_returns_challenge():
    """Factor owed ⇒ GateResult.challenge (token, providers, preferred, expires_in); email sent once."""


@pytest.mark.asyncio
async def test_decide_lock_timeout_is_mfa_unavailable():
    """AC11: user_lock MfaStorageError ⇒ MFARefused('mfa_unavailable', status=503)."""


@pytest.mark.asyncio
async def test_email_gate_verify():
    """AC33: email verify gets no conn; TOTP verify gets the lock connection."""


@pytest.mark.asyncio
async def test_backup_consumed_before_lock_and_last_code_verifies():
    """D16/D5: consume runs with LOCK_CONNECTION unset; the last backup code verifies."""


@pytest.mark.asyncio
async def test_verify_refusals_keep_handler_envelopes():
    """invalid_request/invalid_challenge/stale_challenge/invalid_code(+attempts)/rate_limited codes and statuses."""


@pytest.mark.asyncio
async def test_gate_logs_no_secrets(caplog):
    """No code, challenge token or device token in any log line."""
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the existing feature worktree `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa`** (branch
   `feat-FEAT-106-basicauth-otp-2fa`, PR #633) — never on `dev`. No new worktree.
2. **Read the spec** at the path listed above for full context (§3 Module 5, §7 D1/D2/D5).
3. **Check dependencies** — TASK-171 and TASK-172 must be `"done"` in
   `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json`.
4. **Verify the Codebase Contract** — before writing ANY code:
   - Confirm every import in "Verified Imports" still exists (`grep` or `read` the source)
   - Confirm every class/method in "Existing Signatures" still has the listed attributes
   - If anything has changed, update the contract FIRST, then implement
   - **NEVER** reference an import, attribute, or method not in the contract without verifying it exists
5. **Update status** in `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json` → `"in-progress"`
   (set `started_at`) and commit only that index file
6. **Implement** — start from the Implementation Blueprint blocks, complete every
   `# FILL IN:` marker, and never change a signature or path the blueprint fixes
7. **Verify** all acceptance criteria are met — run the Validation Commands
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`)
9. **Close the task** with `parrot sdd task close TASK-181 basicauth-otp-2fa-review-fixes verified`
   — it moves this file to `sdd/tasks/completed/` and marks it `"done"` in the
   index; never move or copy the file by hand
10. **Fill in the Completion Note** below, then commit the staged SDD state

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any
