# TASK-137: E-mail OTP provider + callback/notification hand-off module

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-131
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 4** — the zero-enrolment e-mail floor — and the
callback plumbing it shares with the downgrade notifications of decision **D6**.

E-mail OTP is what lets a tenant be switched to `enforced` without locking
anybody out (G3, AC8): `User.email` already exists, so every ordinary user has
a working second factor at their next login. It is deliberately the *weak*
factor (`_is_strong = False`): a confirmed TOTP or a registered passkey closes
it (decided in TASK-135's `available_providers`, not here).

navigator-auth **never sends e-mail** (`docs/password_recovery.rst`, recovery
handler `_invoke_callback`, `handlers/recovery/handler.py:363-383`). The live
code is handed to `AUTH_OTP_EMAIL_CALLBACK` inside a frozen
`OtpNotificationPayload` whose `repr` hides the code (TASK-129, AC34); only
its keyed hash `hash_code(code, AUTH_OTP_SECRET)` (HMAC-SHA256, contract D30 — the spec
says "sha256"; a keyed digest keeps that intent and stops a Redis reader from
brute-forcing the 10^6 codes) is ever persisted — inside the challenge record, by the caller
(TASK-138 / TASK-140), via `MfaChallengeStore.issue(..., email_code_hash=…)` or
`replace_email_code()`.

Two failure-posture rules shape the code:

- **R9 — a broken delivery callback must never become an enumeration oracle
  or a 500.** `challenge()` returns the same shape (`{"code_hash": <64 hex>}`)
  whether delivery succeeded, the address was missing, or the callback raised;
  the failure is logged at WARNING with the exception **class name only** (a
  callback's error message may well contain the code it was formatting).
- **D6 — downgrade notifications.** The spec says disenrolment "notifies the
  user" but names no channel. `notify.py` adds `notify_security_event()`, which
  hands a frozen `MfaSecurityNotice` to the optional `AUTH_MFA_NOTIFY_CALLBACK`;
  unset ⇒ an INFO log and nothing else. It never raises. Callers (TASK-141,
  TASK-142, TASK-144) invoke it **after** their transaction commits (D17).

---

## Scope

- Create `navigator_auth/mfa/notify.py`: `invoke_callback()` (dotted-path
  import, sync or async callable, never raises, returns success) and
  `notify_security_event()`.
- Create `navigator_auth/mfa/email_otp.py`: `hash_code()`, `mask_email()`,
  `EmailOTPProvider` implementing every `AbstractOTPProvider` method per the
  contract.
- Write `tests/test_mfa_email_provider.py`.

**NOT in scope**:
- Storing the hash in the challenge, resend semantics (rotate the hash, keep
  expiry and attempt budget) — `MfaChallengeStore.issue` / `replace_email_code`
  (TASK-131) and the resend endpoint (TASK-140).
- The HTTP-level byte-identity of the resend response — TASK-140 (this task
  proves the *provider* returns the same shape and never raises).
- Deciding whether `email` is offered to a user (strong factor closes it) —
  TASK-135.
- Sending any e-mail, SMTP, `aiosmtplib` — out of scope by design.
- Any edit to `navigator_auth/mfa/__init__.py`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/notify.py` | CREATE | Callback hand-off + security notices (D6) |
| `navigator_auth/mfa/email_otp.py` | CREATE | `EmailOTPProvider`, `hash_code`, `mask_email` |
| `tests/test_mfa_email_provider.py` | CREATE | M4 unit tests (+ one live-Redis store test) |

---

## Codebase Contract

> Re-verified on `dev` @ `b10a3a3` (2026-11-11).

### Verified Imports

```python
from navigator_auth import conf as auth_conf          # module import; settings read at call time
#   (house pattern: backends/passkey.py:18 `from .. import conf as auth_conf`)
#   auth_conf.AUTH_OTP_EMAIL_CALLBACK, auth_conf.AUTH_MFA_NOTIFY_CALLBACK,
#   auth_conf.AUTH_OTP_CODE_LENGTH, auth_conf.AUTH_OTP_CHALLENGE_TTL — created by TASK-129
from navigator_auth.mfa.abstract import AbstractOTPProvider     # TASK-129
from navigator_auth.mfa.types import (                          # TASK-129
    PROVIDER_EMAIL, EnrollmentAuthorization, MfaChallenge, MfaModel,
    MfaSecurityNotice, OtpNotificationPayload,
)
from navigator_auth.mfa.store import MfaChallengeStore          # TASK-131 — tests only
```

Stdlib: `asyncio`, `hashlib`, `importlib`, `inspect`, `logging`, `secrets`,
`string`, `datetime` (`datetime`, `timedelta`, `timezone`), `typing`.
`from aiohttp import web` for the `web.Request` annotation.

### Contract signatures this task implements (shared contract §3, TASK-137)

```python
# notify.py
async def invoke_callback(path: Optional[str], payload: MfaModel, *, label: str) -> bool   # never raises
async def notify_security_event(notice: MfaSecurityNotice) -> None                          # AUTH_MFA_NOTIFY_CALLBACK (D6)
# email_otp.py
def hash_code(code: str, secret: bytes) -> str   # HMAC-SHA256 hex, keyed by AUTH_OTP_SECRET (contract D30)
def mask_email(email: str) -> str      # "j***@example.com"
class EmailOTPProvider(AbstractOTPProvider):   # _provider_name="email", _is_strong=False
    def __init__(self, *, secret: bytes, callback: Optional[str] = AUTH_OTP_EMAIL_CALLBACK, code_length: int = AUTH_OTP_CODE_LENGTH, ttl: int = AUTH_OTP_CHALLENGE_TTL)
    async def challenge(self, request, user) -> dict   # {"code_hash": h}
    async def verify(self, request, user, code, challenge=None) -> bool
```

### Types consumed (TASK-129, spec §2 Data Models)

```python
class OtpNotificationPayload(MfaModel):
    email: str
    display_name: str
    username: str
    code: str = Field(repr=False)   # never in an HTTP response, never in a log
    expires_at: datetime
    found: bool                     # False => no usable address; callback decides
    # Pydantic repr excludes code; logging model_dump()/JSON is prohibited.

class MfaChallenge(MfaModel):
    user_id: int; username: str; providers: tuple[str, ...]; preferred: str
    issued_at: float; security_version: int; context_digest: str
    email_code_hash: Optional[str] = None; signature: str

class MfaSecurityNotice(MfaModel):   # D6
    email: Optional[str]; display_name: str; username: str
    event: str; occurred_at: datetime; actor: Optional[str] = None
```

### The pattern being mirrored — `handlers/recovery/handler.py:363-383`

```python
    async def _invoke_callback(self, payload: NotificationPayload) -> None:
        if not AUTH_RECOVERY_CALLBACK:
            logger.warning("PasswordRecovery: no AUTH_RECOVERY_CALLBACK configured; dropping notification")
            return
        try:
            pkg, name = AUTH_RECOVERY_CALLBACK.rsplit(".", 1)
            mod = importlib.import_module(pkg)
            callback = getattr(mod, name)
            if asyncio.iscoroutinefunction(callback):
                await callback(payload)
            else:
                callback(payload)
        except Exception as ex:  # pylint: disable=W0703
            logger.error("PasswordRecovery: notification callback failed: %s", ex)
```

Two deliberate differences (spec §7 "Never import from `handlers/recovery/`" —
clone the shape, don't import it): failures log at **WARNING** with
`type(ex).__name__` only (R9; the recovery version interpolates the message),
and a sync callable that *returns* an awaitable is awaited too
(`inspect.isawaitable`), so a `functools.partial` over a coroutine function
works.

### `User.email` facts

`navigator_auth/models.py:49` — `email: str = Column(required=False, max=254)`
(R3: may be absent). User records reach providers as a dict **or** a
datamodel `Model` (idp `get_user`/`user_from_id` return `AUTH_USER_VIEW`
models). Read fields defensively.

**Usable-address rule (must match TASK-135's `usable_email()` exactly):**
`str(value).strip()`; exactly one `@`; non-empty local part and non-empty
domain; otherwise "no usable address" (`None`).

### Does NOT Exist (Anti-Hallucination)

- ~~`aiosmtplib`~~, ~~`sendgrid`~~, ~~`twilio`~~, ~~any send-mail helper in navigator-auth~~ — delivery is the callback's job.
- ~~`User.email_verified`~~ — no verification state (R4); a wrong address is an accepted bound.
- ~~`navigator_auth.handlers.recovery.handler._invoke_callback` as an importable helper~~ — clone, don't import (spec §7).
- ~~`OtpNotificationPayload.__repr__` override~~ — redaction comes from `Field(repr=False)` (TASK-129); do not re-implement it here.
- ~~persisting the raw code anywhere~~ — only `hash_code(code, secret)` leaves `challenge()`.
- ~~an unkeyed `sha256(code)`~~ — a 6-digit code has 10^6 values, so an unkeyed hash read from Redis IS the code. The hash is keyed with `AUTH_OTP_SECRET` (contract D30).
- ~~`AUTH_OTP_SMS_*`~~ — SMS is out of scope.

---

## Implementation Blueprint

> **D5 — AC5 grep.** Neither file may contain `open_session`, `create_token`
> or `remember(` — not even in a comment.

### `navigator_auth/mfa/notify.py` — CREATE

```python
"""Callback hand-offs for FEAT-106 (OTP delivery and security notices).

navigator-auth never sends e-mail. A live OTP goes to AUTH_OTP_EMAIL_CALLBACK
inside an OtpNotificationPayload; a factor downgrade goes to the optional
AUTH_MFA_NOTIFY_CALLBACK inside an MfaSecurityNotice (decision D6). Neither
hand-off ever raises: a broken callback is an outage for the recipient, never
an exception for the login flow, and never an enumeration oracle (spec R9).
"""
import asyncio
import importlib
import inspect
import logging
from typing import Optional

from navigator_auth import conf as auth_conf

from .types import MfaModel, MfaSecurityNotice

logger = logging.getLogger("navigator.mfa")


async def invoke_callback(path: Optional[str], payload: MfaModel, *, label: str) -> bool:
    """Import ``path`` ("pkg.module.callable") and call it with ``payload``.

    Args:
        path: Dotted path of a sync or async callable; ``None``/empty = not configured.
        payload: Frozen model handed to the callable. NEVER logged.
        label: Short name for log lines (e.g. ``"otp-email"``).

    Returns:
        True when the callable ran without raising, False otherwise.
    """
    if not path:
        logger.warning("MFA: no %s callback configured; dropping hand-off", label)
        return False
    try:
        pkg, name = path.rsplit(".", 1)
        callback = getattr(importlib.import_module(pkg), name)
        if asyncio.iscoroutinefunction(callback):
            await callback(payload)
        else:
            result = callback(payload)
            if inspect.isawaitable(result):
                await result
        return True
    except Exception as ex:  # noqa: BLE001 - never raises, by contract (R9)
        # Class name only: a callback's message may embed the code it formatted.
        logger.warning("MFA: %s callback failed: %s", label, type(ex).__name__)
        return False


async def notify_security_event(notice: MfaSecurityNotice) -> None:
    """Tell the user a factor-state change happened (D6). Never raises.

    Unset AUTH_MFA_NOTIFY_CALLBACK is a legitimate deployment choice, so it
    logs at INFO (not WARNING) and returns.
    """
    path = auth_conf.AUTH_MFA_NOTIFY_CALLBACK
    if not path:
        logger.info(
            "MFA: security event %s for user %s (no AUTH_MFA_NOTIFY_CALLBACK configured)",
            notice.event,
            notice.username,
        )
        return
    await invoke_callback(path, notice, label="security-notice")
```

**Why `auth_conf.X` at call time, not `from ..conf import X`.** Tests (and
operators reloading settings) must be able to change the callback without
re-importing the module; passkey uses the same `auth_conf.` pattern. The
e-mail provider instead takes its callback as a constructor argument (contract
signature), so `MfaServices` (TASK-138) decides once per process and tests pass
it explicitly.

### `navigator_auth/mfa/email_otp.py` — CREATE

```python
"""E-mail OTP — the zero-enrolment floor (FEAT-106, spec Module 4).

Works over the address already on User.email (models.py:49 — required=False,
see spec R3). navigator-auth never sends e-mail: the code goes to
AUTH_OTP_EMAIL_CALLBACK. Only its keyed hash (HMAC-SHA256) leaves challenge(); the caller
persists it inside the HMAC-signed challenge record.
"""
import hashlib
import hmac
import secrets
import string
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from aiohttp import web

from navigator_auth import conf as auth_conf

from .abstract import AbstractOTPProvider
from .notify import invoke_callback
from .types import PROVIDER_EMAIL, EnrollmentAuthorization, MfaChallenge, OtpNotificationPayload


def hash_code(code: str, secret: bytes) -> str:
    """HMAC-SHA256 (keyed by ``AUTH_OTP_SECRET``) of the stripped code — its only stored form.

    Keyed, not a bare sha256: a 6-digit code has only 10^6 values, so an unkeyed
    digest read from Redis would reveal the live code instantly (contract D30).
    """
    return hmac.new(secret, b"mfa-email-otp|" + code.strip().encode("utf-8"), hashlib.sha256).hexdigest()


def mask_email(email: str) -> str:
    """``jane@example.com`` → ``j***@example.com``; anything unusable → ``***``."""
    # FILL IN: partition on the last "@"; empty local or domain ⇒ "***";
    #  else first char of local + "***@" + domain — bounded by AC14 (never echo
    #  the full address in an enrolment response).


def _field(user: Any, name: str, default: Any = None) -> Any:
    # FILL IN: user[name] → user.get(name) → getattr(user, name) → default
    #  (dict OR datamodel Model records).


def _usable_email(user: Any) -> Optional[str]:
    """Same rule as TASK-135 usable_email(): stripped, exactly one '@', non-empty parts.

    Kept local on purpose (contract D26): this module lands before
    navigator_auth/mfa/state.py, and importing state.py from a provider would
    pull the policy/state machinery into the provider layer.
    """
    # FILL IN — bounded by the "Usable-address rule" in the Codebase Contract;
    #  return the stripped address or None. Do NOT import from mfa/state.py.


class EmailOTPProvider(AbstractOTPProvider):
    """Zero-enrolment, weak second factor. Never offered once a strong factor exists."""

    _provider_name = PROVIDER_EMAIL
    _is_strong = False

    def __init__(
        self,
        *,
        secret: bytes,
        callback: Optional[str] = auth_conf.AUTH_OTP_EMAIL_CALLBACK,
        code_length: int = auth_conf.AUTH_OTP_CODE_LENGTH,
        ttl: int = auth_conf.AUTH_OTP_CHALLENGE_TTL,
    ) -> None:
        self._secret = secret
        self._callback = callback
        self._code_length = code_length
        self._ttl = ttl

    def _new_code(self) -> str:
        return "".join(secrets.choice(string.digits) for _ in range(self._code_length))

    async def is_enrolled(self, user: Mapping) -> bool:
        """Enrolment is implicit: True whenever the user has a usable address."""
        return _usable_email(user) is not None

    async def start_enrollment(self, user: Mapping, authorization: EnrollmentAuthorization) -> dict:
        """Nothing to enrol; report the masked address (or None)."""
        address = _usable_email(user)
        return {"email": mask_email(address) if address else None}

    async def confirm_enrollment(
        self, user: Mapping, code: str, enrollment_token: str, session_id: str, *, conn: Any = None
    ) -> bool:
        """Nothing to confirm for an implicit factor."""
        return False

    async def challenge(self, request: web.Request, user: Mapping) -> dict:
        """Generate a code, hand it to the callback, return ONLY its hash.

        The return value is identical in shape whether delivery succeeded, the
        user has no usable address, or the callback raised (spec R9).
        """
        code = self._new_code()
        address = _usable_email(user)
        payload = OtpNotificationPayload(
            email=address or "",
            display_name=str(_field(user, "display_name") or _field(user, "username") or ""),
            username=str(_field(user, "username") or ""),
            code=code,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self._ttl),
            found=address is not None,
        )
        await invoke_callback(self._callback, payload, label="otp-email")
        return {"code_hash": hash_code(code, self._secret)}

    async def verify(
        self, request: web.Request, user: Mapping, code: str, challenge: Optional[MfaChallenge] = None
    ) -> bool:
        """Constant-time compare of the keyed hash of ``code`` with the challenge's stored hash."""
        # FILL IN, in this order — bounded by spec M4 + D4:
        #  1. challenge is None or not challenge.email_code_hash ⇒ False
        #  2. challenge.user_id != int(_field(user, "user_id")) ⇒ False (defensive)
        #  3. code not a str, or stripped code not exactly self._code_length
        #     digits ⇒ False
        #  4. return secrets.compare_digest(hash_code(code, self._secret), challenge.email_code_hash)

    async def disenroll(self, user: Mapping, *, conn: Any = None) -> None:
        """No-op: the e-mail floor cannot be switched off per user (a strong factor closes it)."""
        return None
```

**Why `challenge()` builds the payload even without an address.** Branching
early ("no address ⇒ return nothing") would make the return value — and
therefore the caller's response timing and shape — depend on account data,
which is exactly the oracle R9 forbids. The callback gets `found=False` and
decides what (if anything) to send; the login path separately refuses an
enforced user with no usable address through TASK-135/TASK-138
(`no_factor_available`), so a code delivered nowhere never authenticates
anyone.

**Why the defaults read `auth_conf` at import while `notify` reads it at call
time.** The contract fixes the constructor defaults; `MfaServices` builds the
provider once per process (the spec's "built once per process" for the
provider set), and tests construct it with explicit arguments. Notifications
have no constructor, so they read the module at call time.

**Why `secrets.choice` and `compare_digest`.** A 6-digit code has 20 bits; the
5-attempt budget (TASK-131) is what bounds guessing, but the code itself must
still be unpredictable (`random` is not), and the comparison must not leak
prefix matches through timing.

### `tests/test_mfa_email_provider.py` — CREATE

```python
"""FEAT-106 Module 4 — EmailOTPProvider + notify (spec §4 M4 rows, R9, D6, AC14)."""
import logging
from types import SimpleNamespace

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from navigator_auth.conf import REDIS_AUTH_URL
from navigator_auth.mfa.email_otp import EmailOTPProvider, hash_code, mask_email
from navigator_auth.mfa import notify
from navigator_auth.mfa.store import CHALLENGE_KEY_PREFIX, MfaChallengeStore
from navigator_auth.mfa.types import MfaSecurityNotice, OtpNotificationPayload

SECRET = b"test-mfa-email-secret"   # every EmailOTPProvider(...) in this file passes secret=SECRET
USER = {"user_id": 4242, "username": "otp_user", "email": "otp_user@example.com", "display_name": "Otp User"}
CAPTURED: list = []


def capture(payload):            # sync callback, referenced by dotted path
    CAPTURED.append(payload)


async def capture_async(payload):
    CAPTURED.append(payload)


def explode(payload):
    raise RuntimeError(f"smtp down while sending {payload.code}")   # message embeds the code


CALLBACK = f"{__name__}.capture"


@pytest.fixture(autouse=True)
def _reset():
    CAPTURED.clear()


@pytest_asyncio.fixture
async def redis_pool():
    # Local fixture on purpose: TASK-137 depends only on TASK-131, so
    # tests/fixtures/mfa.py (TASK-130) may not exist yet.
    pool = aioredis.ConnectionPool.from_url(REDIS_AUTH_URL, decode_responses=True, encoding="utf-8")
    yield pool
    # FILL IN: delete f"{CHALLENGE_KEY_PREFIX}*" keys created by the test, then disconnect


class TestChallenge:
    @pytest.mark.asyncio
    async def test_challenge_hands_code_to_callback(self):
        # FILL IN: EmailOTPProvider(secret=SECRET, callback=CALLBACK); result == {"code_hash": hash_code(CAPTURED[0].code, SECRET)};
        #  payload.found is True, len(code)==6 and digits, expires_at tz-aware

    @pytest.mark.asyncio
    async def test_email_otp_response_identical_when_unknown(self):
        """No address, delivery failure and success return the same shape, never raise (R9)."""
        # FILL IN: three runs (user with email + CALLBACK; user without email + CALLBACK;
        #  user with email + f"{__name__}.explode"); each result has exactly the key
        #  "code_hash" with a 64-hex value; the no-address payload has found=False, email=""

    @pytest.mark.asyncio
    async def test_email_otp_callback_exception_is_contained(self, caplog):
        """A raising callback neither raises nor leaks the code into logs."""
        # FILL IN: explode callback; no exception; code absent from caplog.text;
        #  "RuntimeError" present at WARNING

    @pytest.mark.asyncio
    async def test_async_and_missing_callbacks(self, caplog):
        # FILL IN: capture_async works; callback=None ⇒ WARNING "no otp-email callback", no raise

    @pytest.mark.asyncio
    async def test_email_otp_persists_only_hash(self, redis_pool):
        """The challenge record holds the keyed hash of the code, never the code (spec row: "sha256(code)", refined by D30)."""
        # FILL IN: result = await provider.challenge(None, USER); store = MfaChallengeStore(redis_pool, b"k"*32);
        #  token, rec = await store.issue(USER, ["email"], "email", security_version=0,
        #  context_digest="d", email_code_hash=result["code_hash"]); raw Redis value under
        #  CHALLENGE_KEY_PREFIX + sha256(token) contains the hash and not CAPTURED[0].code


class TestVerify:
    # FILL IN helper: a minimal challenge object — build a real MfaChallenge via
    #  MfaChallengeStore.issue in a live test, or SimpleNamespace(user_id=…, email_code_hash=…)
    #  for pure unit tests (verify only reads those two attributes).
    @pytest.mark.asyncio
    async def test_verify_accepts_matching_code(self):
        # FILL IN

    @pytest.mark.asyncio
    async def test_verify_rejects_wrong_missing_or_malformed(self):
        # FILL IN: wrong code; challenge=None; email_code_hash=None; other user_id; "12a456"; "1234567"


class TestRedaction:
    def test_notification_payload_repr_redacted(self):
        """repr()/str() of the payload never show the code (AC14, AC34)."""
        # FILL IN: OtpNotificationPayload(..., code="918273", ...); "918273" not in repr(p) nor str(p)

    def test_mask_email(self):
        # FILL IN: "jane@example.com" → "j***@example.com"; "" / "nope" / "@x" / "a@" → "***"


class TestNotify:
    @pytest.mark.asyncio
    async def test_notify_security_event_uses_callback(self, monkeypatch):
        # FILL IN: monkeypatch notify.auth_conf.AUTH_MFA_NOTIFY_CALLBACK = CALLBACK; notice delivered once

    @pytest.mark.asyncio
    async def test_notify_security_event_unset_logs_info(self, monkeypatch, caplog):
        # FILL IN: None ⇒ INFO record mentioning the event, no WARNING, no raise
```

**Why `explode` embeds the code in its message.** It is the realistic failure
(an SMTP wrapper formatting the body) and the only way to prove the log line
carries the class name and not the message.

### Steps (in order)

1. Confirm TASK-129 and TASK-131 are in `sdd/tasks/completed/`; check that
   `OtpNotificationPayload.code` is declared `Field(repr=False)` and that
   `conf.py` defines `AUTH_OTP_EMAIL_CALLBACK`, `AUTH_MFA_NOTIFY_CALLBACK`,
   `AUTH_OTP_CODE_LENGTH`, `AUTH_OTP_CHALLENGE_TTL`.
2. Write `notify.py` (complete as given). `python -c "import navigator_auth.mfa.notify"`.
3. Write `email_otp.py`; fill `mask_email`, `_field`, `_usable_email`, `verify`.
   Keep `_field`/`_usable_email` local (D26) — the shared versions in
   `mfa/state.py` (TASK-135) must apply the identical rule; TASK-135 owns the
   cross-check test.
4. Write the tests; run them.
5. D5 grep on both files; `ruff check`.
6. Read every `logger.` call in both files: none may format `payload`, a
   payload field other than `event`/`username`, or an exception message.

### FILL IN checklist

- [ ] `mask_email` — masking rule, `***` fallback
- [ ] `_field` — dict / `.get` / attribute
- [ ] `_usable_email` — rule identical to TASK-135, kept local (D26)
- [ ] `EmailOTPProvider.verify` — four-step order, constant-time compare
- [ ] Test fixture cleanup + every test body above

---

## Acceptance Criteria

- [ ] **AC-1** `notify.invoke_callback` imports a dotted path, supports sync, async and awaitable-returning callables, returns True/False, and never raises.
- [ ] **AC-2** Callback failures log at WARNING with the exception class name only; a code embedded in the exception message never reaches the logs (spec **R9**, **AC14**).
- [ ] **AC-3** `notify_security_event` delivers an `MfaSecurityNotice` to `AUTH_MFA_NOTIFY_CALLBACK` and logs at INFO when it is unset (D6); never raises.
- [ ] **AC-4** `EmailOTPProvider.challenge` returns exactly `{"code_hash": <64-hex HMAC>}` whether delivery succeeded, the address is missing (`found=False`) or the callback raised.
- [ ] **AC-5** The raw code exists only in the `OtpNotificationPayload` handed to the callback; a challenge record built from `challenge()`'s result contains the hash and not the code (closes the provider half of spec **AC14**).
- [ ] **AC-6** `verify` requires a challenge with a matching `user_id` and `email_code_hash`, a correctly shaped code, and uses `secrets.compare_digest`.
- [ ] **AC-7** `_is_strong is False`, `_provider_name == "email"`; `start_enrollment` returns only a masked address; `disenroll` is a no-op.
- [ ] **AC-8** `grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/email_otp.py navigator_auth/mfa/notify.py` prints nothing (D5 / spec **AC5**).
- [ ] **AC-9** `pytest tests/test_mfa_email_provider.py -v` passes; `ruff check` clean; no new dependency (spec **AC4**).
- [ ] **AC-10** Neither file touches Postgres; `grep -n "\.execute(" navigator_auth/mfa/email_otp.py navigator_auth/mfa/notify.py` prints nothing (D25).

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_email_provider.py -v
ruff check navigator_auth/mfa/email_otp.py navigator_auth/mfa/notify.py tests/test_mfa_email_provider.py
grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/email_otp.py navigator_auth/mfa/notify.py   # must print nothing
```

Spec §4 rows owned here: `test_email_otp_persists_only_hash`,
`test_email_otp_response_identical_when_unknown` (provider level),
`test_email_otp_callback_exception_is_contained`,
`test_notification_payload_repr_redacted`. The resend row
`test_resend_preserves_budget_and_expiry` belongs to TASK-131 (store) and
TASK-140 (endpoint).

---

## Agent Instructions

1. **Read the spec** `sdd/specs/basicauth-otp-2fa.spec.md` — §3 Module 4, §2
   Data Models (`OtpNotificationPayload`), §7 R3, R4, R9, and the shared
   contract decisions D5, D6.
2. **Check dependencies** — TASK-131 (and transitively TASK-129) must be in
   `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint. Do not import from `handlers/recovery/`;
   do not edit `navigator_auth/mfa/__init__.py`.
5. **Verify** every acceptance criterion, AC-2 and AC-4 included.
6. **Move this file** to `sdd/tasks/completed/TASK-137-mfa-email-provider.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any
