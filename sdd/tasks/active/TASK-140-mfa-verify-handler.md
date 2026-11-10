# TASK-140: `MfaHandler` — challenge resend + verify, and MFA route registration

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-138, TASK-139
**Assigned-to**: unassigned

> **NOT delegation-eligible.** `verify()` is the only code path in the feature
> that turns a second factor into a session. Its correctness is about lock
> scope, ordering and what is (not) consumed on failure — properties a wrong
> edit breaks silently. Thinking model only.

---

## Context

Implements the HTTP second step of **spec §3 Module 10** (`MfaHandler.challenge`
and `MfaHandler.verify`) under the normative **"Security contracts shared by
the modules"** — specifically *Challenge validity and invalidation* and *Retry
accounting and concurrency*. TASK-138 issues a signed challenge and raises
`MFARequired`; TASK-139 returns it as `401 {mfa_required, challenge, …}`. The
client then calls `POST /auth/mfa/verify`. This task owns that endpoint, the
e-mail resend endpoint, the route registration, and the exclusion of exactly
these two routes from the auth middleware.

### The correctness argument

The spec's retry/concurrency contract, restated as the invariants this code
must hold:

1. **One lock, shared by all workers, held through session creation.** The
   per-user PostgreSQL advisory lock (`MfaSecurity.user_lock`, transaction-scoped)
   wraps everything from the re-read of the challenge to `finalize_login()`.
   A security transition (TASK-141/144) takes the same lock, so "either login
   completes before revocation or revocation wins and verification fails". No
   Redis lease that could expire mid-flight.
2. **The lock's user id comes from an authenticated record**, never the request:
   an unlocked `peek()` (HMAC-verified) only tells us *whose* lock to take; the
   record is **re-read after** acquiring it.
3. **Fresh context, compared to the signed one.** Under the lock: fresh user
   (`_idp.user_from_id`), fresh `services.evaluate(user, conn=conn)` (TASK-138),
   then `security_version` and `context_digest` must equal the record's —
   otherwise the challenge is **discarded** (`stale_challenge`). This is what
   makes recovery, password change, factor changes, policy hardening and
   membership edits kill outstanding challenges (AC30).
4. **Provider in both allowlists.** The submitted provider must be in the
   signed `record.providers` **and** the current `evaluation.providers`; a
   forged or since-closed provider (e.g. `email` after TOTP confirmation)
   counts as a failed attempt (AC9, AC30).
5. **Failures never consume; success consumes once.** A wrong code calls
   `register_failure` (attempts 1–4 keep the challenge, the 5th burns it —
   AC31). Only after a successful factor check: `consume()` (GETDEL), and the
   consumed record must equal the verified one before the session is opened.
   Nothing is ever restored after a downstream failure (consumed challenge,
   consumed backup code).
6. **Fail closed.** Any storage error (Redis, Postgres, vault inside a provider)
   ⇒ `503 mfa_unavailable` and no session (AC12, R5).

---

## Scope

- Create `navigator_auth/handlers/mfa.py` with `MFA_PREFIX`, `MfaHandler.verify`,
  `MfaHandler.challenge` (resend), private helpers, and `setup_mfa_routes()`
  registering `POST /auth/mfa/challenge` and `POST /auth/mfa/verify` and
  appending both to `app[AUTH_EXCLUDE_LIST_KEY]`.
- Modify `navigator_auth/handlers/__init__.py`: call `setup_mfa_routes()` from
  `setup_handlers()` **only when** `AUTH_BASIC_2FA_ENABLED` (AC20).
- Write `tests/test_mfa_verify.py`.

**NOT in scope**:
- Enrollment / disenrollment / backup-code endpoints (TASK-141) and admin
  disenrolment (TASK-142) — they extend `setup_mfa_routes()` later; do not stub them.
- Security-event hooks on password/recovery/passkey paths (TASK-144).
- Changing `finalize_login` (TASK-139) or the BasicAuth hook (TASK-138).
- Updating `user_mfa.last_used_at` or writing audit rows for successful logins
  (a login is not a factor-state transition; AC23 does not list it).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/mfa.py` | CREATE | `MfaHandler` (challenge, verify), `setup_mfa_routes` |
| `navigator_auth/handlers/__init__.py` | MODIFY | gated registration |
| `tests/test_mfa_verify.py` | CREATE | retry budget, concurrency, staleness, fail-closed |

---

## Codebase Contract

> Re-verified on `dev` @ `b10a3a3` (2026-11-11). *(TASK-NNN)* = created by a dependency.

### Verified Imports

```python
import logging
import secrets
from typing import Any, Optional
from aiohttp import web
from navigator_auth import conf as auth_conf                     # module attr read at call time (pattern: backends/passkey.py:18)
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY            # conf.py:48
from navigator_auth.responses import JSONResponse                # responses.py:75 (content, status=200, headers=None, …)
from navigator_auth.exceptions import FailedAuth, UserNotFound   # exceptions.py:47, :32
from navigator_auth.exceptions import MfaSignal                  # (TASK-129)
from navigator_auth.mfa.exceptions import MfaStorageError        # (TASK-129)
from navigator_auth.mfa.services import get_mfa_services, MfaServices   # (TASK-138)
from navigator_auth.mfa.trusted_devices import may_offer_trusted_device      # (TASK-133; the single AC17 predicate, contract D27)
from navigator_auth.mfa.types import (AMR_BY_PROVIDER, AMR_PASSWORD, MFA_DEVICE_TOKEN_KEY,
                                      PROVIDER_EMAIL, MfaChallenge, MfaEvaluation)   # (TASK-129)
# handlers/__init__.py additions
from .. import conf as auth_conf
from .mfa import setup_mfa_routes
# tests
import asyncio
import pytest, pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from unittest.mock import AsyncMock
from navigator_auth.mfa.services import MFA_APP_KEY, MfaServices, MfaServicesSlot   # (TASK-138)
from navigator_auth.mfa.store import MfaChallengeStore            # (TASK-131)
from navigator_auth.mfa.limiter import StrictRateLimiter          # (TASK-131)
from navigator_auth.mfa.security import MfaSecurity               # (TASK-132)
from tests.fixtures.mfa import mfa_redis_pool, broken_redis_pool, mfa_db, mfa_secret   # (TASK-130)  # noqa: F401
```

### Existing facts (verified)

- `handlers/__init__.py:20` `def setup_handlers(app, router)`; it is called from
  `AuthHandler.setup()` at `auth.py:713`, **after** `app[AUTH_EXCLUDE_LIST_KEY]`
  is seeded at `auth.py:669` and before the app is frozen — so `setup_mfa_routes`
  may append to the list and add routes.
- Insertion anchor `    ## Security: Environment/Config debug (superuser only, GET only):`
  (`handlers/__init__.py:128`, 1 occurrence). Import anchor
  `from .client_access import ClientAccessHandler` (`:17`, 1 occurrence);
  `from ..conf import SECURITY_CONFIG_HANDLER` (`:2`, 1 occurrence).
- `AuthHandler` is stored at `request.app["auth"]` (`auth.py:90` `name = "auth"`,
  `:671` `self.app[self.name] = self`). `finalize_login(request, userdata)` is
  added by TASK-139.
- `IdentityProvider.user_from_id(uid)` (`backends/idp/__init__.py`, used at
  `auth.py:423`) returns the `AUTH_USER_VIEW` record or raises `UserNotFound`.
  The backend keeps it on `self._idp` (`basic.py:90`, `:105`).
- `BasicAuth.open_session(request, user, extra=None, expiration=None) -> dict`
  (`basic.py:170`); raises `FailedAuth(403)` for an inactive user (`:202-204`).
- Client IP: `request.remote` (house style — `handlers/recovery/handler.py:179`).

### Dependency contracts consumed

```python
# TASK-138
get_mfa_services(app) -> Optional[MfaServices]
MfaServices: backend, available, store, user_limiter, ip_limiter, security, trusted_devices, providers: dict[str, AbstractOTPProvider]
    async evaluate(user, *, conn=None) -> MfaEvaluation      # may raise MFARefused(strong_factor_required)
# TASK-131
MfaChallengeStore: async peek(token) / consume(token) -> Optional[MfaChallenge]; async discard(token) -> None
    async register_failure(token) -> int   # remaining; 0 = burned; -1 = absent
    async replace_email_code(token, new_code_hash) -> Optional[MfaChallenge]; async remaining_ttl(token) -> int
    # every Redis error ⇒ MfaStorageError
StrictRateLimiter: async check(key) -> bool   # storage error ⇒ False
# TASK-132
MfaSecurity.user_lock(user_id) -> async context manager yielding conn (transaction; commit on normal exit, rollback on exception)
# TASK-133
TrustedDeviceStore.issue(user_id, days, label, *, conn=None) -> str
def may_offer_trusted_device(*, has_strong_factor: bool, remember_days: int) -> bool   # D27 — the ONLY AC17 rule
# TASK-129/134/136/137
AbstractOTPProvider.verify(request, user, code, challenge=None) -> bool   # TOTP marks the step (replay); backup consumes on its OWN connection (D16)
EmailOTPProvider.challenge(request, user) -> {"code_hash": str}          # never raises on delivery failure
MfaChallenge: user_id, username, providers: tuple[str, ...], preferred, issued_at, security_version, context_digest, email_code_hash, signature
MfaEvaluation: user_id, policy, memberships, state, has_strong_factor, totp_confirmed, providers, preferred, security_version, context_digest
AMR_BY_PROVIDER = {"email": "otp", "totp": "totp", "backup": "backup"}; AMR_PASSWORD = "pwd"
MFA_DEVICE_TOKEN_KEY = "_mfa_trusted_device"
```

### Does NOT Exist (do not reference)

- ~~a request-supplied `user_id` in verify/resend~~ — forbidden; the user comes from the HMAC-verified record (spec retry contract).
- ~~a Redis lock / `SETNX` lease for verification~~ — forbidden ("No Redis lock lease may expire and allow two workers to mint sessions").
- ~~restoring a challenge or backup code after a downstream failure~~ — forbidden.
- ~~`MfaHandler` as a `navigator.views.BaseView`~~ — not used; plain class with bound coroutine routes and `JSONResponse` (no `self.error()` raising semantics).
- ~~enrollment/admin routes in this task~~ — TASK-141/142.
- ~~`AuthHandler.add_exclude_list` for these paths~~ — not used; follow `basic.py:62` and append to `app[AUTH_EXCLUDE_LIST_KEY]` directly (idempotently).
- ~~a local "strong factor and remember_days > 0" check~~ — call `may_offer_trusted_device()` (D27).
- ~~`conn.execute(...)` in `handlers/mfa.py`~~ — asyncdb's `execute()` swallows every exception and returns from
  `finally` (verified `.venv/.../asyncdb/drivers/pg.py:937-972`, contract D25). This handler issues no SQL itself;
  every DB effect goes through the TASK-131…136 primitives, which use `fetchval`/`fetch_one` with `RETURNING`.

---

## Implementation Blueprint

### `navigator_auth/handlers/mfa.py` — CREATE (block 1 of 3: header, helpers, routes)

```python
"""Second-factor HTTP surface (FEAT-106, spec §3 Module 10).

Only ``verify()`` turns a factor into a session. Every verification and resend
runs under the per-user PostgreSQL advisory lock (MfaSecurity.user_lock), held
through session creation, so it serializes with every MFA security transition.
Codes, challenge tokens and device tokens are never logged (AC14).
"""
import logging
import secrets
from typing import Any, Optional

from aiohttp import web

from navigator_auth import conf as auth_conf
from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY
from navigator_auth.exceptions import FailedAuth, MfaSignal, UserNotFound
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.services import MfaServices, get_mfa_services
from navigator_auth.mfa.trusted_devices import may_offer_trusted_device
from navigator_auth.mfa.types import (
    AMR_BY_PROVIDER, AMR_PASSWORD, MFA_DEVICE_TOKEN_KEY, PROVIDER_EMAIL, MfaChallenge, MfaEvaluation,
)
from navigator_auth.responses import JSONResponse

logger = logging.getLogger("navigator.auth.mfa")

MFA_PREFIX = "/auth/mfa"
NO_STORE = {"Cache-Control": "no-store"}


def _error(code: str, status: int, **extra: Any) -> web.Response:
    """Uniform JSON error; never carries a code, token or seed."""
    return JSONResponse({"error": code, **extra}, status=status, headers=NO_STORE)


async def _json_body(request: web.Request) -> dict:
    """The JSON object body, or {} for anything else (never raises)."""
    # FILL IN: try await request.json(); return it only if isinstance(..., dict); except Exception → {}


def _remote(request: web.Request) -> str:
    return request.remote or "unknown"


def setup_mfa_routes(app: web.Application, router: Any) -> None:
    """Register the MFA routes. Called by setup_handlers() only when AUTH_BASIC_2FA_ENABLED.

    challenge/verify are reachable without a session (the caller holds only a
    first-factor challenge token), so they are excluded from the auth
    middleware; management routes added by TASK-141/142 are NOT excluded.
    """
    handler = MfaHandler()
    router.add_post(f"{MFA_PREFIX}/challenge", handler.challenge, name="mfa_challenge")
    router.add_post(f"{MFA_PREFIX}/verify", handler.verify, name="mfa_verify")
    excluded = app[AUTH_EXCLUDE_LIST_KEY]
    for path in (f"{MFA_PREFIX}/challenge", f"{MFA_PREFIX}/verify"):
        if path not in excluded:
            excluded.append(path)
    # TASK-141 / TASK-142 register their (non-excluded) routes below this line.
```

**Why a plain class with `JSONResponse`.** `navigator.views` handlers raise
from `self.error()`; here every exit must be an explicit, reviewed response
(several of them deliberately *commit* the lock transaction after recording a
failed attempt). `BasicAuth.configure` (`basic.py:62`) is the precedent for
appending to the exclude list directly.

### `navigator_auth/handlers/mfa.py` — CREATE (block 2 of 3: verify)

```python
class MfaHandler:
    """Challenge resend and verification (management routes added by TASK-141/142)."""

    async def verify(self, request: web.Request) -> web.Response:
        """POST /auth/mfa/verify — {challenge, provider, code[, remember_device, device_label]}."""
        services = get_mfa_services(request.app)
        if services is None or not services.available:
            return _error("mfa_unavailable", 503)
        body = await _json_body(request)
        token, provider, code = body.get("challenge"), body.get("provider"), body.get("code")
        if not all(isinstance(v, str) and v for v in (token, provider, code)):
            return _error("invalid_request", 400)
        try:
            preview = await services.store.peek(token)  # ONLY to learn whose lock to take
            if preview is None:
                return _error("invalid_challenge", 401)
            async with services.security.user_lock(preview.user_id) as conn:
                return await self._verify_locked(request, services, conn, token, provider, code, body)
        except web.HTTPException:
            raise  # e.g. finalize_login's session-creation failure: already an HTTP answer
        except Exception as err:  # pylint: disable=W0703 — fail CLOSED (AC12, R5)
            logger.error("MFA verify: refused, dependency failure: %s", type(err).__name__)
            return _error("mfa_unavailable", 503)

    async def _verify_locked(
        self, request: web.Request, services: MfaServices, conn: Any,
        token: str, provider: str, code: str, body: dict,
    ) -> web.Response:
        """Everything below runs inside ONE advisory-lock transaction, through finalize_login."""
        record = await services.store.peek(token)  # re-read AFTER acquiring the lock
        if record is None:
            return _error("invalid_challenge", 401)
        stale = await self._revalidate(request, services, conn, token, record)
        if isinstance(stale, web.Response):
            return stale
        user, evaluation = stale
        if not await services.user_limiter.check(str(record.user_id)) or not await services.ip_limiter.check(_remote(request)):
            return _error("rate_limited", 429)
        if provider not in record.providers or provider not in evaluation.providers or provider not in services.providers:
            return await self._failed(services, token)  # forged/closed provider = failed attempt (AC30)
        if not await services.providers[provider].verify(request, user, code, challenge=record):
            return await self._failed(services, token)
        consumed = await services.store.consume(token)  # GETDEL only after success
        if consumed is None or consumed != record:
            return _error("invalid_challenge", 401)  # expired/raced: never recreated (AC31)
        extra = {"auth_method": "basic", "mfa": True, "amr": [AMR_PASSWORD, AMR_BY_PROVIDER[provider]]}
        try:
            result = await services.backend.open_session(request, user, extra=extra)
        except FailedAuth as err:
            return _error("account_disabled", err.status)
        device = await self._maybe_trust_device(services, conn, evaluation, body)
        if device is not None:
            result[MFA_DEVICE_TOKEN_KEY] = device  # D14: popped by finalize_login
        return await request.app["auth"].finalize_login(request, result)
```

**Why the unlocked `peek` is safe.** It is HMAC-verified (TASK-131), so the
`user_id` it yields is one *this server* signed; it is used only to pick the
lock. Nothing is decided from it: the record is re-read under the lock, and a
challenge that vanished meanwhile is `invalid_challenge`.

**Why the limiter runs after revalidation.** The spec orders it "read and
validate the challenge/context, apply user/IP limits, verify the allowed
provider, then GETDEL". A limiter hit is not a failed attempt (no
`register_failure`): it refuses without spending the budget. A limiter
*storage* error returns `False` (TASK-131) ⇒ 429 — fail closed.

**Why `open_session` and `finalize_login` stay inside the lock.** That is the
"serialize with verification through session creation" requirement: a
concurrent recovery completion (TASK-144) waits for this transaction, then its
revoker kills the session just created — or it wins first, and this
revalidation sees a new version/digest and refuses.

### `navigator_auth/handlers/mfa.py` — CREATE (block 3 of 3: revalidation, failure, device, resend)

```python
    async def _revalidate(self, request, services, conn, token, record: MfaChallenge):
        """Fresh user + evaluation; discard the challenge on ANY drift. Returns (user, evaluation) or a Response."""
        try:
            user = await services.backend._idp.user_from_id(record.user_id)
        except UserNotFound:
            await services.store.discard(token)
            return _error("invalid_challenge", 401)
        try:
            evaluation = await services.evaluate(user, conn=conn)
        except MfaSignal as err:  # strong_factor_required (AC33): no email, no device, no session
            await services.store.discard(token)
            return JSONResponse(err.payload(), status=err.status, headers=NO_STORE)
        if evaluation.security_version != record.security_version or not secrets.compare_digest(
            evaluation.context_digest, record.context_digest
        ):
            await services.store.discard(token)
            return _error("stale_challenge", 401)
        return user, evaluation

    async def _failed(self, services: MfaServices, token: str) -> web.Response:
        """Count a failed attempt; attempts 1–4 keep the challenge, the 5th burns it (AC31)."""
        remaining = await services.store.register_failure(token)
        if remaining < 0:
            return _error("invalid_challenge", 401)
        return _error("invalid_code", 401, attempts_remaining=remaining)

    async def _maybe_trust_device(self, services, conn, evaluation: MfaEvaluation, body: dict) -> Optional[dict]:
        """Issue a trusted device only when asked AND allowed (M6, AC17)."""
        if not body.get("remember_device"):
            return None
        if not may_offer_trusted_device(  # D27: same predicate the BasicAuth hook uses to ACCEPT a device
            has_strong_factor=evaluation.has_strong_factor, remember_days=evaluation.policy.remember_days
        ):
            return None
        # FILL IN: label = str(body.get("device_label") or "")[:128];
        #   raw = await services.trusted_devices.issue(evaluation.user_id, evaluation.policy.remember_days, label, conn=conn)
        #   return {"token": raw, "max_age": evaluation.policy.remember_days * 86400}
        #   — conn=conn so a login that fails after this point rolls the device row back (AC17, D14).

    async def challenge(self, request: web.Request) -> web.Response:
        """POST /auth/mfa/challenge — {challenge}. Resend an e-mail code.

        Same lock and revalidation as verify. Rotates the code hash (the old code
        stops working), keeps the original expiry and the cumulative attempt
        budget. The 202 body is identical whether or not a code was delivered or
        e-mail is even a provider of this challenge (anti-enumeration, R9).
        """
        services = get_mfa_services(request.app)
        if services is None or not services.available:
            return _error("mfa_unavailable", 503)
        token = (await _json_body(request)).get("challenge")
        if not isinstance(token, str) or not token:
            return _error("invalid_request", 400)
        # FILL IN, mirroring verify():
        #  try: preview = await services.store.peek(token); None → 401 invalid_challenge
        #       async with services.security.user_lock(preview.user_id) as conn:
        #           record = re-peek (None → 401); stale = await self._revalidate(...) (Response → return it)
        #           limiter check (user + IP) → 429
        #           if PROVIDER_EMAIL in record.providers and PROVIDER_EMAIL in evaluation.providers:
        #               issued = await services.providers[PROVIDER_EMAIL].challenge(request, user)
        #               if await services.store.replace_email_code(token, issued["code_hash"]) is None → 401 invalid_challenge
        #           expires_in = await services.store.remaining_ttl(token)
        #  except web.HTTPException: raise; except Exception → 503 mfa_unavailable (log class name only)
        #  return JSONResponse({"status": "accepted", "expires_in": expires_in}, status=202, headers=NO_STORE)
        #  — bounded by spec "Challenge validity and invalidation" (resend paragraph), AC30, R9.
```

**Why resend never touches the attempt counter or TTL.** The spec: "retain the
original expiry and cumulative attempt budget". `replace_email_code` re-signs
the immutable record with `KEEPTTL`/`XX` and leaves the separate attempts key
alone (TASK-131), so resending cannot be used to reset guessing.

**Why `_revalidate` discards on drift instead of counting a failure.** A
changed context means the challenge was issued for a world that no longer
exists (new password, recovery, enrolled TOTP, hardened tenant). Keeping it
alive would let a later correct code authenticate into the new world — spec
`test_pending_challenge_invalid_after_recovery`,
`test_email_challenge_invalid_after_totp_confirmation`.

### `navigator_auth/handlers/__init__.py` — MODIFY

```python
# AFTER `from ..conf import SECURITY_CONFIG_HANDLER` (verified: handlers/__init__.py:2)
# occurrences: 1 (verified: grep -cF 'from ..conf import SECURITY_CONFIG_HANDLER' navigator_auth/handlers/__init__.py)
from .. import conf as auth_conf

# AFTER `from .client_access import ClientAccessHandler` (verified: handlers/__init__.py:17)
# occurrences: 1 (verified: grep -cF 'from .client_access import ClientAccessHandler' navigator_auth/handlers/__init__.py)
from .mfa import setup_mfa_routes

# BEFORE `    ## Security: Environment/Config debug (superuser only, GET only):` (verified: handlers/__init__.py:128)
# occurrences: 1 (verified: grep -cF '    ## Security: Environment/Config debug (superuser only, GET only):' navigator_auth/handlers/__init__.py)
    ## Second factor for BasicAuth (FEAT-106): the routes exist only when the
    ## global kill switch is on, so a deployment that never opts in is unchanged (AC20).
    if auth_conf.AUTH_BASIC_2FA_ENABLED:
        setup_mfa_routes(app, router)
```

**Why gate registration, not just the handler.** With the flag off, `/auth/mfa/*`
must not exist at all (404 from the router), and nothing is added to the
exclude list — the strongest form of "zero behavioural change" (G8, AC20).

### `tests/test_mfa_verify.py` — CREATE

```python
"""FEAT-106 TASK-140 — verify/resend: lock scope, retry budget, staleness, fail-closed.

Real Redis (challenge store) and real Postgres (advisory lock) via tests/fixtures/mfa.py;
MfaServices.evaluate, the backend, the providers and app["auth"].finalize_login are fakes so
each invariant of the handler is observable. Skips when Postgres is unreachable (mfa_db).
"""
import asyncio
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY
from navigator_auth.handlers.mfa import setup_mfa_routes
from navigator_auth.mfa.limiter import StrictRateLimiter
from navigator_auth.mfa.security import MfaSecurity
from navigator_auth.mfa.services import MFA_APP_KEY, MfaServices, MfaServicesSlot
from navigator_auth.mfa.store import MfaChallengeStore
from tests.fixtures.mfa import broken_redis_pool, mfa_db, mfa_redis_pool, mfa_secret  # noqa: F401

pytestmark = [pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")]

# FILL IN helpers/fixtures:
#  - FakeBackend: _idp.user_from_id = AsyncMock(return_value=USER); open_session = AsyncMock(return_value={"token": "t", "user_id": 7})
#  - FakeProvider(accept: str): async verify(request, user, code, challenge=None) -> code == accept; async challenge(...) -> {"code_hash": h}
#  - FakeAuth: finalize_login = AsyncMock(side_effect=lambda req, res: JSONResponse({"ok": True}))
#  - evaluation(**over) -> MfaEvaluation matching the issued record (same security_version / context_digest / providers)
#  - client fixture: web.Application(); app[AUTH_EXCLUDE_LIST_KEY] = []; app[MFA_APP_KEY] = MfaServicesSlot(services);
#    app["auth"] = FakeAuth(); setup_mfa_routes(app, app.router); TestClient(TestServer(app))
#  - issue(store, providers=("email",), …) -> token via store.issue(...)


@pytest.mark.asyncio
async def test_concurrent_verify_consumes_once(client):
    """AC31: two correct submissions in parallel ⇒ exactly one 200 and one 401; open_session awaited once.
    Mixed correct/incorrect in parallel never resurrects a consumed challenge."""
    # FILL IN (asyncio.gather of two POSTs)


@pytest.mark.asyncio
async def test_challenge_retry_budget(client):
    """AC31: 4 wrong (attempts_remaining 4→1) keep it, correct 5th ⇒ 200; 5 wrong ⇒ burned, then correct ⇒ 401."""
    # FILL IN


@pytest.mark.asyncio
async def test_verify_rejects_disallowed_provider(client):
    """AC9/AC30: provider absent from the signed list, or present but closed now (email after TOTP), counts as a failure."""
    # FILL IN


@pytest.mark.asyncio
async def test_stale_challenge_rejected(client):
    """AC30: version or digest drift ⇒ 401 stale_challenge and the challenge is discarded (peek → None)."""
    # FILL IN


@pytest.mark.asyncio
async def test_strong_factor_required_on_verify(client):
    """AC33: evaluate raises strong_factor_required ⇒ 403 payload, challenge discarded, no session."""
    # FILL IN


@pytest.mark.asyncio
async def test_expiry_during_verification(client):
    """AC31: challenge vanishes between peek and consume ⇒ 401, open_session never awaited, key not recreated."""
    # FILL IN


@pytest.mark.asyncio
async def test_resend_preserves_budget_and_expiry(client):
    """AC30: resend needs a live challenge, rotates the code (old fails, new passes), TTL not extended,
    attempts cumulative; body identical whether or not email is a provider (R9)."""
    # FILL IN


@pytest.mark.asyncio
async def test_mfa_verify_finalizes_session(client):
    """Success ⇒ open_session(extra mfa=True, amr=['pwd','otp']) then finalize_login once; failure ⇒ neither."""
    # FILL IN


@pytest.mark.asyncio
async def test_remember_device_only_when_allowed(client):
    """AC17: remember_device issues a device only for strong-factor users with remember_days > 0."""
    # FILL IN


@pytest.mark.asyncio
async def test_verify_fails_closed_when_redis_down(broken_redis_pool, mfa_db, mfa_secret):
    """AC12: store errors ⇒ 503 mfa_unavailable; no session."""
    # FILL IN


@pytest.mark.asyncio
async def test_routes_absent_when_disabled(monkeypatch):
    """AC20: with AUTH_BASIC_2FA_ENABLED False, setup_handlers registers no /auth/mfa route and excludes nothing."""
    # FILL IN
```

### Steps (in order)

1. Confirm TASK-138 and TASK-139 are done: `MfaServices.evaluate`, `get_mfa_services`,
   and `AuthHandler.finalize_login` exist.
2. Create `handlers/mfa.py` block 1, then block 2 (`verify`, `_verify_locked`),
   then block 3. Fill the FILL INs.
3. Re-read `_verify_locked` against invariants 1–6 in Context, in order.
   Check every `return` inside the lock: none restores state, none opens a
   session except the single success path.
4. Modify `handlers/__init__.py`.
5. `python -c "import navigator_auth"` (import cycle check).
6. Write and fill the tests; run them; run the regression gate and ruff.

### FILL IN checklist

- [ ] `_json_body`
- [ ] `_maybe_trust_device` — AC17, D14
- [ ] `challenge` (resend) — AC30, R9
- [ ] Test helpers + `client` fixture
- [ ] 11 test bodies

---

## Acceptance Criteria

- [ ] **AC-1** Verification and resend run under `MfaSecurity.user_lock(record.user_id)`, the user id taken from an HMAC-verified record and the record re-read after acquiring the lock; `open_session` and `finalize_login` run inside the lock.
- [ ] **AC-2** Version or digest drift ⇒ `401 stale_challenge`, challenge discarded (spec AC30; spec tests `test_stale_challenge_rejected`).
- [ ] **AC-3** The provider must be in both the signed and the current allowlist; otherwise it is a failed attempt (spec AC9, AC30).
- [ ] **AC-4** Wrong codes keep the challenge for attempts 1–4 and burn it on the 5th; a correct 5th attempt succeeds; only success consumes (spec AC31).
- [ ] **AC-5** Two concurrent correct submissions mint exactly one session; an expired/consumed challenge never mints one and is never recreated (spec AC31).
- [ ] **AC-6** Any Redis/Postgres/provider storage failure ⇒ `503 mfa_unavailable`, no session (spec AC12).
- [ ] **AC-7** Success calls `open_session(request, user, extra={"auth_method": "basic", "mfa": True, "amr": ["pwd", AMR_BY_PROVIDER[p]]})` and returns `finalize_login`'s response; trusted device only when asked and allowed (spec AC17, AC19 for the verify path).
- [ ] **AC-8** Resend rotates the e-mail code, keeps TTL and cumulative attempts, and answers an identical 202 body regardless of delivery (spec AC30, R9).
- [ ] **AC-9** `/auth/mfa/challenge` and `/auth/mfa/verify` are in `app[AUTH_EXCLUDE_LIST_KEY]`; with `AUTH_BASIC_2FA_ENABLED=False` no `/auth/mfa` route exists (spec AC20).
- [ ] **AC-10** No log line contains a code, challenge token or device token (spec AC14) — check every `logger` call in the diff.
- [ ] **AC-11** `pytest tests/test_mfa_verify.py -v` passes; `pytest tests/test_mfa_basic_auth_hook.py tests/test_mfa_auth_login_integration.py -q` still passes; `ruff check navigator_auth/handlers/mfa.py navigator_auth/handlers/__init__.py tests/test_mfa_verify.py` is clean.
- [ ] **AC-12** Device issuance after verify calls `may_offer_trusted_device()` (D27); `grep -rn "\.execute(" navigator_auth/mfa/ navigator_auth/handlers/mfa.py` shows nothing except `mfa/migrations.py` (D25).

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_verify.py -v
pytest tests/test_mfa_basic_auth_hook.py tests/test_mfa_auth_login_integration.py -q
grep -rn "\.execute(" navigator_auth/mfa/ navigator_auth/handlers/mfa.py | grep -v "mfa/migrations.py" ; test $? -eq 1   # AC-12 (D25)
ruff check navigator_auth/handlers/mfa.py navigator_auth/handlers/__init__.py tests/test_mfa_verify.py
```

Spec §4 rows owned here (handler half): `test_concurrent_verify_consumes_once`,
`test_challenge_retry_budget`, `test_verify_rejects_disallowed_provider`,
`test_stale_challenge_rejected`, `test_expiry_during_verification`,
`test_resend_preserves_budget_and_expiry`, `test_mfa_verify_finalizes_session`.
End-to-end variants (real BasicAuth, real providers) are TASK-147.

---

## Agent Instructions

1. **Read the spec** `sdd/specs/basicauth-otp-2fa.spec.md`: §3 M10 (`MfaHandler`
   skeleton), "Security contracts shared by the modules" — *Challenge validity
   and invalidation* and *Retry accounting and concurrency* in full; §7 R5, R9;
   FEAT-106 contract D10, D11, D14, D16, D17.
2. **Check dependencies** — TASK-138 and TASK-139 in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint; keep `setup_mfa_routes` open for TASK-141/142
   to extend (they add routes below the marker comment).
5. **Verify** AC-1…AC-11.
6. **Move this file** to `sdd/tasks/completed/TASK-140-mfa-verify-handler.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
