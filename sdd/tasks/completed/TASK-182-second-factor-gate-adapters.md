# TASK-182: BasicAuth and /auth/mfa/verify delegate to the gate (M5 adapters)

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-173, TASK-174, TASK-181
**Assigned-to**: unassigned

---

## Context

TASK-181 created `SecondFactorGate` (`navigator_auth/mfa/login.py`). This task switches the two existing
second-factor entry points to it and deletes the code the gate replaced (spec §3 Module 5, "Integration
Points" rows `BasicAuth._second_factor` and `MfaHandler.verify / _verify_locked`):

- `BasicAuth._second_factor` (`backends/basic.py:357`) becomes a thin adapter over `gate.decide`;
  `BasicAuth._trusted_device` (`basic.py:404`) is deleted (moved into the gate).
- `MfaHandler.verify` (`handlers/mfa.py:88`) becomes a thin adapter over `gate.verify`; `_verify_locked`,
  `_failed` and `_maybe_trust_device` are deleted; `_revalidate` becomes a 5-line adapter over the gate's
  helper (it is still used by `challenge` and by `tests/test_mfa_enrollment_security.py:501,513`).
- Every `MfaHandler` endpoint holds a TASK-173 **service lease** for its whole duration (spec §3 M1: "Every MFA
  decision point switches … `MfaHandler._session_user`/`challenge`"), through one small decorator.

After this task, BasicAuth logins issue their session inside the user lock (AC18), refuse a login whose
password changed mid-flight (AC17), and never acquire a second pool connection inside the lock (AC10).

---

## Scope

- Replace `BasicAuth._second_factor` with the gate adapter; delete `BasicAuth._trusted_device`; prune the
  imports that become unused in `backends/basic.py`.
- Add the `_with_mfa_services` decorator to `handlers/mfa.py`; apply it to `verify`, `challenge`,
  `enroll_totp`, `confirm_totp`, `disenroll_totp`, `backup_codes`, `admin_disenroll`; give each a
  `services` parameter and pass it to `_session_user(request, services)`.
- Replace `MfaHandler.verify` with the gate adapter; delete `_verify_locked`, `_failed`,
  `_maybe_trust_device`; reduce `_revalidate` to an adapter over `SecondFactorGate._revalidate`.
- Update the existing test doubles that the new `conn=` calls break, and add the AC10/AC33 adapter tests.

**NOT in scope**:
- Backup-code proof and the disenroll guard (TASK-183 edits `disenroll_totp`/`backup_codes` bodies after this).
- The OAuth2 form (TASK-184).
- `BasicAuth.on_cleanup` / `slot.close()` (TASK-173 owns that edit in `basic.py`).
- Any change to `open_session`, `authenticate`'s 2FA-off branch, or `finalize_login`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/basic.py` | MODIFY | `_second_factor` → gate adapter; delete `_trusted_device`; prune imports |
| `navigator_auth/handlers/mfa.py` | MODIFY | lease decorator; `verify` → gate adapter; delete moved helpers; `_revalidate` adapter |
| `tests/test_mfa_review_fixes_gate.py` | MODIFY | AC10 adapter flows under `single_connection_authdb`; AC33 adapters |
| `tests/test_mfa_verify.py` | MODIFY | AC33 adapter test; keep every existing test green |
| `tests/test_mfa_basic_auth_hook.py` | MODIFY | `_services()` gains a lock + `backend._idp`; NONE/hash-drift adapter tests |
| `tests/test_mfa_enrollment_security.py` | MODIFY | `Idp.user_from_id` stub accepts `conn=` |

---

## Codebase Contract (Anti-Hallucination)

> **CRITICAL**: This section contains VERIFIED code references from the actual codebase.
> The implementing agent MUST use these exact imports, class names, and method signatures.
> **DO NOT** invent, guess, or assume any import, attribute, or method not listed here.
> If you need something not listed, VERIFY it exists first with `grep` or `read`.

Verified against `0b80d88` (branch `feat-FEAT-106-basicauth-otp-2fa`). TASK-173 edits `basic.py` before this
task (on_cleanup) — re-run every `grep -c` below before editing.

### Verified Imports
```python
# navigator_auth/backends/basic.py (relative imports, as the module already uses)
from .abstract import BaseAuthBackend, user_is_active        # verified: basic.py:17 (user_is_active at abstract.py:43)
from ..exceptions import FailedAuth, MFARefused, MFARequired # verified: basic.py:20-28 (exceptions.py:53, :108, :80)
from ..mfa.types import MFA_DEVICE_TOKEN_KEY                 # verified: basic.py:37 (types.py:15)
from ..mfa.services import MFA_APP_KEY, MfaServicesSlot, build_mfa_services  # verified: basic.py:32

# navigator_auth/handlers/mfa.py (absolute imports, as the module already uses)
from navigator_auth.mfa.services import MfaServices          # verified: handlers/mfa.py:21 (services.py:28)
from navigator_auth.mfa.types import MFA_DEVICE_TOKEN_KEY, MfaChallenge  # verified: handlers/mfa.py:26-39
# stdlib: functools; typing Awaitable, Callable (added to handlers/mfa.py:13 `from typing import Any, Optional`)

# Created by dependencies (verify they landed first):
from navigator_auth.mfa.login import SecondFactorGate, VerifyRefused   # created by TASK-181
from navigator_auth.mfa.services import mfa_services_lease             # created by TASK-173
#   @asynccontextmanager async def mfa_services_lease(app) -> AsyncIterator[Optional[MfaServices]]
#   — ready() + a lease held for the whole scope; yields None when no slot/services.
from navigator_auth.mfa.security import LOCK_CONNECTION                # created by TASK-171 (tests only)
# tests/fixtures/mfa.py::single_connection_authdb                      # created by TASK-171 (tests only)
#   pool with max_size=1; .acquires_inside_lock: list (acquire() calls made while LOCK_CONNECTION was set)
```

### Existing Signatures to Use
```python
# navigator_auth/backends/basic.py
class BasicAuth(BaseAuthBackend):                                    # line 57
    pwd_atrribute: str = "password"                                  # line 61 — the attribute validate_user checks (basic.py:130)
    userid_attribute: str = "user_id"                                # abstract.py:69
    async def open_session(self, request, user: dict, extra: Optional[dict] = None,
                           expiration: Optional[int] = None) -> dict  # line 201 (Redis only; raises FailedAuth 403 when inactive)
    async def authenticate(self, request)                            # line 327; 2FA branch at 345-348:
    #       if auth_conf.AUTH_BASIC_2FA_ENABLED:
    #           session = await self._second_factor(request, user)
    #           if session is not None: return session
    async def _second_factor(self, request: web.Request, user) -> Optional[dict]   # line 357 (REPLACED)
    async def _trusted_device(self, request: web.Request, services, evaluation) -> Optional[str]  # line 404 (DELETED)

# navigator_auth/handlers/mfa.py
NO_STORE = {"Cache-Control": "no-store"}                             # line 46
def _error(code: str, status: int, **extra: Any) -> web.Response    # line 49
async def _json_body(request) -> dict                                # line 54
def _remote(request) -> str                                          # line 63
class MfaHandler:                                                    # line 85
    async def verify(self, request: web.Request) -> web.Response                     # line 88 (REPLACED)
    async def _session_user(self, request: web.Request) -> tuple[Any, Any, Any]     # line 109 (signature changes)
    async def _verify_locked(...)                                                    # line 171 (DELETED)
    async def _revalidate(self, request, services, conn, token, record)              # line 214 (→ adapter, same signature)
    async def _failed(self, services: MfaServices, token: str) -> web.Response      # line 235 (DELETED)
    async def _maybe_trust_device(...)                                               # line 242 (DELETED)
    async def challenge(self, request: web.Request) -> web.Response                  # line 258
    async def enroll_totp(self, request: web.Request) -> web.Response                # line 294
    async def confirm_totp(self, request: web.Request) -> web.Response               # line 334
    async def disenroll_totp(self, request: web.Request) -> web.Response             # line 385
    async def backup_codes(self, request: web.Request) -> web.Response               # line 436
    async def admin_disenroll(self, request: web.Request) -> web.Response            # line 485
    # finalize: `return await request.app["auth"].finalize_login(request, result)`   # line 212

# Created by TASK-181 (navigator_auth/mfa/login.py) — fixed signatures:
class SecondFactorGate:
    def __init__(self, services: MfaServices, *, userid_attribute: str = "user_id", password_attribute: str = "password")
    async def decide(self, request, user, issue: SessionIssuer[T]) -> GateResult[T]   # raises FailedAuth / MFARefused
    async def verify(self, request, token, provider, code, issue, *, remember_device=False, device_label="") -> GateResult[T]
    async def _revalidate(self, conn, token, record: MfaChallenge) -> tuple[Any, MfaEvaluation]  # raises VerifyRefused
class GateResult: session, challenge: Optional[LoginChallenge], device: Optional[dict]
class LoginChallenge: token, providers: tuple[str, ...], preferred, expires_in
class VerifyRefused(Exception): code: str, status: int, extra: dict
#   gate extra passed to the issuer: {} (MfaState.NONE) or {"mfa": True, "amr": [...]} — never "auth_method".
```

### Does NOT Exist
- ~~`BasicAuth._trusted_device`~~, ~~`MfaHandler._verify_locked`~~, ~~`MfaHandler._failed`~~,
  ~~`MfaHandler._maybe_trust_device`~~ — deleted by THIS task; nothing may call them afterwards.
- ~~`_with_mfa_services`~~ — created by THIS task (TASK-183 relies on it and on `_session_user(request, services)`).
- ~~`get_mfa_services` in `handlers/mfa.py` / `backends/basic.py` after this task~~ — every lookup goes through
  `mfa_services_lease` (the sync `get_mfa_services` stays in `mfa/services.py` for other callers).
- ~~`SecondFactorGate(..., auth_method=...)`~~ — the gate has no such parameter; the issuer merges
  `{"auth_method": "basic"}` itself.
- ~~`request["mfa_services"]`~~ / a ContextVar for services — services are passed as an explicit parameter
  (`tests/test_mfa_verify.py:_post` uses a `SimpleNamespace` request without `__setitem__`).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/backends/basic.py", "action": "MODIFY"},
    {"path": "navigator_auth/handlers/mfa.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_review_fixes_gate.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_verify.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_basic_auth_hook.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_enrollment_security.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/basic.py#BasicAuth._second_factor",
    "sym:navigator_auth/backends/basic.py#BasicAuth._trusted_device",
    "sym:navigator_auth/backends/basic.py#BasicAuth.authenticate",
    "sym:navigator_auth/backends/basic.py#BasicAuth.open_session",
    "sym:navigator_auth/backends/abstract.py#user_is_active",
    "sym:navigator_auth/handlers/mfa.py#_error",
    "sym:navigator_auth/handlers/mfa.py#_json_body",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler.verify",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler._session_user",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler._verify_locked",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler._revalidate",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler._failed",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler._maybe_trust_device",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler.challenge",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler.enroll_totp",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler.confirm_totp",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler.disenroll_totp",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler.backup_codes",
    "sym:navigator_auth/handlers/mfa.py#MfaHandler.admin_disenroll",
    "sym:navigator_auth/mfa/services.py#MfaServices",
    "sym:navigator_auth/exceptions.py#MFARequired",
    "sym:navigator_auth/exceptions.py#MFARefused",
    "sym:navigator_auth/exceptions.py#FailedAuth"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- Run the issuer **inside** the gate: never call `open_session` after `gate.decide/verify` returns, except
  `finalize_login`, which must run after the lock is released (it already does — the gate has returned).
- `extra or None`: the gate passes `{}` for `MfaState.NONE`; the BasicAuth issuer must then call
  `open_session(request, fresh, extra=None)` so the no-factor session keeps today's keys (FEAT-106 AC4,
  this spec AC22). For a non-empty extra merge `{"auth_method": "basic", **extra}` — the existing tests
  `test_mfa_verify_finalizes_session` and `test_trusted_device_skips_otp_with_honest_amr` assert exactly
  `{"auth_method": "basic", "mfa": True, "amr": [...]}`.
- Pass `password_attribute=self.pwd_atrribute` (sic, the existing attribute name) — it is the attribute
  `validate_user` checked (`basic.py:130`), so the gate compares the same hash.
- `authenticate` (basic.py:345-348) needs no edit: `_second_factor` now always returns the opened session or
  raises, so `if session is not None: return session` returns it. A failure inside the issuer on the
  no-factor path now surfaces as `MFARefused` 503 instead of `return False` — intended (fail closed).
- `functools.wraps` keeps `__name__`/docstrings; aiohttp only requires the wrapper to be a coroutine function.
- Never log codes or tokens; keep `logger.error(... type(err).__name__)` style.

### References in Codebase
- `navigator_auth/backends/basic.py:327-419`, `navigator_auth/handlers/mfa.py:85-292`.
- `tests/test_mfa_enrollment_security.py:257-290` — the `env` fixture whose `Idp` stub needs `conn=`.

---

## Implementation Blueprint

> **CRITICAL — Executor-ready starting point.** Write each block below to its declared
> path nearly verbatim, then complete every `# FILL IN:` marker. Blocks were derived
> from the spec's Interface Skeletons and re-verified against the Codebase Contract
> above when this task was written. This is NOT the full implementation:
> business-logic branches, edge cases and test bodies are `FILL IN` stubs by design.
> Never change a signature, class name, or file path the blueprint fixes.

### Steps (in order)
1. Confirm TASK-181/173/174 landed (`grep -n "class SecondFactorGate" navigator_auth/mfa/login.py`,
   `grep -n "def mfa_services_lease" navigator_auth/mfa/services.py`) and re-run the anchor counts — *why*: TASK-173 edited `basic.py` first.
2. Edit `basic.py` (imports, `_second_factor`, delete `_trusted_device`) — *why*: spec §3 M5 BasicAuth adapter.
3. Edit `handlers/mfa.py` top-down: imports → decorator → `verify` → `_session_user` → delete/adapt helpers →
   decorate the remaining endpoints — *why*: keeps line anchors valid while you go.
4. Fix the test doubles (`Idp.user_from_id(conn=)`, hook `_services()`), then add the new tests — *why*: the
   gate calls `user_from_id(uid, conn=conn)` and `services.security.user_lock`, which the old doubles lack.
5. Run every Validation Command; all existing suites must stay green (AC21).

### `navigator_auth/backends/basic.py` (MODIFY — imports)
```python
# occurrences: 1 (verified: grep -c 'from ..mfa.services import MFA_APP_KEY, MfaServicesSlot, build_mfa_services, get_mfa_services' navigator_auth/backends/basic.py)
# REPLACE — lines 32-41 (verified: basic.py:32 `from ..mfa.services import …`, :33 `from ..mfa.trusted_devices import may_offer_trusted_device`, :34-41 `from ..mfa.types import (` … `)`)
from ..mfa.login import SecondFactorGate
from ..mfa.services import MFA_APP_KEY, MfaServicesSlot, build_mfa_services, mfa_services_lease
from ..mfa.types import MFA_DEVICE_TOKEN_KEY
# FILL IN: keep any name TASK-173 added to the services import line; then drop `MfaSignal,` from the
#   `from ..exceptions import (` block (basic.py:25, occurrences: 1) if `grep -n "MfaSignal" basic.py` shows no
#   other use — bounded by: AMR_PASSWORD, AMR_TRUSTED_DEVICE, PROVIDER_EMAIL, TRUSTED_COOKIE, MfaState,
#   may_offer_trusted_device and get_mfa_services were used only in _second_factor/_trusted_device (verified).
```
**Why**: the gate owns trusted-device and challenge logic now; the adapter only needs the gate, the lease and the
device-token key.

### `navigator_auth/backends/basic.py` (MODIFY — `_second_factor`, delete `_trusted_device`)
```python
# occurrences: 1 (verified: grep -c 'async def _second_factor(self, request: web.Request, user) -> Optional[dict]:' navigator_auth/backends/basic.py)
# REPLACE — basic.py:357-419 (from `async def _second_factor(` through the end of `_trusted_device`, i.e. the
#   line before `    async def check_credentials(self, request):` at basic.py:421, occurrences: 1)
    async def _second_factor(self, request: web.Request, user) -> Optional[dict]:
        """Run the shared second-factor gate for this password login (spec §3 M5).

        Returns the session opened inside the gate's user lock (no factor owed, or a valid trusted
        device). Raises ``MFARequired`` when a factor is owed; ``MFARefused``/``FailedAuth`` propagate.
        """
        if not user_is_active(user):
            raise FailedAuth("User account is disabled", status=403)
        async with mfa_services_lease(request.app) as services:
            if services is None or not services.available:
                raise MFARefused("mfa_unavailable", "Second factor is temporarily unavailable", status=503)
            gate = SecondFactorGate(services, userid_attribute=self.userid_attribute, password_attribute=self.pwd_atrribute)

            async def _issue(fresh, extra: dict) -> dict:
                """Open the Basic session inside the gate's lock; ``{}`` keeps the no-MFA session baseline."""
                return await self.open_session(request, fresh, extra={"auth_method": "basic", **extra} if extra else None)

            result = await gate.decide(request, user, _issue)
        if result.challenge is not None:
            raise MFARequired(
                challenge=result.challenge.token,
                providers=list(result.challenge.providers),
                preferred=result.challenge.preferred,
                expires_in=result.challenge.expires_in,
            )
        session = result.session
        if result.device is not None:
            session[MFA_DEVICE_TOKEN_KEY] = result.device
        return session
```
**Why**: spec §3 M5 "`BasicAuth._second_factor` becomes `gate.decide(...)`; map `GateResult.challenge` →
`MFARequired`, `device` → `result[MFA_DEVICE_TOKEN_KEY]`; `_trusted_device` moves into the gate and is deleted".

### `navigator_auth/handlers/mfa.py` (MODIFY — imports and lease decorator)
```python
# occurrences: 1 (verified: grep -c 'import logging' navigator_auth/handlers/mfa.py) — AFTER line 9
import functools
# occurrences: 1 (verified: grep -c 'from typing import Any, Optional' navigator_auth/handlers/mfa.py) — REPLACE line 13
from typing import Any, Awaitable, Callable, Optional
# occurrences: 1 (verified: grep -c 'from navigator_auth.mfa.services import MfaServices, get_mfa_services' navigator_auth/handlers/mfa.py) — REPLACE line 21
from navigator_auth.mfa.login import SecondFactorGate, VerifyRefused
from navigator_auth.mfa.services import MfaServices, mfa_services_lease
# FILL IN: after all edits, drop imports left unused — candidates: `import secrets` (:10), FailedAuth and
#   MfaSignal in line 19, may_offer_trusted_device (:25), AMR_BY_PROVIDER, AMR_PASSWORD, MfaEvaluation in the
#   types block — bounded by `grep -n "<name>" navigator_auth/handlers/mfa.py` showing no remaining use.

# occurrences: 1 (verified: grep -c 'return request.remote or "unknown"' navigator_auth/handlers/mfa.py) — AFTER line 65
def _with_mfa_services(
    method: Callable[..., Awaitable[web.Response]],
) -> Callable[..., Awaitable[web.Response]]:
    """Hold an MFA services lease for the whole handler and pass the services in (spec §3 M1).

    The wrapped method receives ``(self, request, services)``; ``services`` is None when MFA is not
    configured. The lease keeps a retired services object (and its Redis pool) alive until the
    handler — including ``finalize_login`` — has finished (AC34).
    """

    @functools.wraps(method)
    async def wrapper(self: Any, request: web.Request) -> web.Response:
        async with mfa_services_lease(request.app) as services:
            return await method(self, request, services)

    return wrapper
```
**Why**: one decorator gives every endpoint a lease with a two-line diff per endpoint, instead of re-indenting
seven handler bodies (TASK-183 edits two of them next).

### `navigator_auth/handlers/mfa.py` (MODIFY — `verify`, `_session_user`, moved helpers)
```python
# occurrences: 1 (verified: grep -c 'async def verify(self, request: web.Request) -> web.Response:' navigator_auth/handlers/mfa.py)
# REPLACE — handlers/mfa.py:88-107 (the whole current verify)
    @_with_mfa_services
    async def verify(self, request: web.Request, services: Optional[MfaServices]) -> web.Response:
        """POST /auth/mfa/verify: delegate to SecondFactorGate.verify, then finalize after the lock."""
        if services is None or not services.available:
            return _error("mfa_unavailable", 503)
        body = await _json_body(request)

        async def _issue(user: Any, extra: dict) -> dict:
            """Open the Basic session inside the gate's lock (extra is always MFA-marked here)."""
            return await services.backend.open_session(request, user, extra={"auth_method": "basic", **extra})

        try:
            result = await SecondFactorGate(services).verify(
                request, body.get("challenge"), body.get("provider"), body.get("code"), _issue,
                remember_device=bool(body.get("remember_device")), device_label=str(body.get("device_label") or ""),
            )
        except VerifyRefused as err:
            return _error(err.code, err.status, **err.extra)
        session = result.session
        if result.device is not None:
            session[MFA_DEVICE_TOKEN_KEY] = result.device
        return await request.app["auth"].finalize_login(request, session)

# occurrences: 1 (verified: grep -c 'async def _session_user(self, request: web.Request) -> tuple[Any, Any, Any]:' navigator_auth/handlers/mfa.py)
# REPLACE — handlers/mfa.py:109-113 (signature, docstring, the get_mfa_services lookup and its 503 check)
    async def _session_user(self, request: web.Request, services: Optional[MfaServices]) -> tuple[Any, Any, Any]:
        """Return the leased MFA services, the live session, and its fresh user record."""
        if services is None or not services.available:
            raise web.HTTPServiceUnavailable(text='{"error": "mfa_unavailable"}', content_type="application/json")
        # (lines 114-127 unchanged)

# DELETE — handlers/mfa.py:171-212 `_verify_locked`, :235-240 `_failed`, :242-256 `_maybe_trust_device`
#   (occurrences: 1 each — grep -c 'async def _verify_locked(' / 'async def _failed(self, services: MfaServices, token: str) -> web.Response:' / 'async def _maybe_trust_device(')
# occurrences: 1 (verified: grep -c 'async def _revalidate(' navigator_auth/handlers/mfa.py) — REPLACE handlers/mfa.py:214-233
    async def _revalidate(
        self, request: web.Request, services: MfaServices, conn: Any, token: str, record: MfaChallenge
    ) -> tuple[Any, Any] | web.Response:
        """Adapter over SecondFactorGate._revalidate for the resend endpoint (same signature as before)."""
        try:
            return await SecondFactorGate(services)._revalidate(conn, token, record)  # pylint: disable=W0212
        except VerifyRefused as err:
            return _error(err.code, err.status, **err.extra)
```
**Why**: spec §3 M5 "`MfaHandler.verify` becomes `gate.verify(...)`; `VerifyRefused` → `_error(e.code, e.status,
**e.extra)`; success → device + `finalize_login` (after the lock is released)". Keeping `_revalidate`'s
signature keeps `challenge` and `test_mfa_enrollment_security.py:501,513` working.

### `navigator_auth/handlers/mfa.py` (MODIFY — remaining endpoints)
```python
# occurrences: 1 each (verified: grep -c on each def line below) — prepend the decorator and add the parameter:
#   :258 challenge, :294 enroll_totp, :334 confirm_totp, :385 disenroll_totp, :436 backup_codes, :485 admin_disenroll
    @_with_mfa_services
    async def challenge(self, request: web.Request, services: Optional[MfaServices]) -> web.Response:
# … same two-line change for enroll_totp / confirm_totp / disenroll_totp / backup_codes / admin_disenroll.
# In challenge: DELETE the lookup `services = get_mfa_services(request.app)` (handlers/mfa.py:260; after the verify
#   and _session_user edits it is the last of the 3 original occurrences) — keep the `if services is None or not
#   services.available:` check that follows it.
# occurrences: 5 (verified: grep -c 'await self._session_user(request)' navigator_auth/handlers/mfa.py — lines 296, 336, 387, 438, 492)
#   replace ALL five with: await self._session_user(request, services)
```
**Why**: every MFA decision point holds a lease (spec §3 M1). Bodies stay untouched so TASK-183's anchors survive.

### `tests/test_mfa_enrollment_security.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '        async def user_from_id(self, uid):' tests/test_mfa_enrollment_security.py) — REPLACE line 267-272
        async def user_from_id(self, uid, *, conn=None):
            # FILL IN: when conn is given run the SELECT on it (no acquire — the gate calls this inside
            #   user_lock); else keep today's `async with await mfa_db.acquire()` body — bounded by AC10/G3
            ...
```
**Why**: the gate (via `_revalidate`) now calls `user_from_id(uid, conn=conn)`.

### `tests/test_mfa_basic_auth_hook.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '    services = MfaServices(backend=None, available=available)' tests/test_mfa_basic_auth_hook.py) — line 73
# FILL IN: give _services() (line 71) a fake `security` whose user_lock is an @asynccontextmanager yielding a
#   sentinel connection, and `backend=SimpleNamespace(_idp=SimpleNamespace(user_from_id=AsyncMock(return_value=_user())))`
#   so the gate's fresh read returns the same hash — bounded by: every existing hook test keeps its assertions.
# Add: test_no_factor_owed_opens_session_inside_gate (NONE ⇒ open_session(..., extra=None) once, returns it),
#      test_hash_drift_refuses_login (fresh user with another hash ⇒ FailedAuth status 401, open_session not awaited).
```

### `tests/test_mfa_verify.py` / `tests/test_mfa_review_fixes_gate.py` (MODIFY — new tests)
```python
# tests/test_mfa_verify.py — add (existing tests must pass unchanged):
@pytest.mark.asyncio
async def test_verify_adapter_email_without_conn_totp_with_lock_conn(client):
    """AC33: the handler adapter verifies email with no conn; a TOTP provider receives the lock connection."""
    # FILL IN — bounded by AC33

# tests/test_mfa_review_fixes_gate.py — add live tests using single_connection_authdb (TASK-171):
@pytest.mark.asyncio
async def test_no_nested_acquire_basic_login_and_verify(single_connection_authdb):
    """AC10: BasicAuth login (no factor / challenge / trusted device) and /auth/mfa/verify (TOTP, email,
    backup) each finish under asyncio.wait_for(..., 10) and single_connection_authdb.acquires_inside_lock == []."""
    # FILL IN: build real MfaServices over single_connection_authdb (mirror tests/test_mfa_enrollment_security.py
    #   env fixture: MfaSecurity, TrustedDeviceStore, BackupCodeStore, MfaPolicyResolver, MfaStateMachine,
    #   TOTPProvider, EmailOTPProvider) with an idp stub that honours conn=; drive BasicAuth._second_factor via
    #   BasicAuth.__new__ (as tests/test_mfa_basic_auth_hook.py:_backend) and MfaHandler.verify — bounded by AC10, AC18
```

### FILL IN checklist
- [ ] `basic.py` imports — drop now-unused names (verify with grep); keep TASK-173's additions
- [ ] `handlers/mfa.py` imports — drop now-unused names (verify with grep)
- [ ] `test_mfa_enrollment_security.py::Idp.user_from_id` — run on `conn` when given
- [ ] `test_mfa_basic_auth_hook.py::_services` — fake lock + `backend._idp`; two new adapter tests
- [ ] `test_mfa_verify.py` — AC33 adapter test
- [ ] `test_mfa_review_fixes_gate.py` — AC10 live adapter flows

---

## Acceptance Criteria

- [ ] `BasicAuth._trusted_device`, `MfaHandler._verify_locked`, `_failed`, `_maybe_trust_device` no longer exist;
      `grep -n "get_mfa_services" navigator_auth/backends/basic.py navigator_auth/handlers/mfa.py` is empty.
- [ ] **AC10** (BasicAuth no factor / challenge / trusted device; `/auth/mfa/verify` TOTP, email, backup) — each
      completes within 10 s on a one-connection `authdb`, and no `acquire()` happens while `LOCK_CONNECTION` is set.
- [ ] **AC17/AC18** hold through the BasicAuth adapter (hash drift ⇒ 401 `credentials_changed`; issuer under lock).
- [ ] **AC21** — every existing `tests/test_mfa_*.py` suite listed below passes; changed test doubles say why in a comment.
- [ ] **AC22** — 2FA-off BasicAuth login unchanged (`test_disabled_path_is_unchanged` green, `open_session(ANY, user)`).
- [ ] **AC33** — email OTP verifies through the BasicAuth/verify adapter without `conn`; TOTP uses the lock connection.
- [ ] `/auth/mfa/verify` JSON envelopes unchanged (`invalid_code` + `attempts_remaining`, `stale_challenge`, …).

---

## Validation Commands

- `pytest tests/test_mfa_review_fixes_gate.py -q`
- `pytest tests/test_mfa_verify.py -q`
- `pytest tests/test_mfa_basic_auth_hook.py -q`
- `pytest tests/test_mfa_enrollment_security.py -q`
- `pytest tests/test_mfa_admin_disenroll.py -q`
- `pytest tests/test_mfa_e2e.py -q`

---

## Test Specification

```python
# tests/test_mfa_basic_auth_hook.py (additions)
@pytest.mark.asyncio
async def test_no_factor_owed_opens_session_inside_gate(monkeypatch):
    """MfaState.NONE: the gate opens the session (extra=None) and _second_factor returns it."""


@pytest.mark.asyncio
async def test_hash_drift_refuses_login(monkeypatch):
    """AC17 via the adapter: FailedAuth 401 credentials_changed, open_session never awaited."""


# tests/test_mfa_verify.py (addition)
@pytest.mark.asyncio
async def test_verify_adapter_email_without_conn_totp_with_lock_conn(client):
    """AC33 adapter level."""


# tests/test_mfa_review_fixes_gate.py (addition)
@pytest.mark.asyncio
async def test_no_nested_acquire_basic_login_and_verify(single_connection_authdb):
    """AC10 for the BasicAuth and /auth/mfa/verify flows."""
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the stacked feature worktree `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa-review-fixes`** (branch
   `feat-FEAT-106-basicauth-otp-2fa-review-fixes`, stacked on `feat-FEAT-106-basicauth-otp-2fa`; ships in PR #633) — never on `dev`.
2. **Read the spec** at the path listed above for full context (§3 Module 5, §3 Module 1 last bullet).
3. **Check dependencies** — TASK-173, TASK-174 and TASK-181 must be `"done"` in
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
9. **Close the task** with `parrot sdd task close TASK-182 basicauth-otp-2fa-review-fixes verified`
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

---

## Completion Note

Implemented by seat gpt-5.6-luna (codex), 2 attempts (same-seat repair). Merge-tier validation (chunk 5): 83 passed, 1 skipped. File fidelity checked. Closed via `parrot sdd task close`.
