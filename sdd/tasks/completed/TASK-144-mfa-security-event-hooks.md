# TASK-144: `security_transition()` + password / recovery / passkey security-event hooks

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-138
**Assigned-to**: unassigned

---

## Context

Implements spec §3 **Security contracts — "Challenge validity and invalidation"** and
**"Additional integration scope"** (M10): every security transition that happens *outside* the MFA
endpoints must (a) increment the user's durable security version so outstanding challenges die,
(b) revoke trusted devices where the M6 invalidation list says so, (c) write a durable
`auth.user_mfa_audit` row, and (d) **serialize with verification through session creation** —
"either login completes before revocation or revocation wins and verification fails".

TASK-140's verify holds `MfaSecurity.user_lock(user_id)` from re-reading the challenge until the
session is finalized. This task gives every other transition the *same* lock via one context manager,
`security_transition()`, and wires it into the four existing code paths the spec enumerates:

| Site | Event | Revoke trusted devices? | Spec |
|---|---|---|---|
| `handlers/users/session.py` `password_change` | `password_change` | yes | M6 list, AC18 |
| `handlers/users/session.py` `password_reset` (superuser) | `password_reset` | yes | "password change/reset" |
| `handlers/recovery/handler.py` step 3 | `recovery_completion` | yes | AC18, AC30, `test_pending_challenge_invalid_after_recovery` |
| `backends/passkey.py` `register_verify` | `passkey_registered` | **no** (D23) | "passkey registration/removal" bumps version |
| `backends/passkey.py` `delete_credential` | `passkey_removed` | yes, always (D23) | AC27, AC33 |
| *(none exists)* "logout everywhere" | `global_logout` | yes | D22 — exported, **unwired** |

Contract decisions this task applies: **D5** (no `open_session`/`create_token`/`remember(` text under
`navigator_auth/mfa/`), **D6** (downgrade notification via `notify_security_event`), **D17**
(handlers orchestrate; one transaction: body → bump → revoke → audit, notify after commit),
**D22** (global logout unwired), **D23** (passkey rules), **D24** (failure posture).

---

## Scope

- Create `navigator_auth/mfa/events.py` with `SECURITY_EVENTS` and the async context manager
  `security_transition()` exactly as contract §3 (TASK-144).
- Wrap the password write in `UserSession.password_change` and `UserSession.password_reset` with
  `security_transition` (the protected write runs **inside** the lock).
- Wrap the password write in `PasswordRecoveryHandler._step3_confirm` with `security_transition`,
  **before** `self._revoker.revoke_user(...)` runs.
- Wrap `save_credential` in `PasskeyAuth.register_verify` (`revoke_devices=False`).
- In `PasskeyAuth.delete_credential`: refuse the deletion of an **enforced superuser's last strong
  factor** with 409 `strong_factor_required` (checked under the lock, before deleting); run the
  deletion inside `security_transition`; after commit, notify the user when the deletion left them
  with no strong factor (downgrade, AC27).
- Write `tests/test_mfa_security_transitions.py`.

**NOT in scope**:
- The MFA endpoints' own transitions (TOTP confirm/disenrol, backup codes — TASK-141; admin disenrol — TASK-142).
- `apply_tenant_policy` (policy hardening — TASK-135).
- Adding a "logout everywhere" endpoint (D22: export the event, do not invent the endpoint).
- `UserManager` (generic CRUD) password/email writes — R1, explicitly out of scope; their effect is caught
  by the context digest, not by a hook.
- Changing `SessionRevoker`, `PasskeyStore` or any SQL outside `navigator_auth/mfa/`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/events.py` | CREATE | `SECURITY_EVENTS`, `security_transition()` |
| `navigator_auth/handlers/users/session.py` | MODIFY | password_change / password_reset hooks |
| `navigator_auth/handlers/recovery/handler.py` | MODIFY | recovery completion hook |
| `navigator_auth/backends/passkey.py` | MODIFY | registration / deletion hooks + last-strong-factor guard |
| `tests/test_mfa_security_transitions.py` | CREATE | transition semantics + wiring tests |

---

## Codebase Contract

> Re-verified on `dev` @ `b10a3a3` (2026-11-11). Symbols from TASK-129..TASK-138 do not exist yet —
> they are the contract (`/sdd` contract §3); verify each with `grep -n` after its task lands.

### Verified Imports

```python
# stdlib
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Optional

# Created by earlier FEAT-106 tasks (contract §3) — verify after they land:
from navigator_auth.mfa.services import get_mfa_services           # TASK-138
from navigator_auth.mfa.types import MfaAuditEntry, MfaSecurityNotice   # TASK-129
from navigator_auth.mfa.exceptions import MfaStorageError         # TASK-129
from navigator_auth.mfa.notify import notify_security_event       # TASK-137
from navigator_auth.mfa.state import usable_email                 # TASK-135
from navigator_auth.mfa.events import security_transition         # THIS task

# Already present in the modified modules (verified):
#   handlers/users/session.py:15   from .passwd import check_password, set_basic_password
#   handlers/recovery/handler.py:44 from navigator_auth.handlers.recovery.store import RecoveryTokenStore, _hash_token
#   backends/passkey.py:10          import json
#   backends/passkey.py:16          from aiohttp import web
#   backends/passkey.py:31          from ..responses import JSONResponse
```

### MfaServices surface used (contract §3, TASK-138 / 132 / 133 / 135)

```python
services = get_mfa_services(app)            # Optional[MfaServices]; None when AUTH_BASIC_2FA_ENABLED is off
services.available: bool                    # False when tables/secret missing (D13)
async with services.security.user_lock(user_id) as conn: ...   # txn + pg_advisory_xact_lock(LOCK_NAMESPACE, user_id)
await services.security.bump_version(conn, user_id) -> int
await services.security.write_audit(conn, entry: MfaAuditEntry) -> None
await services.trusted_devices.revoke_all(user_id, reason, conn=conn) -> int
await services.resolver.effective(user) -> TenantMfaPolicy
await services.state.requires_strong_factor(user, policy) -> bool
await services.state.totp_confirmed(user_id, conn=conn) -> bool
await services.state.passkey_count(user_id, conn=conn) -> int
await services.state.has_strong_factor(user) -> bool
```

`user_lock` is an `@asynccontextmanager` (contract §3 TASK-132): commit on normal exit, rollback
when an exception propagates out of the `async with` body.

### Edit sites (exact text, verified 2026-11-11)

`navigator_auth/handlers/users/session.py` — `password_change` (`:147-160`):
```python
            db = request.app["authdb"]
            async with await db.acquire() as conn:
                User.Meta.connection = conn
                user = await User.get(user_id=user_id)
                if check_password(user.password, old_password):     # :152  (1 occurrence)
                    # valid, can change password
                    user.password = set_basic_password(new_password)   # :154 (20-space indent; 1 occurrence at this indent)
                    await user.update()                                # :155 (20-space indent; 1 occurrence)
```
`password_reset` (`:186-206`) — `userinfo = session[AUTH_SESSION_OBJECT]` is the **actor** (superuser):
```python
                ## Reset Password:                                       # :203 (1 occurrence)
                user.password = set_basic_password(new_password)       # :204 (16-space; the 16-space text also matches :154 as a substring → 2)
                user.is_new = True                                     # :205 (1 occurrence)
                await user.update()                                    # :206 (16-space text matches :155 too → 2)
```
`navigator_auth/handlers/recovery/handler.py` — step 3 (`:281-323`):
```python
        async with await db.acquire() as conn:                          # :281
            User.Meta.connection = conn
            ...
            user.password = set_basic_password(password)               # :310 (1 occurrence)
            # D17 — self-service reset is NOT the same as a superuser-driven   # :311 (1)
            # password_reset (which sets is_new=True). Do not "harmonise"
            # them.
            user.is_new = False                                        # :314 (1)
            await user.update()                                        # :315 (1)

        await self._store.drop_pair(consumed.recovery_key, _hash_token(token))   # :317 (1)

        revoked = await self._revoker.revoke_user(self.request, user)  # :319
```
`navigator_auth/backends/passkey.py` — `register_verify` (`:261`, `user = self._session_user(request)` at `:263`):
```python
        try:
            if await self._store.get_credential(stored.credential_id) is not None:   # :311 (1)
                raise web.HTTPConflict(reason="Passkey: credential already registered")
            await self._store.save_credential(stored)                  # :313 (1)
        except web.HTTPException:
            raise
```
`delete_credential` (`:549-563`):
```python
    @_json_errors
    async def delete_credential(self, request: web.Request) -> web.Response:
        """Delete one of the caller's passkeys; 409 when it would lock the user out (E13)."""
        user = self._session_user(request)
        credential_id = self._credential_id(request)
        owned = await self._store.list_credentials(user.user_id)
        if credential_id not in {c.credential_id for c in owned}:
            raise web.HTTPNotFound(reason="Passkey: credential not found")
        guard_last = not await self._has_other_login_method(user.user_id)      # :556 (1)
        # With no other login method the store deletes only if another passkey remains,
        # atomically (two concurrent deletes cannot both succeed).
        if not await self._store.delete_credential(user.user_id, credential_id, keep_last=guard_last):   # :559 (1)
            if guard_last:
                raise web.HTTPConflict(reason="Passkey: cannot delete the last login method")
            raise web.HTTPNotFound(reason="Passkey: credential not found")
        return web.Response(status=204)                                # :563 (1)
```
Other verified facts:
- `PasskeyAuth._has_other_login_method` uses `await self._idp.user_from_id(user_id)` (`:570`) — the fresh user record; reuse that call for the superuser check.
- `_json_errors` (`passkey.py:38-56`) maps only `AuthException`; an `aiohttp.web.HTTPException` raised inside the handler propagates as that HTTP response (existing 404/409 behaviour).
- `webauthn` is **not installed** here (spec §6). `PasskeyAuth.on_startup` raises `ConfigError` without it, so passkey HTTP tests skip; unit tests call `PasskeyAuth.delete_credential(fake_self, request)` directly (no webauthn import on that path once `_credential_id` is faked).
- `pyproject` `filterwarnings = ["error", …]` — a stray `DeprecationWarning` fails a test.

### Does NOT Exist (Anti-Hallucination)

- ~~a "logout everywhere" / global-logout endpoint~~ — `AuthHandler.api_logout` (`auth.py:330`) forgets ONE session; `UserSession.logout` (`session.py:266`) invalidates ONE session. Do not wire `global_logout` into either (D22).
- ~~`SessionRevoker` revoking trusted devices~~ — it revokes sessions/jti only (`recovery/revoke.py`); device revocation is this hook's job.
- ~~`MfaServices.notify(...)`~~ — notifications go through `navigator_auth.mfa.notify.notify_security_event` (TASK-137).
- ~~`PasskeyStore` MFA awareness~~ — `user_credentials` carries no MFA state; the strong-factor predicate is derived (spec M7).
- ~~a `conn` parameter on `PasskeyStore.delete_credential`~~ — it acquires its own connection (`store.py:110-129`). The advisory lock still serializes it: the lock is held for the whole `async with` body.

---

## Implementation Blueprint

### `navigator_auth/mfa/events.py` — CREATE

```python
"""Security-transition hook shared by every non-MFA credential change (FEAT-106).

Password change/reset, recovery completion and passkey registration/removal
must serialize with second-factor verification on the same per-user lock,
increment the durable security version (so outstanding challenges die),
optionally revoke trusted devices and leave a durable audit row. See spec
§3 "Security contracts" and contract D17/D22/D23/D24.
"""
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from navigator_auth.mfa.services import get_mfa_services
from navigator_auth.mfa.types import MfaAuditEntry

logger = logging.getLogger("navigator.mfa.events")

SECURITY_EVENTS = frozenset({
    "password_change",
    "password_reset",
    "recovery_completion",
    "passkey_registered",
    "passkey_removed",
    "global_logout",   # D22: exported for a future "logout everywhere"; unwired today
})


@asynccontextmanager
async def security_transition(
    app: Any,
    user_id: int,
    event: str,
    *,
    actor_user_id: Optional[int] = None,
    revoke_devices: bool = True,
    detail: Optional[dict] = None,
    request_id: Optional[str] = None,
) -> AsyncIterator[Optional[Any]]:
    """Run a protected credential change under the user's MFA security lock.

    Yields the lock's connection (``None`` when 2FA is off or MFA storage is
    unusable). On normal exit of the body: bump the security version, revoke
    trusted devices when ``revoke_devices``, write the audit row, commit.
    An exception from the body rolls back and propagates unchanged.

    Args:
        app: The aiohttp application (holds the MFA services).
        user_id: Target user whose factors/credentials change.
        event: One of ``SECURITY_EVENTS``.
        actor_user_id: Who performed the change (``None`` = unknown/system).
        revoke_devices: Revoke the user's trusted devices on success.
        detail: Extra JSON-safe audit detail. Never put secrets here.
        request_id: Correlation id for the audit row.

    Raises:
        ValueError: ``event`` is not a known security event.
    """
    if event not in SECURITY_EVENTS:
        raise ValueError(f"unknown MFA security event {event!r}")
    services = get_mfa_services(app)
    if services is None:
        # 2FA is off: the hook is a no-op (G8 / AC20).
        yield None
        return
    # FILL IN: when `not services.available` → logger.error (event, user_id, NO secrets),
    #   `yield None; return` — bounded by D24 (the protected operation proceeds).
    # FILL IN: enter `services.security.user_lock(int(user_id))` MANUALLY
    #   (`lock_cm = ...; conn = await lock_cm.__aenter__()`); on ANY exception while
    #   entering → logger.error + `yield None; return` — bounded by D24.
    # FILL IN: `try: yield conn` / `except BaseException as exc:` →
    #   `await lock_cm.__aexit__(type(exc), exc, exc.__traceback__)` then `raise`
    #   (rollback, body error propagates unchanged — CancelledError included).
    # FILL IN: after a clean body, in this order on `conn`:
    #   1. await services.security.bump_version(conn, user_id)
    #   2. if revoke_devices: await services.trusted_devices.revoke_all(user_id, event, conn=conn)
    #   3. await services.security.write_audit(conn, MfaAuditEntry(
    #          actor_user_id=actor_user_id, target_user_id=user_id, org_id=None,
    #          action=event, method=None, request_id=request_id,
    #          outcome="success", detail=dict(detail or {})))
    #   then `await lock_cm.__aexit__(None, None, None)` (commit).
    #   If any of 1-3 raises: logger.error, `await lock_cm.__aexit__(type(e), e, e.__traceback__)`
    #   (rollback) and RETURN WITHOUT RAISING — bounded by D24 (the protected write already
    #   committed on its own connection; the context digest still kills old challenges).
```

**Why a manual `__aenter__`/`__aexit__` instead of `async with user_lock(...)`.** Two failure
classes must behave differently: an error *entering* the lock or *after* the body must not abort the
password change (D24), but an error *from the body* must roll back and propagate. A plain
`async with` around `yield` cannot express "swallow errors on the way out but not the body's own".
Keep the generator yielding **exactly once** on every path — `asynccontextmanager` raises
`RuntimeError("generator didn't stop")` otherwise.

**Why the protected write runs inside the lock even though it uses another connection.** The lock is
what verification waits on (TASK-140). Holding it for the duration of the body means a racing verify
either finished (and its session is then killed by `SessionRevoker` on the recovery path) or acquires
the lock afterwards, re-reads `user_mfa_security.version` and the context digest (password verifier
included) and fails — exactly the spec's "either login completes before revocation or revocation wins".

**D5.** Do not write `open_session`, `create_token` or `remember(` anywhere in this file, not even in
the docstring — the refined AC5 grep runs over `navigator_auth/mfa/`.

### `navigator_auth/handlers/users/session.py` — MODIFY (three blocks)

**Block 1 — import.** Insert below the anchor:
```python
# AFTER — insert below `from .passwd import check_password, set_basic_password` (verified: session.py:15)
# occurrences: 1 (verified: grep -cF 'from .passwd import check_password, set_basic_password')
from ...mfa.events import security_transition
```

**Block 2 — `password_change`.** Replace the two 20-space lines (unique at that indent):
```python
# REPLACE — context (verified: session.py:152-155)
#                 if check_password(user.password, old_password):      # occurrences: 1
#                     # valid, can change password
#                     user.password = set_basic_password(new_password)  # 20-space: occurrences 1
#                     await user.update()                               # 20-space: occurrences 1
                if check_password(user.password, old_password):
                    # valid, can change password
                    async with security_transition(
                        request.app, user.user_id, "password_change",
                        actor_user_id=user.user_id,
                    ):
                        user.password = set_basic_password(new_password)
                        await user.update()
```

**Block 3 — `password_reset`.** The 16-space `user.password = …` / `await user.update()` texts also
match the 20-space lines as substrings (`grep -cF` → 2); anchor on the unique `## Reset Password:` /
`user.is_new = True` pair:
```python
# REPLACE — context (verified: session.py:203-206; `## Reset Password:` occurrences: 1,
#           `user.is_new = True` occurrences: 1)
                ## Reset Password:
                async with security_transition(
                    request.app, user.user_id, "password_reset",
                    actor_user_id=userinfo.get("user_id"),
                ):
                    user.password = set_basic_password(new_password)
                    user.is_new = True
                    await user.update()
```

**Why the actor differs.** `password_change` is self-service (actor = target). `password_reset` is
the superuser path: `userinfo = session[AUTH_SESSION_OBJECT]` (`:187`) is the *actor*, `user` the
target — the audit row must say who did it (AC23).

### `navigator_auth/handlers/recovery/handler.py` — MODIFY (two blocks)

**Block 1 — import.**
```python
# AFTER — insert below `from navigator_auth.handlers.recovery.types import NotificationPayload` (verified: :45)
# occurrences: 1 (verified: grep -cF)
from navigator_auth.mfa.events import security_transition
```

**Block 2 — wrap the write.**
```python
# REPLACE — context (verified: handler.py:310-315; each line occurrences: 1)
            async with security_transition(
                self.request.app, user.user_id, "recovery_completion",
                actor_user_id=user.user_id,
            ):
                user.password = set_basic_password(password)
                # D17 — self-service reset is NOT the same as a superuser-driven
                # password_reset (which sets is_new=True). Do not "harmonise"
                # them.
                user.is_new = False
                await user.update()
```

**Why here and not after `revoke_user`.** The spec requires "a challenge predating password recovery
cannot mint a new session after that recovery completes". Bumping the version *after* `revoke_user`
leaves a window where a verify that read the old state mints a session the revoker already passed.
Bumping it **under the lock, before** the revoker runs closes it: any verify either completed first
(its jti is indexed and `revoke_user` kills it) or blocks on the lock and then fails on the version.
The existing D17 comment about `is_new` stays verbatim — it belongs to FEAT-098.

### `navigator_auth/backends/passkey.py` — MODIFY (four blocks)

**Block 1 — imports.**
```python
# AFTER — insert below `from .basic import BasicAuth` (verified: passkey.py:33; occurrences: 1)
from ..mfa.events import security_transition
from ..mfa.exceptions import MfaStorageError
from ..mfa.notify import notify_security_event
from ..mfa.services import get_mfa_services
from ..mfa.state import usable_email
from ..mfa.types import MfaSecurityNotice
```
(`datetime`/`timezone` are needed by Block 4: add `from datetime import datetime, timezone` to the
stdlib import group at the top, after `import secrets` at `:11`.)

**Block 2 — registration.**
```python
# REPLACE — `            await self._store.save_credential(stored)` (verified: :313; occurrences: 1)
            async with security_transition(
                request.app, user.user_id, "passkey_registered",
                actor_user_id=user.user_id, revoke_devices=False,
            ):
                await self._store.save_credential(stored)
```

**Block 3 — deletion (replace `:556-563`, from `guard_last = …` through `return web.Response(status=204)`).**
```python
        guard_last = not await self._has_other_login_method(user.user_id)
        services = get_mfa_services(request.app)
        record, guard_strong = await self._mfa_strong_factor_guard(services, user.user_id)
        async with security_transition(
            request.app, user.user_id, "passkey_removed", actor_user_id=user.user_id,
        ) as conn:
            if guard_strong:
                # FILL IN: conn is None ⇒ raise web.HTTPServiceUnavailable(text=json.dumps(
                #   {"error": "mfa_unavailable", "reason": "Passkey: MFA storage unavailable"}),
                #   content_type="application/json") — bounded by AC33 (fail closed).
                # FILL IN: totp = await services.state.totp_confirmed(user.user_id, conn=conn);
                #   count = await services.state.passkey_count(user.user_id, conn=conn);
                #   if not totp and count <= 1 ⇒ raise web.HTTPConflict(text=json.dumps(
                #   {"error": "strong_factor_required",
                #    "reason": "Passkey: cannot delete the last strong factor"}),
                #   content_type="application/json") — bounded by AC33 (checked UNDER the lock).
                pass
            # With no other login method the store deletes only if another passkey remains,
            # atomically (two concurrent deletes cannot both succeed).
            if not await self._store.delete_credential(user.user_id, credential_id, keep_last=guard_last):
                if guard_last:
                    raise web.HTTPConflict(reason="Passkey: cannot delete the last login method")
                raise web.HTTPNotFound(reason="Passkey: credential not found")
        await self._notify_if_downgraded(services, record)
        return web.Response(status=204)
```

**Block 4 — two private helpers (append after `_has_other_login_method`, end of class).**
```python
    async def _mfa_strong_factor_guard(self, services: Any, user_id: int) -> tuple[Any, bool]:
        """Return ``(fresh user record, must-keep-a-strong-factor)`` for an MFA-enabled app.

        ``(None, False)`` when 2FA is off. Raises 503 (fail closed, AC33) when MFA
        is enabled but its storage cannot answer.
        """
        if services is None:
            return None, False
        # FILL IN: not services.available ⇒ raise web.HTTPServiceUnavailable(JSON mfa_unavailable)
        # FILL IN: record = await self._idp.user_from_id(user_id);
        #   policy = await services.resolver.effective(record);
        #   return record, await services.state.requires_strong_factor(record, policy)
        #   Any MfaStorageError ⇒ HTTPServiceUnavailable(JSON mfa_unavailable) — bounded by AC33.
        raise NotImplementedError

    async def _notify_if_downgraded(self, services: Any, record: Any) -> None:
        """After commit: tell the user when the deletion left them no strong factor (AC27, D6)."""
        if services is None or record is None or not services.available:
            return
        # FILL IN: try: strong = await services.state.has_strong_factor(record)
        #   except MfaStorageError: log WARNING and return (never fail a committed delete).
        #   If not strong: await notify_security_event(MfaSecurityNotice(
        #     email=usable_email(record), display_name=<record display_name or username>,
        #     username=<record username>, event="passkey_removed_last_strong_factor",
        #     occurred_at=datetime.now(timezone.utc), actor=None)) — bounded by D6.
```

**Why the strong-factor check runs inside the lock.** Two concurrent deletes of an enforced
superuser's two passkeys would both pass a check done before the lock and leave zero strong factors.
Re-counting `passkey_count`/`totp_confirmed` **on the lock's connection** serializes them: the second
delete sees one passkey left and is refused. Raising an `HTTPException` inside the `async with` body
makes `security_transition` roll back (no version bump, no audit, no revocation) and re-raise, so a
refused delete leaves no trace beyond the 409. Keep the existing `guard_last` (E13, "last login
method") logic untouched — it is a different invariant (lockout of *any* login), FEAT-101.

**Why always revoke on removal (D23).** Removing a passkey can be a downgrade (reopens e-mail, AC27);
revoking unconditionally is the conservative superset and avoids a second has-strong-factor query
inside the lock. Registration does not revoke: adding a factor never weakens the account.

### `tests/test_mfa_security_transitions.py` — CREATE

```python
"""FEAT-106 TASK-144 — security_transition() semantics and its four wire-ups."""
import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from navigator_auth.mfa.events import SECURITY_EVENTS, security_transition
from navigator_auth.mfa.security import MfaSecurity
from navigator_auth.mfa.services import MFA_APP_KEY, MfaServicesSlot
from navigator_auth.mfa.trusted_devices import TrustedDeviceStore
from tests.fixtures.mfa import mfa_db, mfa_secret, mfa_user_factory  # noqa: F401


def _services(mfa_db, mfa_secret, **over):
    """Duck-typed MfaServices (contract §3 attributes) over real stores."""
    base = dict(
        available=True,
        security=MfaSecurity(mfa_db, mfa_secret),
        trusted_devices=TrustedDeviceStore(mfa_db),
    )
    base.update(over)
    return SimpleNamespace(**base)


@pytest.mark.asyncio
async def test_noop_when_2fa_disabled():
    """No services on the app ⇒ yields None, body runs, nothing else happens (AC20)."""
    ran = []
    async with security_transition({}, 1, "password_change") as conn:
        ran.append(conn)
    assert ran == [None]


@pytest.mark.asyncio
async def test_unknown_event_rejected():
    with pytest.raises(ValueError):
        async with security_transition({}, 1, "nope"):
            pass

# FILL IN (each a separate test; real Postgres via mfa_db/mfa_user_factory;
#   app = {MFA_APP_KEY: MfaServicesSlot(_services(...))} — get_mfa_services() (TASK-138) only
#   unwraps an MfaServicesSlot; a bare services object reads as "2FA off"):
#  - test_transition_bumps_version_and_audits — version +1, exactly one user_mfa_audit row with
#    action=event, actor, target, outcome="success" (AC23).
#  - test_password_change_revokes_trusted_devices — issue a device, run the "password_change"
#    transition, consume_and_rotate(token, uid) is None (AC18).
#  - test_recovery_completion_revokes_trusted_devices — same for "recovery_completion" (AC18).
#  - test_passkey_registered_does_not_revoke — revoke_devices=False keeps the device usable (D23).
#  - test_body_exception_rolls_back — body raises RuntimeError ⇒ propagates; version and audit unchanged.
#  - test_pending_challenge_invalid_after_recovery — read current_version (= the version a challenge
#    would carry), run "recovery_completion", current_version differs ⇒ the stale-check of TASK-140
#    rejects that challenge (unit form; full HTTP flow in TASK-147) (AC30).
#  - test_verify_security_transition_races — task A holds the transition (body awaits an Event);
#    task B enters services.security.user_lock(uid) and reads current_version; assert B is NOT done
#    after 0.3 s, set the Event, then B observes the bumped version (AC30, AC31).
#  - test_failure_posture_d24 — services.security.bump_version raises ⇒ body still ran, no exception
#    escapes, an ERROR record is logged (caplog), nothing committed; and available=False ⇒ ERROR + body runs.
#  - test_all_wired_events_known — {"password_change","password_reset","recovery_completion",
#    "passkey_registered","passkey_removed","global_logout"} == SECURITY_EVENTS.
```

**Wiring tests (same file, FILL IN).** For each site, monkeypatch the module-level
`security_transition` name (`navigator_auth.handlers.users.session.security_transition`,
`navigator_auth.handlers.recovery.handler.security_transition`,
`navigator_auth.backends.passkey.security_transition`) with a recording `@asynccontextmanager` that
appends `("enter", event, user_id)` / `("exit", …)` and assert the password `update()` /
`save_credential` / `delete_credential` call is recorded **between** enter and exit. Drive the
handlers with fakes (`make_mocked_request`, monkeypatched `get_session`, `User.get` returning a stub
whose `update` is an `AsyncMock`). For `delete_credential` call the decorated function as
`PasskeyAuth.delete_credential(fake_self, request)` with a `SimpleNamespace` `fake_self` exposing
`logger`, `_session_user`, `_credential_id` (returns bytes — no webauthn), `_store` (AsyncMocks),
`_has_other_login_method`, `_idp.user_from_id`, and the two helpers bound from `PasskeyAuth`.
Required cases:
- `test_password_change_wired` / `test_password_reset_wired` (actor = session user, target = URL user).
- `test_recovery_completion_wired_before_revoker` — the transition exits before `revoke_user` is awaited.
- `test_passkey_delete_last_strong_factor_refused` — enforced superuser, no TOTP, one passkey ⇒ 409
  `strong_factor_required`, `delete_credential` NOT called (AC33).
- `test_deleting_last_passkey_reopens_email` — ordinary user, enforced tenant, no TOTP, last passkey:
  delete succeeds (204), the transition ran with `"passkey_removed"` (revocation + bump),
  `notify_security_event` called once, and with real stores `services.state.available_providers`
  now contains `"email"` (AC27).

### Steps (in order)

1. Confirm TASK-138 landed: `grep -n "def get_mfa_services\|MFA_APP_KEY" navigator_auth/mfa/services.py`,
   and that `MfaSecurity.user_lock`, `TrustedDeviceStore.revoke_all(…, conn=)`, `MfaStateMachine.passkey_count(…, conn=)`
   match contract §3 (`grep -n "def " navigator_auth/mfa/{security,trusted_devices,state}.py`).
2. Create `events.py`; fill the four FILL INs; run `test_noop_when_2fa_disabled`, `test_unknown_event_rejected`.
3. Write and pass the real-Postgres transition tests (they define the semantics every hook relies on).
4. Wire `session.py` (Blocks 1-3) → wiring tests.
5. Wire `recovery/handler.py` → wiring test; confirm the existing suite still passes:
   `pytest tests/test_password_recovery.py -q`.
6. Wire `passkey.py` (Blocks 1-4) → wiring tests; existing passkey unit suite:
   `pytest tests/test_passkey_backend_unit.py tests/test_passkey_store.py -q`.
7. Run the whole task gate (Test Specification) and the D5 grep.
8. Check import cycles: `python -c "import navigator_auth.backends.passkey, navigator_auth.handlers"`.
   If a cycle appears (passkey → mfa.services → … → backends), move the `..mfa.*` imports in
   `passkey.py` inside the two helpers / `delete_credential` — never restructure `mfa/services.py` here.

### FILL IN checklist

- [ ] `events.py`: unavailable branch, manual lock enter, body rollback/propagate, post-body bump→revoke→audit→commit, D24 swallow
- [ ] `session.py`: import, password_change wrap, password_reset wrap (actor = session user)
- [ ] `recovery/handler.py`: import, wrap before `revoke_user`
- [ ] `passkey.py`: imports (+ datetime), registration wrap, deletion restructure, in-lock strong-factor check, two helpers
- [ ] Transition tests (9) and wiring tests (6)

---

## Acceptance Criteria

- [ ] **AC-1** `security_transition` is a no-op (yields `None`, body runs, no DB access) when `get_mfa_services(app)` is `None`.
- [ ] **AC-2** On a clean body it bumps `user_mfa_security.version` by exactly 1, revokes trusted devices iff `revoke_devices`, and writes exactly one `auth.user_mfa_audit` row (actor, target, action=event, outcome) — all in the lock's transaction.
- [ ] **AC-3** A body exception rolls back (no bump, no audit, no revocation) and propagates unchanged.
- [ ] **AC-4** With MFA enabled but unavailable, or when the lock/bump/audit fails, the protected operation still completes and an ERROR is logged with no secret (D24).
- [ ] **AC-5** A verification lock request for the same user blocks while a transition body is running (shared advisory lock).
- [ ] **AC-6** Password change, superuser password reset and recovery completion each run their password write inside a transition that revokes trusted devices; recovery's transition completes before `SessionRevoker.revoke_user` runs.
- [ ] **AC-7** Passkey registration bumps the version and audits without revoking devices; passkey deletion always revokes (D23).
- [ ] **AC-8** Deleting an enforced superuser's last strong factor (no TOTP, one passkey) returns 409 `strong_factor_required` and deletes nothing; the check runs under the lock.
- [ ] **AC-9** Deleting an ordinary user's last passkey with no TOTP reopens `email` in `available_providers`, invalidates pending challenges (version bump), is audited, revokes devices and sends one downgrade notice.
- [ ] **AC-10** `grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/` prints nothing (D5); no `global_logout` wiring in `api_logout`/`UserSession.logout` (D22).
- [ ] **AC-11** Existing suites unchanged: `pytest tests/test_password_recovery.py tests/test_passkey_backend_unit.py tests/test_passkey_store.py -q`.
- [ ] **AC-12** D25: no `conn.execute()` call in the code this task adds — `grep -rn "\.execute(" navigator_auth/mfa/ navigator_auth/handlers/mfa.py` shows only `navigator_auth/mfa/migrations.py` (asyncdb `execute()` returns from `finally` and never raises, verified `.venv/.../asyncdb/drivers/pg.py:937-972`; writes use `fetchval`/`fetch_one` … `RETURNING`).
- Spec ACs closed or advanced: **AC18** (password change / recovery revoke), **AC23** (durable audit for these transitions), **AC27**, **AC30** (recovery/credential changes invalidate challenges), **AC33** (last-factor self-removal denied via passkey path).

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_security_transitions.py -v
pytest tests/test_password_recovery.py tests/test_passkey_backend_unit.py tests/test_passkey_store.py -q   # regression
ruff check navigator_auth/mfa/events.py navigator_auth/handlers/users/session.py \
  navigator_auth/handlers/recovery/handler.py navigator_auth/backends/passkey.py \
  tests/test_mfa_security_transitions.py
grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/ ; test $? -eq 1   # D5: no match
```

Spec §4 tests owned here (unit form): `test_password_change_revokes_trusted_devices`,
`test_recovery_completion_revokes_trusted_devices`, `test_deleting_last_passkey_reopens_email`,
`test_pending_challenge_invalid_after_recovery`, `test_verify_security_transition_races`.
Their full HTTP versions live in TASK-147 (`tests/test_mfa_e2e.py`).

---

## Agent Instructions

1. **Read the spec** `sdd/specs/basicauth-otp-2fa.spec.md` — §3 "Security contracts" (Challenge validity and
   invalidation; Retry accounting and concurrency — last paragraph; Superuser invariant; Additional integration
   scope), M6 invalidation list, M7 `has_strong_factor` docstring, §7 R1/R5, AC18/AC23/AC27/AC30/AC33.
2. **Check dependencies** — TASK-138 (and transitively 129–137) must be in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint; keep the generator single-yield on every path.
5. **Verify** every acceptance criterion, AC-5 and AC-8 included.
6. **Move this file** to `sdd/tasks/completed/TASK-144-mfa-security-event-hooks.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: gpt-5.6-luna (codex), 1 attempt
**Date**: 2026-11-11
**Notes**: MFA security-event hooks delivered; merge-tier green.

**Deviations from spec**: none | describe if any
