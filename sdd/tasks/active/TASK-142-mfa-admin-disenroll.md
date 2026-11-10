# TASK-142: Administrative disenrolment endpoint (ABAC `mfa:disenroll` + tenant ownership)

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-141
**Assigned-to**: unassigned

---

## Context

Implements `MfaHandler.admin_disenroll` from spec §3 **Module 10** — `DELETE /auth/mfa/{user_id}` —
the "escape hatch" of goal **G6**: when a user lost their authenticator and has no backup code, an
administrator can switch the OTP **off and nothing else**. The spec makes this deliberately narrow,
because §7 **R1** shows how an over-broad admin action becomes a takeover path (switch OTP off → user
drops to the e-mail floor → edit e-mail through `UserManager` → password recovery → own the account).
The mitigations this task owns:

1. **Separate permission.** Gated by the ABAC action `mfa:disenroll` under the policy
   `mfa_admin_access` (TASK-145), evaluated with the public fail-closed `policy_allows()`. A plain
   `superuser` without that action is denied (AC16). The handler never reads the session's
   `superuser` flag.
2. **Tenant ownership.** Holding the action is not permission across tenants: the target's
   organizations must be a non-empty subset of the actor's (AC26, D7 membership source).
3. **Narrow effect + durable audit.** Disable TOTP and invalidate backup codes (D21) — no password
   reset, no account edit, passkeys untouched — bump the security version (outstanding challenges
   die), revoke trusted devices ("admin disenrolment that does not revoke devices does nothing", R8),
   write a durable `auth.user_mfa_audit` row with actor/target/org (AC23), notify the user after commit (D6).

An enforced superuser target is allowed: per the spec's superuser invariant, they are then unable to
log in through BasicAuth until recovered with an audited operator procedure — intentional.

---

## Scope

- Add `MfaHandler.admin_disenroll(request)`; register `DELETE {MFA_PREFIX}/{user_id:\d+}` **after** the
  literal `/totp` route added by TASK-141.
- Order of checks: live session → parse target id → refuse self-target → ABAC → tenant ownership →
  fresh target record → transition under the target's lock → notify.
- Audit **denials** too (ABAC denial, foreign tenant, self-target) with `outcome="denied"`, so attempts
  are visible next to successes.
- Write `tests/test_mfa_admin_disenroll.py`.

**NOT in scope**:
- The policy pack YAML (TASK-145) — tests stub `policy_allows`; the real-PDP path is covered in TASK-147.
- Self-service disenrolment (TASK-141).
- Any HTTP API for tenant policy (spec Non-Goal).
- Hardening `UserManager` (R1 / FEAT-107).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/mfa.py` | MODIFY | `admin_disenroll` + route |
| `tests/test_mfa_admin_disenroll.py` | CREATE | authorization, scoping and effect tests |

---

## Codebase Contract

> `handlers/mfa.py` and `navigator_auth.mfa.*` come from TASK-129..TASK-141 — **verify after TASK-141 lands**.
> Existing-code facts re-verified on `dev` @ `b10a3a3` (2026-11-11).

### Verified Imports

```python
from datetime import datetime, timezone
from typing import Any, Optional

from aiohttp import web

from navigator_auth.decorators import policy_allows          # verified decorators.py:1170
from navigator_auth.exceptions import UserNotFound           # verified exceptions.py:32
from navigator_auth.responses import JSONResponse
from navigator_auth.mfa.exceptions import MfaStorageError    # TASK-129
from navigator_auth.mfa.types import MfaAuditEntry, MfaSecurityNotice, PROVIDER_TOTP   # TASK-129
from navigator_auth.mfa.state import usable_email            # TASK-135
from navigator_auth.mfa.notify import notify_security_event  # TASK-137
from navigator_auth.mfa.services import get_mfa_services     # TASK-138
```
Add only what is missing from `handlers/mfa.py` and actually used (ruff F401).

### `policy_allows` (verified `navigator_auth/decorators.py:1170-1216`)

```python
async def policy_allows(
    policy: Union[str, list], request: web.Request, action: str = None,
    resource: str = None, resource_type: Any = None, require_all: bool = False,
) -> tuple[bool, str, Any]:
    # Always fails closed: denies when ABAC is not enabled on the app, when the named
    # policy is not declared on the PDP, and when evaluation raises.
```
House call shape (verified `handlers/guards.py:152-157`):
`allowed, reason, _ = await policy_allows(self.policy_name, self.request, action=action, resource=self.request.path)`.
Here: `policy_allows("mfa_admin_access", request, action="mfa:disenroll", resource=request.path)`.

### Policy pack this endpoint expects (TASK-145, spec M11)

`name: mfa_admin_access`, `resources: ["uri:/auth/mfa/*"]`, `actions: ["mfa:disenroll"]`,
`subjects.groups: ["security_admin"]`, `priority: 90`. `admin_full_access.yaml` enumerates its actions
with no wildcard (verified file contents) so `mfa:disenroll` is outside it.

### MfaServices surface (contract §3)

```python
services.resolver.memberships(user_id, *, conn=None) -> tuple[int, ...]   # D7: organization_users by user_id
services.backend._idp.user_from_id(uid) -> record                         # raises UserNotFound (idp/__init__.py)
services.providers[PROVIDER_TOTP].disenroll(user, *, conn) -> None        # soft-deletes seed + user_mfa enabled=false
services.backup_codes.invalidate_all(user_id, *, conn=None) -> int
services.state.totp_confirmed(uid, *, conn=None) -> bool
services.security.user_lock(uid); bump_version(conn, uid); write_audit(conn, MfaAuditEntry)
services.trusted_devices.revoke_all(uid, reason, *, conn=None) -> int
```
Helpers from TASK-141 to reuse: `_err(code, status)`, `_session_user(request)` (returns
`(services, session, actor_record)`). Verify their final names after TASK-141 lands.

### Does NOT Exist (Anti-Hallucination)

- ~~a `security_admin` group~~ — not defined anywhere (spec §6); the handler must not assume it exists — ABAC decides.
- ~~`superuser` ⇒ `mfa:disenroll`~~ — never short-circuit on `session["superuser"]` / `is_superuser`.
- ~~`_resolve_tenant()` for ownership~~ — header-overridable, falls back to `(1, 1)` (R14). Use `resolver.memberships`.
- ~~password reset / e-mail edit / passkey deletion~~ in this endpoint — AC16 "changes nothing but the OTP state".
- ~~an HTTP body on DELETE~~ — the target is the URL `user_id` only.

---

## Implementation Blueprint

### `navigator_auth/handlers/mfa.py` — MODIFY (two blocks)

> **Anchors (verify after TASK-141 lands).** Block 1 appends to the end of `class MfaHandler`, below
> `async def backup_codes(` (`grep -n "    async def backup_codes(self, request" navigator_auth/handlers/mfa.py`,
> expected occurrences: 1). Block 2 goes in `setup_mfa_routes()` right after the line registering
> `handler.backup_codes` (`grep -cF "handler.backup_codes"` → 1).

**Block 1 — handler + denial-audit helper.**
```python
    async def _audit_denied(self, services: Any, actor_id: int, target_id: int, reason: str) -> None:
        """Durable record of a refused admin disenrolment. Best effort: never changes the response."""
        # FILL IN: async with services.security.user_lock(target_id) as conn:
        #     await services.security.write_audit(conn, MfaAuditEntry(actor_user_id=actor_id,
        #         target_user_id=target_id, org_id=None, action="admin_disenroll",
        #         method="admin", outcome="denied", detail={"reason": reason}))
        #   Any exception ⇒ log WARNING (no secrets) and return — bounded by "denial stays a 403".

    async def admin_disenroll(self, request: web.Request) -> web.Response:
        """DELETE /auth/mfa/{user_id} — switch a user's OTP off and nothing else (AC16, AC26).

        Gated by ABAC ``mfa:disenroll`` (policy ``mfa_admin_access``) AND tenant
        ownership. Disables TOTP, invalidates backup codes (D21), bumps the security
        version, revokes trusted devices, audits, then notifies the target.
        """
        services, session, actor = await self._session_user(request)
        actor_id = int(actor["user_id"] if isinstance(actor, dict) else actor.user_id)
        target_id = int(request.match_info["user_id"])
        if target_id == actor_id:
            await self._audit_denied(services, actor_id, target_id, "self_target")
            return self._err("self_disenroll_forbidden", 403)
        allowed, reason, _ = await policy_allows(
            "mfa_admin_access", request, action="mfa:disenroll", resource=request.path,
        )
        if not allowed:
            await self._audit_denied(services, actor_id, target_id, f"abac: {reason}")
            return self._err("forbidden", 403)
        # FILL IN: tenant ownership —
        #   actor_orgs = set(await services.resolver.memberships(actor_id))
        #   target_orgs = set(await services.resolver.memberships(target_id))
        #   if not target_orgs or not target_orgs <= actor_orgs: audit_denied("foreign_tenant"); 403 forbidden
        #   (SAME body as the ABAC denial — no cross-tenant user enumeration) — bounded by AC26, D7.
        # FILL IN: record = await services.backend._idp.user_from_id(target_id); UserNotFound ⇒ 404 not_found
        #   (only reachable after ownership passed, so it leaks nothing across tenants).
        # FILL IN: async with services.security.user_lock(target_id) as conn:
        #     old = "totp" if await services.state.totp_confirmed(target_id, conn=conn) else "none"
        #     await services.providers[PROVIDER_TOTP].disenroll(record, conn=conn)
        #     dropped = await services.backup_codes.invalidate_all(target_id, conn=conn)
        #     await services.security.bump_version(conn, target_id)
        #     revoked = await services.trusted_devices.revoke_all(target_id, "admin_disenroll", conn=conn)
        #     await services.security.write_audit(conn, MfaAuditEntry(actor_user_id=actor_id,
        #         target_user_id=target_id, org_id=min(target_orgs), action="admin_disenroll",
        #         old_state=old, new_state="none", method="admin", outcome="success",
        #         detail={"orgs": sorted(target_orgs), "backup_codes_invalidated": dropped,
        #                 "devices_revoked": revoked}))
        #   MfaStorageError ⇒ 503 mfa_unavailable (nothing committed).
        # FILL IN: after commit — await notify_security_event(MfaSecurityNotice(email=usable_email(record),
        #   display_name=..., username=..., event="admin_disenrolled",
        #   occurred_at=datetime.now(timezone.utc), actor=<actor username>)) — bounded by D6.
        # return JSONResponse({"status": "disenrolled", "user_id": target_id}, status=200)
```

**Why self-target is refused.** The admin route skips the fresh-password and factor-proof
requirements of self-service disenrolment (TASK-141, AC29/AC33). Letting an admin aim it at
themselves would turn a stolen admin session into a way to strip the admin's own second factor
without proving anything. Self-service exists for that.

**Why ABAC before ownership, and one identical 403.** Ownership needs two membership reads; ABAC is
cheaper and denies the common case first. Both denials return the same body so a caller holding
`mfa:disenroll` in tenant A cannot probe which user ids exist in tenant B.

**Why `target ⊆ actor` and not "intersect".** The spec says "the actor's organizations must include
the target's". A target who belongs to A and B, disenrolled by an admin of A only, would lose their
second factor in B's tenant too — B never consented. An empty target set is refused: a user with no
tenant is not in anyone's scope (D8).

**Why backup codes die here but not on self-disenrol (D21).** The admin path exists because the
user's TOTP device is lost or compromised; an attacker holding that device may hold the printed
codes too. Self-disenrol proves possession of a factor, so its recovery set stays.

**Block 2 — route.**
```python
# AFTER — insert below the line registering handler.backup_codes in setup_mfa_routes()
# occurrences: 1 (verify after TASK-141 lands: grep -cF "handler.backup_codes" navigator_auth/handlers/mfa.py)
    router.add_delete(
        rf"{MFA_PREFIX}/{{user_id:\d+}}", handler.admin_disenroll, name="mfa_admin_disenroll"
    )
    # Registered AFTER the literal /totp DELETE; NOT in AUTH_EXCLUDE_LIST_KEY.
```
**Why** `\d+`: `DELETE /auth/mfa/totp` must never be captured as a user id; the regex makes the two
routes disjoint regardless of order, and the order keeps intent obvious.

### `tests/test_mfa_admin_disenroll.py` — CREATE

```python
"""FEAT-106 TASK-142 — administrative disenrolment: permission, tenant scope, narrow effect."""
from types import SimpleNamespace

import pytest

import navigator_auth.handlers.mfa as mfa_handlers
from navigator_auth.mfa.services import MFA_APP_KEY, MfaServicesSlot
from tests.fixtures.mfa import mfa_db, mfa_redis_pool, mfa_secret, mfa_user_factory  # noqa: F401

# NOTE: register services as app[MFA_APP_KEY] = MfaServicesSlot(services) — get_mfa_services()
# (TASK-138) returns None for a bare services object.

# FILL IN: reuse the app-building approach of tests/test_mfa_enrollment_security.py (TASK-141):
#   real stores over mfa_db / mfa_redis_pool in a duck-typed services object, a middleware that
#   authenticates as the ACTOR, monkeypatched get_session.
# FILL IN: local fixture `org_factory` — INSERT INTO auth.organizations(organization, org_slug)
#   VALUES ($1, $2) RETURNING org_id; INSERT INTO auth.organization_users(user_id, org_id);
#   delete the organizations on teardown (organization_users cascades — verified
#   fk_auth_organization_users_org ON DELETE CASCADE).
# FILL IN: `allow_abac` / `deny_abac` fixtures: monkeypatch mfa_handlers.policy_allows with an
#   AsyncMock returning (True, "ok", None) / (False, "denied", None); assert it was awaited with
#   ("mfa_admin_access", <request>, action="mfa:disenroll", resource="/auth/mfa/<id>").

# Required tests:
#  test_admin_disenroll_requires_mfa_action — actor is_superuser=True with session superuser=True,
#      deny_abac ⇒ 403, target TOTP still confirmed, one "denied" audit row (AC16).
#  test_admin_disenroll_rejects_foreign_tenant — allow_abac, actor in org A, target in org B ⇒ 403
#      with the SAME body as the ABAC denial; target in A+B, actor in A only ⇒ 403;
#      target with no org ⇒ 403 (AC26).
#  test_admin_disenroll_revokes_trusted_devices — device issued for the target; after 200 the token
#      no longer rotates (consume_and_rotate ⇒ None) (AC16, AC18).
#  test_admin_disenroll_changes_nothing_but_otp — snapshot auth.users (password, email, is_superuser,
#      is_active), passkey row count, before/after identical; user_mfa totp disabled; seed row
#      soft-deleted; backup codes remaining == 0; version bumped by 1 (AC16, D21).
#  test_admin_disenroll_audits_actor_target_org — one "success" row with actor, target, org_id ==
#      min(target orgs), old_state "totp", new_state "none" (AC23).
#  test_admin_disenroll_self_target_forbidden — 403 self_disenroll_forbidden, nothing changed.
#  test_admin_disenroll_notifies_target — notify_security_event monkeypatched, awaited once AFTER the
#      commit (assert the audit row exists when the spy runs) (D6).
#  test_admin_disenroll_enforced_superuser_target_blocks_basic_login — after disenrolling an enforced
#      superuser's only strong factor, MfaStateMachine.state_of(record, policy) raises MFARefused
#      ("strong_factor_required") for the enforced policy (spec superuser invariant; HTTP login
#      form in TASK-147).
#  test_admin_disenroll_route_does_not_capture_totp — DELETE /auth/mfa/totp still reaches
#      disenroll_totp (TASK-141) and never admin_disenroll.
```

### Steps (in order)

1. Confirm TASK-141 landed; read `handlers/mfa.py`; confirm `_session_user` / `_err` names.
2. Confirm TASK-136's `TOTPProvider.disenroll(user, *, conn)` and TASK-134's
   `BackupCodeStore.invalidate_all(user_id, *, conn)` signatures (`grep -n "def disenroll\|def invalidate_all" navigator_auth/mfa/*.py`).
3. Add Block 1 and Block 2.
4. Write the tests; start with the two authorization tests (they need no factor setup), then the effect tests.
5. Run the Test Specification block plus TASK-141's suite.

### FILL IN checklist

- [ ] `_audit_denied` (best effort, never alters the 403)
- [ ] Tenant ownership (subset rule, identical 403 body)
- [ ] Target record fetch (404 only after ownership)
- [ ] Locked transition: disenroll, invalidate backup codes, bump, revoke, audit with detail
- [ ] Notify after commit
- [ ] Route registration
- [ ] Nine tests

---

## Acceptance Criteria

- [ ] **AC-1** Without `mfa:disenroll` (ABAC deny, ABAC disabled, or policy missing) the endpoint answers 403 — including for a principal with `is_superuser`/session `superuser` true — and changes nothing.
- [ ] **AC-2** With the action, a target whose organizations are not a non-empty subset of the actor's is refused 403 with a body identical to the ABAC denial.
- [ ] **AC-3** An actor cannot target themselves (403 `self_disenroll_forbidden`).
- [ ] **AC-4** On success, in one transaction under the target's lock: TOTP disabled (seed soft-deleted, `user_mfa` disabled), backup codes invalidated, security version +1, all trusted devices revoked, one durable audit row with actor, target, org, old/new state.
- [ ] **AC-5** Password, e-mail, superuser/active flags and passkey credentials are byte-identical before and after.
- [ ] **AC-6** Refusals leave a `denied` audit row; a failure to write it never changes the 403.
- [ ] **AC-7** The target is notified exactly once, after commit.
- [ ] **AC-8** `DELETE /auth/mfa/totp` is never routed to `admin_disenroll`.
- [ ] **AC-9** `pytest tests/test_mfa_admin_disenroll.py -v` passes; TASK-141's suite still passes; `ruff check navigator_auth/handlers/mfa.py tests/test_mfa_admin_disenroll.py` clean.
- [ ] **AC-10** D25: no `conn.execute()` call in the code this task adds — `grep -rn "\.execute(" navigator_auth/mfa/ navigator_auth/handlers/mfa.py` shows only `navigator_auth/mfa/migrations.py` (asyncdb `execute()` returns from `finally` and never raises, verified `.venv/.../asyncdb/drivers/pg.py:937-972`; writes use `fetchval`/`fetch_one` … `RETURNING`).
- Spec ACs closed: **AC16**, **AC26**; advanced: **AC18** (admin disenrol revokes), **AC23** (admin-disenrol rows), **AC33** (privileged target is then blocked).

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_admin_disenroll.py -v
pytest tests/test_mfa_enrollment_security.py -q    # TASK-141 regression
ruff check navigator_auth/handlers/mfa.py tests/test_mfa_admin_disenroll.py
```

Spec §4 tests owned here: `test_admin_disenroll_requires_mfa_action`, `test_admin_disenroll_revokes_trusted_devices`,
`test_admin_disenroll_rejects_foreign_tenant`.

---

## Agent Instructions

1. **Read the spec** `sdd/specs/basicauth-otp-2fa.spec.md` — G6, §3 M10 `admin_disenroll` docstring, M11, §7 R1/R8/R14,
   "Superuser invariant and recovery", AC16/AC23/AC26.
2. **Check dependencies** — TASK-141 must be in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint.
5. **Verify** every acceptance criterion, AC-2 and AC-5 included.
6. **Move this file** to `sdd/tasks/completed/TASK-142-mfa-admin-disenroll.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
