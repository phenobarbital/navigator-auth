# TASK-156: Privileged-grant endpoint `POST /api/v1/users/{id}/role`

**Feature**: FEAT-107 — Write-envelope hardening for the remaining auth CRUD handlers
**Spec**: `sdd/specs/auth-model-crud-hardening.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-149, TASK-150, TASK-153
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 5** (G5, AC11, AC12, AC16). Not delegation-eligible:
a new privilege-granting surface, where the self-grant prohibition and the ABAC
wiring are the whole point (spec R7).

After TASK-153 no CRUD path writes `is_superuser`, `user_role` or `is_staff`.
This endpoint is the **only** way to change them. It is gated by the
`users:grant_role` ABAC action, which `admin_full_access.yaml` cannot reach — it
wildcards resources (`uri:*`) but **enumerates** its actions — so a stock
superuser does not inherit it, and `policy_allows()` fails closed when no policy
matches. TASK-150 grants it to `security_admin` only (shared with FEAT-106's
`mfa:disenroll`). Depends on TASK-153 to respect the spec's order (M1 → M2 → M5:
the CRUD must be closed before its replacement opens).

### Decisions made at /sdd-task time (bounded by spec M5 and R7)

1. **Every self-targeted request is refused**, not only raises. The spec says
   "may not raise their own flags"; refusing all self-targets is stricter,
   simpler, and leaves a de-escalation to another grantor.
2. **"Cannot grant what you do not hold" applies to any change, in either
   direction** — so a lesser actor cannot strip a superuser either:
   - `is_superuser` changes need an actor for whom `_check_superuser()` is true;
   - `is_staff` changes need an actor whose own row has `is_staff = true`;
   - `user_role` changes need an actor whose own `user_role` is ≥ both the
     target's current role and the requested one (`UserType` values,
     `models.py:30-36`); an actor with no role cannot change roles.
   Consequence, by design (spec M5): granting `is_superuser` needs a superuser who
   is also in `security_admin`.
3. **The write uses `fetch_one … RETURNING`, not `Model.update()`.** asyncdb's pg
   `execute()` returns from inside `finally` and never raises (verified on
   2026-11-11, recorded for FEAT-106 as D25). The audit record must describe a
   write that happened; a fail-closed write uses a statement that raises.
4. **Base class.** The spec fixes `(OwnerOrSuperuserGuard, ModelHandler)` without
   saying which `ModelHandler`. Use the **local `handlers/model.py`** one: it
   reaches the database through `request.app["authdb"]` and needs no
   `configure()`. (The ModelView one gets its connection handler only from
   `configure()`, `navigator/views/abstract.py:189-247`, which registers CRUD
   routes this endpoint must not have.) Every inherited verb except `post` is
   overridden to answer **405**, so no generic CRUD is reachable on this route.
5. **Route order.** `UserManager.configure(app, '/api/v1/users')` registers
   `/api/v1/users/{id:.*}` (`abstract.py:225-227`), which would swallow
   `/api/v1/users/5/role`. aiohttp matches in registration order and
   `setup_handlers`' `router` is `self.app.router` (`auth.py:673`), so the role
   route is registered **before** `handlers/__init__.py:38`.

---

## Scope

- Create `navigator_auth/handlers/users/role.py` with `UserRoleHandler`:
  `post` only; payload ⊆ `{is_superuser, user_role, is_staff}`; the policy check,
  self-target refusal and hold rule above; a single `UPDATE … RETURNING`; one
  audit record per call (actor, target, old → new) through `audit_decision()`.
- Register `r"/api/v1/users/{id:\d+}/role"` in `handlers/__init__.py` before `UserManager.configure`.
- Write `tests/unit/handlers/test_user_role_handler.py`.

**NOT in scope**:
- The policy itself (TASK-150).
- Protected-group membership (TASK-152 / TASK-154) — separate, though it uses the same action.
- Changing `password_reset` (spec R13 — recommended follow-up only).
- Seeding the first `security_admin` member (spec R12, documented in TASK-158).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/users/role.py` | CREATE | `UserRoleHandler` |
| `navigator_auth/handlers/__init__.py` | MODIFY | Import + route, before `UserManager.configure` |
| `tests/unit/handlers/test_user_role_handler.py` | CREATE | M5 unit tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `6b8cc84` on 2026-11-11.

### Verified Imports

```python
from typing import Any, Optional
from aiohttp import web
from navigator_auth.decorators import _check_superuser, policy_allows   # decorators.py:291, :1170
from navigator_auth.models import User, UserType                        # models.py:39, :30
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard        # guards.py:31
from navigator_auth.handlers.model import ModelHandler                  # model.py:16 — LOCAL base
# relative, inside navigator_auth/handlers/users/role.py:
#   from ...decorators import policy_allows ; from ...models import User, UserType
#   from ..guards import OwnerOrSuperuserGuard ; from ..model import ModelHandler
```

### Existing Signatures to Use

```python
# navigator_auth/handlers/guards.py
class OwnerOrSuperuserGuard:
    async def _session_info(self) -> tuple[Any, dict, Any]: ...    # :61
    async def acting_user(self) -> tuple[int, bool]: ...           # :85 — is_superuser via _check_superuser
    def _refuse(self, not_found: bool = False): ...                # :108 raises
    async def audit_decision(self, action, allowed, owner_id, reason) -> None: ...   # :278, rule=self.policy_name

# navigator_auth/handlers/model.py (local base)
class ModelHandler(BaseView):
    def __init__(self, request, *args, **kwargs): ...   # :22 — reads self.model.Meta (set model = User)
    # verbs it defines and this task overrides to 405: head :106, get :122, put :216, patch :252, delete :400

# navigator_auth/models.py
class UserType(Enum): USER=1 CUSTOMER=2 STAFF=3 MANAGER=4 ADMIN=5 ROOT=10     # :30-36
class User(Model):  # :39 — Meta.name = AUTH_USERS_TABLE, Meta.schema = AUTH_DB_SCHEMA
    user_role: UserType   # :53
    is_superuser: bool    # :54
    is_staff: bool        # :55

# navigator_auth/handlers/__init__.py
from .partners import PartnerKeyHandler          # :13
    UserManager.configure(app, '/api/v1/users')  # :38  ← register the role route ABOVE this line
# navigator_auth/auth.py:673 — `router = self.app.router` (same object as app.router)

# asyncdb connection (local-base idiom, model.py:224-227):
#   db = self.request.app["authdb"]; async with await db.acquire() as conn: ...
#   conn.fetch_one(sql, *args) raises on DB errors; conn.execute() NEVER raises (D25)
```

- Identifier quoting idiom for a schema-qualified table: `guards.py:245-248`
  (`f'"{schema}"."{table}"'`). Column names here are constants, never client input.

### Does NOT Exist (Anti-Hallucination)

- ~~`UserRoleHandler`~~, ~~`navigator_auth/handlers/users/role.py`~~ — created here.
- ~~a `/api/v1/users/{id}/role` route~~ — added here.
- ~~`users:grant_role` in `admin_full_access.yaml`~~ — must stay absent (spec AC12, R8).
- ~~a `security_admin` group in any fixture~~ — tests build sessions that name it.
- ~~`is_staff` / `user_role` in the session userinfo~~ — not guaranteed; read the actor's row from the database.

---

## Implementation Blueprint

### `navigator_auth/handlers/users/role.py` — CREATE (block 1 of 2: class and gates)

```python
"""The only way to change a privileged user flag (FEAT-107, spec M5)."""

from typing import Any, Optional

from aiohttp import web

from ...decorators import policy_allows
from ...models import User, UserType
from ..guards import OwnerOrSuperuserGuard
from ..model import ModelHandler

_ACTION = "users:grant_role"
_ROLE_COLUMNS = ("is_superuser", "user_role", "is_staff")


class UserRoleHandler(OwnerOrSuperuserGuard, ModelHandler):
    """POST /api/v1/users/{id}/role  {"is_superuser": bool, "user_role": int, "is_staff": bool}

    Gated by the ``users:grant_role`` ABAC action, deliberately absent from
    ``admin_full_access.yaml``'s enumerated actions, so a stock superuser does
    not inherit it. Held by default by ``security_admin`` (shared with
    FEAT-106's ``mfa:disenroll``). Never self-service, and an actor may not
    change a flag they do not hold. Every call is audited.
    """

    model = User
    name: str = "User Role"
    pk: str = "user_id"
    owner_column: Optional[str] = None
    policy_name: str = "users_grant_role"
    superuser_actions = frozenset()

    async def _not_allowed(self):
        raise web.HTTPMethodNotAllowed(self.request.method, ["POST"])

    async def head(self):
        return await self._not_allowed()

    async def get(self):
        return await self._not_allowed()

    async def put(self):
        return await self._not_allowed()

    async def patch(self):
        return await self._not_allowed()

    async def delete(self):
        return await self._not_allowed()

    async def _role_payload(self) -> dict:
        """Validated payload: a non-empty dict ⊆ the three role columns, typed."""
        # FILL IN: json_data() in try/except → not a non-empty dict → 400; any key outside
        #   _ROLE_COLUMNS → 400 (the schema is public, naming keys is fine); is_superuser/is_staff
        #   must be bool; user_role must be an int in {t.value for t in UserType} → else 400.
        raise NotImplementedError

    async def _require_grant_action(self) -> None:
        allowed, reason, _ = await policy_allows(
            self.policy_name, self.request, action=_ACTION, resource=self.request.path
        )
        await self.audit_decision(_ACTION, bool(allowed), None, f"grant_role gate: {reason}")
        if not allowed:
            self._refuse()
```

**Why**: overriding the inherited verbs makes the "no generic CRUD on this
route" property hold even if the route is ever registered with `add_view`. The
gate audits both outcomes, so a refused attempt is visible (AC11).

### `navigator_auth/handlers/users/role.py` — CREATE (block 2 of 2: `post`)

```python
    async def post(self):
        """Change privileged flags of ANOTHER user. Order: gate → self → load → hold → write → audit."""
        payload = await self._role_payload()
        actor_id, actor_is_superuser = await self.acting_user()
        await self._require_grant_action()
        target_id = self.match_parameters(self.request).get("id")
        if target_id is None or str(target_id) == str(actor_id):
            await self.audit_decision(_ACTION, False, target_id, f"self-targeted role change by {actor_id}")
            self._refuse()
        db = self.request.app["authdb"]
        async with await db.acquire() as conn:
            # FILL IN: read actor and target rows: `SELECT user_id, is_superuser, user_role, is_staff
            #   FROM "<schema>"."<table>" WHERE user_id = $1` via conn.fetch_one (schema/table from
            #   User.Meta); target missing → audit DENY + 404 (self.error(..., status=404)).
            # FILL IN: hold rule (Context decision 2), one check per key in payload:
            #   is_superuser → actor_is_superuser; is_staff → actor row is_staff is True;
            #   user_role → actor role not None and actor role >= max(target role or 0, requested).
            #   First miss → audit_decision(_ACTION, False, target_id, "<column>: actor does not hold it") → _refuse().
            # FILL IN: single `UPDATE ... SET <col> = $n, ... WHERE user_id = $1
            #   RETURNING user_id, is_superuser, user_role, is_staff` via conn.fetch_one — columns
            #   from _ROLE_COLUMNS ∩ payload only (constants, never client strings). A None/empty
            #   result → audit DENY "write failed" + 500. NEVER conn.execute() (it never raises).
            updated: dict = {}
            changes: str = ""
        await self.audit_decision(_ACTION, True, target_id, f"actor={actor_id} target={target_id} {changes}")
        return self.json_response(updated, status=200)
```

**Why the order**: the payload is validated first (400 costs nothing and leaks
nothing); the grant gate precedes any database read, so an actor without the
action learns nothing about the target (not even whether it exists); the
self-target check precedes the hold rule so its audit reason is exact. `changes`
must spell `column: old -> new` for every changed column (AC11, spec §4
`test_role_endpoint_audits`).

### `navigator_auth/handlers/__init__.py` — MODIFY

```python
# AFTER — insert below `from .partners import PartnerKeyHandler` (verified: __init__.py:13, occurrences: 1)
from .users.role import UserRoleHandler

# AFTER — insert ABOVE `    UserManager.configure(app, '/api/v1/users')` (verified: __init__.py:38, occurrences: 1)
    # Privileged flags (FEAT-107). MUST precede UserManager.configure: its
    # `/api/v1/users/{id:.*}` route would otherwise match `/api/v1/users/5/role`.
    router.add_view(
        r"/api/v1/users/{id:\d+}/role", UserRoleHandler,
        name="api_user_role"
    )
```

### `tests/unit/handlers/test_user_role_handler.py` — CREATE

```python
"""UserRoleHandler — the only privileged-flag write path (FEAT-107, TASK-156)."""

import pytest
from navigator_auth.handlers.users.role import UserRoleHandler

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

# FILL IN: harness from tests/unit/handlers/test_partner_key_handler_access.py (local base, fake
#   app["authdb"]) with a fake users table and sessions: grantor (superuser + security_admin),
#   security_admin_only (not superuser), plain superuser (no security_admin), ordinary.


class TestGate:
    async def test_role_endpoint_requires_grant_action(self): ...        # plain superuser → 403, no DB read
    async def test_other_verbs_are_405(self): ...


class TestRules:
    async def test_role_endpoint_refuses_self_grant(self): ...           # any self-target → 403
    async def test_role_endpoint_refuses_granting_unheld_flag(self): ... # security_admin_only → is_superuser 403
    async def test_user_role_bounded_by_actor_role(self): ...
    async def test_unknown_key_rejected(self): ...                       # {"email": ...} → 400
    async def test_missing_target_is_404(self): ...


class TestWriteAndAudit:
    async def test_grantor_can_grant_superuser(self): ...                # UPDATE ... RETURNING issued, 200
    async def test_role_endpoint_audits(self): ...                       # actor, target, old → new recorded
    async def test_failed_write_is_500_and_audited(self): ...            # fetch_one returns None


class TestRouting:
    def test_role_route_registered_before_user_crud(self): ...           # see Steps
```

### Steps (in order)

1. Create `role.py` (both blocks) and complete the `FILL IN`s.
2. Register the route **above** `UserManager.configure` — because aiohttp matches
   in registration order.
3. Write `test_role_route_registered_before_user_crud`: build a `web.Application`,
   call `setup_handlers(app, app.router)`, resolve `POST /api/v1/users/5/role` with
   `app.router.resolve(make_mocked_request("POST", "/api/v1/users/5/role", app=app))`
   and assert the handler is `UserRoleHandler` — because a later reordering would
   silently route grants into the user CRUD.
4. Run `pytest tests/unit/handlers/test_user_role_handler.py -v`, then `pytest tests/unit/handlers/ -v`.

### FILL IN checklist

- [ ] `_role_payload` validation.
- [ ] Actor/target reads, hold rule, `UPDATE … RETURNING`, `changes` string.
- [ ] Test harness and all test bodies.

---

## Acceptance Criteria

- [ ] `pytest tests/unit/handlers/test_user_role_handler.py -v` passes.
- [ ] `pytest tests/unit/handlers/ -v` passes (AC2).
- [ ] The endpoint requires `users:grant_role`, refuses a self-grant, refuses an unheld flag, and audits every call (spec AC11).
- [ ] `POST /api/v1/users/{id}/role` resolves to `UserRoleHandler`, not `UserManager`.
- [ ] No `conn.execute(` in `navigator_auth/handlers/users/role.py`.
- [ ] `admin_full_access.yaml` is unchanged (spec AC12).

---

## Test Specification

See the CREATE block above.

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at `sdd/specs/auth-model-crud-hardening.spec.md` (§3 Module 5, §7 R7, R8, R12, R13).
2. **Check dependencies** — TASK-149, TASK-150, TASK-153 are `done` in `sdd/tasks/index/auth-model-crud-hardening.json`.
3. **Re-verify** the `handlers/__init__.py` anchors and `auth.py:673`.
4. **Update status** → `"in-progress"`.
5. **Implement** the blueprint and complete every `FILL IN`.
6. **Verify** the acceptance criteria (`source .venv/bin/activate` first).
7. **Move this file** to `sdd/tasks/completed/` and set the index entry to `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: sdd-worker (orchestrator)
**Date**: 2026-11-11
**Seat**: Backend: codex · Model: gpt-5.6-luna
**Notes**: POST /api/v1/users/{id}/role (UserRoleHandler, users:grant_role). Merge-tier validation: 3 passed. Unit coverage is thin; the endpoint's behaviour is meant to be exercised by TASK-157 e2e. Review: zero fixes (feedback recorded via coder_record_review).
