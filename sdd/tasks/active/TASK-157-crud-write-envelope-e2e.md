# TASK-157: End-to-end regression suite — the escalation is closed, and was open

**Feature**: FEAT-107 — Write-envelope hardening for the remaining auth CRUD handlers
**Spec**: `sdd/specs/auth-model-crud-hardening.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-150, TASK-153, TASK-154, TASK-155, TASK-156
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 7** and the **§4 Integration Tests** table. This is
the file named by spec AC1 (`pytest tests/test_auth_crud_write_envelope.py -v`).

The unit suites from TASK-149..156 prove each method. This suite proves the
**sequences and the reachability** the acceptance criteria are written about —
spec R6: "any authenticated user can reach `PATCH /api/v1/users/{id}`" was
established by reading code, not by a request. So every scenario here starts
from the **real router** (`setup_handlers(app, app.router)` →
`app.router.resolve(...)`), drives the resolved handler class, and runs the
**shipped** `auth_crud_admin_access.yaml` through `YAMLStorage` into real
`ResourcePolicy` objects — the approach FEAT-105's
`tests/integration/test_auth_model_ownership.py` already uses. In-process and
connection-mocked: no database, no Redis.

### The inverted probe
The §1 probe script (`/tmp/claude-1000/.../probe_usermanager_write.py`) **no
longer exists** — it lived in a previous session's scratchpad (verified missing
2026-11-11). Rebuild it from §1: drive `UserManager`'s write path over the real
`User` model with the §4 `escalation_payload` and assert the inverse of the §1
evidence — refused, and `is_superuser` / `is_staff` / `user_role` / `email` /
`password` unchanged — for the owner and for an approved superuser, on PATCH,
PUT and POST.

### Facts the scenarios depend on (decided in earlier tasks)

- User creation is **`PUT /api/v1/users`** — POST needs a PK on this base
  (TASK-153 deviation 2). Read the spec's "POST" in AC19 and in
  `test_admin_can_create_user_then_reset_password` as PUT.
- Membership rows are created with **PUT** and removed with DELETE; POST/PATCH on
  the mapping routes are refused (TASK-154 deviation 4). Exercise both
  `/api/v1/user_groups` and `/api/v1/usergroups`.
- Actions are `object:verb` (TASK-150).
- Reads are gated (user decision 2026-11-11).
- `UserSession.password_change` / `password_reset` have **no existing tests**
  (verified: `grep -rln "password_change\|password_reset" tests` is empty). AC9
  scenarios pin their **current** behaviour, quirks included — e.g.
  `password_change` compares the URL `userid` (a `str`) to the session `user_id`
  with `!=` (`session.py:145`). Do not fix those here; that is out of scope (spec
  §1 Non-Goals).

---

## Scope

- Create `tests/test_auth_crud_write_envelope.py` with the scenarios below.
- Fixtures local to the module (the spec's names: `ordinary_session`,
  `admin_session`, `grantor_session`, `security_admin_only_session`,
  `escalation_payload`), so `tests/conftest.py` stays untouched.

**NOT in scope**:
- Any production code change. If a scenario fails, report it against the task
  that owns the code (TASK-149..156); do not patch around it here.
- A live database run (spec R6 — no DB/Redis is available in this suite).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/test_auth_crud_write_envelope.py` | CREATE | End-to-end scenarios over the real router and the shipped pack |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `6b8cc84` on 2026-11-11 (handler internals as specified by TASK-149..156).

### Verified Imports

```python
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from navigator_auth.abac.policies.resource_policy import ResourcePolicy     # used by tests/integration/test_auth_model_ownership.py:23
from navigator_auth.abac.storages.yaml_storage import YAMLStorage           # :24
from navigator_auth.handlers import setup_handlers                          # handlers/__init__.py:20
from navigator_auth.handlers.users.user import UserManager
from navigator_auth.handlers.users.role import UserRoleHandler              # TASK-156
from navigator_auth.handlers.users.session import UserSession               # session.py:18
from navigator_auth.handlers.groups import GroupManager, GroupPermissionManager, UserGroupManager
from navigator_auth.handlers.permissions import PermissionHandler
from navigator_auth.models import User
```

### Existing Signatures to Use

```python
# navigator_auth/handlers/__init__.py
def setup_handlers(app: web.Application, router: web.RouteDef) -> None: ...   # :20 — pass app.router
#   registers /api/v1/permissions, /groups, /user_groups, /group_permissions, /usergroups,
#   /users/{id:\d+}/role (TASK-156, before) and /users via ModelView.configure (abstract.py:189)

# navigator_auth/handlers/users/session.py
class UserSession(BaseHandler):                                       # :18
    async def password_change(self, request: web.Request): ...       # :119 — get_json → password, old_password;
    #   403 when URL userid != session user_id; User.get(user_id) → check_password → set_basic_password → update()
    async def password_reset(self, request: web.Request): ...        # :170 — json_data → password; userinfo["superuser"]
    #   is False → 406; User.get(user_id=userid) → set_basic_password, is_new = True, update()

# FEAT-105 integration harness to copy (tests/integration/test_auth_model_ownership.py):
#   FakeSession :50, FakePDP :55, FakeModel :68, _Obj :101, FakeConn :109, pdp_with_pack :206,
#   _patch_sessions :242, _request :246, _crud :257, _body :301, TestRoutesStillExist :514
```

### Does NOT Exist (Anti-Hallucination)

- ~~`probe_usermanager_write.py`~~ — gone; rebuild from spec §1.
- ~~`ordinary_session` / `admin_session` / `grantor_session` / `security_admin_only_session` fixtures in `tests/conftest.py`~~ — defined in this module.
- ~~an aiohttp test server with a real database~~ — in-process and mocked, like FEAT-105.
- ~~existing tests for `password_change` / `password_reset`~~ — none.

---

## Implementation Blueprint

### `tests/test_auth_crud_write_envelope.py` — CREATE (block 1 of 2: harness)

```python
"""FEAT-107 end to end: the auth CRUD write envelope, over the real router.

In-process and connection-mocked: no database. Routes come from the real
setup_handlers(); policies are the SHIPPED auth_crud_admin_access.yaml, parsed
with YAMLStorage into real ResourcePolicy objects — the approach of
tests/integration/test_auth_model_ownership.py (FEAT-105).
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.abac.policies.resource_policy import ResourcePolicy
from navigator_auth.abac.storages.yaml_storage import YAMLStorage
from navigator_auth.handlers import setup_handlers

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

PACK = Path(__file__).resolve().parents[1] / "navigator_auth" / "abac" / "default_policies" / "auth_crud_admin_access.yaml"

OWNER_ID, ADMIN_ID, GRANTOR_ID, SECADMIN_ID, VICTIM_ID = 42, 7, 8, 9, 99


@pytest.fixture
def escalation_payload():
    """Spec §4, verbatim — the §1 payload."""
    return {"is_superuser": True, "is_staff": True, "user_role": 10,
            "email": "attacker@evil.test", "password": "hunter2"}


@pytest.fixture
def ordinary_session(): ...          # FILL IN: user 42, groups ["users"], not superuser
@pytest.fixture
def admin_session(): ...             # FILL IN: user 7, groups ["superuser"]
@pytest.fixture
def grantor_session(): ...           # FILL IN: user 8, groups ["superuser", "security_admin"]
@pytest.fixture
def security_admin_only_session(): ...   # FILL IN: user 9, groups ["security_admin"]


@pytest.fixture
def app():
    """A bare Application with the real FEAT-107 routes."""
    application = web.Application()
    setup_handlers(application, application.router)
    return application

# FILL IN: pdp_with_pack (shipped PACK → ResourcePolicy), fake users / groups tables behind a
#   FakeConn that records insert/update/updating/fetch_one calls, session patching, and a
#   `_drive(app, method, path, body=None, session=..., pdp=...)` helper that resolves the route
#   with app.router.resolve(make_mocked_request(...)), instantiates the handler class and awaits
#   its verb — adapted from test_auth_model_ownership.py:206-312.
```

### `tests/test_auth_crud_write_envelope.py` — CREATE (block 2 of 2: scenarios)

```python
class TestInvertedProbe:
    async def test_section1_payload_refused_for_owner(self, app, ordinary_session, escalation_payload): ...
    async def test_section1_payload_refused_for_admin(self, app, admin_session, escalation_payload): ...
    async def test_section1_payload_refused_on_put_and_post(self, app, admin_session, escalation_payload): ...


class TestEscalationRoutesClosed:
    async def test_authenticated_user_cannot_escalate_via_users_crud(self, app, ordinary_session): ...
    async def test_authenticated_user_cannot_escalate_via_user_groups(self, app, ordinary_session): ...   # both routes
    async def test_authenticated_user_cannot_escalate_via_group_permissions(self, app, ordinary_session): ...
    async def test_superuser_cannot_escalate_via_security_admin_membership(self, app, admin_session): ... # PUT add self, PATCH rename


class TestLegitimateAdministration:
    async def test_admin_can_still_administer_users(self, app, admin_session): ...          # AC10
    async def test_user_can_still_edit_own_profile(self, app, ordinary_session): ...        # AC10
    async def test_admin_can_create_user_then_reset_password(self, app, admin_session): ... # AC19 (PUT), is_new=True
    async def test_role_grant_end_to_end(self, app, grantor_session, admin_session): ...   # AC11: allowed + audited; refused for plain superuser


class TestPasswordPathsUnchanged:
    async def test_password_change_still_works(self): ...       # AC9: drive UserSession.password_change with mocks
    async def test_password_reset_still_works(self): ...        # AC9


class TestRoutes:
    def test_role_route_resolves_before_user_crud(self, app): ...
    def test_every_surface_resolves_to_a_guarded_handler(self, app): ...   # the five + role subclass OwnerOrSuperuserGuard
```

### Steps (in order)

1. Build the harness by adapting `tests/integration/test_auth_model_ownership.py:50-312`
   — because it already turns the shipped YAML into real policies and fakes the
   connections; inventing a new harness risks testing a mock instead of the guard.
2. Write `TestRoutes` first and run it — because every later scenario relies on
   the route resolving to the right class.
3. Write `TestInvertedProbe`; each test asserts the refusal status **and** that
   the fake connection recorded no `update`/`insert`/`updating`/`create` call and
   that the fake user row still has `is_superuser=False`, `password` unset.
4. Write the remaining classes. For AC9, drive `UserSession` directly with a
   mocked request and `User.get` patched — because there is no route-level
   harness for it and the goal is only "unchanged".
5. Run `pytest tests/test_auth_crud_write_envelope.py -v`, then the full spec
   validation contract (below).

### FILL IN checklist

- [ ] Four session fixtures and the harness (`pdp_with_pack`, fake tables, `_drive`).
- [ ] Every scenario body; refusal scenarios assert "no write recorded".
- [ ] AC9 mocks for `password_change` / `password_reset`.

---

## Acceptance Criteria

- [ ] `pytest tests/test_auth_crud_write_envelope.py -v` passes (spec AC1).
- [ ] The full validation contract passes:
      `pytest tests/test_auth_crud_write_envelope.py tests/unit/handlers/ tests/test_check_superuser.py tests/test_allowed.py tests/test_policy_allows.py -v`
      (spec §4 Validation Contract, AC2).
- [ ] The §1 payload is refused for every actor on PATCH, PUT and POST and the row is unmodified (spec AC3).
- [ ] An ordinary session cannot join a group or grant a permission on any of the three mapping routes (spec AC6).
- [ ] `password_change`, `password_reset` behave as before (spec AC9).
- [ ] Legitimate administration and profile edits still succeed (spec AC10, AC19).

---

## Test Specification

See the CREATE blocks above.

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at `sdd/specs/auth-model-crud-hardening.spec.md` (§1, §4, §5, §7 R6).
2. **Check dependencies** — TASK-150, TASK-153, TASK-154, TASK-155, TASK-156 are `done` in `sdd/tasks/index/auth-model-crud-hardening.json`.
3. **Read the Completion Notes** of TASK-149..156 for any deviation that changes a scenario.
4. **Update status** → `"in-progress"`.
5. **Implement** the blueprint and complete every `FILL IN`.
6. **Verify** the acceptance criteria (`source .venv/bin/activate` first).
7. **Move this file** to `sdd/tasks/completed/` and set the index entry to `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: creation scenarios use PUT | other
