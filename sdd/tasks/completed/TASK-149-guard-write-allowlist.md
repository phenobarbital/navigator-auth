# TASK-149: Write-column allowlist on `OwnerOrSuperuserGuard`

**Feature**: FEAT-107 — Write-envelope hardening for the remaining auth CRUD handlers
**Spec**: `sdd/specs/auth-model-crud-hardening.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 1** (the security core of FEAT-107). Not
delegation-eligible: thinking model only (spec §3 table).

`OwnerOrSuperuserGuard` (FEAT-105) has a *read* allowlist (`public_columns`)
and a *verb* gate for the admin path (`superuser_actions`), but **no write-column
allowlist**. Worse, `authorize_row()` returns `True` for the row's owner before
any action or column check (`guards.py:141-142`). On `auth.users` the owner's row
carries the owner's own `is_superuser` / `user_role` / `is_staff`, so that early
return would authorize self-escalation the moment `UserManager` is put behind
the guard (TASK-153).

This task gives the guard the write side: four new class attributes, a new
`authorize_columns()` coroutine, and a narrowed owner fast-path. It does **not**
wire any handler — the verb hooks that call this live in TASK-151 (ModelView
base) and TASK-155 (local `handlers/model.py` base).

**Backward compatibility is the second requirement (spec G7, AC2).** The
FEAT-105 handlers (`UserIdentityHandler`, `UserAccountHandler`,
`PartnerKeyHandler`) call `authorize_row(action, owner_id)` with no payload.
They must keep their exact behaviour: the column check runs **only when a
`payload` is passed**.

### Spec deviation recorded at /sdd-task time
- `audit_decision` is defined at `guards.py:278` (spec §6 says `:282`).
- The spec's skeleton types `authorize_columns(payload: dict, ...)`. This task
  types it `Iterable[str]` (a `dict` is one) because TASK-151 passes the
  *union of raw client keys* across a bulk body, which is a `set`. It also adds
  two optional keyword-only args (`action`, `owner_id`) used only for the audit
  record. The skeleton's positional/keyword contract is otherwise unchanged.

---

## Scope

- Add `writable_by_owner`, `writable_by_admin`, `creatable_by_admin`,
  `privileged_columns` class attributes to `OwnerOrSuperuserGuard`, defaulting
  to empty / `None`.
- Implement `authorize_columns(payload, *, is_owner, creating=False, action=None, owner_id=None)`
  with **allowlist** semantics (spec G3) and the precedence:
  `privileged_columns` refused on every path → owner create refused → applicable
  allowlist (`creatable_by_admin` or `writable_by_admin` when creating;
  `writable_by_owner` for the owner; `writable_by_admin` for the admin path).
- Extend `authorize_row()` with keyword-only `payload: Optional[Iterable[str]] = None`
  and `creating: bool = False`. When `payload is not None`, run
  `authorize_columns()` on whichever path authorizes: owner fast-path
  (`is_owner=True`) and admin path after the policy allows (`is_owner=False`).
- Audit every column refusal through the existing `audit_decision()` (AC14).
- Refusal body names no column the caller cannot see (reuse `safe_fields`).
- Write the unit tests in `tests/unit/handlers/test_guard_write_allowlist.py`.

**NOT in scope**:
- Calling the new API from any handler (TASK-151, TASK-153, TASK-154, TASK-155).
- Protected groups: `protected_groups()`, `authorize_protected_group()`,
  `AUTH_PROTECTED_GROUPS` (TASK-152).
- Changing `sanitize_query`, `safe_filter`, `_session_info`, `acting_user`.
- Changing the FEAT-105 handlers or their tests.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/guards.py` | MODIFY | New attributes, `authorize_columns()`, `authorize_row()` payload/creating kwargs and narrowed owner path |
| `tests/unit/handlers/test_guard_write_allowlist.py` | CREATE | Unit tests for the write side of the guard |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `6b8cc84` on 2026-11-11.

### Verified Imports

```python
# already imported in navigator_auth/handlers/guards.py (verified: guards.py:14-24)
import logging
from typing import Any, Optional                       # :15 — add Iterable here
from navigator_session import get_session              # :17
from ..abac.audit import AuditLog                      # :19
from ..abac.policies import PolicyEffect               # :20
from ..abac.policies.abstract import PolicyResponse    # :21
from ..conf import AUTH_SESSION_OBJECT                 # :22
from ..decorators import _check_superuser, policy_allows  # :23
from .redaction import safe_fields                     # :24

# test-side (verified in tests/unit/handlers/test_owner_superuser_guard.py:6-13)
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from navigator_auth.abac.policies import Policy, PolicyEffect
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard
```

### Existing Signatures to Use

```python
# navigator_auth/handlers/guards.py
class OwnerOrSuperuserGuard:                                          # :31
    owner_column: Optional[str] = "user_id"                           # :52
    credential_columns: frozenset[str] = frozenset()                  # :53
    public_columns: frozenset[str] = frozenset()                      # :54  READ allowlist
    policy_name: Optional[str] = None                                 # :55
    superuser_actions: frozenset[str] = frozenset({"read", "revoke", "delete"})  # :56

    async def acting_user(self) -> tuple[int, bool]: ...              # :85  (401 on no session)
    def _refuse(self, not_found: bool = False): ...                   # :108 RAISES 403 / 404
    async def authorize_row(                                          # :114
        self, action: str, owner_id: Optional[int], *,
        not_found_on_deny: bool = False,                              # :119
    ) -> bool:                                                        # :120
        user_id, is_superuser = await self.acting_user()              # :140
        if self.owner_column is not None and owner_id is not None and str(owner_id) == str(user_id):  # :141
            return True                                               # :142  ← the blanket allow
        # :143-151 not-superuser / action ∉ superuser_actions / no policy_name → audit + _refuse
        allowed, reason, _ = await policy_allows(self.policy_name, self.request,
                                                 action=action, resource=self.request.path)  # :152-157
        await self.audit_decision(action, bool(allowed), owner_id, reason)  # :158
        if not allowed:                                               # :159
            self._refuse(not_found_on_deny)                           # :160
        return True                                                   # :161
    async def sanitize_query(self, qp, fields): ...                   # :163
    async def audit_decision(self, action: str, allowed: bool,
                             owner_id: Optional[int], reason: str) -> None: ...  # :278 never raises

# navigator_auth/handlers/redaction.py
def safe_fields(fields: Optional[list[str]], public_columns: frozenset[str]) -> Optional[list[str]]: ...  # :36
#   intersection, caller order; None in → None out
```

- `self.error(...)` **raises** (`navigator/views/base.py:201-243`, documented at
  `guards.py:8-11`). Every refusal must raise; never return `False`.
- The FEAT-105 callers of `authorize_row` pass **no payload**:
  `userattrs.py:110,132,248,271` and others, `partners.py:90`.

### Does NOT Exist (Anti-Hallucination)

- ~~`writable_by_owner` / `writable_by_admin` / `creatable_by_admin` / `privileged_columns`~~ — added by this task.
- ~~`OwnerOrSuperuserGuard.authorize_columns()`~~ — added by this task.
- ~~a write allowlist in `navigator.views.ModelView`~~ — `_hidden` is a response filter.
- ~~`authorize_row(..., payload=...)`~~ — the kwarg is added by this task.
- ~~`protected_groups()` / `authorize_protected_group()`~~ — TASK-152, not here.

---

## Implementation Blueprint

### `navigator_auth/handlers/guards.py` — MODIFY (block 1: import)

```python
# REPLACE `from typing import Any, Optional` (verified: guards.py:15)
# occurrences: 1 (verified: grep -c 'from typing import Any, Optional' navigator_auth/handlers/guards.py)
from typing import Any, Iterable, Optional
```

**Why**: `authorize_columns` and `authorize_row` take `Iterable[str]` payloads.

### `navigator_auth/handlers/guards.py` — MODIFY (block 2: attributes)

```python
# AFTER — insert below `    superuser_actions: frozenset[str] = frozenset({"read", "revoke", "delete"})` (verified: guards.py:56)
# occurrences: 1 (verified: grep -c on that exact line)

    #: Write side (FEAT-107). Allowlists, never denylists (spec G3): a key
    #: absent from the applicable set is refused, so a column added to the
    #: model later is closed by default. All empty by default, and only
    #: consulted when ``authorize_row`` receives a ``payload`` — the FEAT-105
    #: handlers pass none and are unaffected (spec G7).
    writable_by_owner: frozenset[str] = frozenset()
    writable_by_admin: frozenset[str] = frozenset()
    #: ``None`` means "same as ``writable_by_admin``".
    creatable_by_admin: Optional[frozenset[str]] = None
    #: Writable by NO CRUD path, owner included, create included.
    privileged_columns: frozenset[str] = frozenset()
```

Also extend the class docstring's `Attributes:` list (`guards.py:38-50`) with one
entry per new attribute, and change "set the five class attributes below" to
"nine".

**Why**: per-surface behaviour stays configuration, not forked logic
(`guards.py:34-36`, spec §7).

### `navigator_auth/handlers/guards.py` — MODIFY (block 3: `authorize_row` signature)

```python
# AFTER — insert below `        not_found_on_deny: bool = False,` (verified: guards.py:119)
# occurrences: 1 (verified: grep -c '        not_found_on_deny: bool = False,' navigator_auth/handlers/guards.py)
        payload: Optional[Iterable[str]] = None,
        creating: bool = False,
```

Add to the docstring `Args:` (`guards.py:123-129`):

```text
            payload: The CLIENT-SUPPLIED keys of a write (dict or iterable of
                column names). ``None`` — reads, deletes and every FEAT-105
                caller — skips the column check entirely. A write caller that
                omits it gets the pre-FEAT-107 blanket owner allow back, so
                every write hook MUST pass it (TASK-151 / TASK-155).
            creating: The payload is for a new row; checked against
                ``creatable_by_admin``. There is no owner create path.
```

### `navigator_auth/handlers/guards.py` — MODIFY (block 4: the owner fast-path — spec R2)

```python
# REPLACE the two lines starting at
# `        if self.owner_column is not None and owner_id is not None and str(owner_id) == str(user_id):` (verified: guards.py:141)
# occurrences: 1 (verified: grep -c on that exact line). The line below it is `            return True` (guards.py:142).
        if self.owner_column is not None and owner_id is not None and str(owner_id) == str(user_id):
            if payload is not None:
                await self.authorize_columns(
                    payload, is_owner=True, creating=creating, action=action, owner_id=owner_id
                )
            return True
```

**Why**: this early return is the whole feature (spec R2). Keep the column check
**inside** the owner branch and **before** `return True` — placing it after the
branch would never run for owners; placing it before the branch would apply the
owner allowlist to superusers. The owner path still takes no policy and writes
no audit record on success (FEAT-105 contract, `test_owner_writes_no_audit_record`).

### `navigator_auth/handlers/guards.py` — MODIFY (block 5: admin path tail)

```python
# REPLACE the three lines starting at
# `        await self.audit_decision(action, bool(allowed), owner_id, reason)` (verified: guards.py:158)
# occurrences: 1 (verified: grep -c on that exact line). Followed by `        if not allowed:` (:159),
# `            self._refuse(not_found_on_deny)` (:160), `        return True` (:161).
        await self.audit_decision(action, bool(allowed), owner_id, reason)
        if not allowed:
            self._refuse(not_found_on_deny)
        if payload is not None:
            await self.authorize_columns(
                payload, is_owner=False, creating=creating, action=action, owner_id=owner_id
            )
        return True
```

**Why**: the policy decides *whether* the admin path may act; the allowlist
decides *what* it may write (spec G2: enforced on both paths). Running the column
check after the policy keeps the existing audit record of the policy decision
intact and adds a second record only on a column refusal.

### `navigator_auth/handlers/guards.py` — MODIFY (block 6: `authorize_columns`)

```python
# AFTER — insert ABOVE `    async def sanitize_query(` (verified: guards.py:163)
# occurrences: 1 (verified: grep -c '    async def sanitize_query(' navigator_auth/handlers/guards.py)
    async def authorize_columns(
        self,
        payload: Iterable[str],
        *,
        is_owner: bool,
        creating: bool = False,
        action: Optional[str] = None,
        owner_id: Optional[int] = None,
    ) -> None:
        """Refuse a write whose payload touches a column this path may not write.

        Allowlist semantics (spec G3). The applicable set is:

            creating             -> creatable_by_admin (or writable_by_admin)
            updating, owner      -> writable_by_owner
            updating, admin path -> writable_by_admin

        A key in ``privileged_columns`` is refused on every path, owner
        included, create included. There is no owner create path: a create
        always goes through the superuser path of :meth:`authorize_row`.

        Args:
            payload: The client-supplied keys (a dict iterates its keys).
            is_owner: The owner path authorized this write.
            creating: The payload is for a new row.
            action: For the audit record only.
            owner_id: For the audit record only.

        Raises:
            web.HTTPForbidden: a key falls outside the envelope. The body names
                only refused columns that are in ``public_columns``.
            TypeError: ``payload`` is a ``str``/``bytes`` (iterating it would
                yield characters, silently passing the check).
        """
        if isinstance(payload, (str, bytes)):
            raise TypeError("authorize_columns expects column names, not a string")
        keys = {str(k) for k in payload}
        label = action or ("columns:create" if creating else "columns:update")
        if creating and is_owner:
            await self.audit_decision(label, False, owner_id, "no owner create path")
            self._refuse()
        if creating:
            allowed = self.creatable_by_admin if self.creatable_by_admin is not None else self.writable_by_admin
        elif is_owner:
            allowed = self.writable_by_owner
        else:
            allowed = self.writable_by_admin
        refused = (keys & self.privileged_columns) | (keys - allowed)
        if not refused:
            return
        await self.audit_decision(
            label, False, owner_id, f"columns outside the write envelope: {sorted(refused)}"
        )
        body: dict = {"error": "Forbidden"}
        named = safe_fields(sorted(refused), self.public_columns)
        if named:
            body["columns"] = named
        self.error(response=body, status=403)
```

**Why each line**:
- `privileged_columns` is unioned in, not subtracted from `allowed`, so a
  misconfiguration that lists a column in both still refuses it (privileged wins).
- The audit record may name every refused column (it is server-side); the
  response may name only `public_columns` members (spec AC14, `redaction.py:36`).
  The five FEAT-107 handlers declare no `public_columns`, so their refusal body is
  exactly `{"error": "Forbidden"}`.
- `self.error(...)` raises; there is deliberately no `return False` (`guards.py:8-11`).

### `tests/unit/handlers/test_guard_write_allowlist.py` — CREATE

```python
"""Write-column allowlist on OwnerOrSuperuserGuard (FEAT-107, TASK-149).

Driven through a synthetic host, like test_owner_superuser_guard.py: no
handler, no database. Fixtures are copied from that module (lines 23-167).
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from navigator_auth.abac.policies import Policy, PolicyEffect
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

POLICY = "users_admin_access"
ACTIONS = frozenset({"user:read", "user:create", "user:update", "user:delete"})
OWNER = frozenset({"first_name", "last_name", "display_name", "title", "avatar", "timezone"})
ADMIN = OWNER | {"is_active", "email", "alt_email"}
PRIVILEGED = frozenset({"is_superuser", "user_role", "is_staff", "password",
                        "userid", "user_id", "created_at", "last_login"})


class Host(OwnerOrSuperuserGuard):
    owner_column = "user_id"
    policy_name = POLICY
    superuser_actions = ACTIONS
    writable_by_owner = OWNER
    writable_by_admin = ADMIN
    creatable_by_admin = ADMIN | {"username"}
    privileged_columns = PRIVILEGED

    def __init__(self, request):
        self.request = request

    def error(self, response=None, status=400, **kwargs):
        """Mirror BaseHandler.error(): RAISE, never return."""
        # FILL IN: copy Host.error from test_owner_superuser_guard.py:63-73 verbatim


class MappingHost(Host):
    """UserGroupManager-shaped host: no owner, PK columns creatable only."""
    owner_column = None
    policy_name = "user_groups_admin_access"
    superuser_actions = frozenset({"user_group:read", "user_group:create", "user_group:delete"})
    writable_by_owner = frozenset()
    writable_by_admin = frozenset()
    creatable_by_admin = frozenset({"user_id", "group_id"})
    privileged_columns = frozenset()

# FILL IN: copy FakePDP, _audit, _request, _session, _patch_session, _Sess and S
#   from test_owner_superuser_guard.py:84-167; _policy(name, actions) must build a
#   Policy(name, effect=PolicyEffect.ALLOW, actions=list(actions), groups=["superuser"], priority=1)


class TestOwnerPath:
    async def test_owner_cannot_write_privileged_column(self): ...      # FILL IN — AC3/AC4
    async def test_owner_can_write_profile_allowlist(self): ...         # FILL IN — AC10
    async def test_unknown_column_refused_by_default(self): ...        # FILL IN — AC5 ("attributes", "is_new")
    async def test_owner_create_refused(self): ...                      # FILL IN — no owner create path


class TestAdminPath:
    async def test_admin_cannot_write_privileged_column(self): ...     # FILL IN — AC4
    async def test_admin_can_write_admin_allowlist(self): ...          # FILL IN — AC10
    async def test_create_uses_creatable_allowlist(self): ...          # FILL IN — username creatable, not updatable
    async def test_mapping_row_create_allowed_for_admin(self): ...     # FILL IN — AC20 (MappingHost)
    async def test_mapping_row_update_refused(self): ...               # FILL IN — "user_group:update" ∉ superuser_actions


class TestRefusals:
    async def test_refusal_names_no_hidden_column(self): ...           # FILL IN — AC14
    async def test_column_refusal_is_audited(self): ...                 # FILL IN — AC14
    async def test_string_payload_rejected(self): ...                   # FILL IN — TypeError


class TestBackwardCompatibility:
    async def test_payload_none_keeps_owner_blanket_allow(self): ...   # FILL IN — G7
    def test_feat105_handlers_unchanged(self): ...                      # FILL IN — G7, see Steps
```

### Steps (in order)

1. Apply blocks 1–6 to `guards.py` in order — because blocks 4 and 5 call
   `authorize_columns` (block 6) and use the attributes from block 2.
2. Run `pytest tests/unit/handlers/test_owner_superuser_guard.py -v` **before
   writing new tests** — because it proves the payload-less path is unchanged
   (G7). It must pass without edits.
3. Create the test module; copy the harness from
   `tests/unit/handlers/test_owner_superuser_guard.py` rather than re-inventing
   it — because its `Host.error` raises the same exception classes as
   `BaseHandler.error`, which is what makes "refusals are raised" testable.
4. Write `test_feat105_handlers_unchanged` as an attribute check: import
   `UserIdentityHandler`, `UserAccountHandler` (`navigator_auth.handlers.userattrs`)
   and `PartnerKeyHandler` (`navigator_auth.handlers.partners`) and assert their
   four new attributes are empty / `None` — because their behaviour is proven by
   their own suites; this test only pins that FEAT-107 did not configure them.
5. Run the full handler suite (AC2) and `ruff check navigator_auth/handlers/guards.py`.

### FILL IN checklist

- [ ] Class docstring `Attributes:` entries for the four new attributes.
- [ ] Test harness copied from `test_owner_superuser_guard.py` (`Host.error`, `FakePDP`, `_policy`, `_audit`, `_request`, `_session`, `_patch_session`, `S`).
- [ ] Every test body listed above, each asserting the HTTP class raised
      (`web.HTTPForbidden`) **and**, for success cases, that `authorize_row` returned `True`.
- [ ] `test_refusal_names_no_hidden_column`: the raised exception's `.text` contains none of `is_superuser`, `user_role`, `password`.
- [ ] `test_column_refusal_is_audited`: patch `navigator_auth.handlers.guards.AuditLog` (or pass a FakePDP with `_audit()`) and assert one `DENY` record whose response mentions the refused column.

---

## Acceptance Criteria

- [ ] `pytest tests/unit/handlers/test_guard_write_allowlist.py -v` passes.
- [ ] `pytest tests/unit/handlers/ tests/test_check_superuser.py tests/test_allowed.py tests/test_policy_allows.py -v` passes unchanged (spec AC2).
- [ ] The owner of a row cannot write a `privileged_columns` key or any key outside `writable_by_owner` (spec AC3, AC4, AC5 at guard level).
- [ ] `authorize_row(...)` without `payload` behaves exactly as before for every existing test.
- [ ] Every column refusal is audited via `audit_decision()` and its body names no non-public column (spec AC14).
- [ ] `ruff check navigator_auth/handlers/guards.py tests/unit/handlers/test_guard_write_allowlist.py` is clean.

---

## Test Specification

See the CREATE block above. Minimum assertions:

| Test | Asserts |
|---|---|
| `test_owner_cannot_write_privileged_column` | owner (`user_id=42`, row owner 42), `payload={"is_superuser"}` on `user:update` → `HTTPForbidden` |
| `test_owner_can_write_profile_allowlist` | owner, `payload={"first_name","timezone"}` → `True`, no `policy_allows` call |
| `test_unknown_column_refused_by_default` | owner and admin, `payload={"attributes"}` → `HTTPForbidden` |
| `test_admin_can_write_admin_allowlist` | superuser + policy, foreign row, `payload={"email","is_active"}` → `True` |
| `test_create_uses_creatable_allowlist` | `creating=True`: `{"username","email"}` passes; `{"username","password"}` refused; a host with `creatable_by_admin=None` falls back to `writable_by_admin` |
| `test_mapping_row_create_allowed_for_admin` | `MappingHost`, `user_group:create`, `payload={"user_id","group_id"}`, `creating=True` → `True` |
| `test_payload_none_keeps_owner_blanket_allow` | owner, `authorize_row("user:update", 42)` → `True` |

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at `sdd/specs/auth-model-crud-hardening.spec.md` (§2 Overview, §3 Module 1, §6, §7 R2).
2. **Check dependencies** — none.
3. **Re-verify the Codebase Contract** — re-run the `grep -c` for each anchor; stop and report if any count is not 1.
4. **Update status** in `sdd/tasks/index/auth-model-crud-hardening.json` → `"in-progress"`.
5. **Implement** the blueprint and complete every `FILL IN`.
6. **Verify** the acceptance criteria (`source .venv/bin/activate` first).
7. **Move this file** to `sdd/tasks/completed/` and set the index entry to `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: sdd-worker (orchestrator)
**Date**: 2026-11-11
**Seat**: Seat: gpt-5.6-terra · Backend: codex · Model: gpt-5.6-terra · Attempts: 1 (attempt 4 after env-blocked earlier runs) · Duration: 274s
**Notes**: Added writable_by_owner / writable_by_admin / creatable_by_admin / privileged_columns and authorize_columns() to OwnerOrSuperuserGuard; authorize_row gained payload/creating (payload=None keeps FEAT-105 behaviour). Merge-tier: 22 passed. Review: zero fixes (feedback coder-review:b048a9599dab42436ada8d6f).
