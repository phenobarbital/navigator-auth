# TASK-152: Protected groups — `AUTH_PROTECTED_GROUPS` and `authorize_protected_group()`

**Feature**: FEAT-107 — Write-envelope hardening for the remaining auth CRUD handlers
**Spec**: `sdd/specs/auth-model-crud-hardening.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-149
**Assigned-to**: unassigned

---

## Context

Implements the **guard side of spec §3 Module 9** (G8, AC17, AC18). Not
delegation-eligible: each rule is "a one-clause mistake away from re-opening G8".
The call sites in `groups.py` are TASK-154.

Groups are identified by **name** in every authorization check:
`_check_superuser()` treats membership of the group named `superuser` as
superuser (`decorators.py:288-311`), and ABAC policies match `subjects.groups`
against the names in `userinfo["groups"]` (`abac/policies/policy.py:22`). So with
only the plain `superuser` CRUD policy, a superuser could join `security_admin`
(inheriting `users:grant_role` and FEAT-106's `mfa:disenroll`), rename an
ordinary group into it, or add anyone to `superuser` without going through the
role endpoint. A **protected group** closes that: changing its membership or its
definition needs `users:grant_role`, the actor must belong to it, and nobody can
add themselves.

This task depends on TASK-149 only because both edit `guards.py`; there is no
logical dependency on the write allowlist.

### Shared file with FEAT-106
FEAT-106 (`basicauth-otp-2fa`) also adds settings to `navigator_auth/conf.py`.
This task appends `AUTH_PROTECTED_GROUPS` right after `ABAC_DEFAULT_EFFECT`
(`conf.py:710`). Expect at most a trivial textual conflict (spec Worktree Strategy).

---

## Scope

- Add `AUTH_PROTECTED_GROUPS` to `navigator_auth/conf.py` (list of names,
  default `superuser,security_admin`), after `ABAC_DEFAULT_EFFECT`.
- Add module-level `protected_groups() -> frozenset[str]` to `guards.py`:
  `set(AUTH_PROTECTED_GROUPS) | {SUPERUSER_GROUP}`, read at **call time**.
- Add `OwnerOrSuperuserGuard.authorize_protected_group(group_names, *, member_id=None)`
  implementing the four rules of spec §3 M9, raising on refusal, auditing every outcome.
- Write `tests/unit/handlers/test_protected_groups.py`.

**NOT in scope**:
- Resolving a `group_id` to its stored name, and calling this from the group
  handlers (TASK-154).
- The role endpoint (TASK-156) — it uses the same policy name but its own logic.
- Seeding the first `security_admin` member — out-of-band by design (spec R12), documented in TASK-158.
- Deriving the protected set from the policy pack (rejected in spec R11).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/conf.py` | MODIFY | `AUTH_PROTECTED_GROUPS` setting |
| `navigator_auth/handlers/guards.py` | MODIFY | imports, `protected_groups()`, `authorize_protected_group()` |
| `tests/unit/handlers/test_protected_groups.py` | CREATE | Guard-level M9 tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `6b8cc84` on 2026-11-11. Line numbers in `guards.py`
> are pre-TASK-149; re-grep the anchors after TASK-149 lands.

### Verified Imports

```python
# navigator_auth/handlers/guards.py (verified: :15, :22, :23)
from typing import Any, Iterable, Optional                 # Iterable added by TASK-149
from ..conf import AUTH_SESSION_OBJECT                     # :22 — add AUTH_PROTECTED_GROUPS
from ..decorators import _check_superuser, policy_allows   # :23 — add SUPERUSER_GROUP
# navigator_auth/decorators.py
SUPERUSER_GROUP = "superuser"                              # :288
def _check_superuser(userinfo: dict, user: object = None) -> bool: ...   # :291
```

### Existing Signatures to Use

```python
# navigator_auth/conf.py
ABAC_DEFAULT_EFFECT = config.get("ABAC_DEFAULT_EFFECT", fallback="deny")   # :710
ABAC_RELOAD_INTERVAL = config.getint("ABAC_RELOAD_INTERVAL", fallback=0)    # :713

# navigator_auth/decorators.py:291-311 — membership semantics to MIRROR for non-superuser groups
#   groups = userinfo.get("groups")
#   if isinstance(groups, (list, tuple, set, frozenset)): name in groups   ← never `in` on a str (substring)
#   if user is not None and hasattr(user, "groups"):
#       for g in user.groups: getattr(g, "group", None) or getattr(g, "group_name", None)

# navigator_auth/decorators.py:1170
async def policy_allows(policy, request, action=None, resource=None,
                        resource_type=None, require_all=False) -> tuple[bool, str, Any]: ...
#   fails closed: no ABAC, undeclared policy, or raising policy → (False, reason, ...)

# navigator_auth/handlers/guards.py
class OwnerOrSuperuserGuard:
    async def _session_info(self) -> tuple[Any, dict, Any]: ...   # :61  (session, userinfo, user); 401
    async def acting_user(self) -> tuple[int, bool]: ...          # :85
    def _refuse(self, not_found: bool = False): ...               # :108 raises
    async def audit_decision(self, action, allowed, owner_id, reason) -> None: ...  # :278 never raises
_BAD_FILTER = "Invalid _filter"                                   # :28
```

- Policy name and action are fixed by TASK-150: `users_grant_role` / `users:grant_role`.
- The resource passed must be `self.request.path` — `users_grant_role` covers
  `/api/v1/user_groups*`, `/api/v1/usergroups*`, `/api/v1/groups*`, `/api/v1/users*`.

### Does NOT Exist (Anti-Hallucination)

- ~~`AUTH_PROTECTED_GROUPS`~~, ~~`protected_groups()`~~, ~~`authorize_protected_group()`~~ — created here.
- ~~a `security_admin` group anywhere in code or fixtures~~ — only named by config and the pack.
- ~~a helper that returns the acting user's group names~~ — read them from `_session_info()` yourself.

---

## Implementation Blueprint

### `navigator_auth/conf.py` — MODIFY

```python
# AFTER — insert below `ABAC_DEFAULT_EFFECT = config.get("ABAC_DEFAULT_EFFECT", fallback="deny")` (verified: conf.py:710)
# occurrences: 1 (verified: grep -c on that exact line)

# Protected groups (FEAT-107). Membership or definition of these groups can
# only be changed by an actor holding the `users:grant_role` ABAC action who
# belongs to the group; nobody can add themselves. MUST list every group named
# by a privileged policy (users:grant_role, FEAT-106's mfa:disenroll, ...).
# `superuser` is always protected, whatever this says.
AUTH_PROTECTED_GROUPS = [
    e.strip()
    for e in config.get("AUTH_PROTECTED_GROUPS", fallback="superuser,security_admin").split(",")
    if e.strip()
]
```

### `navigator_auth/handlers/guards.py` — MODIFY (block 1: imports)

```python
# REPLACE `from ..conf import AUTH_SESSION_OBJECT` (verified: guards.py:22) — occurrences: 1
from ..conf import AUTH_PROTECTED_GROUPS, AUTH_SESSION_OBJECT
# REPLACE `from ..decorators import _check_superuser, policy_allows` (verified: guards.py:23) — occurrences: 1
from ..decorators import SUPERUSER_GROUP, _check_superuser, policy_allows
```

### `navigator_auth/handlers/guards.py` — MODIFY (block 2: `protected_groups`)

```python
# AFTER — insert below `_BAD_FILTER = "Invalid _filter"` (verified: guards.py:28) — occurrences: 1
_GRANT_ROLE_POLICY = "users_grant_role"
_GRANT_ROLE_ACTION = "users:grant_role"


def protected_groups() -> frozenset[str]:
    """Return the effective protected set: the setting plus ``superuser``.

    Read at call time so a test (or a reloaded config) sees the current value.
    An operator can add to the set but can never un-protect ``superuser``,
    whose membership IS ``is_superuser`` (decorators.py:288-311).
    """
    return frozenset(AUTH_PROTECTED_GROUPS) | {SUPERUSER_GROUP}
```

### `navigator_auth/handlers/guards.py` — MODIFY (block 3: `authorize_protected_group`)

```python
# AFTER — insert ABOVE `    async def sanitize_query(` (verified pre-TASK-149: guards.py:163) — occurrences: 1
#   (TASK-149 inserts authorize_columns above the same anchor; place this method after it.)
    async def authorize_protected_group(
        self,
        group_names: Iterable[str],
        *,
        member_id: Optional[int] = None,
    ) -> None:
        """Gate a change that touches a protected group (spec §3 M9, G8).

        Runs AFTER :meth:`authorize_row` has already passed the superuser path.

        1. No name in :func:`protected_groups` → return (ordinary group).
        2. ``policy_allows("users_grant_role", action="users:grant_role",
           resource=self.request.path)`` must allow → else 403.
        3. ``member_id`` is the acting user → 403 (no self-add; removing
           oneself passes ``member_id=None`` and is allowed — a de-escalation).
        4. The acting user must belong to EVERY protected group named; for
           ``superuser`` "belongs" means ``_check_superuser()`` → else 403.

        Args:
            group_names: Group names involved — for a rename, BOTH the stored
                and the new name. ``None`` entries are ignored.
            member_id: The user being ADDED to the group, on a membership
                create only.

        Raises:
            web.HTTPForbidden: any rule refused. Never returns False.
        """
        involved = {str(n) for n in group_names if n}
        protected = involved & protected_groups()
        if not protected:
            return
        names = sorted(protected)
        allowed, reason, _ = await policy_allows(
            _GRANT_ROLE_POLICY, self.request, action=_GRANT_ROLE_ACTION, resource=self.request.path
        )
        if not allowed:
            await self.audit_decision(_GRANT_ROLE_ACTION, False, member_id, f"protected {names}: {reason}")
            self._refuse()
        user_id, is_superuser = await self.acting_user()
        if member_id is not None and str(member_id) == str(user_id):
            await self.audit_decision(_GRANT_ROLE_ACTION, False, member_id, f"self-add to protected {names}")
            self._refuse()
        # FILL IN: rule 4 — read (session, userinfo, user) via self._session_info(); for each name in
        #   `protected`: name == SUPERUSER_GROUP → require is_superuser; otherwise require membership
        #   using the SAME collection-only logic as decorators.py:299-311 (never `in` on a str).
        #   On the first miss: audit_decision(_GRANT_ROLE_ACTION, False, member_id,
        #   f"actor does not belong to protected group '{name}'") then self._refuse().
        await self.audit_decision(_GRANT_ROLE_ACTION, True, member_id, f"protected {names}: {reason}")
```

**Why each rule is ordered this way**: the policy check comes first so an actor
without `users:grant_role` learns nothing about rules 3–4; the self-add check
precedes the belongs check so the audit reason is the precise one. Rule 4 is the
group analogue of TASK-156's "cannot grant a flag you do not hold". Every branch
raises through `_refuse()` (spec §7: refusals raised, not returned).

### `tests/unit/handlers/test_protected_groups.py` — CREATE

```python
"""Protected groups at the guard level (FEAT-107, TASK-152)."""

import pytest
from navigator_auth.handlers import guards
from navigator_auth.handlers.guards import OwnerOrSuperuserGuard, protected_groups

pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")

# FILL IN: Host / FakePDP / _policy / _request / _session / S harness copied from
#   tests/unit/handlers/test_owner_superuser_guard.py:23-167. The PDP must be able to hold a
#   `users_grant_role` Policy with actions ["users:grant_role"] and groups ["security_admin"].


class TestProtectedSet:
    def test_protected_groups_always_include_superuser(self, monkeypatch): ...   # AC18: [] and ["x"] → superuser ∈
    def test_setting_adds_groups(self, monkeypatch): ...                        # ["ops"] → {"ops","superuser"}
    def test_conf_default_parses_to_clean_names(self): ...                      # list of stripped, non-empty str


class TestAuthorizeProtectedGroup:
    async def test_ordinary_group_is_noop(self): ...                            # no policy_allows call (patch it)
    async def test_superuser_without_grant_role_refused(self): ...              # AC17
    async def test_grantor_can_add_member_to_protected_group(self): ...         # superuser + security_admin, member 99
    async def test_no_self_add_to_protected_group(self): ...                    # member_id == acting user → 403
    async def test_self_removal_allowed(self): ...                              # member_id None, actor belongs → ok
    async def test_cannot_add_to_protected_group_not_held(self): ...            # security_admin only, target "superuser" → 403
    async def test_none_names_ignored(self): ...                                # {None, "sales"} → noop
    async def test_every_outcome_audited(self): ...                             # allow and deny both recorded
```

### Steps (in order)

1. Add the `conf.py` setting — because `guards.py` imports it at module load.
2. Apply guards.py blocks 1–3. Re-grep the `sanitize_query` anchor first: after
   TASK-149 it has moved down, but is still unique.
3. Complete rule 4 by mirroring `_check_superuser`'s membership logic — because a
   substring test on a `str` `groups` value is the bug `decorators.py:296-299`
   documents (`"ex_superuser_revoked"` must not count).
4. Write the tests; use `monkeypatch.setattr(guards, "AUTH_PROTECTED_GROUPS", [...])`
   for the set tests — this is why `protected_groups()` reads the module global
   at call time.
5. Run `pytest tests/unit/handlers/test_protected_groups.py tests/unit/handlers/test_owner_superuser_guard.py tests/test_check_superuser.py -v`.

### FILL IN checklist

- [ ] Rule 4 body (belongs-to check, collection-only, `superuser` via `is_superuser`).
- [ ] Test harness and all test bodies.

---

## Acceptance Criteria

- [ ] `pytest tests/unit/handlers/test_protected_groups.py -v` passes.
- [ ] `pytest tests/unit/handlers/ tests/test_check_superuser.py tests/test_allowed.py tests/test_policy_allows.py -v` passes (AC2).
- [ ] `protected_groups()` contains `superuser` for any value of `AUTH_PROTECTED_GROUPS`, including empty (spec AC18).
- [ ] Without `users:grant_role`, any change touching a protected group is refused; with it, self-add and not-held groups are still refused (guard half of spec AC17).
- [ ] Every outcome is audited.

---

## Test Specification

See the CREATE block above.

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at `sdd/specs/auth-model-crud-hardening.spec.md` (§2 Overview point 3, §3 Module 9, §7 R11–R13).
2. **Check dependencies** — TASK-149 is `done` in `sdd/tasks/index/auth-model-crud-hardening.json`.
3. **Re-verify** the anchors in `guards.py` and `conf.py` (FEAT-106 may have touched `conf.py`).
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
**Notes**: AUTH_PROTECTED_GROUPS config + protected-group tests. Merge-tier validation: 45 passed (tasks 151/152/155 together). Review: zero fixes (feedback coder-review:c37effa5c17585c5849cfc60).
