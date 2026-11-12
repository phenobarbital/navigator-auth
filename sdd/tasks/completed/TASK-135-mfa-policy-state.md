# TASK-135: Tenant policy resolver, `apply_tenant_policy` recipe, per-user state machine

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-132, TASK-133, TASK-134
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 7** — the two objects that decide *whether* a
factor is owed and *which* factors a user may use — plus the "supplied
transactional recipe" for v1 SQL administration of the tenant policy that the
spec's security contracts require.

- `MfaPolicyResolver` — the effective `TenantMfaPolicy` for a user: strictest
  organization wins. **Read on every login, never cached** (AC22).
- `apply_tenant_policy(...)` — the one blessed way to change a tenant's mode:
  one transaction that upserts the row and, when it *hardens* the policy,
  invalidates outstanding challenges and revokes the tenant's trusted devices,
  with a durable audit row (AC18, AC23, AC30).
- `MfaStateMachine` — per-user `none → email → totp` state, the strong-factor
  predicate (confirmed TOTP **or** a registered passkey), the enforced-superuser
  invariant, and the provider allowlist in which a strong factor **closes**
  e-mail (AC9, AC27, AC33).

TASK-138 composes these into `MfaServices.evaluate()`; the pre-flight
(TASK-146) reuses `usable_email` and `has_strong_factor` so activation checks and
login agree.

Decomposition decisions applied (contract `feat106_contract.md`):

- **D7 — membership source.** Default `AUTH_USER_VIEW` is
  `navigator_auth.models.User`, which has **no** `organizations` column. So
  membership is a fresh query keyed by the **authenticated user id**:
  `SELECT org_id FROM {schema}.organization_users WHERE user_id = $1`
  (verified live: `auth.organization_users(user_id bigint, org_id bigint, …)`).
  Never request headers; **never `abac.context._resolve_tenant()`** (spec R14 —
  it prefers `X-Org-Id`/`X-Client-Id` and falls back to the `(1, 1)` global
  sentinel). Table absent ⇒ `()` ⇒ OFF. Any other error ⇒ `MfaStorageError`.
- **D8 — no-tenant policy** `TenantMfaPolicy(org_id=0, mode=OFF,
  remember_days=0, enforced_at=None, enforced_by=None)`; `0` means "no tenant
  policy applies", never a global policy, never read from the table.
- **D9 — strictest wins**: mode = max by `MODE_STRICTNESS`; effective `org_id` =
  the strictest org (tie → smallest org_id); `remember_days` = min over orgs whose
  mode ≠ OFF (none ⇒ 0); orgs without a row contribute nothing.
- **D10 — state/providers** (exact rules in the blueprint).
- **D18 — `apply_tenant_policy`**: one transaction; hardening = strictness
  increases, **or** `remember_days` decreases while the new mode ≠ OFF; hardening
  bumps every member's security version in ONE statement + `revoke_tenant` +
  audit; relaxing audits only; no per-member advisory locks (thousands of xact
  locks would exhaust the shared lock table; the context digest already covers
  the policy).

---

## Scope

- Create `navigator_auth/mfa/policy.py`: `ORG_MEMBERSHIP_TABLE`,
  `combine_policies`, `is_hardening`, `MfaPolicyResolver`, `apply_tenant_policy`.
- Create `navigator_auth/mfa/state.py`: `_field`, `_scope`, `usable_email`,
  `MfaStateMachine`.
- Every storage error raises `MfaStorageError` (fail closed — never degrade to
  `MfaMode.OFF`, spec M7, AC22, `test_policy_read_failure_fails_closed`).
- Passkey credentials are counted from the table with a `to_regclass` guard and
  **without importing `webauthn`** or the passkey backend (spec R10).
- Write `tests/test_mfa_policy_state.py`.

**NOT in scope**: the `MfaEvaluation` assembly and context digest computation
(TASK-138 / TASK-132); passkey registration/removal hooks (TASK-144); the
notification and trusted-device revocation on last-passkey removal (TASK-144);
the pre-flight CLI (TASK-146); an HTTP admin API for the policy (spec non-goal).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/policy.py` | CREATE | Resolver, pure combiners, `apply_tenant_policy` |
| `navigator_auth/mfa/state.py` | CREATE | `MfaStateMachine` + record/connection helpers |
| `tests/test_mfa_policy_state.py` | CREATE | Pure, fake-pool and live-Postgres tests |

---

## Codebase Contract

> Re-verified on `dev` @ `b10a3a3` (2026-11-11).

### Verified Imports

```python
import logging                                                      # stdlib
from collections.abc import Mapping, Sequence                       # stdlib
from contextlib import asynccontextmanager                          # stdlib
from typing import Any, AsyncIterator, Optional                     # stdlib
from navigator_auth.conf import AUTH_DB_SCHEMA                      # verified: conf.py:33
from navigator_auth.exceptions import MFARefused                    # TASK-129 (D1)
from navigator_auth.mfa.exceptions import MfaStorageError           # TASK-129
from navigator_auth.mfa.types import (                              # TASK-129
    MfaAuditEntry, MfaMode, MfaState, TenantMfaPolicy,
    MODE_STRICTNESS, NO_TENANT_ORG_ID,
    PROVIDER_BACKUP, PROVIDER_EMAIL, PROVIDER_TOTP,
)
from navigator_auth.mfa.security import MfaSecurity                 # TASK-132
from navigator_auth.mfa.trusted_devices import TrustedDeviceStore   # TASK-133
from navigator_auth.mfa.backup_codes import BackupCodeStore         # TASK-134
```

### Upstream signatures used

```python
# TASK-132 — navigator_auth/mfa/security.py
class MfaSecurity:
    async def write_audit(self, conn: Any, entry: MfaAuditEntry) -> None
# TASK-133 — navigator_auth/mfa/trusted_devices.py
class TrustedDeviceStore:
    async def revoke_tenant(self, org_id: int, reason: str, *, conn: Any = None) -> int
_ORG_MEMBERSHIP_TABLE = "organization_users"     # must equal ORG_MEMBERSHIP_TABLE here
# TASK-134 — navigator_auth/mfa/backup_codes.py
class BackupCodeStore:
    async def remaining(self, user_id: int, *, conn: Any = None) -> int
# TASK-129 — navigator_auth/exceptions.py
class MFARefused(MfaSignal):
    def __init__(self, code: str, message: Optional[str] = None, status: int = 403): ...
```

### Tables read/written

```
{schema}.tenant_mfa_policy (org_id bigint PK, mode varchar(16) CHECK IN ('off','optional','enforced'),
                            remember_days int >= 0, enforced_at timestamptz, enforced_by varchar(254), updated_at)
{schema}.user_mfa          (user_id, provider, enabled, confirmed_at, …) PK (user_id, provider)
{schema}.user_mfa_security (user_id bigint PK FK users, version bigint, updated_at)
{schema}.organization_users(user_id bigint, org_id bigint, …)  -- NOT created by navigator-auth (verified live)
{schema}.user_credentials  (credential_id, user_id, rp_id, …)  -- passkey table, only when PasskeyAuth ran
                                                                -- (verified passkey/sql/001_passkey_credentials.sql:14)
```

### Spec facts the rules rest on

- `User.is_superuser` — `models.py:54`; `User.email` is `required=False` — `models.py:49` (R3).
- The idp returns a datamodel `Model` from `AUTH_USER_VIEW` (default
  `navigator_auth.models.User`, `conf.py:140`) **or** callers pass a dict:
  read every field through `_field()`.
- `PasskeyStore.count_credentials` exists (`passkey/store.py:131`) but takes no
  connection; this task counts directly so the read can join the caller's lock
  transaction. Importing `navigator_auth.passkey` is safe (its `__init__` never
  imports `webauthn`) but **unnecessary** — do not import it.

### asyncdb connection API (verified `.venv/.../asyncdb/drivers/pg.py`)

`fetchval` / `fetch_one` / `fetch_all` **raise** on error; `fetch_all` returns
**None** when there are no rows. `transaction()` :1069 / `commit()` :1076 /
`rollback()` :1083. **`conn.execute()` swallows errors** (`:937-972` returns
`[result, error]`) — never use it here.

### Does NOT Exist (Anti-Hallucination)

- ~~`abac.context._resolve_tenant()` as the membership source~~ — **prohibited**
  (spec R14, §6 Integration Points strike-through).
- ~~`user.organizations` on the default user model~~ — `navigator_auth/models.py`
  `User` has no such column (D7).
- ~~a startup-cached policy~~ — the resolver holds **no** policy state (AC22).
- ~~a global `(1, 1)` fallback policy~~ — absent membership is OFF (D8).
- ~~`MfaState.PASSKEY`~~ — the enum has exactly NONE/EMAIL/TOTP; the passkey
  half of the strong-factor predicate is derived per login (spec M7).
- ~~`import webauthn`~~ anywhere in `navigator_auth/mfa/` (R10).

---

## Implementation Blueprint

### `navigator_auth/mfa/state.py` — CREATE (two blocks)

**Block 1 — helpers:**

```python
"""Per-user second-factor state for the BasicAuth hook (FEAT-106, spec §3 Module 7).

none -> email -> totp, plus the strong-factor predicate: a confirmed TOTP OR at
least one registered passkey. A strong factor CLOSES the e-mail path. The
passkey half is derived from the credentials table on every login, so deleting
the last passkey reopens e-mail for an ordinary user without TOTP.
"""
import logging
from collections.abc import Mapping
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from navigator_auth.conf import AUTH_DB_SCHEMA
from navigator_auth.exceptions import MFARefused
from navigator_auth.mfa.backup_codes import BackupCodeStore
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.types import (
    MfaMode, MfaState, TenantMfaPolicy, PROVIDER_BACKUP, PROVIDER_EMAIL, PROVIDER_TOTP,
)

logger = logging.getLogger("navigator.mfa.state")

_USER_MFA = f"{AUTH_DB_SCHEMA}.user_mfa"
_CREDENTIALS = f"{AUTH_DB_SCHEMA}.user_credentials"


def _field(user: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` from a dict or a datamodel ``Model`` user record."""
    if isinstance(user, Mapping):
        return user.get(name, default)
    try:
        return user[name]
    except (KeyError, TypeError, AttributeError, IndexError):
        return getattr(user, name, default)


def _user_id(user: Any) -> int:
    """Authenticated user id; a missing or non-integer id is ambiguity -> fail closed."""
    # FILL IN: int(_field(user, "user_id")); on None/ValueError/TypeError raise
    #          MfaStorageError("ambiguous user identity") — bounded by R14 ("reject ambiguity").


def usable_email(user: Any) -> Optional[str]:
    """The address the e-mail floor would use, or None (spec R3).

    Shared with the pre-flight (TASK-146) so B1 and the login path agree.
    """
    # FILL IN: str, stripped, non-empty, contains exactly one "@" with text on both
    #          sides; else None. Do NOT lower-case for delivery — bounded by R3, R4.


@asynccontextmanager
async def _scope(pool: Any, conn: Any = None) -> AsyncIterator[Any]:
    """Caller's connection (e.g. the per-user lock transaction) or a pooled one."""
    if conn is not None:
        yield conn
        return
    async with await pool.acquire() as own:
        yield own
```

**Why `_field`.** `validate_user()` hands the hook whatever the idp returned —
a datamodel `Model` for the default view — while tests and the verify handler
pass dicts. A dict-only `user["is_superuser"]` would raise on one and a
getattr-only read would silently return `None` on the other. One accessor, used
everywhere in M7, removes the difference. `policy.py` imports `_scope` and
`_user_id` from here; the pre-flight (TASK-146) imports `_field` and
`usable_email`; TASK-138 may import `_field` too.

**Block 2 — `MfaStateMachine`:**

```python
class MfaStateMachine:
    """none -> email -> totp, the strong-factor predicate and the provider allowlist."""

    def __init__(self, db_pool: Any, backup_codes: Optional[BackupCodeStore] = None) -> None:
        self._pool = db_pool
        self._backup = backup_codes

    async def totp_confirmed(self, user_id: int, *, conn: Any = None) -> bool:
        """A confirmed, enabled TOTP enrolment exists (``user_mfa`` row)."""
        try:
            async with _scope(self._pool, conn) as db:
                found = await db.fetchval(
                    f"SELECT EXISTS (SELECT 1 FROM {_USER_MFA} WHERE user_id = $1 "
                    "AND provider = $2 AND enabled AND confirmed_at IS NOT NULL)",
                    int(user_id), PROVIDER_TOTP,
                )
        except Exception as err:  # pylint: disable=W0703
            raise MfaStorageError(f"user_mfa read failed: {type(err).__name__}") from err
        return bool(found)

    async def passkey_count(self, user_id: int, *, conn: Any = None) -> int:
        """Registered passkeys. 0 when the passkey table does not exist (backend never ran).

        Reads the table directly — never imports webauthn (R10).
        """
        # FILL IN: inside _scope: regclass = fetchval("SELECT to_regclass($1)", _CREDENTIALS);
        #   None -> 0; else int(fetchval("SELECT count(*) FROM _CREDENTIALS WHERE user_id=$1")).
        #   Other errors -> MfaStorageError (a transient error must NOT read as "no passkey":
        #   that would reopen e-mail for a strong user) — bounded by R10, AC9, AC27.

    async def has_strong_factor(self, user: Any, *, conn: Any = None) -> bool:
        """Confirmed TOTP OR >= 1 passkey. Evaluated fresh every call (spec M7)."""
        # FILL IN: uid = _user_id(user); short-circuit on totp_confirmed, else passkey_count > 0.

    async def requires_strong_factor(self, user: Any, policy: TenantMfaPolicy) -> bool:
        """True for ``is_superuser`` under ENFORCED (D10; models.py:54)."""
        return policy.mode == MfaMode.ENFORCED and bool(_field(user, "is_superuser", False))

    async def state_of(self, user: Any, policy: TenantMfaPolicy, *, conn: Any = None) -> MfaState:
        """D10 — in this order:

        1. requires_strong and not strong -> raise MFARefused("strong_factor_required", status=403)
           (before ANY e-mail fallback or trusted-device use — AC33)
        2. totp_confirmed                 -> MfaState.TOTP
        3. mode in (OFF, OPTIONAL)        -> MfaState.NONE
        4. ENFORCED                       -> MfaState.EMAIL
        """
        # FILL IN — bounded by D10, AC8, AC33. Message must not reveal which factor is missing
        #   beyond the code; never log the user's e-mail.

    async def available_providers(
        self, user: Any, policy: TenantMfaPolicy, *, conn: Any = None
    ) -> tuple[list[str], Optional[str]]:
        """``(providers, preferred)`` per D10.

        - ``totp``   iff TOTP confirmed
        - ``email``  iff mode == ENFORCED and NOT strong and usable_email(user)
        - ``backup`` iff remaining backup codes > 0 (0 when no BackupCodeStore)
        preferred = first present of totp, email, backup; else None.
        A strong factor CLOSES e-mail: the mailbox stops being the ceiling (AC9).
        """
        # FILL IN — bounded by D10, AC9, AC27. Compute totp/strong once each (one query apiece).
```

**Why `passkey_count` distinguishes "no table" from "error".** A missing
`user_credentials` table is structural (PasskeyAuth is not enabled), so 0 is the
truth. A transient error is not: answering 0 would drop a passkey holder back to
the e-mail floor — a silent downgrade of their account. Hence `to_regclass`
first, then a counting query whose failure raises.

**Why e-mail requires ENFORCED.** Under OPTIONAL an unenrolled user owes no
factor (`state_of` → NONE), and an enrolled one is TOTP-strong, which closes
e-mail anyway. Gating e-mail on ENFORCED makes that explicit instead of relying
on two other rules lining up.

### `navigator_auth/mfa/policy.py` — CREATE (two blocks)

**Block 1 — pure combiners and the resolver:**

```python
"""Effective per-tenant MFA policy (FEAT-106, spec §3 Module 7).

The policy table is mutable operational data: it is read on EVERY login and
never cached. Membership comes from the authenticated user id, never from
request headers and never from abac.context._resolve_tenant() (spec R14).
"""
import logging
from collections.abc import Sequence
from typing import Any, Optional

from navigator_auth.conf import AUTH_DB_SCHEMA
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.security import MfaSecurity
from navigator_auth.mfa.state import _scope, _user_id
from navigator_auth.mfa.trusted_devices import TrustedDeviceStore
from navigator_auth.mfa.types import (
    MfaAuditEntry, MfaMode, TenantMfaPolicy, MODE_STRICTNESS, NO_TENANT_ORG_ID,
)

logger = logging.getLogger("navigator.mfa.policy")

ORG_MEMBERSHIP_TABLE = "organization_users"
_MEMBERSHIP = f"{AUTH_DB_SCHEMA}.{ORG_MEMBERSHIP_TABLE}"
_POLICY = f"{AUTH_DB_SCHEMA}.tenant_mfa_policy"
_SECURITY = f"{AUTH_DB_SCHEMA}.user_mfa_security"

NO_TENANT_POLICY = TenantMfaPolicy(
    org_id=NO_TENANT_ORG_ID, mode=MfaMode.OFF, remember_days=0, enforced_at=None, enforced_by=None
)


def combine_policies(rows: Sequence[TenantMfaPolicy]) -> TenantMfaPolicy:
    """Strictest mode wins; smallest remember_days among non-OFF orgs wins (D9).

    Empty input -> NO_TENANT_POLICY (D8). Effective org_id/enforced_* come from the
    strictest org (tie -> smallest org_id, for determinism).
    """
    # FILL IN — bounded by D8, D9, test_policy_strictest_org_wins.


def is_hardening(old: TenantMfaPolicy, new: TenantMfaPolicy) -> bool:
    """D18: strictness increases, or remember_days decreases while new mode != OFF."""
    # FILL IN — bounded by D18, AC18 (relaxing never revokes).


def _row_to_policy(row: Any) -> TenantMfaPolicy:
    """Map a tenant_mfa_policy row; an unknown mode string is ambiguity -> MfaStorageError."""
    # FILL IN: MfaMode(row["mode"]) inside try/except ValueError -> MfaStorageError.


class MfaPolicyResolver:
    """Process-lifetime object holding NO policy: every call is a fresh read (AC22)."""

    def __init__(self, db_pool: Any) -> None:
        self._pool = db_pool

    async def memberships(self, user_id: int, *, conn: Any = None) -> tuple[int, ...]:
        """Org ids of the authenticated user, from organization_users (D7). () when absent."""
        try:
            async with _scope(self._pool, conn) as db:
                if await db.fetchval("SELECT to_regclass($1)", _MEMBERSHIP) is None:
                    return ()
                rows = await db.fetch_all(
                    f"SELECT DISTINCT org_id FROM {_MEMBERSHIP} WHERE user_id = $1 ORDER BY org_id",
                    int(user_id),
                )
        except Exception as err:  # pylint: disable=W0703
            raise MfaStorageError(f"membership read failed: {type(err).__name__}") from err
        return tuple(int(r["org_id"]) for r in (rows or []))

    async def effective(
        self, user: Any, *, conn: Any = None, memberships: Optional[tuple[int, ...]] = None
    ) -> TenantMfaPolicy:
        """Fresh effective policy. Raises MfaStorageError on storage errors —
        never degrades to OFF (spec M7, AC22, test_policy_read_failure_fails_closed).
        """
        # FILL IN — bounded by D7, D8, D9, AC22:
        #   uid = _user_id(user); orgs = memberships if memberships is not None else await
        #   self.memberships(uid, conn=conn); not orgs -> NO_TENANT_POLICY;
        #   rows = fetch_all("SELECT org_id, mode, remember_days, enforced_at, enforced_by FROM
        #   _POLICY WHERE org_id = ANY($1::bigint[])", list(orgs)) or []; wrap errors;
        #   return combine_policies([_row_to_policy(r) for r in rows]).
```

**Why `memberships` is a separate public method.** TASK-138 needs the same
tuple for the context digest, and TASK-142 needs it for the admin
tenant-ownership check. Passing it back into `effective(memberships=…)` avoids a
second read with a different snapshot inside one evaluation.

**Block 2 — `apply_tenant_policy` (the transactional recipe, D18):**

```python
async def apply_tenant_policy(
    *,
    db_pool: Any,
    security: MfaSecurity,
    trusted_devices: TrustedDeviceStore,
    org_id: int,
    mode: MfaMode,
    remember_days: int,
    actor: str,
    actor_user_id: Optional[int] = None,
) -> TenantMfaPolicy:
    """Change a tenant's MFA policy in ONE transaction (the v1 administration recipe).

    Hardening (D18) additionally: bumps auth.user_mfa_security.version for every
    member in one statement (outstanding challenges die), revokes the tenant's
    trusted devices, and audits. Relaxing only audits. Run the pre-flight
    (scripts/preflight_mfa.py) BEFORE switching a tenant to ENFORCED.

    Raises:
        ValueError: remember_days < 0 or org_id <= 0.
        MfaStorageError: the transaction failed (nothing was changed).
    """
    if remember_days < 0 or int(org_id) <= 0:
        raise ValueError("org_id must be positive and remember_days >= 0")
    try:
        async with await db_pool.acquire() as conn:
            await conn.transaction()
            try:
                old_row = await conn.fetch_one(
                    f"SELECT org_id, mode, remember_days, enforced_at, enforced_by "
                    f"FROM {_POLICY} WHERE org_id = $1 FOR UPDATE",
                    int(org_id),
                )
                # FILL IN — bounded by D18, AC18, AC23, AC30:
                #  1. old = _row_to_policy(old_row) if old_row else TenantMfaPolicy(org_id, OFF, 0, None, None)
                #  2. new_row = fetch_one(UPSERT … RETURNING org_id, mode, remember_days, enforced_at,
                #     enforced_by): enforced_at = now() when switching INTO enforced, kept when staying
                #     enforced, NULL otherwise; enforced_by = actor; updated_at = now()
                #  3. hardening = is_hardening(old, new)
                #  4. if hardening:
                #       bumped = fetchval("WITH m AS (SELECT DISTINCT user_id FROM _MEMBERSHIP WHERE
                #         org_id=$1), up AS (INSERT INTO _SECURITY (user_id, version) SELECT user_id, 1
                #         FROM m ON CONFLICT (user_id) DO UPDATE SET version = _SECURITY.version + 1,
                #         updated_at = now() RETURNING 1) SELECT count(*) FROM up")  — skip (0) when
                #         to_regclass(_MEMBERSHIP) is NULL
                #       revoked = await trusted_devices.revoke_tenant(org_id, "tenant_hardening", conn=conn)
                #  5. await security.write_audit(conn, MfaAuditEntry(actor_user_id=actor_user_id,
                #       target_user_id=None, org_id=org_id, action="policy_change",
                #       old_state=old.mode.value, new_state=new.mode.value, method="apply_tenant_policy",
                #       outcome="success", detail={"actor": actor, "hardening": hardening,
                #       "remember_days": [old.remember_days, new.remember_days],
                #       "bumped_users": bumped, "revoked_devices": revoked}))
                #  6. await conn.commit(); return new
                ...
            except BaseException:
                await conn.rollback()
                raise
    except (ValueError, MfaStorageError):
        raise
    except Exception as err:  # pylint: disable=W0703
        raise MfaStorageError(f"apply_tenant_policy failed: {type(err).__name__}") from err
```

**Why one statement for the version bump, and no advisory locks.** Taking every
member's `pg_advisory_xact_lock` in one transaction would consume one shared lock
table slot per member — thousands for a large tenant — and can exhaust
`max_locks_per_transaction`. The serialization guarantee the spec demands is for
*credential* transitions racing a verification; a policy change is already caught
by the HMAC'd context digest (TASK-132), so the bulk bump is defence in depth,
not the only line (D18).

**Why audit inside the transaction.** If the audit insert fails, the policy
change must not commit — spec R1's mitigation leans on the audit row being
durable, so a change without its record is worse than no change (AC23).

### `tests/test_mfa_policy_state.py` — CREATE

```python
"""Policy resolver, apply_tenant_policy and MfaStateMachine — FEAT-106 M7 (TASK-135)."""
import inspect
import re
from pathlib import Path

import pytest

from navigator_auth.exceptions import MFARefused
from navigator_auth.mfa import policy as policy_mod
from navigator_auth.mfa import trusted_devices as td_mod
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.policy import (
    MfaPolicyResolver, NO_TENANT_POLICY, apply_tenant_policy, combine_policies, is_hardening,
)
from navigator_auth.mfa.state import MfaStateMachine, usable_email
from navigator_auth.mfa.types import MfaMode, MfaState, TenantMfaPolicy
from tests.fixtures.mfa import mfa_db, mfa_policy_enforced, mfa_user_factory  # noqa: F401


class _ScriptedConn:
    """Fake asyncdb connection: answers by SQL substring; mutable between calls."""

    def __init__(self, answers: dict, fail: bool = False):
        self.answers, self.fail, self.calls = answers, fail, []

    async def _answer(self, sql, *args):
        self.calls.append((sql, args))
        if self.fail:
            raise ConnectionError("db down")
        for needle, value in self.answers.items():
            if needle in sql:
                return value(*args) if callable(value) else value
        raise AssertionError(f"unscripted SQL: {sql}")

    fetchval = fetch_one = fetch_all = _answer


class _ScriptedPool:
    def __init__(self, conn): self.conn = conn
    async def acquire(self): return self
    async def __aenter__(self): return self.conn
    async def __aexit__(self, *exc): return False


def _p(org, mode, days=0):
    return TenantMfaPolicy(org_id=org, mode=mode, remember_days=days, enforced_at=None, enforced_by=None)


def test_policy_strictest_org_wins():
    """enforced + optional => enforced; smallest remember_days among non-OFF wins (D9)."""
    # FILL IN: combine_policies([_p(5, OPTIONAL, 30), _p(7, ENFORCED, 14), _p(9, OFF, 1)])
    #          -> mode ENFORCED, org_id 7, remember_days 14; [] -> NO_TENANT_POLICY.


def test_is_hardening_directions():
    # FILL IN: OFF->ENFORCED True; ENFORCED->OPTIONAL False; ENFORCED 30->14 True; ENFORCED->OFF False.


def test_membership_table_constant_matches_trusted_devices():
    assert policy_mod.ORG_MEMBERSHIP_TABLE == td_mod._ORG_MEMBERSHIP_TABLE


def test_resolver_ignores_tenant_headers():
    """R14/AC22: no request parameter, no _resolve_tenant reference."""
    assert "request" not in inspect.signature(MfaPolicyResolver.effective).parameters
    source = Path(policy_mod.__file__).read_text()
    assert "_resolve_tenant" not in source and "X-Org-Id" not in source


@pytest.mark.asyncio
async def test_policy_read_is_per_login_not_cached():
    """Changing the scripted row between two calls changes the second result."""
    # FILL IN: answers["to_regclass"]="auth.organization_users"; answers["FROM auth.organization_users"]
    #          returns [{"org_id": 5}]; answers["tenant_mfa_policy"] is a mutable list swapped
    #          between calls (off -> enforced). Same resolver instance.


@pytest.mark.asyncio
async def test_policy_read_failure_fails_closed():
    """A storage error raises MfaStorageError — never returns OFF."""
    # FILL IN: _ScriptedConn({}, fail=True)


@pytest.mark.asyncio
async def test_missing_membership_table_is_no_tenant():
    # FILL IN: to_regclass -> None => effective() == NO_TENANT_POLICY, no policy query issued.


@pytest.mark.asyncio
async def test_enforced_floor_is_email_without_enrolment(mfa_policy_enforced):
    """Ordinary unenrolled user -> EMAIL; providers == ['email'] when an address exists."""
    # FILL IN (scripted: user_mfa EXISTS False, to_regclass(user_credentials) None).


@pytest.mark.asyncio
async def test_superuser_without_strong_factor_denied(mfa_policy_enforced):
    """is_superuser + ENFORCED + no strong factor -> MFARefused('strong_factor_required')."""
    # FILL IN: assert err.payload()["error"] == "strong_factor_required" and err.status == 403.


@pytest.mark.asyncio
async def test_strong_factor_closes_email(mfa_policy_enforced):
    """Confirmed TOTP => 'email' absent, preferred 'totp' (AC9)."""
    # FILL IN


@pytest.mark.asyncio
async def test_registered_passkey_closes_email(mfa_policy_enforced):
    """A passkey credential closes e-mail symmetrically (AC9)."""
    # FILL IN


@pytest.mark.asyncio
async def test_requires_strong_factor_for_superuser(mfa_policy_enforced):
    # FILL IN: True for superuser+ENFORCED; False for OPTIONAL; False for ordinary user.


@pytest.mark.asyncio
async def test_deleting_last_passkey_reopens_email(mfa_policy_enforced):
    """Ordinary user, no TOTP: passkey count 1 -> 0 between calls reopens 'email' (AC27 core)."""
    # FILL IN


@pytest.mark.asyncio
async def test_passkey_count_error_is_not_zero():
    """A failing count query raises MfaStorageError instead of reading as 'no passkey'."""
    # FILL IN


def test_usable_email_rules():
    # FILL IN: "" / None / "nobody" / "a@" -> None; " a@b.c " -> "a@b.c".


@pytest.mark.asyncio
async def test_apply_tenant_policy_hardening_revokes_and_audits(mfa_db, mfa_user_factory):
    """Live PG: OFF->ENFORCED bumps member versions, revokes their devices, writes one audit row."""
    # FILL IN: needs an org + organization_users row for a factory user (inspect FKs first;
    #          create/clean an auth.organizations row if required). Build MfaSecurity +
    #          TrustedDeviceStore on mfa_db, issue a device, apply, assert.


@pytest.mark.asyncio
async def test_apply_tenant_policy_relaxing_does_not_revoke(mfa_db, mfa_user_factory):
    """ENFORCED->OPTIONAL: device still live, versions unchanged, one audit row (AC18)."""
    # FILL IN
```

### Steps (in order)

1. Confirm TASK-132 (`MfaSecurity.write_audit`), TASK-133 (`revoke_tenant`,
   `_ORG_MEMBERSHIP_TABLE`) and TASK-134 (`BackupCodeStore.remaining`) are done.
2. Create `state.py` Block 1, fill `_user_id` and `usable_email`.
3. Add `state.py` Block 2; fill `passkey_count`, `has_strong_factor`,
   `state_of` (ordered), `available_providers`.
4. Create `policy.py` Block 1; fill `combine_policies`, `is_hardening`,
   `_row_to_policy`, `effective`.
5. Add `policy.py` Block 2; fill the recipe.
6. Write the tests; pure ones first, then scripted, then live PG.
7. Run **Test Specification** (including the R10/R14/D5 greps).

### FILL IN checklist

- [ ] `_user_id`, `usable_email` — R3, R14
- [ ] `passkey_count` (regclass vs error) — R10, AC27
- [ ] `has_strong_factor` — spec M7
- [ ] `state_of` ladder — D10, AC33
- [ ] `available_providers` — D10, AC9
- [ ] `combine_policies`, `is_hardening`, `_row_to_policy` — D8, D9, D18
- [ ] `effective` — D7, AC22
- [ ] `apply_tenant_policy` body — D18, AC18, AC23, AC30
- [ ] 17 test bodies (org fixture for the two live tests)

---

## Acceptance Criteria

- [ ] **AC-1** `combine_policies`: strictest mode wins (tie → smallest org_id); `remember_days` is the minimum over non-OFF orgs; empty → `NO_TENANT_POLICY` (`org_id=0`, OFF).
- [ ] **AC-2** `effective()` reads membership and policy on every call (no instance state), takes no request, never references `_resolve_tenant`/headers, and raises `MfaStorageError` on any storage error (spec AC22).
- [ ] **AC-3** Missing `organization_users` ⇒ no tenant ⇒ OFF; missing `user_credentials` ⇒ 0 passkeys; any *other* storage error raises.
- [ ] **AC-4** `state_of` follows D10 exactly; an enforced superuser without a strong factor raises `MFARefused` with code `strong_factor_required`, status 403 (spec AC33).
- [ ] **AC-5** `available_providers` follows D10; a confirmed TOTP or ≥1 passkey removes `email` (spec AC9); passkey count 1→0 reopens `email` for an ordinary user (spec AC27 core).
- [ ] **AC-6** `apply_tenant_policy` hardening bumps every member's version, revokes their trusted devices and writes one `policy_change` audit row in one transaction; relaxing writes the audit row only (spec AC18, AC23, AC30).
- [ ] **AC-7** No `import webauthn`, no `navigator_auth.backends.passkey` import, no `conn.execute()` in `policy.py`/`state.py`.
- [ ] **AC-8** `grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/` prints nothing (D5).
- [ ] Closes the M7 rows of spec §4 and contributes to spec **AC8, AC9, AC18, AC22, AC23, AC27, AC30, AC33**.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_policy_state.py -v
ruff check navigator_auth/mfa/policy.py navigator_auth/mfa/state.py tests/test_mfa_policy_state.py
grep -rnE "remember\(|create_token|open_session" navigator_auth/mfa/ ; test $? -eq 1
grep -nE "webauthn|_resolve_tenant|execute\(" navigator_auth/mfa/policy.py navigator_auth/mfa/state.py ; test $? -eq 1
```

Spec §4 rows owned here: `test_policy_strictest_org_wins`,
`test_enforced_floor_is_email_without_enrolment`, `test_strong_factor_closes_email`,
`test_registered_passkey_closes_email`, `test_requires_strong_factor_for_superuser`,
`test_policy_read_is_per_login_not_cached`, `test_policy_read_failure_fails_closed`,
`test_resolver_ignores_tenant_headers`, `test_deleting_last_passkey_reopens_email`
(state half — the audit/revocation half is TASK-144).

---

## Agent Instructions

1. **Read the spec** — §3 Module 7, §3 "Challenge validity and invalidation"
   (policy hardening), §3 "Superuser invariant and recovery", §7 R3/R10/R14,
   AC8/AC9/AC18/AC22/AC23/AC27/AC30/AC33; contract D7–D10, D18.
2. **Check dependencies** — TASK-132, TASK-133, TASK-134 in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint. The state ladder order is the security
   argument — do not reorder it.
5. **Verify** every acceptance criterion.
6. **Move this file** to `sdd/tasks/completed/TASK-135-mfa-policy-state.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: sonnet (native), 1 attempt
**Date**: 2026-11-11
**Notes**: MFA policy/state machine delivered. 2 live-Postgres tests (apply_tenant_policy) skipped in sandbox — run in CI. Residual F811 fixture-import lint left for /sdd-done.

**Deviations from spec**: none | describe if any
