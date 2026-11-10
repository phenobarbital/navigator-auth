# TASK-146: Enforcement pre-flight script — `python -m scripts.preflight_mfa --org-id N`

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-135
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 12**. Switching a tenant to `enforced` must lock
nobody out (spec G3, AC8). The e-mail floor makes that true for every ordinary
user **with an address**; two populations break it, and the pre-flight refuses
activation while either exists (spec AC15):

- **B1** — active members with **no usable e-mail address**: under enforcement
  they would have *no factor at all* (`User.email` is `required=False`,
  `models.py:49`; spec R3).
- **B2** — active `is_superuser` members with **no strong factor** (no confirmed
  TOTP, no registered passkey): a privileged account may not sit on the e-mail
  floor (spec R7), so enforcement would lock out the administrators.

The pre-flight is an *activation check*, not a permanent guarantee — after
activation the login path itself enforces both rules (spec §3 "Superuser
invariant and recovery", D10). Operators run it, then switch the tenant with
`apply_tenant_policy` (TASK-135, D18), as documented by TASK-148.

It cannot detect an address that is merely **wrong**: there is no
`email_verified` state (spec R4) — the report says so.

Reuse, not re-derivation: B1 uses `usable_email()` and B2 uses
`MfaStateMachine.has_strong_factor()` from TASK-135, so the pre-flight and the
login path can never disagree about who has a factor. Membership comes from
`{schema}.organization_users` (D7), the same source the resolver uses.

---

## Scope

- Create `scripts/preflight_mfa.py` runnable as
  `python -m scripts.preflight_mfa --org-id N [--dsn DSN]` (`scripts/` is a PEP 420
  namespace package — **no `__init__.py`**, verified: `python -m
  scripts.sdd.ensure_worktree` works the same way).
- Implement `run_preflight(db_pool, org_id, *, state=None) -> PreflightReport` and
  `main(argv=None) -> int`.
- Exit codes: **0** tenant can be enforced; **1** blocked (B1 and/or B2, offenders
  listed); **2** operational error (DB unreachable, MFA tables missing,
  `organization_users` missing, invalid arguments other than argparse's own).
- Print a human-readable report on stdout listing every offender
  (`user_id`, `username`) per condition, plus the R4 caveat line.
- Write `tests/test_mfa_preflight.py` using fakes/monkeypatch (no live DB required).

**NOT in scope**: changing the policy (that is `apply_tenant_policy`, TASK-135);
an HTTP admin API (spec non-goal); verifying addresses (spec R4/Q18); inactive
users (they cannot log in — excluded and stated in the report).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `scripts/preflight_mfa.py` | CREATE | CLI + `run_preflight` + report models |
| `tests/test_mfa_preflight.py` | CREATE | Exit-code and offender-listing tests with fakes |

---

## Codebase Contract

> Re-verified on `dev` @ `b10a3a3` (2026-11-11).

### Verified Imports

```python
import argparse, asyncio, logging, sys                          # stdlib
from typing import Any, Optional, Sequence                      # stdlib
from asyncdb import AsyncPool                                   # verified in use: navigator_auth/storages/abstract.py:48
from pydantic import BaseModel, ConfigDict                      # pydantic>=2.12.5 (pyproject.toml:56)
from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE, default_dsn
#   AUTH_DB_SCHEMA conf.py:33, AUTH_USERS_TABLE conf.py:34, default_dsn conf.py:45
from navigator_auth.mfa.exceptions import MfaStorageError       # TASK-129
from navigator_auth.mfa.migrations import mfa_tables_present    # TASK-130 (contract §3)
from navigator_auth.mfa.state import MfaStateMachine, usable_email   # TASK-135
```

### asyncdb pool lifecycle (verified)

```python
pool = AsyncPool("pg", dsn=default_dsn, timeout=10)    # pattern: storages/abstract.py:48-55
await pool.connect()                                   # :55
async with await pool.acquire() as conn: ...           # passkey/store.py:43
await pool.wait_close(gracefully=True, timeout=2)      # storages/postgres.py:36 (asyncdb pg.py:485)
```

`fetch_all` returns **None** (not `[]`) when there are no rows (asyncdb
`pg.py:1000-1016`). `conn.execute()` swallows errors (`pg.py:937-972`) — not
used here (read-only script).

### Upstream signatures used

```python
# TASK-130
async def mfa_tables_present(db_pool: Any) -> bool        # raises on storage error
# TASK-135
def usable_email(user: Any) -> Optional[str]
class MfaStateMachine:
    def __init__(self, db_pool: Any, backup_codes: Optional[BackupCodeStore] = None)
    async def has_strong_factor(self, user: Any, *, conn: Any = None) -> bool
```

### Live schema facts (verified 2026-11-11)

- `auth.organization_users(user_id bigint, org_id bigint, properties jsonb, created_at, updated_at, created_by)`.
- `auth.users` NOT NULL columns: `user_id bigint` (serial), `userid uuid`
  (default), `username varchar`, `user_role int` (default 1), `is_superuser`
  (default false), `is_active` (default true), `is_new` (default true). `email`
  is nullable.

### Does NOT Exist (Anti-Hallucination)

- ~~`scripts/__init__.py`~~ — do not create it; the namespace import works without it.
- ~~`User.email_verified`~~ — no verification state (spec §6, R4).
- ~~a pre-authentication tenant resolver~~ / ~~`_resolve_tenant()` for membership~~ — D7/R14.
- ~~`print`-free CLI requirement~~ — the report IS the product: write it to
  `sys.stdout` through one `_emit()` helper; diagnostics go to `logging`.

---

## Implementation Blueprint

### `scripts/preflight_mfa.py` — CREATE (two blocks)

**Block 1 — models, queries, `run_preflight`:**

```python
"""MFA enforcement pre-flight for one tenant (FEAT-106, spec §3 Module 12).

    python -m scripts.preflight_mfa --org-id N [--dsn DSN]

Exit 0 only when the tenant can be switched to ``enforced`` without locking
anyone out. Exit 1, listing offenders, on either blocking condition:

  B1  active members with no usable e-mail address (they would have NO factor)
  B2  active superusers with no strong factor (no confirmed TOTP, no passkey)

Exit 2 on an operational error. It cannot detect an address that is merely
WRONG: there is no e-mail verification state (spec R4).
"""
import argparse
import asyncio
import logging
import sys
from typing import Any, Optional, Sequence

from asyncdb import AsyncPool
from pydantic import BaseModel, ConfigDict

from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE, default_dsn
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.migrations import mfa_tables_present
from navigator_auth.mfa.state import MfaStateMachine, usable_email

logger = logging.getLogger("navigator.mfa.preflight")

EXIT_OK, EXIT_BLOCKED, EXIT_ERROR = 0, 1, 2

_MEMBERSHIP = f"{AUTH_DB_SCHEMA}.organization_users"
_USERS = f"{AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE}"
_MEMBERS_SQL = (
    f"SELECT u.user_id, u.username, u.email, u.is_superuser, u.is_active "
    f"FROM {_MEMBERSHIP} ou JOIN {_USERS} u ON u.user_id = ou.user_id "
    "WHERE ou.org_id = $1 AND u.is_active ORDER BY u.user_id"
)


class PreflightError(Exception):
    """Operational failure: the pre-flight could not decide (exit 2)."""


class Offender(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    user_id: int
    username: str


class PreflightReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    org_id: int
    members: int
    missing_email: tuple[Offender, ...]                    # B1
    superusers_without_strong_factor: tuple[Offender, ...]  # B2

    @property
    def ok(self) -> bool:
        """True only when neither blocking condition has an offender."""
        return not self.missing_email and not self.superusers_without_strong_factor


async def run_preflight(
    db_pool: Any, org_id: int, *, state: Optional[MfaStateMachine] = None
) -> PreflightReport:
    """Evaluate B1/B2 for every ACTIVE member of ``org_id``.

    Args:
        db_pool: connected asyncdb pool.
        org_id: tenant to check (> 0).
        state: injectable state machine (tests); defaults to MfaStateMachine(db_pool).

    Raises:
        PreflightError: MFA tables missing, organization_users missing, or a storage error.
    """
    # FILL IN — bounded by spec M12, AC15, D7, R3:
    #  1. org_id <= 0 -> PreflightError.
    #  2. if not await mfa_tables_present(db_pool): PreflightError("MFA tables missing — start the
    #     service once with AUTH_BASIC_2FA_ENABLED=true"). Wrap storage exceptions (incl.
    #     MfaStorageError) in PreflightError.
    #  3. in one acquired conn: to_regclass(_MEMBERSHIP) is None -> PreflightError(
    #     "organization_users not found"); rows = await conn.fetch_all(_MEMBERS_SQL, org_id) or [].
    #  4. state = state or MfaStateMachine(db_pool). For each row (dict(row)):
    #       B1: usable_email(row) is None -> missing_email
    #       B2: row["is_superuser"] and not await state.has_strong_factor(row) -> superusers_…
    #     A superuser lacking BOTH lands in both lists.
    #  5. return PreflightReport(org_id, members=len(rows), tuples sorted by user_id).
```

**Why active members only.** `open_session()` already refuses a disabled user
(`basic.py:202-204`, FAILED 403), so an inactive account cannot be locked out by
enforcement; counting it would block activation for no one. If it is
re-activated later without an address, the login path fails closed
(`no_factor_available`, D10) — spec R3's "fails closed for users created
afterwards" covers it.

**Why `has_strong_factor` and not a local query.** B2 must use the same
predicate the login path uses (TOTP confirmed **or** ≥1 passkey, D10), or an
administrator whose only strong factor is a passkey would be reported as an
offender — or worse, the reverse.

**Block 2 — rendering and the CLI:**

```python
def _emit(line: str = "") -> None:
    """The report is the CLI's product: write it to stdout."""
    sys.stdout.write(f"{line}\n")


def render_report(report: PreflightReport) -> None:
    """Human-readable report; offenders listed per blocking condition."""
    # FILL IN — bounded by AC15 ("lists them"):
    #   header "MFA pre-flight for org_id=N: M active member(s)";
    #   "B1 — no usable e-mail address (no factor under enforcement): K" + one line per offender
    #   "  - user_id=<id> username=<name>"; same for "B2 — superuser without a strong factor
    #   (enrol TOTP or register a passkey first): K"; then either
    #   "RESULT: OK — tenant can be enforced" or "RESULT: BLOCKED";
    #   always the caveat "Note: addresses are not verified; a wrong address cannot be detected (R4)."
    #   Never print e-mail addresses or any secret.


def _parse(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.preflight_mfa",
        description="Refuse MFA enforcement for a tenant that would lock users out.",
    )
    parser.add_argument("--org-id", type=int, required=True, help="Tenant (organization) id")
    parser.add_argument("--dsn", default=None, help="Postgres DSN (default: navigator_auth.conf.default_dsn)")
    return parser.parse_args(argv)


async def _amain(args: argparse.Namespace) -> int:
    pool = AsyncPool("pg", dsn=args.dsn or default_dsn, timeout=10)
    try:
        await pool.connect()
        report = await run_preflight(pool, args.org_id)
    except PreflightError as err:
        logger.error("MFA pre-flight could not run: %s", err)
        _emit(f"ERROR: {err}")
        return EXIT_ERROR
    except Exception as err:  # pylint: disable=W0703
        logger.error("MFA pre-flight failed: %s", type(err).__name__)
        _emit(f"ERROR: {type(err).__name__}")
        return EXIT_ERROR
    finally:
        # FILL IN: close the pool if it connected (pool.wait_close(gracefully=True, timeout=2)),
        #          swallowing close errors with a logger.warning — bounded by "never mask the exit code".
        ...
    render_report(report)
    return EXIT_OK if report.ok else EXIT_BLOCKED


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point. Returns the process exit code (0 ok, 1 blocked, 2 error)."""
    return asyncio.run(_amain(_parse(argv)))


if __name__ == "__main__":
    sys.exit(main())
```

**Why three exit codes.** Spec M12 only requires "0 only when the tenant can be
enforced"; distinguishing *blocked* (1, actionable: fix the offenders) from
*could not decide* (2, actionable: fix the environment) lets an operator's
automation refuse activation in both cases while telling them which problem
they have. Both are non-zero, so the spec contract holds.

### `tests/test_mfa_preflight.py` — CREATE

```python
"""Pre-flight — FEAT-106 spec §3 Module 12 (TASK-146). No live DB: fakes only."""
import pytest

import scripts.preflight_mfa as preflight
from scripts.preflight_mfa import (
    EXIT_BLOCKED, EXIT_ERROR, EXIT_OK, PreflightError, PreflightReport, run_preflight,
)


class _Conn:
    def __init__(self, rows, membership_table="auth.organization_users"):
        self.rows, self.membership_table = rows, membership_table

    async def fetchval(self, sql, *args):
        assert "to_regclass" in sql
        return self.membership_table

    async def fetch_all(self, sql, *args):
        return self.rows or None   # asyncdb returns None on no rows


class _Pool:
    def __init__(self, conn): self.conn = conn
    async def acquire(self): return self
    async def __aenter__(self): return self.conn
    async def __aexit__(self, *exc): return False


class _State:
    """Stands in for MfaStateMachine: strong users by id."""
    def __init__(self, strong_ids=()): self.strong_ids = set(strong_ids)
    async def has_strong_factor(self, user, *, conn=None):
        return int(user["user_id"]) in self.strong_ids


def _row(uid, email="u@example.com", su=False):
    return {"user_id": uid, "username": f"user{uid}", "email": email, "is_superuser": su, "is_active": True}


@pytest.fixture(autouse=True)
def _tables_present(monkeypatch):
    async def _present(_pool): return True
    monkeypatch.setattr(preflight, "mfa_tables_present", _present)


@pytest.mark.asyncio
async def test_preflight_blocks_users_without_email():
    """B1: a member with no address is listed; report.ok is False."""
    # FILL IN: rows [_row(1), _row(2, email=None), _row(3, email="  ")] -> missing_email ids [2, 3]


@pytest.mark.asyncio
async def test_preflight_blocks_superuser_without_strong_factor():
    """B2: a superuser without TOTP/passkey is listed; one with a passkey is not."""
    # FILL IN: _State(strong_ids={11}); rows [_row(10, su=True), _row(11, su=True)] -> B2 ids [10]


@pytest.mark.asyncio
async def test_preflight_passes_clean_tenant():
    # FILL IN: all members have addresses, superusers strong -> report.ok


@pytest.mark.asyncio
async def test_preflight_missing_membership_table_is_error():
    # FILL IN: _Conn(rows, membership_table=None) -> PreflightError


@pytest.mark.asyncio
async def test_preflight_missing_mfa_tables_is_error(monkeypatch):
    # FILL IN: monkeypatch mfa_tables_present -> False -> PreflightError


def test_main_exit_codes(monkeypatch, capsys):
    """main() returns 1 and lists offenders (user_id + username) on stdout; 0 when clean;
    2 when run_preflight raises PreflightError. Patch preflight.AsyncPool with a stub whose
    connect()/wait_close() are no-ops and preflight.run_preflight with canned reports."""
    # FILL IN — assert no e-mail address appears in captured stdout.


def test_report_mentions_unverified_addresses(capsys):
    # FILL IN: render_report(clean report) prints the R4 caveat line.
```

### Steps (in order)

1. Confirm TASK-135 (`usable_email`, `MfaStateMachine.has_strong_factor`) and
   TASK-130 (`mfa_tables_present`) are done.
2. Create Block 1; fill `run_preflight`.
3. Add Block 2; fill `render_report` and the pool close in `_amain`.
4. Write and fill the tests.
5. Smoke-run against the live DB with an org that has no members:
   `python -m scripts.preflight_mfa --org-id 999999` → exit 0, "0 active member(s)".
6. Run **Test Specification**.

### FILL IN checklist

- [ ] `run_preflight` — B1/B2, active members only, error mapping — AC15, D7, R3
- [ ] `render_report` — offenders listed, R4 caveat, no addresses printed — AC15, R4
- [ ] pool close in `_amain` finally — never masks the exit code
- [ ] 7 test bodies

---

## Acceptance Criteria

- [ ] **AC-1** `python -m scripts.preflight_mfa --org-id N` runs without a `scripts/__init__.py`.
- [ ] **AC-2** Exit 1 and every offender listed (`user_id`, `username`) when an active member lacks a usable address (B1) **or** an active superuser lacks a strong factor (B2) (spec AC15).
- [ ] **AC-3** Exit 0 only when both lists are empty; exit 2 when the MFA tables or `organization_users` are missing or the DB fails.
- [ ] **AC-4** B1 uses `usable_email()` and B2 uses `MfaStateMachine.has_strong_factor()` (same predicates as the login path); membership comes from `organization_users` (D7).
- [ ] **AC-5** The report prints the R4 caveat and never prints an e-mail address or secret.
- [ ] **AC-6** `ruff check scripts/preflight_mfa.py tests/test_mfa_preflight.py` is clean.
- [ ] Closes spec **AC15**; supports **AC8** (preflight-eligible activation locks nobody out).

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_preflight.py -v
ruff check scripts/preflight_mfa.py tests/test_mfa_preflight.py
python -m scripts.preflight_mfa --help
```

Spec §4 rows owned here: `test_preflight_blocks_users_without_email`,
`test_preflight_blocks_superuser_without_strong_factor`.

---

## Agent Instructions

1. **Read the spec** — §3 Module 12, §3 "Superuser invariant and recovery",
   §7 R3/R4/R7, AC8, AC15; contract D7, D10, D18.
2. **Check dependencies** — TASK-135 in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint.
5. **Verify** every acceptance criterion.
6. **Move this file** to `sdd/tasks/completed/TASK-146-mfa-preflight-script.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**:
**Date**:
**Notes**:

**Deviations from spec**: none | describe if any
