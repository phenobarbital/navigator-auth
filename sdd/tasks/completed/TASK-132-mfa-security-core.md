# TASK-132: Security version, per-user advisory lock, durable audit writer, context digest

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-129, TASK-130
**Assigned-to**: unassigned

---

## Context

The spec's §3 "Security contracts shared by the modules" require four
primitives that no single module owns. This task builds them, in one new module
`navigator_auth/mfa/security.py`, on top of the tables from TASK-130:

1. **Per-user serialization** — "Serialize verification and MFA security
   transitions for a user using a **transaction-scoped PostgreSQL advisory
   lock**, shared by all workers … No Redis lock lease may expire and allow two
   workers to mint sessions." → `MfaSecurity.user_lock(user_id)`.
2. **Monotonic security version** — "Persist a monotonic version in
   `auth.user_mfa_security` … Reverting a change must not resurrect challenges
   invalidated through the versioned paths." → `current_version`, `bump_version`.
3. **Durable audit** — every factor-state transition leaves an
   `auth.user_mfa_audit` row (spec M8, AC23) — **not** `abac/audit.py`'s
   `AuditLog`, which is best-effort and records authorization decisions (spec R1,
   §9 S10). → `write_audit`.
4. **Context digest** — "HMAC-sign the version and a canonical keyed context
   digest covering the stored password verifier, active/superuser flags, email,
   organization membership, effective policy including remember-days, and
   current factor state. Never put the password verifier itself in Redis or HTTP
   output." → `context_digest`. It also catches account/policy/membership edits
   made through generic CRUD/SQL paths that bypass the version hooks (spec R1).

Consumers: TASK-135 (`apply_tenant_policy`), TASK-138 (`MfaServices.evaluate`
and the hook), TASK-140..142 (verify / enrolment / admin handlers), TASK-144
(`security_transition`). Per **D17**, providers never call this module — the
handler holds the lock and runs provider primitive → `bump_version` →
(revocation) → `write_audit` in **one** transaction.

### asyncdb rules this module must follow (contract D25 — verified by execution)

- **`conn.execute()` NEVER raises.** It returns from inside its `finally` block
  (`.venv/.../asyncdb/drivers/pg.py:937-972`), so every DB error is swallowed and
  returned as data: `await conn.execute("SELECT * FROM auth.nope")` →
  `[None, UndefinedTableError(...)]`. A version bump or audit insert written with
  `execute()` would silently "succeed" when it failed — the opposite of fail-closed.
  **This module uses no `execute()` at all**: the lock, the version reads/writes
  and the audit insert all go through `fetchval` (with `RETURNING` for writes),
  which raises `StatementError` / `ProviderError` (verified).
- Transactions (verified `pg.py:1069-1087`): `await conn.transaction()` starts one
  on the acquired connection; `await conn.commit()` / `await conn.rollback()` end it.
- Pool usage: `async with await pool.acquire() as conn:` (verified
  `passkey/store.py`; `pgPool.acquire()` supports this shape, `pg.py:443-451`).
- Pool connections register a **jsonb codec** that encodes Python objects
  (`pg.py:307-327`) → pass `detail` as a **dict**, never a pre-serialized string
  (a string would be stored as a JSON string scalar).
- Verified live: `await conn.fetchval("SELECT pg_advisory_xact_lock($1, $2)", 0x4D464131, 1)`
  inside a transaction returns `None` and holds the lock until commit/rollback.

### Lock key: the int4 problem

`pg_advisory_xact_lock(int4, int4)` takes two **int4** keys; `auth.users.user_id`
is **bigint** (verified live). Namespace = `LOCK_NAMESPACE = 0x4D464131`
(1 296 449 841 < 2³¹−1 ✓). The user key is the id itself when it fits int4, else
folded `uid % (2**31 - 1)`. Folding can only make two users share a lock
(over-serialization, harmless); it can never let one user's two requests run
unserialized. Cast explicitly: `SELECT pg_advisory_xact_lock($1::int4, $2::int4)`.

### Canonical digest inputs (binding — TASK-138 and TASK-140 compare these)

| Key | Source | Normalization |
|---|---|---|
| `v` | constant | `1` (schema version of the digest) |
| `uid` | `user[AUTH_USERID_ATTRIBUTE]` | `int` |
| `pwd` | `user[AUTH_PASSWORD_ATTRIBUTE]` — the stored **verifier** (pbkdf2 string), never a plaintext | `str` or `""` |
| `active` | `user["is_active"]` | `bool`, missing ⇒ `True` (house default, `models.py:58`) |
| `su` | `user["is_superuser"]` | `bool`, missing ⇒ `False` |
| `email` | `user["email"]` | `strip().lower()`, missing ⇒ `""` |
| `orgs` | `memberships` argument | `sorted(set(int(o) …))` |
| `policy_org` | `policy.org_id` | `int` |
| `mode` | `policy.mode.value` | `str` |
| `remember_days` | `policy.remember_days` | `int` |
| `state` | `state.value` | `str` |
| `strong` | `has_strong_factor` | `bool` |

`digest = HMAC-SHA256(secret, b"navigator-auth/mfa/context/v1|" + canonical_json(fields)).hexdigest()`.
The verifier enters only the HMAC input; the output (hex) is what goes to Redis
inside `MfaChallenge.context_digest`. Domain separation (the prefix) keeps this
HMAC distinct from the challenge-record HMAC that shares `AUTH_OTP_SECRET`.

`canonical_json` is defined in `mfa/store.py` (TASK-131), which this task does
**not** depend on (TASK-131 may land later or in parallel) → `security.py` keeps a
private `_canonical_bytes()` with **identical** parameters
(`json.dumps(sort_keys=True, separators=(",", ":"), default=str)`). Likewise a
private `_user_field()` accessor (contract D26: the shared `_field()` arrives
with TASK-135, later).

---

## Scope

- Create `navigator_auth/mfa/security.py`: `LOCK_NAMESPACE`, `MfaSecurity` with
  `user_lock`, `current_version`, `bump_version`, `write_audit`, `context_digest`.
- Create `tests/test_mfa_security_core.py` (live Postgres via `mfa_db` /
  `mfa_user_factory`, plus pure digest tests).

**NOT in scope**: deciding *when* to bump or audit (TASK-135/138/140-144);
trusted-device revocation (TASK-133); reading policy/state (TASK-135); any Redis.
Do not touch `abac/audit.py`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/security.py` | CREATE | Lock, version, audit, digest |
| `tests/test_mfa_security_core.py` | CREATE | Live-PG lock/version/audit tests + pure digest tests |

---

## Codebase Contract

> Verified on `dev` @ `b10a3a3` (2026-11-11) and against live Postgres + installed asyncdb 2.16.3.

### Verified Imports

```python
import hashlib
import hmac
import json
import logging
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Any
from navigator_auth.conf import (
    AUTH_DB_SCHEMA,                                        # conf.py:33 ("auth")
    AUTH_USERID_ATTRIBUTE, AUTH_PASSWORD_ATTRIBUTE,        # conf.py:320, :322 ("user_id", "password")
)
from navigator_auth.mfa.exceptions import MfaStorageError                    # TASK-129
from navigator_auth.mfa.types import MfaAuditEntry, MfaState, TenantMfaPolicy  # TASK-129
# tests:
import asyncio
import pytest
from datetime import datetime, timezone
from navigator_auth.mfa.types import MfaMode
from tests.fixtures.mfa import mfa_db, mfa_user_factory, mfa_secret  # noqa: F401   (TASK-130)
```

### Tables used (TASK-130 DDL — exact columns)

```sql
{schema}.user_mfa_security (user_id bigint PK REFERENCES users ON DELETE CASCADE,
                            version bigint NOT NULL DEFAULT 0, updated_at timestamptz NOT NULL DEFAULT now())
{schema}.user_mfa_audit    (id bigserial PK, occurred_at timestamptz DEFAULT now(), actor_user_id bigint,
                            target_user_id bigint, org_id bigint, action varchar(64) NOT NULL,
                            old_state varchar(16), new_state varchar(16), method varchar(32),
                            request_id varchar(128), outcome varchar(16) NOT NULL,
                            detail jsonb NOT NULL DEFAULT '{}'::jsonb)          -- no FKs (D18)
```

### asyncdb connection API (verified `.venv/lib/python3.11/site-packages/asyncdb/drivers/pg.py`)

```python
async def fetchval(self, sentence: str, *args, column: int = 0, **kwargs)   # :1052 — RAISES StatementError/ProviderError
async def fetch_one(self, sentence: str, *args, **kwargs)                   # :1036 — RAISES
async def transaction(self)        # :1069 — starts self._connection.transaction(); returns self
async def commit(self)             # :1076
async def rollback(self)           # :1083
async def execute(self, sentence, *args, **kwargs)  # :937 — NEVER raises (returns from finally) — DO NOT USE (D25)
```

### `MfaAuditEntry` (TASK-129) — maps 1:1 to the audit columns

```python
class MfaAuditEntry(MfaModel):
    actor_user_id: Optional[int]; target_user_id: Optional[int]; org_id: Optional[int]
    action: str; old_state: Optional[str] = None; new_state: Optional[str] = None
    method: Optional[str] = None; request_id: Optional[str] = None
    outcome: str; detail: dict = Field(default_factory=dict)
```

### Does NOT Exist (Anti-Hallucination)

- ~~Any advisory-lock helper in the package~~ — `grep -rn pg_advisory navigator_auth` is empty; this is the first.
- ~~`abac.audit.AuditLog` as the MFA audit sink~~ (`abac/audit.py:189`) — explicitly rejected (spec R1, §9 S10).
- ~~A Redis lock (`SET NX PX` lease)~~ — forbidden: "No Redis lock lease may expire and allow two workers to mint sessions."
- ~~`canonical_json` import from `mfa/store.py`~~ — not a dependency of this task; use the private twin.
- ~~`mfa/state.py` `_field()`~~ — lands in TASK-135 (D26); use the private `_user_field()`.

---

## Implementation Blueprint

### `navigator_auth/mfa/security.py` — CREATE (block 1 of 3: header, helpers, lock)

```python
"""MFA security primitives (FEAT-106, spec §3 "Security contracts").

- user_lock(): transaction-scoped PostgreSQL advisory lock per user, shared
  by every worker; the only serialization primitive for verification and
  factor-state transitions (never a Redis lease).
- current_version()/bump_version(): durable monotonic invalidation version.
- write_audit(): durable auth.user_mfa_audit row (not abac AuditLog).
- context_digest(): keyed digest of the security inputs a challenge depends on.

asyncdb rule (D25): conn.execute() never raises, so nothing here uses it —
every statement goes through fetchval (RETURNING for writes), which raises.
"""
import hashlib
import hmac
import json
import logging
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Any

from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_PASSWORD_ATTRIBUTE, AUTH_USERID_ATTRIBUTE
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.types import MfaAuditEntry, MfaState, TenantMfaPolicy

logger = logging.getLogger("navigator.mfa")

LOCK_NAMESPACE = 0x4D464131          # "MFA1"; first int4 key of pg_advisory_xact_lock
_INT4_MAX = 2**31 - 1
_DIGEST_DOMAIN = b"navigator-auth/mfa/context/v1|"


def _canonical_bytes(fields: dict) -> bytes:
    """Identical parameters to mfa/store.py canonical_json (TASK-131)."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _user_field(user: Mapping, name: str, default: Any = None) -> Any:
    """Read ``name`` from a dict or a datamodel Model (idp returns either)."""
    # FILL IN: try user[name]; on (KeyError, TypeError, AttributeError) return
    #  getattr(user, name, default); a None value also yields `default` —
    #  bounded by the digest table's "missing ⇒" column.


def _lock_key(user_id: int) -> int:
    """int4 user key for pg_advisory_xact_lock; folding only over-serializes."""
    # FILL IN: reject bool and negative ids (ValueError); return uid when
    #  uid <= _INT4_MAX else uid % _INT4_MAX — bounded by "Lock key" in Context.


class MfaSecurity:
    """Per-user lock, security version, durable audit and context digest."""

    def __init__(self, db_pool: Any, secret: bytes):
        if not secret:
            raise ValueError("MfaSecurity requires a non-empty secret")
        self._pool = db_pool
        self._secret = secret
        self._schema = AUTH_DB_SCHEMA

    @asynccontextmanager
    async def user_lock(self, user_id: int) -> AsyncIterator[Any]:
        """Yield a connection inside a transaction holding the user's advisory lock.

        Commit on normal exit, roll back on any exception from the body (which
        is re-raised unchanged). Lock/transaction/commit failures raise
        MfaStorageError. The lock is released by the commit/rollback itself.
        """
        key = _lock_key(user_id)
        async with await self._pool.acquire() as conn:
            try:
                await conn.transaction()
                await conn.fetchval(
                    "SELECT pg_advisory_xact_lock($1::int4, $2::int4)", LOCK_NAMESPACE, key
                )
            except Exception as err:
                # FILL IN (replace the placeholder `raise` below): best-effort
                #  `await conn.rollback()` (suppress its own error), then
                #  raise MfaStorageError(f"MFA user lock failed: {type(err).__name__}") from err
                #  — bounded by fail-closed (spec R5); no user data in the message.
                raise
            try:
                yield conn
            except BaseException:
                await conn.rollback()
                raise
            # FILL IN: await conn.commit(); a commit error -> MfaStorageError
            #  (the caller must not report success for an uncommitted transition).
```

**Why** a Postgres advisory lock and not Redis: the spec forbids a lease that
can expire while a worker is still minting a session; an xact lock lives exactly
as long as the transaction, across every worker sharing the database, and is
released automatically by commit, rollback or a dropped connection. **Why** the
body's exception is re-raised unchanged: callers raise `MFARefused` /
`web.HTTPException` from inside the lock — wrapping them would change their
HTTP meaning. **Why** `$1::int4, $2::int4`: asyncpg would otherwise infer
`bigint` for a large Python int and pick the wrong overload.

### `navigator_auth/mfa/security.py` — CREATE (block 2 of 3: version and audit)

```python
    async def current_version(self, conn: Any, user_id: int) -> int:
        """The user's security version, initializing the row at 0 atomically."""
        sql = (
            f"WITH ins AS (INSERT INTO {self._schema}.user_mfa_security (user_id) VALUES ($1) "
            f"ON CONFLICT (user_id) DO NOTHING RETURNING version) "
            f"SELECT version FROM ins UNION ALL "
            f"SELECT version FROM {self._schema}.user_mfa_security WHERE user_id = $1 LIMIT 1"
        )
        # FILL IN: return int(await conn.fetchval(sql, int(user_id))); any
        #  exception -> MfaStorageError(type name only); a None result (cannot
        #  happen when the statement succeeds) -> MfaStorageError too.

    async def bump_version(self, conn: Any, user_id: int) -> int:
        """Increment and return the version. Monotonic: never decremented, never reset."""
        sql = (
            f"INSERT INTO {self._schema}.user_mfa_security (user_id, version) VALUES ($1, 1) "
            f"ON CONFLICT (user_id) DO UPDATE SET "
            f"version = {self._schema}.user_mfa_security.version + 1, updated_at = now() "
            f"RETURNING version"
        )
        # FILL IN: same fetchval / MfaStorageError handling as current_version.

    async def write_audit(self, conn: Any, entry: MfaAuditEntry) -> None:
        """Insert one durable auth.user_mfa_audit row (raises on failure)."""
        sql = (
            f"INSERT INTO {self._schema}.user_mfa_audit (actor_user_id, target_user_id, org_id, "
            f"action, old_state, new_state, method, request_id, outcome, detail) "
            f"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id"
        )
        # FILL IN: fetchval(sql, entry.actor_user_id, entry.target_user_id,
        #  entry.org_id, entry.action, entry.old_state, entry.new_state,
        #  entry.method, entry.request_id, entry.outcome, dict(entry.detail));
        #  a None id or any exception -> MfaStorageError. `detail` stays a dict
        #  (asyncdb jsonb codec). Never put a code, token, seed or verifier in
        #  detail — callers' responsibility, but log nothing from it here.
```

**Why** the CTE in `current_version`: the INSERT and the SELECT share one
snapshot, so the SELECT cannot see a row the INSERT just created — `ins`
returns that one, the SELECT covers the pre-existing case; one statement, no
race, and `fetchval` raises on any failure (D25). **Why** an FK violation is not
special-cased: a version row for a user that does not exist must fail loudly.
**Why** `write_audit` raises instead of logging: it runs inside the transition's
transaction — if the audit row cannot be written, the transition must roll back
with it (spec AC23 makes the audit row part of the transition).

### `navigator_auth/mfa/security.py` — CREATE (block 3 of 3: context digest)

```python
    def context_digest(self, *, user: Mapping, memberships: tuple[int, ...],
                       policy: TenantMfaPolicy, state: MfaState, has_strong_factor: bool) -> str:
        """Keyed digest of every security input a challenge depends on.

        Covers the stored password verifier, active/superuser flags, email,
        organization membership, the effective policy (incl. remember_days) and
        the factor state. The verifier only enters the HMAC; the hex output is
        safe to store in Redis. Pure: no I/O.
        """
        fields = {
            "v": 1,
            "uid": int(_user_field(user, AUTH_USERID_ATTRIBUTE)),
            "pwd": str(_user_field(user, AUTH_PASSWORD_ATTRIBUTE, "") or ""),
            "active": bool(_user_field(user, "is_active", True)),
            "su": bool(_user_field(user, "is_superuser", False)),
            "email": str(_user_field(user, "email", "") or "").strip().lower(),
            "orgs": sorted({int(org) for org in memberships}),
            "policy_org": int(policy.org_id),
            "mode": policy.mode.value,
            "remember_days": int(policy.remember_days),
            "state": state.value,
            "strong": bool(has_strong_factor),
        }
        return hmac.new(self._secret, _DIGEST_DOMAIN + _canonical_bytes(fields), hashlib.sha256).hexdigest()
```

**Why** every field is normalized before hashing: the issuing side (TASK-138,
fresh login) and the verifying side (TASK-140, fresh re-read under the lock) read
the user through possibly different paths (dict vs Model, `None` vs missing); a
normalization difference would make every challenge "stale". **Why** `orgs` is a
sorted set: membership order from SQL is not stable. **Why** `is_active` defaults
to `True`: mirrors `models.py:58` and `user_is_active()` semantics — a record
without the column is an active user, and the digest must not flip on that.

### `tests/test_mfa_security_core.py` — CREATE

```python
"""FEAT-106 TASK-132 — advisory lock, security version, durable audit, digest."""
import asyncio
from datetime import datetime, timezone

import pytest

from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.security import LOCK_NAMESPACE, MfaSecurity, _lock_key
from navigator_auth.mfa.types import MfaAuditEntry, MfaMode, MfaState, TenantMfaPolicy
from tests.fixtures.mfa import mfa_db, mfa_secret, mfa_user_factory  # noqa: F401

POLICY = TenantMfaPolicy(org_id=5, mode=MfaMode.ENFORCED, remember_days=30,
                         enforced_at=datetime(2026, 11, 1, tzinfo=timezone.utc), enforced_by="t")
USER = {"user_id": 42, "password": "pbkdf2_sha256$80000$salt$hash", "is_active": True,
        "is_superuser": False, "email": "A@Example.com"}


def _digest(sec, **over):
    kw = dict(user=USER, memberships=(7, 5), policy=POLICY, state=MfaState.EMAIL, has_strong_factor=False)
    kw.update(over)
    return sec.context_digest(**kw)


def test_context_digest_stable_and_normalized(mfa_secret):
    # FILL IN: same inputs -> same digest; memberships (5, 7) == (7, 5); email case/space
    #  insensitive; a datamodel-like object with the same attributes == the dict; the raw
    #  verifier never appears in the hex digest.


@pytest.mark.parametrize("change", ["password", "is_active", "is_superuser", "email",
                                    "memberships", "policy_mode", "remember_days",
                                    "policy_org", "state", "strong"])
def test_context_digest_changes_per_input(mfa_secret, change):  # feeds spec test_stale_challenge_rejected
    # FILL IN: altering exactly the named input changes the digest.


def test_context_digest_keyed(mfa_secret):
    # FILL IN: a different secret yields a different digest (domain-separated HMAC).


def test_lock_key_folding():
    # FILL IN: small id unchanged; 2**40 folds into int4 range; bool/negative -> ValueError;
    #  LOCK_NAMESPACE < 2**31 - 1.


@pytest.mark.asyncio
async def test_version_initializes_and_is_monotonic(mfa_db, mfa_user_factory, mfa_secret):
    # FILL IN: current_version == 0 (row created); bump -> 1, 2; current_version == 2;
    #  calling current_version again does not reset it.


@pytest.mark.asyncio
async def test_user_lock_rolls_back_on_error(mfa_db, mfa_user_factory, mfa_secret):
    # FILL IN: inside user_lock: bump_version then raise RuntimeError -> RuntimeError
    #  propagates unchanged; afterwards current_version is unchanged (rolled back).


@pytest.mark.asyncio
async def test_user_lock_serializes_same_user(mfa_db, mfa_user_factory, mfa_secret):
    # FILL IN: task A enters the lock and holds it ~0.5 s; task B (same user) starts
    #  0.1 s later; B's entry timestamp >= A's exit timestamp. Spec "Retry accounting
    #  and concurrency" (shared lock across workers).


@pytest.mark.asyncio
async def test_user_lock_independent_users(mfa_db, mfa_user_factory, mfa_secret):
    # FILL IN: two different users' locks overlap in time (neither waits).


@pytest.mark.asyncio
async def test_audit_row_is_durable_and_complete(mfa_db, mfa_user_factory, mfa_secret):
    # FILL IN: write_audit inside user_lock; after exit, read the row on a DIFFERENT
    #  connection: actor, target, org, action, old/new state, outcome match and
    #  detail comes back as a dict. Writer half of spec test_factor_transitions_write_durable_audit (AC23).


@pytest.mark.asyncio
async def test_audit_rolls_back_with_transition(mfa_db, mfa_user_factory, mfa_secret):
    # FILL IN: write_audit then raise inside user_lock -> no row persisted.


@pytest.mark.asyncio
async def test_storage_failures_raise(mfa_db, mfa_secret):
    # FILL IN: bump_version for a nonexistent user id (FK violation) raises
    #  MfaStorageError — proves fetchval is used (execute() would have swallowed it, D25).
```

### Steps (in order)

1. Confirm TASK-129 and TASK-130 landed; run `pytest tests/test_mfa_migrations.py -rs -q`
   and make sure the live test **PASSED** (if it skipped, every live test here will skip too).
2. Write block 1; fill `_user_field`, `_lock_key`, the two `user_lock` FILL INs.
3. Write blocks 2 and 3; fill the three fetchval bodies.
4. Write the tests; fill every body. For the serialization test use
   `asyncio.Event`/`time.monotonic()` stamps, not sleeps alone.
5. Run the Test Specification. Live tests must show PASSED.
6. Confirm the D25 gate: no `.execute(` in `security.py`.

### FILL IN checklist

- [ ] `_user_field` — dict/Model, `None` ⇒ default
- [ ] `_lock_key` — int4 folding, bool/negative rejected
- [ ] `user_lock` acquisition failure → rollback + `MfaStorageError`
- [ ] `user_lock` commit → `MfaStorageError` on failure
- [ ] `current_version` / `bump_version` — fetchval, `MfaStorageError`
- [ ] `write_audit` — fetchval `RETURNING id`, dict `detail`, `MfaStorageError`
- [ ] Ten test bodies (four pure, six live)

---

## Acceptance Criteria

- [ ] **AC-1** `user_lock(user_id)` holds `pg_advisory_xact_lock(LOCK_NAMESPACE, key)` for the life of one transaction: a second `user_lock` for the same user waits until the first commits/rolls back; different users do not wait (spec "Retry accounting and concurrency").
- [ ] **AC-2** An exception raised in the lock body rolls back every statement executed on the yielded connection and propagates unchanged; acquisition/commit failures raise `MfaStorageError`.
- [ ] **AC-3** `current_version()` initializes a missing row at 0 without resetting an existing one; `bump_version()` is monotonic (+1, never decremented).
- [ ] **AC-4** `write_audit()` persists one durable row with actor, target, org, action, old/new state, method, request id, outcome and a dict `detail`, inside the caller's transaction (writer half of spec **AC23**).
- [ ] **AC-5** `context_digest()` changes when any of the twelve canonical inputs changes, is invariant to membership order / email case, and never contains the verifier (digest half of spec **AC30**).
- [ ] **AC-6** `grep -n "\.execute(" navigator_auth/mfa/security.py` prints nothing; a DB error (e.g. FK violation) surfaces as `MfaStorageError` (D25).
- [ ] **AC-7** `pytest tests/test_mfa_security_core.py tests/test_mfa_types.py -v -rs` passes with the live tests PASSED (not SKIPPED); `ruff check navigator_auth/mfa/security.py tests/test_mfa_security_core.py` is clean.

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_security_core.py -v -rs     # live tests must show PASSED
pytest tests/test_mfa_types.py -q                 # D5 regression over security.py
ruff check navigator_auth/mfa/security.py tests/test_mfa_security_core.py
grep -rn "\.execute(" navigator_auth/mfa/ | grep -v "navigator_auth/mfa/migrations.py" ; test $? -eq 1   # D25
```

Spec §4 rows touched: writer half of `test_factor_transitions_write_durable_audit` (M8);
digest/version groundwork for `test_stale_challenge_rejected`, `test_concurrent_verify_consumes_once`,
`test_verify_security_transition_races` (completed in TASK-140/144/147).

---

## Agent Instructions

1. **Read the spec** — §3 "Security contracts shared by the modules" (Challenge validity and invalidation;
   Retry accounting and concurrency), §3 M8 (audit + security tables), §7 R1/R5, §9 S10, AC23/AC30/AC31.
2. **Check dependencies** — TASK-129 and TASK-130 must be in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint. No `conn.execute()` (D25); no Redis.
5. **Verify** every acceptance criterion; live tests must PASS, not SKIP.
6. **Move this file** to `sdd/tasks/completed/TASK-132-mfa-security-core.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: gpt-5.6-terra (codex), 1 attempt
**Date**: 2026-11-11
**Notes**: MFA security core delivered; merge-tier green (31 passed across wave). Engine lint residuals (style) left for /sdd-done.

**Deviations from spec**: none expected (module placement `mfa/security.py` is a FEAT-106 task-contract decision);
list anything else here.
