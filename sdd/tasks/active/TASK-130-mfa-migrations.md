# TASK-130: MFA tables (six) + startup migration with usability flag + shared test fixtures

**Feature**: FEAT-106 — 2FA (OTP) for BasicAuth — TOTP + Email, per-tenant enforcement
**Spec**: `sdd/specs/basicauth-otp-2fa.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-129
**Assigned-to**: unassigned

---

## Context

Implements **spec §3 Module 8**: the six new tables, created idempotently at
startup, behind a migration wrapper that **reports usability instead of
swallowing failure**. It also creates `tests/fixtures/mfa.py`, the shared
fixtures every DB- or Redis-backed MFA test from TASK-132 onward imports.

Why the wrapper differs from its model (`passkey/migrations.py`): spec M8 and
§7 R13. `setup_passkey_tables()` / `setup_vault_tables()` log a DDL failure and
continue — right for features whose absence is a *degradation*. For a second
factor, a silently missing table makes the factor silently **absent**: a bypass.
But hard-failing startup would turn one missing table into a total outage for
every tenant, including those with 2FA off (spec §9 S5, rejected half). So
`setup_mfa_tables()` never raises and returns a `bool`; TASK-138 stores it and
refuses every BasicAuth login while it is `False` (D13).

### Two verified facts that change how the migration must be written

1. **asyncdb's `conn.execute()` NEVER raises (contract D25).** Verified by
   execution (2026-11-11): `await conn.execute("SELECT * FROM auth.no_such_table")`
   returns `[None, UndefinedTableError(...)]`; the method `return`s from inside
   its `finally` block (`.venv/.../asyncdb/drivers/pg.py:937-972`), which
   suppresses every exception, even the ones it re-raises. The passkey migration
   ignores that return value, so it can "succeed" without creating anything.
   Here: `ensure_mfa_tables()` MUST inspect the execute result and raise, AND
   `setup_mfa_tables()` MUST confirm with an independent `to_regclass` probe
   through `fetchval` (which *does* raise — verified: `StatementError`). The
   multi-statement DDL in this file is the **only** `execute()` allowed anywhere
   under `navigator_auth/mfa/` (D25); every other MFA module uses
   `fetchval`/`fetch_one` with `RETURNING`.
2. **Live-Postgres tests silently SKIP under this repo's pytest config unless
   `FutureWarning` is suppressed while asyncdb loads.** `pyproject.toml` sets
   `filterwarnings = ["error", …]`; constructing `asyncdb.AsyncPool("pg", …)`
   imports `google.api_core`, which emits a `FutureWarning` → becomes an error →
   asyncdb reports "Cannot Load Backend Pool: pgPool". Verified: the existing
   `tests/test_passkey_store.py` **skips all 4 tests** today for this reason, and
   wrapping the pool construction in
   `warnings.catch_warnings(); warnings.simplefilter("ignore", FutureWarning)`
   makes a live query pass. The `mfa_db` fixture below does exactly that — without
   it every DB-backed MFA test in the feature would skip and look green.

### Decomposition decisions this task implements

- **D15** — `user_trusted_devices` gains `rotated_at` and `revoke_reason`
  (rotation must keep superseded rows to detect replay).
- **D18** — `user_mfa_audit.target_user_id` is nullable (tenant-policy rows have
  no target user); the audit table has **no foreign keys** (audit outlives users).
- `user_id` columns are **`bigint`** — verified live: `auth.users.user_id` is
  `bigint` (the passkey DDL's `integer` predates that check; do not copy it).

---

## Scope

- Create `navigator_auth/mfa/sql/001_mfa_tables.sql` with the six tables + indexes.
- Create `navigator_auth/mfa/migrations.py`: `render_sql`, `ensure_mfa_tables`,
  `mfa_tables_present`, `setup_mfa_tables`.
- Create `tests/fixtures/mfa.py` (shared fixtures, contract §3 list).
- Create `tests/test_mfa_migrations.py`.

**NOT in scope**: calling `setup_mfa_tables()` from `BasicAuth.on_startup` (TASK-138);
any read/write of these tables (TASK-132..135); the vault seed (lives in the
existing `auth.user_vault_secrets`, TASK-136); `organization_users` (exists already,
not ours to create).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/sql/001_mfa_tables.sql` | CREATE | Six tables, idempotent DDL |
| `navigator_auth/mfa/migrations.py` | CREATE | Migration + usability probe |
| `tests/fixtures/mfa.py` | CREATE | Shared Redis/PG/user/policy/clock/callback fixtures |
| `tests/test_mfa_migrations.py` | CREATE | Unit (fake pool) + live tests |

---

## Codebase Contract

> Verified on `dev` @ `b10a3a3` (2026-11-11) and against the live dev database.

### Verified Imports

```python
import logging
import secrets
import warnings
from pathlib import Path
from typing import Any
from datetime import datetime, timezone
import pytest
import pytest_asyncio
import redis.asyncio as aioredis                                   # redis 5.2.1
from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE   # conf.py:33-34 ("auth", "users")
from navigator_auth.conf import REDIS_AUTH_URL, default_dsn       # conf.py:297, :45
from navigator_auth.handlers.users.passwd import set_basic_password   # handlers/users/passwd.py:12
from navigator_auth.mfa.exceptions import MfaStorageError          # TASK-129
from navigator_auth.mfa.types import MfaMode, OtpNotificationPayload, TenantMfaPolicy   # TASK-129
# asyncdb is imported INSIDE the mfa_db fixture under a FutureWarning filter (see Context fact 2):
#   import asyncdb; asyncdb.AsyncPool("pg", dsn=default_dsn)       # pattern: tests/test_passkey_store.py:18-29
```

### The pattern being mirrored — `navigator_auth/passkey/migrations.py` (verified, 60 lines)

```python
SQL_DIR = Path(__file__).parent / "sql"
_MIGRATION_FILES = ("001_passkey_credentials.sql",)
def render_sql(sql: str) -> str:
    return sql.replace("{schema}", AUTH_DB_SCHEMA).replace("{users_table}", AUTH_USERS_TABLE)
async def _run_sql(db_pool: Any, sql: str) -> None:      # :25-40 — handles both acquire() shapes:
    ctx = db_pool.acquire()
    if hasattr(ctx, "__aenter__"):
        async with ctx as conn: await conn.execute(sql)
    else:
        conn = await ctx
        try: await conn.execute(sql)
        finally: ...release...
async def ensure_passkey_tables(db_pool: Any) -> None: ...   # :43 — ignores execute()'s return value
async def setup_passkey_tables(db_pool: Any) -> None: ...    # :55 — "logs errors, never raises"
```

### asyncdb connection behaviour (verified by execution)

```python
await conn.execute("SELECT 1")                       # -> ['SELECT 1', None]
await conn.execute("SELECT * FROM auth.nope")        # -> [None, UndefinedTableError(...)]   (does NOT raise)
await conn.fetchval("SELECT 1 FROM auth.nope")       # raises asyncdb StatementError
await conn.fetchval("SELECT to_regclass($1)::text", "auth.users")   # -> 'auth.users'
# Multi-statement SQL through execute() with no args works (passkey migration relies on it).
# Pool connections register a jsonb codec (asyncdb/drivers/pg.py:307-327): pass dicts, not JSON strings.
```

### Live schema facts (verified 2026-11-11)

- `auth.users`: `user_id bigint` (nextval), `userid uuid` default, `username varchar` NOT NULL
  (no default), `user_role/is_superuser/is_active/is_new` have defaults → an insert needs only `username`.
- `auth.organization_users(user_id bigint, org_id bigint, properties jsonb, …)` exists.
- `auth.user_vault_secrets` exists (vault migrations).

### Does NOT Exist (Anti-Hallucination)

- ~~`auth.tenant_mfa_policy`, `auth.user_mfa`, `auth.user_mfa_backup_codes`,
  `auth.user_trusted_devices`, `auth.user_mfa_audit`, `auth.user_mfa_security`~~ — created here.
- ~~`setup_passkey_tables` as a usable model for the return value~~ — it returns `None`; ours returns `bool`.
- ~~`tests/fixtures/mfa.py`, `tests/conftest.py` MFA fixtures~~ — none; fixtures are imported explicitly
  (`from tests.fixtures.mfa import mfa_db  # noqa: F401`), the convention of `tests/fixtures/passkey.py`
  (e.g. `tests/test_passkey_management.py:6`). Do NOT add them to `tests/conftest.py`.
- ~~`fakeredis`~~ — not installed; Redis fixtures use the real server at `REDIS_AUTH_URL` (live, 7.2.3).
- ~~`UserDevices` reuse~~ (`models.py:143`) — not a trusted-device store (spec §6).

---

## Implementation Blueprint

### `navigator_auth/mfa/sql/001_mfa_tables.sql` — CREATE (complete)

```sql
-- FEAT-106 second factor for BasicAuth — six tables.
-- {schema} / {users_table} are substituted by mfa/migrations.py.
-- Additive and idempotent: safe to run on every startup.
-- The TOTP seed is NOT here: it lives sealed in {schema}.user_vault_secrets
-- under the reserved 'mfa:' namespace (TASK-136 / TASK-143).
CREATE SCHEMA IF NOT EXISTS {schema};

-- Per-tenant policy: DATA, not configuration. Absent row == mode 'off'.
CREATE TABLE IF NOT EXISTS {schema}.tenant_mfa_policy (
    org_id         bigint PRIMARY KEY,
    mode           varchar(16) NOT NULL DEFAULT 'off'
                   CHECK (mode IN ('off', 'optional', 'enforced')),
    remember_days  integer NOT NULL DEFAULT 0 CHECK (remember_days >= 0),
    enforced_at    timestamptz,
    enforced_by    varchar(254),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- Per-user factor enrolment (TOTP today). E-mail is implicit (User.email).
CREATE TABLE IF NOT EXISTS {schema}.user_mfa (
    user_id       bigint NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    provider      varchar(16) NOT NULL,
    enabled       boolean NOT NULL DEFAULT false,
    confirmed_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    PRIMARY KEY (user_id, provider)
);

-- Single-use backup codes, stored only as a keyed hash (D16).
CREATE TABLE IF NOT EXISTS {schema}.user_mfa_backup_codes (
    id          bigserial PRIMARY KEY,
    user_id     bigint NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    code_hash   varchar(64) NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS user_mfa_backup_codes_user_idx
    ON {schema}.user_mfa_backup_codes (user_id) WHERE used_at IS NULL;

-- Remember-me: rotating bearer second factor; superseded rows are kept
-- (rotated_at) so a replay is detectable and revokes the family (D15).
CREATE TABLE IF NOT EXISTS {schema}.user_trusted_devices (
    id             bigserial PRIMARY KEY,
    user_id        bigint NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    token_hash     varchar(64) NOT NULL UNIQUE,
    family_id      uuid NOT NULL,
    label          varchar(128) NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    last_used_at   timestamptz,
    rotated_at     timestamptz,
    revoked_at     timestamptz,
    revoke_reason  varchar(64)
);
CREATE INDEX IF NOT EXISTS user_trusted_devices_user_idx
    ON {schema}.user_trusted_devices (user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS user_trusted_devices_family_idx
    ON {schema}.user_trusted_devices (family_id);

-- Durable, action-specific record of every factor-state transition.
-- NOT abac/audit.py AuditLog (best-effort, records authorization decisions).
-- No foreign keys: the audit trail must outlive the users it mentions.
CREATE TABLE IF NOT EXISTS {schema}.user_mfa_audit (
    id              bigserial PRIMARY KEY,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    actor_user_id   bigint,
    target_user_id  bigint,
    org_id          bigint,
    action          varchar(64) NOT NULL,
    old_state       varchar(16),
    new_state       varchar(16),
    method          varchar(32),
    request_id      varchar(128),
    outcome         varchar(16) NOT NULL,
    detail          jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS user_mfa_audit_target_idx
    ON {schema}.user_mfa_audit (target_user_id, occurred_at DESC);

-- Durable monotonic challenge-invalidation version (spec security contracts).
CREATE TABLE IF NOT EXISTS {schema}.user_mfa_security (
    user_id     bigint PRIMARY KEY REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    version     bigint NOT NULL DEFAULT 0,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
```

**Why** the file is given in full: column names and types are the contract of
TASK-132..135 (they write these columns by name). **Why** no CHECK on
`user_mfa.provider`: future providers (spec Non-Goals mention a later unified
surface) must not need a migration. **Why** `bigint`: verified live column type
of `auth.users.user_id`.

### `navigator_auth/mfa/migrations.py` — CREATE

```python
"""MFA tables — idempotent startup migration with a usability flag (FEAT-106, spec M8).

Mirrors navigator_auth/passkey/migrations.py, except that failure is REPORTED,
not swallowed: a silently missing table would make the second factor silently
absent (spec R13). setup_mfa_tables() never raises, so a broken schema cannot
take down tenants that never enabled 2FA; BasicAuth refuses logins instead.
"""
import logging
from pathlib import Path
from typing import Any

from ..conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE
from .exceptions import MfaStorageError

logger = logging.getLogger("navigator.mfa")

SQL_DIR = Path(__file__).parent / "sql"
_MIGRATION_FILES = ("001_mfa_tables.sql",)
MFA_TABLES = (
    "tenant_mfa_policy", "user_mfa", "user_mfa_backup_codes",
    "user_trusted_devices", "user_mfa_audit", "user_mfa_security",
)


def render_sql(sql: str) -> str:
    """Substitute ``{schema}`` and ``{users_table}``, as passkey/migrations.py does."""
    return sql.replace("{schema}", AUTH_DB_SCHEMA).replace("{users_table}", AUTH_USERS_TABLE)


async def _with_conn(db_pool: Any, fn):
    """Run ``await fn(conn)`` on a pooled connection; both acquire() shapes
    (async-context and awaitable), exactly like passkey/migrations.py:_run_sql."""
    # FILL IN: copy the two-branch acquire/release shape of
    #  navigator_auth/passkey/migrations.py:25-40, returning fn(conn)'s result.


def _raise_on_execute_error(result: Any, filename: str) -> None:
    """asyncdb execute() returns [result, error] instead of raising (verified)."""
    # FILL IN: when result is a list/tuple of length 2 and result[1] is truthy,
    #  raise MfaStorageError(f"MFA migration {filename} failed: {type(err).__name__}")
    #  — bounded by Context fact 1; never put SQL text or values in the message.


async def ensure_mfa_tables(db_pool: Any) -> None:
    """Create the six tables if missing. Raises MfaStorageError on failure."""
    for filename in _MIGRATION_FILES:
        sql = render_sql((SQL_DIR / filename).read_text())

        async def _apply(conn, _sql=sql, _name=filename):
            _raise_on_execute_error(await conn.execute(_sql), _name)

        await _with_conn(db_pool, _apply)
    logger.info("MFA tables ensured.")


async def mfa_tables_present(db_pool: Any) -> bool:
    """True iff all six tables exist (to_regclass probe through fetchval, which raises)."""
    names = [f"{AUTH_DB_SCHEMA}.{table}" for table in MFA_TABLES]
    # FILL IN: one fetchval of
    #  "SELECT count(*) FROM unnest($1::text[]) AS t(name) WHERE to_regclass(t.name) IS NOT NULL"
    #  with `names`; return count == len(MFA_TABLES). Let storage errors propagate
    #  (the caller decides) — bounded by spec M8 "usability flag".


async def setup_mfa_tables(db_pool: Any) -> bool:
    """Startup wrapper. Returns True when the tables are present and usable.

    Never raises. False => BasicAuth records MFA as unavailable and refuses
    every login that owes a factor (spec M8, G7, D13).
    """
    # FILL IN: try ensure_mfa_tables(); then return await mfa_tables_present();
    #  on ANY exception log ERROR "MFA tables unavailable: <ErrorClass>" and
    #  return False; a db_pool of None -> log ERROR, return False.
    #  Bounded by: never raises (spec §9 S5 rejected half), never returns True
    #  without the probe (Context fact 1).
```

**Why** a probe after `ensure`: `ensure` can only detect what `execute()`
reports; the probe is an independent `fetchval` that raises on error and checks
the *outcome* (six relations exist), which is the thing that actually matters.
**Why** `_with_conn` copies the passkey shape: callers pass `app["authdb"]`
(asyncdb pool, both shapes) in production and simple fakes in unit tests.

### `tests/fixtures/mfa.py` — CREATE (block 1 of 2: constants, secret, Redis, Postgres)

```python
"""Shared FEAT-106 MFA test fixtures.

Import explicitly, like tests/fixtures/passkey.py:
    from tests.fixtures.mfa import mfa_db, mfa_user_factory  # noqa: F401
"""
import secrets
import warnings
from datetime import datetime, timezone

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE, REDIS_AUTH_URL, default_dsn
from navigator_auth.handlers.users.passwd import set_basic_password
from navigator_auth.mfa.migrations import ensure_mfa_tables
from navigator_auth.mfa.types import MfaMode, OtpNotificationPayload, TenantMfaPolicy

MFA_TEST_SECRET = b"test-mfa-secret-feat106-not-for-production"
USERS = f"{AUTH_DB_SCHEMA}.{AUTH_USERS_TABLE}"
FROZEN_EPOCH = 1_700_000_010          # 10 s into a 30 s TOTP step
TEST_PASSWORD = "correct-horse-battery-9"


@pytest.fixture
def mfa_secret() -> bytes:
    return MFA_TEST_SECRET


async def _purge_mfa_keys(pool) -> None:
    async with aioredis.Redis(connection_pool=pool) as r:
        keys = [k async for k in r.scan_iter(match="auth:mfa:*")]
        if keys:
            await r.delete(*keys)


@pytest_asyncio.fixture
async def mfa_redis_pool():
    """Real Redis at REDIS_AUTH_URL; auth:mfa:* purged before and after."""
    pool = aioredis.ConnectionPool.from_url(REDIS_AUTH_URL, decode_responses=True, encoding="utf-8")
    await _purge_mfa_keys(pool)
    yield pool
    await _purge_mfa_keys(pool)
    await pool.disconnect()


@pytest_asyncio.fixture
async def broken_redis_pool():
    """Every command fails (unreachable host) — exercises fail-CLOSED paths."""
    pool = aioredis.ConnectionPool.from_url(
        "redis://mfa-test-unreachable-host.invalid:6379/0",
        decode_responses=True, encoding="utf-8", socket_connect_timeout=1,
    )
    yield pool
    await pool.disconnect()


@pytest_asyncio.fixture
async def mfa_db():
    """asyncdb pool on live Postgres with the MFA tables; skips when unavailable.

    asyncdb's pg backend pulls in google.api_core, which emits a FutureWarning;
    under this repo's filterwarnings=error that aborts the pool load and every
    test would SKIP silently (verified — tests/test_passkey_store.py does today).
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            import asyncdb  # pylint: disable=import-outside-toplevel
            pool = asyncdb.AsyncPool("pg", dsn=default_dsn)
        await pool.connect()
        await ensure_mfa_tables(pool)
    except Exception as err:  # pylint: disable=W0703
        pytest.skip(f"Postgres unavailable: {type(err).__name__}: {err}")
    yield pool
    await pool.close()
```

### `tests/fixtures/mfa.py` — CREATE (block 2 of 2: users, policy, clock, callback spy)

```python
@pytest_asyncio.fixture
async def mfa_user_factory(mfa_db):
    """``await make(superuser=False, email=..., active=True, password=TEST_PASSWORD)``
    -> dict(user_id, username, email, password (hash), password_plain,
    is_superuser, is_active). Rows deleted on teardown (CASCADE cleans MFA rows)."""
    created: list[str] = []

    async def _make(*, superuser: bool = False, email: str | None = "default",
                    active: bool = True, password: str = TEST_PASSWORD) -> dict:
        username = f"mfa_test_{secrets.token_hex(4)}"
        address = f"{username}@example.com" if email == "default" else email
        # FILL IN: parameterized INSERT INTO {USERS} (username, email, password,
        #  is_superuser, is_active, is_new, first_name, last_name) ... RETURNING
        #  user_id via `async with await mfa_db.acquire() as conn: conn.fetch_one(...)`;
        #  password column = set_basic_password(password); append username to
        #  `created`; return the dict above — bounded by: parameterized SQL only,
        #  only `username` is NOT NULL without default (verified live).
        raise NotImplementedError

    yield _make
    # FILL IN: delete the created rows with the D25 idiom (execute() would hide
    #  a failure): conn.fetchval(f"WITH d AS (DELETE FROM {USERS} WHERE username
    #  = ANY($1::text[]) RETURNING 1) SELECT count(*) FROM d", created).


@pytest.fixture
def mfa_policy_enforced() -> TenantMfaPolicy:
    return TenantMfaPolicy(
        org_id=5, mode=MfaMode.ENFORCED, remember_days=30,
        enforced_at=datetime(2026, 11, 1, tzinfo=timezone.utc), enforced_by="fixture",
    )


class FrozenClock:
    """Deterministic epoch for TOTP skew tests; ``advance(seconds)`` moves it."""

    def __init__(self, epoch: float = FROZEN_EPOCH) -> None:
        self.now = float(epoch)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def frozen_totp_clock() -> FrozenClock:
    return FrozenClock()


CAPTURED_OTP: list[OtpNotificationPayload] = []


def capture_otp(payload: OtpNotificationPayload) -> None:
    """Dotted-path target for AUTH_OTP_EMAIL_CALLBACK in tests."""
    assert payload.code not in repr(payload)       # redaction invariant (AC14)
    CAPTURED_OTP.append(payload)


class _OtpSpy:
    path = "tests.fixtures.mfa.capture_otp"

    @property
    def payloads(self) -> list[OtpNotificationPayload]:
        return CAPTURED_OTP


@pytest.fixture
def otp_callback_spy():
    CAPTURED_OTP.clear()
    yield _OtpSpy()
    CAPTURED_OTP.clear()
```

**Why** the callback spy is a module-level function: providers resolve
`AUTH_OTP_EMAIL_CALLBACK` as a *dotted path* (`importlib`, the recovery pattern
at `handlers/recovery/handler.py:363-383`), so the target must be importable.
**Why** `mfa_user_factory` uses real rows: every MFA table has an FK to
`auth.users`, and CASCADE gives free cleanup of everything a test wrote.
**Why** `email="default"` sentinel: tests for spec R3 need `email=None` to mean
"no address", distinct from "give me the default address".

### `tests/test_mfa_migrations.py` — CREATE

```python
"""FEAT-106 TASK-130 — MFA DDL, migration, usability flag."""
import pytest

from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.migrations import (
    MFA_TABLES, SQL_DIR, _MIGRATION_FILES, ensure_mfa_tables, mfa_tables_present,
    render_sql, setup_mfa_tables,
)
from tests.fixtures.mfa import mfa_db  # noqa: F401


class _FakeConn:
    def __init__(self, execute_result=("CREATE", None), present=len(MFA_TABLES), raise_on=None):
        self.executed, self._result, self._present, self._raise_on = [], execute_result, present, raise_on

    async def execute(self, sql):
        # FILL IN: record sql; raise if self._raise_on == "execute"; return list(self._result)

    async def fetchval(self, sql, *args):
        # FILL IN: raise if self._raise_on == "fetchval"; return self._present


class _FakePool:
    # FILL IN: acquire() returns an async-context yielding one shared _FakeConn
    #  (pattern: tests/test_passkey_migrations.py:15-39).


def test_render_sql_substitutes_placeholders():
    # FILL IN: no "{schema}" / "{users_table}" survives render_sql of the file.


def test_migration_declares_six_tables():
    # FILL IN: every MFA_TABLES name appears as "CREATE TABLE IF NOT EXISTS {schema}.<name>";
    #  user_trusted_devices declares rotated_at and revoke_reason (D15);
    #  user_mfa_audit has no "REFERENCES" (D18).


@pytest.mark.asyncio
async def test_ensure_raises_on_swallowed_execute_error():
    """asyncdb execute() returns [None, err] — ensure must raise (Context fact 1)."""
    # FILL IN: _FakePool(execute_result=(None, RuntimeError("x"))) -> MfaStorageError.


@pytest.mark.asyncio
async def test_setup_returns_false_and_never_raises():
    # FILL IN: three cases — execute error, fetchval raising, probe count 5 —
    #  each returns False without raising; db_pool=None returns False (spec M8).


@pytest.mark.asyncio
async def test_setup_returns_true_when_all_present():
    # FILL IN: healthy fake -> True; exactly len(_MIGRATION_FILES) executes.


@pytest.mark.asyncio
async def test_live_setup_is_idempotent(mfa_db):
    # FILL IN: setup_mfa_tables(mfa_db) is True twice in a row and
    #  mfa_tables_present(mfa_db) is True (live Postgres).
```

### Steps (in order)

1. Confirm TASK-129 landed: `python -c "from navigator_auth.mfa.exceptions import MfaStorageError"`.
2. Write the SQL file verbatim; then `migrations.py`; fill `_with_conn`,
   `_raise_on_execute_error`, `mfa_tables_present`, `setup_mfa_tables`.
3. Write `tests/fixtures/mfa.py`; fill `mfa_user_factory` (insert + teardown).
4. Write `tests/test_mfa_migrations.py`; fill the fakes and bodies.
5. Run the Test Specification. **Check the live test actually ran** (`PASSED`, not
   `SKIPPED`) — if it skipped, read the skip reason before going further: a skip
   here means every later DB-backed MFA test would silently skip too.
6. Optional sanity: `psql`-free check via the fixture that `\d auth.user_trusted_devices`
   has `rotated_at` (the static test already asserts the DDL text).

### FILL IN checklist

- [ ] `_with_conn` — both acquire shapes (passkey/migrations.py:25-40)
- [ ] `_raise_on_execute_error` — Context fact 1, no SQL in message
- [ ] `mfa_tables_present` — single `fetchval`, errors propagate
- [ ] `setup_mfa_tables` — never raises, probe-gated True, `None` pool → False
- [ ] `mfa_user_factory` insert + teardown — parameterized SQL
- [ ] `_FakeConn` / `_FakePool`
- [ ] Six test bodies

---

## Acceptance Criteria

- [ ] **AC-1** `001_mfa_tables.sql` creates exactly the six tables of contract §3 with `bigint` user ids, the D15 columns, a nullable FK-free `user_mfa_audit` (D18), and the listed indexes; rendering leaves no placeholder.
- [ ] **AC-2** `ensure_mfa_tables()` raises `MfaStorageError` when asyncdb's `execute()` returns an error slot instead of raising.
- [ ] **AC-3** `setup_mfa_tables()` never raises; returns `True` only when ensure succeeded **and** the `to_regclass` probe finds all six tables; returns `False` otherwise, including a `None` pool (spec M8; prerequisite of spec **AC24**).
- [ ] **AC-4** Against live Postgres, `setup_mfa_tables()` returns `True` on two consecutive runs (idempotent) — and the test reports PASSED, not SKIPPED.
- [ ] **AC-5** `tests/fixtures/mfa.py` provides `mfa_secret`, `mfa_redis_pool`, `broken_redis_pool`, `mfa_db`, `mfa_user_factory`, `mfa_policy_enforced`, `frozen_totp_clock`, `otp_callback_spy`, and `mfa_db` suppresses `FutureWarning` only around the asyncdb import/pool construction.
- [ ] **AC-6** `test_no_session_minting_text_in_mfa_package` (TASK-129) still passes with the new files (D5).
- [ ] **AC-7** `pytest tests/test_mfa_migrations.py tests/test_mfa_types.py -v` passes; `ruff check navigator_auth/mfa tests/fixtures/mfa.py tests/test_mfa_migrations.py` clean.
- [ ] **AC-8** `grep -rn "\.execute(" navigator_auth/mfa/` shows matches only in `navigator_auth/mfa/migrations.py` (D25).

---

## Test Specification

```bash
source .venv/bin/activate
pytest tests/test_mfa_migrations.py -v -rs        # -rs: show skip reasons — the live test must PASS
pytest tests/test_mfa_types.py -q                 # D5 regression over the new files
ruff check navigator_auth/mfa tests/fixtures/mfa.py tests/test_mfa_migrations.py
grep -rn "\.execute(" navigator_auth/mfa/ | grep -v "navigator_auth/mfa/migrations.py" ; test $? -eq 1   # D25
```

Spec §4 rows touched: prerequisite for `test_missing_mfa_tables_refuse_login` (M8 — the refusal itself is TASK-138)
and `test_factor_transitions_write_durable_audit` (M8 — the writer is TASK-132).

---

## Agent Instructions

1. **Read the spec** — §3 M8, §7 R5/R13, §9 S5, §4 Test Data / Fixtures.
2. **Check dependencies** — TASK-129 must be in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/basicauth-otp-2fa.json` → `"in-progress"`.
4. **Implement** per the blueprint. Do not "simplify" the probe away: Context fact 1 is the reason it exists.
5. **Verify** every acceptance criterion; AC-4 must show PASSED.
6. **Move this file** to `sdd/tasks/completed/TASK-130-mfa-migrations.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**:
**Date**:
**Notes**:

**Deviations from spec**: D15 columns, D18 nullable FK-free audit, `bigint` ids — pre-recorded; list anything else here.
