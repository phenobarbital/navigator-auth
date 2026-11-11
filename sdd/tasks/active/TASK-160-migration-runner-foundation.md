# TASK-160: Migration runner foundation — fail-closed execute, ledger and status

**Feature**: FEAT-110 — navauth self upgrade database migration command
**Spec**: `sdd/specs/new-command-migration.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-159
**Assigned-to**: unassigned

---

## Context

Implements the first half of spec §3 **Module 2** (Runner + ledger): the parts
every other module needs before `upgrade()` exists.

- `execute_checked` — asyncdb's `pg.execute()` never raises, it returns
  `[result, error]`; this wrapper always raises (spec G4).
- `acquire_pooled` / `acquire_raw` — one place for the two pool `acquire()`
  styles the legacy `_run_sql` copies handle today, plus unwrapping an asyncdb
  connection to the raw asyncpg one.
- The ledger table `<AUTH_DB_SCHEMA>.schema_migrations`, `ledger_exists`,
  `ensure_ledger` and the read-only `get_status`.
- The status/report Pydantic models and `MigrationError`.
- `FakeConnection` in the shared `conftest.py`, used by every later migration test.

`upgrade()` itself is TASK-163; prerequisite/postcondition checks are TASK-161;
runtime grants are TASK-162.

---

## Scope

- Create `navigator_auth/migrations/runner.py` with: `logger`, `LEDGER_TABLE`,
  `ADVISORY_LOCK_KEY`, `MigrationError`, `MigrationState`, `MigrationStatus`,
  `MigrationResult`, `UpgradeReport`, `quote_ident`, `ledger_name`,
  `acquire_pooled`, `acquire_raw`, `execute_checked`, `ledger_exists`,
  `ensure_ledger`, `get_status`.
- Re-export the public names from `navigator_auth/migrations/__init__.py`.
- Add `FakeConnection` (and a `fake_conn` fixture) to `tests/unit/migrations/conftest.py`.
- Create `tests/unit/migrations/test_runner.py` with the M2 tests listed below.

**NOT in scope**: `upgrade()`, the advisory lock, ledger upserts (TASK-163);
prerequisite/postcondition checks (TASK-161); grants (TASK-162); changing the
legacy `ensure_*` functions (TASK-164); the startup check (TASK-166).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/migrations/runner.py` | CREATE | Models, fail-closed execute, acquire helpers, ledger, status |
| `navigator_auth/migrations/__init__.py` | MODIFY | Re-export runner names |
| `tests/unit/migrations/conftest.py` | MODIFY | Add `FakeConnection` + `fake_conn` fixture |
| `tests/unit/migrations/test_runner.py` | CREATE | Runner foundation tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `87c9b9c` (2026-11-11) and the installed asyncdb / asyncpg.

### Verified Imports
```python
from asyncdb.interfaces.abstract import AbstractDriver   # verified: .venv/.../asyncdb/interfaces/abstract.py:10; issubclass(asyncdb.drivers.pg.pg, AbstractDriver) is True
from navigator_auth.conf import AUTH_DB_SCHEMA           # verified: navigator_auth/conf.py:33 (default "auth")
from navigator_auth.migrations.catalog import MigrationFile, discover   # created by TASK-159
from pydantic import BaseModel, Field                     # pydantic 2.13.4 installed
from contextlib import asynccontextmanager                # stdlib
from collections.abc import AsyncIterator, Iterable       # stdlib
from datetime import datetime                             # stdlib
from enum import Enum                                     # stdlib
import logging                                            # stdlib
```

### Existing Signatures to Use
```python
# navigator_auth/migrations/catalog.py (TASK-159)
class MigrationFile(BaseModel):            # frozen; migration_set, filename, path: Path, checksum: str
def discover(sets: Iterable[str] | None = None) -> tuple[MigrationFile, ...]

# asyncdb (site-packages, not this repo)
# asyncdb/interfaces/abstract.py
class AbstractDriver(ABC):                 # line 10
    def get_connection(self):              # line 66 — returns the raw asyncpg connection
# asyncdb/drivers/pg.py
class _pgAcquireContext:                   # line 134 — awaitable AND async context manager
class pgPool:
    def acquire(self) -> "_pgAcquireContext":          # line 443
    async def release(self, connection=None, timeout=5):  # line 457 — accepts a `pg` wrapper
class pg(SQLDriver, ...):                  # line 572 — subclass of AbstractDriver
    async def execute(self, sentence, *args, **kwargs):  # line 937 — NEVER raises for most errors; returns [result, error]

# Legacy release logic to reproduce verbatim in acquire_pooled
# navigator_auth/identity/migrations.py:34-49 (`_run_sql`)
ctx = db_pool.acquire()
if hasattr(ctx, "__aenter__"): async with ctx as conn: ...
else: conn = await ctx; try ... finally: db_pool.release(conn) | conn.release() | conn.close()
```

Import trap (verified with `python -W error`): `import asyncdb.drivers.pg` emits a
`FutureWarning` from `google.api_core`, which `filterwarnings = ["error", …]`
(`pyproject.toml:121`) turns into a failure. `asyncdb` and
`asyncdb.interfaces.abstract` import cleanly. Never import `asyncdb.drivers.pg`
in `runner.py` or in tests; spec mocks on `AbstractDriver`
(`isinstance(MagicMock(spec=AbstractDriver), AbstractDriver)` is `True`).

Mock facts that shape `acquire_raw`: `isinstance(AsyncMock(), AbstractDriver)` and
`isinstance(MagicMock(), AbstractDriver)` are both `False`, while any attribute
exists on a mock — so detect asyncdb connections with `isinstance`, never with
`hasattr(conn, "get_connection")`. asyncpg's pool proxy
(`asyncpg.pool.PoolConnectionProxy`) is not an `asyncpg.Connection` subclass and
has no `get_connection`; it is yielded as is.

Ledger DDL (spec §2 Data Models, verbatim apart from the quoted name):
```sql
CREATE TABLE IF NOT EXISTS {ledger} (
    migration_set   VARCHAR(64)  NOT NULL,
    filename        VARCHAR(255) NOT NULL,
    checksum        CHAR(64)     NOT NULL,
    applied_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    applied_by      TEXT         NOT NULL DEFAULT current_user,
    package_version VARCHAR(32),
    execution_ms    INTEGER,
    PRIMARY KEY (migration_set, filename)
);
GRANT SELECT ON {ledger} TO PUBLIC;
```

### Does NOT Exist
- ~~`schema_migrations` or any applied-migrations table~~ — none anywhere; this task defines it.
- ~~`asyncdb` `execute()` raising on SQL errors~~ — it returns `[result, error]` for most errors.
- ~~`pgPool.fetchval` / `pgPool.fetch_all`~~ — query methods live on the acquired connection.
- ~~`asyncpg.utils.quote_ident` as public API~~ — do not import asyncpg internals; `quote_ident` is defined here.
- ~~`upgrade`, `check_prerequisites`, `grant_runtime_access`~~ — TASK-163 / TASK-161 / TASK-162.
- ~~`navigator_auth/migrations/models.py`~~ — the models live in `runner.py` (spec M2).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/migrations/runner.py", "action": "CREATE"},
    {"path": "navigator_auth/migrations/__init__.py", "action": "MODIFY"},
    {"path": "tests/unit/migrations/conftest.py", "action": "MODIFY"},
    {"path": "tests/unit/migrations/test_runner.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/migrations/catalog.py#MigrationFile",
    "sym:navigator_auth/migrations/catalog.py#discover"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- `get_status` is read-only: it never creates the ledger (AC "`--check` … creates nothing").
- Every identifier interpolated into SQL goes through `quote_ident`; values go as
  `$n` parameters (spec runtime access contract: "never interpolate an unquoted role").
- Logger name `navigator.migrations` (spec §7 Patterns).
- `FakeConnection` is the contract later tasks test against (TASK-161/162/163/165/166):
  keep it generic (`respond`, `fail_on`, `relations`) so they configure it from
  their own test files instead of editing this conftest — this task is the last
  one allowed to change it.

---

## Implementation Blueprint

### Steps (in order)
1. Write `runner.py` from the blocks below and fill the two `FILL IN`s — *why*:
   TASK-161..166 import these names.
2. Extend `__init__.py` — *why*: spec M1 says the package re-exports `get_status`.
3. Add `FakeConnection` + `fake_conn` to `conftest.py`, following the marker rules
   in its docstring exactly — *why*: later tasks rely on those rules.
4. Write `test_runner.py`; run the Validation Commands.

### `navigator_auth/migrations/runner.py` (CREATE) — block 1: models, helpers
```python
"""Migration runner — fail-closed execution, ledger and status (FEAT-110, spec M2)."""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import datetime
from enum import Enum
from typing import Any

from asyncdb.interfaces.abstract import AbstractDriver
from pydantic import BaseModel, Field

from ..conf import AUTH_DB_SCHEMA
from .catalog import MigrationFile, discover

logger = logging.getLogger("navigator.migrations")

LEDGER_TABLE = "schema_migrations"
ADVISORY_LOCK_KEY: int = 1102026  # session-level pg_advisory_lock key for an upgrade run

_LEDGER_DDL = """
CREATE TABLE IF NOT EXISTS {ledger} (
    migration_set   VARCHAR(64)  NOT NULL,
    filename        VARCHAR(255) NOT NULL,
    checksum        CHAR(64)     NOT NULL,
    applied_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    applied_by      TEXT         NOT NULL DEFAULT current_user,
    package_version VARCHAR(32),
    execution_ms    INTEGER,
    PRIMARY KEY (migration_set, filename)
)
"""


class MigrationError(Exception):
    """A statement failed, or the database is not usable for migrations."""


class MigrationState(str, Enum):
    """Ledger state of one catalog file."""

    APPLIED = "applied"
    PENDING = "pending"
    CHANGED = "changed"


class MigrationStatus(BaseModel):
    """State of one catalog file against the ledger."""

    file: MigrationFile
    state: MigrationState
    applied_at: datetime | None = None
    recorded_checksum: str | None = None


class MigrationResult(BaseModel):
    """Outcome of applying one file."""

    file: MigrationFile
    ok: bool
    error: str | None = None
    duration_ms: int = 0


class UpgradeReport(BaseModel):
    """Outcome of one ``upgrade()`` run."""

    applied: list[MigrationResult] = Field(default_factory=list)
    failed: list[MigrationResult] = Field(default_factory=list)
    skipped_changed: list[MigrationStatus] = Field(default_factory=list)
    access_errors: list[str] = Field(default_factory=list)  # runtime grant/verification failures


def quote_ident(name: str) -> str:
    """Quote a PostgreSQL identifier: wrap in double quotes, double embedded quotes.

    Raises:
        MigrationError: when ``name`` is empty.
    """
    if not name:
        raise MigrationError("Empty SQL identifier")
    return '"' + name.replace('"', '""') + '"'


def ledger_name() -> str:
    """Quoted ``<AUTH_DB_SCHEMA>.schema_migrations``."""
    return f"{quote_ident(AUTH_DB_SCHEMA)}.{quote_ident(LEDGER_TABLE)}"
```
**Why this shape**: names, model fields and constants are fixed by spec §2 Data
Models and the M2 skeleton. `quote_ident` lives here so TASK-161/162 share one
quoting rule.

### `navigator_auth/migrations/runner.py` (CREATE) — block 2: connections, execute
```python
@asynccontextmanager
async def acquire_pooled(db_pool: Any) -> AsyncIterator[Any]:
    """Yield a connection from ``db_pool`` exactly as the pool returns it (no unwrapping).

    Handles both ``acquire()`` styles (async context manager, awaitable) and
    releases the connection the way the legacy ``_run_sql`` copies did. Used by
    the legacy ``ensure_*`` shims (TASK-164), whose mocked-pool tests assert on
    the pool's own connection object.
    """
    ctx = db_pool.acquire()
    if hasattr(ctx, "__aenter__"):
        async with ctx as conn:
            yield conn
        return
    conn = await ctx
    try:
        yield conn
    finally:
        if hasattr(db_pool, "release"):
            await db_pool.release(conn)
        elif hasattr(conn, "release"):
            await conn.release()
        else:
            await conn.close()


@asynccontextmanager
async def acquire_raw(db_pool: Any) -> AsyncIterator[Any]:
    """Yield a raw asyncpg connection from an asyncpg or asyncdb pool.

    An asyncdb connection (``AbstractDriver``) is unwrapped with ``get_connection()``;
    anything else is yielded unchanged. Release is delegated to ``acquire_pooled``.
    """
    async with acquire_pooled(db_pool) as conn:
        yield conn.get_connection() if isinstance(conn, AbstractDriver) else conn


async def execute_checked(conn: Any, sql: str, *args: Any) -> Any:
    """``conn.execute(sql, *args)`` that always raises on failure.

    asyncdb returns ``[result, error]`` instead of raising. When the return value
    is a 2-item list/tuple whose second item is not ``None``, raise
    ``MigrationError``: chain exception-valued errors (``from error``); include
    string-valued errors (empty strings too) in the message without chaining.
    ``[result, None]`` and native asyncpg command-status strings pass through.
    """
    result = await conn.execute(sql, *args)
    # FILL IN: the check described above — test `is not None`, never truthiness (spec M2);
    #   message must not contain the SQL text or any DSN (spec §2 "never printed or logged").
    return result
```
**Why**: the release branch is copied from the legacy runners so their tests keep
passing when TASK-164 switches to it. `isinstance` (not `hasattr`) keeps mocks
from being "unwrapped".

### `navigator_auth/migrations/runner.py` (CREATE) — block 3: ledger and status
```python
async def ledger_exists(conn: Any) -> bool:
    """True when ``<schema>.schema_migrations`` exists (``to_regclass`` probe)."""
    return bool(await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", ledger_name()))


async def ensure_ledger(conn: Any) -> None:
    """Create the ledger table and its ``GRANT SELECT … TO PUBLIC``.

    Raises:
        MigrationError: when ``AUTH_DB_SCHEMA`` does not exist (base schema is the
            Navigator platform's job — spec Non-Goals).
    """
    exists = await conn.fetchval("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)", AUTH_DB_SCHEMA)
    if not exists:
        raise MigrationError(f"Schema {AUTH_DB_SCHEMA!r} does not exist; it is provisioned by the Navigator platform")
    await execute_checked(conn, _LEDGER_DDL.format(ledger=ledger_name()))
    await execute_checked(conn, f"GRANT SELECT ON {ledger_name()} TO PUBLIC")


async def get_status(conn: Any, sets: Iterable[str] | None = None) -> list[MigrationStatus]:
    """State of every catalog file. Read-only: never creates the ledger.

    A database without the ledger has every file PENDING.
    """
    files = discover(sets)
    rows: dict[tuple[str, str], Any] = {}
    if await ledger_exists(conn):
        for row in await conn.fetch(f"SELECT migration_set, filename, checksum, applied_at FROM {ledger_name()}"):
            rows[(row["migration_set"], row["filename"])] = row
    # FILL IN: one MigrationStatus per file, in catalog order — APPLIED when a row has the same
    #   checksum, CHANGED when the row's checksum differs (fill recorded_checksum/applied_at),
    #   PENDING otherwise — bounded by spec §2 Overview item 2.
    raise NotImplementedError
```
**Why**: the SQL strings here are the ones `FakeConnection` recognises; if you
change one, change the fake's marker rule in the same commit.

### `navigator_auth/migrations/__init__.py` (MODIFY)
```python
# occurrences: 1 (verified after TASK-159: grep -c '^from .catalog import (' navigator_auth/migrations/__init__.py)
# AFTER — insert below the `from .catalog import (...)` block:
from .runner import (
    MigrationError,
    MigrationResult,
    MigrationState,
    MigrationStatus,
    UpgradeReport,
    get_status,
)
# FILL IN: add the six names to __all__ (keep it sorted).
```

### `tests/unit/migrations/conftest.py` (MODIFY)
```python
# AFTER — append below the `tmp_catalog` fixture (created by TASK-159)
class FakeConnection:
    """In-memory stand-in for an asyncpg connection.

    Records every call in ``statements`` as ``(method, sql, args)``. Rules, first match wins:

    - ``execute``: raises the exception registered with ``fail_on(marker, exc)`` when the
      SQL contains ``marker``; ``CREATE TABLE IF NOT EXISTS`` on ``schema_migrations`` sets
      ``ledger_present``; ``INSERT INTO`` on ``schema_migrations`` upserts
      ``ledger[(args[0], args[1])] = {"migration_set", "filename", "checksum", "applied_at",
      "package_version", "execution_ms"}`` from args[0..4]; returns ``"OK"``.
    - ``fetch`` / ``fetchval`` / ``fetchrow``: a value registered with ``respond(marker, value)``
      (``value`` may be ``callable(sql, args)``); else ``to_regclass`` with an arg ending in
      ``schema_migrations`` (quotes stripped) → ``ledger_present``; else ``to_regclass`` → arg
      (quotes stripped) in ``relations``; ``pg_namespace`` → ``not schema_missing``;
      ``FROM`` … ``schema_migrations`` → list of ledger rows (dicts); else ``None``.
    - ``transaction()``: async context manager; snapshots ``ledger``/``ledger_present`` and
      restores them when the block raises; appends ``("transaction", "BEGIN"/"COMMIT"/"ROLLBACK", ())``.
    - ``close()``: sets ``closed``.
    """

    def __init__(self) -> None:
        self.statements: list[tuple[str, str, tuple]] = []
        self.ledger: dict[tuple[str, str], dict] = {}
        self.ledger_present = False
        self.schema_missing = False
        self.relations: set[str] = set()
        self.closed = False
        self._responses: list[tuple[str, object]] = []
        self._failures: list[tuple[str, BaseException]] = []

    def respond(self, marker: str, value: object) -> None:
        self._responses.append((marker, value))

    def fail_on(self, marker: str, exc: BaseException) -> None:
        self._failures.append((marker, exc))

    # FILL IN: async execute/fetch/fetchval/fetchrow/close and transaction() per the rules above;
    #   a helper `writes()` returning executed statements other than SELECTs is handy for
    #   "writes nothing" assertions in TASK-165/166.


@pytest.fixture
def fake_conn() -> FakeConnection:
    """A fresh ``FakeConnection``."""
    return FakeConnection()
```

### FILL IN checklist
- [ ] `runner.py::execute_checked` — error-pair check; bounded by spec M2 docstring
- [ ] `runner.py::get_status` — state mapping; bounded by spec §2 item 2
- [ ] `__init__.py` — `__all__`
- [ ] `conftest.py::FakeConnection` — methods per docstring rules
- [ ] `test_runner.py` — tests below

---

## Acceptance Criteria

- [ ] `execute_checked` raises `MigrationError` on `[x, Exception]` (chained) and on `[x, "msg"]` / `[x, ""]` (not chained); returns `[x, None]` and status strings unchanged.
- [ ] `acquire_raw` unwraps an `AbstractDriver` with `get_connection()` and releases through both acquire styles; mocks are yielded unchanged.
- [ ] `get_status` on a connection without the ledger returns every file PENDING and issues no DDL.
- [ ] A ledger row with a different checksum yields CHANGED with `recorded_checksum` set.
- [ ] `ensure_ledger` raises `MigrationError` when the schema is missing, else creates the table and the `GRANT SELECT … TO PUBLIC`.
- [ ] `from navigator_auth.migrations import get_status, MigrationStatus, UpgradeReport` works.

---

## Validation Commands

- `pytest tests/unit/migrations/test_runner.py -q`

---

## Test Specification

```python
# tests/unit/migrations/test_runner.py
import pytest
from unittest.mock import AsyncMock, MagicMock

from asyncdb.interfaces.abstract import AbstractDriver  # NOT asyncdb.drivers.pg — see contract
from navigator_auth.migrations.runner import (
    MigrationError, MigrationState, acquire_pooled, acquire_raw, ensure_ledger,
    execute_checked, get_status, ledger_exists, quote_ident,
)


@pytest.mark.asyncio
async def test_execute_checked_raises_on_asyncdb_error_pair():
    """exception and string errors (including "") raise; [result, None] and "CREATE TABLE" pass;
    __cause__ set only for exception-valued errors."""


@pytest.mark.asyncio
async def test_acquire_raw_unwraps_asyncdb_and_releases():
    """MagicMock(spec=AbstractDriver) with get_connection() → raw conn; context-manager and awaitable pools
    both release (pool.release awaited with the pool's own connection)."""


@pytest.mark.asyncio
async def test_acquire_pooled_yields_pool_connection_unchanged():
    """An AsyncMock connection is yielded as is (no get_connection call)."""


@pytest.mark.asyncio
async def test_status_without_ledger_is_all_pending_and_writes_nothing(fake_conn):
    """Every catalog file PENDING; fake_conn saw no execute()."""


@pytest.mark.asyncio
async def test_status_marks_changed_on_checksum_mismatch(fake_conn):
    """One APPLIED row with the right checksum, one row with a wrong checksum → CHANGED."""


@pytest.mark.asyncio
async def test_ensure_ledger_requires_schema_and_grants_public(fake_conn):
    """schema_missing → MigrationError and no DDL; otherwise CREATE TABLE + GRANT SELECT … TO PUBLIC."""


def test_quote_ident_doubles_quotes_and_rejects_empty():
    """quote_ident('a"b') == '"a""b"'; quote_ident('') raises MigrationError."""
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug new-command-migration --feature-id FEAT-110`)
2. **Read the spec** at the path listed above for full context
3. **Check dependencies** — every `Depends-on` task must be `"done"` in the
   per-spec index `sdd/tasks/index/new-command-migration.json`
4. **Verify the Codebase Contract** — before writing ANY code:
   - Confirm every import in "Verified Imports" still exists (`grep` or `read` the source)
   - Confirm every class/method in "Existing Signatures" still has the listed attributes
   - If anything has changed, update the contract FIRST, then implement
   - **NEVER** reference an import, attribute, or method not in the contract without verifying it exists
5. **Update status** in `sdd/tasks/index/new-command-migration.json` → `"in-progress"`
   (set `started_at`) and commit only that index file
6. **Implement** — start from the Implementation Blueprint blocks, complete every
   `# FILL IN:` marker, and never change a signature or path the blueprint fixes
7. **Verify** all acceptance criteria are met — run the Validation Commands
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`)
9. **Close the task** with `parrot sdd task close TASK-160 new-command-migration verified`
   — it moves this file to `sdd/tasks/completed/` and marks it `"done"` in the
   index; never move or copy the file by hand
10. **Fill in the Completion Note** below, then commit the staged SDD state

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any
