# TASK-87: `navigator_auth.passkey` package — types, DDL and startup migration

**Feature**: FEAT-101 — Passkey (WebAuthn) Authentication Backend
**Spec**: `sdd/specs/passkey-support-backend.spec.md` (Module 2, §2 Data Models, AC3)
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-86
**Assigned-to**: unassigned

---

## Context

Part of serial stage S0. This task creates the `navigator_auth/passkey/` package with:
- the Pydantic models that every later module exchanges (`RelyingParty`, `StoredCredential`, `ChallengeState`);
- the two tables;
- the idempotent startup migration.

It follows the `identity/migrations.py` precedent exactly. The store CRUD is TASK-88.

---

## Scope

- Create `navigator_auth/passkey/__init__.py`, `types.py`, `migrations.py` and `sql/001_passkey_credentials.sql`.
- The SQL file uses `{schema}` and `{users_table}` placeholders. The runner substitutes
  `AUTH_DB_SCHEMA` and `AUTH_USERS_TABLE` (spec §2 Data Models).
- `ensure_passkey_tables(db_pool)` runs every file in `_MIGRATION_FILES` in order.
  `setup_passkey_tables(db_pool)` is the non-raising startup wrapper.
- Write `tests/test_passkey_migrations.py`:
  - a unit test of the placeholder substitution with a fake pool;
  - `test_migration_idempotent`, live and skipped without Postgres.

**NOT in scope**: `PasskeyStore` (TASK-88), `RelyingPartyResolver` (TASK-89), and calling the
migration from `PasskeyAuth.on_startup` (TASK-93).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/passkey/__init__.py` | CREATE | Package docstring and re-exports of the types |
| `navigator_auth/passkey/types.py` | CREATE | `RelyingParty`, `StoredCredential`, `ChallengeState` |
| `navigator_auth/passkey/migrations.py` | CREATE | `ensure_passkey_tables`, `setup_passkey_tables` |
| `navigator_auth/passkey/sql/001_passkey_credentials.sql` | CREATE | DDL for both tables |
| `tests/test_passkey_migrations.py` | CREATE | Substitution unit test and live idempotency test |

---

## Codebase Contract (Anti-Hallucination)

> Verified 2026-10-02 against `dev` @ `564c440`.

### Verified Imports
```python
from navigator_auth.conf import AUTH_DB_SCHEMA      # conf.py:32 (fallback "auth")
from navigator_auth.conf import AUTH_USERS_TABLE    # conf.py:33 (fallback "users")
from pydantic import BaseModel, Field               # pydantic>=2.12.5 (pyproject dependencies)
```

### Existing Signatures to Use (pattern — copy, do not import)
```python
# navigator_auth/identity/migrations.py (whole file, 64 lines)
logger = logging.getLogger("navigator.identity")
SQL_DIR = Path(__file__).parent / "sql"
_MIGRATION_FILES = ("001_identity_credentials.sql", ...)
async def _run_sql(db_pool: Any, sql: str) -> None:    # handles acquire() as async-ctx or awaitable
async def ensure_identity_columns(db_pool: Any) -> None
async def setup_identity_columns(db_pool: Any) -> None  # try/except Exception → logger.error, never raises
```
- Packaging: `MANIFEST.in` has `graft navigator_auth`, and `pyproject.toml:78` has
  `include = ["navigator_auth*"]`. The `identity/sql/*.sql` files ship this way, so a new
  `passkey/sql/` directory needs no packaging change.
- `models.User` (`models.py:39`): `user_id` is an int PK in `AUTH_DB_SCHEMA.AUTH_USERS_TABLE`.
  The FK target is `{schema}.{users_table}(user_id)`.

### Does NOT Exist
- `navigator_auth/passkey/` (all new); `RelyingParty`, `StoredCredential`, `ChallengeState`.
- A shared migration-runner helper. Each package (`identity/`, `vault/`) has its own private
  `_run_sql`, so copy it; do not import `identity.migrations._run_sql`.
- `org_id` on `models.User`.

---

## Implementation Blueprint

### Steps (in order)
1. Write `types.py` exactly as spec §2 Data Models. The field names are frozen: tasks 88, 89 and
   93 to 96 depend on them.
2. Write the SQL with `{schema}` and `{users_table}` placeholders. Do not hardcode `auth.users`,
   because `AUTH_USERS_TABLE` is configurable (`conf.py:33`).
3. Write `migrations.py`. Copy `_run_sql`, and render the placeholders with `str.replace`, not
   `str.format`. The DDL has no braces today, but `str.replace` stays safe if a later migration
   adds JSON defaults.
4. Write the tests and run them.

### `navigator_auth/passkey/types.py` — CREATE
```python
"""Pydantic data models for the passkey (WebAuthn) backend (FEAT-101)."""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class RelyingParty(BaseModel):
    """One allow-listed WebAuthn relying party (one tenant site)."""

    origin: str = Field(..., description="Exact origin, e.g. https://app.tenant-a.com")
    rp_id: str = Field(..., description="Registrable domain, e.g. tenant-a.com")
    rp_name: str = "Navigator"
    org_id: Optional[int] = None
    client_id: Optional[int] = None


class StoredCredential(BaseModel):
    """A row of ``{schema}.user_credentials``."""

    credential_id: bytes
    user_id: int
    rp_id: str
    public_key: bytes
    sign_count: int = 0
    transports: Optional[list[str]] = None
    aaguid: Optional[str] = None
    device_type: Optional[str] = None
    backed_up: bool = False
    label: Optional[str] = None
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None


class ChallengeState(BaseModel):
    """Redis payload for a pending registration or login ceremony."""

    challenge: str  # base64url
    rp_id: str
    origin: str
    expected_user_id: Optional[int] = None  # username-first, known user
    decoy: bool = False  # username-first, unknown user
```
**Why**: The spec freezes these shapes (§2). The project rules require Pydantic for new data
structures. `aaguid` is a `str` because asyncpg returns `uuid.UUID`, and TASK-88 converts it.

### `navigator_auth/passkey/sql/001_passkey_credentials.sql` — CREATE
```sql
-- Passkey (WebAuthn) credentials — FEAT-101.
-- {schema} / {users_table} are substituted by passkey/migrations.py.
-- Additive and idempotent: safe to run on every startup.
CREATE SCHEMA IF NOT EXISTS {schema};

CREATE TABLE IF NOT EXISTS {schema}.user_passkey_handles (
    user_id      integer NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    rp_id        varchar(253) NOT NULL,
    user_handle  bytea NOT NULL UNIQUE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, rp_id)
);

CREATE TABLE IF NOT EXISTS {schema}.user_credentials (
    credential_id  bytea PRIMARY KEY,
    user_id        integer NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    rp_id          varchar(253) NOT NULL,
    public_key     bytea NOT NULL,
    sign_count     bigint NOT NULL DEFAULT 0,
    transports     text[],
    aaguid         uuid,
    device_type    varchar(32),
    backed_up      boolean NOT NULL DEFAULT false,
    label          varchar(128),
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_used_at   timestamptz
);
CREATE INDEX IF NOT EXISTS user_credentials_user_rp_idx
    ON {schema}.user_credentials (user_id, rp_id);
```
**Why**: This is the DDL from spec §2, verbatim apart from the placeholders.

### `navigator_auth/passkey/migrations.py` — CREATE
```python
"""Passkey tables — idempotent startup migration (FEAT-101).

Mirrors ``navigator_auth/identity/migrations.py``. Run by
``PasskeyAuth.on_startup`` so the tables only exist when the backend is enabled.
"""
import logging
from pathlib import Path
from typing import Any

from ..conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE

logger = logging.getLogger("navigator.passkey")

SQL_DIR = Path(__file__).parent / "sql"

_MIGRATION_FILES = ("001_passkey_credentials.sql",)


def render_sql(sql: str) -> str:
    """Substitute ``{schema}`` and ``{users_table}`` in a migration file."""
    return sql.replace("{schema}", AUTH_DB_SCHEMA).replace("{users_table}", AUTH_USERS_TABLE)


async def _run_sql(db_pool: Any, sql: str) -> None:
    # FILL IN: copy identity/migrations.py `_run_sql` verbatim (acquire() as async context
    #          manager OR awaitable, then release/close) — bounded by: identical behaviour to
    #          the identity runner, so both work with the same `app["authdb"]` pool.
    raise NotImplementedError


async def ensure_passkey_tables(db_pool: Any) -> None:
    """Create the passkey tables if they don't already exist.

    Args:
        db_pool: asyncpg-compatible pool with an ``acquire()`` method (``app["authdb"]``).
    """
    for filename in _MIGRATION_FILES:
        sql = render_sql((SQL_DIR / filename).read_text())
        await _run_sql(db_pool, sql)
    logger.info("Passkey tables ensured.")


async def setup_passkey_tables(db_pool: Any) -> None:
    """Non-blocking wrapper used at startup: logs errors, never raises."""
    try:
        await ensure_passkey_tables(db_pool)
    except Exception as err:  # pylint: disable=W0703
        logger.error("Failed to ensure passkey tables: %s", err)
```
**Why**: Never raising at startup keeps a DB hiccup from taking down every other backend. This is
the same trade-off `setup_identity_columns` makes.

### `navigator_auth/passkey/__init__.py` — CREATE
```python
"""Passkey (WebAuthn) support for navigator-auth (FEAT-101).

Importing this package never imports ``webauthn`` (optional extra ``passkey``).
"""
from .types import ChallengeState, RelyingParty, StoredCredential

__all__ = ("ChallengeState", "RelyingParty", "StoredCredential")
```

### `tests/test_passkey_migrations.py` — CREATE
```python
"""FEAT-101 TASK-87 — passkey migration rendering and idempotency."""
import pytest

from navigator_auth.passkey.migrations import render_sql, ensure_passkey_tables, SQL_DIR


def test_render_sql_substitutes_placeholders():
    """No {schema}/{users_table} placeholder survives rendering."""
    sql = render_sql((SQL_DIR / "001_passkey_credentials.sql").read_text())
    assert "{schema}" not in sql and "{users_table}" not in sql


async def test_ensure_passkey_tables_uses_pool(fake_pool):
    # FILL IN: a minimal fake pool whose acquire() is an async context manager and records
    #          execute() calls; assert one execute per migration file.
    ...


@pytest.mark.asyncio
async def test_migration_idempotent():
    """Live Postgres: ensure_passkey_tables twice succeeds (spec §4)."""
    # FILL IN: build an asyncdb/asyncpg pool from navigator_auth.conf default_dsn the way
    #          tests/test_basic_auth.py does, skip if unreachable, run ensure twice.
```

### FILL IN checklist
- [ ] `_run_sql` copied from `identity/migrations.py`.
- [ ] Fake-pool unit test.
- [ ] Live idempotency test, skipped without Postgres.

---

## Acceptance Criteria

- [ ] `from navigator_auth.passkey import RelyingParty, StoredCredential, ChallengeState` works without `webauthn` installed.
- [ ] Running `ensure_passkey_tables` twice against live Postgres succeeds (AC3, migration part).
- [ ] `pytest tests/test_passkey_migrations.py -v` passes (the live test may skip).
- [ ] `ruff check navigator_auth/passkey tests/test_passkey_migrations.py` is clean.

---

## Test Specification

See the `tests/test_passkey_migrations.py` blueprint above (spec §4: `test_migration_idempotent`).

---

## Agent Instructions

1. Read the spec (Module 2, §2 Data Models).
2. Confirm TASK-86 is in `sdd/tasks/completed/`.
3. Set this task to `"in-progress"` in `sdd/tasks/index/passkey-support-backend.json`.
4. Implement inside `.worktrees/feat-FEAT-101-passkey-support-backend`.
5. Verify the acceptance criteria.
6. Move this file to `sdd/tasks/completed/`, set the index entry to `"done"`, and fill in the Completion Note.

---

## Completion Note

**Completed by**:
**Date**:
**Notes**:
**Deviations from spec**: none
