# TASK-175: Durable recovery-consumption and OAuth-generation state

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Spec §3 Module 4, "Durable recovery and token revocation contract" (G4, G9; building blocks for AC28,
AC30, AC32). Two pieces of state must live in Postgres so they commit or roll back **in the same
transaction** as a credential change:

- `{schema}.recovery_confirm_consumptions` — the SHA-256 digest of each consumed recovery confirmation.
  The committed digest, not the Redis record, is what makes a confirmation single-use (TASK-180).
- `{schema}.oauth_user_generation` — one row per user, default generation 0. `password_reset` and
  recovery increment it (TASK-179, TASK-180); every OAuth code, device carrier, access and refresh token is
  stamped with the generation it was minted under and rejected once it differs (TASK-185).

The spec gives no location for this migration. It is decided here: a new package
`navigator_auth/security_state/` (SQL + migration runner + store helpers), applied from
`AuthHandler.auth_startup` next to the vault and identity migrations, because both tables are required
**regardless of the MFA setting** (MFA migrations only run when 2FA is on).

This task is **exclusive** (`parallel: false`): its tests apply DDL against the shared live test database.

---

## Scope

- Create `navigator_auth/security_state/sql/001_security_state.sql` (both tables, idempotent).
- Create `navigator_auth/security_state/migrations.py`: `SECURITY_STATE_TABLES`, `ensure_security_state_tables`,
  `security_state_tables_present`, `setup_security_state_tables` (never raises).
- Create `navigator_auth/security_state/store.py`: `GENERATION_CLAIM`, `SecurityStateError`, `generation_of`,
  `stamp_generation`, `current_generation`, `increment_generation`, `record_confirmation`,
  `confirmation_recorded`, `generation_matches` — signatures fixed below.
- Create `navigator_auth/security_state/__init__.py` exporting the public names.
- Wire `await setup_security_state_tables(app["authdb"])` into `AuthHandler.auth_startup` and log CRITICAL when it
  returns False.
- Write `tests/test_mfa_review_fixes_revocation.py`.

**NOT in scope**:
- Calling these helpers from `password_reset` (TASK-179), recovery (TASK-180) or any OAuth endpoint/middleware
  (TASK-185) — this task only provides them.
- Strict session revocation / `PasswordRecoveryHandler.session_revoker()` (TASK-176).
- A purge job for expired consumption markers — rows are retained (the contract requires "at least until the signed
  confirmation expires"); purging is a follow-up.
- Any per-user advisory lock — callers pass a connection that already holds one (TASK-171's `advisory_user_lock`).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/security_state/__init__.py` | CREATE | Package exports |
| `navigator_auth/security_state/migrations.py` | CREATE | Idempotent migration runner + readiness probe |
| `navigator_auth/security_state/store.py` | CREATE | Generation + consumption helpers (connection-scoped) |
| `navigator_auth/security_state/sql/001_security_state.sql` | CREATE | `recovery_confirm_consumptions`, `oauth_user_generation` |
| `navigator_auth/auth.py` | MODIFY | Apply the migration in `auth_startup` |
| `tests/test_mfa_review_fixes_revocation.py` | CREATE | Unit + live tests for the store and migration |

---

## Codebase Contract (Anti-Hallucination)

> **CRITICAL**: This section contains VERIFIED code references from the actual codebase.
> The implementing agent MUST use these exact imports, class names, and method signatures.
> **DO NOT** invent, guess, or assume any import, attribute, or method not listed here.
> If you need something not listed, VERIFY it exists first with `grep` or `read`.
>
> Verified against `0b80d88` (branch `feat-FEAT-106-basicauth-otp-2fa`).

### Verified Imports
```python
from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE          # verified: navigator_auth/conf.py:33,34
from navigator_auth.mfa.migrations import render_sql, _with_conn           # verified: navigator_auth/mfa/migrations.py:24,36
from tests.fixtures.mfa import mfa_db, mfa_user_factory                    # verified: tests/fixtures/mfa.py:59,76
# navigator_auth/auth.py already imports (module-level, relative):
from .identity.migrations import setup_identity_columns                    # verified: navigator_auth/auth.py:38
```

### Existing Signatures to Use
```python
# navigator_auth/mfa/migrations.py
def render_sql(sql: str) -> str                    # line 24 — replaces {schema} and {users_table} (str.replace, so '%' is safe)
async def _with_conn(db_pool: Any, fn: Any) -> Any # line 36 — runs fn(conn) on either pool acquire shape
def _raise_on_execute_error(result, filename)      # line 62 — pattern only: asyncdb execute returns (result, error); raises MfaStorageError
async def mfa_tables_present(db_pool) -> bool      # line 96 — pattern for the to_regclass probe
async def setup_mfa_tables(db_pool) -> bool        # line 117 — pattern for "never raises, returns bool"

# navigator_auth/auth.py
class AuthHandler:
    async def auth_startup(self, app):             # line 179
        # ... line 190: setup_vault_keyring(app)
        # line 191: if "authdb" in app:
        # line 192:     await setup_vault_tables(app["authdb"])
        # line 193:     await setup_identity_columns(app["authdb"])
    self.logger = logging.getLogger(name="Nav.Auth")   # line 171

# navigator_auth/mfa/security.py — transaction pattern on an asyncdb connection
await conn.transaction(); await conn.fetchval(...); await conn.rollback(); await conn.commit()  # lines 60-74

# asyncdb pg connection (as used across navigator_auth/mfa): fetchval(sql, *args) RAISES on DB errors;
# execute(sql) does NOT raise — it returns (result, error) (project memory asyncdb-execute-never-raises).
```

### Does NOT Exist
- ~~`navigator_auth/security_state/`~~ (package, tables, every helper) — created by this task.
- ~~`navigator_auth/handlers/auth.py`~~ — does not exist (spec M4 path list is wrong); the auth handler is `navigator_auth/auth.py`.
- ~~`advisory_user_lock` / `LOCK_CONNECTION`~~ — created by TASK-171; not used here.
- ~~`OauthAuthorizationCode.generation` / `OauthRefreshToken.generation`~~ — created by TASK-185.
- ~~`SessionRevoker.revoke_user(..., strict=...)`, `PasswordRecoveryHandler.session_revoker`~~ — TASK-176.
- ~~a `navigator_auth.mfa.migrations.ensure_tables(files=...)` generic runner~~ — none; each package has its own `_MIGRATION_FILES` loop.
- ~~`app["security_state_ready"]`~~ — do not store a flag on the app at startup (aiohttp warns on mutating a started app); callers fail closed on the DB error instead.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/security_state/__init__.py", "action": "CREATE"},
    {"path": "navigator_auth/security_state/migrations.py", "action": "CREATE"},
    {"path": "navigator_auth/security_state/store.py", "action": "CREATE"},
    {"path": "navigator_auth/security_state/sql/001_security_state.sql", "action": "CREATE"},
    {"path": "navigator_auth/auth.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_review_fixes_revocation.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/mfa/migrations.py#render_sql",
    "sym:navigator_auth/mfa/migrations.py#_with_conn",
    "sym:navigator_auth/auth.py#AuthHandler.auth_startup"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
```python
# navigator_auth/mfa/migrations.py:77-134 — ensure (raise on execute error slot), probe (to_regclass), setup (never raises)
async def setup_mfa_tables(db_pool: Any) -> bool:
    if db_pool is None:
        logger.error("MFA tables unavailable: NoneType")
        return False
    try:
        await ensure_mfa_tables(db_pool)
        return await mfa_tables_present(db_pool)
    except Exception as err:  # pylint: disable=W0703
        logger.error("MFA tables unavailable: %s", type(err).__name__)
        return False
```

### Key Constraints
- **Every write is `fetchval … RETURNING`** — asyncdb `conn.execute` swallows DB errors, which would turn a failed
  marker insert or generation bump into a silent success (project memory `asyncdb-execute-never-raises`).
- The store functions take a **caller-owned connection** and never commit, roll back or acquire — they must run
  inside the caller's transaction (the credential-change transaction of TASK-179/180, the token-issuance lock of
  TASK-185). Only `generation_matches` (a read-only validation used by resource servers) acquires its own connection.
- Any DB failure raises `SecurityStateError` (never returns a default): callers fail closed (503, `inactive`, 401).
- Generation encoding (spec M9 "Generation encoding"): generation 0 is an **absent** claim/field; positive values are
  explicit; on validation a missing claim means 0. `stamp_generation` therefore never writes `0`.
- Never store raw confirmation tokens: `record_confirmation` takes the 64-char lowercase hex SHA-256 digest and
  rejects anything else with `ValueError` (programming error, not storage error).
- No secrets in logs (digests are not secrets, but log only the user id). Google docstrings + type hints; module logger.
- The migration runs in `auth_startup` for every deployment, MFA on or off.

### References in Codebase
- `navigator_auth/mfa/migrations.py` — runner pattern (reuse `render_sql`, `_with_conn`)
- `navigator_auth/mfa/security.py:94-108` — `bump_version` upsert-RETURNING pattern to copy for `increment_generation`
- `navigator_auth/handlers/recovery/store.py:37` — `_hash_token` (sha256 hex) is how callers will compute the digest

---

## Implementation Blueprint

> **CRITICAL — Executor-ready starting point.** Write each block below to its declared
> path nearly verbatim, then complete every `# FILL IN:` marker. Blocks were derived
> from the spec's Interface Skeletons and re-verified against the Codebase Contract
> above when this task was written. This is NOT the full implementation:
> business-logic branches, edge cases and test bodies are `FILL IN` stubs by design.
> Never change a signature, class name, or file path the blueprint fixes.

### Steps (in order)
1. Create the SQL file — *why*: the tables are the durable source of truth that later tasks write inside their transactions.
2. Create `migrations.py` — *why*: startup must create the tables idempotently and report (not raise) when it cannot.
3. Create `store.py` — *why*: one place owns the SQL and the generation encoding so TASK-179/180/185 cannot diverge.
4. Create `__init__.py` — *why*: dependent tasks import from `navigator_auth.security_state`.
5. Wire `auth.py` — *why*: the tables must exist whether or not 2FA is enabled (spec M4 contract).
6. Write the tests and run them — *why*: prove fail-closed reads, single-use markers and transactional rollback.

### `navigator_auth/security_state/sql/001_security_state.sql` (CREATE)
```sql
-- FEAT-106 review fixes (spec M4): durable credential-change state, required regardless of MFA.
-- {schema} / {users_table} are substituted by security_state/migrations.py.
-- Additive and idempotent: safe to run on every startup.
CREATE SCHEMA IF NOT EXISTS {schema};

-- One row per consumed recovery confirmation: SHA-256 hex digest only, never the raw token.
-- Written on the recovery transaction's connection; the committed row makes the confirmation single-use.
CREATE TABLE IF NOT EXISTS {schema}.recovery_confirm_consumptions (
    digest      CHAR(64)    PRIMARY KEY,
    user_id     bigint      NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS recovery_confirm_consumptions_expires_idx
    ON {schema}.recovery_confirm_consumptions (expires_at);

-- OAuth credential generation per user. Absent row == generation 0. Incremented by password_reset and
-- recovery in the same transaction as the password write; every user OAuth artifact carries the
-- generation it was minted under and is rejected once it differs.
CREATE TABLE IF NOT EXISTS {schema}.oauth_user_generation (
    user_id     bigint      PRIMARY KEY REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    generation  bigint      NOT NULL DEFAULT 0 CHECK (generation >= 0),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```
**Why this shape**: plan-fixed DDL. `recovery_confirm_consumptions.user_id` has no FK on purpose — a marker must
survive (and keep blocking replay) even if it outlives a user row edit; the generation table cascades with the user.

### `navigator_auth/security_state/migrations.py` (CREATE)
```python
"""Durable security-state tables — idempotent startup migration (FEAT-106 review fixes, spec M4)."""

import logging
from pathlib import Path
from typing import Any

from ..conf import AUTH_DB_SCHEMA
from ..mfa.migrations import _with_conn, render_sql
from .store import SecurityStateError

logger = logging.getLogger("navigator.auth.security_state")

SQL_DIR = Path(__file__).parent / "sql"
_MIGRATION_FILES = ("001_security_state.sql",)
SECURITY_STATE_TABLES = ("recovery_confirm_consumptions", "oauth_user_generation")


async def ensure_security_state_tables(db_pool: Any) -> None:
    """Create the security-state tables if missing.

    Args:
        db_pool: Database pool (``app["authdb"]``).

    Raises:
        SecurityStateError: If asyncdb reports an execution error.
    """
    for filename in _MIGRATION_FILES:
        sql = render_sql((SQL_DIR / filename).read_text())

        async def _apply(conn: Any, _sql: str = sql, _name: str = filename) -> None:
            result = await conn.execute(_sql)
            # FILL IN: raise SecurityStateError(f"security-state migration {_name} failed: <ErrClass>") when
            #          `result` is an asyncdb (result, error) pair with a populated error slot — bounded by
            #          mfa/migrations.py:62-74 (same detection, different exception type).

        await _with_conn(db_pool, _apply)
    logger.info("Security-state tables ensured.")


async def security_state_tables_present(db_pool: Any) -> bool:
    """Return whether every security-state relation exists (to_regclass probe)."""
    names = [f"{AUTH_DB_SCHEMA}.{table}" for table in SECURITY_STATE_TABLES]

    async def _probe(conn: Any) -> bool:
        count = await conn.fetchval(
            "SELECT count(*) FROM unnest($1::text[]) AS t(name) WHERE to_regclass(t.name) IS NOT NULL",
            names,
        )
        return count == len(SECURITY_STATE_TABLES)

    return await _with_conn(db_pool, _probe)


async def setup_security_state_tables(db_pool: Any) -> bool:
    """Ensure the tables and report readiness; never raises (startup must not fail).

    Returns:
        True only after successful DDL and a successful relation probe.
    """
    if db_pool is None:
        logger.critical("Security-state tables unavailable: no authdb pool")
        return False
    try:
        await ensure_security_state_tables(db_pool)
        ready = await security_state_tables_present(db_pool)
    except Exception as err:  # pylint: disable=W0703
        logger.critical("Security-state tables unavailable: %s", type(err).__name__)
        return False
    if not ready:
        logger.critical("Security-state tables missing; password reset, recovery and OAuth tokens will fail closed")
    return ready
```
**Why this shape**: mirrors `mfa/migrations.py` so operators see one migration idiom; CRITICAL (not ERROR) because
without these tables every reset, recovery and OAuth user-token validation answers 503/inactive.

### `navigator_auth/security_state/store.py` (CREATE)
```python
"""Durable credential-change state helpers (FEAT-106 review fixes, spec M4).

Every write helper runs on the CALLER's connection inside the caller's transaction and never commits,
rolls back or acquires. Any database failure raises :class:`SecurityStateError` so callers fail closed.
"""

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from ..conf import AUTH_DB_SCHEMA

GENERATION_CLAIM = "gen"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_GENERATION_TABLE = f"{AUTH_DB_SCHEMA}.oauth_user_generation"
_CONSUMPTION_TABLE = f"{AUTH_DB_SCHEMA}.recovery_confirm_consumptions"


class SecurityStateError(Exception):
    """Durable security state could not be read or written; never shown to a client."""


def generation_of(payload: Mapping[str, Any]) -> int:
    """Return the generation an OAuth artifact carries (missing/None -> 0).

    Raises:
        SecurityStateError: For a bool, non-int or negative value (a forged or corrupt claim).
    """
    # FILL IN: value = payload.get(GENERATION_CLAIM); None -> 0; reject bool, non-int and < 0 — bounded by spec M9
    #          "Generation encoding" (missing means 0) and fail-closed posture.


def stamp_generation(payload: dict, generation: int) -> dict:
    """Set ``GENERATION_CLAIM`` only when ``generation > 0`` (0 stays absent for legacy compatibility); return ``payload``."""
    # FILL IN: ValueError for negative; mutate and return payload — bounded by AC24 (2FA-off gen-0 payload keys unchanged).


async def current_generation(conn: Any, user_id: int) -> int:
    """Return the user's OAuth credential generation (absent row -> 0) on ``conn``."""
    try:
        value = await conn.fetchval(f"SELECT generation FROM {_GENERATION_TABLE} WHERE user_id = $1", int(user_id))
    except Exception as err:
        raise SecurityStateError(f"generation read failed: {type(err).__name__}") from err
    return 0 if value is None else int(value)


async def increment_generation(conn: Any, user_id: int) -> int:
    """Increment and return the user's generation inside the caller's transaction."""
    sql = (
        f"INSERT INTO {_GENERATION_TABLE} (user_id, generation) VALUES ($1, 1) "
        f"ON CONFLICT (user_id) DO UPDATE SET generation = {_GENERATION_TABLE}.generation + 1, updated_at = now() "
        f"RETURNING generation"
    )
    # FILL IN: fetchval(sql, int(user_id)); None or any exception -> SecurityStateError — bounded by
    #          mfa/security.py:94-108 (bump_version) and AC28/AC30 (the increment commits with the password or not at all).


async def record_confirmation(conn: Any, digest: str, user_id: int, expires_at: datetime) -> bool:
    """Insert a consumption marker; return False when the digest was already recorded (replay).

    Raises:
        ValueError: ``digest`` is not a 64-char lowercase hex SHA-256 digest.
        SecurityStateError: On any database failure.
    """
    if not isinstance(digest, str) or not _DIGEST.match(digest):
        raise ValueError("digest must be a lowercase hex SHA-256 digest")
    # FILL IN: INSERT (digest, user_id, expires_at) ... ON CONFLICT (digest) DO NOTHING RETURNING digest via fetchval;
    #          None -> False, value -> True, exception -> SecurityStateError — bounded by AC32 (exactly-once reuse).


async def confirmation_recorded(conn: Any, digest: str) -> bool:
    """Return whether ``digest`` has a committed (or same-transaction) consumption marker."""
    # FILL IN: SELECT 1 ... WHERE digest = $1 via fetchval; exception -> SecurityStateError.


async def generation_matches(db_pool: Any, user_id: int, presented: int) -> bool:
    """Resource-server check: does ``presented`` equal the user's current generation? (own pooled read)

    Raises:
        SecurityStateError: When the generation cannot be read (callers answer 503 / inactive / 401).
    """
    # FILL IN: async with await db_pool.acquire() as conn: return await current_generation(conn, user_id) == int(presented)
    #          — wrap acquire failures in SecurityStateError; bounded by AC30 ("unavailable generation storage fails closed").
```
**Why this shape**: plan-fixed public API (TASK-179/180/185 call these exact names). The DB helpers are thin on
purpose: locking and transaction boundaries belong to the callers.

### `navigator_auth/security_state/__init__.py` (CREATE)
```python
"""Durable credential-change state: recovery consumption markers and OAuth credential generation (FEAT-106)."""

from .migrations import (
    SECURITY_STATE_TABLES,
    ensure_security_state_tables,
    security_state_tables_present,
    setup_security_state_tables,
)
from .store import (
    GENERATION_CLAIM,
    SecurityStateError,
    confirmation_recorded,
    current_generation,
    generation_matches,
    generation_of,
    increment_generation,
    record_confirmation,
    stamp_generation,
)

__all__ = (
    "SECURITY_STATE_TABLES",
    "ensure_security_state_tables",
    "security_state_tables_present",
    "setup_security_state_tables",
    "GENERATION_CLAIM",
    "SecurityStateError",
    "confirmation_recorded",
    "current_generation",
    "generation_matches",
    "generation_of",
    "increment_generation",
    "record_confirmation",
    "stamp_generation",
)
```

### `navigator_auth/auth.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'from .identity.migrations import setup_identity_columns' navigator_auth/auth.py)
# AFTER — insert below `from .identity.migrations import setup_identity_columns` (verified: navigator_auth/auth.py:38)
from .security_state import setup_security_state_tables

# occurrences: 1 (verified: grep -c 'await setup_identity_columns(app\["authdb"\])' navigator_auth/auth.py)
# AFTER — insert below `            await setup_identity_columns(app["authdb"])` (verified: navigator_auth/auth.py:193), same indent
            # FEAT-106 review fixes (spec M4): required with MFA on or off; logs CRITICAL when not ready.
            await setup_security_state_tables(app["authdb"])
```
**Why**: same place and style as the vault/identity migrations; `setup_security_state_tables` never raises, so a
database hiccup cannot abort startup — reset/recovery/OAuth fail closed later instead.

### `tests/test_mfa_review_fixes_revocation.py` (CREATE)
```python
"""FEAT-106 review fixes — durable security state (spec M4 contract; building blocks of AC28, AC30, AC32)."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from navigator_auth.security_state import (
    GENERATION_CLAIM,
    SECURITY_STATE_TABLES,
    SecurityStateError,
    confirmation_recorded,
    current_generation,
    ensure_security_state_tables,
    generation_matches,
    generation_of,
    increment_generation,
    record_confirmation,
    setup_security_state_tables,
    stamp_generation,
)
from navigator_auth.security_state.migrations import SQL_DIR, _MIGRATION_FILES
from tests.fixtures.mfa import mfa_db, mfa_user_factory  # noqa: F401


def test_generation_encoding_absent_means_zero():
    """Missing claim -> 0; 0 is never stamped; positive values round-trip (spec M9 Generation encoding, AC24)."""
    assert generation_of({}) == 0
    assert stamp_generation({"sub": "1"}, 0) == {"sub": "1"}
    assert generation_of(stamp_generation({}, 3)) == 3 and GENERATION_CLAIM == "gen"


@pytest.mark.parametrize("bad", [True, "2", -1, 1.5])
def test_generation_of_rejects_forged_values(bad):
    with pytest.raises(SecurityStateError):
        generation_of({GENERATION_CLAIM: bad})


def test_migration_declares_both_tables():
    sql = "\n".join((SQL_DIR / name).read_text() for name in _MIGRATION_FILES)
    for table in SECURITY_STATE_TABLES:
        assert f"CREATE TABLE IF NOT EXISTS {{schema}}.{table}" in sql


@pytest.mark.asyncio
async def test_setup_never_raises():
    assert await setup_security_state_tables(None) is False
    # FILL IN: a fake pool whose execute returns (None, RuntimeError("x")) and one whose fetchval raises -> False


@pytest_asyncio.fixture
async def state_db(mfa_db):
    await ensure_security_state_tables(mfa_db)
    yield mfa_db


@pytest.mark.asyncio
async def test_generation_increment_and_match(state_db, mfa_user_factory):
    """Absent row is 0; increments are monotonic; generation_matches compares to the committed value."""
    # FILL IN: user = await mfa_user_factory(); on a conn: current_generation == 0; increment -> 1, -> 2;
    #          generation_matches(state_db, uid, 2) True, (uid, 0) False.


@pytest.mark.asyncio
async def test_generation_matches_fails_closed():
    """An unreadable generation raises SecurityStateError, never True (AC30)."""
    # FILL IN: a pool whose acquire() raises -> pytest.raises(SecurityStateError)


@pytest.mark.asyncio
async def test_record_confirmation_single_use_and_transactional(state_db, mfa_user_factory):
    """Second insert of a digest -> False; a rolled-back insert leaves no marker (AC32 building block)."""
    digest = hashlib.sha256(secrets.token_bytes(16)).hexdigest()
    expires = datetime.now(timezone.utc) + timedelta(minutes=15)
    # FILL IN: inside conn.transaction(): record_confirmation -> True, rollback -> confirmation_recorded False;
    #          then commit path: True, then False on replay; ValueError for an uppercase/short digest;
    #          delete the digests in a finally block.
```
**Why this shape**: the pure tests pin the encoding every other task relies on; the live tests use the existing
`mfa_db` skip-if-no-Postgres fixture and the user factory (the generation table has an FK to users).

### FILL IN checklist
- [ ] `migrations.py::ensure_security_state_tables` — execute-error detection; bounded by mfa/migrations.py:62-74
- [ ] `store.py::generation_of` / `stamp_generation` — encoding rules; bounded by spec M9 Generation encoding, AC24
- [ ] `store.py::increment_generation` / `record_confirmation` / `confirmation_recorded` / `generation_matches` — fetchval + SecurityStateError; bounded by AC28, AC30, AC32
- [ ] test bodies marked FILL IN

---

## Acceptance Criteria

- [ ] `setup_security_state_tables(app["authdb"])` runs in `AuthHandler.auth_startup` with MFA on or off, creates both tables idempotently and never raises.
- [ ] `current_generation` returns 0 for an absent row; `increment_generation` returns 1, 2, … and commits/rolls back with the caller's transaction.
- [ ] `record_confirmation` returns False on a replayed digest, rejects non-digest input with `ValueError`, and a rolled-back insert leaves no marker.
- [ ] `generation_matches` raises `SecurityStateError` when storage is unavailable (fail closed, AC30).
- [ ] `generation_of({}) == 0` and `stamp_generation(p, 0)` leaves `p` unchanged (AC24 compatibility).
- [ ] All tests pass: `pytest tests/test_mfa_review_fixes_revocation.py -q`
- [ ] Imports work: `from navigator_auth.security_state import setup_security_state_tables, increment_generation, generation_matches`.

---

## Validation Commands

- `pytest tests/test_mfa_review_fixes_revocation.py -q`

---

## Test Specification

```python
# tests/test_mfa_review_fixes_revocation.py — scaffold in the Implementation Blueprint.
# Required: encoding tests (pure), migration-declares-tables (pure), setup-never-raises (fake pool),
# generation increment/match (live), generation fails closed (fake pool), consumption single-use + rollback (live).
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the existing feature worktree `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa`** (branch
   `feat-FEAT-106-basicauth-otp-2fa`, PR #633) — never on `dev`.
2. **Read the spec** at the path listed above (§3 Module 4 "Durable recovery and token revocation contract", §3 Module 9 "Generation encoding").
3. **Check dependencies** — none.
4. **Verify the Codebase Contract** — re-run the two `grep -c` anchors in `navigator_auth/auth.py`; update the contract first if they moved.
5. **Update status** in `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json` → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** — start from the Implementation Blueprint blocks, complete every `# FILL IN:` marker, and never change a signature or path the blueprint fixes.
7. **Verify** all acceptance criteria — run the Validation Commands (exclusive task: no concurrent DDL).
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`).
9. **Close the task** with `parrot sdd task close TASK-175 basicauth-otp-2fa-review-fixes verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none (the migration location is a task-time decision; spec M4 left it open).
