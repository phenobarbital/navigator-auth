# TASK-166: Startup stops running DDL — read-only pending-migration check

**Feature**: FEAT-110 — navauth self upgrade database migration command
**Spec**: `sdd/specs/new-command-migration.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-160
**Assigned-to**: unassigned

---

## Context

Implements spec §3 **Module 6** (goal G6) for the two call sites on `dev`:

- `AuthHandler.auth_startup` runs vault and identity DDL on every boot with the
  runtime user, logging failures only. It now reads the ledger and logs **one**
  warning listing what is pending, naming `navauth self upgrade`; a failing check
  never blocks startup.
- `PasskeyAuth.on_startup` runs the passkey DDL. It now checks that the two passkey
  tables exist and raises `ConfigError` telling the operator to run
  `navauth self upgrade` when they do not (user decision: "Fail startup").

The MFA startup path (FEAT-106) is handled in TASK-170 once FEAT-106 is on `dev`.

---

## Scope

- Create `navigator_auth/migrations/startup.py`: `pending_migrations`,
  `warn_pending_migrations`, `tables_present`.
- `navigator_auth/auth.py`: replace the `setup_vault_tables` / `setup_identity_columns`
  awaits in `auth_startup` with `await warn_pending_migrations(app["authdb"])`; drop
  both now-unused imports; fix the comment above `setup_vault_keyring(app)`.
- `navigator_auth/backends/passkey.py`: replace the `ensure_passkey_tables` try/except
  in `on_startup` with the `tables_present` check; swap the import.
- Create `tests/unit/migrations/test_startup.py`.

**NOT in scope**: `navigator_auth/vault/integration.py::setup_vault_tables` stays (tests
patch it) — it is just no longer called by `auth_startup`. The MFA call in
`navigator_auth/mfa/services.py` (TASK-170). The legacy `ensure_*` modules (TASK-164).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/migrations/startup.py` | CREATE | Read-only startup checks |
| `navigator_auth/auth.py` | MODIFY | `auth_startup` warns instead of migrating |
| `navigator_auth/backends/passkey.py` | MODIFY | Presence check instead of DDL |
| `tests/unit/migrations/test_startup.py` | CREATE | Startup tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `87c9b9c` (2026-11-11).

### Verified Imports
```python
from navigator_auth.migrations.runner import MigrationState, MigrationStatus, acquire_raw, get_status  # TASK-160
from navigator_auth.exceptions import ConfigError      # verified: navigator_auth/exceptions.py:26; already imported in backends/passkey.py:20
from navigator_auth import conf as auth_conf           # verified: navigator_auth/backends/passkey.py:18 (use auth_conf.AUTH_DB_SCHEMA)
from navigator_auth.auth import AuthHandler            # verified: navigator_auth/auth.py (class AuthHandler; auth_startup at line 178)
```

### Existing Signatures to Use
```python
# navigator_auth/auth.py
from .vault.integration import (                       # lines 31-37
    load_vault_for_session,
    setup_vault_keyring,
    setup_vault_tables,                                # line 34 — remove (only other use is line 191)
    VAULT_KEYRING_APP_KEY,
    VAULT_SESSION_KEY,
)
from .identity.migrations import setup_identity_columns   # line 38 — replace
class AuthHandler:
    async def auth_startup(self, app):                 # line 178
        # 182-187: backends' on_startup, wrapped into AuthException
        # Create vault tables if they don't exist (non-blocking)   # line 188
        setup_vault_keyring(app)                       # line 189 — KEEP
        if "authdb" in app:                            # line 190
            await setup_vault_tables(app["authdb"])    # line 191
            await setup_identity_columns(app["authdb"])  # line 192
        # 193-199: exclude providers (self._exclude_providers, self.register_exclusions, self.logger)
        await self._load_subnet_service_tags()         # line 203

# navigator_auth/backends/passkey.py
from ..passkey.migrations import ensure_passkey_tables   # line 30 — replace
class PasskeyAuth(BasicAuth):
    async def on_startup(self, app: web.Application) -> None:   # line 93
        await super().on_startup(app)                  # line 95
        # 96-99: lazy `import webauthn`; ImportError → ConfigError
        self._store = PasskeyStore(app["authdb"])      # line 102
        try:                                           # line 103
            await ensure_passkey_tables(app["authdb"]) # line 104
        except Exception as err:  # pylint: disable=W0703        # line 105
            raise ConfigError(f"PasskeyAuth: could not create passkey tables: {err}") from err   # line 106

# navigator_auth/migrations/runner.py (TASK-160)
@asynccontextmanager
async def acquire_raw(db_pool: Any) -> AsyncIterator[Any]     # asyncdb conn unwrapped; release handled
async def get_status(conn, sets=None) -> list[MigrationStatus] # read-only, never creates the ledger
```

Passkey tables (verified, `001_passkey_credentials.sql` lines 6 and 14):
`{schema}.user_passkey_handles`, `{schema}.user_credentials`.

Tests that must keep passing: `tests/test_passkey_backend_unit.py::test_on_startup_without_webauthn_raises`
(ConfigError before the table check), `tests/unit/test_exclude_provider.py`,
`tests/unit/vault/test_integration.py` (tests `setup_vault_tables` directly). No test imports
`setup_vault_tables` or `setup_identity_columns` from `navigator_auth.auth` (verified by grep).

### Does NOT Exist
- ~~`setup_vault_tables` in `navigator_auth/vault/migrations.py`~~ — it is in `navigator_auth/vault/integration.py:102`.
- ~~`navigator_auth/mfa/`~~ — not on `dev`; nothing MFA here (TASK-170).
- ~~A ledger write at startup~~ — startup is read-only; `get_status` never creates the ledger.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/migrations/startup.py", "action": "CREATE"},
    {"path": "navigator_auth/auth.py", "action": "MODIFY"},
    {"path": "navigator_auth/backends/passkey.py", "action": "MODIFY"},
    {"path": "tests/unit/migrations/test_startup.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/auth.py#AuthHandler.auth_startup",
    "sym:navigator_auth/backends/passkey.py#PasskeyAuth.on_startup",
    "sym:navigator_auth/migrations/runner.py#acquire_raw",
    "sym:navigator_auth/migrations/runner.py#get_status"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- `warn_pending_migrations` never raises; on any error it logs a WARNING that the migration
  state could not be verified (and suggests `navauth self upgrade --check`), at INFO when all
  is applied (spec M6 docstring).
- Exactly one WARNING for the pending case, listing `set/filename (state)` for each file and the
  command `navauth self upgrade` (AC "logs one warning naming them").
- The passkey check runs no DDL; a probe failure is wrapped in `ConfigError` too, so the backend
  keeps failing fast with a clear message.

---

## Implementation Blueprint

### Steps (in order)
1. Write `startup.py` — *why*: both call sites import it.
2. Edit `auth.py` and `backends/passkey.py` per the blocks.
3. Write `test_startup.py`; run the Validation Commands (the three existing suites prove nothing else moved).

### `navigator_auth/migrations/startup.py` (CREATE)
```python
"""Startup migration checks — read-only (FEAT-110, spec M6).

Application startup no longer applies schema changes; ``navauth self upgrade`` does.
These helpers only read the ledger and the catalog.
"""
from __future__ import annotations

import logging
from typing import Any

from .runner import MigrationState, MigrationStatus, acquire_raw, get_status

logger = logging.getLogger("navigator.migrations")


async def pending_migrations(db_pool: Any) -> list[MigrationStatus]:
    """Files whose state is not APPLIED, read through ``acquire_raw(db_pool)``."""
    async with acquire_raw(db_pool) as conn:
        return [status for status in await get_status(conn) if status.state is not MigrationState.APPLIED]


async def warn_pending_migrations(db_pool: Any) -> None:
    """Log one WARNING naming the pending/changed files and the command to run.

    Never raises: any error is logged as a warning that the migration state could not
    be verified. Logs at INFO when everything is applied.
    """
    # FILL IN: try pending_migrations; except Exception → logger.warning("Could not verify database migration
    #   state (%s); run `navauth self upgrade --check`", type(err).__name__) and return; pending → ONE
    #   logger.warning listing "set/filename (state)" and "Run `navauth self upgrade`"; else logger.info.
    raise NotImplementedError


async def tables_present(db_pool: Any, *qualified_names: str) -> bool:
    """True when every name resolves with ``to_regclass``."""
    async with acquire_raw(db_pool) as conn:
        for name in qualified_names:
            if not await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", name):
                return False
    return True
```

### `navigator_auth/auth.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '    setup_vault_tables,' navigator_auth/auth.py)
# DELETE line 34 `    setup_vault_tables,` (verified: navigator_auth/auth.py:34)

# occurrences: 1 (verified: grep -c 'from .identity.migrations import setup_identity_columns' navigator_auth/auth.py)
# REPLACE line 38 (verified: navigator_auth/auth.py:38) with:
from .migrations.startup import warn_pending_migrations

# occurrences: 1 each (verified: grep -c '            await setup_vault_tables(app["authdb"])' and
#   grep -c '            await setup_identity_columns(app["authdb"])' navigator_auth/auth.py)
# REPLACE lines 188-192 (verified: navigator_auth/auth.py:188-192):
        # Create vault tables if they don't exist (non-blocking)
        setup_vault_keyring(app)
        if "authdb" in app:
            await setup_vault_tables(app["authdb"])
            await setup_identity_columns(app["authdb"])
# WITH:
        # Load the vault keyring (non-blocking).
        setup_vault_keyring(app)
        # Schema changes are applied by `navauth self upgrade` (FEAT-110); startup only checks.
        if "authdb" in app:
            await warn_pending_migrations(app["authdb"])
```

### `navigator_auth/backends/passkey.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'from ..passkey.migrations import ensure_passkey_tables' navigator_auth/backends/passkey.py)
# REPLACE line 30 (verified: navigator_auth/backends/passkey.py:30) with:
from ..migrations.startup import tables_present

# occurrences: 1 (verified: grep -c '            await ensure_passkey_tables(app["authdb"])' navigator_auth/backends/passkey.py)
# REPLACE the try/except at lines 103-106 (verified: navigator_auth/backends/passkey.py:103-106) WITH:
        schema = auth_conf.AUTH_DB_SCHEMA
        try:
            present = await tables_present(
                app["authdb"], f"{schema}.user_credentials", f"{schema}.user_passkey_handles"
            )
        except Exception as err:  # pylint: disable=W0703
            raise ConfigError(f"PasskeyAuth: could not verify passkey tables ({type(err).__name__})") from err
        if not present:
            raise ConfigError("PasskeyAuth: passkey tables are missing — run `navauth self upgrade`")
```
Also update the `on_startup` docstring (line 94): "…store and migration." → "…store and table check."

### FILL IN checklist
- [ ] `warn_pending_migrations` — three outcomes
- [ ] `test_startup.py` — tests below

---

## Acceptance Criteria

- [ ] `AuthHandler.auth_startup` executes no DDL; with pending migrations it logs one warning naming them and `navauth self upgrade`; a failing check never blocks startup.
- [ ] `PasskeyAuth.on_startup` raises `ConfigError` mentioning `navauth self upgrade` when the passkey tables are missing, and runs no DDL.
- [ ] `navigator_auth.auth` no longer imports `setup_vault_tables` or `setup_identity_columns`; `navigator_auth.vault.integration.setup_vault_tables` still exists.
- [ ] Existing suites in the Validation Commands pass.

---

## Validation Commands

- `pytest tests/unit/migrations/test_startup.py -q`
- `pytest tests/test_passkey_backend_unit.py -q`
- `pytest tests/unit/test_exclude_provider.py -q`
- `pytest tests/unit/vault/test_integration.py -q`

> `tests/test_passkey_backend_unit.py` is a pre-existing regression suite for `PasskeyAuth.on_startup`,
> run here at task tier; the new passkey behaviour is covered at merge tier by
> `test_passkey_startup_raises_when_tables_missing` in `test_startup.py` (in the Validation Contract).

---

## Test Specification

```python
# tests/unit/migrations/test_startup.py
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_warn_pending_logs_and_never_raises(caplog, fake_conn, tmp_catalog):
    """Pool yielding fake_conn without ledger → one WARNING listing every file + `navauth self upgrade`;
    a pool whose acquire() raises → WARNING "could not verify", no exception; all applied → INFO."""


@pytest.mark.asyncio
async def test_auth_startup_runs_no_ddl(monkeypatch):
    """AuthHandler.auth_startup(stub, {"authdb": pool}) with stub = SimpleNamespace(backends={},
    _exclude_providers=[], logger=MagicMock(), register_exclusions=MagicMock(),
    _load_subnet_service_tags=AsyncMock()); patch navigator_auth.auth.setup_vault_keyring and
    navigator_auth.auth.warn_pending_migrations → warn awaited once with pool; the module has no
    setup_vault_tables / setup_identity_columns attribute."""


@pytest.mark.asyncio
async def test_passkey_startup_raises_when_tables_missing(monkeypatch):
    """PasskeyAuth(user_model=MagicMock(), identity=MagicMock()); monkeypatch BasicAuth.on_startup → AsyncMock,
    sys.modules['webauthn'] → MagicMock(), navigator_auth.backends.passkey.tables_present → AsyncMock(False):
    ConfigError mentioning `navauth self upgrade`. With True → no error."""


@pytest.mark.asyncio
async def test_tables_present(fake_conn):
    """relations contain both → True; one missing → False."""
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
9. **Close the task** with `parrot sdd task close TASK-166 new-command-migration verified`
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
