# TASK-164: Legacy migration runners become shims over the catalog and `execute_checked`

**Feature**: FEAT-110 — navauth self upgrade database migration command
**Spec**: `sdd/specs/new-command-migration.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-160
**Assigned-to**: unassigned

---

## Context

Implements spec §3 **Module 3** for the three released sets (identity, vault,
passkey). The public functions `ensure_identity_columns`, `ensure_vault_tables`,
`ensure_passkey_tables` and their `setup_*` wrappers keep their names,
signatures and behaviour (apply one set, no ledger) because tests and outside
callers use them. What changes:

- their hand-written file tuples become `set_filenames("<set>")` — a file that is
  not listed can no longer be skipped (the identity `006` incident);
- their three private `_run_sql` copies are deleted in favour of
  `runner.acquire_pooled` + `runner.execute_checked`, so an asyncdb error pair is
  a failure instead of a silent success (spec G4);
- `passkey.migrations.render_sql` becomes a re-export of `catalog.render_sql`.

TASK-159 already repointed `SQL_DIR`. The MFA module is shimmed in TASK-170.

---

## Scope

- `navigator_auth/identity/migrations.py`: `_MIGRATION_FILES = set_filenames("identity")`;
  delete `_run_sql`; run each file through `acquire_pooled` + `execute_checked`; keep the
  collect-then-raise loop exactly as is; update the module docstring.
- `navigator_auth/vault/migrations.py`: `MIGRATION_FILES = set_filenames("vault")`; delete
  `_run_sql`; same execution change; first failure still propagates; update docstring.
- `navigator_auth/passkey/migrations.py`: `_MIGRATION_FILES = set_filenames("passkey")`;
  replace the local `render_sql` with `from ..migrations.catalog import render_sql`;
  delete `_run_sql`; same execution change; update docstring; drop the now-unused
  `from ..conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE`.
- Add one regression test per set: an asyncdb-style `[None, error]` return from
  `conn.execute` makes `ensure_*` raise.

**NOT in scope**: `navigator_auth/vault/integration.py::setup_vault_tables` (unchanged);
`auth.py` / `backends/passkey.py` startup calls (TASK-166); `navigator_auth/mfa/`
(TASK-170). Do not edit any existing test assertion.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/identity/migrations.py` | MODIFY | Discovered file list, shared execution, docstring |
| `navigator_auth/vault/migrations.py` | MODIFY | Discovered file list, shared execution, docstring |
| `navigator_auth/passkey/migrations.py` | MODIFY | Discovered file list, re-exported `render_sql`, shared execution |
| `tests/unit/identity/test_identity_migrations.py` | MODIFY | Add asyncdb error-pair regression test |
| `tests/unit/vault/test_migrations.py` | MODIFY | Add asyncdb error-pair regression test |
| `tests/test_passkey_migrations.py` | MODIFY | Add asyncdb error-pair regression test |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `87c9b9c` (2026-11-11). Line numbers are pre-TASK-159; TASK-159
> swaps one import line per file, so they may shift by ±1 — re-locate by the anchors.

### Verified Imports
```python
from navigator_auth.migrations.catalog import render_sql, set_dir, set_filenames   # TASK-159
from navigator_auth.migrations.runner import acquire_pooled, execute_checked       # TASK-160
```

### Existing Signatures to Use
```python
# navigator_auth/identity/migrations.py
logger = logging.getLogger("navigator.identity")                 # line 16
SQL_DIR = set_dir("identity")                                    # line 18 (after TASK-159)
_MIGRATION_FILES = (                                             # lines 21-31 incl. the 3-line comment above it
async def _run_sql(db_pool: Any, sql: str) -> None:              # lines 34-49 — delete
async def ensure_identity_columns(db_pool: Any) -> None:         # line 52 — collect failures, raise RuntimeError once
            await _run_sql(db_pool, sql)                         # line 82
async def setup_identity_columns(db_pool: Any) -> None:          # line 97 — unchanged

# navigator_auth/vault/migrations.py
SQL_DIR = set_dir("vault")                                       # line 18 (after TASK-159)
MIGRATION_FILES = (                                              # lines 20-24 incl. comment line 20
async def _run_sql(db_pool: Any, sql: str) -> None:              # lines 27-42 — delete
async def ensure_vault_tables(db_pool: Any) -> None:             # line 45 — first failure propagates
        await _run_sql(db_pool, (SQL_DIR / filename).read_text())   # line 55

# navigator_auth/passkey/migrations.py
from ..conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE              # line 11 — becomes unused; delete
SQL_DIR = set_dir("passkey")                                     # line 15 (after TASK-159)
_MIGRATION_FILES = ("001_passkey_credentials.sql",)              # line 17
def render_sql(sql: str) -> str:                                 # lines 20-22 — replace by import
async def _run_sql(db_pool: Any, sql: str) -> None:              # lines 25-40 — delete
async def ensure_passkey_tables(db_pool: Any) -> None:           # line 43
        await _run_sql(db_pool, sql)                             # line 51
async def setup_passkey_tables(db_pool: Any) -> None:            # line 55 — unchanged

# navigator_auth/migrations/runner.py (TASK-160)
@asynccontextmanager
async def acquire_pooled(db_pool: Any) -> AsyncIterator[Any]     # pool's own connection; legacy release logic
async def execute_checked(conn: Any, sql: str, *args: Any) -> Any   # raises MigrationError on [x, error]
```

Existing tests that must pass **unchanged** (verified):
- `tests/unit/identity/test_identity_migrations.py` — `AsyncMock` connection; `test_awaitable_acquire_releases`
  asserts `pool.release.await_count == 6` and `assert_awaited_with(conn)`; failure tests assert
  `"1 of 6"`, `"6 of 6"`, the failing filename and `__cause__` type.
- `tests/unit/vault/test_migrations.py:149-154` — `MIGRATION_FILES == ("001_create_vault_tables.sql", "002_vault_crypto_hardening.sql")`.
- `tests/test_passkey_migrations.py` — `_FakeConn.execute(self, sql)` takes one argument (so call
  `execute_checked(conn, sql)` with no extra args); `len(pool.executed) == len(_MIGRATION_FILES)`.
- `tests/test_identity_id_token.py:257-331` — `FakeConn.execute(self, sql)` returning `None`.
- `AsyncMock().execute(...)` returns a `MagicMock` (not a list/tuple) → `execute_checked` passes it through.

### Does NOT Exist
- ~~`setup_vault_tables` in `navigator_auth/vault/migrations.py`~~ — it is in `navigator_auth/vault/integration.py:102`; leave it.
- ~~`acquire_raw` for the shims~~ — use `acquire_pooled`: `acquire_raw` unwraps asyncdb connections, and the
  mocked-pool tests assert on the pool's own connection object (spec M3).
- ~~A ledger write from `ensure_*`~~ — the shims apply one set with no ledger (spec §2 item 6).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/identity/migrations.py", "action": "MODIFY"},
    {"path": "navigator_auth/vault/migrations.py", "action": "MODIFY"},
    {"path": "navigator_auth/passkey/migrations.py", "action": "MODIFY"},
    {"path": "tests/unit/identity/test_identity_migrations.py", "action": "MODIFY"},
    {"path": "tests/unit/vault/test_migrations.py", "action": "MODIFY"},
    {"path": "tests/test_passkey_migrations.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/identity/migrations.py#ensure_identity_columns",
    "sym:navigator_auth/identity/migrations.py#setup_identity_columns",
    "sym:navigator_auth/vault/migrations.py#ensure_vault_tables",
    "sym:navigator_auth/passkey/migrations.py#ensure_passkey_tables",
    "sym:navigator_auth/passkey/migrations.py#setup_passkey_tables",
    "sym:navigator_auth/passkey/migrations.py#render_sql",
    "sym:navigator_auth/migrations/runner.py#acquire_pooled",
    "sym:navigator_auth/migrations/runner.py#execute_checked",
    "sym:navigator_auth/migrations/catalog.py#set_filenames"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- Signatures and names unchanged (spec AC: `ensure_*`, `setup_*`, `SQL_DIR`,
  `MIGRATION_FILES` / `_MIGRATION_FILES`, `passkey.migrations.render_sql` importable as before).
- One connection per file, acquired from `db_pool` — same as today (spec M3).
- Docstrings say "applied by `navauth self upgrade`; kept for programmatic use and tests"
  instead of "at every startup" (spec M3).

---

## Implementation Blueprint

### Steps (in order)
1. Edit the three modules per the blocks — *why*: removes the three `_run_sql` copies.
2. Run the existing tests first — *why*: they prove behaviour did not change.
3. Add the three regression tests; run all Validation Commands.

### `navigator_auth/identity/migrations.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '_MIGRATION_FILES = (' navigator_auth/identity/migrations.py)
# REPLACE the comment block + tuple `_MIGRATION_FILES = (` … `)` (verified: navigator_auth/identity/migrations.py:21-31) with:
# Discovered from navigator_auth/migrations/sql/identity/ (FEAT-110): no hand-written list.
_MIGRATION_FILES = set_filenames("identity")

# occurrences: 1 (verified: grep -c 'async def _run_sql(db_pool: Any, sql: str) -> None:' navigator_auth/identity/migrations.py)
# DELETE `async def _run_sql` … (verified: navigator_auth/identity/migrations.py:34-49)

# occurrences: 1 (verified: grep -c '            await _run_sql(db_pool, sql)' navigator_auth/identity/migrations.py)
# REPLACE `            await _run_sql(db_pool, sql)` (verified: navigator_auth/identity/migrations.py:82) with:
            async with acquire_pooled(db_pool) as conn:
                await execute_checked(conn, sql)
```
Imports: extend TASK-159's `from ..migrations.catalog import set_dir` to
`from ..migrations.catalog import set_dir, set_filenames` and add
`from ..migrations.runner import acquire_pooled, execute_checked`.
**Why**: the `try/except` around this call already collects failures per file;
`execute_checked` turns an asyncdb error pair into one of them.
```python
# FILL IN: module docstring (lines 1-10) — replace "Idempotent; executed at application startup, mirroring the
#   Session Vault migration." with "Applied by `navauth self upgrade`; kept for programmatic use and tests."
#   Keep the rest of the docstring, and fix "on every startup after the first" to "on every run after the first".
```

### `navigator_auth/vault/migrations.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'MIGRATION_FILES = (' navigator_auth/vault/migrations.py)
# REPLACE `# Applied in order, at every startup. …` + `MIGRATION_FILES = (` … `)` (verified: navigator_auth/vault/migrations.py:20-24) with:
# Discovered from navigator_auth/migrations/sql/vault/ (FEAT-110): no hand-written list.
MIGRATION_FILES = set_filenames("vault")

# DELETE `async def _run_sql` … (verified: navigator_auth/vault/migrations.py:27-42; occurrences: 1)

# occurrences: 1 (verified: grep -c '        await _run_sql(db_pool, (SQL_DIR / filename).read_text())' navigator_auth/vault/migrations.py)
# REPLACE that line (verified: navigator_auth/vault/migrations.py:55) with:
        async with acquire_pooled(db_pool) as conn:
            await execute_checked(conn, (SQL_DIR / filename).read_text())
```
Imports as for identity. Docstring line 4-5 "applied in order at every startup" →
"applied in order by `navauth self upgrade`; kept for programmatic use and tests".

### `navigator_auth/passkey/migrations.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '_MIGRATION_FILES = ("001_passkey_credentials.sql",)' navigator_auth/passkey/migrations.py)
# REPLACE (verified: navigator_auth/passkey/migrations.py:17) with:
_MIGRATION_FILES = set_filenames("passkey")

# occurrences: 1 (verified: grep -c 'def render_sql(sql: str) -> str:' navigator_auth/passkey/migrations.py)
# DELETE the local `def render_sql` (lines 20-22) — `render_sql` now comes from the import below.
# DELETE `async def _run_sql` (lines 25-40; occurrences: 1).
# DELETE `from ..conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE` (line 11; occurrences: 1) — unused now.

# occurrences: 1 (verified: grep -c '        await _run_sql(db_pool, sql)' navigator_auth/passkey/migrations.py)
# REPLACE (verified: navigator_auth/passkey/migrations.py:51) with:
        async with acquire_pooled(db_pool) as conn:
            await execute_checked(conn, sql)
```
Imports: `from ..migrations.catalog import render_sql, set_dir, set_filenames` and
`from ..migrations.runner import acquire_pooled, execute_checked`. Module docstring:
"Run by `PasskeyAuth.on_startup`" → "Applied by `navauth self upgrade`; kept for
programmatic use and tests."
**Why**: `render_sql` stays importable from `navigator_auth.passkey.migrations`
(spec AC) because the module imports it by that name.

### Tests (MODIFY — append one test to each file)
```python
# FILL IN: tests/unit/identity/test_identity_migrations.py — conn.execute returns [None, RuntimeError("x")] for
#   one file → ensure_identity_columns raises RuntimeError naming that file, all six attempted.
# FILL IN: tests/unit/vault/test_migrations.py — conn.execute returns [None, "Postgres Error: boom"] → ensure_vault_tables raises.
# FILL IN: tests/test_passkey_migrations.py — a _FakeConn variant returning [None, "err"] → ensure_passkey_tables raises;
#   setup_passkey_tables with the same pool does not raise.
```

### FILL IN checklist
- [ ] Three modules edited; no `_run_sql` left (`grep -rn "_run_sql" navigator_auth/` is empty outside `mfa/`)
- [ ] Docstrings updated
- [ ] Three regression tests

---

## Acceptance Criteria

- [ ] `grep -rn "def _run_sql" navigator_auth/identity navigator_auth/vault navigator_auth/passkey` is empty.
- [ ] `_MIGRATION_FILES` / `MIGRATION_FILES` come from `set_filenames`; values equal the old tuples.
- [ ] `from navigator_auth.passkey.migrations import render_sql, SQL_DIR, _MIGRATION_FILES` still works.
- [ ] An asyncdb `[None, error]` return makes each `ensure_*` raise; the `setup_*` wrappers still never raise.
- [ ] Every existing test in the Validation Commands passes unchanged.

---

## Validation Commands

- `pytest tests/unit/identity/test_identity_migrations.py -q`
- `pytest tests/unit/vault/test_migrations.py -q`
- `pytest tests/unit/vault/test_integration.py -q`
- `pytest tests/test_passkey_migrations.py -q`
- `pytest tests/test_identity_id_token.py -q`

---

## Test Specification

```python
# tests/unit/vault/test_migrations.py  (append)
class TestEnsureVaultTablesFailClosed:
    @pytest.mark.asyncio
    async def test_asyncdb_error_pair_raises(self):
        """conn.execute returns [None, "Postgres Error: boom"] → MigrationError from ensure_vault_tables."""
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
9. **Close the task** with `parrot sdd task close TASK-164 new-command-migration verified`
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
