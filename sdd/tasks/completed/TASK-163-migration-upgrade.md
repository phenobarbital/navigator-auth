# TASK-163: `upgrade()` — advisory lock, per-file transaction, ledger upsert, access reconciliation

**Feature**: FEAT-110 — navauth self upgrade database migration command
**Spec**: `sdd/specs/new-command-migration.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-161, TASK-162
**Assigned-to**: unassigned

---

## Context

Completes spec §3 **Module 2**: the `upgrade()` function that `navauth self upgrade`
(TASK-165) calls. It ties together the runner foundation (TASK-160), the
prerequisite/postcondition checks (TASK-161) and the runtime grants (TASK-162):

- one session-level `pg_advisory_lock(ADVISORY_LOCK_KEY)` for the whole run;
- per pending file, **one transaction**: prerequisites → rendered SQL →
  postconditions → runtime grants → grant verification → ledger upsert. Any
  failure rolls the whole file back, so a failed file never gets a ledger row;
- a failed file is recorded and the run continues (unless `fail_fast`);
- `CHANGED` files are skipped unless `reapply_changed`;
- runtime access for already-applied sets is reconciled in a separate
  transaction under the same lock, failures go to `report.access_errors`.

---

## Scope

- Add `upgrade`, `_apply_file`, `_upsert_ledger`, `_reconcile_access` to
  `navigator_auth/migrations/runner.py`.
- Export `upgrade` from `navigator_auth/migrations/__init__.py`.
- Add the upgrade unit tests to `tests/unit/migrations/test_runner.py`, including the
  spec's `test_guarded_skip_stays_pending_and_retries`,
  `test_missing_prerequisites_and_oauth2_postconditions_fail` and
  `test_runtime_grants_and_reconciliation`.

**NOT in scope**: the CLI and exit codes (TASK-165); live PostgreSQL tests
(TASK-168); the OAuth2 SQL (TASK-167). Do not change `checks.py`, `access.py` or
`conftest.py` — configure `FakeConnection` from the test file.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/migrations/runner.py` | MODIFY | Add `upgrade()` and its helpers |
| `navigator_auth/migrations/__init__.py` | MODIFY | Export `upgrade` |
| `tests/unit/migrations/test_runner.py` | MODIFY | Upgrade tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `87c9b9c` (2026-11-11); TASK-160/161/162 symbols as defined in those tasks.

### Verified Imports
```python
from navigator_auth.version import __version__        # verified: navigator_auth/version.py:7 ("0.29.0")
from navigator_auth.migrations.catalog import render_sql   # created by TASK-159
# Imported INSIDE upgrade() — checks.py and access.py import runner.py (module-level import = cycle):
from navigator_auth.migrations.checks import check_postconditions, check_prerequisites   # TASK-161
from navigator_auth.migrations.access import (                                          # TASK-162
    grant_runtime_access, validate_runtime_role, verify_runtime_access,
)
import time                                           # stdlib
```

### Existing Signatures to Use
```python
# navigator_auth/migrations/runner.py (TASK-160)
logger = logging.getLogger("navigator.migrations")
ADVISORY_LOCK_KEY: int = 1102026
class MigrationError(Exception)
class MigrationState(str, Enum): APPLIED, PENDING, CHANGED
class MigrationStatus(BaseModel): file, state, applied_at, recorded_checksum
class MigrationResult(BaseModel): file, ok, error: str | None, duration_ms: int
class UpgradeReport(BaseModel): applied, failed, skipped_changed, access_errors   # lists, default empty
def ledger_name() -> str
async def execute_checked(conn, sql, *args) -> Any
async def ensure_ledger(conn) -> None          # raises MigrationError when AUTH_DB_SCHEMA is missing
async def get_status(conn, sets=None) -> list[MigrationStatus]

# navigator_auth/migrations/checks.py (TASK-161)
async def check_prerequisites(conn: Any, file: MigrationFile) -> None    # raises MigrationError
async def check_postconditions(conn: Any, file: MigrationFile) -> None   # raises MigrationError
# rules keyed on ("identity", "006_identity_drop_legacy_uid.sql") and ("oauth2", "001_oauth2_schema.sql")

# navigator_auth/migrations/access.py (TASK-162)
async def validate_runtime_role(conn: Any, role: str | None) -> str      # raises MigrationError
async def grant_runtime_access(conn: Any, migration_set: str, role: str) -> None   # raises MigrationError
async def verify_runtime_access(conn: Any, migration_set: str, role: str) -> None  # raises MigrationError

# tests/unit/migrations/conftest.py (TASK-159/160)
tmp_catalog (fixture) -> Path       # vault/001_first.sql, vault/002_second.sql, identity/001_third.sql
fake_conn (fixture) -> FakeConnection   # ledger upsert emulated from INSERT INTO … schema_migrations args[0..4];
                                        # transaction() restores ledger on exception; relations; respond; fail_on
```

Raw asyncpg facts: `conn.transaction()` is an async context manager that rolls back on
exception; `conn.execute(sql)` without args runs a multi-statement script (DO blocks
included) and raises `asyncpg.PostgresError` on failure. A session-level advisory lock
belongs to the connection, so the whole run must use the one `conn` (spec §7).

### Does NOT Exist
- ~~Module-level `from .checks import …` / `from .access import …` in `runner.py`~~ — import cycle; import inside `upgrade()`.
- ~~`pg_advisory_xact_lock`~~ — the spec uses the session-level lock held for the whole run.
- ~~Down migrations / rollback of applied files~~ — spec Non-Goals.
- ~~A `--force`/`--mark-applied` path~~ — not in the spec; a failed file stays pending.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/migrations/runner.py", "action": "MODIFY"},
    {"path": "navigator_auth/migrations/__init__.py", "action": "MODIFY"},
    {"path": "tests/unit/migrations/test_runner.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/migrations/runner.py#get_status",
    "sym:navigator_auth/migrations/runner.py#ensure_ledger",
    "sym:navigator_auth/migrations/runner.py#execute_checked",
    "sym:navigator_auth/migrations/runner.py#UpgradeReport",
    "sym:navigator_auth/migrations/checks.py#check_prerequisites",
    "sym:navigator_auth/migrations/checks.py#check_postconditions",
    "sym:navigator_auth/migrations/access.py#validate_runtime_role",
    "sym:navigator_auth/migrations/access.py#grant_runtime_access",
    "sym:navigator_auth/migrations/access.py#verify_runtime_access",
    "sym:navigator_auth/version.py#__version__"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- Validate the runtime role **before** taking the lock or writing anything — spec: invalid
  configuration fails before writes.
- The per-file order inside the transaction is fixed: prerequisites → SQL → postconditions →
  grants → verify → ledger upsert. The upsert is last so nothing records a file that did not
  fully complete (spec "Completion and retry contract").
- A failed reapplication keeps the previous ledger row (rollback) — the file stays CHANGED.
- Unlock in `finally`; an unlock error is logged as a warning and never masks the original error.
- Per-file failures never raise out of `upgrade()`; they go to `report.failed`. Only run-level
  problems (invalid role, missing schema, lock failure) raise `MigrationError`.

---

## Implementation Blueprint

### Steps (in order)
1. Add the blocks below to the end of `runner.py`; fill the `FILL IN`s — *why*: TASK-165
   calls `upgrade()`.
2. Export `upgrade` from `__init__.py` (add to `__all__`).
3. Append the tests to `test_runner.py` using `tmp_catalog` + `fake_conn`; for the 006 and
   OAuth2 cases write `identity/006_identity_drop_legacy_uid.sql` /
   `oauth2/001_oauth2_schema.sql` into the tmp tree so the TASK-161 rules apply.
4. Run the Validation Commands.

### `navigator_auth/migrations/runner.py` (MODIFY)
```python
# occurrences: 1 (verified after TASK-160: grep -c '^async def get_status(' navigator_auth/migrations/runner.py)
# AFTER — append at the end of the module, below `get_status`:
_UPSERT_SQL = """
INSERT INTO {ledger} (migration_set, filename, checksum, package_version, execution_ms)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (migration_set, filename) DO UPDATE SET
    checksum = EXCLUDED.checksum,
    applied_at = now(),
    applied_by = current_user,
    package_version = EXCLUDED.package_version,
    execution_ms = EXCLUDED.execution_ms
"""


async def _upsert_ledger(conn: Any, file: MigrationFile, duration_ms: int) -> None:
    """Record ``file`` as applied with its current checksum."""
    await execute_checked(
        conn, _UPSERT_SQL.format(ledger=ledger_name()),
        file.migration_set, file.filename, file.checksum, __version__, duration_ms,
    )


async def _apply_file(conn: Any, file: MigrationFile, runtime_role: str) -> MigrationResult:
    """Apply one file in one transaction; never raises — failures become ``ok=False``."""
    from .access import grant_runtime_access, verify_runtime_access  # noqa: PLC0415 — cycle
    from .checks import check_postconditions, check_prerequisites  # noqa: PLC0415 — cycle

    started = time.monotonic()
    # FILL IN: `async with conn.transaction():` check_prerequisites → execute_checked(render_sql(
    #   file.path.read_text(encoding="utf-8"))) → check_postconditions → grant_runtime_access →
    #   verify_runtime_access → _upsert_ledger(duration so far). On any Exception: logger.error naming
    #   set/filename (never the DSN), return MigrationResult(ok=False, error=str(err), duration_ms=…).
    #   Bounded by spec M2 upgrade() docstring and "Completion and retry contract".
    raise NotImplementedError


async def _reconcile_access(conn: Any, migration_set: str, runtime_role: str) -> list[str]:
    """Grant + verify one set's runtime access in its own transaction; return error strings."""
    from .access import grant_runtime_access, verify_runtime_access  # noqa: PLC0415 — cycle

    try:
        async with conn.transaction():
            await grant_runtime_access(conn, migration_set, runtime_role)
            await verify_runtime_access(conn, migration_set, runtime_role)
    except Exception as err:  # pylint: disable=W0703
        logger.error("Runtime access for set %s could not be reconciled: %s", migration_set, err)
        return [f"{migration_set}: {err}"]
    return []


async def upgrade(
    conn: Any,
    sets: Iterable[str] | None = None,
    *,
    runtime_role: str,
    reapply_changed: bool = False,
    fail_fast: bool = False,
) -> UpgradeReport:
    """Apply pending files (and changed ones when ``reapply_changed``).

    Holds ``pg_advisory_lock(ADVISORY_LOCK_KEY)`` for the run. Each file: prerequisite
    checks + SQL + postcondition checks + runtime grants + ledger upsert in one
    transaction. A failure rolls back the entire file, is recorded in ``report.failed``
    and the run continues, unless ``fail_fast``. Access for already-applied selected
    files is reconciled as well; failures appear in ``report.access_errors``.

    Raises:
        MigrationError: invalid runtime role, missing schema, or the lock cannot be taken.
    """
    from .access import validate_runtime_role  # noqa: PLC0415 — cycle

    await validate_runtime_role(conn, runtime_role)
    report = UpgradeReport()
    await execute_checked(conn, "SELECT pg_advisory_lock($1)", ADVISORY_LOCK_KEY)
    try:
        await ensure_ledger(conn)
        statuses = await get_status(conn, sets)
        # FILL IN: loop in catalog order — APPLIED: remember its set for reconciliation; CHANGED and
        #   not reapply_changed: report.skipped_changed; else _apply_file → report.applied / report.failed;
        #   stop when a file failed and fail_fast. Then, unless stopped, _reconcile_access for each set
        #   that had an APPLIED file (once per set), extending report.access_errors; stop at the first
        #   access error when fail_fast. Bounded by spec M2 docstring + "Runtime access contract".
    finally:
        # FILL IN: SELECT pg_advisory_unlock($1); on error logger.warning, never re-raise from finally.
        pass
    return report
```
**Why this shape**: the signature is the spec's M2 skeleton. Function-level imports
break the `runner ↔ checks/access` import cycle. `_UPSERT_SQL` matches the
`FakeConnection` upsert rule (args 0..4).

Also add `import time` to the module imports and `from .catalog import MigrationFile, discover, render_sql`
(extend the existing `from .catalog import …` line).

### `navigator_auth/migrations/__init__.py` (MODIFY)
```python
# occurrences: 1 (verified after TASK-160: grep -c '^from .runner import (' navigator_auth/migrations/__init__.py)
# MODIFY — add `upgrade` to the `from .runner import (...)` block and to `__all__`.
```

### FILL IN checklist
- [ ] `_apply_file` — transaction body and failure mapping
- [ ] `upgrade` — status loop, skip/apply/fail-fast, reconciliation set selection
- [ ] `upgrade` `finally` — unlock without masking
- [ ] `test_runner.py` — tests below

---

## Acceptance Criteria

- [ ] Pending files run in catalog order; each SQL, its grants and its ledger upsert happen inside one transaction.
- [ ] A failing file is in `report.failed` by name, has no ledger row, and later files still run; with `fail_fast` the run stops there.
- [ ] Identity `006` with `uid` still present → failed, no ledger row; after the blocker is gone an ordinary `upgrade()` applies the unchanged file.
- [ ] A missing base table or an unmet OAuth2 postcondition fails the file without a ledger row.
- [ ] `CHANGED` files are in `skipped_changed` unless `reapply_changed`; a failed reapply keeps the old row.
- [ ] Already-applied sets get their grants reconciled without re-running SQL; grant failures land in `access_errors`.
- [ ] The advisory lock is taken once and released on success and on error; an invalid runtime role raises before the lock.

---

## Validation Commands

- `pytest tests/unit/migrations/test_runner.py -q`

---

## Test Specification

```python
# tests/unit/migrations/test_runner.py  (append)
@pytest.mark.asyncio
async def test_upgrade_applies_pending_in_order_and_records_ledger(tmp_catalog, fake_conn):
    """BEGIN, SQL, GRANTs, INSERT INTO schema_migrations, COMMIT per file; three ledger rows."""

@pytest.mark.asyncio
async def test_upgrade_continues_after_failure_and_reports_it(tmp_catalog, fake_conn):
    """fail_on a marker in vault/002 → report.failed names it; identity/001 applied; no row for vault/002."""

@pytest.mark.asyncio
async def test_upgrade_fail_fast_stops(tmp_catalog, fake_conn):
    """Same failure with fail_fast=True → identity/001 never executed."""

@pytest.mark.asyncio
async def test_upgrade_skips_changed_unless_reapply(tmp_catalog, fake_conn):
    """Ledger row with wrong checksum → skipped_changed; reapply_changed=True → re-run + row updated."""

@pytest.mark.asyncio
async def test_upgrade_takes_and_releases_advisory_lock(tmp_catalog, fake_conn):
    """pg_advisory_lock then pg_advisory_unlock on success, and on a run-level error (schema_missing)."""

@pytest.mark.asyncio
async def test_guarded_skip_stays_pending_and_retries(tmp_catalog, fake_conn):
    """identity/006 with uid present (respond pg_attribute) → failed, no row; remove uid → applied."""

@pytest.mark.asyncio
async def test_missing_prerequisites_and_oauth2_postconditions_fail(tmp_catalog, fake_conn):
    """oauth2/001 without clients → failed; with base tables but no client_access → failed; no rows."""

@pytest.mark.asyncio
async def test_runtime_grants_and_reconciliation(tmp_catalog, fake_conn):
    """Pending file: GRANT before the upsert in its transaction. Applied file: grants re-issued, its SQL
    not re-run. fail_on('GRANT') → file failed + rolled back; on reconcile → access_errors."""

@pytest.mark.asyncio
async def test_upgrade_rejects_invalid_runtime_role_before_writes(tmp_catalog, fake_conn):
    """respond('pg_roles', False) → MigrationError; no lock, no DDL."""
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
9. **Close the task** with `parrot sdd task close TASK-163 new-command-migration verified`
   — it moves this file to `sdd/tasks/completed/` and marks it `"done"` in the
   index; never move or copy the file by hand
10. **Fill in the Completion Note** below, then commit the staged SDD state

---

## Completion Note

**Completed by**: sdd-worker (native sonnet for TASK-163, codex gpt-5.6-luna for TASK-167)
**Date**: 2026-11-11
**Notes**: Delivered and merged; merge-tier validation green (19 passed); orchestrator review found no defects, 0 fix commits. Closed via `parrot sdd task close` (durable evidence root read-only in sandbox).

**Deviations from spec**: none
