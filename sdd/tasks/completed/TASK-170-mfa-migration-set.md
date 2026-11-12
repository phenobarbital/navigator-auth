# TASK-170: MFA set joins the catalog — relocate SQL, shim the runner, presence check at startup

**Feature**: FEAT-110 — navauth self upgrade database migration command
**Spec**: `sdd/specs/new-command-migration.spec.md`
**Status**: done
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-161, TASK-162, TASK-169
**Assigned-to**: unassigned

---

> ## ⛔ GATE — do not start until FEAT-106 is on `dev`
>
> This task needs `navigator_auth/mfa/`, which FEAT-106 (`basicauth-otp-2fa`, PR #633) creates.
> At decomposition time (2026-11-11, `dev` @ `efb7f1e`) FEAT-106 was **not merged**, and its
> approved follow-up spec `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md` (tasks TASK-171…TASK-188,
> index `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json`, all pending)
> still changes exactly what this task moves: it adds `navigator_auth/mfa/sql/002_mfa_secrets.sql`,
> edits `_MIGRATION_FILES` / `MFA_TABLES` in `navigator_auth/mfa/migrations.py`, edits the
> header of `001_mfa_tables.sql`, and reworks how MFA availability is decided at startup
> (review finding #4, "self-heals without a restart").
>
> **Step 0 — check, then stop or continue:**
> 1. `git fetch origin dev && git merge-base --is-ancestor origin/feat-FEAT-106-basicauth-otp-2fa origin/dev`
>    must succeed, **and** the review-fixes work must be merged (every task in
>    `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json` is `done` on `dev`, or the user confirms
>    it was dropped).
> 2. The FEAT-110 feature branch must contain that `dev` (host operator: sync the feature
>    worktree with `dev` first; inside a worker sandbox use
>    `parrot sdd worktree sync-base FEAT-110 …` — never `git fetch/pull` there).
> 3. `navigator_auth/mfa/migrations.py` and `navigator_auth/mfa/sql/` exist in the worktree.
>
> If any check fails: set nothing to done, write **BLOCKED: FEAT-106 not on dev** in the
> Completion Note, and stop. Every MFA name below was read from the FEAT-106 branch
> (`origin/feat-FEAT-106-basicauth-otp-2fa` @ `0b80d88`), **not** from `dev` — re-verify each one
> before writing code and update this file's contract first where it moved.

---

## Context

Implements the MFA parts of spec §3 **Modules 1, 3 and 6**, split out of TASK-159,
TASK-164 and TASK-166 because FEAT-106 had not landed (spec §7 "FEAT-106 merges first";
the user chose to decompose now with MFA isolated in this gated task).

- **M1**: move `navigator_auth/mfa/sql/*.sql` into `navigator_auth/migrations/sql/mfa/`
  (byte-identical), so the `mfa` set — already in `MIGRATION_SETS` — gets its files.
- **M3**: `navigator_auth/mfa/migrations.py` keeps `render_sql`, `ensure_mfa_tables`,
  `mfa_tables_present`, `setup_mfa_tables`, `MFA_TABLES` and their contracts; `SQL_DIR`
  and `_MIGRATION_FILES` come from the catalog. The module **keeps its own execute-result
  check** (FEAT-106 TASK-130 AC-8 allows `.execute(` only in that file — spec M3).
- **M6**: the MFA usability flag comes from `mfa_tables_present()` instead of
  `setup_mfa_tables()`, so startup runs no MFA DDL; when the flag is false the log line
  names `navauth self upgrade`.
- Runner integration the spec requires for any new set: the MFA prerequisites/postconditions
  (`checks.py`) and the MFA tables in the runtime grant scope (`access.py` — spec: "Future
  files that introduce application tables must extend the grant scope and its tests").
- `docs/migrations/README.md` gets the MFA index rows (TASK-169's test enforces it).

---

## Scope

- `git mv navigator_auth/mfa/sql/*.sql navigator_auth/migrations/sql/mfa/` (every file present
  after the gate — `001_mfa_tables.sql`, and `002_mfa_secrets.sql` if the review fixes delivered it).
- `navigator_auth/mfa/migrations.py`: `SQL_DIR = set_dir("mfa")`, `_MIGRATION_FILES = set_filenames("mfa")`,
  `render_sql` imported from the catalog under the same name; docstring "startup migration" →
  "applied by `navauth self upgrade`; kept for programmatic use and tests". Keep `_with_conn` and
  `_raise_on_execute_error`.
- The MFA startup call (FEAT-106 branch: `navigator_auth/mfa/services.py:132`
  `available = await setup_mfa_tables(db_pool)` inside `build_mfa_services`) →
  `mfa_tables_present(db_pool)`, never raising (a probe error means `False`), logging
  `run \`navauth self upgrade\`` when false. If the review fixes moved this decision, apply the
  same replacement at its new home.
- `navigator_auth/migrations/checks.py`: `prerequisite_tables("mfa")` →
  `((AUTH_DB_SCHEMA, AUTH_USERS_TABLE),)`; postcondition for `mfa/001_mfa_tables.sql` → every
  table of `MFA_TABLES` from FEAT-106's first file exists (and for `002_…` its table).
- `navigator_auth/migrations/access.py`: `RUNTIME_TABLES["mfa"]` = the MFA application tables in
  `AUTH_DB_SCHEMA` (`(None, name)` entries).
- `docs/migrations/README.md`: one Index row per MFA file.
- Tests: MFA checksums + old-dir-gone in `test_catalog.py`; MFA scope in `test_access.py`; MFA
  rules in `test_checks.py`; keep `tests/test_mfa_migrations.py` and the MFA services/preflight
  tests passing (change only assertions that encode the old `mfa/sql/` path or `setup_mfa_tables`
  being called at startup).

**NOT in scope**: designing or editing MFA tables (FEAT-106); editing the content of MFA SQL files
(they move byte-identical); the FEAT-106 review fixes themselves.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/migrations/sql/mfa/001_mfa_tables.sql` | CREATE | `git mv` from `navigator_auth/mfa/sql/` |
| `navigator_auth/mfa/sql/001_mfa_tables.sql` | DELETE | source of the `git mv` |
| `navigator_auth/migrations/sql/mfa/002_mfa_secrets.sql` | CREATE | `git mv` — only if FEAT-106 review fixes delivered it |
| `navigator_auth/mfa/sql/002_mfa_secrets.sql` | DELETE | source of the `git mv` — only if present |
| `navigator_auth/mfa/migrations.py` | MODIFY | Catalog-backed `SQL_DIR` / `_MIGRATION_FILES` / `render_sql` |
| `navigator_auth/mfa/services.py` | MODIFY | Usability flag from `mfa_tables_present()` |
| `navigator_auth/migrations/checks.py` | MODIFY | MFA prerequisites + postconditions |
| `navigator_auth/migrations/access.py` | MODIFY | MFA tables in the runtime grant scope |
| `docs/migrations/README.md` | MODIFY | MFA index rows |
| `tests/unit/migrations/test_catalog.py` | MODIFY | MFA checksums, old dir gone |
| `tests/unit/migrations/test_checks.py` | MODIFY | MFA rules |
| `tests/unit/migrations/test_access.py` | MODIFY | MFA scope |
| `tests/test_mfa_migrations.py` | MODIFY | Only old-path / startup-DDL assertions, if any |
| `tests/fixtures/mfa.py` | MODIFY | Only if it patches `setup_mfa_tables` for startup |
| `tests/test_mfa_preflight.py` | MODIFY | Only if it encodes the old path or `setup_mfa_tables` at startup |

---

## Codebase Contract (Anti-Hallucination)

> `dev` names verified @ `87c9b9c`. **MFA names are UNVERIFIED on `dev`** — read from
> `origin/feat-FEAT-106-basicauth-otp-2fa` @ `0b80d88`; re-verify after the gate.

### Verified Imports
```python
from navigator_auth.migrations.catalog import render_sql, set_dir, set_filenames   # TASK-159
from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE                    # navigator_auth/conf.py:33-34
# FEAT-106 branch (unverified on dev):
from navigator_auth.mfa.migrations import mfa_tables_present, MFA_TABLES           # mfa/migrations.py
from navigator_auth.mfa.exceptions import MfaStorageError                            # imported by mfa/migrations.py:8
```

### Existing Signatures to Use
```python
# navigator_auth/mfa/migrations.py  (FEAT-106 branch @ 0b80d88 — unverified on dev)
logger = logging.getLogger("navigator.mfa")
SQL_DIR = Path(__file__).parent / "sql"                         # line 12
_MIGRATION_FILES = ("001_mfa_tables.sql",)                      # line 13 — review fixes: + "002_mfa_secrets.sql"
MFA_TABLES = ("tenant_mfa_policy", "user_mfa", "user_mfa_backup_codes",
              "user_trusted_devices", "user_mfa_audit", "user_mfa_security")   # lines 14-21 — review fixes: + "user_mfa_secrets"
def render_sql(sql: str) -> str:                                # line 24 — same body as catalog.render_sql
async def _with_conn(db_pool: Any, fn: Any) -> Any:             # line 36 — keep
def _raise_on_execute_error(result: Any, filename: str) -> None: # line 61 — keep (TASK-130 AC-8)
async def ensure_mfa_tables(db_pool: Any) -> None:              # line 76
async def mfa_tables_present(db_pool: Any) -> bool:             # line 95 — to_regclass probe, may raise
async def setup_mfa_tables(db_pool: Any) -> bool:               # line 116 — ensure + probe, never raises

# navigator_auth/mfa/services.py  (FEAT-106 branch @ 0b80d88)
from navigator_auth.mfa.migrations import setup_mfa_tables      # line 14
async def build_mfa_services(app: Any, backend: Any) -> MfaServices:   # line 119
        available = await setup_mfa_tables(db_pool)             # line 132 — inside a try block

# navigator_auth/mfa/sql/001_mfa_tables.sql  (FEAT-106 branch)
#   sha256 34524d11aa27da84a502907a8646f94407e39bb3dbbd8c0c383f281301a4ae51 at 0b80d88 — the review
#   fixes edit its header, so RECOMPUTE from `git show HEAD:navigator_auth/mfa/sql/001_mfa_tables.sql`
#   before the move and hard-code that value in test_catalog.py.
#   Uses {schema}/{users_table}; `CREATE SCHEMA IF NOT EXISTS {schema}` (line 6); bigserial ids at
#   lines 32, 44, 65 (owned sequences → access.py grants them through pg_depend).

# navigator_auth/migrations/checks.py (TASK-161)
def prerequisite_tables(migration_set: str) -> tuple[tuple[str, str], ...]   # returns () for "mfa" today
async def check_postconditions(conn: Any, file: MigrationFile) -> None        # dispatch by (set, filename)
async def _tables_unmet(conn, schema, tables) -> list[str]
# navigator_auth/migrations/access.py (TASK-162)
RUNTIME_TABLES: dict[str, tuple[tuple[str | None, str], ...]]                # "mfa": () today
```

FEAT-106 tests touching these names (branch @ `0b80d88`): `tests/test_mfa_migrations.py` (15 hits),
`tests/fixtures/mfa.py` (2), `tests/test_mfa_preflight.py` (2).

### Does NOT Exist
- ~~`navigator_auth/mfa/` on `dev` @ `87c9b9c`~~ — hence the gate.
- ~~`BasicAuth.on_startup` calling `setup_mfa_tables`~~ — the spec's guess; on the FEAT-106 branch the call is in
  `navigator_auth/mfa/services.py::build_mfa_services` (line 132). Re-locate after the gate.
- ~~`execute_checked` in `mfa/migrations.py`~~ — keep the module's own check (spec M3).

### Gate cleared — verified on this branch (2026-11-11, after `dev` sync c3968cf)
- GATE passed: FEAT-106 + FEAT-114 (18/18 tasks done) are in this branch; `navigator_auth/mfa/` and `mfa/sql/` exist.
- `navigator_auth/mfa/sql/` holds `001_mfa_tables.sql` (sha256 `0f1211a10d13c7a3a6dc6118d12a9e423fe75bfe08cc4e867bfc0f0b3dda776d`) and `002_mfa_secrets.sql` (sha256 `6a2f97527369ea862e09b83f07eb3b27d90dc74aeb4b71a7f455f7a4990e78a9`). Move BOTH.
- `mfa/migrations.py`: line 12 `SQL_DIR = Path(__file__).parent / "sql"`, line 13 `_MIGRATION_FILES = ("001_mfa_tables.sql", "002_mfa_secrets.sql")`, `MFA_TABLES` has SEVEN names (the six + `user_mfa_secrets`), `render_sql` at line ~24.
- `002_mfa_secrets.sql` creates `{schema}.user_mfa_secrets` -> postcondition for 002 = that table; 001 postcondition = the first six tables.
- Startup call: `navigator_auth/mfa/services.py` line 17 import and line 246 `available = await setup_mfa_tables(db_pool)` inside `build_mfa_services`' try block (no `preflight.py` module under navigator_auth/mfa; tests monkeypatch `preflight.mfa_tables_present` elsewhere — keep `mfa_tables_present` importable from `navigator_auth.mfa.migrations`).
- `checks.py`: `prerequisite_tables` ends with `return ()` after the oauth2 branch (line ~137); `access.py` line 31 `"mfa": (),`.
- The MFA tests `test_catalog.py` currently scope to `RELEASED_SETS = [vault, identity, passkey]`; add MFA checksums as a separate assertion, do not add mfa to RELEASED_SETS.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/migrations/sql/mfa/001_mfa_tables.sql", "action": "CREATE"},
    {"path": "navigator_auth/migrations/sql/mfa/002_mfa_secrets.sql", "action": "CREATE"},
    {"path": "navigator_auth/mfa/migrations.py", "action": "MODIFY"},
    {"path": "navigator_auth/mfa/services.py", "action": "MODIFY"},
    {"path": "navigator_auth/migrations/checks.py", "action": "MODIFY"},
    {"path": "navigator_auth/migrations/access.py", "action": "MODIFY"},
    {"path": "docs/migrations/README.md", "action": "MODIFY"},
    {"path": "tests/unit/migrations/test_catalog.py", "action": "MODIFY"},
    {"path": "tests/unit/migrations/test_checks.py", "action": "MODIFY"},
    {"path": "tests/unit/migrations/test_access.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_migrations.py", "action": "MODIFY"},
    {"path": "tests/fixtures/mfa.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_preflight.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/migrations/checks.py#prerequisite_tables",
    "sym:navigator_auth/migrations/checks.py#check_postconditions",
    "sym:navigator_auth/migrations/catalog.py#set_filenames"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- Byte-identical move: `git status` shows renames; checksums recomputed from `HEAD` before the move.
- `ensure_mfa_tables`, `setup_mfa_tables`, `mfa_tables_present`, `render_sql`, `MFA_TABLES` keep names and
  contracts (spec AC); `setup_mfa_tables` stays for programmatic use and tests — only startup stops calling it.
- The usability flag keeps its meaning ("the MFA tables exist"); a probe error → `False` (startup never fails
  because of it), with a log line naming `navauth self upgrade`.
- MFA grants: `(None, name)` entries resolve to `AUTH_DB_SCHEMA` — the MFA SQL is templated.

---

## Implementation Blueprint

### Steps (in order)
0. Run the **GATE** checks; stop with BLOCKED if any fails.
1. Re-verify every MFA name in this contract; fix the contract first where it moved.
2. Record checksums (`git show HEAD:<file> | sha256sum`), then `git mv` the MFA SQL files.
3. Edit `mfa/migrations.py`, the startup call, `checks.py`, `access.py`, the README.
4. Update tests; run the Validation Commands (and the live tests if `NAVAUTH_MIGRATIONS_TEST_DSN` is set).

### `navigator_auth/mfa/migrations.py` (MODIFY)
```python
# FILL IN: disambiguate after the gate — anchors as of FEAT-106 @ 0b80d88:
#   `SQL_DIR = Path(__file__).parent / "sql"` (line 12) → SQL_DIR = set_dir("mfa")
#   `_MIGRATION_FILES = ("001_mfa_tables.sql",)` (line 13, or the 2-file tuple after review fixes)
#       → _MIGRATION_FILES = set_filenames("mfa")
#   `def render_sql(sql: str) -> str:` (lines 24-33) → delete; add `from ..migrations.catalog import render_sql, set_dir, set_filenames`
#   drop `from pathlib import Path` and `from ..conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE` ONLY if no longer used
#   (mfa_tables_present uses AUTH_DB_SCHEMA — keep that import).
#   Re-run `grep -c` on each anchor and record the counts here before editing.
```

### `navigator_auth/mfa/services.py` (MODIFY)
```python
# FILL IN: disambiguate after the gate — FEAT-106 @ 0b80d88 anchor:
#   `        available = await setup_mfa_tables(db_pool)` (line 132, inside build_mfa_services' try block)
# REPLACE WITH (keeps "available" == "the MFA tables exist", runs no DDL):
        try:
            available = await mfa_tables_present(db_pool)
        except Exception as err:  # pylint: disable=W0703
            logger.error("MFA tables could not be verified (%s); run `navauth self upgrade`", type(err).__name__)
            available = False
        if not available:
            logger.critical("MFA tables are missing; run `navauth self upgrade`. BasicAuth logins will be refused")
# and import `mfa_tables_present` instead of `setup_mfa_tables` (line 14). If the review fixes moved the
# availability decision, apply this replacement where it now lives.
```

### `navigator_auth/migrations/checks.py` / `access.py` (MODIFY)
```python
# checks.py — prerequisite_tables: add before `return ()`:
    if migration_set == "mfa":
        return ((AUTH_DB_SCHEMA, AUTH_USERS_TABLE),)
# checks.py — check_postconditions dispatch: ("mfa", "001_mfa_tables.sql") → _tables_unmet(AUTH_DB_SCHEMA, <the six tables>)
#   FILL IN: ("mfa", "002_mfa_secrets.sql") → its table, if the file exists.
# access.py — RUNTIME_TABLES["mfa"]: FILL IN `(None, "<table>")` for every MFA application table (six + user_mfa_secrets if present).
```

### FILL IN checklist
- [ ] GATE passed (or BLOCKED recorded)
- [ ] MFA anchors re-verified with counts
- [ ] SQL moved, checksums hard-coded
- [ ] shim, startup flag, checks, access, README
- [ ] tests updated and passing

---

## Acceptance Criteria

- [ ] `navigator_auth/mfa/sql/` no longer exists; MFA files are under `navigator_auth/migrations/sql/mfa/`, byte-identical.
- [ ] The MFA startup path runs no DDL: its usability flag comes from `mfa_tables_present()`; `ensure_mfa_tables`, `setup_mfa_tables`, `mfa_tables_present` and `render_sql` remain importable from `navigator_auth.mfa.migrations`.
- [ ] `navauth self upgrade --set mfa` applies the MFA files, checks the users-table prerequisite and the tables' presence, and grants the runtime role access to the MFA tables and their sequences.
- [ ] `docs/migrations/README.md` lists the MFA files.
- [ ] FEAT-106's MFA tests and the migration suites in the Validation Commands pass.

---

## Validation Commands

- `pytest tests/unit/migrations/test_catalog.py -q`
- `pytest tests/unit/migrations/test_checks.py -q`
- `pytest tests/unit/migrations/test_access.py -q`
- `pytest tests/test_mfa_migrations.py -q`
- `pytest tests/test_mfa_preflight.py -q`

> `test_docs_index.py` (README lists the MFA files) and `test_runner.py` are in the spec's Validation
> Contract, so the merge tier runs them. `test_checks.py` / `test_access.py` are task-tier suites
> (see TASK-161/162). The two `tests/test_mfa_*.py` suites belong to FEAT-106 and only exist once the
> GATE passes. With `NAVAUTH_MIGRATIONS_TEST_DSN` set, also run `pytest tests/unit/migrations/test_runner.py -q`
> to prove the MFA set applies on a throwaway database (TASK-168's live tests).

---

## Test Specification

```python
# tests/unit/migrations/test_access.py  (append)
def test_mfa_scope_lists_mfa_tables_in_configured_schema():
    """scope_for('mfa') == [(AUTH_DB_SCHEMA, t) for t in MFA application tables]."""

# tests/unit/migrations/test_checks.py  (append)
@pytest.mark.asyncio
async def test_mfa_prerequisite_and_postcondition(fake_conn):
    """mfa without users table → MigrationError; after 001 with a table missing → MigrationError."""
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug new-command-migration --feature-id FEAT-110`)
2. **Read the spec** at the path listed above for full context
3. **Check dependencies** — every `Depends-on` task must be `"done"` in the
   per-spec index `sdd/tasks/index/new-command-migration.json` — **and the GATE above must pass**
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
9. **Close the task** with `parrot sdd task close TASK-170 new-command-migration verified`
   — it moves this file to `sdd/tasks/completed/` and marks it `"done"` in the
   index; never move or copy the file by hand
10. **Fill in the Completion Note** below, then commit the staged SDD state

---

## Completion Note

**Completed by**: sdd-worker (codex gpt-5.6-terra · attempt 1 · 464s · tokens n/a)
**Date**: 2026-11-11
**Notes**: Initially BLOCKED (FEAT-114 not on dev); gate cleared after the dev sync (c3968cf), contract re-verified, then implemented. Both MFA SQL files moved byte-identical, mfa/migrations.py catalog-backed, startup flag via mfa_tables_present, checks/access/README/tests updated. Merge-tier: 163 passed, 5 skipped. Orchestrator review: no defects. Closed via `parrot sdd task close` (durable evidence root read-only in sandbox).

**Deviations from spec**: none
