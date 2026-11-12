# TASK-165: `navauth self upgrade` CLI, admin credentials and console script

**Feature**: FEAT-110 — navauth self upgrade database migration command
**Spec**: `sdd/specs/new-command-migration.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-162, TASK-163
**Assigned-to**: unassigned

---

## Context

Implements spec §3 **Module 5** (goals G1 and G5): the `navauth` console script with
`self upgrade` and `self upgrade --check`, connecting with **admin** credentials
(separate from the runtime `DBUSER`) through a single raw asyncpg connection, and
mapping outcomes to the spec's exit codes.

It is the only task that edits `pyproject.toml` (first `[project.scripts]` table) and
`navigator_auth/conf.py` (three admin settings).

---

## Scope

- Add `AUTH_ADMIN_DSN`, `AUTH_ADMIN_USER`, `AUTH_ADMIN_PWD` to `navigator_auth/conf.py`.
- Create `navigator_auth/migrations/cli.py`: `EXIT_*` constants, `build_parser`,
  `resolve_dsn`, `run`, `main`, `console_entry`, plus private report printers.
- Add `[project.scripts] navauth = "navigator_auth.migrations.cli:console_entry"` to
  `pyproject.toml`, before the `navigator_session.vault_targets` entry-points table.
- Create `tests/unit/migrations/test_cli.py` (unit tests + `test_wheel_contains_sql`).

Flags (spec §2): `--check`, `--dsn DSN`, `--user USER`, `--set NAME` (repeatable,
choices = `MIGRATION_SETS`), `--runtime-role ROLE` (default `DBUSER`),
`--reapply-changed`, `--fail-fast`, `-v/--verbose`.

Exit codes: `0` success / nothing pending · `1` `--check` found pending/changed files or
missing runtime privileges · `2` a migration or a runtime grant failed (`report.failed`
or `report.access_errors`) · `3` usage, configuration or connection error (including
an argparse error, an invalid runtime role, a missing schema, a catalog error).

**NOT in scope**: runner behaviour (TASK-163); docs (TASK-169); live database tests
(TASK-168). Do not add `asyncpg` to `pyproject.toml` dependencies (spec §7: it comes with asyncdb).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/migrations/cli.py` | CREATE | The `navauth` command |
| `navigator_auth/conf.py` | MODIFY | Admin credential settings |
| `pyproject.toml` | MODIFY | `[project.scripts]` table |
| `tests/unit/migrations/test_cli.py` | CREATE | CLI tests + wheel test |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `87c9b9c` (2026-11-11).

### Verified Imports
```python
from navigator_auth import conf          # module object — read settings at call time so tests can monkeypatch
# conf attributes used: DBUSER, DBHOST, DBPORT, DBNAME, default_dsn   # verified: navigator_auth/conf.py:39-45
#                       AUTH_ADMIN_DSN, AUTH_ADMIN_USER, AUTH_ADMIN_PWD # added by this task
from navconfig import config             # verified: navigator_auth/conf.py:11 (config.get(key, fallback=...))
from navigator_auth.migrations.access import missing_runtime_access, validate_runtime_role   # TASK-162
from navigator_auth.migrations.catalog import MIGRATION_SETS, MigrationCatalogError          # TASK-159
from navigator_auth.migrations.runner import (                                               # TASK-160/163
    MigrationError, MigrationState, MigrationStatus, UpgradeReport, get_status, upgrade,
)
import argparse, asyncio, getpass, logging, sys                       # stdlib
from urllib.parse import quote, urlsplit                              # stdlib — DSN build / safe description
from collections.abc import Awaitable, Callable, Sequence             # stdlib
import asyncpg   # 0.32.0 installed via asyncdb; imports cleanly under -W error; import LAZILY inside the default connect
```

### Existing Signatures to Use
```python
# navigator_auth/conf.py
DBUSER = config.get("DBUSER")                                    # line 39 (may be None)
DBHOST = config.get("DBHOST", fallback="localhost")              # line 40
DBPWD = config.get("DBPWD")                                      # line 41
DBNAME = config.get("DBNAME", fallback="navigator")              # line 42
DBPORT = config.get("DBPORT", fallback=5432)                     # line 43
default_dsn = f"postgres://{DBUSER}:{DBPWD}@{DBHOST}:{DBPORT}/{DBNAME}"   # line 45

# pyproject.toml
# line 67: [project.urls]
# lines 74-75: comment "# Protected stores for navigator-session vault rotation / migration" (+1 line)
# line 76: [project.entry-points."navigator_session.vault_targets"]
# line 112-116: --strict-markers, only `xmlsec` declared → do NOT add an unregistered marker

# navigator_auth/migrations/runner.py (TASK-160/163)
async def get_status(conn, sets=None) -> list[MigrationStatus]          # read-only
async def upgrade(conn, sets=None, *, runtime_role, reapply_changed=False, fail_fast=False) -> UpgradeReport
#   per-file failures are in the report; raises MigrationError only for run-level problems
# navigator_auth/migrations/access.py (TASK-162)
async def validate_runtime_role(conn, role: str | None) -> str          # read-only; raises MigrationError
async def missing_runtime_access(conn, migration_set: str, role: str) -> list[str]   # read-only

# tests/unit/migrations/conftest.py (TASK-160)
fake_conn fixture → FakeConnection (respond, fail_on, relations, writes(), closed)
```

### Does NOT Exist
- ~~`[project.scripts]` / `console_scripts`~~ — never present in `pyproject.toml` or `setup.py`; this task adds the first.
- ~~`navigator_auth/cli.py`, `navigator_auth/__main__.py`~~ — no CLI module; do not create them.
- ~~`click`, `typer`~~ — not dependencies; use `argparse` (spec §7 "CLI shape").
- ~~`AUTH_ADMIN_DSN`, `AUTH_ADMIN_USER`, `AUTH_ADMIN_PWD`~~ — not in `conf.py` until this task.
- ~~`navigator_session.vault.migrate.cli`~~ — lives in navigator-session; do not import it.
- ~~`asyncdb.AsyncPool` for the CLI~~ — one raw `asyncpg.connect()` connection (advisory lock is per session).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/migrations/cli.py", "action": "CREATE"},
    {"path": "navigator_auth/conf.py", "action": "MODIFY"},
    {"path": "pyproject.toml", "action": "MODIFY"},
    {"path": "tests/unit/migrations/test_cli.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/migrations/runner.py#get_status",
    "sym:navigator_auth/migrations/runner.py#upgrade",
    "sym:navigator_auth/migrations/access.py#validate_runtime_role",
    "sym:navigator_auth/migrations/access.py#missing_runtime_access"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- **Never print or log the DSN or the password** — report only the source label
  (`--dsn`, `AUTH_ADMIN_DSN`, `--user`, `AUTH_ADMIN_USER`, `default_dsn`), host, port,
  database and user (spec §2). Connection-error messages may echo connection strings:
  print the exception type and a message with the password and DSN removed.
- `--check` writes nothing: `validate_runtime_role`, `get_status` and
  `missing_runtime_access` only (spec §2, AC 1).
- Report lines go to stdout; notices and errors to stderr; diagnostics through
  `logging.getLogger("navigator.migrations")` (spec M5).
- argparse exits with code 2 on usage errors — catch `SystemExit` in `main` and return
  `EXIT_CONFIG` (3); `--help` still returns 0.
- `asyncio.run()` inside `main`; `asyncpg` imported lazily inside the default connect
  (spec §7 "CLI shape"). Always close the connection.
- `pyproject.toml` is a shared manifest — this task runs exclusively.

---

## Implementation Blueprint

### Steps (in order)
1. Add the three settings to `conf.py` — *why*: `resolve_dsn` reads them.
2. Write `cli.py` blocks 1-2; fill the `FILL IN`s.
3. Add `[project.scripts]` to `pyproject.toml`.
4. Write `test_cli.py` with an injected `connect` returning `fake_conn`; run the Validation Commands.

### `navigator_auth/conf.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'default_dsn = f"postgres://{DBUSER}:{DBPWD}@{DBHOST}:{DBPORT}/{DBNAME}"' navigator_auth/conf.py)
# AFTER — insert below `default_dsn = f"postgres://{DBUSER}:{DBPWD}@{DBHOST}:{DBPORT}/{DBNAME}"` (verified: navigator_auth/conf.py:45)

## Admin credentials for `navauth self upgrade` (FEAT-110). Schema changes run with
## these, never with the runtime DBUSER unless nothing else is configured.
AUTH_ADMIN_DSN = config.get("AUTH_ADMIN_DSN", fallback=None)
AUTH_ADMIN_USER = config.get("AUTH_ADMIN_USER", fallback=None)
AUTH_ADMIN_PWD = config.get("AUTH_ADMIN_PWD", fallback=None)
```

### `pyproject.toml` (MODIFY)
```toml
# occurrences: 1 (verified: grep -c '# Protected stores for navigator-session vault rotation / migration' pyproject.toml)
# BEFORE — insert above `# Protected stores for navigator-session vault rotation / migration` (verified: pyproject.toml:74)
[project.scripts]
navauth = "navigator_auth.migrations.cli:console_entry"

```
**Why**: spec M5 places the table before `[project.entry-points."navigator_session.vault_targets"]`
(line 76); inserting above its comment keeps the comment attached to its table.

### `navigator_auth/migrations/cli.py` (CREATE) — block 1: parser and credentials
```python
"""``navauth`` console script — ``navauth self upgrade`` (FEAT-110, spec M5)."""
from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import sys
from collections.abc import Awaitable, Callable, Sequence
from typing import Any
from urllib.parse import quote, urlsplit

from .. import conf
from .access import missing_runtime_access, validate_runtime_role
from .catalog import MIGRATION_SETS, MigrationCatalogError
from .runner import MigrationError, MigrationState, UpgradeReport, get_status, upgrade

logger = logging.getLogger("navigator.migrations")

EXIT_OK, EXIT_PENDING, EXIT_FAILED, EXIT_CONFIG = 0, 1, 2, 3


def build_parser() -> argparse.ArgumentParser:
    """``navauth`` → subcommand group ``self`` → command ``upgrade``."""
    parser = argparse.ArgumentParser(prog="navauth", description="navigator-auth administration")
    groups = parser.add_subparsers(dest="group", required=True)
    self_cmd = groups.add_parser("self", help="manage this navigator-auth installation")
    commands = self_cmd.add_subparsers(dest="command", required=True)
    up = commands.add_parser("upgrade", help="apply pending database migrations")
    up.add_argument("--check", action="store_true", help="report applied/pending/changed; change nothing")
    up.add_argument("--dsn", help="admin DSN (highest precedence)")
    up.add_argument("--user", help="admin user; password from AUTH_ADMIN_PWD or a prompt")
    up.add_argument("--set", dest="sets", action="append", choices=MIGRATION_SETS, help="restrict to one set; repeatable")
    up.add_argument("--runtime-role", help="application database role; defaults to DBUSER")
    up.add_argument("--reapply-changed", action="store_true", help="also re-run files whose checksum changed")
    up.add_argument("--fail-fast", action="store_true", help="stop at the first failed file")
    up.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return parser


def resolve_dsn(args: argparse.Namespace, *, getpass_fn: Callable[[str], str] = getpass.getpass) -> tuple[str, str]:
    """Return ``(dsn, source_label)``.

    Precedence: ``--dsn`` → ``AUTH_ADMIN_DSN`` → ``--user``/``AUTH_ADMIN_USER`` with
    ``AUTH_ADMIN_PWD`` (or a prompt on a TTY) plus ``DBHOST``/``DBPORT``/``DBNAME`` →
    ``default_dsn`` with a notice on stderr that runtime credentials are used.

    Raises:
        MigrationError: when no credentials resolve (e.g. a user without password off a TTY).
    """
    # FILL IN: the four steps above, reading conf.* at call time. Build the user DSN as
    #   f"postgres://{quote(user, safe='')}:{quote(password, safe='')}@{conf.DBHOST}:{conf.DBPORT}/{conf.DBNAME}".
    #   Prompt only when sys.stdin.isatty(); otherwise MigrationError. default_dsn requires conf.DBUSER.
    #   Labels: "--dsn", "AUTH_ADMIN_DSN", "--user", "AUTH_ADMIN_USER", "default_dsn".
    raise NotImplementedError


def _describe(dsn: str) -> str:
    """``user@host:port/database`` — never the password."""
    parts = urlsplit(dsn)
    return f"{parts.username or '?'}@{parts.hostname or '?'}:{parts.port or ''}/{parts.path.lstrip('/')}"
```

### `navigator_auth/migrations/cli.py` (CREATE) — block 2: run and entry points
```python
async def _default_connect(dsn: str) -> Any:
    import asyncpg  # pylint: disable=C0415 — lazy, spec §7

    return await asyncpg.connect(dsn)


async def run(args: argparse.Namespace, *, connect: Callable[[str], Awaitable[Any]] | None = None) -> int:
    """Connect, run ``get_status`` or ``upgrade``, print the report, return the exit code.

    Always closes the connection.
    """
    # FILL IN: resolve_dsn (MigrationError → stderr, EXIT_CONFIG); print f"navauth: {label} → {_describe(dsn)}";
    #   connect (any Exception → stderr with type name + sanitized message, EXIT_CONFIG);
    #   runtime_role = args.runtime_role or conf.DBUSER → validate_runtime_role (MigrationError → EXIT_CONFIG);
    #   --check: _print_status(get_status(...)) + missing_runtime_access per selected set (args.sets or MIGRATION_SETS)
    #     → EXIT_PENDING if any state != APPLIED or any missing privilege, else EXIT_OK;
    #   else upgrade(...) → _print_report → EXIT_FAILED if report.failed or report.access_errors else EXIT_OK;
    #   MigrationError / MigrationCatalogError raised by the run → EXIT_CONFIG; `finally: await conn.close()`.
    raise NotImplementedError


def main(argv: Sequence[str] | None = None, *, connect: Callable[[str], Awaitable[Any]] | None = None) -> int:
    """Parse ``argv`` and run. ``connect`` is injectable for tests; default is ``asyncpg.connect``."""
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # argparse: --help → 0, usage error → 2; spec wants 3 for usage errors
        return EXIT_OK if exc.code in (0, None) else EXIT_CONFIG
    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    return asyncio.run(run(args, connect=connect))


def console_entry() -> None:
    """``sys.exit(main())``."""
    sys.exit(main())

# FILL IN: _print_status(statuses) and _print_report(report: UpgradeReport) — one stdout line per file
#   ("applied   vault/001_create_vault_tables.sql"), failures with their error, skipped CHANGED files with
#   the hint `--reapply-changed`, access errors, and a final summary line.
```

### FILL IN checklist
- [ ] `resolve_dsn` — precedence, quoting, TTY prompt, notice
- [ ] `run` — flow, exit-code mapping, sanitized errors, close
- [ ] `_print_status` / `_print_report`
- [ ] `test_cli.py` — tests below

---

## Acceptance Criteria

- [ ] `navauth self upgrade --check` on a database without the ledger lists every catalog file as pending, exits `1`, and writes nothing.
- [ ] Exit codes: `0` nothing pending / success; `1` `--check` with pending, changed or missing access; `2` failed file or access error; `3` bad `--set`, connect error, invalid runtime role, missing credentials.
- [ ] Credentials resolve `--dsn` → `AUTH_ADMIN_DSN` → `--user`/`AUTH_ADMIN_USER` + `AUTH_ADMIN_PWD` or prompt → `default_dsn` (with a notice); neither the DSN nor the password appears in stdout, stderr or logs.
- [ ] `pyproject.toml` declares `navauth = "navigator_auth.migrations.cli:console_entry"`.
- [ ] A built wheel contains `navigator_auth/migrations/sql/identity/004_identity_base_columns.sql` and the `navauth` entry point (or the test skips when the build toolchain is unavailable).

---

## Validation Commands

- `pytest tests/unit/migrations/test_cli.py -q`

---

## Test Specification

```python
# tests/unit/migrations/test_cli.py
import pytest

from navigator_auth.migrations import cli


def test_resolve_dsn_precedence(monkeypatch):
    """flag → AUTH_ADMIN_DSN → user+password (and getpass_fn on a TTY) → default_dsn with a stderr notice;
    no credentials off a TTY → MigrationError."""


def test_cli_never_prints_dsn_or_password(fake_conn, capsys, caplog, monkeypatch):
    """AUTH_ADMIN_PWD='s3cr3t-pw', --dsn with a password, and a connect error echoing the DSN:
    neither string appears in captured stdout, stderr or caplog.text."""


@pytest.mark.parametrize("scenario,expected", [("nothing_pending", 0), ("check_pending", 1),
                                               ("failed_file", 2), ("bad_set", 3), ("connect_error", 3),
                                               ("invalid_runtime_role", 3)])
def test_cli_exit_codes(fake_conn, tmp_catalog, scenario, expected):
    """main([...], connect=<returns fake_conn or raises>) returns the spec exit code."""


def test_cli_check_does_not_write(fake_conn):
    """--check: fake_conn.writes() is empty; no GRANT, no CREATE, no INSERT."""


def test_check_reports_missing_runtime_access_without_writes(fake_conn, capsys):
    """respond('has_table_privilege', False) → exit 1 and a missing-access line; quoted role identifiers
    never reach SQL text (role is a $n parameter); invalid role → exit 3."""


def test_console_script_declared():
    """tomllib: project.scripts.navauth == 'navigator_auth.migrations.cli:console_entry'."""


def test_wheel_contains_sql(tmp_path):
    """Build a wheel (python -m build --wheel); assert the identity 004 SQL file and the `navauth`
    console_scripts entry are inside. pytest.skip when `build` is not importable or the build fails for
    toolchain reasons (no compiler)."""
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
9. **Close the task** with `parrot sdd task close TASK-165 new-command-migration verified`
   — it moves this file to `sdd/tasks/completed/` and marks it `"done"` in the
   index; never move or copy the file by hand
10. **Fill in the Completion Note** below, then commit the staged SDD state

---

## Completion Note

**Completed by**: sdd-worker (codex gpt-5.6-terra · attempt 1 · 362s)
**Date**: 2026-11-11
**Notes**: CLI delivered and merged. Merge-tier surfaced two failures in TASK-159's test_catalog.py caused by TASK-167's oauth2 set; fixed by orchestrator (tests scoped to released sets), tests/unit/migrations 58 passed. Closed via `parrot sdd task close` (durable evidence root read-only).

**Deviations from spec**: none
