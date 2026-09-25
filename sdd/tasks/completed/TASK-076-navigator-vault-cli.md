# TASK-076: `navigator-vault` CLI and `purge-redis`

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 6 CLI, §2 Deployment Runbook)
**Repository**: `../navigator-session`
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-075, TASK-073
**Assigned-to**: unassigned

---

## Context

Operators run the migration through a single command. The CLI wires resources (PostgreSQL
pool, Redis, and whatever factories ai-parrot targets need), discovers targets, calls the
runner, prints/saves the JSON report and returns meaningful exit codes. It also provides the
SCAN-based Redis purge used for the forced re-login.

---

## Scope

- `navigator_session/vault/migrate/cli.py` + console script `navigator-vault` in `pyproject.toml`.
- Subcommands (spec §2):
  - `migrate --dry-run`
  - `migrate --run --backup-dir DIR [--quarantine] [--batch-size N] [--target NAME ...] [--run-id ID]`
  - `verify [--target NAME ...]`
  - `restore --backup-dir DIR/<run_id> [--target NAME ...]` (asks for confirmation unless `--yes`)
  - `rotate --from N --to M [--target NAME ...]` (thin wrapper over TASK-074)
  - `purge-redis [--sessions] [--dry-run]` — `SCAN MATCH vault:*` (and legacy `vault:*` v1
    names) plus `session:*` when `--sessions`; batched `UNLINK`; prints counts only.
  - `list-targets` — names discovered via entry points.
- Resource configuration from environment (same variables navigator-auth uses for `authdb` /
  Redis); resources passed to `discover_targets(**resources)`.
- Exit codes: `0` success/verified, `2` failures present, `3` configuration error, `4` backup
  error. `--report PATH` writes `MigrationReport` JSON.
- Tests `tests/vault/test_cli.py` (argument parsing, exit codes, purge with fake Redis).

**NOT in scope**: runner logic (TASK-075), docs/runbook (TASK-085).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_session/vault/migrate/cli.py` | CREATE | CLI |
| `pyproject.toml` | MODIFY | `[project.scripts] navigator-vault = ...` |
| `tests/vault/test_cli.py` | CREATE | CLI tests |

---

## Implementation Notes

### Runner API delivered by TASK-075 (use as-is)
- `migrate_v1_to_v2(targets, keyring, *, dry_run, quarantine, backup_dir, batch_size, run_id=None,
  legacy=None)` → `MigrationReport`; `report.ok` is False when unquarantined failures remain
  (→ exit 2). Raises `ValueError` (bad args → exit 3) and `BackupError` (→ exit 4).
  `--run-id` resumes when `<backup-dir>/<run_id>/manifest.json` exists.
- `verify_v2(targets, keyring, *, exclude_refs=())` → `report.verified`. For `verify`, accept an
  optional `--backup-dir DIR/<run_id>` and pass `JsonlBackupSource(run_dir).quarantined_refs()`
  as `exclude_refs`, otherwise quarantined rows (still v1) fail verification.
- `restore_backup(targets, run_dir, *, only=None)` verifies checksums before writing
  (`BackupIntegrityError` → exit 4).
- `LegacyV1Reader.from_env()` is the default v1 reader; `KeyRing.from_env()` for v2.
- Reports serialize with `report.model_dump_json()`.
- Not implemented in TASK-075 (do it here if cheap): warning about concurrent writers during a
  run (e.g. compare `auth.user_vault_audit` max `created_at` before/after).

### Key Constraints
- Async entry via `asyncio.run()`; optional `uvloop` must not be required.
- Never print values; report shows refs, counts, durations.
- `purge-redis` must not use `KEYS`.
- `--run` refuses to start if `list-targets` is empty or a known target reports `None`
  resource unless `--target` restricts the run explicitly.

### References in Codebase
- `navigator_session/storages/redis.py` — Redis connection settings and `session:` prefix
- `navigator_session/conf.py` — configuration access

---

## Acceptance Criteria

- [ ] All subcommands parse and dispatch; `--help` documents runbook order
- [ ] `migrate --run` without `--backup-dir` exits `3` with no writes
- [ ] Failures without quarantine exit `2`; report JSON written with `--report`
- [ ] `purge-redis --sessions --dry-run` counts keys without deleting; real run uses SCAN+UNLINK
- [ ] `pytest tests/vault/test_cli.py -v` passes

---

## Test Specification

```python
# tests/vault/test_cli.py
import pytest
from navigator_session.vault.migrate.cli import main


def test_run_requires_backup_dir(capsys):
    assert main(["migrate", "--run"]) == 3


@pytest.mark.asyncio
async def test_purge_redis_uses_scan(fake_redis_with_keys, monkeypatch):
    ...
```

---

## Agent Instructions

1. **Read the spec** (Module 6, Runbook)
2. **Check dependencies** — TASK-073, TASK-075 completed
3. **Update status** → `"in-progress"`
4. **Implement** in the navigator-session feature worktree
5. **Verify** acceptance criteria
6. **Move file** to `sdd/tasks/completed/`, index → `"done"`
7. **Completion Note**

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: claude-session (Claude Opus 5)
**Date**: 2026-09-16
**Notes**:
- navigator-session worktree branch `feat-FEAT-099-vault-crypto-hardening`, commit `97e5eed`.
- `navigator_session/vault/migrate/cli.py`: `main(argv, *, resources_factory, discover, confirm,
  out) -> int` (injectable for tests), `console_entry()`, `build_parser()`, `purge_redis()`,
  `select_targets()`, `resolve_dsn()`, `resolve_redis_url()`, `default_resources()`.
  - Subcommands: `migrate --dry-run | --run --backup-dir DIR [--quarantine] [--run-id]
    [--batch-size] [--target ...]`, `verify [--backup-dir RUN_DIR] [--target ...]`,
    `restore --backup-dir RUN_DIR [--yes] [--target ...]`, `rotate --from N --to M`,
    `purge-redis [--sessions] [--dry-run]`, `list-targets`; global `--dsn`, `--redis-url`,
    `--report PATH` (JSON, 0600), `--log-level`.
  - Resources: DSN from `--dsn` → `VAULT_DB_DSN` → navconfig `DBUSER/DBPWD/DBHOST/DBPORT/DBNAME`
    (asyncpg imported lazily, not a navigator-session dependency); Redis from `--redis-url` →
    `VAULT_REDIS_URL` → `SESSION_URL`. Errors report exception class only (DSN never printed).
  - Exit codes: 0 ok, 1 restore aborted, 2 failed rows / verification failed / rotation errors,
    3 usage (argparse errors mapped from 2 to 3) or configuration (keys, unknown targets, bad
    args), 4 backup errors.
  - `migrate --run` requires `--backup-dir` (checked before opening resources) and refuses to run
    when fewer targets are configured than registered entry points, unless `--target` is used.
  - Concurrent-writer check: compares `max(created_at)` of user-initiated audit operations
    (`set/get/delete`) before/after `--run` and logs a warning (best-effort; returns None on error).
  - `purge-redis`: `SCAN` + `UNLINK` over `vault:*` (covers v1 and `vault:v2:*` names) and, with
    `--sessions`, `session:*`. `user:*` identity index keys are left untouched (they point to
    deleted sessions and are ignored on next login).
  - `restore` without `--yes` asks the operator to type the run id.
- `pyproject.toml`: `[project.scripts] navigator-vault = "navigator_session.vault.migrate.cli:console_entry"`.
- Tests `tests/vault/test_cli.py` (25): help/usage exit codes, backup-dir required before
  resources open, missing keys, unknown/unconfigured targets, list-targets, full runbook
  (dry run → run with JSON report → verify with backup exclusions → aborted restore → restore
  byte-identical), failures exit 2 vs quarantine exit 0, tampered backup and unsafe dir exit 4,
  concurrent-writer warning, rotate ok/unknown key/errors, purge-redis dry run / vault only /
  sessions with paginated SCAN on a double without `KEYS`, DSN/Redis URL resolution.
- Results: navigator-session `tests/` 337 passed; `ruff check` clean; `python -m
  navigator_session.vault.migrate.cli --help` works.
- Not exercised against real PostgreSQL/Redis (`default_resources` path) — covered by the
  cross-repo rehearsal in TASK-085.

**Deviations from spec**:
- Added exit code `1` (operator aborted restore) and mapped argparse usage errors to `3`, so `2`
  always means "data failures".
- `verify` accepts `--backup-dir` to exclude rows quarantined by that run.
- `list-targets` opens the database pool (factories need it to report configured targets).
- The concurrent-writer warning (deferred from TASK-075) is implemented here.
