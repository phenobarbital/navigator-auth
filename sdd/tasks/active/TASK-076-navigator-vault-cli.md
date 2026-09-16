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

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
