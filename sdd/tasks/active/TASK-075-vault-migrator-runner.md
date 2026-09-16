# TASK-075: Offline migrator — legacy v1 reader, backup export/restore, runner

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 6, §2 Deployment Runbook & Quarantine semantics)
**Repository**: `../navigator-session`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-072
**Assigned-to**: unassigned

---

## Context

G5. Migration is offline and one-shot; v1 is rejected afterwards. This is the only place where
v1 decryption survives. The runner must be safe to operate: mandatory raw backup before each
target is written, resumable, explicit quarantine, byte-exact restore for rollback.

---

## Scope

- `navigator_session/vault/migrate/legacy_v1.py` — v1 `decrypt_for_db` equivalent (HKDF
  `"vault-db-v{N}"`, format `key_id‖nonce‖ct‖tag`, cipher from `VAULT_CIPHER_BACKEND`);
  **not** exported from `navigator_session.vault`.
- `navigator_session/vault/migrate/backup.py`:
  - `JsonlBackupSink` / `JsonlBackupSource` implementing the protocols from TASK-072;
    layout `backup-dir/<run_id>/<target>.jsonl` + `manifest.json` (target, count, SHA-256,
    started/finished timestamps, package versions).
  - Directory checks: must exist or be creatable, empty for a new `run_id`, not world-readable;
    create files `0600`, dirs `0700`.
  - Records contain stored blobs (base64) + row identity only — never plaintext.
- `navigator_session/vault/migrate/runner.py`:
  - `migrate_v1_to_v2(targets, keyring, *, dry_run, quarantine, backup_dir, batch_size)`.
  - Per target: (run) export → iterate → for each field: if already v2 (`0xA2` and opens
    with context) count `already_v2`; else v1 decrypt → optional `target.legacy_unwrap(...)` →
    `seal` with context under the active key → `write`. Failures → `failed_refs`; with
    `quarantine=True` call `target.quarantine(row, reason, run_id)`.
  - `dry_run`: decrypt-only pass, zero writes, no backup required.
  - Resumable: reuse existing `run_id` manifest; skip export if the target's backup is complete.
  - Exit semantics: report `verified=False` and non-success if `failed > 0` without quarantine.
  - `verify_v2(targets, keyring)`: every non-NULL blob opens as v2 with its context.
  - `restore_backup(targets, backup_dir)`: call `target.restore_raw(source)` for each target in
    the manifest; verify SHA-256 first.
  - Warn if audit rows newer than run start appear during the run (concurrent writers).
- `MigrationReport` / `MigrationTargetReport` models (spec §2).
- Tests `tests/vault/test_migrate_runner.py`, `tests/vault/test_backup.py` using the frozen
  `tests/vault/fixtures/v1_blobs.json` from TASK-071 and fake targets.

**NOT in scope**: CLI argument parsing and `purge-redis` (TASK-076); concrete identity / parrot
targets (TASK-077, TASK-079, TASK-081); end-to-end rehearsal (TASK-085).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_session/vault/migrate/__init__.py` | CREATE | Package (no v1 re-export) |
| `navigator_session/vault/migrate/legacy_v1.py` | CREATE | Isolated v1 reader |
| `navigator_session/vault/migrate/backup.py` | CREATE | JSONL sink/source + manifest |
| `navigator_session/vault/migrate/runner.py` | CREATE | migrate / verify / restore |
| `navigator_session/vault/migrate/models.py` | CREATE | Report models |
| `tests/vault/test_migrate_runner.py` | CREATE | Runner tests |
| `tests/vault/test_backup.py` | CREATE | Backup tests |

---

## Implementation Notes

### Key Constraints
- Backup export for a target completes (and is fsync'ed) **before** its first write.
- v1 detection: attempt v2 parse only if first byte is `0xA2` **and** it opens; otherwise treat
  as v1. A v1 blob that fails v1 decryption is a failure, never silently skipped.
- Plaintext lives only in local variables per row; never logged, never written to backup.
- Deterministic ordering (by PK / `_id`) so resumes are predictable.

### References in Codebase
- `navigator_session/vault/crypto.py` (git history before TASK-071) — v1 algorithm
- `navigator_session/vault/registry.py` — protocols
- `tests/vault/fixtures/v1_blobs.json` — frozen v1 data

---

## Acceptance Criteria

- [ ] `dry_run` reports counts with zero writes
- [ ] `run` without valid `backup_dir` fails before any write
- [ ] Backup exists with manifest + SHA-256 before first write; no plaintext in files
- [ ] Interrupted run resumes; migrated rows counted as `already_v2`
- [ ] Failure without quarantine → not verified; with quarantine → target `quarantine` called with `run_id`
- [ ] migrate → restore yields byte-identical rows
- [ ] `legacy_v1` not importable via `navigator_session.vault`
- [ ] `pytest tests/vault -v` passes

---

## Test Specification

```python
# tests/vault/test_migrate_runner.py
import pytest
from navigator_session.vault.migrate.runner import migrate_v1_to_v2, restore_backup


@pytest.mark.asyncio
async def test_run_requires_backup_dir(keyring, fake_v1_target):
    with pytest.raises(ValueError):
        await migrate_v1_to_v2([fake_v1_target], keyring, dry_run=False,
                               quarantine=False, backup_dir=None)
    assert fake_v1_target.writes == 0


@pytest.mark.asyncio
async def test_migrate_then_restore_is_byte_identical(keyring, fake_v1_target, tmp_path):
    before = fake_v1_target.snapshot()
    report = await migrate_v1_to_v2([fake_v1_target], keyring, dry_run=False,
                                    quarantine=False, backup_dir=tmp_path)
    assert report.targets[0].migrated == len(before)
    await restore_backup([fake_v1_target], tmp_path / report.run_id)
    assert fake_v1_target.snapshot() == before
```

---

## Agent Instructions

1. **Read the spec** (Module 6, Runbook, Quarantine semantics)
2. **Check dependencies** — TASK-072 completed (TASK-071 fixtures available)
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
