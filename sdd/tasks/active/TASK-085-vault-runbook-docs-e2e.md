# TASK-085: Runbook, docs, versions and cross-repo migration rehearsal

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 14, §2 Deployment Runbook, §5 Acceptance Criteria)
**Repository**: `../navigator-session` + `navigator-auth` (docs/CHANGELOG/version in `ai-parrot` too)
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-074, TASK-076, TASK-078, TASK-081, TASK-082, TASK-083, TASK-084
**Assigned-to**: unassigned

---

## Context

Closing task. Proves the whole system works together on seeded v1 data across every target,
measures the migration duration for ops, and ships the operator documentation and version
bumps for a coordinated breaking release.

---

## Scope

- **E2E rehearsal** `navigator-session/tests/integration/test_vault_migration_e2e.py`:
  seed v1 data (frozen fixtures) in PostgreSQL targets (`auth.user_vault_secrets`,
  `auth.user_identities`, `users_bots`) and DocumentDB doubles/containers (`user_credentials`,
  `user_llm_keys`) with all packages installed (entry points discovered) → `migrate --dry-run`
  → `migrate --run --backup-dir` → `verify` → runtime reads succeed with v2 → v1 rejected →
  `restore` returns byte-identical data. Include one deliberately undecryptable row per engine
  and a `--quarantine` run. Mark as integration (skippable without DB services).
- `test_rotation_after_migration`, `test_redis_dump_not_decryptable` integration tests (spec §4).
- Record measured duration and row counts in the runbook.
- **Docs** in `navigator-session/docs/vault/`: `format.md` (envelope, AAD, key schedule,
  errors), `targets.md` (registry, entry points, writing a target), `migration-runbook.md`
  (spec §2 runbook, quarantine semantics, backup handling/retention, rollback, `purge-redis`),
  threat model update. Link from navigator-auth `docs/` (vault/identity pages).
- **Versions/CHANGELOG**: navigator-session `1.0.0`, navigator-auth `0.28.0`, ai-parrot and
  ai-parrot-server next minor; CHANGELOG entries flag BREAKING changes (crypto API, HTTP GET
  vault value removal, IdentityCipher signature, credential helper signatures).
- Final acceptance sweep: grep checks from spec §5 (no `associated_data=None`, no v1 function
  references, no `value` in vault GET responses) across all four repos; run each repo's test
  suite and save logs to `artifacts/logs/` in navigator-auth.

**NOT in scope**: executing the production migration (ops); new functionality.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `../navigator-session/tests/integration/test_vault_migration_e2e.py` | CREATE | Rehearsal |
| `../navigator-session/tests/integration/test_vault_security.py` | CREATE | Rotation + Redis dump tests |
| `../navigator-session/docs/vault/format.md` | CREATE | Format + key schedule |
| `../navigator-session/docs/vault/targets.md` | CREATE | Registry guide |
| `../navigator-session/docs/vault/migration-runbook.md` | CREATE | Runbook |
| `../navigator-session/navigator_session/version.py` | MODIFY | `1.0.0` |
| `../navigator-session/CHANGELOG.md` | MODIFY | BREAKING notes |
| `navigator_auth/version.py`, `CHANGELOG.md`, `docs/` | MODIFY | `0.28.0`, notes, links |
| `../ai-parrot/packages/*/CHANGELOG*` / version files | MODIFY | Next minor, notes |
| `artifacts/logs/feat-099-*.log` | CREATE | Test evidence |

---

## Implementation Notes

### Key Constraints
- The rehearsal must run the real CLI entry point (subprocess or `main([...])`), not only
  runner functions.
- Rehearsal backup dir under `tmp_path` with permission assertions (`0700`/`0600`).
- Keep docs free of real key material; examples use `generate_master_key()` output placeholders.

### References in Codebase
- Spec §2 Deployment Runbook and Quarantine semantics, §4 Integration Tests, §5
- `navigator_auth/version.py` (`0.26.0` today; FEAT-098 targets `0.27.0`)
- `../navigator-session/navigator_session/version.py` (`0.10.2` today)

---

## Acceptance Criteria

- [ ] E2E rehearsal green: dry-run, run (with backup), verify, quarantine, restore
- [ ] Rotation-after-migration and Redis-dump tests green
- [ ] Runbook documents measured duration, backup handling and rollback
- [ ] Versions bumped and CHANGELOGs mark BREAKING changes in all Python packages
- [ ] Spec §5 grep checks pass in all repos; per-repo test logs saved in `artifacts/logs/`
- [ ] All §5 acceptance criteria of the spec checked off

---

## Test Specification

```python
# navigator-session/tests/integration/test_vault_migration_e2e.py
import pytest
from navigator_session.vault.migrate.cli import main

pytestmark = pytest.mark.integration


def test_full_rehearsal(seeded_v1_environment, tmp_path):
    assert main(["migrate", "--dry-run"]) == 0
    assert main(["migrate", "--run", "--backup-dir", str(tmp_path), "--quarantine"]) == 0
    assert main(["verify"]) == 0
    seeded_v1_environment.assert_runtime_reads_v2()
    run_dir = next(tmp_path.iterdir())
    assert main(["restore", "--backup-dir", str(run_dir), "--yes"]) == 0
    seeded_v1_environment.assert_byte_identical_to_seed()
```

---

## Agent Instructions

1. **Read the spec** (Module 14, §2 runbook, §4, §5)
2. **Check dependencies** — all listed tasks completed and merged in their repos
3. **Update status** → `"in-progress"`
4. **Implement** (navigator-session and navigator-auth feature worktrees)
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
