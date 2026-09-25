# TASK-072: Context registry, entry-point discovery and PostgreSQL target base

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 3)
**Repository**: `../navigator-session`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-071
**Assigned-to**: unassigned

---

## Context

G4: one registry describes every protected store so runtime, rotation (TASK-074) and migration
(TASK-075) agree on contexts. navigator-session must not depend on DocumentDB, so stores are
contributed by packages through the entry-point group `navigator_session.vault_targets`
(navigator-auth: identity; ai-parrot: credentials, BYOK, users_bots).

This task delivers the protocols, discovery, a reusable asyncpg target base with
export/restore/quarantine, and the first concrete target: `auth.user_vault_secrets`.

---

## Scope

- `navigator_session/vault/registry.py`:
  - `TargetRow` and `ProtectedTarget` protocols exactly as spec §2 (incl. `quarantine(row,
    reason, run_id)`, `export_raw(sink)`, `restore_raw(source)`, optional
    `legacy_unwrap(field, plaintext, row) -> bytes` hook).
  - `BackupSink` / `BackupSource` protocols (implemented in TASK-075).
  - `discover_targets(**resources)` — loads entry points; each entry point is a factory
    `(resources) -> ProtectedTarget | None`; failing factories are logged and skipped;
    duplicate `name` → error.
- `navigator_session/vault/targets/postgres.py`: `PostgresTarget` base:
  - keyset pagination by primary key (`WHERE pk > $1 ORDER BY pk LIMIT $2`);
  - per-batch transactions; `write()` updates ciphertext columns + `key_version`;
  - `export_raw` streams rows as-is; `restore_raw` rewrites stored bytes by PK;
  - `quarantine` = soft-delete (`deleted_at = NOW()`) + audit hook (overridable per table).
  - Reuse the pool acquire/release compatibility pattern from `session_vault.py`.
- `navigator_session/vault/targets/user_vault.py`: `UserVaultTarget` for
  `auth.user_vault_secrets` (context `user-vault`/`db`/`(user_id, key)`; includes soft-deleted
  rows; quarantine audit `operation='quarantine'` into `auth.user_vault_audit`).
- `pyproject.toml`: declare entry-point group and register `user_vault`.
- Tests `tests/vault/test_registry.py`, `tests/vault/test_postgres_target.py` (async pool double).

**NOT in scope**: identity / parrot targets (TASK-077, TASK-079, TASK-081); migration runner
and backup file format (TASK-075); rotation (TASK-074); `SessionVault` (TASK-073).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_session/vault/registry.py` | CREATE | Protocols + discovery |
| `navigator_session/vault/targets/__init__.py` | CREATE | Package |
| `navigator_session/vault/targets/postgres.py` | CREATE | `PostgresTarget` base |
| `navigator_session/vault/targets/user_vault.py` | CREATE | `auth.user_vault_secrets` target |
| `pyproject.toml` | MODIFY | `[project.entry-points."navigator_session.vault_targets"]` |
| `tests/vault/test_registry.py` | CREATE | Discovery tests |
| `tests/vault/test_postgres_target.py` | CREATE | Pagination, write, quarantine, export/restore |

---

## Implementation Notes

### Key Constraints
- Keyset pagination is mandatory (the OFFSET bug fixed in `key_rotation.py` must not return).
- `TargetRow.ref` must be printable and secret-free (e.g. `"user_vault:id=42"`).
- SQL identifiers (schema/table/columns) come from the target definition, never from user
  input; still quote them.
- Entry-point factories receive resources such as `db_pool`, `docdb_factory`, `redis`; a
  target returns `None` when its resource is absent (e.g. no DocumentDB configured).

### References in Codebase
- `navigator_session/vault/key_rotation.py` — batch/transaction/offset handling to improve on
- `navigator_session/vault/session_vault.py` — acquire/release compatibility pattern, SQL
- `../navigator-auth/navigator_auth/vault/sql/001_create_vault_tables.sql` — table definitions

---

## Acceptance Criteria

- [ ] `discover_targets()` returns registered targets; broken factory logged + skipped
- [ ] `PostgresTarget` visits every row exactly once with keyset pagination
- [ ] `quarantine` soft-deletes and writes audit with `run_id`
- [ ] `export_raw` → `restore_raw` restores byte-identical ciphertext
- [ ] `UserVaultTarget.context_for` returns `user-vault`/`db`/`(user_id, key)`
- [ ] `pytest tests/vault -v` passes

---

## Test Specification

```python
# tests/vault/test_postgres_target.py
import pytest
from navigator_session.vault.targets.user_vault import UserVaultTarget


@pytest.mark.asyncio
async def test_iter_batches_visits_all(fake_pool_with_rows):
    target = UserVaultTarget(db_pool=fake_pool_with_rows(250))
    seen = [r.ref async for batch in target.iter_batches(100) for r in batch]
    assert len(seen) == len(set(seen)) == 250


def test_context_for(sample_row):
    ctx = UserVaultTarget(db_pool=None).context_for(sample_row, "ciphertext_db")
    assert ctx.purpose == "user-vault" and ctx.layer == "db"
    assert [n for n, _ in ctx.fields] == ["user_id", "key"]
```

---

## Agent Instructions

1. **Read the spec** (Module 3, §2 interfaces and quarantine semantics)
2. **Check dependencies** — TASK-071 completed
3. **Update status** → `"in-progress"`
4. **Implement** in the navigator-session feature worktree
5. **Verify** acceptance criteria
6. **Move file** to `sdd/tasks/completed/`, index → `"done"`
7. **Completion Note**

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: claude-session (Claude Opus 5)
**Date**: 2026-09-15
**Notes**:
- navigator-session worktree branch `feat-FEAT-099-vault-crypto-hardening`, commit `dcdd785`.
- `registry.py`: `VaultRow` (frozen dataclass: `ref`, `pk`, `identity`, `values`,
  `key_version`, `state`), protocols `TargetRow`, `ProtectedTarget` (runtime-checkable),
  `BackupSink.write(target, record)`, `BackupSource.read(target)`; `discover_targets(**resources)`
  loads entry points sorted by name, passes the resources mapping to each factory, skips
  factories that raise / return `None` / return a non-target (logged), rejects duplicate names.
- `targets/postgres.py`: `quote_ident`, `acquire_connection`, `fetch_rows` (shared pool/driver
  compatibility helpers) and `PostgresTarget` (declarative class attributes; keyset pagination;
  connection released before yielding a batch; `transaction()` nested-safe via a per-target
  `ContextVar`; `write`; `quarantine` = `quarantine_assignments` + `audit_quarantine` hook in
  one transaction; `export_raw`/`restore_raw` restore blobs + key version + lifecycle columns in
  one transaction; `LookupError` when a row is missing).
- `targets/user_vault.py`: `UserVaultTarget` (`id` UUID pk, identity `(user_id:int, key:str)`,
  `ciphertext_db`, state `deleted_at`/`updated_at`, quarantine
  `deleted_at = COALESCE(deleted_at, NOW())`, audit `operation='quarantine'`,
  `session_id='run:<run_id>'`, run_id `[A-Za-z0-9_-]{1,32}`) + `factory` (needs `db_pool`).
- `pyproject.toml`: entry point `user_vault` in `navigator_session.vault_targets`.
- Tests: `tests/vault/fake_pg.py` (in-memory PG double enforcing pool size and transactions,
  reusable by TASK-073/074/075), `test_registry.py`, `test_postgres_target.py` (32 tests,
  incl. 250-row keyset iteration with soft-deleted rows, write-while-iterating on a 1-connection
  pool, rollback, awaitable pools, sealed cross-user swap detection, quarantine audit,
  byte-identical export→migrate→quarantine→restore). navigator-session `tests/` 213 passed;
  `ruff check` clean.

**Deviations from spec**:
- `ProtectedTarget` gained `transaction()` (needed for per-batch transactions in rotation and
  migration, since `write()` takes no connection).
- `restore_raw` also restores lifecycle columns (`deleted_at`, `updated_at`) so rollback is
  byte-identical, including rows quarantined by the migration.
- Schema findings pushed to TASK-078 (migration 002) and TASK-073: audit `operation` CHECK
  rejects `quarantine`/`integrity_fail`, `session_id VARCHAR(36)` < 64-char HMAC,
  `key_version SMALLINT` < `KeyRing` max key id 65535. Migration 002 must run before the
  migrator.
- Entry-point discovery is tested with patched `entry_points` and by resolving the
  `pyproject.toml` declaration; the installed-metadata path is exercised in TASK-085 once the
  package is reinstalled.
