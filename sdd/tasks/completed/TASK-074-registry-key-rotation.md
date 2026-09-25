# TASK-074: Registry-driven master key rotation

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 5)
**Repository**: `../navigator-session`
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-072
**Assigned-to**: unassigned

---

## Context

`rotate_master_key()` today only knows `auth.user_vault_secrets` and re-encrypts without
context. With AAD every store needs its own context, and identity/parrot stores must rotate
too. Rotation becomes a loop over discovered `ProtectedTarget`s.

---

## Scope

- Rewrite `navigator_session/vault/key_rotation.py`:
  `rotate_master_key(targets, old_key_id, new_key_id, keyring, batch_size=100) -> dict[str, dict]`.
  - For each target and row whose blobs carry `old_key_id` (parse header): `open_sealed` with
    `target.context_for(row, field)` → `seal` under `new_key_id` → `target.write(...)`.
  - Stats per target: `total`, `rotated`, `skipped` (already on new key / NULL field),
    `errors`; failed rows stay untouched and are reported by `ref`.
  - Audit `operation='rotate'` via target hook where the target supports audit.
  - Validate both key ids exist in the ring (`UnknownKeyVersionError`).
- `KeyRing` helper to seal with an explicit `key_id` (if not already available from TASK-071,
  add a keyword `key_id=` to `seal`).
- Remove any temporary v1 shim usage for this module.
- Tests `tests/vault/test_key_rotation.py` (port scenarios from
  `../navigator-auth/tests/unit/vault/test_key_rotation.py`: batching, error rows not skipped,
  idempotency).

**NOT in scope**: CLI wiring for rotation (optional follow-up; migrator CLI is TASK-076);
v1→v2 migration (TASK-075).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_session/vault/key_rotation.py` | MODIFY | Registry-driven rotation |
| `navigator_session/vault/envelope.py` | MODIFY | `key_id=` override for `seal` (if needed) |
| `tests/vault/test_key_rotation.py` | CREATE | Rotation tests with two fake targets |

---

## Implementation Notes

### Key Constraints
- A row is "on old key" when any of its non-NULL blobs has header `key_id == old_key_id`.
- Multi-field rows (identity tokens, users_bots configs) rotate all fields in one `write`.
- Naming key is unaffected by rotation (TASK-070 guarantees it).
- Never log values.

### References in Codebase
- `navigator_session/vault/key_rotation.py` — current batching and offset rationale comments
- `navigator_session/vault/registry.py` — `ProtectedTarget`

---

## Acceptance Criteria

- [ ] Two targets (single-field and multi-field) fully rotated; stats per target
- [ ] Rows that fail to open are left intact and reported; loop terminates
- [ ] Re-running rotation is idempotent (`rotated == 0`, all `skipped`)
- [ ] Unknown key ids raise before touching data
- [ ] `pytest tests/vault/test_key_rotation.py -v` passes

---

## Test Specification

```python
# tests/vault/test_key_rotation.py
import pytest
from navigator_session.vault.key_rotation import rotate_master_key


@pytest.mark.asyncio
async def test_rotates_all_targets(keyring_two_keys, fake_single_target, fake_multi_target):
    stats = await rotate_master_key([fake_single_target, fake_multi_target], 1, 2,
                                    keyring_two_keys)
    assert stats[fake_single_target.name]["rotated"] == fake_single_target.count
    assert all(h.key_id == 2 for h in fake_multi_target.headers())


@pytest.mark.asyncio
async def test_idempotent(keyring_two_keys, fake_single_target):
    await rotate_master_key([fake_single_target], 1, 2, keyring_two_keys)
    stats = await rotate_master_key([fake_single_target], 1, 2, keyring_two_keys)
    assert stats[fake_single_target.name]["rotated"] == 0
```

---

## Agent Instructions

1. **Read the spec** (Module 5)
2. **Check dependencies** — TASK-072 completed
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
- navigator-session worktree branch `feat-FEAT-099-vault-crypto-hardening`, commit `fa267c5`.
- `key_rotation.py` rewritten: `rotate_master_key(targets, old_key_id, new_key_id, keyring,
  batch_size=100) -> dict[target_name, stats]`, stats = `total`, `rotated`, `skipped`, `errors`,
  `failed_refs`. Validates both key ids (`UnknownKeyVersionError`) and `old != new`,
  `batch_size >= 1` before any read. Iterates `target.iter_batches()` (keyset), one
  `target.transaction()` per batch; per row: parse headers of non-NULL fields, skip if none on
  `old_key_id`, re-seal every field not already on `new_key_id` via
  `open_sealed(context_for) → seal(key_id=new)`, single `target.write(row, blobs, new_key_id)`,
  then optional `target.record_rotation(row, new_key_id)`.
  `VaultCryptoError` (tamper, swapped context, v1 blob, missing key version) and `LookupError`
  (row vanished) → row untouched, counted as error with its ref; any other exception rolls back
  the batch and propagates.
- `UserVaultTarget.record_rotation`: audit `operation='rotate'`, `session_id` NULL, on the
  current transaction connection.
- `_legacy_v1_shim.py` deleted — no v1 crypto remains in the runtime package (migrator gets its
  own isolated reader in TASK-075). Package docstring updated.
- `tests/vault/fake_pg.py`: `NULL` literal support in INSERT.
- Tests `tests/vault/test_key_rotation.py` (14): both targets rotated incl. soft-deleted rows
  and NULL fields, audit rows, mixed-version multi-field row only re-seals old fields,
  idempotency (byte-identical second run), third key version untouched, tampered/swapped/v1
  rows reported and left intact, field on a key version missing from the ring, unknown key ids
  rejected with zero SQL, argument validation, vanished row, mid-batch failure rolls back only
  that batch, no plaintext/blobs in logs, shim import fails.
- Results: navigator-session `tests/` 273 passed; `ruff check` clean.

**Deviations from spec**:
- Rotation iterates **all** rows of each target (keyset over PK) instead of filtering by the
  `key_version` column, because the authoritative key id is in each blob header and multi-field
  rows can mix versions. Cost is a full scan per rotation (acceptable for an operator job).
- Fields on a third key version (neither old nor new) in a row that also has an old-key field
  are re-sealed to `new_key_id` too, so the row ends consistent with `key_version = new_key_id`.
- The stats dict gained `failed_refs`; the return type changed from one flat dict to per-target
  stats (no external callers of the old signature exist).
- No CLI wiring here (planned as `navigator-vault rotate` in TASK-076).
