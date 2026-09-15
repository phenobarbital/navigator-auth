# TASK-073: `SessionVault` v2 — keyed session layer, HMAC names, metadata, `:` keys

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 4)
**Repository**: `../navigator-session`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-071, TASK-072
**Assigned-to**: unassigned

---

## Context

The runtime face of F1, F2 and F4. `SessionVault` currently derives the session key from
`session_uuid`, stores `vault:{session_uuid}:{key}` in Redis, writes the raw session id to
`auth.user_vault_audit`, and forbids `:` in keys — which silently breaks ai-parrot's
`VaultTokenSync` (`jira:access_token`).

---

## Scope

- Rewrite `navigator_session/vault/session_vault.py` on top of `KeyRing` + envelope:
  - DB layer: `seal_value(value, VaultContext("user-vault","db",(user_id,key)), keyring)`.
  - Session layer: context `("user-vault","session",(sid_hmac, user_id, key))` +
    `session_uuid=`; derived session key cached per instance.
  - Redis key: `vault:v2:{keyring.naming_hmac(session_uuid)}:{keyring.naming_hmac(key)}`.
  - Audit: store `keyring.naming_hmac(session_uuid)` in `session_id`.
  - Key validation: non-empty, ≤ 255 chars, no control characters (`\x00-\x1f`, `\x7f`);
    **allow `:`**.
  - `load_for_session`: select `key, ciphertext_db, key_version, updated_at`; on
    `VaultIntegrityError` / `UnknownKeyVersionError` / `UnsupportedFormatError` skip the entry,
    log (key name + user id + error class only) and audit `operation='integrity_fail'`.
  - New `list_metadata() -> list[VaultSecretMetadata]` (key, updated_at, key_version) kept in
    an in-memory metadata map updated by `set`/`delete`/load.
  - `set()` returns `VaultSecretMetadata` (used by TASK-078 POST response).
  - Constructor accepts an optional `keyring: KeyRing` (default `KeyRing.from_env()`); remove
    `_master_keys` attribute.
- Add `VaultSecretMetadata` model (spec §2 Data Models) in `navigator_session/vault/models.py`.
- Delete any temporary `_legacy_v1_shim` usage introduced in TASK-071 for this module.
- Tests `tests/vault/test_session_vault.py` (port relevant cases from
  `../navigator-auth/tests/unit/vault/test_session_vault.py`, rewritten for v2).

**NOT in scope**: HTTP handler changes (TASK-078); removing navigator-auth's old tests
(TASK-077); rotation (TASK-074); migrator (TASK-075).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_session/vault/session_vault.py` | MODIFY | v2 implementation |
| `navigator_session/vault/models.py` | CREATE | `VaultSecretMetadata` |
| `navigator_session/vault/__init__.py` | MODIFY | Export model |
| `tests/vault/test_session_vault.py` | CREATE | v2 behaviour tests |

---

## Implementation Notes

### Key Constraints
- Public method names/signatures stay (`set`, `get`, `delete`, `keys`, `exists`,
  `load_for_session`) except `set` now returning metadata — callers ignoring the return value
  keep working.
- `get()` keeps lookup order memory → Redis → default (no DB fallback; spec non-goal).
- Deterministic callers (`telegram-persistent:{user_id}`) must work unchanged.
- Schema constraints (found in TASK-072, fixed by navigator-auth migration 002 in TASK-078):
  `auth.user_vault_audit.operation` CHECK currently rejects `'integrity_fail'`, and
  `session_id VARCHAR(36)` is too short for the 64-char HMAC. Implement against the target
  schema; tests use `tests/vault/fake_pg.py` (no constraints), and document the dependency.
- Reuse `tests/vault/fake_pg.py` (`FakeDatabase`, `FakePool`, `AwaitablePool`) and
  `targets/postgres.py` helpers `acquire_connection` / `fetch_rows` instead of re-implementing
  the pool compatibility code.
- Never log values, blobs, raw session ids.

### References in Codebase
- `navigator_session/vault/session_vault.py` — current implementation and SQL
- `../navigator-auth/tests/unit/vault/test_session_vault.py` — existing behavioural cases
- `../ai-parrot/packages/ai-parrot-server/src/parrot/services/vault_token_sync.py` — `:` keys

---

## Acceptance Criteria

- [ ] Redis key names contain neither the raw session id nor the secret name
- [ ] Audit insert receives the HMAC session id
- [ ] `set("jira:access_token", ...)` / `get` round-trips; control chars rejected
- [ ] Blob copied from another user's row is skipped on load + `integrity_fail` audit, load succeeds
- [ ] Redis contents + session id without master keys cannot be decrypted (test derives v1-style key and fails)
- [ ] `list_metadata()` returns no values
- [ ] `pytest tests/vault -v` passes

---

## Test Specification

```python
# tests/vault/test_session_vault.py
import pytest
from navigator_session.vault import SessionVault


@pytest.mark.asyncio
async def test_redis_names_are_hmac(keyring, fake_pool, fake_redis):
    vault = SessionVault("sid-123", 7, fake_pool, fake_redis, keyring=keyring)
    await vault.set("jira:access_token", "tok")
    names = fake_redis.written_keys()
    assert all("sid-123" not in n and "jira" not in n for n in names)
    assert await vault.get("jira:access_token") == "tok"


@pytest.mark.asyncio
async def test_cross_user_row_skipped(keyring, fake_pool_with_swapped_row, fake_redis):
    vault = await SessionVault.load_for_session("sid", 2, fake_pool_with_swapped_row,
                                                fake_redis, keyring=keyring)
    assert "stolen" not in await vault.keys()
    assert fake_pool_with_swapped_row.audit_ops() == ["integrity_fail"]
```

---

## Agent Instructions

1. **Read the spec** (Module 4)
2. **Check dependencies** — TASK-071, TASK-072 completed
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
