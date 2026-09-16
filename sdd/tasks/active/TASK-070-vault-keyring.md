# TASK-070: `KeyRing` — master key ring and v2 key schedule

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 1)
**Repository**: `../navigator-session` (base branch `main`; current checkout is `session-data` — confirm before branching)
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Foundation of the whole feature. Today key material is handled as loose `dict[int, bytes]`
passed around (`load_master_keys()`, `get_active_master_key()`) and each call site derives
keys ad hoc with v1 labels (`"vault-db-v{N}"`, `"vault-session"`). F1 (session key derived
from `session_uuid` only) and F3 (algorithm not recorded) both start here.

`KeyRing` owns the ring, the write algorithm, the naming key and every HKDF derivation with
**v2-only, domain-separated labels** (spec §2 "Key schedule"). Raw master keys never leave it.

---

## Scope

- Implement `KeyRing` in `navigator_session/vault/keyring.py`:
  - `from_env()` and a constructor taking an explicit ring (for tests and the migrator).
  - `active_key_id`, `write_alg_id` (from `VAULT_CIPHER_BACKEND`: `aesgcm`→`0x01`,
    `chacha20`→`0x02`), `naming_key_id`, `has_key(key_id)`.
  - Internal derivations (used by the envelope in TASK-071): `db_key(key_id, alg_id)`,
    `session_key(key_id, alg_id, session_uuid)` — HKDF-SHA256, 32-byte output, `info` labels
    exactly as in spec §2, `lp()` length prefixing.
  - `naming_hmac(value: str) -> str` — HMAC-SHA256 hex with the naming key
    (`HKDF(master_key[naming_key_id], "navigator-vault/v2/naming")`).
  - `naming_key_id` = `VAULT_NAMING_KEY_ID` if set, else the **lowest** key id in the ring;
    fail fast (`ValueError`) if that id is not in the ring.
  - `__repr__` / logging never include key bytes.
- Extend `navigator_session/vault/config.py`: parse `VAULT_NAMING_KEY_ID`; `VaultConfig`
  validates naming key presence; keep `generate_master_key()`.
- Unit tests in `tests/vault/test_keyring.py` (create `tests/vault/` in navigator-session).

**NOT in scope**: AEAD seal/open, AAD encoding, envelope format (TASK-071); removing v1
functions from `crypto.py` (TASK-071); any consumer changes.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_session/vault/keyring.py` | CREATE | `KeyRing` + derivations + `naming_hmac` |
| `navigator_session/vault/config.py` | MODIFY | `VAULT_NAMING_KEY_ID`, `VaultConfig` validation |
| `tests/vault/__init__.py` | CREATE | Test package |
| `tests/vault/conftest.py` | CREATE | `master_key_env`, `keyring` fixtures (shared by later NS tasks) |
| `tests/vault/test_keyring.py` | CREATE | Unit tests |

---

## Implementation Notes

### Pattern to Follow
- Reuse `load_master_keys()` validation (base64, exactly 32 bytes) from `config.py`.
- HKDF usage identical to `crypto.derive_key()` but with `info` built from bytes, not
  f-strings: `b"navigator-vault/v2/session" + bytes([alg_id]) + lp(session_uuid)`.
- Use `hmac.new(naming_key, value.encode(), hashlib.sha256).hexdigest()`.

### Key Constraints
- No raw master key accessor on the public surface; derivation methods may be
  underscore-prefixed or documented as kernel-internal.
- Cache derived DB keys per `(key_id, alg_id)` inside the instance (cheap, bounded).
- Do **not** cache session keys in `KeyRing` (unbounded); `SessionVault` caches its own.
- Logger `navigator.vault`; log key ids only.
- Google-style docstrings, strict typing.

### References in Codebase
- `navigator_session/vault/config.py` — `load_master_keys`, `get_active_key_id`, `VaultConfig`
- `navigator_session/vault/crypto.py` — `derive_key`, `_get_cipher_cls` (v1 behaviour to replace)

---

## Acceptance Criteria

- [ ] `KeyRing.from_env()` loads ring, active id, write alg, naming key id
- [ ] DB, session and naming keys are pairwise different for the same master key and differ from
      v1 `derive_key(master, "vault-db-v1")` / `derive_key(session_uuid, "vault-session")`
- [ ] Changing `VAULT_ACTIVE_KEY_ID` does not change `naming_hmac` output
- [ ] Missing naming key id → `ValueError` at construction
- [ ] Same `session_uuid` with a different master key yields a different session key
- [ ] No key bytes in `repr()` or captured logs
- [ ] `pytest tests/vault/test_keyring.py -v` passes (navigator-session)

---

## Test Specification

```python
# tests/vault/test_keyring.py
import base64, os, pytest
from navigator_session.vault.keyring import KeyRing


@pytest.fixture
def master_key_env(monkeypatch):
    k1, k2 = os.urandom(32), os.urandom(32)
    monkeypatch.setenv("VAULT_MASTER_KEY_v1", base64.b64encode(k1).decode())
    monkeypatch.setenv("VAULT_MASTER_KEY_v2", base64.b64encode(k2).decode())
    monkeypatch.setenv("VAULT_ACTIVE_KEY_ID", "1")
    monkeypatch.delenv("VAULT_NAMING_KEY_ID", raising=False)
    return {1: k1, 2: k2}


class TestKeyRing:
    def test_loads_ring(self, master_key_env):
        ring = KeyRing.from_env()
        assert ring.active_key_id == 1 and ring.naming_key_id == 1

    def test_naming_stable_across_rotation(self, master_key_env, monkeypatch):
        before = KeyRing.from_env().naming_hmac("sid")
        monkeypatch.setenv("VAULT_ACTIVE_KEY_ID", "2")
        assert KeyRing.from_env().naming_hmac("sid") == before

    def test_missing_naming_key(self, master_key_env, monkeypatch):
        monkeypatch.setenv("VAULT_NAMING_KEY_ID", "9")
        with pytest.raises(ValueError):
            KeyRing.from_env()

    def test_repr_has_no_key_material(self, master_key_env):
        ring = KeyRing.from_env()
        assert base64.b64encode(master_key_env[1]).decode() not in repr(ring)
```

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify `Depends-on` tasks are in `sdd/tasks/completed/`
3. **Update status** in `sdd/tasks/.index.json` (navigator-auth) → `"in-progress"`
4. **Implement** in a navigator-session worktree
   (`.claude/worktrees/feat-FEAT-099-vault-crypto-hardening`, branch
   `feat-FEAT-099-vault-crypto-hardening`)
5. **Verify** all acceptance criteria are met
6. **Move this file** to `sdd/tasks/completed/` and update the index → `"done"`
7. **Fill in the Completion Note** below

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
