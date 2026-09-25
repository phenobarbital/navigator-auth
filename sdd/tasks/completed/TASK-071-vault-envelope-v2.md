# TASK-071: Envelope v2, `VaultContext`, canonical AAD and typed errors

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 2)
**Repository**: `../navigator-session`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-070
**Assigned-to**: unassigned

---

## Context

Fixes F2 (no AAD) and F3 (algorithm not recorded) at the cipher level. After this task the
only way to encrypt anything with the vault keys is `seal()` with a `VaultContext`, and the
only way to decrypt is `open_sealed()` with the **expected** context. v1 functions leave the
public API (the migrator gets its own isolated copy in TASK-075).

Spec §2: "Envelope v2 format", "Canonical AAD encoding", "New Public Interfaces".

---

## Scope

- `navigator_session/vault/context.py`: `VaultContext` (Pydantic, frozen) with `purpose`,
  `layer: Literal["db","session"]`, ordered `fields`; `ContextValue = str | int | UUID | None`;
  validators (non-empty purpose, unique field names).
- `navigator_session/vault/envelope.py`:
  - `EnvelopeHeader` pack/parse (16 bytes: `0xA2`, `alg_id`, `key_id` u16 BE, 12-byte nonce).
  - Canonical AAD encoder exactly as spec §2 (magic `"NAVVAULT-AAD"`, header, `lp(purpose)`,
    `lp(layer)`, `u16(count)`, per field `lp(name) ‖ type_tag ‖ lp(value)`; tags `0x00` NULL,
    `0x01` str, `0x02` int decimal ASCII, `0x03` UUID lowercase canonical).
  - `seal()`, `open_sealed()`, `seal_value()`, `open_value()`; `session_uuid` keyword required
    when `context.layer == "session"` and rejected otherwise.
  - Errors: `VaultCryptoError`, `VaultIntegrityError` (wraps `InvalidTag`),
    `UnknownKeyVersionError` (also `KeyError`), `UnsupportedFormatError` (bad version byte,
    unknown `alg_id`, blob < 32 bytes).
- `navigator_session/vault/crypto.py`: keep `serialize_value` / `deserialize_value`; **remove**
  `derive_key`, `encrypt_for_session`, `decrypt_for_session`, `encrypt_for_db`,
  `decrypt_for_db`, `CIPHER_CLS` from the module.
- `navigator_session/vault/__init__.py`: export `KeyRing`, `VaultContext`, `seal`, `open_sealed`,
  `seal_value`, `open_value`, error classes; update the threat-model docstring (F1/F2 fixed).
- Temporarily keep `session_vault.py` / `key_rotation.py` importable: they are rewritten in
  TASK-073/074 — if they import removed names, switch their imports to a private
  `navigator_session.vault._legacy_v1_shim` **only** if needed to keep the package importable,
  and mark it for deletion in TASK-073/074.
- Unit tests `tests/vault/test_envelope.py`, `tests/vault/test_context.py`.

**NOT in scope**: `SessionVault` rewrite (TASK-073), rotation (TASK-074), migrator and the real
legacy v1 decryptor (TASK-075), any downstream repo.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_session/vault/context.py` | CREATE | `VaultContext` |
| `navigator_session/vault/envelope.py` | CREATE | Header, AAD, seal/open, errors |
| `navigator_session/vault/crypto.py` | MODIFY | Serializer only |
| `navigator_session/vault/__init__.py` | MODIFY | New exports, threat model |
| `tests/vault/test_envelope.py` | CREATE | Envelope tests |
| `tests/vault/test_context.py` | CREATE | Context/AAD encoding tests |
| `tests/vault/fixtures/v1_blobs.json` | CREATE | Frozen v1 ciphertexts (generated once with the pre-change code) for rejection tests and reuse in TASK-075 |

---

## Implementation Notes

### Key Constraints
- AAD **includes the header**; build header first, then AAD, then encrypt.
- `open_sealed()` order: length check → version byte → `alg_id` known → `key_id` in ring
  (`UnknownKeyVersionError`) → derive key → decrypt with AAD → `VaultIntegrityError` on
  `InvalidTag`. Never return partial data.
- Algorithm for opening comes from `alg_id` in the header, **not** from env.
- `NULL` vs `""` must encode differently (tag `0x00` with empty value vs tag `0x01` + `lp("")`).
- Integers: reject `bool` (subclass of `int`) explicitly.
- Generate `v1_blobs.json` **before** removing v1 functions (record: purpose, user_id, key,
  key_id, base64 blob, plaintext only for test assertions — test-only data).
- Never log plaintext, blobs or keys.

### References in Codebase
- `navigator_session/vault/crypto.py` — current AEAD usage and serializer
- `navigator_session/vault/keyring.py` — derivations from TASK-070
- `ai-parrot-server/src/parrot/handlers/models/_encrypted_field.py` — prior art for context tuples

---

## Acceptance Criteria

- [ ] Round-trip for AES-GCM and ChaCha20-Poly1305; header records `alg_id`
- [ ] Blob sealed with AES opens after `VAULT_CIPHER_BACKEND=chacha20`
- [ ] Any change in purpose / layer / field name / field value / field order → `VaultIntegrityError`
- [ ] Flipping `key_id` or `alg_id` byte never yields plaintext
- [ ] v1 fixture blobs → `UnsupportedFormatError` (or `VaultIntegrityError` if the first byte collides — assert no plaintext)
- [ ] `None` vs `""` and `("a:b","c")` vs `("a","b:c")` produce different AAD
- [ ] `from navigator_session.vault.crypto import encrypt_for_db` raises `ImportError`
- [ ] `pytest tests/vault -v` passes (navigator-session)

---

## Test Specification

```python
# tests/vault/test_envelope.py
import pytest
from navigator_session.vault import (
    VaultContext, seal, open_sealed, VaultIntegrityError, UnsupportedFormatError,
)


def ctx(user_id=1, key="api", layer="db"):
    return VaultContext(purpose="user-vault", layer=layer,
                        fields=(("user_id", user_id), ("key", key)))


class TestEnvelope:
    def test_roundtrip(self, keyring):
        blob = seal(b"secret", ctx(), keyring)
        assert blob[0] == 0xA2
        assert open_sealed(blob, ctx(), keyring) == b"secret"

    @pytest.mark.parametrize("other", [ctx(user_id=2), ctx(key="other")])
    def test_wrong_context(self, keyring, other):
        blob = seal(b"secret", ctx(), keyring)
        with pytest.raises(VaultIntegrityError):
            open_sealed(blob, other, keyring)

    def test_session_layer_requires_uuid(self, keyring):
        with pytest.raises(ValueError):
            seal(b"x", ctx(layer="session"), keyring)

    def test_short_blob(self, keyring):
        with pytest.raises(UnsupportedFormatError):
            open_sealed(b"\xa2" * 10, ctx(), keyring)
```

---

## Agent Instructions

1. **Read the spec** (Module 2, §2 format sections)
2. **Check dependencies** — TASK-070 in `sdd/tasks/completed/`
3. **Update status** in `sdd/tasks/.index.json` → `"in-progress"`
4. **Implement** in the navigator-session feature worktree
5. **Verify** acceptance criteria
6. **Move this file** to `sdd/tasks/completed/`, index → `"done"`
7. **Fill in the Completion Note**

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: claude-session (Claude Opus 5)
**Date**: 2026-09-15
**Notes**:
- navigator-session worktree branch `feat-FEAT-099-vault-crypto-hardening`, commit `a05daae`.
- `context.py`: frozen `VaultContext` (purpose pattern `[a-z0-9][a-z0-9._-]{0,63}`, layer
  `db|session`, ordered unique fields, values `str|int|UUID|None`, bool/float/bytes rejected),
  `canonical_bytes()`, `get()`.
- `envelope.py`: `EnvelopeHeader` (`to_bytes`/`from_bytes`), `read_header()`, `build_aad()`,
  `seal()` (with `key_id=` override already available for TASK-074), `open_sealed()`,
  `seal_value()`, `open_value()`; errors `VaultCryptoError`, `VaultIntegrityError`,
  `UnknownKeyVersionError` (also `KeyError`, clean `str()`), `UnsupportedFormatError`.
- `crypto.py` reduced to `serialize_value`/`deserialize_value`. v1 primitives moved verbatim
  to private `navigator_session/vault/_legacy_v1_shim.py`, imported only by
  `session_vault.py` (TODO TASK-073) and `key_rotation.py` (TODO TASK-074) — delete it there.
- `__init__.py`: exports the kernel API; threat model updated (with a transitional note until
  TASK-073/074).
- `tests/vault/fixtures/v1_blobs.json`: 7 frozen v1 blobs (db: aesgcm/chacha20, key ids 1/2,
  str/dict/int/bytes/None; session: aesgcm/chacha20) generated with the pre-change code,
  verified against v1 decrypt, test-only random master keys + session uuid included for
  TASK-075. Session blobs were regenerated if their first byte was 0xA2.
- Tests: `test_context.py` + `test_envelope.py` (84 new, incl. independent known-answer
  vectors for db/AES-GCM and session/ChaCha20 built from spec §2, tamper matrix, v1 rejection).
  navigator-session `tests/` 181 passed; `ruff check` clean.
- Expected downstream breakage when navigator-auth runs against this worktree
  (`PYTHONPATH=<worktree>`): the 3 v1 test modules in `tests/unit/vault/` fail to collect
  (removed by TASK-077), and 23 identity tests fail because `IdentityCipher` imports
  `encrypt_for_db` (rewritten by TASK-077). navigator-auth's own venv is unaffected (it has a
  non-editable copy of navigator-session 0.10.2).

**Deviations from spec**:
- `seal()` gained an optional `key_id=` keyword now (TASK-074 would otherwise add it).
- Added `read_header()` and `VaultContext.get()` helpers (for rotation/migration and targets).
- Crypto errors deliberately do **not** subclass `ValueError`, so handlers that map
  `ValueError` → 400 cannot swallow integrity failures.
- Context values are strictly typed: `1`, `"1"` and `UUID(...)` vs its string all encode
  differently — targets must use consistent Python types on seal and open.
