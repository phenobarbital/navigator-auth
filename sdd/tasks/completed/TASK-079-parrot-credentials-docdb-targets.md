# TASK-079: ai-parrot — context-bound credential helpers and DocumentDB targets

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 9, first half)
**Repository**: `../ai-parrot` — package `packages/ai-parrot` (branch from ai-parrot `dev`)
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-072
**Assigned-to**: unassigned

---

## Context

ai-parrot stores user credentials and BYOK LLM keys in **DocumentDB** using
`encrypt_for_db`/`decrypt_for_db` without context:

- `user_credentials` — identity `(user_id, name)`, field `credential` (base64 text)
- `user_llm_keys` — identity `(user_id, provider)`, field `api_key` (base64 text)

This task changes the shared helpers in `parrot.security` and contributes both collections as
`ProtectedTarget`s (navigator-session has no DocumentDB dependency; discovery is via entry
points). Call sites in `ai-parrot-server` are TASK-080.

---

## Scope

- `parrot/security/credentials_utils.py`:
  `encrypt_credential(credential: dict, context: VaultContext, keyring: KeyRing) -> str` and
  `decrypt_credential(encrypted: str, context: VaultContext, keyring: KeyRing) -> dict`
  (base64 text representation unchanged); context builders
  `credential_context(user_id, name)` → `("parrot-credential","db",(user_id,name,"credential"))`
  and `llm_key_context(user_id, provider)` → `("parrot-llm-key","db",(user_id,provider,"api_key"))`.
- `parrot/security/vault_utils.py`: replace `load_vault_keys()` tuple with a cached `KeyRing`;
  `store_vault_credential` / `retrieve_vault_credential` / `delete_vault_credential` build the
  context from `(user_id, vault_name)`.
- `parrot/handlers/credentials_utils.py`, `parrot/handlers/vault_utils.py` (compat redirects):
  keep re-exports in sync with the new names/signatures.
- `parrot/auth/broker.py` (`user_llm_keys` read at ~line 380–394): use `KeyRing` +
  `llm_key_context`.
- `parrot/vault_targets.py`: `UserCredentialsTarget`, `UserLlmKeysTarget` implementing
  `ProtectedTarget` over `DocumentDb`:
  - deterministic iteration by `_id`, batch reads;
  - `write` updates the encrypted field (+ `key_version`, `updated_at`);
  - `export_raw` / `restore_raw` (documents as stored, identity + blob);
  - `quarantine`: insert into `<collection>_quarantine` with `quarantined_at`, `reason`,
    `run_id`, original `_id`, then delete from source (spec §2 Quarantine semantics);
    `restore_raw` removes quarantine copies it restores.
  - Factories return `None` when DocumentDB is not configured.
- `pyproject.toml` (`packages/ai-parrot`): `navigator-session>=1.0.0`; entry points
  `parrot_user_credentials`, `parrot_user_llm_keys`.
- Tests: update `tests/handlers/test_credential_encryption.py`,
  `tests/unit/test_user_llm_key_resolver.py`, `tests/auth/test_o365_devicecode_resolver.py`
  (if affected); add `tests/security/test_vault_targets.py` with an in-memory DocumentDB double.

**NOT in scope**: `ai-parrot-server` call sites (`handlers/credentials.py`, `studio/byok.py`,
`handlers/agent.py`) → TASK-080; `users_bots` → TASK-081; integrations → TASK-082.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `packages/ai-parrot/src/parrot/security/credentials_utils.py` | MODIFY | Context-bound helpers + context builders |
| `packages/ai-parrot/src/parrot/security/vault_utils.py` | MODIFY | KeyRing + contexts |
| `packages/ai-parrot/src/parrot/handlers/credentials_utils.py` | MODIFY | Compat re-exports |
| `packages/ai-parrot/src/parrot/handlers/vault_utils.py` | MODIFY | Compat re-exports |
| `packages/ai-parrot/src/parrot/auth/broker.py` | MODIFY | BYOK read with context |
| `packages/ai-parrot/src/parrot/vault_targets.py` | CREATE | DocumentDB targets + factories |
| `packages/ai-parrot/pyproject.toml` | MODIFY | Dependency + entry points |
| `packages/ai-parrot/tests/security/test_vault_targets.py` | CREATE | Target tests |
| `packages/ai-parrot/tests/handlers/test_credential_encryption.py` | MODIFY | New signatures, swap tests |
| `packages/ai-parrot/tests/unit/test_user_llm_key_resolver.py` | MODIFY | Context |

---

## Implementation Notes

### Key Constraints
- `user_id` type differs across call sites (`str` vs `int`): normalise in the context builder
  (int when numeric string) and document it — the same value must be used on write and read.
- Renaming `name` / `provider` must re-seal (enforced in TASK-080 handlers; helpers expose a
  `reseal_credential(encrypted, old_ctx, new_ctx, keyring)` utility).
- Activate the venv before running anything: `source .venv/bin/activate`; use `uv`.
- Never log credential dicts or API keys.

### References in Codebase
- `packages/ai-parrot/src/parrot/security/credentials_utils.py`, `vault_utils.py`
- `packages/ai-parrot/src/parrot/interfaces/documentdb.py` — `DocumentDb` API
- `../navigator-session/navigator_session/vault/registry.py` — protocols (TASK-072)

---

## Acceptance Criteria

- [ ] No `encrypt_for_db` / `decrypt_for_db` imports remain in `packages/ai-parrot/src`
- [ ] Credential moved to another `(user_id, name)` → decrypt raises `VaultIntegrityError`
- [ ] BYOK key moved to another provider → `VaultIntegrityError`
- [ ] Quarantine moves document to `<collection>_quarantine` with metadata; restore reverses it
- [ ] Targets discovered through entry points; factory returns `None` without DocumentDB
- [ ] `pytest packages/ai-parrot/tests/security packages/ai-parrot/tests/handlers/test_credential_encryption.py packages/ai-parrot/tests/unit/test_user_llm_key_resolver.py -v` passes

---

## Test Specification

```python
# packages/ai-parrot/tests/security/test_vault_targets.py
import pytest
from navigator_session.vault import VaultIntegrityError
from parrot.security.credentials_utils import (
    encrypt_credential, decrypt_credential, credential_context,
)


def test_credential_bound_to_name(keyring):
    blob = encrypt_credential({"driver": "pg"}, credential_context(1, "prod"), keyring)
    with pytest.raises(VaultIntegrityError):
        decrypt_credential(blob, credential_context(1, "staging"), keyring)


@pytest.mark.asyncio
async def test_quarantine_moves_document(fake_docdb, keyring):
    from parrot.vault_targets import UserCredentialsTarget
    target = UserCredentialsTarget(fake_docdb)
    row = await fake_docdb.seed_one("user_credentials", user_id=1, name="x", credential="bad")
    await target.quarantine(row, "undecryptable", run_id="r1")
    assert fake_docdb.count("user_credentials") == 0
    q = fake_docdb.find_one("user_credentials_quarantine")
    assert q["run_id"] == "r1" and q["reason"] == "undecryptable"
```

---

## Agent Instructions

1. **Read the spec** (Module 9, Quarantine semantics)
2. **Check dependencies** — TASK-072 completed
3. **Update status** in navigator-auth `sdd/tasks/.index.json` → `"in-progress"`
4. **Implement** in an ai-parrot worktree
   (`.claude/worktrees/feat-FEAT-099-vault-crypto-hardening`, branch
   `feat-FEAT-099-vault-crypto-hardening` from ai-parrot `dev`)
5. **Verify** acceptance criteria
6. **Move file** to `sdd/tasks/completed/` (navigator-auth), index → `"done"`
7. **Completion Note**

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: claude-session (Claude Opus 5)
**Date**: 2026-09-16
**Notes**:
- ai-parrot worktree `.claude/worktrees/feat-FEAT-099-vault-crypto-hardening` (branch from `dev`),
  commit `4e56747`.
- `security/credentials_utils.py`: rewritten on the v2 envelope —
  `encrypt_credential(credential, context, keyring, *, key_id=None) -> str` (base64),
  `decrypt_credential(encrypted, context, keyring) -> dict`, `reseal_credential`,
  `credential_context(user_id, name)` (`parrot-credential`, field `credential`),
  `llm_key_context(user_id, provider)` (`parrot-llm-key`, field `api_key`), `normalize_user_id`
  (digit strings → int, shared by runtime and targets).
- `security/vault_utils.py`: cached `get_vault_keyring()` + `reset_vault_keyring()`; store/retrieve
  use contexts; `load_vault_keys()` kept **deprecated** (raw keys) only for
  `handlers/models/_encrypted_field.py` until TASK-081.
- `auth/broker.py` BYOK resolver: `get_vault_keyring()` + `llm_key_context`; still fails closed.
- `handlers/credentials_utils.py` / `handlers/vault_utils.py` compat shims re-export the new names.
- `vault_targets.py`: `DocumentDbTarget` base + `UserCredentialsTarget` (`user_credentials`,
  `(user_id, name)`) and `UserLlmKeysTarget` (`user_llm_keys`, `(user_id, provider)`) implementing
  `ProtectedTarget`; rows expose decoded blob bytes (writes re-encode base64), quarantine moves the
  document to `<collection>_quarantine` with `quarantined_at`/`reason`/`run_id`, `restore_raw`
  replaces documents and drops quarantine copies. Entry points `parrot_user_credentials` /
  `parrot_user_llm_keys` registered in `packages/ai-parrot/pyproject.toml`.
- Tests: rewrote `tests/handlers/test_credential_encryption.py` (round-trips, v2 envelope, context
  binding across user/name/provider/purpose, wrong key, unknown key version, v1 rejection, reseal),
  adapted `tests/unit/test_user_llm_key_resolver.py` to the keyring/context, added
  `tests/security/test_vault_targets.py` (protocol conformance, entry points, deterministic
  batches, context binding, write/validation/missing doc, quarantine move, export→migrate→
  quarantine→restore byte-identical, backup free of plaintext).
- Results: targeted suites — dev baseline 109 passed; worktree 109-equivalent with 16 failures, all
  in files owned by later tasks (`test_credentials_handler.py` 5 and
  `test_credentials_integration.py` 6 → TASK-080; `test_user_bots_security.py` 5 → TASK-081), which
  still call the v1 signature. Files owned by this task all pass. `ruff check` clean.

**Deviations from spec**:
- `load_vault_keys()` was kept (deprecated) instead of being replaced outright, so the repo stays
  importable until TASK-080/081 migrate their call sites.
- DocumentDB targets read each collection once and batch in memory (documents are few per user and
  the driver strips `_id`, so rows are addressed by their natural key) instead of cursor paging.
- Backup records carry the full document so quarantined (deleted) documents can be restored;
  `restore_raw` replaces documents rather than `$set`-merging, so migration-added fields
  (`updated_at`) do not survive a rollback.
- `navigator-session>=1.0.0` pin deferred to TASK-085 (as in TASK-077).
