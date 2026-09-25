# TASK-080: ai-parrot-server — credential, BYOK and MCP-restore call sites

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 9, second half)
**Repository**: `../ai-parrot` — package `packages/ai-parrot-server`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-079
**Assigned-to**: unassigned

---

## Context

After TASK-079 the helpers require a context. The server handlers still call the old
signatures and load raw master keys themselves (`load_master_keys`, `get_active_key_id`).
This task migrates every server-side call site.

---

## Scope

- `parrot/handlers/credentials.py` (`COLLECTION = "user_credentials"`):
  - reads at ~195–223 and writes at ~298, ~401: use `credential_context(user_id, name)`;
  - any update that changes `name` re-seals with the new context (`reseal_credential`);
  - replace direct `navigator_session.vault.config` imports with the shared `KeyRing`.
- `parrot/handlers/studio/byok.py` (`user_llm_keys`): reads ~129, write ~191 with
  `llm_key_context(user_id, provider)`.
- `parrot/handlers/agent.py` (~1144–1180, MCP restore from `user_credentials`): context from
  `(user_id, config.vault_credential_name)`; on `VaultIntegrityError` log and skip server
  (existing warning path), never crash.
- `parrot/handlers/credentials_utils.py` / `vault_utils.py` in `ai-parrot-server` (if present
  as shims): align with TASK-079.
- `pyproject.toml` (`packages/ai-parrot-server`): `navigator-session>=1.0.0`.
- Tests: update `packages/ai-parrot/tests/handlers/test_credentials_handler.py`,
  `test_credentials_integration.py` (live under `packages/ai-parrot/tests/handlers/`) and add a
  BYOK handler test + MCP restore integrity test in `packages/ai-parrot-server/tests/unit/`.

**NOT in scope**: `users_bots` sealed fields (TASK-081); integrations / `VaultTokenSync`
(TASK-082).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `packages/ai-parrot-server/src/parrot/handlers/credentials.py` | MODIFY | Contexts + re-seal on rename |
| `packages/ai-parrot-server/src/parrot/handlers/studio/byok.py` | MODIFY | BYOK context |
| `packages/ai-parrot-server/src/parrot/handlers/agent.py` | MODIFY | MCP restore context |
| `packages/ai-parrot-server/pyproject.toml` | MODIFY | Dependency |
| `packages/ai-parrot/tests/handlers/test_credentials_handler.py` | MODIFY | Signatures |
| `packages/ai-parrot/tests/handlers/test_credentials_integration.py` | MODIFY | Signatures |
| `packages/ai-parrot-server/tests/unit/test_byok_context.py` | CREATE | BYOK swap test |
| `packages/ai-parrot-server/tests/unit/test_mcp_restore_integrity.py` | CREATE | Skip on integrity error |

---

## Implementation Notes

### Delivered by TASK-079 (use as-is)
- `parrot.security.credentials_utils`: `encrypt_credential(credential, context, keyring, *, key_id=None)`,
  `decrypt_credential(encrypted, context, keyring)`, `reseal_credential(encrypted, old_ctx, new_ctx,
  keyring)`, `credential_context(user_id, name)`, `llm_key_context(user_id, provider)`,
  `normalize_user_id`. Same base64 text representation.
- `parrot.security.vault_utils.get_vault_keyring()` (cached `KeyRing`) / `reset_vault_keyring()`.
  `load_vault_keys()` is **deprecated** and only kept for `_encrypted_field` (TASK-081); replace
  `_load_vault_keys()` in `credentials.py` / `studio/byok.py` with `get_vault_keyring()`.
- Failing tests handed over (they still use the v1 signature): `tests/handlers/
  test_credentials_handler.py` (5) and `tests/handlers/test_credentials_integration.py` (6) in
  `packages/ai-parrot/tests`.
- Worktree test setup: `PYTHONPATH=<wt>/packages/ai-parrot/src:<wt>/packages/ai-parrot-server/src:
  <navigator-session worktree>` and copy the `*.cpython-312-*.so` build artifacts into the worktree
  (`parrot.utils.types`), as done in TASK-079.

### Key Constraints
- Keep HTTP response shapes of the credentials and BYOK handlers unchanged.
- A single `KeyRing` per process (reuse the cached one from `parrot.security.vault_utils`).
- Verify the `user_id` normalisation from TASK-079 is used identically on read and write.

### References in Codebase
- `packages/ai-parrot-server/src/parrot/handlers/credentials.py`
- `packages/ai-parrot-server/src/parrot/handlers/studio/byok.py`
- `packages/ai-parrot-server/src/parrot/handlers/agent.py`

---

## Acceptance Criteria

- [ ] `grep -rn "encrypt_for_db\|decrypt_for_db\|load_master_keys" packages/ai-parrot-server/src` returns nothing
- [ ] Renaming a credential re-seals and remains readable under the new name only
- [ ] MCP restore skips (warning) on integrity error
- [ ] Touched test suites pass with `pytest -v`

---

## Test Specification

```python
# packages/ai-parrot-server/tests/unit/test_mcp_restore_integrity.py
import pytest


@pytest.mark.asyncio
async def test_mcp_restore_skips_tampered_credential(agent_handler, fake_docdb_swapped, caplog):
    restored = await agent_handler._restore_mcp_servers(user_id=1)
    assert restored == []
    assert "failed to decrypt Vault credential" in caplog.text
```

---

## Agent Instructions

1. **Read the spec** (Module 9)
2. **Check dependencies** — TASK-079 completed
3. **Update status** → `"in-progress"`
4. **Implement** in the ai-parrot feature worktree
5. **Verify** acceptance criteria
6. **Move file** to `sdd/tasks/completed/`, index → `"done"`
7. **Completion Note**

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: claude-session (Claude Opus 5)
**Date**: 2026-09-16
**Notes**:
- ai-parrot worktree `.claude/worktrees/feat-FEAT-099-vault-crypto-hardening`, commit `a31b9c1`.
- `handlers/credentials.py`: `_load_vault_keys()` replaced by `_vault_keyring()` (thin seam over
  `parrot.security.vault_utils.get_vault_keyring()`, kept so tests can patch one symbol); GET
  single (`credential_context(user_id, name)`), GET list (per-document `cname`), POST
  (`payload.name`) and PUT (URL `name`) all seal/open with contexts.
- `handlers/studio/byok.py`: same `_vault_keyring()` seam; list masks keys with
  `llm_key_context(user.user_id, doc["provider"])`, POST seals with
  `llm_key_context(user.user_id, provider)`; `503 vault_unavailable` behaviour unchanged.
- `handlers/agent.py` MCP restore: loads the key ring once, decrypts with
  `credential_context(user_id, config.vault_credential_name)`; integrity failures keep logging
  a warning and skipping that MCP server.
- Tests: `tests/handlers/test_credentials_handler.py` and `test_credentials_integration.py`
  patch `_vault_keyring` and build fixtures with contexts (new `keyring` fixture / `_keyring()`
  helper, `_make_encrypted(cred, user_id, name)`); new
  `packages/ai-parrot-server/tests/unit/test_byok_context.py` and
  `test_mcp_restore_integrity.py` (context binding + the handlers' use of contexts and
  skip-on-failure behaviour).
- Results: targeted suites — dev baseline 109 passed; worktree 131 passed, 5 failed, all in
  `tests/handlers/test_user_bots_security.py` (owned by TASK-081). `grep` for
  `encrypt_for_db|decrypt_for_db|load_master_keys` in `ai-parrot-server/src` only matches a
  docstring line in `models/_encrypted_field.py` (TASK-081's file). `ruff`: the same 3
  pre-existing warnings as on `dev` (E401 in two test helpers, one in `agent.py`).

**Deviations from spec**:
- "Renaming a credential re-seals": there is no rename path in this handler — `PUT` takes the
  name from the URL and ignores `payload.name`, so the context never changes. `reseal_credential`
  from TASK-079 stays available if a rename endpoint is added.
- Kept a `_vault_keyring()` indirection in both handlers instead of calling `get_vault_keyring()`
  inline, to preserve a single patch point for the existing tests.
