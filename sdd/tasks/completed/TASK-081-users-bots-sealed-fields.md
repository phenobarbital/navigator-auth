# TASK-081: `users_bots` sealed fields — AAD instead of `_ctx` envelope, target with legacy unwrap

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 11)
**Repository**: `../ai-parrot` — package `packages/ai-parrot-server`
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-075, TASK-079
**Assigned-to**: unassigned

---

## Context

`UserBotModel` (`{PARROT_SCHEMA}.users_bots`, PostgreSQL) seals `mcp_config` and `tools_config`
through `_encrypted_field.seal/unseal`, which embeds `{"_v":1,"_ctx":{"u","c","f"},"v":...}`
inside the plaintext because AAD was unavailable. With envelope v2 the context moves into AAD.
The migrator must verify the v1 `_ctx` before re-sealing, or an already-swapped v1 blob would
be legitimised.

---

## Scope

- `parrot/handlers/models/_encrypted_field.py`: `seal(value, *, user_id, chatbot_id, field)` /
  `unseal(...)` keep their signatures but use `seal_value`/`open_value` with context
  `("parrot-user-bot","db",(user_id, chatbot_id, field))`; no in-plaintext envelope for new
  data; remove `_ENVELOPE_VERSION` write path; keep a private `_unwrap_v1_envelope(payload,
  user_id, chatbot_id, field)` used only by the migration target.
- `parrot/handlers/models/users_bots.py`: unchanged accessors; confirm `chatbot_id` UUID is passed
  as `UUID` (AAD tag `0x03`).
- `parrot/vault_targets.py` (ai-parrot-server): `UsersBotsTarget(PostgresTarget)` for
  `{PARROT_SCHEMA}.users_bots` with fields `mcp_config`, `tools_config`; `legacy_unwrap` hook
  verifies `_ctx` (`u`, `c`, `f`) matches the row and returns the inner `v` serialized; mismatch
  raises so the runner records a failure. Quarantine: the table has no `deleted_at`, but
  `UserBotModel` has `enabled: bool` (`users_bots.py:46`) — set `enabled = false`, leave the
  sealed columns untouched (restore puts them back), and log the `run_id` (same pattern as the
  identity target in TASK-077).
- `pyproject.toml` (ai-parrot-server): entry point `parrot_users_bots`.
- Tests: update `packages/ai-parrot/tests/handlers/test_user_bots_security.py`; add
  `packages/ai-parrot-server/tests/unit/test_users_bots_target.py`.

**NOT in scope**: other parrot stores (TASK-079/080); runner changes (TASK-075).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `packages/ai-parrot-server/src/parrot/handlers/models/_encrypted_field.py` | MODIFY | AAD-based seal/unseal |
| `packages/ai-parrot-server/src/parrot/handlers/models/users_bots.py` | MODIFY | Only if UUID typing needs adjustment |
| `packages/ai-parrot-server/src/parrot/vault_targets.py` | CREATE | `UsersBotsTarget` + factory |
| `packages/ai-parrot-server/pyproject.toml` | MODIFY | Entry point |
| `packages/ai-parrot/tests/handlers/test_user_bots_security.py` | MODIFY | v2 behaviour |
| `packages/ai-parrot-server/tests/unit/test_users_bots_target.py` | CREATE | Legacy unwrap tests |

---

## Implementation Notes

### Delivered by TASK-079
- Context helpers and `get_vault_keyring()` in `parrot.security` (see TASK-080 notes).
  `parrot.security.vault_utils.load_vault_keys()` exists only for `_encrypted_field`; **delete it**
  once this task migrates that module.
- `parrot/vault_targets.py` (ai-parrot package) already holds the DocumentDB targets; add the
  PostgreSQL `users_bots` target in `ai-parrot-server` as planned.
- Failing tests handed over: `packages/ai-parrot/tests/handlers/test_user_bots_security.py` (5,
  still using the v1 `_ctx` envelope API).

### Key Constraints
- The table is created by the model (`Meta.name = "users_bots"`, `schema = PARROT_SCHEMA`);
  read the schema from `parrot.conf.PARROT_SCHEMA` at factory time.
- Stored representation stays text/base64 as today — only the sealed payload changes.
- `mcp_config` ↔ `tools_config` swap must fail (field in AAD).

### References in Codebase
- `packages/ai-parrot-server/src/parrot/handlers/models/_encrypted_field.py` — current envelope
- `packages/ai-parrot-server/src/parrot/handlers/models/users_bots.py` — accessors, `Meta`
- `../navigator-session/navigator_session/vault/targets/postgres.py` — base (TASK-072)

---

## Acceptance Criteria

- [ ] New seals contain no `_ctx` envelope; context enforced via AAD
- [ ] `mcp_config` ↔ `tools_config` and cross-bot swaps → `VaultIntegrityError`
- [ ] Migration of a valid v1 envelope succeeds; mismatching `_ctx` → recorded failure
- [ ] Quarantine sets `enabled = false` without modifying sealed columns
- [ ] Touched tests pass

---

## Test Specification

```python
# packages/ai-parrot-server/tests/unit/test_users_bots_target.py
import pytest
from parrot.vault_targets import UsersBotsTarget


def test_legacy_unwrap_rejects_mismatching_ctx(v1_envelope_for_other_bot, row_bot_a):
    target = UsersBotsTarget(db_pool=None)
    with pytest.raises(ValueError):
        target.legacy_unwrap("mcp_config", v1_envelope_for_other_bot, row_bot_a)
```

---

## Agent Instructions

1. **Read the spec** (Module 11)
2. **Check dependencies** — TASK-075, TASK-079 completed
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
- ai-parrot worktree `.claude/worktrees/feat-FEAT-099-vault-crypto-hardening`, commit `d3f4e72`.
- `handlers/models/_encrypted_field.py`: `seal`/`unseal` keep their signatures but use envelope v2
  with `user_bot_context(user_id, chatbot_id, field)` (`parrot-user-bot` purpose) as AAD; the
  in-plaintext `_ctx` envelope is no longer written. `VaultCryptoError` is translated to the
  `ValueError("… context mismatch …")` the callers/tests already expect. `unwrap_legacy_envelope()`
  is kept **only** for the migrator hook.
- `handlers/models/vault_target.py`: `UsersBotsTarget(PostgresTarget)` over
  `<PARROT_SCHEMA>.users_bots` (pk `chatbot_id`, identity `(user_id, chatbot_id)`, fields
  `mcp_config`/`tools_config`, state `enabled`, quarantine `enabled = false`, no key_version
  column) + `factory` (`parrot_db_pool` or `db_pool`); `legacy_unwrap` verifies the old `_ctx`
  before re-sealing. Entry point `parrot_users_bots` registered in the server `pyproject.toml`.
- Removed the deprecated `load_vault_keys()` from `parrot.security.vault_utils` and its re-exports
  (`parrot.security.__init__`, `parrot.handlers.vault_utils`) — no caller needs raw master keys now.
- Tests: `tests/handlers/test_user_bots_security.py` patches `get_vault_keyring` and asserts v2
  rejection semantics (foreign-context blob and raw v1 blob); new
  `packages/ai-parrot-server/tests/unit/test_users_bots_target.py` (declaration/entry point,
  target context equals model sealing, row/column swaps detected, legacy unwrap accepted and
  rejected for substituted/missing envelopes).
- Results: ai-parrot targeted suite 137 passed (was 131 passed / 5 failed);
  `ai-parrot-server/tests/unit` 123 passed; `ruff check` clean on touched files.

**Deviations from spec**:
- The target module lives at `parrot/handlers/models/vault_target.py`, not
  `parrot/vault_targets.py`: the `parrot` namespace is shared via `pkgutil.extend_path`, so the
  ai-parrot package already owns the `parrot.vault_targets` module name (DocumentDB targets) and a
  second module with the same name would be shadowed.
- `unseal()` raises `ValueError` (not `VaultIntegrityError`) so existing callers and tests keep
  working; the underlying error class is named in the message.
- `test_legacy_envelope_rejected` now uses a foreign-context v2 blob plus a new `test_v1_blob_rejected`,
  since v1 blobs can no longer be produced with the current helpers.
