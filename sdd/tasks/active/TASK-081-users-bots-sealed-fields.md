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

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
