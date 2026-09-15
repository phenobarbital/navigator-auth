# TASK-077: Identity Vault — context-bound `IdentityCipher`, store re-seal, identity target

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 7)
**Repository**: `navigator-auth` (this repo, branch from `dev`)
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-072
**Assigned-to**: unassigned

---

## Context

`auth.user_identities` holds three independently encrypted token columns per linked account.
Without AAD, tokens can be swapped between users, accounts and columns. This task binds each
token to `(user_id, auth_provider, provider_user_id, field)` and registers the table as a
`ProtectedTarget` so rotation and migration cover it.

It is also the first navigator-auth task after the navigator-session API break, so it removes
navigator-auth's copies of v1 kernel tests that would otherwise fail.

---

## Scope

- `navigator_auth/identity/crypto.py`: replace `encrypt_for_db`/`decrypt_for_db` usage with
  `KeyRing` + `seal_value`/`open_value`; new keyword-only signature
  `encrypt(value, *, user_id, auth_provider, provider_user_id, field)` / `decrypt(...)`;
  keep `key_id` property (active key); keep `ConfigError` behaviour when vault crypto is
  unavailable.
- `navigator_auth/identity/store.py`: pass contexts in `save_linked_identity`, token refresh
  update path (`~line 172`) and `decrypt_credential`; when an upsert changes
  `provider_user_id`, re-seal **all** non-NULL token fields in the same transaction; map
  `VaultIntegrityError` to a typed store error so handlers can surface `needs_reconnect`.
- `navigator_auth/identity/targets.py`: `IdentityTarget(PostgresTarget)` for
  `auth.user_identities` (fields `access_token`, `refresh_token`, `id_token`; quarantine sets
  `enabled = false` + audit, tokens left as-is).
- `pyproject.toml`: `navigator-session>=1.0.0`; entry point
  `identity = navigator_auth.identity.targets:factory` in `navigator_session.vault_targets`.
- Tests: update `tests/unit/identity/test_identity_crypto.py`,
  `tests/unit/identity/test_identity_store.py`, `tests/test_identity_id_token.py`,
  `tests/test_token_exchange_backend.py` for the new signatures; add swap/relink tests.
- **Remove** `tests/unit/vault/test_crypto.py`, `tests/unit/vault/test_session_vault.py`,
  `tests/unit/vault/test_key_rotation.py` (they test navigator-session v1 internals; v2
  equivalents live in navigator-session `tests/vault/` since TASK-071/073/074).

**NOT in scope**: `VaultView` / vault integration (TASK-078); navigator-session changes.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/identity/crypto.py` | MODIFY | Context-bound cipher |
| `navigator_auth/identity/store.py` | MODIFY | Contexts, re-seal on relink, typed error |
| `navigator_auth/identity/targets.py` | CREATE | `IdentityTarget` + factory |
| `pyproject.toml` | MODIFY | Dependency bump + entry point |
| `tests/unit/identity/test_identity_crypto.py` | MODIFY | New signatures, swap tests |
| `tests/unit/identity/test_identity_store.py` | MODIFY | Relink re-seal test |
| `tests/test_identity_id_token.py`, `tests/test_token_exchange_backend.py` | MODIFY | Signatures |
| `tests/unit/identity/test_identity_target.py` | CREATE | Target context/quarantine |
| `tests/unit/vault/test_crypto.py`, `test_session_vault.py`, `test_key_rotation.py` | DELETE | Superseded by navigator-session tests |

---

## Implementation Notes

### Key Constraints
- `provider_user_id` is nullable (unique index `WHERE provider_user_id IS NOT NULL`): pass
  `None`, never `""`.
- `auth_provider` column name as stored in `auth.user_identities` (check the model in
  `identity/types.py` / migrations) — do not use display names.
- Develop against the navigator-session feature worktree installed editable (navigator-auth
  already declares `[tool.uv.sources] navigator-session = { path = "../navigator-session", editable = true }`;
  point it at the worktree or check out the feature branch there while developing).

### References in Codebase
- `navigator_auth/identity/crypto.py`, `store.py`
- `navigator_auth/identity/sql/001_identity_credentials.sql` — columns and unique index
- `../navigator-session/navigator_session/vault/targets/postgres.py` — base class (TASK-072)

---

## Acceptance Criteria

- [ ] No `encrypt_for_db` / `decrypt_for_db` references left in `navigator_auth/`
- [ ] Moving `access_token` blob into `refresh_token` (same row) → integrity error
- [ ] Moving tokens to another user / provider account → integrity error
- [ ] `provider_user_id` change re-seals all token fields
- [ ] `IdentityTarget` discovered via entry point
- [ ] `source .venv/bin/activate && pytest tests/unit/identity tests/test_identity_id_token.py tests/test_token_exchange_backend.py -v` passes

---

## Test Specification

```python
# tests/unit/identity/test_identity_crypto.py
import pytest
from navigator_session.vault import VaultIntegrityError
from navigator_auth.identity.crypto import IdentityCipher

CTX = dict(user_id=1, auth_provider="google", provider_user_id="g-1")


def test_field_swap_detected(keyring):
    cipher = IdentityCipher(keyring=keyring)
    blob = cipher.encrypt("acc", field="access_token", **CTX)
    with pytest.raises(VaultIntegrityError):
        cipher.decrypt(blob, field="refresh_token", **CTX)


def test_null_provider_user_id_distinct(keyring):
    cipher = IdentityCipher(keyring=keyring)
    blob = cipher.encrypt("acc", user_id=1, auth_provider="google",
                          provider_user_id=None, field="access_token")
    with pytest.raises(VaultIntegrityError):
        cipher.decrypt(blob, user_id=1, auth_provider="google",
                       provider_user_id="", field="access_token")
```

---

## Agent Instructions

1. **Read the spec** (Module 7)
2. **Check dependencies** — TASK-072 completed (TASK-071 API available)
3. **Update status** → `"in-progress"`
4. **Implement** in `.claude/worktrees/feat-FEAT-099-vault-crypto-hardening`
5. **Verify** acceptance criteria
6. **Move file** to `sdd/tasks/completed/`, index → `"done"`
7. **Completion Note**

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: claude-session (Claude Opus 5)
**Date**: 2026-09-16
**Notes**:
- navigator-auth worktree `.claude/worktrees/feat-FEAT-099-vault-crypto-hardening`, commit `d7dbc8f`.
- `identity/crypto.py`: `IdentityCipher(master_keys=None, *, keyring=None)` on navigator-session
  `KeyRing` + `seal_value`/`open_value`; keyword-only `encrypt/decrypt(value, *, user_id,
  auth_provider, provider_user_id, field)`; `key_id` and `keyring` properties; active key =
  `VAULT_ACTIVE_KEY_ID` if in the ring else newest (previous fallback kept). Helpers
  `normalize_user_id` (int for ints/digit strings, str otherwise) and `identity_context`;
  constants `IDENTITY_PURPOSE`, `IDENTITY_FIELDS`.
- `identity/store.py`: `_seal`/`_open` context helpers; `save_linked_identity` seals with
  `(user_id, provider, token.provider_user_id, column)` and, when an existing row's
  `provider_user_id` differs (legacy rows without one), re-seals kept `refresh_token`/`id_token`;
  `update_tokens` uses the row context; `decrypt_credential` raises the new
  `IdentityCredentialError(provider, field, reason)` on any `VaultCryptoError`.
- `handlers/user_identities.py`: `BaseIdentityView._decrypt` maps `IdentityCredentialError` →
  `409 "<provider>: stored credential cannot be read; re-link the identity."` (renew and
  credential endpoints).
- `identity/targets.py`: `IdentityTarget` (`<AUTH_DB_SCHEMA>.user_identities`, pk `identity_id`,
  identity `(user_id, auth_provider, provider_user_id)`, fields `access_token/refresh_token/
  id_token`, `include_field_in_context`, state `enabled`, quarantine `enabled = false`, no touch
  column) + `factory`; entry point `identity` in `pyproject.toml`.
- Tests: rewrote `tests/unit/identity/test_identity_crypto.py` (env isolated), adapted
  `test_identity_store.py` and `tests/test_identity_id_token.py` to contexts, added handler 409
  tests and `tests/unit/identity/test_identity_vault_v2.py` (row/column/account swaps, relink
  re-seal, same-account keep, tampered kept token, update_tokens context, target context equals
  store sealing, target iterate/quarantine/export/restore, entry point). Deleted
  `tests/unit/vault/test_crypto.py`, `test_session_vault.py`, `test_key_rotation.py`.
- Test setup for this worktree: the editable install points at the main checkout, so the
  compiled `*.cpython-311-*.so` extensions (git-ignored) were copied into the worktree and tests
  run with `PYTHONPATH=<auth worktree>:<session worktree>`.
- Results: full navigator-auth suite dev 33 failed / 1396 passed vs worktree 32 failed / 1327
  passed — no new failures (remaining failures are pre-existing, e.g. YAML storage/PDP), and
  `test_key_rotation_old_ciphertext_still_readable` fixed (it depended on the developer's
  `VAULT_ACTIVE_KEY_ID`). Identity suites incl. real-DB `test_token_exchange_backend.py` pass.
  `ruff check` clean on touched files.

**Deviations from spec**:
- `navigator-session>=1.0.0` dependency pin deferred to TASK-085 (navigator-session is still
  0.10.2 in its worktree; pinning now would break local resolution).
- Relink re-seal is triggered inside `save_linked_identity` when the matched row's
  `provider_user_id` differs from the token's; `update_tokens` never changes the account.
- A tampered kept token during relink raises `IdentityCredentialError` instead of silently
  dropping it.
- Handlers gained a 409 mapping (small addition beyond the store) so unreadable credentials do
  not surface as 500.
- `IdentityTarget.name` follows `AUTH_DB_SCHEMA` (e.g. `tenant_auth.user_identities`).
