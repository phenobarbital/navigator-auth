# TASK-047: Vault `id_token` column + `find_user_by_provider_account`

**Feature**: FEAT-096 external-token-exchange
**Spec**: `sdd/specs/external-token-exchange.spec.md` (Module 2, decisions D3, D7, D10)
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

The exchange flow vaults the provider access token, refresh token **and
id_token** (D7) in `auth.user_identities`, and resolves the internal user first
by the stable `(auth_provider, provider_user_id)` pair. The identity vault
today has no `id_token` column and no reverse lookup from provider account to
`user_id`. This task adds both, following the existing additive-migration
pattern.

**Parallelizable**: touches only `identity/*` and `models.py`; no contention
with TASK-046/048.

---

## Scope

- `TokenResponse` (`identity/types.py`): add `id_token: Optional[str] = None`;
  include it in `credential()` and `from_credential()`; `from_oauth_response`
  picks `payload.get("id_token")`. `raw` still never leaves.
- SQL migration `identity/sql/002_identity_id_token.sql`:
  `ALTER TABLE IF EXISTS auth.user_identities ADD COLUMN IF NOT EXISTS id_token BYTEA;`
  Wire it in `identity/migrations.py` (run 001 then 002; idempotent).
- `UserIdentity` model (`models.py`): `id_token: bytes = Column(required=False, repr=False)`.
- `IdentityStore.save_linked_identity`: cipher and store `id_token` when present.
  When `token.refresh_token is None` and a row exists, **keep** the stored
  refresh token (D10) — confirm current behaviour and add a test.
- `IdentityStore.decrypt_credential`: return `id_token` decrypted.
  `masked()`: mask it like the other secrets.
- New `IdentityStore.find_user_by_provider_account(provider, provider_user_id) -> Optional[Any]`:
  returns `user_id` of the **enabled** row matching `(auth_provider, provider_user_id)`,
  `None` otherwise. Ignore `enabled = false` rows.
- Unit tests for all of the above.

**NOT in scope**: any backend code, the credential endpoint handler (it already
serialises `credential()` and will pick up `id_token` automatically — verify
with one test, do not modify the handler).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/identity/types.py` | MODIFY | `id_token` on `TokenResponse` |
| `navigator_auth/identity/sql/002_identity_id_token.sql` | CREATE | Additive column |
| `navigator_auth/identity/migrations.py` | MODIFY | Run `002` after `001` |
| `navigator_auth/models.py` | MODIFY | `UserIdentity.id_token` |
| `navigator_auth/identity/store.py` | MODIFY | save/decrypt/mask `id_token`; `find_user_by_provider_account` |
| `tests/test_identity_id_token.py` | CREATE | Types round-trip, store cipher, lookup, refresh preservation |

---

## Implementation Notes

### Pattern to Follow
Mirror how `refresh_token` is handled end-to-end in `identity/store.py`
(encrypt on save, decrypt in `decrypt_credential`, `mask_value` in `masked`).
Migration loading mirrors `ensure_identity_columns` (a list of SQL files run in
order is fine).

### Key Constraints
- Column is `BYTEA`, ciphered with the same `IdentityCipher` and `key_version`.
- `find_user_by_provider_account` must use the existing unique partial index
  `(user_id, auth_provider, provider_user_id)`; a plain `filter(auth_provider=,
  provider_user_id=)` is enough, then filter `enabled` in Python if needed.
- Use the existing `NoDataFound` handling style in the store.

### References in Codebase
- `navigator_auth/identity/store.py:29` — `save_linked_identity`.
- `navigator_auth/identity/sql/001_identity_credentials.sql`.
- `navigator_auth/identity/migrations.py` — `ensure_identity_columns`.
- `navigator_auth/handlers/user_identities.py:172` — credential endpoint (read only).

---

## Acceptance Criteria

- [ ] `TokenResponse.credential()` ↔ `from_credential()` preserve `id_token`; `raw` excluded
- [ ] Migration is idempotent (run twice, no error), and `UserIdentity` loads with the column
- [ ] `save_linked_identity` stores ciphered `id_token`; `decrypt_credential` returns it;
      `masked()` hides it
- [ ] Re-save with `refresh_token=None` keeps the previously stored refresh token
- [ ] `find_user_by_provider_account`: hit → `user_id`; miss → `None`; disabled row → `None`
- [ ] `pytest tests/test_identity_id_token.py -v` passes; `ruff check navigator_auth/identity` clean

---

## Test Specification

```python
# tests/test_identity_id_token.py
# use a fake pool/conn and monkeypatched UserIdentity.get/filter/insert as the existing
# identity tests do (no live DB)
# test_token_response_id_token_roundtrip
# test_store_saves_and_decrypts_id_token
# test_masked_hides_id_token
# test_resave_without_refresh_keeps_existing_refresh
# test_find_user_by_provider_account_hit_miss_disabled
# test_migration_runs_002_after_001
```

---

## Agent Instructions

1. **Read the spec**; 2. **Check dependencies** (none);
3. **Update index** → in-progress; 4. **Implement**; 5. **Verify**;
6. **Move to completed/**; 7. **Update index** → done; 8. **Fill Completion Note**.

---

## Completion Note

**Completed by**: sdd-worker
**Date**: 2026-09-04
**Notes**:
- `TokenResponse.id_token: Optional[str] = None` added; `credential()` /
  `from_credential()` / `from_oauth_response()` all carry it; `raw` still
  never leaves `credential()`.
- `navigator_auth/identity/sql/002_identity_id_token.sql` created
  (`ADD COLUMN IF NOT EXISTS id_token BYTEA`); `identity/migrations.py`
  now runs a `_MIGRATION_FILES` tuple (`001` then `002`) in order, each
  additive/idempotent — verified with a 2-file-execution-order test and a
  run-twice-no-error test.
- `UserIdentity.id_token: bytes = Column(required=False, repr=False)`.
- `IdentityStore.save_linked_identity` ciphers and stores `id_token` (same
  `IdentityCipher`/`key_version` as `access_token`/`refresh_token`).
  Implemented D10 for **both** `refresh_token` and `id_token`: on an
  existing row, when the incoming `token.refresh_token`/`token.id_token`
  is `None`, that field is left out of the update instead of being
  overwritten with `None` — the previously vaulted value survives a
  re-exchange that doesn't return a fresh one.
- `decrypt_credential` decrypts `id_token` when present; `masked()` now
  reports `has_id_token: bool` instead of ever exposing the raw column
  (mirrors `has_refresh_token`).
- `IdentityStore.find_user_by_provider_account(provider, provider_user_id)`
  added: `UserIdentity.filter(auth_provider=, provider_user_id=)`, then
  `enabled` rows filtered in Python, returns the first `user_id` or `None`
  on miss/disabled-only/`NoDataFound`.
- The credential endpoint (`handlers/user_identities.py`) was **not**
  modified, as specified; verified with a dedicated test that
  `decrypt_credential(...).credential()` now serializes `id_token`
  automatically.
- Fixed 3 pre-existing unit tests in `tests/unit/identity/` that the
  additive change legitimately invalidated (not a new file per the task's
  table, but required to avoid leaving the suite red):
  - `test_token_response.py::test_credential_shape_and_no_raw` — exact key
    set now includes `id_token`.
  - `test_identity_store.py::TestCipherRoundtripThroughStore` (2 tests) —
    bare `MagicMock()` identities didn't set `.id_token`, so the mock
    auto-attribute (truthy) was fed to the cipher; now explicitly set to a
    real ciphertext / `None` per case.
  - `test_identity_migrations.py` (3 tests) — updated `assert_awaited_once`
    → 2-call assertions (001 then 002) and added coverage for the new
    `002_identity_id_token.sql` file.
  - `test_identity_crypto.py::test_key_rotation_old_ciphertext_still_readable`
    remains failing — confirmed identical failure on `dev` before this
    task (unrelated pre-existing bug in key-selection ordering), left
    untouched.
- `pytest tests/test_identity_id_token.py tests/unit/identity/ -v`: 115
  passed, 1 pre-existing unrelated failure. `ruff check
  navigator_auth/identity`: clean except the pre-existing unused
  `typing.Any` import in `flow_store.py` (confirmed identical on `dev`,
  untouched — out of scope, not a file this task modifies).

**Deviations from spec**: None functionally; touched three existing
`tests/unit/identity/*.py` files beyond the task's file table to fix
regressions the additive `id_token` field/migration directly caused
(documented above).
