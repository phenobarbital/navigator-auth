# FEAT-099 — vault crypto hardening: final verification

Date: 2026-09-16 · branch `feat-FEAT-099-vault-crypto-hardening` in every repo.

## Test results (worktrees vs. their `dev`/`main` baseline)

| Repo | Suite | Baseline | This branch | New failures |
|---|---|---|---|---|
| navigator-session | `tests/` | 96 passed | **341 passed**, 0 failed | none |
| navigator-auth | `tests/` | 33 failed / 1396 passed | **32 failed / 1342 passed** | none (one pre-existing failure fixed) |
| ai-parrot | `tests/{handlers,unit,auth,security}` | 42 failed / 570 passed | **42 failed / 607 passed** | none |
| ai-parrot-server | `tests/{unit,integration}` | 3 failed / 205 passed | **3 failed / 227 passed** | none |
| navigator-frontend-next | `vitest run` | 9 failed / 694 passed | **9 failed / 723 passed** | none |

Remaining failures are pre-existing and unrelated to the vault (navigator-auth:
YAML policy storage / PDP; ai-parrot: dataset, planogram, A2A broker
registration; frontend: 3 unrelated test files). The navigator-auth count drops
by one because `test_key_rotation_old_ciphertext_still_readable` no longer
depends on the developer's `VAULT_ACTIVE_KEY_ID`.

Raw output: `feat-099-navigator-session.log`, `feat-099-navigator-auth.log`
(trimmed to its summary — the full run is dominated by DEBUG logging),
`feat-099-ai-parrot.log`, `feat-099-frontend.log`.

## Spec §5 checks

| Check | Result |
|---|---|
| No AEAD call with `associated_data=None` in runtime code | clean |
| No v1 helpers (`encrypt_for_db`/`decrypt_for_db`/`*_for_session`/`load_vault_keys`) outside the migrator | clean |
| `load_master_keys` only in key-ring construction and the isolated v1 reader | clean |
| Vault HTTP responses never contain `value` | clean (only the POST request body reads it) |
| `svelte-check` | 0 errors (168 pre-existing warnings) |
| `ruff` | no new findings (pre-existing: 2 in navigator-auth tests, 3 in ai-parrot) |

## Migration rehearsal

`navigator-session/tests/integration/test_vault_migration_e2e.py` drives the real
`navigator-vault` CLI over three seeded v1 stores (single-field PostgreSQL table,
multi-field table with the legacy `_ctx` envelope, and a document store):

- `list-targets` → `migrate --dry-run` (no writes) → `migrate --run --backup-dir
  --quarantine` → `verify --backup-dir` → `restore`.
- Soft-deleted rows migrate; a v1 blob copied between rows is rejected by
  `legacy_unwrap` and quarantined instead of being legitimised.
- Backups contain v1 ciphertext only (no plaintext), and the restore returns all
  three stores byte-for-byte to their pre-migration state.
- A second run reports `migrated=0` / `already_v2>0` and changes nothing.
- Rotation after migration re-seals every target and leaves the Redis naming key
  unchanged.

The navigator-auth schema migration (`002_vault_crypto_hardening.sql` and identity
`003`) was executed against a real PostgreSQL during TASK-078, inside a
transaction rolled back on a scratch schema.

## Still to be done by operators

Production rehearsal on a copy of live data to measure the maintenance window,
then the migration itself — see
`navigator-session/docs/vault/migration-runbook.md`.
