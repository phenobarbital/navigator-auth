---
id: FW-005
query_id: Q002
type: wiki_query
intent: "Orient: session vault integrity check and secret format"
executed_at: 2026-11-11T14:52:00Z
duration_ms: 1100
parent_id: null
depth: 0
---

# FW-005 — UnsupportedFormatError is the typed error for a non-v2 envelope (legacy v1 blob) after FEAT-099

## Summary

FEAT-099 (vault crypto hardening) replaced the vault cipher with sealed envelope v2. TASK-071 defines typed errors:
`UnsupportedFormatError` = bad version byte, unknown `alg_id` or blob < 32 bytes, and its acceptance criterion is
"v1 fixture blobs → `UnsupportedFormatError`". TASK-075 ships an offline migrator (`migrate_v1_to_v2`, dry-run,
quarantine, backup) run via `navigator-vault migrate --run`, which requires `002_vault_crypto_hardening.sql` first;
that SQL also adds the `integrity_fail` audit operation that SessionVault load writes. So user 35's `account`
secret is most likely a pre-FEAT-099 (v1) row that was never migrated — a data/runbook issue in the dev DB, not
a code bug — and the loader fails it closed per row (0 secrets, 1 integrity failure).

## Citations

- path: `sdd/tasks/completed/TASK-071-vault-envelope-v2.md`
  lines: 44-46
  excerpt: |
    - Errors: `VaultCryptoError`, `VaultIntegrityError` (wraps `InvalidTag`),
      `UnknownKeyVersionError` (also `KeyError`), `UnsupportedFormatError` (bad version byte,
      unknown `alg_id`, blob < 32 bytes).

- path: `sdd/tasks/completed/TASK-071-vault-envelope-v2.md`
  lines: 104
  excerpt: |
    - [ ] v1 fixture blobs → `UnsupportedFormatError` (or `VaultIntegrityError` if the first byte collides — assert no plaintext)

- path: `sdd/tasks/completed/TASK-075-vault-migrator-runner.md`
  lines: 42-49
  symbol: `migrate_v1_to_v2`
  excerpt: |
    - `migrate_v1_to_v2(targets, keyring, *, dry_run, quarantine, backup_dir, batch_size)`.
    - `dry_run`: decrypt-only pass, zero writes, no backup required.

- path: `navigator_auth/vault/sql/002_vault_crypto_hardening.sql`
  lines: 1-14
  excerpt: |
    -- Session Vault: schema changes for envelope v2 (FEAT-099)
    -- 2. auth.user_vault_audit.operation also accepts 'quarantine' (offline migrator)
    --    and 'integrity_fail' (SessionVault load).
    -- Must be applied before running `navigator-vault migrate --run`.

## Notes

Wiki: query score TASK-143 1.00, `file:navigator_auth/handlers/vault.py` 0.89, SQL page 0.86; follow-up query
"vault envelope v2 migrate legacy format UnsupportedFormatError" → TASK-075 1.00, TASK-071 0.89, spec
`sdd/specs/vault-crypto-hardening.spec.md` 0.54. The envelope code lives in the `navigator_session` package
(TASK-071 lines 47-55), not in this repo. Alternative cause not excluded: a row written by a different/older
navigator-session wheel (memory mem-1365e23be030: navigator-session is a wheel install, not editable).
[cross-lane: type=read, intent=confirm session_vault.py:440-495 catches per-row errors and logs 'failed integrity check' + audit integrity_fail]
[cross-lane: type=git_log, intent=date FEAT-099 merge vs when user 35's account secret was written]
