---
id: F009
query_id: "Q013"
type: "git_log"
intent: "Recent commits on vault (format change -> UnsupportedFormatError)"
executed_at: 2026-11-11T14:47:00Z
parent_id: null
depth: 0
merged_from: [FG-002]
---

# F009 — Vault: FEAT-099 vault-crypto-hardening made v1 secrets unreadable at runtime

## Summary

No commit touched `navigator_auth/vault/` in the last 45 days; the last change is FEAT-099
`vault-crypto-hardening` (merged 2026-09-16, PR #599, navigator-auth 0.28.0). `session_vault.py`
and `UnsupportedFormatError` do not live in this repo (no `git log -S` hit under
`navigator_auth`): per the FEAT-099 spec they are in the sibling package `navigator-session`
(`navigator_session/vault/`). The spec makes the v2 envelope mandatory and raises
`UnsupportedFormatError` for anything not v2, including legacy v1; v1 data must be converted
offline with the `navigator-vault migrate` CLI. The user=35 `account` secret is therefore most
likely a pre-FEAT-099 v1 secret that was never migrated (or a secret sealed with another key ring).

## Citations

- path: `sdd/specs/vault-crypto-hardening.spec.md`
  lines: 82-84
  symbol: `G5`
  excerpt: |
    **G5** — An offline batch migrator converts all v1 data to v2 with dry-run, mandatory
    pre-migration raw export (backup), verify, resume, restore and explicit quarantine; after
    migration v1 is rejected at runtime.

- path: `sdd/specs/vault-crypto-hardening.spec.md`
  lines: 303
  symbol: `UnsupportedFormatError`
  excerpt: |
    class UnsupportedFormatError(VaultCryptoError): ...        # not v2 (incl. legacy v1) / bad alg

- path: `sdd/specs/vault-crypto-hardening.spec.md`
  lines: 216
  symbol: `navigator_session/vault/session_vault.py`
  excerpt: |
    | `navigator_session/vault/session_vault.py` | modifies | Context-bound seal/open, HMAC Redis names, ...

- path: `sdd/specs/vault-crypto-hardening.spec.md`
  lines: 383-386
  symbol: `navigator-vault migrate`
  excerpt: |
    3. `navigator-vault migrate --dry-run` → review report (must show `failed == 0`, ...)
    4. `navigator-vault migrate --run --backup-dir /secure/path [--quarantine]`.

- path: `navigator_auth/handlers/vault.py`
  lines: n/a
  symbol: `VaultView`
  excerpt: |
    d9906ac 2026-09-16 TASK-078 — Session Vault HTTP API v2: GET key -> metadata
    (409 vault_integrity_error when the secret no longer opens); shared KeyRing app['vault_keyring']

## Notes

- Vault history: 5af071b/44f1de2/d9906ac/d7dbc8f (2026-09-16, FEAT-099), 1c941c5 2026-08-21,
  76c4bed/470ccaf 2026-06-19, then Feb 2026 initial vault support.
- The log line "1 integrity failure(s)" is the designed fail-closed path, not a crash; the fix is
  operational (migrate/quarantine/re-create the secret) or a friendlier message, not crypto code.
- [cross-lane: type=read, intent=confirm installed navigator-session version and the
  session_vault.py:457 integrity-check site in .venv; check whether the example writes an
  `account` vault secret and with which writer]
