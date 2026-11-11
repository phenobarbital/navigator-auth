---
id: FC-001
query_id: Q006
type: grep
intent: "Locate UnsupportedFormatError and the vault integrity check"
executed_at: 2026-11-11T14:44:00Z
duration_ms: 900
parent_id: null
depth: 0
---

# FC-001 — Vault UnsupportedFormatError comes from navigator-session's v2 envelope (legacy v1 blob)

## Summary

`UnsupportedFormatError` is not in navigator_auth: it lives in the installed dependency
`navigator-session` 1.1.1 (`navigator_session/vault/envelope.py`). Any DB ciphertext whose
first byte is not `FORMAT_VERSION = 0xA2` (or is shorter than 32 bytes, or has an unknown
alg id) raises it. `SessionVault.load_for_session` catches it per row, logs
"failed integrity check", audits `integrity_fail`, and continues — non-fatal by design
("Loading never fails because of a single bad secret"). The user=35 key=`account` row is
therefore almost certainly a pre-v2 (v1/legacy) blob that was never migrated. navigator-session
ships an operator CLI `navigator-vault migrate` with a `LegacyV1Reader` for exactly this.

## Citations

- path: `.venv/lib/python3.11/site-packages/navigator_session/vault/envelope.py`
  lines: 34-39
  symbol: `FORMAT_VERSION`
  excerpt: |
    FORMAT_VERSION = 0xA2
    NONCE_SIZE = 12
    TAG_SIZE = 16
    HEADER_SIZE = 16
    MIN_BLOB_SIZE = HEADER_SIZE + TAG_SIZE
    AAD_MAGIC = b"NAVVAULT-AAD"

- path: `.venv/lib/python3.11/site-packages/navigator_session/vault/envelope.py`
  lines: 69-69, 118-134
  symbol: `UnsupportedFormatError`
  excerpt: |
    69  class UnsupportedFormatError(VaultCryptoError):
    122     raise UnsupportedFormatError("blob too short for a v2 envelope header")
    124 if version != FORMAT_VERSION:
    125     raise UnsupportedFormatError(
    130     raise UnsupportedFormatError(f"unknown vault algorithm id {alg_id}")

- path: `.venv/lib/python3.11/site-packages/navigator_session/vault/session_vault.py`
  lines: 420-424, 448-460
  symbol: `SessionVault.load_for_session`
  excerpt: |
    420  Secrets whose database ciphertext fails to open (tampered, moved from
    421  another user/key, unknown key version, legacy format) are skipped,
    422  logged by key name and error class, and audited as ``integrity_fail``.
    423  Loading never fails because of a single bad secret.
    453  except INTEGRITY_ERRORS as err:
    454      logger.error(
    455          "Vault secret failed integrity check: user=%s key=%s error=%s",
    459      failures.append((key, row["key_version"]))
    460      continue

- path: `.venv/lib/python3.11/site-packages/navigator_session/vault/migrate/cli.py`
  lines: 1-16
  symbol: `navigator-vault` CLI
  excerpt: |
    ``navigator-vault`` — operator CLI for the vault migration runbook.
        navigator-vault list-targets
        navigator-vault migrate --dry-run
        navigator-vault migrate --run --backup-dir /secure/path [--quarantine]
        navigator-vault verify --backup-dir /secure/path/<run_id>
    keys      VAULT_MASTER_KEY_v{N}, VAULT_ACTIVE_KEY_ID, VAULT_CIPHER_BACKEND, VAULT_NAMING_KEY_ID

- path: `.venv/lib/python3.11/site-packages/navigator_session/vault/migrate/legacy_v1.py`
  lines: 45
  symbol: `LegacyV1Reader`
  excerpt: |
    """Decrypts v1 database-layer blobs with the legacy key schedule.

- path: `navigator_auth/vault/integration.py`
  lines: 18, 87
  symbol: `SessionVault.load_for_session` call site
  excerpt: |
    18  from navigator_session.vault.session_vault import SessionVault
    87          vault = await SessionVault.load_for_session(

## Notes

- Fix is operational (run `navigator-vault migrate` against the example DB, or delete the
  stale row), not a code bug in navigator_auth. The logged error is expected behaviour of the
  v2 envelope. Could also be a v2 blob sealed under a different master key / key id — that
  raises a different error class (key unknown / InvalidTag), so `UnsupportedFormatError`
  specifically points to legacy format or truncated blob.
- Tests already cover the error class: `tests/unit/vault/test_vault_view.py:114`,
  `tests/unit/identity/test_identity_crypto.py:135`.
- [cross-lane: type=git_log, intent=when navigator-session was bumped to the v2 envelope (pyproject.toml / uv.lock) — dates the legacy row]
