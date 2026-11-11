---
id: FG-002
query_id: Q024
type: git_log
intent: "Recent history of the vault and passkey migration runners."
executed_at: 2026-11-11T13:44:31Z
duration_ms: 400
parent_id: null
depth: 0
---

# FG-002 — Vault and passkey migration runner history (last 180 days)

## Summary

4 commits, 2026-06-19 → 2026-10-02. Both runners are low-churn compared with identity: the passkey runner was created with its single SQL file on 2026-10-02 (TASK-87) and only reformatted since; the vault runner was last functionally changed on 2026-09-16 when `002_vault_crypto_hardening.sql` was added. Each subsystem carries its own runner plus its own `sql/` folder with independent numbering (vault 00x, passkey 001, identity 001–006). Path filter was widened to include `navigator_auth/vault/sql` and `navigator_auth/passkey/sql`.

## Citations

- path: `navigator_auth/passkey/migrations.py`
  commit: `1e1666a` — 2026-10-02 — Jesus Lara — "style: apply black formatting (post sdd-worker)"
  files: `navigator_auth/passkey/migrations.py`

- path: `navigator_auth/passkey/sql/001_passkey_credentials.sql`
  commit: `75b4475` — 2026-10-02 — Jesus Lara — "feat(passkey-support-backend): TASK-87 — Passkey types and migration"
  files: `navigator_auth/passkey/migrations.py`, `navigator_auth/passkey/sql/001_passkey_credentials.sql`

- path: `navigator_auth/vault/sql/002_vault_crypto_hardening.sql`
  commit: `d9906ac` — 2026-09-16 — Jesus Lara — "feat(vault-crypto-hardening): TASK-078 — Session Vault HTTP API v2 — metadata only, typed errors, audit migration"
  files: `navigator_auth/vault/migrations.py`, `navigator_auth/vault/sql/002_vault_crypto_hardening.sql`

- path: `navigator_auth/vault/migrations.py`
  commit: `470ccaf` — 2026-06-19 — Jesus — "feat(auth): enforce SOC2 auth, add allowed_ips backend and request sanitization"
  files: `navigator_auth/vault/migrations.py`

## Notes

- d9906ac touched both the vault and identity runners in one commit (also cited in FG-001): a single feature already spans two migration sets.
- No commits in the window for vault `001_*.sql` (older than 180 days or never changed).
