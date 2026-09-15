# TASK-078: Session Vault HTTP API v2 — metadata only, typed errors, audit migration

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 8, §2 HTTP contract)
**Repository**: `navigator-auth` (this repo)
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-073, TASK-077
**Assigned-to**: unassigned

---

## Context

G6: plaintext secrets must never reach the browser. Today
`GET /api/v1/user/vault/{key}` returns `{"key", "value"}` (`handlers/vault.py:70`). The
frontend Secrets UI (TASK-083) is built against the contract defined in the spec, so the
response shapes here must match it exactly.

---

## Scope

- `navigator_auth/handlers/vault.py` (`VaultView`):
  - `GET /api/v1/user/vault` → `{"secrets": [VaultSecretMetadata...]}` from
    `vault.list_metadata()`.
  - `GET /api/v1/user/vault/{key}` → `VaultSecretMetadata` (no `value`), `404` if absent.
  - `POST` → `201 {"key", "updated_at", "key_version", "message"}` using the metadata returned
    by `SessionVault.set()`; `400` for validation (`ValueError`).
  - `DELETE` unchanged shape.
  - Error mapping: vault cannot be loaded → `503 {"error": "vault_unavailable"}`;
    `VaultIntegrityError` for the requested key → `409 {"error": "vault_integrity_error"}`.
- `navigator_auth/vault/integration.py`: pass/obtain `KeyRing` once per app (store on
  `app["vault_keyring"]` at startup, fallback to `KeyRing.from_env()`); loading stays
  non-blocking; non-integer `user_id` still skipped.
- `navigator_auth/vault/sql/002_vault_audit_sid_hmac.sql` + `vault/migrations.py` — idempotent
  migration, **must be applied before running the migrator** (add to runbook in TASK-085).
  Findings from TASK-072 against `001_create_vault_tables.sql`:
  - `auth.user_vault_audit.session_id` is `VARCHAR(36)`; `naming_hmac()` is 64 hex chars →
    widen to `VARCHAR(64)` and add a column comment (HMAC of the session id, or `run:<run_id>`
    for migration audit rows).
  - `auth.user_vault_audit.operation` has `CHECK (operation IN ('set','get','delete','rotate'))`
    → replace the constraint to also allow `'quarantine'` (written by
    `UserVaultTarget.audit_quarantine`, TASK-072) and `'integrity_fail'` (TASK-073). Both fit
    `VARCHAR(16)`.
  - `auth.user_vault_secrets.key_version` is `SMALLINT` (max 32767) while `KeyRing` accepts
    key ids up to 65535 → widen to `INTEGER` (and `auth.user_vault_audit.key_version`,
    `auth.vault_key_registry.key_id`), or document a 32767 cap. Recommended: widen.
- Tests: update `tests/unit/vault/test_vault_view.py`, `tests/unit/vault/test_integration.py`,
  `tests/unit/vault/test_migrations.py`.

**NOT in scope**: frontend (TASK-083); identity handlers (covered by TASK-077 store error).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/vault.py` | MODIFY | Metadata responses + error mapping |
| `navigator_auth/vault/integration.py` | MODIFY | KeyRing wiring |
| `navigator_auth/vault/sql/002_vault_audit_sid_hmac.sql` | CREATE | Audit column migration |
| `navigator_auth/vault/migrations.py` | MODIFY | Apply 002 |
| `tests/unit/vault/test_vault_view.py` | MODIFY | New contract tests |
| `tests/unit/vault/test_integration.py` | MODIFY | KeyRing wiring |
| `tests/unit/vault/test_migrations.py` | MODIFY | 002 applied idempotently |

---

## Implementation Notes

### Key Constraints
- Serialize `updated_at` as ISO-8601 UTC string.
- Never include `value` in any response, including error bodies and logs.
- Keep `@user_session()` and CORS behaviour unchanged.
- Keep existing `_json_error` helper usage.

### References in Codebase
- `navigator_auth/handlers/vault.py`
- `navigator_auth/vault/integration.py`
- `navigator_auth/vault/sql/001_create_vault_tables.sql`

---

## Acceptance Criteria

- [ ] GET list/detail return metadata only; POST returns metadata + message
- [ ] `409 vault_integrity_error` and `503 vault_unavailable` covered by tests
- [ ] Audit migration idempotent
- [ ] Vault load failures still never block login (existing tests green)
- [ ] `source .venv/bin/activate && pytest tests/unit/vault -v` passes

---

## Test Specification

```python
# tests/unit/vault/test_vault_view.py
async def test_get_key_returns_metadata_only(client_with_vault):
    resp = await client_with_vault.get("/api/v1/user/vault/api_key")
    body = await resp.json()
    assert resp.status == 200
    assert set(body) == {"key", "updated_at", "key_version"}


async def test_post_returns_metadata(client_with_vault):
    resp = await client_with_vault.post("/api/v1/user/vault",
                                        json={"key": "jira:token", "value": "x"})
    body = await resp.json()
    assert resp.status == 201 and "value" not in body
    assert {"key", "updated_at", "key_version", "message"} <= set(body)
```

---

## Agent Instructions

1. **Read the spec** (Module 8, HTTP contract)
2. **Check dependencies** — TASK-073, TASK-077 completed
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
- navigator-auth worktree `.claude/worktrees/feat-FEAT-099-vault-crypto-hardening`, commit `d9906ac`.
- `handlers/vault.py` (`VaultView`): `GET /api/v1/user/vault` → `{"secrets": [{key, updated_at,
  key_version}]}` from `list_metadata()`; `GET /{key}` → metadata only, after verifying the secret
  still opens (`vault.get` result discarded) → `409 {"error": "vault_integrity_error"}` on any
  `VaultCryptoError`; missing metadata (Redis-only cache) → `{key, updated_at: null, key_version:
  null}`; `POST` → `201 {key, updated_at, key_version, message}`; `DELETE` unchanged; vault not
  loadable / no DB pool → `503 {"error": "vault_unavailable"}` (previously 500).
- `vault/integration.py`: `setup_vault_keyring(app)` stores a shared `KeyRing` at
  `app["vault_keyring"]` (`VAULT_KEYRING_APP_KEY`), non-blocking; `load_vault_for_session(...,
  keyring=None)` forwards it; `get_session_vault` passes the app keyring; error logs show the
  exception class only. `auth.py` calls `setup_vault_keyring(app)` on startup and passes the
  keyring on login.
- `vault/sql/002_vault_crypto_hardening.sql` + `vault/migrations.py` (`MIGRATION_FILES`
  001→002): conditional `DO` blocks (no locks once applied) — `user_vault_audit.session_id`
  → `VARCHAR(64)` + column comment, `user_vault_audit_operation_check` replaced to add
  `quarantine`/`integrity_fail` (only when outdated), `user_vault_secrets.key_version`,
  `user_vault_audit.key_version`, `vault_key_registry.key_id` → `INTEGER` (only while smallint).
- `identity/sql/003_identity_key_version_integer.sql` registered in identity migrations
  (`user_identities.key_version` → INTEGER when smallint).
- Tests: rewrote `tests/unit/vault/test_vault_view.py` (metadata-only list/detail, no value in any
  body, 409 for integrity/format errors, POST metadata body, colon keys, 400/500 without leaking
  the value, 503 for unavailable/failed load); `test_integration.py` (keyring forwarded, app
  keyring wiring); `test_migrations.py` (002 registered, guarded changes); identity migration
  tests updated to 3 files.
- Real PostgreSQL validation (dev DB, one transaction rolled back, scratch schema
  `feat099_scratch` — the `auth` schema was not touched): 001 tables → old CHECK rejects
  `quarantine` → 002+003 applied twice without error → columns INTEGER / VARCHAR(64),
  constraint includes new operations, inserts with 64-char session id, new operations and
  key_version 65535 succeed, column comment set; schema absent after rollback.
- Results: vault + identity suites 233 passed; full navigator-auth suite 32 failed / 1342 passed
  with no failures beyond the dev baseline. `ruff`: only the 2 pre-existing warnings in
  `tests/unit/vault/test_migrations.py`.

**Deviations from spec**:
- Migration file named `002_vault_crypto_hardening.sql` (covers audit sid, operation CHECK and
  key version widening, not only the session id).
- Also widened `auth.user_identities.key_version` (identity migration 003) for consistency with
  `IdentityTarget`.
- `GET /{key}` decrypts server-side (value discarded) to detect integrity failures for the 409.
- The "no DB pool" configuration error also returns `503 vault_unavailable` (was 500).
