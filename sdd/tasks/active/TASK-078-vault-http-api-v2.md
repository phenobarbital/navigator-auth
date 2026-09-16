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
- `navigator_auth/vault/sql/002_vault_audit_sid_hmac.sql` + `vault/migrations.py`: document that
  `auth.user_vault_audit.session_id` holds `naming_hmac(session_uuid)` (column comment; widen to
  `VARCHAR(64)` if narrower) — idempotent migration.
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

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
