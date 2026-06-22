# TASK-034: Device authorization request endpoint (RFC 8628 §3.1–§3.2)

**Feature**: oauth2-introspection-device-grant (FEAT-094)
**Spec**: `sdd/specs/oauth2-introspection-device-grant.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-032
**Assigned-to**: unassigned

---

## Context

Implements spec §3 Module 3 — `POST /oauth2/device_authorization`, the first half of the device
grant. Issues `device_code`/`user_code` and persists a pending `OauthDeviceCode` (from TASK-032).
Shares `backend.py`/`conf.py` with TASK-033/035/036, so runs sequentially in the feature worktree.

---

## Scope

- Register `POST /oauth2/device_authorization` in `Oauth2Provider.configure()` (+ exclude-list).
- Validate `client_id` (resolve `client_uid`); filter requested `scope` to the client allow-list
  (`invalid_scope` on unknown).
- Generate `device_code` (`secrets.token_urlsafe`) + `user_code` (TASK-032 helper, regenerate on
  collision).
- **PKCE (D4):** capture `code_challenge` / `code_challenge_method`; for **public** clients require
  PKCE **S256** (reject missing or `plain`, per FEAT-093 `OAUTH_REQUIRE_PKCE_PUBLIC`).
- Persist a `pending` `OauthDeviceCode` via `DeviceCodeStorage` (TTL `OAUTH_DEVICE_CODE_TTL`).
- Return the RFC 8628 payload: `device_code`, `user_code`, `verification_uri`
  (`OAUTH_DEVICE_VERIFICATION_URI` or derived from request host + `/oauth2/device`),
  `verification_uri_complete` (`?user_code=…`), `expires_in`, `interval`.
- Add config keys: `OAUTH_DEVICE_CODE_TTL`, `OAUTH_DEVICE_POLL_INTERVAL`,
  `OAUTH_DEVICE_VERIFICATION_URI`, `OAUTH_DEVICE_USER_CODE_LENGTH`,
  `OAUTH_DEVICE_USER_CODE_ALPHABET`, `OAUTH_DEVICE_SLOW_DOWN_INCREMENT`.
- Write unit tests.

**NOT in scope**: the verification page (TASK-035), token polling (TASK-036).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `device_authorization` handler + route + exclude-list |
| `navigator_auth/conf.py` | MODIFY | `OAUTH_DEVICE_*` keys |
| `tests/test_device_authorization.py` | CREATE | Unit tests |

---

## Implementation Notes

### Key Constraints
- Reuse FEAT-093 PKCE helper (`oauth2/pkce.py`) for challenge validation; public clients must
  send S256.
- Use the TASK-032 `generate_user_code` + `DeviceCodeStorage`.
- `verification_uri` derivation should reuse `get_domain(request)` style host detection already in
  `backend.py`.

### References in Codebase
- `navigator_auth/backends/oauth2/backend.py` — `configure()`, `authorize` (scope filtering,
  client validation), `get_domain`, `prepare_url`.
- `navigator_auth/backends/oauth2/pkce.py` — FEAT-093 PKCE helper.

---

## Acceptance Criteria

- [ ] `POST /oauth2/device_authorization` returns all RFC 8628 fields incl.
      `verification_uri_complete`.
- [ ] Scope filtered to client allow-list (`invalid_scope` on unknown).
- [ ] Public client without `code_challenge` (or `plain`) ⇒ rejected (D4).
- [ ] Pending `OauthDeviceCode` persisted with correct TTL/interval.
- [ ] Tests pass: `pytest tests/test_device_authorization.py -v`.

---

## Test Specification

```python
# tests/test_device_authorization.py — maps to spec §4:
#   test_device_authorization_response, test_device_invalid_scope, test_device_public_requires_pkce
```

---

## Agent Instructions

When you pick up this task:
1. **Read the spec** at the path above.
2. **Check dependencies** — TASK-032 in `tasks/completed/`.
3. **Update status** in `tasks/.index.json` → `"in-progress"`.
4. **Implement** per scope.
5. **Verify** acceptance criteria.
6. **Move** this file to `tasks/completed/TASK-034-device-authorization-endpoint.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: sdd-worker (claude-sonnet-4-6)
**Date**: 2026-06-22
**Notes**: All 8 unit tests pass. POST /oauth2/device_authorization registered + excluded in configure(). Client validation, scope filtering to allow-list, PKCE S256 enforcement for public clients, device code generation (regenerate on collision), DeviceCodeStorage persist, RFC 8628 payload returned. OAUTH_DEVICE_* config keys in conf.py.
**Deviations from spec**: none
