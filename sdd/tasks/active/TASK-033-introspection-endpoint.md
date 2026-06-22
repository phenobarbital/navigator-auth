# TASK-033: Token Introspection endpoint (RFC 7662)

**Feature**: oauth2-introspection-device-grant (FEAT-094)
**Spec**: `sdd/specs/oauth2-introspection-device-grant.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none *(FEAT-093 must be merged — external prerequisite)*
**Assigned-to**: unassigned

---

## Context

Implements spec §3 Module 2 — the standalone `POST /oauth2/introspect` (RFC 7662). A thin read
path (brainstorm shortcut D-1) over FEAT-093's `decode_token` + `AccessTokenStorage` /
`RefreshTokenStorage`. **Independent of the device tasks at the file level for the model/storage**,
but shares `backend.py`/`conf.py` with TASK-034/035/036 — schedule first (smaller, read-only,
low risk) per the spec Worktree Strategy.

---

## Scope

- Register `POST /oauth2/introspect` in `Oauth2Provider.configure()` (+ exclude-list).
- Authenticate the caller as a **confidential client** (D1: `client_id` + `client_secret`,
  reusing FEAT-093's secret check). `401 invalid_client` (`WWW-Authenticate`) on bad creds;
  `400 invalid_request` on missing/duplicate `token`.
- Decode the presented token via `IdentityProvider.decode_token`; branch by `token_type_hint`
  then fallback. Access token ⇒ real-time `AccessTokenStorage.is_revoked(jti)` (no cache).
  Refresh token ⇒ `RefreshTokenStorage.get_token` (rotated/revoked ⇒ inactive).
- Enforce **same-client-only**: caller `client_uid` must equal the token's `client_id`; else
  `{"active": false}`.
- Return RFC 7662 claims for active tokens (`scope`, `client_id`=`client_uid`, `username`,
  `token_type`, `exp`, `iat`, `sub`, `aud`); `200 {"active": false}` for anything
  invalid/expired/revoked/foreign (D5: strict — no ABAC scopes,
  `OAUTH_INTROSPECT_INCLUDE_ABAC_SCOPES=False`).
- Add config key `OAUTH_INTROSPECT_INCLUDE_ABAC_SCOPES` (default `False`) to `conf.py`.
- Write unit tests.

**NOT in scope**: device flow, `/oauth2/revoke` (FEAT-093 owns it), any token *minting*.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `introspect` handler + route + exclude-list |
| `navigator_auth/conf.py` | MODIFY | `OAUTH_INTROSPECT_INCLUDE_ABAC_SCOPES` |
| `tests/test_oauth2_introspection.py` | CREATE | Unit tests |

---

## Implementation Notes

### Key Constraints
- RFC 7662 §4 privacy: never differentiate *why* a token is inactive — identical
  `{"active": false}` for expired / revoked / unknown / foreign-client.
- Revocation truth is **real-time** (no TTL cache) — this endpoint is the authority.
- `hmac.compare_digest` / constant-time secret comparison; never log the raw token.
- Reuse existing `get_payload`, `auth_error`, and the confidential-client check from FEAT-093.

### References in Codebase
- `navigator_auth/backends/oauth2/backend.py` — `configure()`, `token_request` (confidential
  check), `get_payload`, `auth_error`.
- `navigator_auth/backends/idp/__init__.py` — `decode_token`.
- `navigator_auth/backends/oauth2/code_backend.py` — `AccessTokenStorage`, `RefreshTokenStorage`.

---

## Acceptance Criteria

- [ ] `POST /oauth2/introspect` requires confidential-client auth; `400`/`401` per spec.
- [ ] Active access **and** refresh tokens (own client) ⇒ `active:true` + RFC 7662 claims.
- [ ] Revoked `jti` / rotated refresh / foreign client / expired ⇒ `{"active": false}`.
- [ ] No ABAC scopes leaked (flag default `False`); no secrets logged.
- [ ] Tests pass: `pytest tests/test_oauth2_introspection.py -v`.

---

## Test Specification

```python
# tests/test_oauth2_introspection.py — maps to spec §4:
#   test_introspect_active_access_token, test_introspect_revoked_jti_inactive,
#   test_introspect_refresh_token, test_introspect_foreign_client_inactive,
#   test_introspect_requires_client_auth
```

---

## Agent Instructions

When you pick up this task:
1. **Read the spec** at the path above.
2. **Check dependencies** — FEAT-093 storages + confidential-client check present.
3. **Update status** in `tasks/.index.json` → `"in-progress"`.
4. **Implement** per scope.
5. **Verify** acceptance criteria.
6. **Move** this file to `tasks/completed/TASK-033-introspection-endpoint.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:
**Deviations from spec**: none | describe if any
