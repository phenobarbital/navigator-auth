# TASK-027: P3 — Grants, consent-skip, revocation, jti tracking, per-app revoke

**Feature**: Production-grade 3LO (Three-Legged OAuth2)
**Spec**: `sdd/specs/oauth2-3lo-implementation.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-024, TASK-026
**Assigned-to**: unassigned

---

## Context

Implements **Module 5** of FEAT-093. Adds durable consent records, consent-skip, RFC 7009
revocation, `jti` access-token tracking, and the per-app revocation surface. See spec §3 M5,
source §3.3/§3.4/§5.7/§7, Resolved Decision **D4**.

---

## Scope

- `oauth2/models.py`: `OauthGrant` (consent record) and `OauthAccessTokenRecord` (jti).
- Storages: `GrantStorage` ABC + memory/redis/pg; `AccessTokenStorage` ABC + memory/redis/pg;
  both via the factory honoring `OAUTH2_CLIENT_STORAGE`.
- DDL: `auth.oauth_grants` (UNIQUE `(user_id, client_id)`) and `auth.oauth_access_tokens`
  (FK `client_id INTEGER` → PK).
- `consent`: upsert `OauthGrant(user_id, client_id=client_uid, scopes)`.
- `authorize`: **skip consent** when an unrevoked grant covers `granted` scopes and the
  client did not send `prompt=consent`.
- Token mint: inject `jti=str(uuid4())` into the `data` passed to `create_token`; persist an
  `OauthAccessTokenRecord`.
- `POST /oauth2/revoke` (RFC 7009): accept `token` + `token_type_hint`; revoke the refresh
  chain and/or access `jti`; **always return 200**.
- `GET /api/v1/oauth2/grants`: list the current user's authorized apps + scopes.
- `DELETE /api/v1/oauth2/grants/{client_id}`: revoke the grant **and** cascade — revoke all
  live refresh tokens for `(user_id, client_id)` and the access `jti`s.

**NOT in scope**: per-request jti revocation check / resource-server backend (TASK-029);
userinfo/logout (TASK-028); `audience` kwarg (TASK-029).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/models.py` | MODIFY | `OauthGrant`, `OauthAccessTokenRecord` |
| `navigator_auth/backends/oauth2/code_backend.py` | MODIFY | `GrantStorage` + `AccessTokenStorage` (memory/redis/pg) |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | Consent upsert + skip; jti mint; /revoke; grants API |
| `navigator_auth/backends/oauth2/ddl.sql` | MODIFY | `auth.oauth_grants`, `auth.oauth_access_tokens` |
| `tests/test_oauth2_grants_revoke.py` | CREATE | Consent-skip, revoke 200, per-app cascade |

---

## Implementation Notes

### Key Constraints
- Grant/record `client_id` is the public `client_uid` string; table FKs use the integer PK.
- `jti` passes through `create_token` via `**data` (not stripped) — no IdP change here.
- RFC 7009: `/revoke` returns 200 regardless of token validity.

### References in Codebase
- `navigator_auth/backends/oauth2/client_backend.py` — ABC + factory pattern to mirror.
- `navigator_auth/backends/idp/__init__.py:272-304` — `create_token` (jti via data).

---

## Acceptance Criteria

- [ ] Unrevoked grant covering scopes skips consent (absent `prompt=consent`).
- [ ] `jti` minted + persisted per access token.
- [ ] `/oauth2/revoke` returns 200 and revokes the chain/jti.
- [ ] `DELETE /api/v1/oauth2/grants/{client_id}` revokes grant + cascades to tokens.
- [ ] Tests pass: `pytest tests/test_oauth2_grants_revoke.py -v`.

---

## Test Specification

```python
# tests/test_oauth2_grants_revoke.py
class TestGrantsRevoke:
    async def test_consent_skip(self, ...): ...
    async def test_revoke_endpoint_200(self, ...): ...
    async def test_per_app_revoke_cascade(self, ...): ...
```

---

## Agent Instructions

1. Read the spec (§3 M5, D4). 2. Verify TASK-024 + TASK-026 completed. 3. Index → `in-progress`.
4. Implement. 5. Verify. 6. Move to `completed/`. 7. Index → `done` + Completion Note.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:
**Deviations from spec**: none
