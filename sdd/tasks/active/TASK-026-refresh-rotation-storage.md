# TASK-026: P2 — Refresh hardening + durable storage

**Feature**: Production-grade 3LO (Three-Legged OAuth2)
**Spec**: `sdd/specs/oauth2-3lo-implementation.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-024
**Assigned-to**: unassigned

---

## Context

Implements **Module 4** of FEAT-093. Hardens refresh tokens (rotation, reuse detection,
absolute lifetime) and adds durable, multi-tier storage. See spec §3 M4, §6 refresh policy,
Resolved Decision **D4**.

---

## Scope

- `oauth2/models.py`: add `parent_token: Optional[str]` and `absolute_expires_at: datetime`
  to `OauthRefreshToken`.
- Rotation/reuse as a pure state-machine helper: on refresh use, mint new access + refresh,
  set new `parent_token`, copy `absolute_expires_at`, mark old `revoked(reason=rotated)`.
  **Reuse detection**: presenting an already-`rotated` token ⇒ `revoke_chain` + `invalid_grant`.
- Sliding expiry (`expires_at`) bounded by `absolute_expires_at`; past absolute ⇒
  `invalid_grant`. Refresh issued **only if** `offline_access` granted; scope **narrowing**
  only (never widening).
- Storage: define `RefreshTokenStorage` ABC additions (`revoke_token`, `revoke_chain`,
  `list_tokens`) + **memory/redis/postgres** implementations, selected by a factory honoring
  `OAUTH2_CLIENT_STORAGE`.
- DDL: `auth.oauth_refresh_tokens` (FK `client_id INTEGER` → `auth.clients(client_id)` PK).
- Config: `OAUTH_REFRESH_TOKEN_TTL`, `OAUTH_REFRESH_ABSOLUTE_TTL`, `OAUTH_REFRESH_ROTATION`;
  replace hardcoded `timedelta(days=30/365)`.

**NOT in scope**: grants/consent-skip/jti/revoke endpoint (TASK-027); access-token store
(TASK-027).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/models.py` | MODIFY | `parent_token`, `absolute_expires_at` |
| `navigator_auth/backends/oauth2/code_backend.py` | MODIFY | RefreshTokenStorage ABC + memory/redis/pg + factory; rotation helpers |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | Rotation + reuse + absolute-expiry + offline_access gate |
| `navigator_auth/backends/oauth2/ddl.sql` | MODIFY | `auth.oauth_refresh_tokens` |
| `navigator_auth/conf.py` | MODIFY | Refresh TTL/rotation config |
| `tests/test_oauth2_refresh.py` | CREATE | Rotation, reuse→chain, absolute expiry, offline_access |

---

## Implementation Notes

### Key Constraints
- Rotation/reuse logic must be pure-function-testable without external storage.
- FK references the integer PK (`client_pk`), not the public `client_uid` (D7).
- Memory tier required for tests (`OAUTH2_CLIENT_STORAGE=memory`).

### References in Codebase
- `navigator_auth/backends/oauth2/code_backend.py:66-105` — existing Redis-only RefreshTokenStorage.
- `navigator_auth/backends/oauth2/client_backend.py` — `ClientStorage` factory pattern to mirror.

---

## Acceptance Criteria

- [ ] New refresh issued on use; old marked `revoked(reason=rotated)`.
- [ ] Replay of a rotated token ⇒ entire chain revoked + `invalid_grant`.
- [ ] Past `absolute_expires_at` ⇒ `invalid_grant`. No `offline_access` ⇒ no refresh token.
- [ ] Memory/redis/postgres storages selectable via `OAUTH2_CLIENT_STORAGE`; DDL added.
- [ ] Tests pass: `pytest tests/test_oauth2_refresh.py -v`.

---

## Test Specification

```python
# tests/test_oauth2_refresh.py
class TestRefresh:
    async def test_rotation(self, ...): ...
    async def test_reuse_revokes_chain(self, ...): ...
    async def test_absolute_expiry(self, ...): ...
    async def test_no_offline_access_no_refresh(self, ...): ...
```

---

## Agent Instructions

1. Read the spec (§3 M4, §6, D4). 2. Verify TASK-024 completed. 3. Index → `in-progress`.
4. Implement. 5. Verify. 6. Move to `completed/`. 7. Index → `done` + Completion Note.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:
**Deviations from spec**: none
