# TASK-029: IdP `audience` + resource-server bearer backend

**Feature**: Production-grade 3LO (Three-Legged OAuth2)
**Spec**: `sdd/specs/oauth2-3lo-implementation.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-024, TASK-027
**Assigned-to**: unassigned

---

## Context

Implements **Module 7** of FEAT-093. Adds the `aud` claim plumbing and extends the
resource-server bearer path to surface scopes/client_id and enforce per-request `jti`
revocation. Prerequisite for the scope↔ABAC composition. See spec §3 M7, source §11.1,
Resolved Decisions **D2/D3**.

---

## Scope

- `IdentityProvider.create_token`: add a backward-compatible `audience: str = None` kwarg —
  when provided, set `payload['aud']`; when omitted, behavior is unchanged (no `aud`). Keep
  the 4-tuple return. OAuth2 callers pass `audience='user'` (3LO) / `'app'` (2LO).
- `APIKeyAuth` (resource server, `backends/api.py`): after decoding the JWT, copy into
  `userinfo`: `scopes = payload.get('scope','').split()`,
  `client_id = payload.get('client_id')` (the public `client_uid`),
  `token_type = payload.get('aud','user')`. Call `ctx.set('scopes', ...)` and
  `ctx.set('client_id', ...)`.
- Per-request `jti` revocation check: consult `AccessTokenStorage.is_revoked(jti)` via an
  in-process TTL cache (`OAUTH_REVOCATION_CACHE_TTL`, default 30s); 401 if revoked. Cache is
  evicted on `/revoke` and per-app revoke (coordinate with TASK-027 revoke paths).

**NOT in scope**: `@scope_required`/`Policy.scopes`/cache-key fix (TASK-030).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/idp/__init__.py` | MODIFY | Additive `audience` kwarg on `create_token` |
| `navigator_auth/backends/api.py` | MODIFY | Populate `userinfo[scopes/client_id/token_type]`; per-request jti check |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | Pass `audience` on token mint (`'user'`/`'app'`) |
| `tests/test_resource_server_bearer.py` | CREATE | aud back-compat, scope propagation, jti revocation 401 |

---

## Implementation Notes

### Key Constraints
- `create_token` strips `aud` from `data` (`idp:282`) — the new kwarg is the only way to set
  it; existing callers (no kwarg) keep current behavior (D2).
- Propagate `aud`, do **not** enforce `aud` verification in `decode_token`.
- `userinfo['client_id']` is the public `client_uid` string (distinct from FEAT-092 tenant
  client_id int).

### References in Codebase
- `navigator_auth/backends/idp/__init__.py:272-304` — `create_token`.
- `navigator_auth/backends/api.py:83-96,166-246` — `get_token_info`, `check_credentials`,
  `auth_middleware`.
- `navigator_auth/abac/context.py` — `EvalContext.set`.

---

## Acceptance Criteria

- [ ] `create_token` without `audience` ⇒ no `aud` (existing behavior preserved).
- [ ] Resource-server `userinfo` carries `scopes`, `client_id`(uid), `token_type`.
- [ ] Revoked `jti` ⇒ 401 on a resource-server request; revocation effective within the cache TTL.
- [ ] Tests pass: `pytest tests/test_resource_server_bearer.py -v`.

---

## Test Specification

```python
# tests/test_resource_server_bearer.py
class TestBearer:
    def test_audience_kwarg_backcompat(self, idp): ...
    async def test_scope_propagation(self, ...): ...
    async def test_jti_revocation_check(self, ...): ...
```

---

## Agent Instructions

1. Read the spec (§3 M7, D2/D3). 2. Verify TASK-024 + TASK-027 completed. 3. Index → `in-progress`.
4. Implement. 5. Verify. 6. Move to `completed/`. 7. Index → `done` + Completion Note.

---

## Completion Note

**Completed by**: sdd-worker (claude-sonnet-4-6)
**Date**: 2026-06-22
**Notes**:
- idp/__init__.py: create_token gets additive audience kwarg (default None); when provided
  sets payload['aud']; existing callers unchanged. 4-tuple return preserved.
- backends/api.py: get_token_info bearer branch now injects scopes/client_id/token_type
  into the payload; per-request jti revocation via AccessTokenStorage.is_revoked().
- backend.py already passes audience='user' (3LO) and audience='app' (2LO) since TASK-024.
- tests/test_resource_server_bearer.py: 21 tests, all passing.
**Deviations from spec**: None; audience kwarg on backend.py was implemented in TASK-024
as that commit rewrote backend.py.
