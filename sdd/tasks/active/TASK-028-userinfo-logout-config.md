# TASK-028: P4 — userinfo / logout / config

**Feature**: Production-grade 3LO (Three-Legged OAuth2)
**Spec**: `sdd/specs/oauth2-3lo-implementation.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-024, TASK-027
**Assigned-to**: unassigned

---

## Context

Implements **Module 6** of FEAT-093. Replaces the `userinfo`/`logout`/`finish_logout` stubs
and centralizes configuration. See spec §3 M6, source §5.6/§5.8/§8, Resolved Decisions
**D3/D8**.

---

## Scope

- `userinfo`: decode the bearer token via the IdP; check the `jti` is not revoked; return
  claims allowed by the token's scopes (`sub`/`user_id`, `username`, `email`, `given_name`,
  `family_name`); 401 on invalid/expired/revoked.
- `logout`/`finish_logout`: session teardown + redirect to the existing
  `AUTH_LOGOUT_REDIRECT_URI` (`conf.py:120`).
- Config: add `OAUTH_ACCESS_TOKEN_TTL` (3600), `OAUTH_REVOCATION_CACHE_TTL` (30), and finish
  replacing hardcoded durations (the "2 hours" TODO, `minutes=2`,
  `OAUTH_DEFAULT_TOKEN_EXPIRATION_DAYS`).

**NOT in scope**: the per-request jti revocation cache implementation in the resource-server
backend (TASK-029); scope-gated ABAC (TASK-030).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | Implement userinfo/logout/finish_logout |
| `navigator_auth/conf.py` | MODIFY | `OAUTH_ACCESS_TOKEN_TTL`, `OAUTH_REVOCATION_CACHE_TTL`; replace hardcoded durations |
| `tests/test_oauth2_userinfo_logout.py` | CREATE | Scope-gated claims, 401 cases, logout redirect |

---

## Implementation Notes

### Key Constraints
- `userinfo` claims are limited by the token's scopes.
- `AUTH_LOGOUT_REDIRECT_URI` already exists — do not add a new key (D8).

### References in Codebase
- `navigator_auth/backends/oauth2/backend.py:570-578` — current stubs.
- `navigator_auth/conf.py:120` — `AUTH_LOGOUT_REDIRECT_URI`.
- `navigator_auth/backends/idp/__init__.py:306-339` — `decode_token`.

---

## Acceptance Criteria

- [ ] `userinfo` returns scope-gated claims; 401 on revoked/expired/invalid.
- [ ] `logout`/`finish_logout` tear down session and redirect correctly (no stubs remain).
- [ ] Config keys added; hardcoded durations removed.
- [ ] Tests pass: `pytest tests/test_oauth2_userinfo_logout.py -v`.

---

## Test Specification

```python
# tests/test_oauth2_userinfo_logout.py
class TestUserinfoLogout:
    async def test_userinfo_scope_gated(self, ...): ...
    async def test_userinfo_401_on_revoked(self, ...): ...
    async def test_logout_redirect(self, ...): ...
```

---

## Agent Instructions

1. Read the spec (§3 M6, D3/D8). 2. Verify TASK-024 + TASK-027 completed. 3. Index → `in-progress`.
4. Implement. 5. Verify. 6. Move to `completed/`. 7. Index → `done` + Completion Note.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:
**Deviations from spec**: none
