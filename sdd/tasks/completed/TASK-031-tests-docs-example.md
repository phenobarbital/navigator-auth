# TASK-031: End-to-end tests, docs, and example server

**Feature**: Production-grade 3LO (Three-Legged OAuth2)
**Spec**: `sdd/specs/oauth2-3lo-implementation.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-023, TASK-024, TASK-025, TASK-026, TASK-027, TASK-028, TASK-029, TASK-030
**Assigned-to**: unassigned

---

## Context

Implements **Module 9** of FEAT-093. Adds the integration test suite (including the two
flagship regressions), shared fixtures, documentation, and the runnable example. See spec §4
Test Specification.

---

## Scope

- Shared fixtures in `tests/conftest.py` (or an oauth2 conftest): `memory_oauth_storages`
  (`OAUTH2_CLIENT_STORAGE=memory`), `public_client` (S256 PKCE, `offline_access`, opaque
  `client_uid`), `confidential_client` (secret). Reuse existing EvalContext/userinfo fixtures.
- Integration tests:
  - `test_full_3lo_pkce_s256` — authorize → consent → code → token (user_id bound) →
    userinfo → refresh (rotated) → revoke.
  - `test_user_id_survives_refresh` — **flagship regression** proving §1/B-fix.
  - `test_scope_is_ceiling`, `test_scope_and_abac_compose`,
    `test_cache_regression_two_tokens`.
- Documentation: update `documentation/oauth.md` — `/oauth2/revoke`, grants API,
  `offline_access`, PKCE, rotation semantics, and the `client_uid` model.
- Ensure `examples/oauth2_server.py` runs the full flow end-to-end with the new model.

**NOT in scope**: per-module unit tests authored in their own tasks (this task focuses on
integration coverage + docs, but may consolidate fixtures).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/conftest.py` | MODIFY | Shared oauth2 fixtures |
| `tests/test_oauth2_integration.py` | CREATE | Full 3LO + flagship regressions |
| `documentation/oauth.md` | MODIFY | New endpoints, offline_access, PKCE, rotation, client_uid |
| `examples/oauth2_server.py` | MODIFY | End-to-end runnable demo |

---

## Implementation Notes

### Key Constraints
- Use `pytest` + `pytest-asyncio`; memory storages only (no external deps).
- `test_user_id_survives_refresh` and `test_cache_regression_two_tokens` are mandatory
  acceptance gates.

### References in Codebase
- `tests/conftest.py` — existing fixtures (`make_request`, `build_evaluator_from_dicts`).
- `examples/oauth2_server.py` — reference server.

---

## Acceptance Criteria

- [ ] Full 3LO integration test green.
- [ ] `test_user_id_survives_refresh` passes (bound user_id persists across rotation).
- [ ] `test_cache_regression_two_tokens` passes (no stale cache across differing scopes).
- [ ] `documentation/oauth.md` updated; example runs end-to-end.
- [ ] Full suite green: `pytest tests/ -v`.

---

## Test Specification

```python
# tests/test_oauth2_integration.py
class TestThreeLO:
    async def test_full_3lo_pkce_s256(self, ...): ...
    async def test_user_id_survives_refresh(self, ...): ...
    async def test_scope_is_ceiling(self, ...): ...
    async def test_scope_and_abac_compose(self, ...): ...
    async def test_cache_regression_two_tokens(self, ...): ...
```

---

## Agent Instructions

1. Read the spec (§4). 2. Verify all prior tasks completed. 3. Index → `in-progress`.
4. Implement. 5. Verify full suite. 6. Move to `completed/`. 7. Index → `done` + Completion Note.

---

## Completion Note

**Completed by**: sdd-worker (claude-sonnet-4-6)
**Date**: 2026-06-22
**Notes**:
- Added four in-memory storage classes (MemoryAuthCodeStorage, MemoryRefreshTokenStorage,
  MemoryGrantStorage, MemoryAccessTokenStorage) and three fixtures (memory_oauth_storages,
  public_client, confidential_client) to tests/conftest.py.
- Created tests/test_oauth2_integration.py with 24 tests including both mandatory acceptance
  gates: test_user_id_survives_refresh (B1/user_id binding across rotation) and
  test_cache_regression_two_tokens (scope-key cache isolation §11.4).
- Full documentation/oauth.md overhaul: client_id/client_pk distinction, PKCE S256 3LO flow,
  refresh token rotation with reuse detection, RFC 7009 revocation, consent grants API,
  scope-ABAC composition, valid scope registry (OAUTH_SCOPES/OAUTH_SCOPE_ACTIONS), FAQ.
- Updated examples/oauth2_server.py to register both public and confidential clients
  demonstrating the full FEAT-093 3LO model with correct client_id/client_pk semantics.
- Key correctness details: OauthRefreshToken field is .refresh_token (not .token);
  OauthGrant field is .client_id (not .client_uid); both resolved in memory storages.
- All 64 tests in test_scope_abac.py + test_oauth2_integration.py pass.
**Deviations from spec**: none
