# TASK-037: Integration tests, docs, and example server

**Feature**: oauth2-introspection-device-grant (FEAT-094)
**Spec**: `sdd/specs/oauth2-introspection-device-grant.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-032, TASK-033, TASK-034, TASK-035, TASK-036
**Assigned-to**: unassigned

---

## Context

Implements spec §3 Module 6 — end-to-end integration coverage, documentation, and example-server
updates for both new surfaces. Depends on all prior FEAT-094 tasks.

---

## Scope

- Add integration tests (spec §4):
  - `test_full_device_flow` — device_authorization → login+consent at `/oauth2/device` → poll →
    owner-bound access (+refresh on `offline_access`) → introspect=active.
  - `test_device_user_id_survives` — owner-binding regression (issued `user_id` is the approving
    user, persists across refresh rotation).
  - `test_introspect_reflects_revocation` — revoke (FEAT-093 `/oauth2/revoke`) ⇒ introspect
    immediately `{"active": false}`.
  - `test_device_then_revoke_grant_cascade` — DELETE grant ⇒ device refresh chain + access `jti`
    revoked ⇒ introspect inactive.
- Update `documentation/oauth.md` for `/introspect` and the device grant (endpoints, params,
  error codes, PKCE requirement, lockout behavior).
- Update `examples/oauth2_server.py` to register a public device client + a confidential
  introspection client and demonstrate both flows.

**NOT in scope**: implementing the endpoints/storage (TASK-032–036).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/test_oauth2_introspection_device_integration.py` | CREATE | Integration tests |
| `documentation/oauth.md` | MODIFY | Document introspection + device grant |
| `examples/oauth2_server.py` | MODIFY | Demo both flows |

---

## Implementation Notes

### Key Constraints
- Reuse FEAT-093 conftest fixtures (storages factory, owner-bound token helpers) +
  `memory_oauth_storages` / `public_device_client` / `confidential_introspect_client` (spec §4).
- The owner-binding regression (`test_device_user_id_survives`) is the correctness gate.

### References in Codebase
- `tests/` — FEAT-093 OAuth2 test suite + conftest.
- `examples/oauth2_server.py` — existing example server.
- `documentation/oauth.md` — existing OAuth docs.

---

## Acceptance Criteria

- [ ] All integration tests pass: `pytest tests/ -v`.
- [ ] `documentation/oauth.md` covers both surfaces.
- [ ] `examples/oauth2_server.py` runs both flows end-to-end.
- [ ] Full suite green at the feature boundary.

---

## Test Specification

```python
# tests/test_oauth2_introspection_device_integration.py — maps to spec §4 Integration Tests
```

---

## Agent Instructions

When you pick up this task:
1. **Read the spec** at the path above.
2. **Check dependencies** — TASK-032–036 in `tasks/completed/`.
3. **Update status** in `tasks/.index.json` → `"in-progress"`.
4. **Implement** per scope.
5. **Verify** acceptance criteria.
6. **Move** this file to `tasks/completed/TASK-037-tests-docs-example.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:
**Deviations from spec**: none | describe if any
