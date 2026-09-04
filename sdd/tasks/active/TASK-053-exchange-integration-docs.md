# TASK-053: End-to-end exchange tests, docs and version bump

**Feature**: FEAT-096 external-token-exchange
**Spec**: `sdd/specs/external-token-exchange.spec.md` (Module 8, §4 Integration Tests, §5)
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-052
**Assigned-to**: unassigned

---

## Context

Closes FEAT-096: proves the whole path through the real aiohttp app
(`/api/v1/login` → session → protected route → credential endpoint) and
documents the contract for integrators.

**Not parallelizable**: final integration coverage; depends on TASK-052.

---

## Scope

- Integration tests (pattern: `tests/test_basic_auth.py` `live_app` fixture and
  the OAuth2 integration suites):
  - `test_exchange_end_to_end_azure`: mocked JWKS + Graph; `POST /api/v1/login`
    with `X-Auth-Method: TokenExchange` → 200, session cookie set with
    `Max-Age == cap`, Redis key TTL ≈ cap; then
    `GET /api/v1/user/identities/azure/credential` returns the vaulted
    credential including `id_token`.
  - `test_exchange_end_to_end_github`: mocked app-token check; classic token
    (no expiry) → cap = `TOKEN_EXCHANGE_MAX_TTL`.
  - `test_exchange_then_protected_route`: the exchanged session passes the auth
    middleware and a PBAC-protected route exactly like a Basic session
    (compare `request.user` shape and `auth_method`).
  - `test_exchange_unknown_user_401_no_row`: with `AUTH_MISSING_ACCOUNT="create"`.
- Docs:
  - `docs/security.rst` or a new `docs/token_exchange.rst` (link from
    `docs/index.rst`): request contract, claims (`auth_method`, `auth_origin`,
    `external_expires_at`), lifetime cap and `TOKEN_EXCHANGE_MAX_TTL`,
    "user must pre-exist" rule, vault retrieval via the credential endpoint,
    per-provider audience rules (Azure id_token vs access token weaker path,
    Google `azp`, GitHub app-token check).
  - `docs/settings.rst`: the two new settings.
  - `README.md`: add `TokenExchange` to the auth-methods table.
  - `docs/changelog.rst`: FEAT-096 entry.
- Bump `navigator_auth/version.py` to `0.25.0`.

**NOT in scope**: new functionality; fixing provider verifiers (open a
follow-up task if the integration tests expose a defect).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/test_token_exchange_integration.py` | CREATE | End-to-end tests |
| `tests/conftest.py` | MODIFY | Shared `rsa_keypair`, `provider_userinfo`, `existing_user`, `linked_identity` fixtures if not already added |
| `docs/token_exchange.rst` | CREATE | Integrator docs |
| `docs/index.rst`, `docs/settings.rst`, `docs/changelog.rst` | MODIFY | Link, settings, changelog |
| `README.md` | MODIFY | Auth-methods table |
| `navigator_auth/version.py` | MODIFY | `0.25.0` |

---

## Implementation Notes

### Key Constraints
- Tests must not call real provider endpoints; mock at the `ExternalAuth.get`
  / `request` / `jwksutils.get_jwks` boundary.
- If the DB-backed `live_app` fixture is unavailable in CI, mark tests with the
  same skip marker the existing DB-dependent suites use.
- Docs must state plainly that tokens issued to other applications are rejected
  and that the flow never creates users.

### References in Codebase
- `tests/test_basic_auth.py:67` — `live_app` fixture.
- `tests/test_oauth2_integration.py` — integration style.
- `navigator_auth/handlers/user_identities.py:172` — credential endpoint.

---

## Acceptance Criteria

- [ ] All four integration tests pass (or are correctly skip-marked where DB is absent)
- [ ] Every FEAT-096 spec §5 acceptance criterion is checked off in the spec file
- [ ] Docs build (`make -C docs html`) without new warnings
- [ ] `version.py` is `0.25.0`; changelog entry present
- [ ] Full suite: `pytest tests/ -v` green (excluding pre-existing environment failures, listed in the completion note)

---

## Test Specification

```python
# tests/test_token_exchange_integration.py
# test_exchange_end_to_end_azure
# test_exchange_end_to_end_github
# test_exchange_then_protected_route
# test_exchange_unknown_user_401_no_row
```

---

## Agent Instructions

1. **Read the spec**; 2. **Check dependencies** (TASK-052 completed);
3. **Update index** → in-progress; 4. **Implement**; 5. **Verify**;
6. **Move to completed/**; 7. **Update index** → done; 8. **Fill Completion Note**.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**:
**Date**:
**Notes**:

**Deviations from spec**:
