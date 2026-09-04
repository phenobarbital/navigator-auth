# TASK-052: `TokenExchangeAuth` backend, config and login wiring

**Feature**: FEAT-096 external-token-exchange
**Spec**: `sdd/specs/external-token-exchange.spec.md` (Module 7, decisions D1–D10)
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-046, TASK-047, TASK-048, TASK-049, TASK-050, TASK-051
**Assigned-to**: unassigned

---

## Context

The integration point: a new backend reachable through
`X-Auth-Method: TokenExchange` on `POST /api/v1/login`. It verifies the
provider token through the provider backend, resolves an **existing** user,
vaults the credential, and opens a Basic session with `auth_origin` and a
capped lifetime.

**Not parallelizable**: depends on every prior FEAT-096 task.

---

## Scope

- `navigator_auth/backends/exchange.py`: `TokenExchangeAuth(BasicAuth)` with
  `_service_name = "token_exchange"`, `_description`, `_external_auth = False`.
  - `get_payload(request) -> ExchangeRequest` (dataclass `provider`, `token`,
    `token_type="Bearer"`, `id_token=None`). JSON body only. Missing
    `provider`/`token` → `AuthException(status=400)`. `provider` must be in
    `TOKEN_EXCHANGE_PROVIDERS` and resolve to a loaded backend
    (`request.app["auth"].backends`, matched by `_service_name`) else 400.
  - `authenticate(request)`:
    1. `userinfo, ext = await provider_backend.verify_external_token(...)`;
       `NotImplementedError` → 400; `InvalidAuth` → 401 (log reason code).
    2. `email = _require_verified_email(userinfo)` (provider verifiers already
       enforce this; keep as belt-and-braces).
    3. `user_id = await IdentityStore.find_user_by_provider_account(provider, ext.provider_user_id)`;
       if found → `user = idp.get_user_by_id(user_id)` (add to IdP if absent; or
       `get_user(username)` via the identity row's `user_id|username` FK).
       Else `user = idp.get_user(email)`. `UserNotFound` → 401 `user_not_found`.
       **Never** call `create_external_user`, regardless of `AUTH_MISSING_ACCOUNT` (D4).
    4. Best-effort `IdentityStore.save_linked_identity(user_id, provider, ext, userinfo)`
       (warning on failure; login continues) (D3, D7, D10).
    5. `cap = self._cap_expiration(ext)`:
       `min(SESSION_TIMEOUT, int((ext.expires_at - now).total_seconds()))` if
       `expires_at` else `TOKEN_EXCHANGE_MAX_TTL`; `cap < 60` → 401 `expired` (D2, D6).
    6. `return await self.open_session(request, user, extra={
       "auth_method": "basic", "auth_origin": provider,
       "external_expires_at": iso_or_none, "provider_user_id": ext.provider_user_id},
       expiration=cap)` (D1, D5, D8, D9).
  - Audit log line at `info` on success (`provider`, `user_id`, `cap`) and at
    `warning` on failure (`provider`, `provider_user_id` if known, reason code).
    HTTP bodies stay generic ("Invalid Credentials").
- `conf.py`: `TOKEN_EXCHANGE_MAX_TTL = config.getint(..., fallback=SESSION_TIMEOUT)`,
  `TOKEN_EXCHANGE_PROVIDERS = ["azure","google","github"]` (list/CSV via config).
- Export the backend from `navigator_auth/backends/__init__.py` following the
  existing export/registration convention so `AUTH_BACKENDS` can list it and
  `X-Auth-Method: TokenExchange` resolves.
- Unit tests (mocked provider backends, store, idp) covering every branch.

**NOT in scope**: docs, end-to-end integration tests (TASK-053), provider code.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/exchange.py` | CREATE | `TokenExchangeAuth`, `ExchangeRequest`, `_cap_expiration` |
| `navigator_auth/conf.py` | MODIFY | `TOKEN_EXCHANGE_MAX_TTL`, `TOKEN_EXCHANGE_PROVIDERS` |
| `navigator_auth/backends/__init__.py` | MODIFY | Export/registration |
| `tests/test_token_exchange_backend.py` | CREATE | Unit tests |

---

## Implementation Notes

### Pattern to Follow
`BasicAuth.authenticate` (post TASK-046) for the wrapper shape;
`ExternalAuth._vault_upstream_token` for best-effort vaulting;
`AuthHandler.get_auth_backend` (`auth.py:331`) for how the header maps to
`self.backends[...]` — confirm the registered key name and document it in the
completion note.

### Key Constraints
- Do not touch `api_login`; it already loads the session, registers the refresh
  token and loads the vault.
- No password handling anywhere in this backend; `validate_user` is not used.
- `AUTH_MISSING_ACCOUNT` must have **no** effect here (explicit test).
- Backend is a singleton: no per-request state on `self`.
- The provider backend may not be loaded in a deployment → 400, not 500.

### References in Codebase
- `navigator_auth/auth.py:331` — `get_auth_backend`; `:457` `api_login`.
- `navigator_auth/backends/external.py:410` — `_vault_upstream_token`.
- `navigator_auth/backends/idp/__init__.py:145` — `get_user`.

---

## Acceptance Criteria

- [ ] Malformed payload / unknown or unloaded provider → 400
- [ ] Verifier `InvalidAuth` → 401; body does not reveal the reason; reason logged
- [ ] Linked identity wins over e-mail match; unknown user → 401 and **no** user created
      even with `AUTH_MISSING_ACCOUNT="create"`
- [ ] Session + JWT carry `auth_method="basic"`, `auth_origin`, at top level and in
      `AUTH_SESSION_OBJECT`; response shape equals Basic login + `auth_origin`,
      `external_expires_at`
- [ ] JWT `exp` ≤ external `expires_at`; no expiry → `TOKEN_EXCHANGE_MAX_TTL`;
      `< 60 s` → 401; `session.max_age == cap`
- [ ] Vault row written (access/refresh/id_token); Redis session contains no raw token;
      vault failure does not fail login
- [ ] Basic callbacks fire; re-exchange without refresh token preserves the vaulted one
- [ ] `pytest tests/test_token_exchange_backend.py -v` passes; `ruff check` clean

---

## Test Specification

```python
# tests/test_token_exchange_backend.py
# fixtures: fake provider backend exposing verify_external_token; fake IdentityStore;
#           mocked IdentityProvider (get_user, create_token real); make_request from conftest
# test_payload_validation_400
# test_unsupported_provider_400
# test_verifier_invalid_auth_401
# test_linked_identity_precedence
# test_user_must_exist_even_with_create_policy
# test_session_claims_both_levels_and_jwt
# test_expiration_cap_with_expires_at / _fallback_max_ttl / _too_short_401
# test_session_max_age_matches_cap
# test_vaults_credential_not_session
# test_vault_failure_non_fatal
# test_fires_basic_callbacks
# test_reexchange_preserves_refresh_token
```

---

## Agent Instructions

1. **Read the spec**; 2. **Check dependencies** (TASK-046..051 completed);
3. **Update index** → in-progress; 4. **Implement**; 5. **Verify**;
6. **Move to completed/**; 7. **Update index** → done; 8. **Fill Completion Note**.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**:
**Date**:
**Notes**:

**Deviations from spec**:
