# TASK-049: Azure `verify_external_token` (audience-bound) + fix `check_credentials`

**Feature**: FEAT-096 external-token-exchange
**Spec**: `sdd/specs/external-token-exchange.spec.md` (Module 4)
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-048
**Assigned-to**: unassigned

---

## Context

`AzureAuth.check_credentials` (`backends/azure.py:392`) accepts any bearer that
Graph `/me` answers for, regardless of which application minted it. This task
implements the verifier contract for Azure and makes the existing endpoint use
it, closing that gap.

**Parallelizable**: after TASK-048 lands, this touches only `backends/azure.py`
and its test; it can run in a worktree alongside TASK-050 and TASK-051.

---

## Scope

- Implement `AzureAuth.verify_external_token(token, token_type, id_token)`:
  1. If `id_token` is given: `_verify_jwt(id_token, audience=AZURE_ADFS_CLIENT_ID,
     issuer=[f"https://login.microsoftonline.com/{TENANT}/v2.0",
     f"https://sts.windows.net/{TENANT}/"], tenant_id=AZURE_ADFS_TENANT_ID)`.
     `expires_at` from its `exp`. `provider_user_id` = `oid` claim (fallback `sub`).
  2. Else the access token must be a JWT: verify signature/`exp` and require
     `aud ∈ {AZURE_ADFS_CLIENT_ID, "https://graph.microsoft.com",
     "00000003-0000-0000-c000-000000000000"}` **and**
     `appid` or `azp == AZURE_ADFS_CLIENT_ID`. Document this as the weaker path
     (Graph tokens are not meant for third-party validation; a signature failure
     on a Graph-audience token is tolerated only if `appid` matches **and**
     Graph `/me` returns 200 — log at `warning`).
  3. Call Graph `/me` with the access token (existing `self.get(...)`) for the
     profile; merge `client_info` handling as `auth_callback` does.
  4. Return `(userinfo, TokenResponse(access_token, id_token=id_token,
     expires_at, provider_user_id, scopes from `scp`))`.
- Refactor `check_credentials` to call `verify_external_token` before
  `build_user_info`/`validate_user_info`; behaviour otherwise unchanged
  (redirect/JSON branches stay).
- Unit tests with mocked JWKS and mocked Graph.

**NOT in scope**: the exchange backend, session creation, Google/GitHub.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/azure.py` | MODIFY | `verify_external_token`; `check_credentials` delegates |
| `tests/test_azure_token_verifier.py` | CREATE | ok / wrong aud / wrong appid / expired / regression |

---

## Implementation Notes

### Key Constraints
- Use the helpers from TASK-048; do not re-implement JWT decoding.
- Never log tokens. Log `kid`, `aud`, `appid`, reason code.
- `AZURE_ADFS_TENANT_ID` may be `common`/`organizations`; then accept issuer
  from the token's `tid` claim (`https://login.microsoftonline.com/{tid}/v2.0`).
- Keep `check_credentials` response shapes identical (existing callers/tests).

### References in Codebase
- `navigator_auth/backends/azure.py:392` — `check_credentials`.
- `navigator_auth/backends/azure.py:227` — `auth_callback` client_info merge.
- `navigator_auth/backends/jwksutils.py` — tenant discovery helpers.

---

## Acceptance Criteria

- [ ] Valid id_token for our client id → userinfo + `TokenResponse` with `provider_user_id`, `expires_at`, `id_token`
- [ ] id_token with another `aud` → `InvalidAuth("wrong_audience")`
- [ ] Access-token-only path rejects tokens whose `appid/azp` ≠ our client id
- [ ] Expired token → `InvalidAuth("expired")`
- [ ] `check_credentials` now rejects a Graph token from another app (regression test)
- [ ] `pytest tests/test_azure_token_verifier.py -v` passes; `ruff check` clean

---

## Test Specification

```python
# tests/test_azure_token_verifier.py
# reuse rsa_keypair/jwks fixtures pattern from tests/test_external_verify_helpers.py
# mock AzureAuth.get (Graph /me) with a canned profile
# test_verify_id_token_ok
# test_verify_id_token_wrong_aud
# test_verify_access_token_requires_appid
# test_verify_expired
# test_check_credentials_audience_bound_regression
```

---

## Agent Instructions

1. **Read the spec**; 2. **Check dependencies** (TASK-048 completed);
3. **Update index** → in-progress; 4. **Implement**; 5. **Verify**;
6. **Move to completed/**; 7. **Update index** → done; 8. **Fill Completion Note**.

---

## Completion Note

**Completed by**: sdd-worker
**Date**: 2026-09-04
**Notes**:
- `AzureAuth.verify_external_token`: id_token path fully verified via
  `_verify_jwt` (signature, `aud == AZURE_ADFS_CLIENT_ID`, `iss` from
  `_accepted_id_token_issuers`, which handles the `common`/`organizations`/
  `consumers` multi-tenant alias by reading the token's own `tid` claim).
  Access-token-only path (`_verify_access_token`) requires `aud` in
  `{AZURE_ADFS_CLIENT_ID, "https://graph.microsoft.com",
  "00000003-0000-0000-c000-000000000000"}` and `appid`/`azp` ==
  `AZURE_ADFS_CLIENT_ID`; a subsequent signature-verification failure is
  tolerated (logged `warning`) since Graph-audience tokens aren't meant
  for third-party signature validation and the Graph `/me` call right
  after acts as the liveness check. `provider_user_id` = `oid` (fallback
  `sub`); `expires_at` from `exp`.
- `check_credentials` now calls `verify_external_token` before
  `build_user_info`/`validate_user_info`; redirect/JSON response shapes
  are byte-for-byte unchanged, only the new 401 branch is added.
- Found and worked around (without touching `backends/abstract.py`) a
  pre-existing bug in `BaseAuthBackend.auth_error()`: a dict `reason`
  with the default `application/json` content type raises `KeyError`
  (the dict branch never populates `args["reason"]`, which the trailing
  `if content_type == "application/json"` block unconditionally reads).
  The new 401 branch passes a plain string reason instead, sidestepping
  it; the existing dict-reason call sites elsewhere in `check_credentials`
  are pre-existing and out of scope.
- `tests/test_azure_token_verifier.py` (6 tests, all passing): id_token
  ok / wrong-`aud`, access-token `appid` enforcement (reject + accept),
  expiry, and the `check_credentials` audience-bound regression (a Graph
  token with a foreign `appid` — previously accepted unconditionally —
  now gets 401). Mocks both steps of Azure/ADFS discovery (`.well-known`
  → `jwks_uri` → JWKS) and `AzureAuth.get` (Graph `/me`); no real network
  calls. Also ignores a second pre-existing, unrelated
  `DeprecationWarning` surfaced by the same `auth_error` bug
  (`aiohttp.web.HTTPUnauthorized(body=...)` is deprecated) since this
  project's pytest config turns warnings into errors.
- `pytest tests/test_azure_token_verifier.py -v`: 6 passed. Regression:
  `tests/test_oauth2_upstream_idp.py` (Azure-adjacent, still green).
  `ruff check navigator_auth/backends/azure.py
  tests/test_azure_token_verifier.py`: clean.

**Deviations from spec**: None functionally. The 401 error path in
`check_credentials` uses a string `reason` instead of the file's usual
dict `reason` to avoid triggering the pre-existing `auth_error` bug
described above.
