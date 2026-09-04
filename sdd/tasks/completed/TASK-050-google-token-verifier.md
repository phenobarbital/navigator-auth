# TASK-050: Google `verify_external_token` (id_token JWKS / tokeninfo `azp`)

**Feature**: FEAT-096 external-token-exchange
**Spec**: `sdd/specs/external-token-exchange.spec.md` (Module 5)
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-048
**Assigned-to**: unassigned

---

## Context

`GoogleAuth.check_credentials` is a stub. Google clients typically hold an OIDC
id_token (signed JWT, `aud` = our client id) and/or an opaque access token.
This task implements the verifier for both shapes, requiring a verified e-mail.

**Parallelizable**: after TASK-048, touches only `backends/google.py` and its
test; runs alongside TASK-049 and TASK-051.

---

## Scope

- Implement `GoogleAuth.verify_external_token(token, token_type, id_token)`:
  1. If `id_token` given (or `token` itself parses as a JWT and no `id_token`):
     `_verify_jwt(jwt, audience=GOOGLE_CLIENT_ID,
     issuer=["accounts.google.com", "https://accounts.google.com"],
     jwks_url="https://www.googleapis.com/oauth2/v3/certs")`.
     Require `email_verified` (via `_require_verified_email`). Claims are the
     userinfo (`sub`, `email`, `given_name`, `family_name`, `name`, `picture`).
  2. If an opaque access token is provided: GET
     `https://oauth2.googleapis.com/tokeninfo?access_token=<token>`; require
     `aud == GOOGLE_CLIENT_ID` or `azp == GOOGLE_CLIENT_ID`; `expires_in` from
     the response. Then GET `self.userinfo_uri` with the bearer for the profile;
     require `email_verified`.
  3. `provider_user_id = sub`; `scopes` from tokeninfo `scope` (if any);
     `expires_at` from id_token `exp` or tokeninfo `expires_in`.
  4. Return `(userinfo, TokenResponse(access_token=token or id_token,
     id_token=id_token, ...))`.
- Replace the stub `check_credentials` with: verifier → `build_user_info` →
  `validate_user_info` → JSON session info (mirror Azure's non-redirect branch).
- Unit tests with mocked JWKS, mocked `tokeninfo` and mocked userinfo.

**NOT in scope**: the exchange backend, session creation, Azure/GitHub.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/google.py` | MODIFY | `verify_external_token`; real `check_credentials` |
| `tests/test_google_token_verifier.py` | CREATE | id_token ok / unverified email / azp mismatch / expired |

---

## Implementation Notes

### Key Constraints
- Use TASK-048 helpers; JWKS URL is static for Google (no OIDC discovery needed).
- Map with `GOOGLE_MAPPING` (`id` ← `sub`); do not change the mapping dict.
- Never log tokens; log `sub`, `aud`/`azp`, reason code.
- `tokeninfo` returns 400 for invalid/expired tokens → `InvalidAuth("expired")`
  or `("invalid_token")`.

### References in Codebase
- `navigator_auth/backends/google.py:21` — `GOOGLE_MAPPING`.
- `navigator_auth/backends/external.py:726` — `get()` helper for HTTP.
- `navigator_auth/backends/azure.py:392` — `check_credentials` non-redirect branch to mirror.

---

## Acceptance Criteria

- [ ] Valid id_token for our client id with `email_verified=true` → userinfo + `TokenResponse`
- [ ] `email_verified=false` → `InvalidAuth("email_unverified")`
- [ ] Wrong `aud` on id_token, or `azp` mismatch on tokeninfo → `InvalidAuth("wrong_audience")`
- [ ] Expired id_token / 400 tokeninfo → `InvalidAuth("expired")`
- [ ] `check_credentials` no longer returns `True` unconditionally
- [ ] `pytest tests/test_google_token_verifier.py -v` passes; `ruff check` clean

---

## Test Specification

```python
# tests/test_google_token_verifier.py
# test_verify_id_token_ok
# test_verify_id_token_email_unverified
# test_verify_id_token_wrong_aud
# test_verify_access_token_tokeninfo_azp_ok
# test_verify_access_token_tokeninfo_azp_mismatch
# test_verify_expired
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
- `GoogleAuth.verify_external_token`: prefers an id_token (given
  explicitly, or when `token` itself has the 3-part JWT shape and no
  separate id_token was supplied — id-token-only clients), verified
  against Google's static JWKS (`https://www.googleapis.com/oauth2/v3/certs`,
  no OIDC discovery), `aud == GOOGLE_CLIENT_ID`, `iss ∈
  {accounts.google.com, https://accounts.google.com}`, requiring
  `email_verified`. Otherwise treats `token` as an opaque access token:
  `tokeninfo` must report `aud` or `azp == GOOGLE_CLIENT_ID`, then the
  OIDC userinfo endpoint supplies the (verified-e-mail) profile.
  `provider_user_id = sub`; `scopes` from tokeninfo `scope`; `expires_at`
  from id_token `exp` or tokeninfo `expires_in`.
- Replaced the `check_credentials` stub (`return True`) with verifier ->
  `build_user_info` -> `validate_user_info` -> JSON session info,
  mirroring `AzureAuth`'s non-redirect branch; added a `get_auth`
  header/query token extractor (Google had none) to match.
- Reused the string-`reason` `auth_error` workaround documented in
  TASK-049 (pre-existing dict-reason bug in
  `BaseAuthBackend.auth_error`, out of scope here too).
- `tests/test_google_token_verifier.py` (11 tests, all passing):
  id_token ok / unverified-e-mail / wrong-`aud` / expired, a bare
  JWT-shaped `token` treated as an id_token, tokeninfo `azp` ok/mismatch,
  userinfo unverified e-mail, a 400 tokeninfo response mapped to
  `InvalidAuth("expired")`, and two `check_credentials` regression tests
  proving it no longer returns `True` unconditionally.
- `pytest tests/test_google_token_verifier.py -v`: 11 passed.
  `ruff check navigator_auth/backends/google.py
  tests/test_google_token_verifier.py`: clean.

**Deviations from spec**: None functionally; same string-`reason`
`auth_error` workaround as TASK-049 (Azure), for the same pre-existing
reason.
