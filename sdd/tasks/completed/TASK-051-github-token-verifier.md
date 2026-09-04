# TASK-051: GitHub `verify_external_token` (app-token check + verified e-mail)

**Feature**: FEAT-096 external-token-exchange
**Spec**: `sdd/specs/external-token-exchange.spec.md` (Module 6)
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-048
**Assigned-to**: unassigned

---

## Context

GitHub tokens are opaque; the only way to prove a token belongs to **our**
OAuth app is GitHub's "check a token" endpoint, authenticated with the app's
client credentials. `GithubAuth.check_credentials` is a stub today.

**Parallelizable**: after TASK-048, touches only `backends/github.py` and its
test; runs alongside TASK-049 and TASK-050.

---

## Scope

- Implement `GithubAuth.verify_external_token(token, token_type, id_token=None)`
  (`id_token` ignored; GitHub has none):
  1. `POST https://api.github.com/applications/{GITHUB_CLIENT_ID}/token` with
     `Authorization: Basic base64(GITHUB_CLIENT_ID:GITHUB_CLIENT_SECRET)`,
     `Accept: application/vnd.github+json`, body `{"access_token": token}`.
     `200` → token is valid **and** belongs to our app; `404` → foreign or
     revoked → `InvalidAuth("wrong_audience")`; `401` → misconfigured client
     credentials → `AuthException` (500-class, logged).
     From the response take `user` (profile), `scopes`, `expires_at` (GitHub
     Apps user-to-server tokens; `None` for classic OAuth tokens).
  2. If `user.email` is empty, call `get_github_email` but accept **only** a
     `primary and verified` entry (tighten the existing fallback, which returns
     the first e-mail); otherwise `InvalidAuth("email_unverified")`.
  3. `provider_user_id = str(user.id)`.
  4. Return `(userinfo, TokenResponse(access_token=token, expires_at, scopes, provider_user_id))`.
- Replace the stub `check_credentials` with verifier → `build_user_info` →
  `validate_user_info` → JSON session info.
- Unit tests with a mocked `token_request`/HTTP client.

**NOT in scope**: the exchange backend, session creation, Azure/Google, GitHub
App refresh tokens (not presented in an exchange).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/github.py` | MODIFY | `verify_external_token`; tighten e-mail rule; real `check_credentials` |
| `tests/test_github_token_verifier.py` | CREATE | 200 / 404 / 401 / no verified e-mail |

---

## Implementation Notes

### Key Constraints
- Use `ExternalAuth.request()`/`post()` helpers; do not add an HTTP library.
- Do **not** change `get_github_email` behaviour for the login callback path;
  add a `verified_only: bool = False` parameter and pass `True` from the verifier.
- Never log the token or client secret.

### References in Codebase
- `navigator_auth/backends/github.py:63` — `get_github_email`.
- `navigator_auth/backends/external.py:734` — `request()` helper.
- GitHub REST: "Check a token" `POST /applications/{client_id}/token`.

---

## Acceptance Criteria

- [ ] 200 from the check endpoint → userinfo + `TokenResponse` (`expires_at` `None` for classic tokens)
- [ ] 404 → `InvalidAuth("wrong_audience")`; 401 → `AuthException`
- [ ] Missing verified primary e-mail → `InvalidAuth("email_unverified")`
- [ ] `check_credentials` no longer returns `True` unconditionally
- [ ] `pytest tests/test_github_token_verifier.py -v` passes; `ruff check` clean

---

## Test Specification

```python
# tests/test_github_token_verifier.py
# test_verify_app_token_ok_classic (no expires_at)
# test_verify_app_token_ok_github_app (expires_at set)
# test_verify_foreign_token_404
# test_verify_bad_client_credentials_401
# test_requires_verified_primary_email
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
- `GithubAuth.verify_external_token` -> `_check_app_token`: POSTs
  `/applications/{GITHUB_CLIENT_ID}/token` with our own client
  credentials as Basic auth (via `self.post`), confirming the caller's
  token both is valid and belongs to this app. `provider_user_id =
  str(user.id)`; `expires_at` from the GitHub-Apps-only `expires_at`
  field (`None` for classic OAuth tokens); `scopes` from the response.
- **Deviation-with-reason**: `ExternalAuth.request()` collapses every
  non-200 response into a generic `AuthException` whose message is the
  stringified response body, discarding the actual HTTP status code —
  so 404 ("foreign/revoked token") and 401 ("our own client credentials
  are wrong") can't be told apart by status. GitHub's "check a token"
  endpoint has two stable, documented response bodies for exactly these
  two cases (`"Not Found"` / `"Bad credentials"`), so `_check_app_token`
  branches on that substring instead: 404-equivalent ->
  `InvalidAuth("wrong_audience")`; 401-equivalent -> a fresh 500-class
  `AuthException` (misconfigured client credentials, logged at `error`).
  Still uses only `ExternalAuth.post()`/`request()` — no new HTTP
  library — per the task's constraint.
- Tightened `get_github_email`: new `verified_only: bool = False` param;
  `True` (used by the verifier) restricts the result to a
  `primary and verified` entry with no fallback; the default (login
  callback, unchanged) still falls back to the first listed e-mail.
  `user.email` empty -> `get_github_email(token, verified_only=True)` ->
  `InvalidAuth("email_unverified")` when none found.
- Replaced the `check_credentials` stub (`return True`) with verifier ->
  `build_user_info` -> `validate_user_info` -> JSON session info
  (mirrors `AzureAuth`'s non-redirect branch); added a matching
  `get_auth` header/query extractor (GitHub had none). Reused the
  string-`reason` `auth_error` workaround from TASK-049/050.
- `tests/test_github_token_verifier.py` (9 tests, all passing): classic
  vs GitHub-App token check shape, the 404/401 branches, the tightened
  verified-only e-mail path (plus a direct regression proving the
  default/login-callback fallback is unchanged), and two
  `check_credentials` tests proving it no longer returns `True`
  unconditionally.
- `pytest tests/test_github_token_verifier.py -v`: 9 passed. No
  pre-existing `GithubAuth`-specific tests found to regress-check.
  `ruff check navigator_auth/backends/github.py
  tests/test_github_token_verifier.py`: clean.

**Deviations from spec**: `_check_app_token` distinguishes 404 vs 401 by
response-body substring rather than HTTP status code, because
`ExternalAuth.request()` (which the task requires reusing) does not
preserve the status code on error — documented above. Functionally
equivalent to a status-code check against GitHub's real, stable API
responses.
