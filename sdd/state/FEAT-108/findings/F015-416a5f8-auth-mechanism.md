---
id: F015
query_id: Q030
type: git_log
intent: "Recent commits on the OAuth2 provider (regression window) — follow-up on 416a5f8."
executed_at: 2026-11-11T14:41:30Z
duration_ms: 400
parent_id: FG-001
depth: 1
merged_from: [FG-004]
---

# F015 — 416a5f8: per-request authentication mechanism (csrf scoping)

## Summary

416a5f8 (2026-10-08, Jesus Lara) makes every auth middleware record the credential that authenticated
the request under `request[AUTH_MECHANISM_KEY]` and limits `csrf_middleware` to cookie sessions.
In `api.py` the API-key path sets `AUTH_MECHANISM_APIKEY`; in `Oauth2Provider.authenticate` the call
became `self._set_user_request(request, user, mechanism=AUTH_MECHANISM_BEARER)`. It is the latest
commit that touches both `api.py` and the OAuth2 backend; it does not change token decoding,
session binding or the decorator fallback.

## Citations

- commit: `416a5f8` — 2026-10-08 23:35 +0200 — Jesus Lara
  message: "fix(csrf): scope the check by authentication mechanism, not by Authorization header"
  files: |
    CHANGELOG.md, navigator_auth/auth.py, navigator_auth/backends/abstract.py, navigator_auth/backends/api.py,
    navigator_auth/backends/django.py, navigator_auth/backends/oauth2/backend.py, navigator_auth/backends/token.py,
    navigator_auth/backends/troc.py, navigator_auth/conf.py, navigator_auth/middlewares/csrf.py,
    tests/test_csrf_middleware.py (203+, 14-)

- path: `navigator_auth/backends/api.py`
  symbol: `APIKeyAuth.auth_middleware`
  excerpt: |
    request.user = await self.get_session_user(session)
    request["authenticated"] = True
    request[AUTH_MECHANISM_KEY] = AUTH_MECHANISM_APIKEY

- path: `navigator_auth/backends/oauth2/backend.py`
  symbol: `Oauth2Provider.authenticate`
  excerpt: |
    request["userdata"] = payload
    request["authenticated"] = True
    self._set_user_request(request, user, mechanism=AUTH_MECHANISM_BEARER)

## Notes

*From FG-004:*
- The 500 trace passes through `csrf_middleware` (csrf.py:81) before reaching the decorator; csrf is not
  the failing frame.
