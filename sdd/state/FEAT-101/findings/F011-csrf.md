# F011 — CSRF middleware applies to cookie-session POSTs
- citations: navigator_auth/middlewares/csrf.py `_is_cookie_only_session` (authenticated and no Authorization header), `csrf_middleware` rejects UNSAFE_METHODS without valid CSRF_HEADER_NAME header when ENABLE_CSRF_PROTECTION; recent commit 5df3e94.
- digest: New. register/options, register/verify and P2 DELETE/PATCH, when called from the browser with only the session cookie, must send the CSRF header. Brainstorm does not mention CSRF; JS snippets must include it. login/options and /api/v1/login are unauthenticated so unaffected.
- confidence: high
