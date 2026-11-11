---
id: FC-004
query_id: Q017
type: read
intent: "Read AuthHandler._auth_middleware and backend loading (auth.py:1040-1075)."
executed_at: 2026-11-11T14:40:00Z
duration_ms: 700
parent_id: null
depth: 0
---

# FC-004 — allow_hosts authz exempts every localhost request; the exempt path needs a bound session and never publishes the claims

## Summary

`AuthHandler.verify_exceptions` returns True when any authorization backend
(`allow_hosts` here, FC-003) authorizes the request — so every request to
`localhost:5000`, including `/api/v1/me` and `/api/v1/oauth2/grants`, takes the
"exception" branch (the traceback's auth.py:1073 is that branch's
`return await handler(request)`). That branch only does a best-effort bearer check
that REQUIRES an existing session (`get_session(request, payload, new=False)`); a
claim-less token (FC-002) resolves none, so the request continues unauthenticated
into the decorators. Even on success this branch sets `request.user` and
`authenticated` but NOT `request["userdata"]` (the main path sets it at 1136/1168),
so `/api/v1/me`'s `token_claims` would be null and handlers reading claims lose them.
The main (non-exempt) path, by contrast, recreates a missing session from the token
(1103) or raises 401.

## Citations

- path: `navigator_auth/auth.py`
  lines: 979-988
  symbol: `AuthHandler.verify_exceptions`
  excerpt: |
    ### Authorization backends:
    for backend in self._authz_backends:
        if await backend.check_authorization(request):
            ...
            self._mark_authz(request, type(backend).__name__)
            return True

- path: `navigator_auth/auth.py`
  lines: 1056-1073
  symbol: `AuthHandler._auth_middleware`
  excerpt: |
    if await self.verify_exceptions(request):
        if hdrs.AUTHORIZATION in request.headers:
            try:
                ...
                    session = await get_session(request, payload, new=False)
                    if session:
                        user = await self.get_session_user(session)
                        if user:
                            request.user = user
                            request["authenticated"] = True
            except Exception:
                pass  # Best-effort
        return await handler(request)

- path: `navigator_auth/auth.py`
  lines: 1101-1104
  symbol: `AuthHandler._auth_middleware`
  excerpt: |
    if not session:
        self.logger.warning("Session Missing or Expired, recreating from Token")
        try:
            session = await get_session(request, payload, new=True)

- path: `navigator_auth/auth.py`
  lines: 1136, 1168
  symbol: `AuthHandler._auth_middleware`
  excerpt: |
    request["userdata"] = payload

- path: `navigator_auth/auth.py`
  lines: 240-252
  symbol: `AuthHandler.get_backends`
  excerpt: |
    for backend in self._backend_list:
        ...
        backends[bkname] = obj(**kwargs)
    return backends

## Notes

`get_backends` preserves the configured order, which is the order the
`is_authenticated` loop walks (FC-005).
