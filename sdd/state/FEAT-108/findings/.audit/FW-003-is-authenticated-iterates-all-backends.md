---
id: FW-003
query_id: Q003
type: wiki_query
intent: "Orient: is_authenticated decorator and how it iterates backends."
executed_at: 2026-11-11T14:39:00Z
duration_ms: 800
parent_id: null
depth: 0
---

# FW-003 — `@is_authenticated()` calls `authenticate()` on every enabled backend, catching only `AuthException`

## Summary

Wiki `sym:navigator_auth/decorators.py#is_authenticated` (score 1.00) and
`#is_authenticated._func_wrapper` (L197-242). When `request["authenticated"]` is not set
(i.e. the middleware chain did not authenticate the request), the decorator loops over
`auth.backends` and awaits `backend.authenticate(request)` on each, in order. Only
`AuthException` is caught (`continue`); any other exception (e.g. the `TypeError` from
`APIKeyAuth.authenticate`) escapes as a 500 — this is the `decorators.py:217` frame in the
traceback. The first truthy, non-`StreamResponse` result is accepted as authentication,
so a backend that always returns truthy userdata (NoAuth, see FW-004) makes the decorator
pass for anonymous callers.

## Citations

- path: `navigator_auth/decorators.py`
  lines: 179-285
  symbol: `is_authenticated`
  wiki: `sym:navigator_auth/decorators.py#is_authenticated` (score 1.00)

- path: `navigator_auth/decorators.py`
  lines: 197-242
  symbol: `is_authenticated._func_wrapper`
  wiki: `sym:navigator_auth/decorators.py#is_authenticated._func_wrapper` (score 0.11)
  excerpt: |
    if request.get("authenticated", False):
        return await handler(*args, **kwargs)
    else:
        ...
        for _, backend in auth.backends.items():
            try:
                result = await backend.authenticate(request)
            except AuthException:
                continue
            if not result:
                continue
            if isinstance(result, web.StreamResponse):
                continue
            userdata = result
            break

## Notes

- Same "iterate every backend, continue on a narrow exception tuple" pattern exists in
  `AuthHandler.api_login` (auth.py:484-491) per saved wiki lesson `mem-b8bff584423d` (FW-007).
- The StreamResponse skip explains the Azure/ADFS "Redirect URL" log lines on /api/v1/me:
  external backends are invoked by this loop and answer with an IdP redirect.
- `tests/unit/test_is_authenticated_exclude.py` covers the exclude-list / `allow_anonymous`
  short-circuits, not the backend loop's exception handling.
- [cross-lane: type=read, intent=Why is request["authenticated"] False for a valid 3LO bearer — does auth.py _auth_middleware fail to resolve the session-less token (FW-001)?]
