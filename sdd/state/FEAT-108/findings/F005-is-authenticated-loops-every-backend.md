---
id: F005
query_id: Q012
type: read
intent: "Read is_authenticated / user_session decorators around decorators.py:217."
executed_at: 2026-11-11T14:39:00Z
duration_ms: 500
parent_id: null
depth: 0
merged_from: [FC-005, FW-003]
---

# F005 — is_authenticated tries every configured backend, catches only AuthException, and accepts any truthy result

## Summary

When the request is not yet `authenticated`, `@is_authenticated()` walks
`auth.backends` in config order calling `backend.authenticate(request)`. It skips
backends that raise `AuthException`, return falsy, or return a `StreamResponse`
(external IdP redirect — the Azure/ADFS "Redirect URL" log lines are these calls).
Any OTHER exception (e.g. the `TypeError` from `APIKeyAuth`, FC-006) escapes as a
500, and the FIRST truthy result is accepted as authentication without checking
`is_authenticated`, user identity, or mechanism — so NoAuth's anonymous dict
(FC-007) passes. With the FC-003 order (Azure, APIKey, Token, TrocToken, ADFS,
Oauth2Provider, Basic, NoAuth), a bearer request crashes in APIKeyAuth before
Oauth2Provider.authenticate is reached; a credential-less one ends in NoAuth.
`@user_session()` then injects whatever session/user the request carries.

*(merged from FW-003)* Wiki `sym:navigator_auth/decorators.py#is_authenticated` (score 1.00) and
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
  lines: 207-237
  symbol: `is_authenticated._func_wrapper._wrap`
  excerpt: |
    if _is_path_excluded(request) or getattr(request, "allow_anonymous", False):
        return await handler(*args, **kwargs)
    if request.get("authenticated", False):
        return await handler(*args, **kwargs)
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
        if userdata:
            return await handler(*args, **kwargs)
        else:
            raise web.HTTPUnauthorized(

- path: `navigator_auth/decorators.py`
  lines: 261
  symbol: `is_authenticated._method_wrapper`
  excerpt: |
    result = await backend.authenticate(request)

- path: `navigator_auth/decorators.py`
  lines: 117-148
  symbol: `user_session._func_wrapper._wrap`
  excerpt: |
    session = await get_session(request, new=False)
    try:
        user = session.decode("user")
    ...
    return await handler(*args, session=session, user=user, **kwargs)

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

*From FC-005:*
The method-wrapper variant (line 261) has the same loop, so class-based views share
the defect. `Oauth2Provider.authenticate` (backend.py:2833-2882) is a correct
resource-server check (raises InvalidAuth when no bound session) — it just never
runs first.

*From FW-003:*
- Same "iterate every backend, continue on a narrow exception tuple" pattern exists in
  `AuthHandler.api_login` (auth.py:484-491) per saved wiki lesson `mem-b8bff584423d` (FW-007).
- The StreamResponse skip explains the Azure/ADFS "Redirect URL" log lines on /api/v1/me:
  external backends are invoked by this loop and answer with an IdP redirect.
- `tests/unit/test_is_authenticated_exclude.py` covers the exclude-list / `allow_anonymous`
  short-circuits, not the backend loop's exception handling.
- [cross-lane: type=read, intent=Why is request["authenticated"] False for a valid 3LO bearer — does auth.py _auth_middleware fail to resolve the session-less token (FW-001)?]

[citation-check: stale] navigator_auth/decorators.py:217 — anchor `result = await backend.authenticate(request)` matches 2 lines (217, 261); both are cited (function and method wrappers) — consistent, not unique.
