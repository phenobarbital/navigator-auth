---
id: FC-005
query_id: Q012
type: read
intent: "Read is_authenticated / user_session decorators around decorators.py:217."
executed_at: 2026-11-11T14:39:00Z
duration_ms: 500
parent_id: null
depth: 0
---

# FC-005 — is_authenticated tries every configured backend, catches only AuthException, and accepts any truthy result

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

## Notes

The method-wrapper variant (line 261) has the same loop, so class-based views share
the defect. `Oauth2Provider.authenticate` (backend.py:2833-2882) is a correct
resource-server check (raises InvalidAuth when no bound session) — it just never
runs first.
