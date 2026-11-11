---
id: FW-004
query_id: Q004
type: wiki_query
intent: "Orient: NoAuth anonymous backend and AUTHENTICATION_BACKENDS loading."
executed_at: 2026-11-11T14:39:30Z
duration_ms: 900
parent_id: null
depth: 0
---

# FW-004 — NoAuth always authenticates as an anonymous guest; AuthHandler takes an explicit `backends=` list meant for examples

## Summary

`NoAuth.authenticate` (wiki `sym:navigator_auth/backends/noauth.py#NoAuth.authenticate`,
score 0.74) creates an anonymous user, mints a token, remembers a session and returns a
truthy dict — for any request. Combined with FW-003 this yields the reported
"200 Hello Anonymous ..." instead of 401. `AuthHandler.get_backends` imports every dotted
path in `self._backend_list`. `AuthHandler.__init__` accepts `backends=` (overrides
`AUTHENTICATION_BACKENDS`) and `authz_backends=`; its docstring says to use them "when the
enabled backends are a property of the application itself (the bundled examples do) and
must not depend on the `settings.settings` module that `navigator_auth.conf` imports last",
and to pass `authz_backends=[]` because inherited `allow_hosts`/`allowed_ips` authorize
requests without authentication.

## Citations

- path: `navigator_auth/backends/noauth.py`
  lines: 54-82
  symbol: `NoAuth.authenticate`
  wiki: `sym:navigator_auth/backends/noauth.py#NoAuth.authenticate` (score 0.74)
  excerpt: |
    async def authenticate(self, request):
        userdata, key = self.get_userdata()
        user = await self.create_user(userdata[AUTH_SESSION_OBJECT])
        ...
        await self.remember(request, key, userdata, user)
        return {"token": token, ..., self.username_attribute: f"Anonymous {key}", ...}

- path: `navigator_auth/auth.py`
  lines: 241-254
  symbol: `AuthHandler.get_backends`
  wiki: `sym:navigator_auth/auth.py#AuthHandler.get_backends` (score 1.00)

- path: `navigator_auth/auth.py`
  lines: 95-172
  symbol: `AuthHandler.__init__`
  wiki: `sym:navigator_auth/auth.py#AuthHandler.__init__` (score 0.47)
  excerpt: |
    backends: explicit list of dotted paths to the authentication
        backends to enable, overriding ``AUTHENTICATION_BACKENDS``.
        Use it when the enabled backends are a property of the
        application itself (the bundled examples do) and must not
        depend on the ``settings.settings`` module that
        ``navigator_auth.conf`` imports last.
    authz_backends: ... Pass an empty list to require authentication for every request

- path: `navigator_auth/backends/__init__.py`
  lines: 1-40
  symbol: module exports (`NoAuth`, `TrocToken`, `TokenAuth`, `APIKeyAuth`, `ADFSAuth`, `AzureAuth`, `Oauth2Provider`, ...)
  wiki: `file:navigator_auth/backends/__init__.py` (score 0.55)

## Notes

- Spawned FW-005 (depth 1): the examples that do pass `backends=`.
- [cross-lane: type=grep, intent=Confirm navigator_auth/conf.py ends with `from settings.settings import *` and that the repo's settings/settings.py enables NoAuth, TrocToken, APIKeyAuth, Azure, ADFS and a short AUTH_SECRET_KEY / issuer 'Mobileinsight']
