---
id: F007
query_id: Q015
type: read
intent: "Read NoAuth backend: does it authenticate every request as anonymous?"
executed_at: 2026-11-11T14:40:30Z
duration_ms: 400
parent_id: null
depth: 0
merged_from: [FC-007, FW-004]
---

# F007 — NoAuth.authenticate always succeeds with an anonymous user and a new session

## Summary

`NoAuth.authenticate` unconditionally builds an anonymous user (`Anonymous <key>`,
group `guest`), mints a token, `remember`s a new session and returns a truthy dict.
Since `@is_authenticated()` accepts the first truthy result (FC-005), any request
with no credentials reaching the decorator loop is "authenticated" as anonymous when
NoAuth is configured — exactly the reported 200 "Hello Anonymous …" with a fresh
session_id. NoAuth is last in the local `settings/settings.py` list (FC-003); it is
not in the backend list the example intends to run.

*(merged from FW-004)* `NoAuth.authenticate` (wiki `sym:navigator_auth/backends/noauth.py#NoAuth.authenticate`,
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
  excerpt: |
    userdata, key = self.get_userdata()
    user = await self.create_user(userdata[AUTH_SESSION_OBJECT])
    user.id = key
    user.add_group(Guest)
    user.set(self.username_attribute, f"Anonymous {key}")
    ...
    await self.remember(request, key, userdata, user)
    return {
        "token": token,

- path: `navigator_auth/backends/noauth.py`
  lines: 30-32
  symbol: `NoAuth.check_credentials`
  excerpt: |
    async def check_credentials(self, request):
        return True

- path: `navigator_auth/backends/__init__.py`
  lines: 1-40
  symbol: module exports (`NoAuth`, `TrocToken`, `TokenAuth`, `APIKeyAuth`, `ADFSAuth`, `AzureAuth`, `Oauth2Provider`, ...)
  wiki: `file:navigator_auth/backends/__init__.py` (score 0.55)

## Notes

*From FC-007:*
Whether `is_authenticated` should ever accept an anonymous (is_authenticated=False)
result is a library-level design question, not only an example issue: any app with
NoAuth enabled gets this behaviour on every `@is_authenticated()` route that is
exempted from the middleware.

*From FW-004:*
- Spawned FW-005 (depth 1): the examples that do pass `backends=`.
- [cross-lane: type=grep, intent=Confirm navigator_auth/conf.py ends with `from settings.settings import *` and that the repo's settings/settings.py enables NoAuth, TrocToken, APIKeyAuth, Azure, ADFS and a short AUTH_SECRET_KEY / issuer 'Mobileinsight']

*Merge redirects:*
- `navigator_auth/backends/noauth.py` :: `NoAuth.authenticate` — duplicate from FW-004, collapsed into the first citation.
- `navigator_auth/auth.py` :: `AuthHandler.get_backends` — canonical citation lives in F004 (from FW-004).
- `navigator_auth/auth.py` :: `AuthHandler.__init__` — canonical citation lives in F003 (from FW-004).
