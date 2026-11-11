---
id: FC-007
query_id: Q015
type: read
intent: "Read NoAuth backend: does it authenticate every request as anonymous?"
executed_at: 2026-11-11T14:40:30Z
duration_ms: 400
parent_id: null
depth: 0
---

# FC-007 — NoAuth.authenticate always succeeds with an anonymous user and a new session

## Summary

`NoAuth.authenticate` unconditionally builds an anonymous user (`Anonymous <key>`,
group `guest`), mints a token, `remember`s a new session and returns a truthy dict.
Since `@is_authenticated()` accepts the first truthy result (FC-005), any request
with no credentials reaching the decorator loop is "authenticated" as anonymous when
NoAuth is configured — exactly the reported 200 "Hello Anonymous …" with a fresh
session_id. NoAuth is last in the local `settings/settings.py` list (FC-003); it is
not in the backend list the example intends to run.

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

## Notes

Whether `is_authenticated` should ever accept an anonymous (is_authenticated=False)
result is a library-level design question, not only an example issue: any app with
NoAuth enabled gets this behaviour on every `@is_authenticated()` route that is
exempted from the middleware.
