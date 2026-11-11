---
id: FW-006
query_id: Q005
type: wiki_query
intent: "Orient: OAuth2 grants listing and userinfo handlers."
executed_at: 2026-11-11T14:40:30Z
duration_ms: 800
parent_id: null
depth: 0
---

# FW-006 — userinfo degrades to empty claims on unknown user; grants API depends on `request["userdata"]` from the auth middleware

## Summary

`Oauth2Provider.userinfo` (L2194-2252) decodes the bearer itself (not via the middleware),
sets `sub` from `user_id`, and loads profile/email via `self._idp.user_from_id`; on failure
it logs `userinfo: could not load user ...` and every `_claim()` falls back to `""` —
exactly the reported `{"sub":"35","username":"","given_name":"",...}`.
`Oauth2Provider.list_grants` (L2311-2330) returns 401 "Not authenticated." when
`_get_request_user_id` finds nothing. `_get_request_user_id` (L2801-2827) reads
`request["userdata"]["user_id"]` (published by the auth middleware from decoded claims),
then `request["userinfo"]`, then the request user object. A 401 therefore means the
middleware did not publish `userdata` for this bearer request.

## Citations

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 2194-2252
  symbol: `Oauth2Provider.userinfo`
  wiki: `sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.userinfo` (score 0.00 in Q001; page read)
  excerpt: |
    user_id = payload.get("user_id", "")
    claims = {"sub": str(user_id)}
    user = None
    if user_id and ("profile" in scopes or "email" in scopes):
        try:
            user = await self._idp.user_from_id(user_id)
        except Exception as e:  # noqa: BLE001
            self.logger.warning(f"userinfo: could not load user {user_id}: {e}")

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 2311-2330
  symbol: `Oauth2Provider.list_grants`
  wiki: `sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.list_grants` (score 0.06)
  excerpt: |
    user_id = self._get_request_user_id(request)
    if not user_id:
        return self._error_response("unauthorized", "Not authenticated.", status=401)

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 2801-2827
  symbol: `Oauth2Provider._get_request_user_id`
  wiki: `sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._get_request_user_id` (score 0.03)
  excerpt: |
    for source in (request.get("userdata"), request.get("userinfo")):
        if isinstance(source, dict):
            uid = source.get("user_id")
    ...
    user = request.get(self.user_property) or getattr(request, "user", None)

## Notes

- `/oauth2/userinfo` returning 200 with empty strings for an unresolvable user is a
  spec-conformance question (OIDC: omit unknown claims rather than send ""); the handler
  itself works — the root input is the unresolvable user_id 35.
- The report's log excerpt shows no `userinfo: could not load user` line; the user may have
  trimmed it, or another path served the call — not verifiable from the wiki.
- [cross-lane: type=read, intent=In auth.py _auth_middleware, when does a decoded bearer get published as request["userdata"]; is that skipped when the token has no session_id claim?]
