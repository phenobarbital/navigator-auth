---
id: F008
query_id: Q014
type: grep
intent: "Locate userinfo and grants endpoint handlers in the OAuth2 provider."
executed_at: 2026-11-11T14:41:00Z
duration_ms: 700
parent_id: null
depth: 0
merged_from: [FC-008, FC-009, FW-006]
---

# F008 — GET /api/v1/oauth2/grants returns 401 because neither claims nor a user reach the request

## Summary

The grants list route is `GET /api/v1/oauth2/grants` → `Oauth2Provider.list_grants`
(registered at 351, not in the exclude list). It has no auth of its own: it reads
the user id via `_get_request_user_id`, which looks at `request["userdata"]` /
`request["userinfo"]` and then `request.user`. For a localhost request the auth
middleware takes the allow_hosts exempt branch (FC-004), which never sets
`request["userdata"]` and only sets `request.user` when the token's session exists —
it doesn't (FC-002). So both sources are empty → `401 unauthorized / "Not
authenticated."`. The handler does not call `self.authenticate(request)` itself.

*(merged from FC-009)* `userinfo` decodes the bearer itself (so it returns 200 even though the session is
unbound), sets `sub` from `user_id`, and — because profile/email are not in the
JWT — loads the user with `self._idp.user_from_id(user_id)`. For user 35 that raises
in the demo IdP; the exception is only logged and every `_claim` falls back to the
default `""`, producing `{"sub":"35","username":"","given_name":"","family_name":"","email":""}`.
Returning empty strings rather than omitting unknown claims is itself questionable
(OIDC userinfo omits claims it cannot supply).

*(merged from FW-006)* `Oauth2Provider.userinfo` (L2194-2252) decodes the bearer itself (not via the middleware),
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
  lines: 289, 351
  symbol: `Oauth2Provider.configure`
  excerpt: |
    self.grants_uri: str = "/api/v1/oauth2/grants"
    router.add_route("GET", self.grants_uri, self.list_grants, name="nav_oauth2_grants_list")

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 2311-2315
  symbol: `Oauth2Provider.list_grants`
  excerpt: |
    async def list_grants(self, request):
        """GET /api/v1/oauth2/grants — list current user's authorized apps."""
        user_id = self._get_request_user_id(request)
        if not user_id:
            return self._error_response("unauthorized", "Not authenticated.", status=401)

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 2801-2830
  symbol: `Oauth2Provider._get_request_user_id`
  excerpt: |
    for source in (request.get("userdata"), request.get("userinfo")):
        if isinstance(source, dict):
            uid = source.get("user_id")
    ...
    user = request.get(self.user_property) or getattr(request, "user", None)

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 2221-2231
  symbol: `Oauth2Provider.userinfo`
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
  lines: 2234-2254
  symbol: `Oauth2Provider.userinfo._claim`
  excerpt: |
    def _claim(name: str, default: str = "") -> str:
        if payload.get(name) not in (None, ""):
            return payload.get(name)
        if user is not None:
            ...
        return default
    if "profile" in scopes:
        claims["username"] = str(_claim("username"))

## Notes

*From FC-008:*
`revoke_grant` (2332) uses the same helper, so "Revoke grant" fails the same way.
Once the session binds, the user fallback would work, but the claims source would
still be empty on the exempt path (FC-004).

*From FC-009:*
The user's userinfo log excerpt shows only the bind warnings, not this
"userinfo: could not load user" warning; the 200 body matches the user_from_id
failure path regardless.

*From FW-006:*
- `/oauth2/userinfo` returning 200 with empty strings for an unresolvable user is a
  spec-conformance question (OIDC: omit unknown claims rather than send ""); the handler
  itself works — the root input is the unresolvable user_id 35.
- The report's log excerpt shows no `userinfo: could not load user` line; the user may have
  trimmed it, or another path served the call — not verifiable from the wiki.
- [cross-lane: type=read, intent=In auth.py _auth_middleware, when does a decoded bearer get published as request["userdata"]; is that skipped when the token has no session_id claim?]

*Merge redirects:*
- `navigator_auth/backends/oauth2/backend.py` :: `Oauth2Provider.userinfo` — duplicate from FW-006, collapsed into the first citation.
- `navigator_auth/backends/oauth2/backend.py` :: `Oauth2Provider.list_grants` — duplicate from FW-006, collapsed into the first citation.
- `navigator_auth/backends/oauth2/backend.py` :: `Oauth2Provider._get_request_user_id` — duplicate from FW-006, collapsed into the first citation.
