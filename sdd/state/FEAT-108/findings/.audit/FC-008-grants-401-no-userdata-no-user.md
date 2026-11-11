---
id: FC-008
query_id: Q014
type: grep
intent: "Locate userinfo and grants endpoint handlers in the OAuth2 provider."
executed_at: 2026-11-11T14:41:00Z
duration_ms: 700
parent_id: null
depth: 0
---

# FC-008 — GET /api/v1/oauth2/grants returns 401 because neither claims nor a user reach the request

## Summary

The grants list route is `GET /api/v1/oauth2/grants` → `Oauth2Provider.list_grants`
(registered at 351, not in the exclude list). It has no auth of its own: it reads
the user id via `_get_request_user_id`, which looks at `request["userdata"]` /
`request["userinfo"]` and then `request.user`. For a localhost request the auth
middleware takes the allow_hosts exempt branch (FC-004), which never sets
`request["userdata"]` and only sets `request.user` when the token's session exists —
it doesn't (FC-002). So both sources are empty → `401 unauthorized / "Not
authenticated."`. The handler does not call `self.authenticate(request)` itself.

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

## Notes

`revoke_grant` (2332) uses the same helper, so "Revoke grant" fails the same way.
Once the session binds, the user fallback would work, but the claims source would
still be empty on the exempt path (FC-004).
