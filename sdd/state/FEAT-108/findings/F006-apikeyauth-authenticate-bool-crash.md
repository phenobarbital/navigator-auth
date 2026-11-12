---
id: F006
query_id: Q013
type: read
intent: "Read APIKeyAuth.authenticate / check_token_info / auth_middleware (api.py:154, :292)."
executed_at: 2026-11-11T14:39:30Z
duration_ms: 600
parent_id: null
depth: 0
merged_from: [FC-006]
---

# F006 — APIKeyAuth.authenticate indexes a False return for any non-API-key bearer

## Summary

`APIKeyAuth.get_payload` claims every `Authorization: Bearer <jwt>` (mech
`bearer`) unless the token contains `:`. `get_token_info` decodes the JWT with the
shared IdP and returns `check_token_info(...)`, which returns `False` when the
payload has no `device_id` (every 3LO/OAuth2 token). `authenticate` then does
`data["device_id"]` on `False` → `TypeError: 'bool' object is not subscriptable`;
only `KeyError` is caught. `check_credentials` (used by the APIKey middleware)
already guards with `if not data: return False` — the guard is missing only in
`authenticate`. Its middleware wraps unknown errors in a 500 too, but it returned
falsy here so the request passed (api.py:292 in the traceback).

## Citations

- path: `navigator_auth/backends/api.py`
  lines: 64-75
  symbol: `APIKeyAuth.get_payload`
  excerpt: |
    elif "Authorization" in request.headers:
        scheme, token = request.headers.get("Authorization").strip().split(" ", 1)
        mech = "bearer"
        ...
        if ":" in token:
            # is an Partner Token, not API
            return [None, None]

- path: `navigator_auth/backends/api.py`
  lines: 185-190
  symbol: `APIKeyAuth.check_token_info`
  excerpt: |
    try:
        user_id = payload["user_id"]
        device_id = payload["device_id"]
    except KeyError:
        return False

- path: `navigator_auth/backends/api.py`
  lines: 143-157
  symbol: `APIKeyAuth.authenticate`
  excerpt: |
    if not token or not mech:
        return None
    else:
        data = await self.get_token_info(request, mech, token)
        try:
            device_id = str(data["device_id"])
            user_id = data["user_id"]
        except KeyError as err:
            raise InvalidAuth(f"Missing attributes for API Key: {err!s}", status=401) from err

- path: `navigator_auth/backends/api.py`
  lines: 211-219
  symbol: `APIKeyAuth.check_credentials`
  excerpt: |
    mech, token = await self.get_payload(request)
    if not token or not mech:
        return False
    try:
        data = await self.get_token_info(request, mech, token)
        if not data:
            return False

## Notes

*From FC-006:*
`check_token_info` also needs `app["authdb"]` (api.py:198) — absent with
`enable_authdb=False`; it returns False there too (broad except), so APIKeyAuth can
never succeed in this example. Bearer JWT handling in APIKeyAuth is TASK-029
(oauth2-3lo-implementation).
[cross-lane: type=git_log, intent=when was the bearer branch added to APIKeyAuth.get_payload/get_token_info (92e2e7d TASK-029?)]
