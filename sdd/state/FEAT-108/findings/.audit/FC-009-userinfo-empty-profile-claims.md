---
id: FC-009
query_id: Q014
type: read
intent: "Locate userinfo and grants endpoint handlers in the OAuth2 provider."
executed_at: 2026-11-11T14:41:30Z
duration_ms: 500
parent_id: FC-008
depth: 1
---

# FC-009 — /oauth2/userinfo fills profile claims from user_from_id and defaults to ""

## Summary

`userinfo` decodes the bearer itself (so it returns 200 even though the session is
unbound), sets `sub` from `user_id`, and — because profile/email are not in the
JWT — loads the user with `self._idp.user_from_id(user_id)`. For user 35 that raises
in the demo IdP; the exception is only logged and every `_claim` falls back to the
default `""`, producing `{"sub":"35","username":"","given_name":"","family_name":"","email":""}`.
Returning empty strings rather than omitting unknown claims is itself questionable
(OIDC userinfo omits claims it cannot supply).

## Citations

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

The user's userinfo log excerpt shows only the bind warnings, not this
"userinfo: could not load user" warning; the 200 body matches the user_from_id
failure path regardless.
