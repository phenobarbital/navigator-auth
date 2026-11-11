---
id: FW-001
query_id: Q001
type: wiki_query
intent: "Orient: Oauth2Provider backend, session binding and user_from_id in the graph."
executed_at: 2026-11-11T14:38:00Z
duration_ms: 900
parent_id: null
depth: 0
---

# FW-001 — `_token_session_claims` binds a session via `self._idp.user_from_id` and degrades to `{}` on failure

## Summary

Top hit for session binding is `Oauth2Provider._token_session_claims`
(wiki `sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._token_session_claims`, score 0.82).
It resolves the resource owner with `self._idp.user_from_id(user_id)`; any exception is
logged as the exact warning in the report ("cannot bind a session to the token for
user_id=...") and the method returns `{}` — the token is still issued, but without the
`session_id`/`id`/`username` claims that `auth_middleware` / `@user_session()` need to
resolve a user. So the warning in every token/refresh exchange means every access token
from that run is session-less.

## Citations

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 688-710
  symbol: `Oauth2Provider._token_session_claims`
  wiki: `sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._token_session_claims` (score 0.82)
  excerpt: |
    try:
        user = await self._idp.user_from_id(user_id)
    except Exception as exc:  # pylint: disable=W0703
        self.logger.warning(f"Oauth2: cannot bind a session to the token for user_id={user_id}: {exc}")
        return {}
    session = await self._create_user_session(request, user)
    if not session:
        return {}

## Notes

- Docstring states the empty-dict fallback is deliberate ("leaving the token usable for
  introspection-based resource servers"), so a token without a session is a designed state,
  not a crash — consumers must cope with it.
- The warning text "Invalid Credentials for user_id=35" matches
  `DemoIdentityProvider.user_from_id` in `examples/oauth2_3lo_server.py` (only ids 1, 2 exist),
  i.e. the demo IdP is the one consulted for binding, while user 35 came from somewhere else.
- [cross-lane: type=grep, intent=Which IdentityProvider authenticates the /oauth2/login form (does it go through self._idp or another backend / DB), and how does user_id 35 reach the code?]
