---
id: F001
query_id: Q011
type: grep
intent: "Find which IdentityProvider instance the OAuth2 login/consent and token paths use (does it honour backend._idp?)."
executed_at: 2026-11-11T14:38:00Z
duration_ms: 900
parent_id: null
depth: 0
merged_from: [FC-001]
---

# F001 — The resource owner of a 3LO code comes from the browser session cookie, not from a fresh login

## Summary

Every IdP call in the OAuth2 provider goes through `self._idp` (the demo IdP the
example swaps in): login uses `self._idp.authenticate_credentials` (1636). But
`/oauth2/authorize` and `/oauth2/consent` do NOT require a login when a session
already exists: they read the user from the session cookie via `check_session`
(`get_session(..., ignore_cookie=False)`, line 529) and rebuild it with
`_decode_session_user` (reads `user_id` out of the stored blob). With a prior grant
the code is issued directly (consent-skip, 1450-1456). So a `user_id` that is not
in `DEMO_USERS` (ids 1, 2) — e.g. `35` — can only enter the token through a
pre-existing session cookie for `localhost:5000` (shared Redis session store),
never through the demo login form.

## Citations

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 523-536
  symbol: `Oauth2Provider.check_session`
  excerpt: |
    session = request.get("session")
    if not session:
        try:
            session = await get_session(request, None, new=False, ignore_cookie=False)
    ...
    if session and "user" in session:
        return session["user"]

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 1422-1433
  symbol: `Oauth2Provider.authorize`
  excerpt: |
    # Check user session.
    session = await self.check_session(request)
    if not session:
        location = request.app.router["nav_oauth2_login"].url_for()
        ...
    gate_user = self._decode_session_user(session)

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 1636
  symbol: `Oauth2Provider.auth_login`
  excerpt: |
    user = await self._idp.authenticate_credentials(login=username, password=password)

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 1816
  symbol: `Oauth2Provider._handle_authorization_code`
  excerpt: |
    user_id = auth_code.user_id

- path: `examples/oauth2_3lo_server.py`
  lines: 84-101
  symbol: `DEMO_USERS`
  excerpt: |
    DEMO_USERS = [
        {"user_id": 1, "username": "demo", ...},
        {"user_id": 2, "username": "alice", ...},
    ]

## Notes

*From FC-001:*
All `self._idp` call sites in the package (grep): 402, 698, 894, 1636, 1855, 1946,
2050, 2206, 2230, 2298, 2409, 2487, 2848, 2851 — no other IdP instance is built in
`navigator_auth/backends/oauth2/`, so the example's `backend._idp = demo_idp` swap
is honoured everywhere in the provider.
The log at backend.py:490 ("Redirect URI: .../callback?code=...") at 14:20:24 shows a
code issued with no login POST in the excerpt, consistent with the session-cookie path.
Which app created the user-35 session cannot be proven from code.
[cross-lane: type=git_log, intent=did d3f85ba add the session-cookie resource-owner path to authorize/consent?]

*Merge redirects:*
- `navigator_auth/backends/oauth2/backend.py` :: `Oauth2Provider.authorize` — duplicate from FC-001, collapsed into the first citation.

[citation-check: stale] navigator_auth/backends/oauth2/backend.py:1450 — anchor `existing_grant = await self.grant_storage.get_grant(` matches 2 lines (1450, 2722); cited range 1447-1456 contains 1450, so the citation is consistent — the anchor is just not unique (2722 is a different handler).
