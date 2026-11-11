---
id: F002
query_id: Q010
type: read
intent: "Read the session-binding code around backend.py:700 and the code that mints the access token."
executed_at: 2026-11-11T14:36:00Z
duration_ms: 600
parent_id: null
depth: 0
merged_from: [FC-002, FW-001, FW-007]
---

# F002 — Session-bind failure is swallowed: the token is still issued, without session claims

## Summary

`_token_session_claims` resolves the owner with `self._idp.user_from_id(user_id)`;
any exception is logged as the reported warning ("cannot bind a session to the
token for user_id=…") and an EMPTY dict is returned. The caller spreads that dict
into `token_data`, so the access token is minted anyway — carrying only
`user_id/client_id/scope/jti`, with no `session_id`/username claims. The same call
runs on the refresh grant (2046), which explains the warning on "Refresh Token".
Downstream, nothing can resolve a session from such a token (see FC-004, FC-008).

*(merged from FW-001)* Top hit for session binding is `Oauth2Provider._token_session_claims`
(wiki `sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._token_session_claims`, score 0.82).
It resolves the resource owner with `self._idp.user_from_id(user_id)`; any exception is
logged as the exact warning in the report ("cannot bind a session to the token for
user_id=...") and the method returns `{}` — the token is still issued, but without the
`session_id`/`id`/`username` claims that `auth_middleware` / `@user_session()` need to
resolve a user. So the warning in every token/refresh exchange means every access token
from that run is session-less.

*(merged from FW-007)* `wikitoolkit related file:navigator_auth/backends/oauth2/backend.py` returns mostly
`defines` edges (session helpers: `_create_user_session`, `_decode_session_user`,
`_session_storage`, `_token_session_claims`; grant handlers: `_handle_authorization_code`,
`_handle_refresh_token`; `authenticate`, `check_credentials`, `auth_login`, `userinfo`...).
Incoming `references` come only from tests: `test_oauth2_3lo_session_binding.py`,
`test_oauth2_conformance.py`, `test_oauth2_issuer.py`, `test_oauth2_mcp_conformance.py`,
`test_oauth2_provider_cleanup.py`, `test_oauth2_session_user_decoding.py` — no example and
no integration test wires it through a real `AuthHandler` backend list. Saved memory
`mem-b8bff584423d` (lesson, 2026-11-06) records that `api_login` iterates every backend and
`continue`s on `(AuthException, UserNotFound, InvalidAuth, FailedAuth)` — the same
"first truthy backend wins" semantics FW-003 shows in `is_authenticated`, with a narrower
catch tuple there.

## Citations

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 688-710
  symbol: `Oauth2Provider._token_session_claims`
  excerpt: |
    try:
        user = await self._idp.user_from_id(user_id)
    except Exception as exc:  # pylint: disable=W0703
        self.logger.warning(f"Oauth2: cannot bind a session to the token for user_id={user_id}: {exc}")
        return {}
    session = await self._create_user_session(request, user)
    if not session:
        return {}

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 1822-1830
  symbol: `Oauth2Provider._handle_authorization_code`
  excerpt: |
    token_data = {
        "user_id": user_id,
        "client_id": client.client_id,
        "scope": scope,
        "jti": jti,
        **await self._token_session_claims(request, user_id),
    }

- path: `navigator_auth/backends/oauth2/backend.py`
  lines: 2046
  symbol: `Oauth2Provider._handle_refresh_token`
  excerpt: |
    **await self._token_session_claims(request, user_id),

- path: `examples/oauth2_3lo_server.py`
  lines: 131-135
  symbol: `DemoIdentityProvider.user_from_id`
  excerpt: |
    for user in self._users.values():
        if str(user.user_id) == str(uid):
            return user
    raise UserNotFound(f"Invalid Credentials for user_id={uid!r}")

- path: `navigator_auth/auth.py`
  lines: 484-499
  symbol: `AuthHandler.api_login`
  wiki: memory `mem-b8bff584423d` (lesson; cites auth.py:484-491, :497-499)
  excerpt: |
    api_login ITERA BACKENDS: auth.py:484-491 recorre todos los backends y su
    'except (AuthException, UserNotFound, InvalidAuth, FailedAuth): continue' pasa al
    SIGUIENTE backend; y un retorno truthy se carga como sesion via load_session

## Notes

*From FC-002:*
The decoded tokens in the report confirm the claim-less shape:
`{'exp','iat','iss','jti','user_id': 35,'client_id','scope','aud'}` — no session id.
The degrade-silently behaviour is intentional and tested (FC-010,
`test_unknown_user_degrades_without_raising`).

*From FW-001:*
- Docstring states the empty-dict fallback is deliberate ("leaving the token usable for
  introspection-based resource servers"), so a token without a session is a designed state,
  not a crash — consumers must cope with it.
- The warning text "Invalid Credentials for user_id=35" matches
  `DemoIdentityProvider.user_from_id` in `examples/oauth2_3lo_server.py` (only ids 1, 2 exist),
  i.e. the demo IdP is the one consulted for binding, while user 35 came from somewhere else.
- [cross-lane: type=grep, intent=Which IdentityProvider authenticates the /oauth2/login form (does it go through self._idp or another backend / DB), and how does user_id 35 reach the code?]

*From FW-007:*
- Memory `mem-f3cb0b08a3ec` ("auth_token in session is the provider token, and load_session
  discards fresh userdata") may matter if the fix touches session creation; not read in full.
- Memory `mem-1365e23be030`: navigator-session is a wheel install (traceback frame
  `navigator_session/middleware.py`) — fixes cannot patch it in-repo.
- [cross-lane: type=read, intent=Oauth2Provider.auth_login / check_credentials: which IdP / backend validates the login form credentials (source of user_id 35)?]
- [cross-lane: type=git_log, intent=Recent commits touching _token_session_claims / _handle_refresh_token (session binding on refresh).]

*Merge redirects:*
- `navigator_auth/backends/oauth2/backend.py` :: `Oauth2Provider._token_session_claims` — duplicate from FW-001, collapsed into the first citation.
- `navigator_auth/backends/oauth2/backend.py` :: `Oauth2Provider._token_session_claims` — duplicate from FW-007, collapsed into the first citation.
- `navigator_auth/backends/oauth2/backend.py` :: `Oauth2Provider._handle_refresh_token` — canonical citation lives in F002 (from FW-007).
- `navigator_auth/backends/oauth2/backend.py` :: `Oauth2Provider.auth_login` — canonical citation lives in F001 (from FW-007).

[citation-check: stale] navigator_auth/backends/oauth2/backend.py:1829 — anchor `**await self._token_session_claims(request, user_id),` matches 2 lines (1829, 2046); both are cited (1822-1830 code grant, 2046 refresh grant) — consistent, not unique.
