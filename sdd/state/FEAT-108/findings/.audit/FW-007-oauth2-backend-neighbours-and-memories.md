---
id: FW-007
query_id: Q006
type: wiki_related
intent: "Neighbours of the Oauth2Provider backend module."
executed_at: 2026-11-11T14:41:00Z
duration_ms: 600
parent_id: null
depth: 0
---

# FW-007 — `backend.py` neighbours are its own symbols plus 6 test files; one saved lesson on backend-iteration semantics

## Summary

`wikitoolkit related file:navigator_auth/backends/oauth2/backend.py` returns mostly
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
  wiki: `file:navigator_auth/backends/oauth2/backend.py` (related, defines edge)

- path: `navigator_auth/backends/oauth2/backend.py`
  symbol: `Oauth2Provider._handle_refresh_token`
  wiki: `sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider._handle_refresh_token` (defines edge; not read)

- path: `navigator_auth/backends/oauth2/backend.py`
  symbol: `Oauth2Provider.auth_login`
  wiki: `sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.auth_login` (defines edge; not read)

- path: `navigator_auth/auth.py`
  lines: 484-499
  symbol: `AuthHandler.api_login`
  wiki: memory `mem-b8bff584423d` (lesson; cites auth.py:484-491, :497-499)
  excerpt: |
    api_login ITERA BACKENDS: auth.py:484-491 recorre todos los backends y su
    'except (AuthException, UserNotFound, InvalidAuth, FailedAuth): continue' pasa al
    SIGUIENTE backend; y un retorno truthy se carga como sesion via load_session

## Notes

- Memory `mem-f3cb0b08a3ec` ("auth_token in session is the provider token, and load_session
  discards fresh userdata") may matter if the fix touches session creation; not read in full.
- Memory `mem-1365e23be030`: navigator-session is a wheel install (traceback frame
  `navigator_session/middleware.py`) — fixes cannot patch it in-repo.
- [cross-lane: type=read, intent=Oauth2Provider.auth_login / check_credentials: which IdP / backend validates the login form credentials (source of user_id 35)?]
- [cross-lane: type=git_log, intent=Recent commits touching _token_session_claims / _handle_refresh_token (session binding on refresh).]
