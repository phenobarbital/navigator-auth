---
id: FW-002
query_id: Q002
type: wiki_page
intent: "Read the existing 3LO session-binding regression tests (what is already covered)."
executed_at: 2026-11-11T14:38:30Z
duration_ms: 700
parent_id: null
depth: 0
---

# FW-002 — `tests/test_oauth2_3lo_session_binding.py` covers 4 earlier 3LO defects, none of the ones reported now

## Summary

Wiki page `file:tests/test_oauth2_3lo_session_binding.py` (score 1.00 in the orientation
query, 0.68 here). Its module docstring locks four earlier defects: (1) `decode_token`
rejecting `aud`, (2) access tokens minted with no session linkage, (3) login/consent
templates dropping `code_challenge`, (4) `_get_request_user_id` reading `request["userinfo"]`
(grants API 401). All tests are unit-level with `MagicMock` IdP/storage — none boots the
example app or a real `AuthHandler` with its backend list.

Not covered (gaps relevant to this report): the example's backend wiring
(`AUTHENTICATION_BACKENDS` / NoAuth / `settings.settings` override); `is_authenticated`
iterating backends and a non-`AuthException` from one of them; `APIKeyAuth.authenticate`
on a 3LO JWT bearer; an end-to-end `/api/v1/me` 401-without-credentials check; userinfo
returning empty claims when `user_from_id` fails; consistency between the IdP used at login
and the IdP used at binding. `test_unknown_user_degrades_without_raising` actually asserts
the silent `{}` degradation that hides the problem in the example.

## Citations

- path: `tests/test_oauth2_3lo_session_binding.py`
  lines: 1-17
  symbol: module docstring
  wiki: `file:tests/test_oauth2_3lo_session_binding.py` (score 1.00 / 0.68)
  excerpt: |
    """Regression tests for the 3LO end-to-end path (see examples/oauth2_3lo_server.py).
    ...
    2. ``Oauth2Provider`` minted access tokens with no session linkage, so
       ``auth_middleware`` / ``@user_session()`` could not resolve a user from them.
    ...
    4. ``_get_request_user_id`` read ``request["userinfo"]``, a key nothing sets,
       making the grants API answer 401 to authenticated users.

- path: `tests/test_oauth2_3lo_session_binding.py`
  lines: 40-64
  symbol: `TestDecodeTokenAudience`

- path: `tests/test_oauth2_3lo_session_binding.py`
  lines: 82-101
  symbol: `provider` / `make_request`
  excerpt: |
    prov = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())

- path: `tests/test_oauth2_3lo_session_binding.py`
  lines: 102-136
  symbol: `TestTokenSessionBinding`
  excerpt: |
    async def test_unknown_user_degrades_without_raising(self, provider):
        provider._idp.user_from_id = AsyncMock(side_effect=RuntimeError("no such user"))
        request = make_request(MagicMock())
        assert await provider._token_session_claims(request, 404) == {}

- path: `tests/test_oauth2_3lo_session_binding.py`
  lines: 138-150
  symbol: `TestPkcePropagation`

- path: `tests/test_oauth2_3lo_session_binding.py`
  lines: 152-168
  symbol: `TestRequestUserId`

## Notes

- Other OAuth2 test files that reference `backend.py` (from Q006): `test_oauth2_conformance.py`,
  `test_oauth2_issuer.py`, `test_oauth2_mcp_conformance.py`, `test_oauth2_provider_cleanup.py`,
  `test_oauth2_session_user_decoding.py`, plus `test_oauth2_userinfo_logout.py` and
  `test_oauth2_grants_revoke.py` (Q005 hits).
- [cross-lane: type=git_log, intent=Which commit added this test file (expected d3f85ba) and did the example change after it?]
