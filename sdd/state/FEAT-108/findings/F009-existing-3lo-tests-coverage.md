---
id: F009
query_id: Q018
type: read
intent: "Read the existing 3LO session-binding tests."
executed_at: 2026-11-11T14:43:00Z
duration_ms: 800
parent_id: null
depth: 0
merged_from: [FC-010, FW-002]
---

# F009 — Existing 3LO tests mock user_from_id; nothing covers the decorator loop, APIKeyAuth on a 3LO bearer, NoAuth or allow_hosts

## Summary

`tests/test_oauth2_3lo_session_binding.py` (added with the example) unit-tests
`_token_session_claims` with a mocked `user_from_id` (success → session claims;
failure → `{}` without raising), PKCE propagation through the login template, and
`_get_request_user_id` sources. It never runs the example app end-to-end, never
exercises `@is_authenticated()` with several backends configured, and nothing in
`tests/` calls `APIKeyAuth.authenticate` with a non-API-key bearer or configures
`authz_backends`/`allow_hosts`. `NoAuth` appears only in
`tests/test_auth_middleware_mechanism.py` and
`tests/unit/identity/test_external_token_capture.py`.

*(merged from FW-002)* Wiki page `file:tests/test_oauth2_3lo_session_binding.py` (score 1.00 in the orientation
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
  lines: 102-131
  symbol: `TestTokenSessionBinding`
  excerpt: |
    provider._idp.user_from_id = AsyncMock(
        return_value=DummyUser(user_id=11, username="demo")
    )
    claims = await provider._token_session_claims(request, 11)
    ...
    async def test_unknown_user_degrades_without_raising(self, provider):
        provider._idp.user_from_id = AsyncMock(side_effect=RuntimeError("no such user"))
        assert await provider._token_session_claims(request, 404) == {}

- path: `tests/test_oauth2_3lo_session_binding.py`
  lines: 138-164
  symbol: `TestPkcePropagation / TestRequestUserId`
  excerpt: |
    def test_template_forwards_the_code_challenge(self, template):
    def test_reads_the_token_claims(self, provider):
    def test_falls_back_to_the_session_user(self, provider):
    def test_returns_none_when_anonymous(self, provider):

- path: `tests/unit/test_is_authenticated_exclude.py`
  lines: null
  symbol: `TestAllowAnonymous`
  excerpt: |
    (wiki: Unit tests for is_authenticated exclude-list short-circuit (FEAT-241 M3))

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
  lines: 138-150
  symbol: `TestPkcePropagation`

- path: `tests/test_oauth2_3lo_session_binding.py`
  lines: 152-168
  symbol: `TestRequestUserId`

## Notes

*From FC-010:*
`test_unknown_user_degrades_without_raising` locks in the silent-degrade behaviour
of FC-002; changing it to fail the token request would require updating this test.
Grep for `APIKeyAuth(`/`.authenticate(` on api.py and for `authz_backends|allow_hosts`
in tests/ returned no matches.

*From FW-002:*
- Other OAuth2 test files that reference `backend.py` (from Q006): `test_oauth2_conformance.py`,
  `test_oauth2_issuer.py`, `test_oauth2_mcp_conformance.py`, `test_oauth2_provider_cleanup.py`,
  `test_oauth2_session_user_decoding.py`, plus `test_oauth2_userinfo_logout.py` and
  `test_oauth2_grants_revoke.py` (Q005 hits).
- [cross-lane: type=git_log, intent=Which commit added this test file (expected d3f85ba) and did the example change after it?]

*Merge redirects:*
- `tests/test_oauth2_3lo_session_binding.py` :: `TestTokenSessionBinding` — duplicate from FW-002, collapsed into the first citation.
