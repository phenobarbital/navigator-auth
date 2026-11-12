---
id: FC-010
query_id: Q018
type: read
intent: "Read the existing 3LO session-binding tests."
executed_at: 2026-11-11T14:43:00Z
duration_ms: 800
parent_id: null
depth: 0
---

# FC-010 — Existing 3LO tests mock user_from_id; nothing covers the decorator loop, APIKeyAuth on a 3LO bearer, NoAuth or allow_hosts

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

## Notes

`test_unknown_user_degrades_without_raising` locks in the silent-degrade behaviour
of FC-002; changing it to fail the token request would require updating this test.
Grep for `APIKeyAuth(`/`.authenticate(` on api.py and for `authz_backends|allow_hosts`
in tests/ returned no matches.
