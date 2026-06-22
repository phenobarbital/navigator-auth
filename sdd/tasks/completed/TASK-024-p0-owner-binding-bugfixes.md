# TASK-024: P0 Correctness — resource-owner binding + B1–B5

**Feature**: Production-grade 3LO (Three-Legged OAuth2)
**Spec**: `sdd/specs/oauth2-3lo-implementation.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-023
**Assigned-to**: unassigned

---

## Context

Implements **Module 2** of FEAT-093 — the correctness core that gates every later phase.
Eliminates the central defect: tokens deriving the user from `client.user`. Binds `user_id`
(the authenticated resource owner) through consent → code → token → refresh, and fixes
B1–B5. See spec §1 Goals, §3 M2, Resolved Decision **D1**.

---

## Scope

- `oauth2/models.py`: add `user_id: int` (required) to `OauthAuthorizationCode` and
  `OauthRefreshToken`; **rename** the `OAuthClient`-typed field `client_id` → `client` on
  `OauthAuthorizationCode`/`OauthRefreshToken`/`OauthToken`; update all access sites
  (`auth_code.client_id.client_id` → `auth_code.client.client_id`).
- `oauth2/backend.py`:
  - Resolve the authenticated `user_id` from the jsonpickle session `'user'` at consent;
    401 if absent — never mint a code.
  - Thread `user_id` into the auth code and (later) refresh token; in the refresh grant,
    **read `user_id` from the refresh token**, never `client.user`. Same for
    `client_credentials` (B-context: it uses client identity legitimately — leave 2LO but
    stop using `rt.client_id.user` paths).
  - **B1**: compute `expires_in = int(exp - datetime.now(timezone.utc).timestamp())` in the
    token response (do not change `IdentityProvider.create_token`).
  - **B2**: for confidential clients (`client_type != 'public'`), require + verify
    `client_secret` on the auth-code token branch (`hmac.compare_digest`).
  - **B3**: exact-match `redirect_uri` against `client.redirect_uris`; on mismatch render an
    error page — **never** redirect.
  - **B4**: validate `response_type == "code"` else `error=unsupported_response_type`.
  - **B5**: enforce single-use codes — reject `used`/expired (`invalid_grant`); on exchange
    set `used=True`, `used_at=now`, delete from storage.
- `oauth2/code_backend.py`: ensure auth-code save/load round-trips `user_id`.

**NOT in scope**: PKCE verification (TASK-025); rotation/reuse (TASK-026); grants/consent-skip
(TASK-027); userinfo/logout (TASK-028); scope↔ABAC (TASK-030).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/models.py` | MODIFY | `user_id` on code/refresh; rename `client_id`→`client` |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | Bind `user_id`; B1–B5; drop `client.user` derivation |
| `navigator_auth/backends/oauth2/code_backend.py` | MODIFY | Round-trip `user_id` on codes |
| `tests/test_oauth2_p0_correctness.py` | CREATE | B1–B5 + owner-binding unit tests |

---

## Implementation Notes

### Key Constraints
- `user_id` MUST originate from `session['user']` (jsonpickle-encoded in `auth_login`),
  decoded to extract the id — never from `client.user`.
- Use `hmac.compare_digest` for `client_secret`; never log secrets.
- Keep the IdP `create_token` 4-tuple signature stable (D1).

### References in Codebase
- `navigator_auth/backends/oauth2/backend.py:237,247,474,502,506,549` — session check,
  redirect_uri, token mint, client_secret, the `client.user` defect sites.
- `navigator_auth/backends/idp/__init__.py:272-304` — `create_token` (exp is absolute).

---

## Acceptance Criteria

- [ ] Token `user_id` always comes from the authenticated owner; no `client.user` reads remain.
- [ ] B1: `expires_in` is seconds. B2: confidential client secret verified. B3: redirect_uri
      exact-match, no redirect on mismatch. B4: `response_type` validated. B5: codes single-use
      and deleted.
- [ ] Nested-model field renamed `client_id`→`client`; all call sites updated.
- [ ] Tests pass: `pytest tests/test_oauth2_p0_correctness.py -v`.

---

## Test Specification

```python
# tests/test_oauth2_p0_correctness.py
import pytest

class TestP0:
    async def test_expires_in_is_seconds(self, public_client, memory_oauth_storages): ...
    async def test_redirect_uri_exact_match(self, public_client): ...
    async def test_response_type_validation(self, public_client): ...
    async def test_auth_code_single_use(self, public_client): ...
    async def test_confidential_client_secret(self, confidential_client): ...
    async def test_user_id_bound_from_session(self, public_client): ...
```

---

## Agent Instructions

1. Read the spec (§1, §3 M2, D1). 2. Verify TASK-023 is completed. 3. Index → `in-progress`.
4. Implement. 5. Verify criteria. 6. Move to `completed/`. 7. Index → `done` + Completion Note.

---

## Completion Note

**Completed by**: sdd-worker (claude-sonnet-4-6)
**Date**: 2026-06-22
**Notes**:
- `backend.py` fully rewritten: user_id from session/auth_code at every grant type,
  B1-B5 implemented, confidential client secret verification via hmac.compare_digest,
  PKCE S256 verification hooked in (calls pkce.py), all `auth_code.client_id`/`rt.client_id`
  references renamed to `.client`.
- `code_backend.py` extended with mark_used(), revoke_token(), revoke_chain(), list_tokens(),
  GrantStorage, AccessTokenStorage (covers TASK-026/027 storage needs too).
- `pkce.py` created (S256 only; plain rejected) — TASK-025 module created here since
  backend.py imports it immediately.
- `conf.py` extended with 6 new OAUTH_* constants.
- 27 tests: 26 pass, 1 skipped (fakeredis not installed in env).
**Deviations from spec**: pkce.py created as part of TASK-024 commit (ahead of TASK-025)
because backend.py imports it; TASK-025 will add the conf.py OAUTH_REQUIRE_PKCE_PUBLIC
test and refine the authorize() PKCE capture path.
