# TASK-044: OAuth 2.1 / Claude conformance hardening

**Feature**: FEAT-095 oauth2-for-mcp-agents
**Spec**: `sdd/specs/oauth2-for-mcp-agents.spec.md` (Module 7, decision D5)
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-039, TASK-040
**Assigned-to**: unassigned

---

## Context

Claude's client sends form-urlencoded token requests, may authenticate
`client_secret_basic`, sends the RFC 8707 `resource` parameter, and expects standards-shaped
401 challenges. This task closes those conformance gaps. Per D5, audience *enforcement*
stays on the resource-server side (ai-parrot `ExternalOAuthValidator`); navigator-auth only
validates and reflects.

---

## Scope

- `/oauth2/token`: reject non-`application/x-www-form-urlencoded` bodies with **415**
  (JSON body ⇒ 415; form ⇒ normal).
- Accept `client_secret_basic` (HTTP Basic) in addition to `client_secret_post` at
  `/oauth2/token`, `/oauth2/introspect`, `/oauth2/revoke` (RFC 8414 advertises both;
  constant-time comparison preserved).
- RFC 8707 minimal: accept `resource` at authorize + token; validate absolute URI without
  fragment (`invalid_target` on bad values); persist through the authorization code;
  reflect the canonical resource into `aud` alongside the FEAT-093 `'user'`/`'app'` marker
  (list-valued `aud`).
- Bearer 401s (resource-server path `backends/api.py` + `auth.py` middleware) add
  `WWW-Authenticate: Bearer resource_metadata="{issuer}/.well-known/oauth-protected-resource"`.
- Unit tests per spec §4 (four `test_*` rows for M7).

**NOT in scope**: audience enforcement (resource-server side, D5), timing-budget assertions
(TASK-045 conformance tests), any grant-flow change.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | 415 guard; Basic auth; `resource` handling |
| `navigator_auth/backends/oauth2/models.py` | MODIFY | `resource` on `OauthAuthorizationCode` |
| `navigator_auth/backends/api.py` | MODIFY | 401 challenge header |
| `navigator_auth/auth.py` | MODIFY | Middleware 401 challenge header |
| `tests/test_oauth2_conformance.py` | CREATE | 415 / Basic / resource→aud / challenge tests |

---

## Implementation Notes

### Key Constraints
- `decode_token` must keep working with list-valued `aud` (verify_aud remains opt-in —
  FEAT-093 Q2 decision: propagate, don't enforce).
- The challenge header must appear on **all** bearer 401s, including revoked-`jti`
  rejections, without leaking why the token failed.
- Keep FEAT-093/094 token tests passing unmodified — the 415 guard must not affect
  existing form-based tests.

### References in Codebase
- `navigator_auth/backends/oauth2/backend.py:752` `token_request` — entry point.
- `navigator_auth/backends/api.py` — `APIKeyAuth` bearer path (`get_token_info`,
  `auth_middleware`).
- `navigator_auth/auth.py:952` `_token_is_revoked` / middleware 401 emission.

---

## Acceptance Criteria

- [ ] JSON body at `/oauth2/token` ⇒ 415; form-urlencoded unchanged
- [ ] `client_secret_basic` accepted at token/introspect/revoke
- [ ] `resource` validated + reflected into `aud`; bad values ⇒ `invalid_target`
- [ ] Bearer 401s carry the `resource_metadata` challenge
- [ ] FEAT-093/094 suites pass unmodified
- [ ] Tests pass: `pytest tests/test_oauth2_conformance.py -v`

---

## Test Specification

```python
# tests/test_oauth2_conformance.py — per spec §4:
# test_token_endpoint_415_json, test_client_secret_basic,
# test_resource_param_aud, test_www_authenticate_challenge
```

---

## Agent Instructions

1. **Read the spec**; 2. **Check dependencies** (TASK-039, TASK-040 completed);
3. **Update index** → in-progress; 4. **Implement**; 5. **Verify**;
6. **Move to completed/**; 7. **Update index** → done; 8. **Fill Completion Note**.

---

## Completion Note

**Completed by**: sdd-worker (Claude Opus 5)
**Date**: 2026-08-31
**Notes**: **415 guard**: `token_request` refuses any POST whose Content-Type is present and is not `application/x-www-form-urlencoded`, returning 415 with an `Accept` header. Comparison is lower-cased, and an *absent* Content-Type is tolerated so the FEAT-093/094 token tests keep passing unmodified (explicitly covered by two tests). **client_secret_basic**: one `_merge_basic_auth` helper now serves `/oauth2/token`, `/oauth2/introspect` and `/oauth2/revoke`; it form-urldecodes both components per RFC 6749 §2.3.1 (the previous inline introspect implementation did not), preserves colons in secrets, lets body credentials win over the header, and treats a malformed header as "no credentials" rather than raising. The existing `hmac.compare_digest` checks downstream are untouched. **RFC 8707**: `validate_resource_uri` (absolute URI, no fragment) gates the parameter at authorize, at consent, at the authorization_code exchange and at client_credentials; bad values ⇒ `invalid_target`. `resource` is persisted on `OauthAuthorizationCode` and threaded through `_issue_code` from both the consent-skip and the consent-POST paths. At the token exchange a `resource` on the request must match the one the code was issued for — silently downgrading would let a client swap the audience after consent. `_resource_audience` appends the canonical resource to the FEAT-093 `'user'`/`'app'` marker, giving a list-valued `aud`; with no resource the claim stays the plain string it has always been. Enforcement stays on the resource server per D5. **Challenges**: `api.py` marks bearer requests with `BEARER_CHALLENGE_KEY`, and `auth_middleware` now wraps its body and decorates any escaping `HTTPUnauthorized` with `WWW-Authenticate: Bearer resource_metadata="{issuer}/.well-known/oauth-protected-resource"`. Doing it once at the boundary covers every 401 path — including the revoked-`jti` rejection — instead of patching 18 call sites. The marker means session/cookie 401s do not get a bearer challenge they cannot act on; `bearer_challenge` never raises (a discovery convenience must not turn a 401 into a 500) and leaks nothing about why the token failed. 39 new tests; 377 pass across the non-DB OAuth2 suites.

**Deviations from spec**: one file beyond the task's table — `templates/oauth/consent.html` gained a hidden `resource` field. Without it the resource indicator is silently dropped at the consent hop and never reaches `_issue_code`, so the acceptance criterion "resource validated + reflected into aud" would fail for the interactive flow. This is exactly the bug the template's existing PKCE comment documents for `code_challenge`. A test asserts the field is present.
