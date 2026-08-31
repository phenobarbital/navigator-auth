# TASK-039: Discovery documents (RFC 8414 + RFC 9728)

**Feature**: FEAT-095 oauth2-for-mcp-agents
**Spec**: `sdd/specs/oauth2-for-mcp-agents.spec.md` (Module 2)
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-038
**Assigned-to**: unassigned

---

## Context

Claude's connector infrastructure discovers the AS via
`GET /.well-known/oauth-authorization-server` (RFC 8414) and resources via
`/.well-known/oauth-protected-resource` (RFC 9728). Neither exists in navigator-auth.
Wire-contract reference: ai-parrot `parrot/mcp/oauth_server.py` `_handle_discovery`
(proven against Claude's client) — copy the document shape, not the code.

---

## Scope

- Create `navigator_auth/backends/oauth2/metadata.py` with **pure builders** (no aiohttp
  imports): `build_as_metadata(...)` and `build_protected_resource_metadata(...)` per spec
  §2 "New Public Interfaces". The PRM builder must be importable standalone (ai-parrot
  consumes it — spec D6).
- AS metadata fields: `issuer`, `authorization_endpoint`, `token_endpoint`,
  `registration_endpoint` (iff DCR enabled), `introspection_endpoint`,
  `revocation_endpoint`, `device_authorization_endpoint`,
  `response_types_supported: ["code"]`, `grant_types_supported`,
  `code_challenge_methods_supported: ["S256"]`,
  `token_endpoint_auth_methods_supported: ["client_secret_post","client_secret_basic","none"]`,
  `scopes_supported` (from `OAUTH_SCOPES` when non-empty), `jwks_uri` (iff `OAUTH_JWT_KEYS`
  loaded — read config only; do not depend on TASK-043 code).
- Register `GET` routes in `Oauth2Provider.configure()` at the **origin root**
  (`/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`) plus
  aliases under the AS path; append both to `AUTH_EXCLUDE_LIST_KEY`.
- In-process caching of the built documents; responses < 1 s.
- Unit tests: `test_as_metadata_document`, `test_prm_document`.

**NOT in scope**: DCR endpoint (TASK-040), JWKS endpoint itself (TASK-043),
`WWW-Authenticate` challenges (TASK-044).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/metadata.py` | CREATE | Pure RFC 8414/9728 builders |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | Routes in `configure()` + exclude list |
| `tests/test_oauth2_metadata.py` | CREATE | Document shape + conditional-field tests |

---

## Implementation Notes

### Pattern to Follow
Pure-helper discipline of `oauth2/pkce.py` / `oauth2/devicecode.py` (FEAT-093/094): plain
functions over plain data, exhaustively unit-testable without a server.

### Key Constraints
- Issuer comes from TASK-038's `issuer_url(request)`; RFC 8414 §3 requires the metadata to
  live at the origin root and `issuer` to match its location.
- `registration_endpoint` appears only when `OAUTH_DCR_POLICY != "disabled"`.
- `jwks_uri` appears only when a key registry is configured (never advertise an empty one).

### References in Codebase
- `ai-parrot .../parrot/mcp/oauth_server.py:417` — proven RFC 8414 document shape.
- `navigator_auth/auth.py:897` `verify_exceptions` — how exclude-list paths bypass auth.

---

## Acceptance Criteria

- [ ] Both documents served unauthenticated at the origin root, valid per RFC
- [ ] Conditional fields behave per config (`registration_endpoint`, `jwks_uri`, `scopes_supported`)
- [ ] PRM builder importable without aiohttp/server context
- [ ] Tests pass: `pytest tests/test_oauth2_metadata.py -v`

---

## Test Specification

```python
# tests/test_oauth2_metadata.py
def test_as_metadata_document(...)       # all required fields; issuer; S256 only
def test_as_metadata_no_dcr(...)         # policy=disabled ⇒ no registration_endpoint
def test_as_metadata_jwks_conditional(...)
def test_prm_document(...)               # resource, authorization_servers=[issuer], scopes
async def test_wellknown_routes(...)     # 200, unauthenticated, JSON content-type
```

---

## Agent Instructions

1. **Read the spec**; 2. **Check dependencies** (TASK-038 completed);
3. **Update index** → in-progress; 4. **Implement**; 5. **Verify**;
6. **Move to completed/**; 7. **Update index** → done; 8. **Fill Completion Note**.

---

## Completion Note

**Completed by**:
**Date**:
**Notes**:

**Deviations from spec**: none
