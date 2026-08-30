# TASK-038: Issuer identity + configuration foundation

**Feature**: FEAT-095 oauth2-for-mcp-agents
**Spec**: `sdd/specs/oauth2-for-mcp-agents.spec.md` (Module 1)
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Every new endpoint in FEAT-095 (RFC 8414/9728 discovery, DCR, JWKS) needs a canonical
**https issuer URL**. Today `AUTH_TOKEN_ISSUER` defaults to the URN `urn:Navigator`
(`conf.py:360`), which RFC 8414 does not allow as an issuer identifier. This task lays the
config foundation the other seven tasks build on.

---

## Scope

- Add `AUTH_ISSUER_URL` to `navigator_auth/conf.py` (default: unset ⇒ derived per request).
- Add the full FEAT-095 config block (spec §6 table): `OAUTH_DCR_POLICY` (`open`),
  `OAUTH_DCR_REDIRECT_ALLOWLIST` (Claude callbacks), `OAUTH_DCR_DEFAULT_SCOPES`,
  `OAUTH_DCR_GATE_NEW_CLIENTS` (True), `OAUTH_DCR_RATE_LIMIT`, `OAUTH_DCR_UNUSED_TTL`,
  `OAUTH_UPSTREAM_IDP_BACKENDS` ([]), `OAUTH_UPSTREAM_FLOW_TTL` (600),
  `OAUTH_ACCESS_GATE_ENABLED` (False), `OAUTH_ACCESS_GATE_QUEUE` (True),
  `OAUTH_JWT_SIGNING_ALG` (`HS256`), `OAUTH_JWT_KEYS` ([]).
- Implement an `issuer_url(request)` helper on `Oauth2Provider` (or a small pure module):
  returns `AUTH_ISSUER_URL` when set; otherwise derives `scheme://host` honoring
  `X-Forwarded-Proto` / `Host` (reverse-proxy safe); https enforced (http allowed only for
  localhost dev).
- Write unit tests for the helper (`test_issuer_derivation_proxy`).

**NOT in scope**: any endpoint, document builder, or behavior change (TASK-039+).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/conf.py` | MODIFY | New FEAT-095 config block (navconfig `config.get/getboolean/getint`) |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `issuer_url(request)` helper (no routes yet) |
| `tests/test_oauth2_issuer.py` | CREATE | Derivation + proxy-header + https-enforcement tests |

---

## Implementation Notes

### Pattern to Follow
Mirror the existing `OAUTH_*` block (`conf.py:650-750`, added by FEAT-093/094): navconfig
`config.get(..., fallback=...)` style, grouped with a comment header.

### Key Constraints
- Do not change `AUTH_TOKEN_ISSUER` semantics — existing JWT `iss` behavior for non-OAuth2
  backends stays untouched; `AUTH_ISSUER_URL` is a *new* setting used by FEAT-095 surfaces.
- `X-Forwarded-Proto` only trusted for scheme; never derive from user-controlled headers
  beyond scheme/host.

### References in Codebase
- `navigator_auth/conf.py:650-750` — FEAT-093/094 `OAUTH_*` block pattern.
- `navigator_auth/backends/oauth2/backend.py` `prepare_url` — existing URL assembly.

---

## Acceptance Criteria

- [ ] All spec §6 config keys exist with the documented defaults
- [ ] `issuer_url(request)` honors `AUTH_ISSUER_URL`, proxy headers, https enforcement
- [ ] Tests pass: `pytest tests/test_oauth2_issuer.py -v`
- [ ] FEAT-093/094 suites pass unmodified

---

## Test Specification

```python
# tests/test_oauth2_issuer.py
async def test_issuer_from_setting(...):        # AUTH_ISSUER_URL set ⇒ returned verbatim
async def test_issuer_derived_from_request(...) # unset ⇒ scheme://host
async def test_issuer_proxy_headers(...)        # X-Forwarded-Proto: https honored
async def test_issuer_https_enforced(...)       # http non-localhost ⇒ rejected/upgraded
```

---

## Agent Instructions

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — none
3. **Update status** in `tasks/.index.json` → `"in-progress"`
4. **Implement**, **verify**, **move to** `tasks/completed/`, **update index** → `"done"`

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**:
**Date**:
**Notes**:

**Deviations from spec**: none
