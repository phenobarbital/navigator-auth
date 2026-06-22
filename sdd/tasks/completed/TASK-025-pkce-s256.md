# TASK-025: P1 — PKCE (S256)

**Feature**: Production-grade 3LO (Three-Legged OAuth2)
**Spec**: `sdd/specs/oauth2-3lo-implementation.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-024
**Assigned-to**: unassigned

---

## Context

Implements **Module 3** of FEAT-093. Adds PKCE capture at `authorize` and verification at
`token`, with S256 required for public clients. See spec §3 M3.

---

## Scope

- Add a pure verifier helper (e.g. `oauth2/pkce.py`): `verify(verifier, challenge, method)`
  — `S256` → `base64url(sha256(verifier)) == challenge`; `plain` → equality. Use
  `hmac.compare_digest`.
- `authorize`: capture `code_challenge` + `code_challenge_method` (default reasoning per
  config) and persist on the auth code.
- `token` (authorization_code): if a challenge was stored, require `code_verifier` and
  verify; failure → `invalid_grant`. For public clients with
  `OAUTH_REQUIRE_PKCE_PUBLIC=True`, require PKCE and **reject `plain`** (S256 only).
- Config: honor `OAUTH_REQUIRE_PKCE_PUBLIC` (default `True`).

**NOT in scope**: confidential-client secret auth (TASK-024); rotation (TASK-026).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/pkce.py` | CREATE | Pure S256/plain verifier |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | Capture + verify PKCE; enforce S256 for public |
| `navigator_auth/conf.py` | MODIFY | `OAUTH_REQUIRE_PKCE_PUBLIC` |
| `tests/test_oauth2_pkce.py` | CREATE | S256 match/mismatch, public-requires-S256 |

---

## Implementation Notes

### Key Constraints
- Verifier is a pure function — unit-testable with no server/Redis/DB (Option C discipline).
- Constant-time comparison only; never log verifiers/challenges.

### References in Codebase
- `navigator_auth/backends/oauth2/models.py` — `code_challenge`/`code_challenge_method`
  already exist on `OauthAuthorizationCode`.

---

## Acceptance Criteria

- [ ] S256 hash match passes; mismatch ⇒ `invalid_grant`.
- [ ] Public client without PKCE, or with `plain` when S256 required, ⇒ rejected.
- [ ] Tests pass: `pytest tests/test_oauth2_pkce.py -v`.

---

## Test Specification

```python
# tests/test_oauth2_pkce.py
import pytest
from navigator_auth.backends.oauth2.pkce import verify

class TestPKCE:
    def test_s256_match(self): assert verify(VERIFIER, CHALLENGE_S256, "S256")
    def test_s256_mismatch(self): assert not verify(VERIFIER, "wrong", "S256")
    async def test_public_requires_s256(self, public_client): ...
```

---

## Agent Instructions

1. Read the spec (§3 M3). 2. Verify TASK-024 completed. 3. Index → `in-progress`.
4. Implement. 5. Verify. 6. Move to `completed/`. 7. Index → `done` + Completion Note.

---

## Completion Note

**Completed by**: sdd-worker (claude-sonnet-4-6)
**Date**: 2026-06-22
**Notes**:
- pkce.py (pure S256 verifier, hmac.compare_digest, plain rejected) was created
  as part of TASK-024 commit since backend.py imports it immediately.
- OAUTH_REQUIRE_PKCE_PUBLIC=True added to conf.py in TASK-024 commit.
- backend.py PKCE capture/verify already implemented in TASK-024 commit.
- This commit adds tests/test_oauth2_pkce.py: 21 tests (21 pass).
  Covers RFC 7636 test vector, round-trip, edge cases (None/empty),
  plain/unknown method rejection, config flag presence.
**Deviations from spec**: pkce.py and conf.py changes were in TASK-024 commit;
TASK-025 only required adding the test file.
