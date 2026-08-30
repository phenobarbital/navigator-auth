# TASK-043: Asymmetric signing (RS256/ES256) + JWKS endpoint

**Feature**: FEAT-095 oauth2-for-mcp-agents
**Spec**: `sdd/specs/oauth2-for-mcp-agents.spec.md` (Module 6, decision D4)
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-038
**Assigned-to**: unassigned

---

## Context

Tokens are HS256 with a shared `SECRET_KEY`; third-party/polyglot resource servers can only
validate via introspection. D4: add an optional RS256/ES256 signing path with `kid`
dispatch, `/oauth2/jwks`, and rotation. HS256 stays the default and must remain
**byte-identical** when unconfigured.

**Parallelizable**: touches only `backends/idp/` + one route — no contention with
TASK-039..042 (spec Worktree Strategy).

---

## Scope

- Create `navigator_auth/backends/idp/keys.py`: `SigningKey` model (spec §2) + registry
  loaded from `OAUTH_JWT_KEYS` (PEM file paths or inline; each with `kid`, algorithm,
  `active` flag; **exactly one active signer**, inactive keys verify-only for rotation).
- `IdentityProvider.create_token`: when `OAUTH_JWT_SIGNING_ALG` is RS256/ES256, sign with
  the active private key and set the `kid` header. **4-tuple signature unchanged.**
- `IdentityProvider.decode_token`: select verification key by `kid` header; fall back to
  `SECRET_KEY` HS256 (mixed-token migration window).
- `GET /oauth2/jwks` on `Oauth2Provider`: public JWK Set only (`use: "sig"`, `kid`, no
  private material ever); exclude list. (TASK-039's metadata already advertises `jwks_uri`
  when keys are loaded — config-driven, no code dependency.)
- Unit tests: `test_jwks_document`, `test_rs256_sign_verify_kid`,
  `test_hs256_default_unchanged`; integration `test_asymmetric_e2e`.

**NOT in scope**: changing default signing behavior, `AUTH_TOKEN_ISSUER` semantics, key
*generation* tooling (documented ops runbook in TASK-045).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/idp/keys.py` | CREATE | `SigningKey` + registry + JWK serialization |
| `navigator_auth/backends/idp/__init__.py` | MODIFY | `create_token`/`decode_token` kid dispatch |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `/oauth2/jwks` route |
| `tests/test_oauth2_jwks.py` | CREATE | Sign/verify/rotation/no-leak tests |

---

## Implementation Notes

### Key Constraints
- PyJWT RS256/ES256 requires the `cryptography` package — **verify it is already a
  transitive dependency before touching `pyproject.toml`** (spec §6). If it must be added,
  flag in the completion note.
- `IdentityProvider` is shared by all backends: with default config, output must be
  bit-for-bit unchanged (`test_hs256_default_unchanged` gates this).
- JWKS must never serialize private material — dedicated test.
- Private keys via `SecretStr`; never logged.

### References in Codebase
- `navigator_auth/backends/idp/__init__.py:~330` — `create_token` (4-tuple; keep callers).
- `navigator_auth/backends/jwksutils.py` — existing *outbound* JWKS consumption (Microsoft)
  for JWK shape reference.

---

## Acceptance Criteria

- [ ] RS256-configured tokens carry `kid`; decode dispatches by `kid`; old keys verify,
      only the active key signs
- [ ] `/oauth2/jwks` serves public keys only; metadata advertises it iff keys loaded
- [ ] Unconfigured ⇒ HS256 output identical to pre-feature (regression)
- [ ] Third party validates a token using only the JWK Set (integration)
- [ ] Tests pass: `pytest tests/test_oauth2_jwks.py -v`

---

## Test Specification

```python
# tests/test_oauth2_jwks.py
# fixture rsa_keypair(tmp_path): throwaway RS256 keypair, registry kid="test-1"
# test_jwks_document, test_rs256_sign_verify_kid, test_rotation_old_key_verifies,
# test_hs256_default_unchanged, test_no_private_material_in_jwks, test_asymmetric_e2e
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
