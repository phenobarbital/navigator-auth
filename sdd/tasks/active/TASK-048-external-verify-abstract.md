# TASK-048: `ExternalAuth.verify_external_token` contract + shared JWT/JWKS helpers

**Feature**: FEAT-096 external-token-exchange
**Spec**: `sdd/specs/external-token-exchange.spec.md` (Module 3)
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Each provider backend must be able to answer "is this bearer token live and
minted for **this** client, and who is it?" with one uniform signature so the
exchange backend stays provider-agnostic. Azure and Google id_tokens are JWTs
verified against a JWKS; this task provides the abstract method and the shared
verification helpers the three provider tasks (TASK-049/050/051) build on.

**Parallelizable**: touches only `backends/external.py` and
`backends/jwksutils.py`; no contention with TASK-046/047. It is a hard
prerequisite of TASK-049/050/051 because it fixes the signature they implement.

---

## Scope

- Add to `ExternalAuth`:
  ```python
  async def verify_external_token(
      self, token: str, token_type: str = "Bearer", id_token: Optional[str] = None
  ) -> tuple[dict, TokenResponse]:
      raise NotImplementedError(f"{self._service_name}: token exchange not supported")
  ```
  Docstring per spec §2 "New Public Interfaces". Raising `NotImplementedError`
  (not `InvalidAuth`) lets the exchange backend distinguish "unsupported
  provider" (400) from "bad token" (401).
- Shared helper on `ExternalAuth`:
  `_verify_jwt(token, *, audience, issuer, jwks_url=None, tenant_id=None, leeway=30) -> dict`
  → decodes with PyJWT using `jwksutils.get_public_key`, enforces `exp`, `aud`
  (accepts str or list), `iss` (str or list), and returns claims. Any failure →
  `InvalidAuth` with a reason code in the message (`bad_signature`,
  `wrong_audience`, `wrong_issuer`, `expired`).
- Shared helper `_require_verified_email(userinfo, *, key="email", verified_key="email_verified") -> str`
  → `InvalidAuth("email_unverified")` when missing/false.
- Extend `jwksutils` so a **static JWKS URL** can be passed (Google publishes
  `https://www.googleapis.com/oauth2/v3/certs`; current helpers derive it from
  OIDC discovery). Keep the per-process cache and its existing behaviour for
  Azure/ADFS callers.
- Reason codes constant set (e.g. `EXCHANGE_REASONS`) exported from
  `external.py` for reuse in logging/tests.
- Unit tests with a throwaway RSA keypair and monkeypatched JWKS fetch.

**NOT in scope**: provider-specific logic (aud values, userinfo calls), the
exchange backend, Basic changes.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/external.py` | MODIFY | Abstract method, `_verify_jwt`, `_require_verified_email`, reason codes |
| `navigator_auth/backends/jwksutils.py` | MODIFY | Accept explicit `jwks_url`; keep cache |
| `tests/test_external_verify_helpers.py` | CREATE | Helper tests |

---

## Implementation Notes

### Pattern to Follow
`backends/adfs.py` already does `jwt.decode(..., key=get_public_key(...))`;
lift that into the helper. Follow the existing `InvalidAuth(message, status=401)`
usage in `backends/basic.py`.

### Key Constraints
- Backends are process-wide singletons: no per-request state on `self`.
- JWKS fetch is blocking `requests` in `jwksutils`; call it via
  `asyncio.get_running_loop().run_in_executor(self.executor, ...)` (the
  `ThreadPoolExecutor` already exists on `BaseAuthBackend`).
- Never log the token; log only `kid`, `iss`, `aud` and the reason code.
- The project runs pytest with `filterwarnings = error`; PyJWT key-length
  warnings must be avoided in fixtures (use a 2048-bit RSA key).

### References in Codebase
- `navigator_auth/backends/jwksutils.py:115` — `get_public_key`.
- `navigator_auth/backends/adfs.py:254` — existing JWKS-based decode.
- `navigator_auth/backends/external.py:552` — `get_identity_userinfo` (style for provider calls).

---

## Acceptance Criteria

- [ ] `ExternalAuth.verify_external_token` exists and raises `NotImplementedError` by default
- [ ] `_verify_jwt` accepts a valid RS256 token; rejects bad signature / wrong `aud` /
      wrong `iss` / expired with the matching reason code in `InvalidAuth`
- [ ] `_require_verified_email` rejects missing and `false` verification
- [ ] `jwksutils` works with an explicit JWKS URL and still with tenant discovery
- [ ] `pytest tests/test_external_verify_helpers.py -v` passes; `ruff check` clean

---

## Test Specification

```python
# tests/test_external_verify_helpers.py
# fixture rsa_keypair (2048-bit) + jwks_doc; monkeypatch jwksutils.get_jwks
# test_verify_jwt_ok
# test_verify_jwt_bad_signature
# test_verify_jwt_wrong_audience / _wrong_issuer / _expired
# test_verify_jwt_accepts_audience_list
# test_require_verified_email_missing / _false / _ok
# test_default_verify_external_token_not_implemented
```

---

## Agent Instructions

1. **Read the spec**; 2. **Check dependencies** (none);
3. **Update index** → in-progress; 4. **Implement**; 5. **Verify**;
6. **Move to completed/**; 7. **Update index** → done; 8. **Fill Completion Note**.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**:
**Date**:
**Notes**:

**Deviations from spec**:
