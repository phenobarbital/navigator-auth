---
id: FW-007
query_id: Q003
type: wiki_query
intent: "Extra orient: source of the HMAC key used for JWT encode/decode (6-byte key warning)"
executed_at: 2026-11-11T14:54:00Z
duration_ms: 600
parent_id: null
depth: 0
---

# FW-007 — conf.SECRET_KEY = AUTH_SECRET_KEY verbatim, with no minimum length; only the unset fallback is 32 bytes

## Summary

`navigator_auth/conf.py` sets `SECRET_KEY = config.get("AUTH_SECRET_KEY")`; only when it is unset does it fall
back to a random 32-byte Fernet key. There is no length validation, and `AUTH_JWT_ALGORITHM` defaults to `HS256`.
A 6-byte HMAC key therefore means `AUTH_SECRET_KEY` (or a literal key in the example's local JWT decode) is a
6-character string in the dev env — e.g. a placeholder like `secret`. Wiki also shows `SECRET_KEY` is used for
CSRF HMAC (`libs/csrf.py::_key`) and `JWTStrategy` (`middlewares/strategies.py`), so a short key weakens more
than JWTs. Fix candidates: warn/fail at startup when `len(SECRET_KEY) < 32`, and fix the example/env template.

## Citations

- path: `navigator_auth/conf.py`
  symbol: `SECRET_KEY`
  excerpt: |
    SECRET_KEY = config.get("AUTH_SECRET_KEY")
    if not SECRET_KEY:
        fernet_key = fernet.Fernet.generate_key()
        SECRET_KEY = base64.urlsafe_b64decode(fernet_key)
    AUTH_JWT_ALGORITHM = config.get("JWT_ALGORITHM", fallback="HS256")

- path: `navigator_auth/libs/csrf.py`
  symbol: `_key`
  excerpt: |
    ``hmac`` needs bytes; ``SECRET_KEY`` is a ``str`` when ``AUTH_SECRET_KEY`` is set.

- path: `navigator_auth/middlewares/strategies.py`
  symbol: `JWTStrategy`
  excerpt: |
    Extract Bearer token, validate via jwt.decode().

## Notes

Wiki: query "JWT secret key AUTH_SECRET_KEY length HMAC encode token" → `sym:navigator_auth/libs/csrf.py#_key` 1.00,
`JWTStrategy` 0.01; `file:navigator_auth/conf.py` page. conf.py line numbers not taken (wiki file-page offsets ≠ source lines).
PyJWT warns at both encode (api_jwt.py:147) and decode (:368) — same key on both sides.
[cross-lane: type=grep, intent=find AUTH_SECRET_KEY value in env/*.ini/.env used by the example and any hard-coded key in examples/policy_server.py]
