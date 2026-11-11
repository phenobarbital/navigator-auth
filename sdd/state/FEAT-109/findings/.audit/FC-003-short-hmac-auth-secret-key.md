---
id: FC-003
query_id: Q007
type: grep
intent: "Find the JWT HMAC secret source (6-byte key)"
executed_at: 2026-11-11T14:46:00Z
duration_ms: 800
parent_id: null
depth: 0
---

# FC-003 — The 6-byte HMAC key is AUTH_SECRET_KEY from env/.env; no startup length check

## Summary

`SECRET_KEY` is `config.get("AUTH_SECRET_KEY")`; only when unset is a random Fernet key generated.
`env/.env` and `env/prod/.env` both set `AUTH_SECRET_KEY` to a 6-character value (lengths measured,
values not printed); `PARTNER_KEY` is 16 chars. `SECRET_KEY` signs/verifies HS256 JWTs in the IdP
backend (`jwt.encode` at idp/__init__.py:432, authz codes at :250/:267), which is what PyJWT ≥2.10's
`InsecureKeyLengthWarning` (encode line 147, decode line 368) flags. No code in navigator_auth validates
the key length at startup.

## Citations

- path: `navigator_auth/conf.py`
  lines: 305-308
  symbol: `SECRET_KEY`
  excerpt: |
    305  SECRET_KEY = config.get("AUTH_SECRET_KEY")
    306  if not SECRET_KEY:
    307      fernet_key = fernet.Fernet.generate_key()
    308      SECRET_KEY = base64.urlsafe_b64decode(fernet_key)

- path: `navigator_auth/conf.py`
  lines: 318, 344, 349
  symbol: `AUTH_TOKEN_SECRET`
  excerpt: |
    318  AUTH_JWT_ALGORITHM = config.get("JWT_ALGORITHM", fallback="HS256")
    344  PARTNER_KEY = config.get("PARTNER_KEY")
    349  AUTH_TOKEN_SECRET = config.get("AUTH_TOKEN_SECRET", fallback=PARTNER_KEY)

- path: `env/.env`
  lines: n/a
  symbol: `AUTH_SECRET_KEY`
  excerpt: |
    AUTH_SECRET_KEY len=6   (value withheld)
    PARTNER_KEY     len=16  (value withheld)

- path: `navigator_auth/backends/idp/__init__.py`
  lines: 250, 267, 432
  symbol: `SECRET_KEY` JWT use
  excerpt: |
    250  authzcode = jwt.encode(payload, SECRET_KEY, algorithm=AUTH_JWT_ALGORITHM)
    267  payload = jwt.decode(code, SECRET_KEY, algorithms=[AUTH_JWT_ALGORITHM])
    432  jwt_token = jwt.encode(payload, SECRET_KEY, AUTH_JWT_ALGORITHM, json_encoder=DefaultEncoder)

- path: `navigator_auth/backends/token.py`
  lines: 105
  symbol: `AUTH_TOKEN_SECRET` decode
  excerpt: |
    105  payload = jwt.decode(token, AUTH_TOKEN_SECRET, algorithms=[AUTH_JWT_ALGORITHM], leeway=30)

## Notes

- `env/prod/.env` carries the same 6-char value — worth flagging even if it is a dev placeholder.
- `PARTNER_KEY` (16 bytes) also falls below 32 bytes for HS256 when used as `AUTH_TOKEN_SECRET`.
- Fix is config (rotate to ≥32 bytes) plus optionally a startup check that logs/raises on short HMAC keys.
- [cross-lane: type=git_log, intent=when PyJWT was bumped to a version emitting InsecureKeyLengthWarning (uv.lock)]
