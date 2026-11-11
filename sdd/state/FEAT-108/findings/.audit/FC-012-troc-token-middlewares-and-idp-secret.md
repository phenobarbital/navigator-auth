---
id: FC-012
query_id: Q020
type: read
intent: "TrocToken / TokenAuth middlewares: do they act on a 3LO bearer token? (+Q021 IdP secret)"
executed_at: 2026-11-11T14:44:00Z
duration_ms: 700
parent_id: null
depth: 0
---

# FC-012 — TrocToken/TokenAuth middlewares pass the 3LO bearer through; the IdP signs with conf.SECRET_KEY

## Summary

The TrocToken and TokenAuth middlewares (installed because the local settings enable
those backends, FC-003) run before AuthHandler's middleware; each calls its own
backend-level `verify_exceptions` and, for a bearer that isn't theirs, hands the
request on unchanged (the "MIDDLEWARE: TrocToken" debug line). They are noise, not a
cause. The IdP signs and verifies HS256 tokens with the module-level
`conf.SECRET_KEY` (imported at idp/__init__.py:30) — the 6-byte value from
`env/.env`, hence the InsecureKeyLengthWarning on encode and decode.

## Citations

- path: `navigator_auth/backends/troc.py`
  lines: 210-218
  symbol: `TrocToken.auth_middleware`
  excerpt: |
    if await self.verify_exceptions(request):
        return await handler(request)
    self.logger.debug(f"MIDDLEWARE: {self.__class__.__name__}")
    try:
        payload = None
        token = await self.get_payload(request)
        if not token:
            return await handler(request)

- path: `navigator_auth/backends/token.py`
  lines: 195-200
  symbol: `TokenAuth.auth_middleware`
  excerpt: |
    if await self.verify_exceptions(request):
        return await handler(request)
    tenant, jwt_token = await self.get_payload(request)
    if not tenant:
        return await handler(request)

- path: `navigator_auth/backends/idp/__init__.py`
  lines: 30, 432, 494
  symbol: `IdentityProvider.create_token / decode_token`
  excerpt: |
    SECRET_KEY,
    jwt_token = jwt.encode(payload, SECRET_KEY, AUTH_JWT_ALGORITHM, json_encoder=DefaultEncoder)
    self.logger.debug(f"Decoded Token: {payload!s}")

## Notes

The short key is a local-environment issue (env/.env), not a code defect; the
example could still guard against it by passing its own key or warning at startup.
Because SECRET_KEY is bound at import time, `os.environ.setdefault` in the example
cannot change it once navconfig has loaded env/.env.
