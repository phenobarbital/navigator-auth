# F002 — `BasicAuth.open_session` already encapsulates post-validation tail
- query: read navigator_auth/backends/basic.py:150-312
- citations: basic.py:154 `_JWT_EXTRA_KEYS = ("auth_method", "auth_origin", "external_expires_at")`; basic.py:171 `async def open_session(self, request, user, extra=None, expiration=None) -> dict`; basic.py:226-257 jti recording into `access_token_storage` (FEAT-098 revocation); basic.py:259 `userdata["refresh_token"]`; basic.py:262 default `auth_method="basic"` unless in extra; basic.py:311 `authenticate` → `open_session`.
- precedent: navigator_auth/backends/exchange.py:31 `class TokenExchangeAuth(BasicAuth)` → exchange.py:216 `return await self.open_session(request, user, extra=extra, expiration=cap)`. Introduced by commit 458084c (TASK-046).
- digest: PasskeyAuth should subclass BasicAuth (or otherwise call open_session) with `extra={"auth_method": "passkey"}`, not re-copy the tail. Copying would miss jti revocation (password-reset revocation), refresh_token and BASIC_USER_MAPPING. `auth_method` also lands in the JWT.
- confidence: high
