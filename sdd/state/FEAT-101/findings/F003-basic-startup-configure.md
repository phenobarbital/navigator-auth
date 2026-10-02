# F003 — BasicAuth.configure / on_startup side effects
- citations: basic.py:52-62 `configure` registers GET `/auth/{_service_name}/check_credentials` and appends to `app[AUTH_EXCLUDE_LIST_KEY]`; basic.py:64-73 `on_startup` creates `self.access_token_storage = AccessTokenStorage()` (attribute name load-bearing for `AuthHandler._token_is_revoked`).
- digest: A BasicAuth subclass inherits these; PasskeyAuth.on_startup must call super() (to keep access_token_storage) and add its Redis pool. Inherited check_credentials route at /auth/passkey/check_credentials is harmless.
- confidence: high
