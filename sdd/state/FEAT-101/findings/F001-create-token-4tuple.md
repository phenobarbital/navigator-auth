# F001 — `IdentityProvider.create_token` returns a 4-tuple
- query: read navigator_auth/backends/idp/__init__.py:379-400
- citations: navigator_auth/backends/idp/__init__.py:379 (`create_token`), docstring "Returns: (jwt_token, refresh_token, exp, scheme) — 4-tuple"; navigator_auth/backends/basic.py:226 `token, refresh_token, exp, scheme = self._idp.create_token(...)`; navigator_auth/auth.py `api_refresh_token` unpacks 4.
- digest: Brainstorm skeleton unpacks 3 values (`token, exp, scheme`) → would raise ValueError, swallowed by the broad except → login returns False/403. Contradicts brainstorm "verified" table.
- confidence: high
