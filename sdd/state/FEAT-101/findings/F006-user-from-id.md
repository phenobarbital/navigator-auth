# F006 — `IdentityProvider.user_from_id` body
- citations: idp/__init__.py:124-144; abstract.py:251-266 `validate_user(login=None, userid=None)` → `self._idp.user_from_id(userid)`.
- digest: Exists; takes int uid, raises UserNotFound on NoDataFound/any error. `validate_user(userid=...)` is a valid path for PasskeyAuth. Note BasicAuth overrides validate_user(login, password) — a BasicAuth subclass must call `self._idp.user_from_id` directly or `BaseAuthBackend.validate_user`.
- confidence: high
