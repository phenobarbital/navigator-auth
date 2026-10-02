# F010 — How protected routes get `request.user`
- citations: auth.py:1062 `_auth_middleware` sets `request.user` and `request["authenticated"] = True` (bearer token or session); auth.py `api_create_token` pattern: `if not request.get("authenticated", False): raise self.Unauthorized(...)`; `user = request.user`; uses `user.user_id`; decorators.py:170 `is_authenticated()` decorator; identities.py:78 `is_authenticated` column.
- digest: Resolves "not verified": enrollment endpoints should gate on `request.get("authenticated")` (existing convention) rather than `getattr(user, "is_authenticated")`, and read `user.user_id` (brainstorm skeleton uses `user.id`).
- confidence: medium-high (attribute name on session user object inferred from api_create_token)
