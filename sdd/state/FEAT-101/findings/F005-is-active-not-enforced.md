# F005 — No login path checks `is_active`
- query: grep is_active in backends/basic.py, abstract.py, external.py, exchange.py; read idp/__init__.py:124-198
- citations: models.py:58 `User.is_active: bool = Column(required=True, default=True)`; idp/__init__.py:124 `user_from_id(uid: int)` and :146 `get_user(login)` search `user_search` (AUTH_USER_VIEW, conf.py:133, default navigator_auth.models.User) with no active filter.
- digest: Resolves brainstorm "not verified" item: BasicAuth does NOT reject inactive users (unless a deployment's AUTH_USER_VIEW filters them). E9 must be implemented explicitly in PasskeyAuth; whether to also fix BasicAuth is a scope decision.
- confidence: high (code), medium (deployment views may filter)
