# F007 — User PK is integer `user_id` in schema AUTH_DB_SCHEMA (default "auth")
- citations: models.py:39 `class User(Model)`; models.py:42 `user_id: int = Column(primary_key=True, db_default="auto")`; models.py:68-70 Meta schema=AUTH_DB_SCHEMA; conf.py:32 `AUTH_DB_SCHEMA` fallback "auth"; models.py:77-114 `UserIdentity` (table user_identities, fk "user_id|username") as sibling precedent.
- digest: `user_id integer` FK to auth.users(user_id) is correct; table schema should follow AUTH_DB_SCHEMA rather than hardcoded `auth`.
- confidence: high
