# F004 — Public routes go into `app[AUTH_EXCLUDE_LIST_KEY]`, not module `exclude_list`
- citations: conf.py:47 `AUTH_EXCLUDE_LIST_KEY = "auth_exclude_list"`; conf.py:73 module `exclude_list`; basic.py:61 `app[AUTH_EXCLUDE_LIST_KEY].append(...)`; decorators.py:28 and abac/middleware.py:34 read `request.app.get(AUTH_EXCLUDE_LIST_KEY)`.
- digest: Brainstorm skeleton appends to module-level `exclude_list`; current convention is the app-scoped key. login/options must be registered there.
- confidence: high
