---
id: F002
query_id: "Q004, Q014, Q003"
type: "git_log, grep, wiki_query"
intent: "Locate the 'is not Authenticated' warning (middleware.py:43)"
executed_at: 2026-11-11T14:45:00Z
parent_id: null
depth: 0
merged_from: [FC-002, FG-003, FW-006]
---

# F002 — "Access to X is not Authenticated" is a WARNING in abac_middleware for every unauthenticated, non-excluded request

## Summary

*[FC-002]* The only source of the message is `navigator_auth/abac/middleware.py:43` (`abac_middleware`), logged
via `navconfig.logging.logging` (the stdlib root logger, hence `root(middleware.py:43)`). It is an
informational pass-through: the request still reaches the handler; it only means "ABAC skipped because
the request is anonymous". Skips happen for OPTIONS, `SystemRoute` (404), the per-app exclude list
(`fnmatch` over `app["auth_exclude_list"]`), and three hard-coded `/api/v1/abac/*` paths. Browser probe
paths (`/favicon.ico`, `/.well-known/appspecific/com.chrome.devtools.json`, `/client-config`) are not
routes in the example and are not in the exclude list. There is also a duplicated, unreachable
`except (TypeError, KeyError)` clause (lines 47-56).

*[FG-003]* `examples/policy_server.py` has not changed since 1e3ebbc (2026-06-30 "PDP policy and config
auth"), so the 428 regression comes from library code or data it loads, not from the example.
The example calls `auth.setup(app)` (line 533) **before** `pdp.setup(app)` (line 589), so the
abac-middleware reordering in f2885be does not alter its middleware order. The example loads
`navigator_auth/abac/default_policies/` twice — via `YAMLStorage` (550) and
`evaluator.load_from_directory` (560). `navigator_auth/middlewares/` only changed in 416a5f8
(CSRF scoping, 2026-10-08). No commit in the window touches JWT secret handling.

*[FW-006]* The `middleware.py:43` warning comes from `navigator_auth/abac/middleware.py::abac_middleware` (wiki score 1.00):
after skipping OPTIONS, `SystemRoute` (404s), the per-app `AUTH_EXCLUDE_LIST_KEY` fnmatch patterns and three
hard-coded ABAC endpoints, it does `logging.warning(f'Access to {request.path} is not Authenticated.')` and
**still calls the handler** (no deny). It logs on the root logger (`navconfig.logging.logging`), matching
`root(middleware.py:43)`. The default exclude list (`conf.EXCLUDE_DEFAULTS` + `ROUTES_EXCLUDED`) has no
`/favicon.ico`, `/.well-known/*` or `/client-config`, and the example only excludes `/`, `/login`, `/logout`
(FW-003). So the warnings are pure log noise for browser/devtools probes — the level (WARNING for a
pass-through) and the missing well-known excludes are the defect.

## Citations

- path: `navigator_auth/abac/middleware.py`
  lines: 1-13
  symbol: `exceptions`
  excerpt: |
    5  from navconfig.logging import logging
    6  from navigator_auth.conf import AUTH_EXCLUDE_LIST_KEY
    9  exceptions = (
    10     "/api/v1/abac/authorize",
    11     "/api/v1/abac/is_allowed",
    12     "/api/v1/abac/reload"
    13 )

- path: `navigator_auth/abac/middleware.py`
  lines: 16-58
  symbol: `abac_middleware`
  excerpt: |
    28  if isinstance(request.match_info.route, SystemRoute):  # eg. 404
    29      return await handler(request)
    33  for pattern in request.app.get(AUTH_EXCLUDE_LIST_KEY, ()):
    34      if fnmatch.fnmatch(request.path, pattern):
    35          return await handler(request)
    42  if request.get('authenticated', False) is False:
    43      logging.warning(f'Access to {request.path} is not Authenticated.')
    44      return await handler(request)

- path: `navigator_auth/abac/middleware.py`
  lines: 46-56
  symbol: `abac_middleware`
  excerpt: |
    46      response = await request.app['security'].authorize(request=request)
    47  except (TypeError, KeyError) as ex:
    52  except (TypeError, KeyError) as ex:   # duplicate, unreachable

- path: `navigator_auth/conf.py`
  lines: 48, 63-72
  symbol: `EXCLUDE_DEFAULTS`
  excerpt: |
    48  AUTH_EXCLUDE_LIST_KEY = "auth_exclude_list"
    63  EXCLUDE_DEFAULTS: list[str] = [
    64      "/static/",
    70  _extra_excluded = [e.strip() for e in config.get("ROUTES_EXCLUDED", fallback="").split(",")]
    72  exclude_list = EXCLUDE_DEFAULTS + [e for e in _extra_excluded if e]

- path: `navigator_auth/auth.py`
  lines: 844-853
  symbol: `AuthHandler.add_exclude_list`
  excerpt: |
    844  def add_exclude_list(self, path: str) -> None:
    845      """Idempotent: append path only if not already present.
    847          path: URL pattern (fnmatch glob) to add to the per-app exclude list.
    850      lst: list[str] = self.app[AUTH_EXCLUDE_LIST_KEY]

- path: `navigator_auth/auth.py`
  lines: 734-744
  symbol: `AuthHandler.setup`
  excerpt: |
    737  # abac_middleware is already registered in front of them (outermost):
    739  if abac_middleware in mdl:
    740      mdl.remove(abac_middleware)
    741      mdl.append(abac_middleware)

- path: `examples/policy_server.py`
  lines: 533-589
  symbol: `auth.setup | pdp.setup`
  excerpt: |
    533:    auth.setup(app)
    544:    default_policies_dir = (... / "navigator_auth" / "abac" / "default_policies"
    550:        yaml_storage = YAMLStorage(directory=str(default_policies_dir))
    560:        evaluator.load_from_directory(default_policies_dir)
    572:    pdp = PDP(
    589:    pdp.setup(app)

- path: `navigator_auth/middlewares/csrf.py`
  lines: n/a
  symbol: `csrf middleware`
  excerpt: |
    416a5f8 2026-10-08 fix(csrf): scope the check by authentication mechanism, not by Authorization header
    (auth.py +7, conf.py +18/-2, middlewares/csrf.py +34/-11)

- path: `navigator_auth/conf.py`
  lines: n/a
  symbol: `AZURE_FLOW_TTL`
  excerpt: |
    e23a48a/e44c9eb 2026-10-23 (FEAT-103 external-provider-token-capture), 1d6d5ed/e3ed500 passkey
    settings 2026-10-02, plus black/revert churn; no JWT-secret or ABAC_DEFAULT_EFFECT change

## Notes

*[FC-002]* - Runtime introspection of `create_app()` (aiohttp 3.14.3): middleware order is
  `cookie_to_bearer_middleware, middleware, auth_middleware×4, csrf, security, version, abac_middleware`;
  no catch-all route exists. aiohttp's 404 `MatchInfoError.route` IS a `SystemRoute` (verified in a REPL),
  so a true 404 should be skipped at line 28 — yet the user's log shows the warning for `/favicon.ico`.
  Unresolved: either the request matched something at runtime (e.g. the 2nd unnamed `middleware`
  rewrites match_info) or the user's running build differs. Needs a live repro.
- The effective exclude list also contains `/admin` (from env `ROUTES_EXCLUDED`) — the example's
  `/admin/` route is therefore NOT excluded (fnmatch is exact), but this env value is surprising.
- Fix shape is a design choice: downgrade to DEBUG, or add a quiet-path list
  (favicon/.well-known/devtools), or both.

*[FG-003]* - Example history (all time): 1e3ebbc 2026-06-30, ea8c599 2026-04-16 "add default value for pep
  evaluator", 8148367/27b478b 2026-04-02 (initial PBAC).
- Every file in default_policies/ already declared `defaults: effect: deny` before f6be206, so the
  new pack does not flip the default effect by itself (git grep at HEAD).
- [cross-lane: type=read, intent=read evaluator.load_from_directory + YAMLStorage to see how
  file-level `defaults.effect` and duplicate loading interact, and which policy (if any) in the
  example should grant uri:/dashboard/]
- [cross-lane: type=grep, intent=find which middleware logs "is not Authenticated" at
  middleware.py:43 — not under navigator_auth/middlewares history; may be in navigator-session
  or navigator core]

*[FW-006]* Wiki pages: `sym:navigator_auth/abac/middleware.py#abac_middleware` (1.00), `file:navigator_auth/abac/middleware.py`
(0.94), `file:navigator_auth/conf.py`. Also seen: duplicated identical `except (TypeError, KeyError)` block in the
same function (dead code). `/.well-known/appspecific/com.chrome.devtools.json` and `/favicon.ico` likely 404 →
but SystemRoute is only for unmatched routes; if the example has a catch-all/static route they won't be SystemRoute.
`tests/test_probes.py` (score 0.18) mentions a "security warning for hosts that repeatedly probe the server
unauthenticated" — a separate probe tracker exists; demoting this log must not break it.
[cross-lane: type=grep, intent=where does /client-config come from (example route or frontend fetch) and is it a 404 SystemRoute]
[cross-lane: type=read, intent=check tests/test_probes.py to see if it depends on this warning]
