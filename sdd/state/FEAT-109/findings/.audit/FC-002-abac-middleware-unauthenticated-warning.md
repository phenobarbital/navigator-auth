---
id: FC-002
query_id: Q004
type: grep
intent: "Locate the 'is not Authenticated' warning (middleware.py:43)"
executed_at: 2026-11-11T14:45:00Z
duration_ms: 700
parent_id: null
depth: 0
---

# FC-002 — "Access to X is not Authenticated" is a WARNING in abac_middleware for every unauthenticated, non-excluded request

## Summary

The only source of the message is `navigator_auth/abac/middleware.py:43` (`abac_middleware`), logged
via `navconfig.logging.logging` (the stdlib root logger, hence `root(middleware.py:43)`). It is an
informational pass-through: the request still reaches the handler; it only means "ABAC skipped because
the request is anonymous". Skips happen for OPTIONS, `SystemRoute` (404), the per-app exclude list
(`fnmatch` over `app["auth_exclude_list"]`), and three hard-coded `/api/v1/abac/*` paths. Browser probe
paths (`/favicon.ico`, `/.well-known/appspecific/com.chrome.devtools.json`, `/client-config`) are not
routes in the example and are not in the exclude list. There is also a duplicated, unreachable
`except (TypeError, KeyError)` clause (lines 47-56).

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
  lines: 24-44
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
  lines: 735-741
  symbol: `AuthHandler.setup`
  excerpt: |
    737  # abac_middleware is already registered in front of them (outermost):
    739  if abac_middleware in mdl:
    740      mdl.remove(abac_middleware)
    741      mdl.append(abac_middleware)

## Notes

- Runtime introspection of `create_app()` (aiohttp 3.14.3): middleware order is
  `cookie_to_bearer_middleware, middleware, auth_middleware×4, csrf, security, version, abac_middleware`;
  no catch-all route exists. aiohttp's 404 `MatchInfoError.route` IS a `SystemRoute` (verified in a REPL),
  so a true 404 should be skipped at line 28 — yet the user's log shows the warning for `/favicon.ico`.
  Unresolved: either the request matched something at runtime (e.g. the 2nd unnamed `middleware`
  rewrites match_info) or the user's running build differs. Needs a live repro.
- The effective exclude list also contains `/admin` (from env `ROUTES_EXCLUDED`) — the example's
  `/admin/` route is therefore NOT excluded (fnmatch is exact), but this env value is surprising.
- Fix shape is a design choice: downgrade to DEBUG, or add a quiet-path list
  (favicon/.well-known/devtools), or both.
