---
id: FW-006
query_id: Q003
type: wiki_query
intent: "Orient: auth middleware unauthenticated access warning"
executed_at: 2026-11-11T14:53:00Z
duration_ms: 700
parent_id: null
depth: 0
---

# FW-006 — abac_middleware logs WARNING for every unauthenticated, non-excluded request, then lets it through

## Summary

The `middleware.py:43` warning comes from `navigator_auth/abac/middleware.py::abac_middleware` (wiki score 1.00):
after skipping OPTIONS, `SystemRoute` (404s), the per-app `AUTH_EXCLUDE_LIST_KEY` fnmatch patterns and three
hard-coded ABAC endpoints, it does `logging.warning(f'Access to {request.path} is not Authenticated.')` and
**still calls the handler** (no deny). It logs on the root logger (`navconfig.logging.logging`), matching
`root(middleware.py:43)`. The default exclude list (`conf.EXCLUDE_DEFAULTS` + `ROUTES_EXCLUDED`) has no
`/favicon.ico`, `/.well-known/*` or `/client-config`, and the example only excludes `/`, `/login`, `/logout`
(FW-003). So the warnings are pure log noise for browser/devtools probes — the level (WARNING for a
pass-through) and the missing well-known excludes are the defect.

## Citations

- path: `navigator_auth/abac/middleware.py`
  lines: 16-58
  symbol: `abac_middleware`
  excerpt: |
    for pattern in request.app.get(AUTH_EXCLUDE_LIST_KEY, ()):
        if fnmatch.fnmatch(request.path, pattern):
            return await handler(request)
    if request.path in exceptions:
        return await handler(request)
    if request.get('authenticated', False) is False:
        logging.warning(f'Access to {request.path} is not Authenticated.')
        return await handler(request)

- path: `navigator_auth/conf.py`
  symbol: `EXCLUDE_DEFAULTS`
  excerpt: |
    EXCLUDE_DEFAULTS: list[str] = [
        "/static/", "/api/v1/login", "/api/v1/logout",
        "/api/v1/forgot-password", "/api/v1/reset-password",
    ]
    exclude_list = EXCLUDE_DEFAULTS + [e for e in _extra_excluded if e]

## Notes

Wiki pages: `sym:navigator_auth/abac/middleware.py#abac_middleware` (1.00), `file:navigator_auth/abac/middleware.py`
(0.94), `file:navigator_auth/conf.py`. Also seen: duplicated identical `except (TypeError, KeyError)` block in the
same function (dead code). `/.well-known/appspecific/com.chrome.devtools.json` and `/favicon.ico` likely 404 →
but SystemRoute is only for unmatched routes; if the example has a catch-all/static route they won't be SystemRoute.
`tests/test_probes.py` (score 0.18) mentions a "security warning for hosts that repeatedly probe the server
unauthenticated" — a separate probe tracker exists; demoting this log must not break it.
[cross-lane: type=grep, intent=where does /client-config come from (example route or frontend fetch) and is it a 404 SystemRoute]
[cross-lane: type=read, intent=check tests/test_probes.py to see if it depends on this warning]
