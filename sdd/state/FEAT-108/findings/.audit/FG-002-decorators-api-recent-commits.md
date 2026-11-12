---
id: FG-002
query_id: Q031
type: git_log
intent: "Recent commits on decorators.py and api.py."
executed_at: 2026-11-11T14:40:30Z
duration_ms: 250
parent_id: null
depth: 0
---

# FG-002 — decorators.py and api.py: commits in the last 120 days

## Summary

13 commits since 2026-07-14. `decorators.py` changed for ABAC (`check_access`, `policy_allows`,
2026-09-05..10-24), legacy session-user normalization (d31f568, 2026-10-13), `user_session` on
bare-function handlers (1fb8fff, 2026-08-20) and superuser/group guards (2026-07-29).
`api.py` changed only twice: af51e88 (bearer challenge marker, FG-005) and 416a5f8 (records
`AUTH_MECHANISM_APIKEY`, FG-004). No commit touches `APIKeyAuth.authenticate` / its `data["device_id"]`
access or the backend-fallback loop in `is_authenticated` — the crash at api.py:154 and the loop at
decorators.py:217 are not recent regressions.

## Citations

- path: `navigator_auth/decorators.py`
  commits: |
    7300e6d 2026-10-24 fix(user-identities-ownership-abac): resolve review findings — ... fail-closed scrub ...
    257d48c 2026-10-24 feat(user-identities-ownership-abac): TASK-119 — public fail-closed policy_allows()
    d31f568 2026-10-13 feat(fix-organizations-orgid): TASK-100 — Normalize legacy session users at rehydration points
    21a1593 2026-09-05 feat(decorators): add check_access(policy) ABAC decorator
    b9e9069 2026-08-21 testing the user identities
    1fb8fff 2026-08-20 (Jesus) Fix user_session attaching session/user to request on bare-function handlers
    61e871c 2026-07-29 (Henry Cabello) fix(decorators): type-guard _check_superuser groups; bind userinfo in allowed_groups
    8663359 2026-07-29 (Jesus) Add is_superuser decorator to restrict handlers to superusers
    (+ black-formatting commits 42691ab, 2ae0560)

- path: `navigator_auth/backends/api.py`
  commits: |
    416a5f8 2026-10-08 fix(csrf): scope the check by authentication mechanism, not by Authorization header
    af51e88 2026-08-31 feat(oauth2-for-mcp-agents): TASK-044 — OAuth 2.1 / Claude conformance hardening

## Notes

- Absence of recent changes to `APIKeyAuth.authenticate` suggests the `'bool' object is not subscriptable`
  crash is latent and only surfaced because the example's request reached the decorator's backend fallback.
- [cross-lane: type=read, intent=read decorators.is_authenticated _wrap (~line 217) to see when it falls back to calling every backend's authenticate()]
