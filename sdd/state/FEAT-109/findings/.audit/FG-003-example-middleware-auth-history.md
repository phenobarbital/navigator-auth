---
id: FG-003
query_id: Q014
type: git_log
intent: "Recent commits on the example and middlewares"
executed_at: 2026-11-11T14:49:00Z
duration_ms: 1300
parent_id: null
depth: 0
---

# FG-003 — policy_server.py untouched since June; auth.py/conf.py changed for identity, CSRF, sessions

## Summary

`examples/policy_server.py` has not changed since 1e3ebbc (2026-06-30 "PDP policy and config
auth"), so the 428 regression comes from library code or data it loads, not from the example.
The example calls `auth.setup(app)` (line 533) **before** `pdp.setup(app)` (line 589), so the
abac-middleware reordering in f2885be does not alter its middleware order. The example loads
`navigator_auth/abac/default_policies/` twice — via `YAMLStorage` (550) and
`evaluator.load_from_directory` (560). `navigator_auth/middlewares/` only changed in 416a5f8
(CSRF scoping, 2026-10-08). No commit in the window touches JWT secret handling.

## Citations

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

- path: `navigator_auth/auth.py`
  lines: 734-744
  symbol: `AuthHandler.setup`
  excerpt: |
    f2885be 2026-09-30: if abac_middleware in mdl: mdl.remove(abac_middleware); mdl.append(abac_middleware)

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

- Example history (all time): 1e3ebbc 2026-06-30, ea8c599 2026-04-16 "add default value for pep
  evaluator", 8148367/27b478b 2026-04-02 (initial PBAC).
- Every file in default_policies/ already declared `defaults: effect: deny` before f6be206, so the
  new pack does not flip the default effect by itself (git grep at HEAD).
- [cross-lane: type=read, intent=read evaluator.load_from_directory + YAMLStorage to see how
  file-level `defaults.effect` and duplicate loading interact, and which policy (if any) in the
  example should grant uri:/dashboard/]
- [cross-lane: type=grep, intent=find which middleware logs "is not Authenticated" at
  middleware.py:43 — not under navigator_auth/middlewares history; may be in navigator-session
  or navigator core]
