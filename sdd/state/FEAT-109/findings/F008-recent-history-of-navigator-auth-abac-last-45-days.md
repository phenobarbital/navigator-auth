---
id: F008
query_id: "Q012"
type: "git_log"
intent: "Recent commits on abac/PDP (regression for 428)"
executed_at: 2026-11-11T14:45:00Z
parent_id: null
depth: 0
merged_from: [FG-001]
---

# F008 — Recent history of navigator_auth/abac/ (last 45 days)

## Summary

12 commits touched `navigator_auth/abac/` since 2026-09-27; only four change behaviour, the
rest are black-format churn on `abac/context.py`. No commit since 2026-10-03 touches the
evaluator, PDP, middleware or YAML storage code — the only later abac change is a new
default policy *data* file (FEAT `user-identities-ownership-abac`, TASK-120). None of the
behaviour commits obviously flips a match into a "No Matching Policies" deny: the cache-key
rewrite (a3706f0) keeps every key component, and the middleware-order fix (f2885be) does not
change the example's order (see FG-003).

## Citations

- path: `navigator_auth/abac/policies/evaluator.py`
  lines: 339-371
  symbol: `PolicyEvaluator._make_cache_key`
  excerpt: |
    a3706f0 2026-10-03 fix(abac): use structured tuple cache key instead of SHA-256 digest
    return (str(user_id), frozenset(user_groups or ()), str(rtype_val), resource_name,
            action, env_str, org_id, client_id, frozenset(scope_key or ()), client_uid or "")

- path: `navigator_auth/abac/pdp.py`
  lines: 357-363
  symbol: `PDP.setup`
  excerpt: |
    f2885be 2026-09-30 fix(abac): keep abac_middleware after the authentication middlewares
    mdl.append(abac_middleware)   # comment only; behaviour moved to AuthHandler.setup

- path: `navigator_auth/abac/default_policies/auth_model_admin_access.yaml`
  lines: 1-39
  symbol: `user_identities_admin_access | user_accounts_admin_access | partner_keys_admin_access`
  excerpt: |
    f6be206 2026-10-24 feat(user-identities-ownership-abac): TASK-120 — auth model ABAC policy pack
    7300e6d 2026-10-24 fix(...): drop dead account:revoke
    defaults: {effect: deny}; three superuser-only allow policies on uri:/api/v1/user_identity*,
    uri:/api/v1/user_accounts*, uri:/api/v1/partner/tokens* (priority 90)

- path: `navigator_auth/abac/context.py`
  lines: n/a
  symbol: `EvalContext`
  excerpt: |
    d7f0520 2026-10-02 feat(passkey-support-backend): TASK-92 — EvalContext auth_method/mfa (+7)
    then 6 black/revert churn commits (1e1666a, 11e1a85, 031b8c9, e919298, 428d244, 5f0b34c, 5c75ffb)

## Notes

- Older relevant commits: e9c242c 2026-09-10 pins Rust glob semantics (`*` never crosses `/`,
  `groups*` does not cover `groups/123`, `**` does); 48b12cc 2026-07-10 "Fix on YAML storage
  overriding policies" (yaml_storage.py, pdp.py).
- [cross-lane: type=read, intent=check whether uri patterns used by policy_server.py for
  /dashboard/ rely on single `*` crossing `/` (e9c242c semantics) and whether the Rust .so in
  navigator_auth/ is stale vs navigator_auth/rs_pep/src/lib.rs]
