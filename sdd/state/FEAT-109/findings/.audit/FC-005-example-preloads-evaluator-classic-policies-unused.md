---
id: FC-005
query_id: Q008
type: read
intent: "Read the example server: routes, policies loaded, PDP setup, exclude lists"
executed_at: 2026-11-11T14:48:00Z
duration_ms: 1200
parent_id: null
depth: 0
---

# FC-005 — policy_server.py pre-loads the evaluator, then grants /dashboard/ only through a classic Policy via add_policy()

## Summary

`create_app()` builds a `PolicyEvaluator`, loads the default YAML packs into it
(`evaluator.load_from_directory`) plus five `ResourcePolicy` objects (vector/tool/agent types), then
creates `PDP(storage, yaml_storage, evaluator)` and adds the URI policies (`public_dashboard` for
`urn:uri:/dashboard/`, `admin_panel`, `analytics_business_hours`, …) with `pdp.add_policy()`. Combined with
FC-004 this means: at startup the evaluator is non-empty → `_load_policies` skips storage; the classic URI
policies sit only in `pdp._policies`; `authorize()` asks the evaluator about `uri:/dashboard/` and finds no
match → 428. Exclude list adds only `/`, `/login`, `/logout`. No `/favicon.ico` or `/client-config` route.

## Citations

- path: `examples/policy_server.py`
  lines: 125-132
  symbol: `public_dashboard`
  excerpt: |
    126  public_dashboard = Policy(
    127      name="public_dashboard",
    128      effect=PolicyEffect.ALLOW,
    130      resource=["urn:uri:/dashboard/"],
    131      priority=5,

- path: `examples/policy_server.py`
  lines: 535-538
  symbol: `create_app`
  excerpt: |
    536  auth.add_exclude_list("/")
    537  auth.add_exclude_list("/login")
    538  auth.add_exclude_list("/logout")

- path: `examples/policy_server.py`
  lines: 552-569
  symbol: `create_app`
  excerpt: |
    553  evaluator = PolicyEvaluator(
    559  if default_policies_dir.is_dir():
    560      evaluator.load_from_directory(default_policies_dir)
    563  evaluator.load_policies([
    564      data_science_vectors,

- path: `examples/policy_server.py`
  lines: 571-589
  symbol: `create_app`
  excerpt: |
    572  pdp = PDP(
    573      storage=storage,
    574      yaml_storage=yaml_storage,
    575      evaluator=evaluator,
    579  for policy in [
    580      public_dashboard,
    586      pdp.add_policy(policy)
    589  pdp.setup(app)

- path: `examples/policy_server.py`
  lines: 592-601
  symbol: `create_app` routes
  excerpt: |
    592  app.router.add_get("/", index)
    596  app.router.add_view("/dashboard/", DashboardView)
    597  app.router.add_view("/admin/", AdminView)

## Notes

- Runtime check: `create_app()` registers ~60 resources (oauth2, azure, adfs, abac REST, example views);
  `/.well-known/oauth-*` exist but `/.well-known/appspecific/...` does not.
- Two fix directions (design choice): (a) make `PDP.add_policy` adapt classic policies into the evaluator
  (and/or have `_load_policies` merge instead of skip); (b) change the example to express its URI policies as
  ResourcePolicy/YAML loaded into the evaluator. (a) fixes every caller using the documented add_policy API.
