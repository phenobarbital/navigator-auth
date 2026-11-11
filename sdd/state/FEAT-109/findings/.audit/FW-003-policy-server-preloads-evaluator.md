---
id: FW-003
query_id: Q001
type: wiki_page
intent: "Follow-up: how examples/policy_server.py wires PDP, evaluator and classic policies"
executed_at: 2026-11-11T14:48:00Z
duration_ms: 800
parent_id: FW-001
depth: 1
---

# FW-003 — policy_server.create_app pre-populates the evaluator, then registers /dashboard/ only as a classic add_policy

## Summary

`create_app` builds a `PolicyEvaluator`, calls `evaluator.load_from_directory(default_policies_dir)` and
`evaluator.load_policies([...5 ResourcePolicies...])`, passes it to `PDP(storage=pgStorage, yaml_storage=..., evaluator=evaluator)`,
then adds five classic `Policy` objects via `pdp.add_policy(policy)` — including `public_dashboard`
(`resource=["urn:uri:/dashboard/"]`, ALLOW, priority 5, no groups) and `admin_panel_access`. Combined with FW-002,
the evaluator is non-empty at startup, so the guard skips storage load and the classic policies (the only
ones covering `/dashboard/`) never reach the evaluator → 428 on `/dashboard/` and other classic-covered URLs.
Exclude list in the example: only `/`, `/login`, `/logout`.

## Citations

- path: `examples/policy_server.py`
  lines: 528-603
  symbol: `create_app`
  excerpt: |
    evaluator = PolicyEvaluator(cache_size=1024, cache_ttl_seconds=300)
    if default_policies_dir.is_dir():
        evaluator.load_from_directory(default_policies_dir)
    evaluator.load_policies([data_science_vectors, qa_testing_tools, ...])
    pdp = PDP(storage=storage, yaml_storage=yaml_storage, evaluator=evaluator)
    for policy in [public_dashboard, admin_panel, analytics_business_hours, ...]:
        pdp.add_policy(policy)
    pdp.setup(app)

- path: `examples/policy_server.py`
  symbol: `public_dashboard`
  excerpt: |
    public_dashboard = Policy(
        name="public_dashboard", effect=PolicyEffect.ALLOW,
        resource=["urn:uri:/dashboard/"], priority=5,
    )

- path: `examples/policy_server.py`
  symbol: `create_app`
  excerpt: |
    auth.add_exclude_list("/")
    auth.add_exclude_list("/login")
    auth.add_exclude_list("/logout")
    app.router.add_view("/dashboard/", DashboardView)

## Notes

Wiki page: `sym:examples/policy_server.py#create_app` (score 0.05 on Q001, 0.22 on policy-pack query).
Line numbers for `public_dashboard` not available from the symbol index (module-level assignment).
[cross-lane: type=read, intent=read examples/policy_server.py index()/DashboardView/JWT decode to find the 6-byte HMAC key literal and /client-config route]
