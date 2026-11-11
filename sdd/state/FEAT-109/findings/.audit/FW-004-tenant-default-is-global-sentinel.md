---
id: FW-004
query_id: Q001
type: wiki_page
intent: "Follow-up: could a tenant mismatch (classic policies default to org/client 1,1) cause the no-match?"
executed_at: 2026-11-11T14:50:00Z
duration_ms: 1000
parent_id: FW-002
depth: 2
---

# FW-004 — Classic policies default to tenant (1,1), which is the global sentinel; tenant mismatch is unlikely the cause

## Summary

`PolicyAdapter._tenant` coerces a classic policy's `org_id`/`client_id`, defaulting to `(1, 1)`.
`_resolve_tenant` (abac/context.py) resolves the request tenant kwarg → trusted headers → userinfo → `(1, 1)`.
The wiki test `TestE2ETenantScoping.test_e2e_global_policy_applies_to_all` states the `org_id=1` allow policy
grants access to all tenants, and `pgStorage.load_policies` treats `(1,1)` rows as global. So even if user 35
has a non-1 org in userinfo, global classic policies would still apply — this rules tenant scoping down as
the 428 cause (lower than FW-002).

## Citations

- path: `navigator_auth/abac/policies/adapter.py`
  lines: 36-46
  symbol: `PolicyAdapter._tenant`
  excerpt: |
    """Extract and coerce tenant pair from policy dict. Defaults to (1, 1)."""
    return (
        _coerce(policy_dict.get("org_id", 1)),
        _coerce(policy_dict.get("client_id", 1)),
    )

- path: `navigator_auth/abac/policies/adapter.py`
  lines: 186-221
  symbol: `PolicyAdapter._adapt_classic`
  excerpt: |
    subjects_data = {
        'groups': set(policy_dict.get('groups') or []),
        'users': set(raw_subject)
    }
    subjects = SubjectSpec.from_dict(subjects_data)
    ...
    p = ResourcePolicy(name=name, effect=effect, resources=final_resources, ...,
                       org_id=org_id, client_id=client_id)

- path: `navigator_auth/abac/context.py`
  lines: 29-79
  symbol: `_resolve_tenant`
  excerpt: |
    Priority:
      1. Explicit kwarg ... 2. Request headers X-Org-Id / X-Client-Id (only when
      ABAC_TENANT_TRUST_HEADERS ...) 3. userinfo dict ... 4. Default (1, 1) — global sentinel.

- path: `tests/test_tenant_scoping.py`
  symbol: `TestE2ETenantScoping.test_e2e_global_policy_applies_to_all`
  excerpt: |
    The org_id=1 allow policy grants access to all tenants for non-blocked tools.

## Notes

Wiki pages: `sym:navigator_auth/abac/policies/adapter.py#PolicyAdapter._tenant`,
`sym:navigator_auth/abac/context.py#_resolve_tenant`, query "evaluator check_access tenant ..." (test page score 0.00).
Read adapter.py:186-249 directly (1 file read). Open sub-question: how a classic policy with EMPTY groups/users
(`public_dashboard`) is matched by `SubjectSpec.from_dict` — if empty subjects mean "match nobody", the policy would
fail even once loaded into the evaluator.
[cross-lane: type=read, intent=check SubjectSpec.from_dict semantics for empty groups+users (match-all vs match-none)]
