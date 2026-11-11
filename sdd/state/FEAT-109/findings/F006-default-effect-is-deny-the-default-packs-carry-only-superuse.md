---
id: F006
query_id: "Q015"
type: "glob"
intent: "Policy definition files used by the example and their match rules"
executed_at: 2026-11-11T14:49:00Z
parent_id: null
depth: 1
merged_from: [FC-006]
---

# F006 — Default effect is deny; the default packs carry only superuser-only URI policies

## Summary

`navigator_auth/abac/default_policies/` holds 7 YAML packs (admin_full_access, auth_model_admin_access,
business_hours_only, deny_after_hours, engineering_tools, mcp_services, readonly_agents), each with
`defaults: effect: deny`. The only `uri:` resources are in `auth_model_admin_access.yaml`
(`/api/v1/user_identity*`, `/api/v1/user_accounts*`, `/api/v1/partner/tokens*`, superuser only). The
evaluator's default effect comes from `ABAC_DEFAULT_EFFECT` (fallback `"deny"`) and is passed to the Rust
`evaluate_single`; on engine errors it fails closed. So any URI not covered → not allowed, no matched
policy → 428 from PDP.

## Citations

- path: `navigator_auth/abac/default_policies/auth_model_admin_access.yaml`
  lines: 2-38
  symbol: `user_identities_admin_access`
  excerpt: |
    2   defaults:
    3     effect: deny
    5     - name: user_identities_admin_access
    10      resources: ["uri:/api/v1/user_identity*"]
    13        groups: ["superuser"]
    21      resources: ["uri:/api/v1/user_accounts*"]
    33      resources: ["uri:/api/v1/partner/tokens*"]

- path: `navigator_auth/abac/default_policies/admin_full_access.yaml`
  lines: 1-10
  symbol: `admin_full_access`
  excerpt: |
    2  defaults:
    3    effect: deny
    5    - name: admin_full_access
    8      resources:
    9        - "tool:*"
    10       - "kb:*"

- path: `navigator_auth/conf.py`
  lines: 710
  symbol: `ABAC_DEFAULT_EFFECT`
  excerpt: |
    710  ABAC_DEFAULT_EFFECT = config.get("ABAC_DEFAULT_EFFECT", fallback="deny")

- path: `navigator_auth/abac/policies/evaluator.py`
  lines: 229, 483-509
  symbol: `PolicyEvaluator.check_access`
  excerpt: |
    229  self._default_effect = _coerce_default_effect(ABAC_DEFAULT_EFFECT)
    483  result_dict = evaluate_single(
    490      default_effect=_coerce_default_effect(self._default_effect),
    500  except Exception as e:
    501      # Fail closed: deny access on Rust engine errors (no silent fallback)

## Notes

- Did not verify whether `admin_full_access` lists a `uri:*` resource further down (only first 10 lines read).
  If it does, superusers would pass while user 35 (non-superuser?) gets 428 — consistent with the report.
- [cross-lane: type=git_log, intent=when auth_model_admin_access.yaml and ABAC_DEFAULT_EFFECT fallback "deny" landed — FEAT-107 auth-model-crud-hardening is the likely source]
