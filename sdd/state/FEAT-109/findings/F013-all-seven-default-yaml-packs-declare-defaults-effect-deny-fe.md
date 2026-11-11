---
id: F013
query_id: "Q001"
type: "wiki_related"
intent: "Follow-up: what the default policy packs loaded by the example contribute (defaults, newest pack)"
executed_at: 2026-11-11T14:49:00Z
parent_id: null
depth: 1
merged_from: [FW-008]
---

# F013 — All seven default YAML packs declare `defaults.effect: deny`; FEAT-105 added auth_model_admin_access.yaml

## Summary

`wikitoolkit related dir:navigator_auth/abac/default_policies` lists 7 packs; a grep shows every one declares
`defaults: effect: deny`. `auth_model_admin_access.yaml` (TASK-120, FEAT-105) is a recent addition granting
superusers `uri:/api/v1/user_identity*`, `user_accounts*`, `partner/tokens*`. None of these packs covers
`/dashboard/`, so the packs neither cause nor fix the 428 — they only make the evaluator non-empty, which
triggers the FW-002 skip. More packs are queued (TASK-145 `mfa_admin_access.yaml`, TASK-150 auth CRUD pack, both active).

## Citations

- path: `navigator_auth/abac/default_policies/auth_model_admin_access.yaml`
  lines: 1-3
  excerpt: |
    version: "1.0"
    defaults:
      effect: deny

- path: `navigator_auth/abac/default_policies/admin_full_access.yaml`
  lines: 2-3
  excerpt: |
    defaults:
      effect: deny

- path: `sdd/tasks/completed/TASK-120-auth-model-policy-pack.md`
  excerpt: |
    TASK-120: Default ABAC policy pack — `auth_model_admin_access.yaml`

## Notes

Same `defaults: effect: deny` at lines 2-3 in business_hours_only, deny_after_hours, engineering_tools,
mcp_services, readonly_agents (1 grep call). Wiki: query "default_policies policy pack YAML TASK-120" → TASK-120 0.70,
dir page 0.12. Open: whether a pack's `defaults.effect` is applied globally by `load_from_directory`
(see `tests/test_default_effect_coercion.py`, `PolicyLoader`).
