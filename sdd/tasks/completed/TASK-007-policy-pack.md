# TASK-007: Ready-to-Use Policy Pack

**Feature**: FEAT-001 — policy-based-access-control
**Module**: Module 7 — Ready-to-Use Policy Pack
**Status**: in-progress

## Description

Ship YAML policy templates for common scenarios.

## Files

- **CREATE**: `navigator_auth/abac/default_policies/admin_full_access.yaml`
- **CREATE**: `navigator_auth/abac/default_policies/business_hours_only.yaml`
- **CREATE**: `navigator_auth/abac/default_policies/engineering_tools.yaml`
- **CREATE**: `navigator_auth/abac/default_policies/readonly_agents.yaml`
- **CREATE**: `navigator_auth/abac/default_policies/mcp_services.yaml`
- **CREATE**: `navigator_auth/abac/default_policies/deny_after_hours.yaml`

## Acceptance Criteria

- [ ] At least 6 YAML policy templates shipped
- [ ] All parse without error using PolicyLoader
- [ ] Cover common access scenarios
- [ ] Follow YAML policy schema from spec

## Completion Note

_To be filled on completion._
