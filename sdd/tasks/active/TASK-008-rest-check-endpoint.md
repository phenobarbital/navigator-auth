# TASK-008: REST Check Endpoint

**Feature**: FEAT-001 — policy-based-access-control
**Module**: Module 8 — REST Check Endpoint
**Status**: in-progress

## Description

Add `POST /api/v1/abac/check` endpoint that accepts `{user, resource, action}` and returns the PBAC decision.

## Files

- **MODIFY**: `navigator_auth/abac/pdp.py` (register route)
- **MODIFY**: `navigator_auth/abac/guardian.py` (add check handler)

## Classes/Functions

- `PEP.check(request)` — handler for POST /api/v1/abac/check
- Response: `{"allowed": bool, "effect": str, "policy": str, "reason": str}`

## Acceptance Criteria

- [ ] `POST /api/v1/abac/check` endpoint registered
- [ ] Accepts `{user, resource, action}` JSON body
- [ ] Returns `{allowed, effect, policy, reason}`
- [ ] Uses PolicyEvaluator for resource-based checks
- [ ] Falls back to PDP authorize for URI-based checks

## Completion Note

_To be filled on completion._
