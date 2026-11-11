---
id: FW-001
query_id: Q001
type: wiki_query
intent: "Orient: PBAC policy decision point and 'No Matching Policies' deny path"
executed_at: 2026-11-11T14:44:00Z
duration_ms: 900
parent_id: null
depth: 0
---

# FW-001 — PDP.authorize raises PreconditionFailed (428) when the evaluator finds no matching policy

## Summary

`wikitoolkit query` → `sym:navigator_auth/abac/pdp.py#PDP.authorize` (score 1.00). `PDP.authorize`
evaluates ONLY through `self._evaluator.check_access(ctx, ResourceType.URI, request.path, action, ...)`
(or a per-tenant evaluator when `ABAC_TENANT_SQL_FILTERING`). When the result is not allowed and
`result.matched_policy` is empty it raises `PreconditionFailed("No Matching Policies were found, Deny access.")`
— the exact 428 text in the report. A matched deny raises `AccessDenied` instead. So the 428 means the
evaluator holds no policy matching `/dashboard/` for this user, not that a deny policy fired.

## Citations

- path: `navigator_auth/abac/pdp.py`
  lines: 397-448
  symbol: `PDP.authorize`
  excerpt: |
    result = evaluator.check_access(
        ctx, ResourceType.URI, request.path, action,
        org_id=ctx.org_id, client_id=ctx.client_id,
    )
    ...
    if not result.allowed:
        if result.matched_policy:
            raise AccessDenied(f"Access Denied: {result.reason}")
        else:
            raise PreconditionFailed(
                "No Matching Policies were found, Deny access."
            )

- path: `navigator_auth/abac/guardian.py`
  symbol: `Guardian.authorize`
  excerpt: |
    (wiki sym:navigator_auth/abac/guardian.py#Guardian.authorize, score 0.95 — PEP/Guardian front PDP.authorize)

## Notes

Wiki page: `sym:navigator_auth/abac/pdp.py#PDP.authorize` (score 1.00). Wiki reports 15 stale sources — line
numbers are from the wiki symbol index; codebase lane should confirm against the working tree.
[cross-lane: type=read, intent=confirm PDP.authorize lines and how abac_middleware/Guardian maps PreconditionFailed to HTTP 428]
