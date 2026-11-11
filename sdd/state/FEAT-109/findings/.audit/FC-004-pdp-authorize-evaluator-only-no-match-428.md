---
id: FC-004
query_id: Q005
type: read
intent: "Locate the 'No Matching Policies' deny and the 428 status; read the PDP evaluation path"
executed_at: 2026-11-11T14:47:00Z
duration_ms: 1500
parent_id: null
depth: 1
---

# FC-004 — PDP.authorize consults only the PolicyEvaluator; classic add_policy() policies never reach it, and the startup guard skips storage when the evaluator is pre-loaded

## Summary

`PDP.authorize` delegates to `evaluator.check_access(ctx, ResourceType.URI, request.path, action)` and
raises `PreconditionFailed` (HTTP 428, "No Matching Policies were found, Deny access.") when the result is
not allowed AND no policy matched. `PDP.add_policy()` only appends to `self._policies` — it never adapts
the policy into the evaluator. Policies reach the evaluator only through `_load_policy_dicts`
(`PolicyAdapter.adapt_batch` → `evaluator.load_policies`), called from `_load_policies` at startup — but
`_load_policies` returns early if the evaluator index is already non-empty ("skipping on-startup storage
load to prevent duplicates"). So in a setup where the caller pre-populates the evaluator (as the example
does), neither the classic `add_policy()` policies nor the DB/YAML storage policies are evaluated.
The same 428 is raised from two other PDP paths (filter_files ~544, and ~653).

## Citations

- path: `navigator_auth/abac/pdp.py`
  lines: 103-108
  symbol: `PDP.add_policy`
  excerpt: |
    103  def add_policy(self, policy: Policy):
    104      self._policies.append(policy)
    105      self.sorted_policies()

- path: `navigator_auth/abac/pdp.py`
  lines: 110-121
  symbol: `PDP._load_policies`
  excerpt: |
    111  # Guard: if the evaluator was pre-populated externally (e.g. by
    112  # setup_pbac / enable_pbac loading via PolicyLoader), skip the
    113  # on-startup storage load to avoid duplicating or corrupting
    115  if self._evaluator._index.all():
    116      self.logger.info(
    117          "Evaluator already has %d policies loaded externally; "
    118          "skipping on-startup storage load to prevent duplicates.",
    121      return

- path: `navigator_auth/abac/pdp.py`
  lines: 142-153
  symbol: `PDP._load_policy_dicts`
  excerpt: |
    144  resource_policies, warnings = PolicyAdapter.adapt_batch(policies)
    148  # Also keep them in self._policies for backward compatibility
    150  self._policies.extend(resource_policies)
    153  self._evaluator.load_policies(resource_policies)

- path: `navigator_auth/abac/pdp.py`
  lines: 393-443
  symbol: `PDP.authorize`
  excerpt: |
    410  action = PolicyAdapter.METHOD_ACTION_MAP.get(request.method, "uri:read")
    416      evaluator = self._evaluator
    419  result = evaluator.check_access(
    420      ctx, ResourceType.URI, request.path, action,
    436  if not result.allowed:
    437      if result.matched_policy:
    438          raise AccessDenied(f"Access Denied: {result.reason}")
    440          raise PreconditionFailed(
    441              "No Matching Policies were found, Deny access."

- path: `navigator_auth/abac/pdp.py`
  lines: 540-546, 653-654
  symbol: `PDP.filter_files`
  excerpt: |
    540  result = evaluator.filter_resources(
    543  if not result.allowed and not result.denied:
    544      raise PreconditionFailed(
    545          "No Matching Policies were found, Deny access."

- path: `navigator_auth/abac/errors.py`
  lines: 77-80
  symbol: `PreconditionFailed`
  excerpt: |
    77  def PreconditionFailed(reason: Union[str, dict], **kwargs) -> web.HTTPError:
    80      reason=msg, **kwargs, status=428

## Notes

- 428 is semantically "Precondition Required"; 412 is "Precondition Failed" — the helper name and status
  disagree (minor, pre-existing; `errors.py:70` maps 412→HTTPPreconditionFailed).
- The error propagates out of `abac_middleware` because it only catches `(TypeError, KeyError)` (FC-002).
- [cross-lane: type=git_log, intent=commit that added the _index.all() guard in PDP._load_policies (likely the yaml double-load fix) — candidate regression for "was working before"]
- [cross-lane: type=git_log, intent=commit that switched PDP.authorize from iterating self._policies to evaluator.check_access]
