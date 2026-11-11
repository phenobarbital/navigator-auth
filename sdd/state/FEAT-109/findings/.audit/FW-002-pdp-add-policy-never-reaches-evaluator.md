---
id: FW-002
query_id: Q001
type: wiki_page
intent: "Follow-up: where do classic policies added with PDP.add_policy end up, and does on-startup loading feed them to the evaluator?"
executed_at: 2026-11-11T14:47:00Z
duration_ms: 1200
parent_id: FW-001
depth: 1
---

# FW-002 — PDP.add_policy only appends to PDP._policies; _load_policies skips when the evaluator is pre-populated

## Summary

`PDP.add_policy` appends the classic `Policy` to `self._policies` and sorts — it never adapts it nor calls
`self._evaluator.load_policies`. The only code that pushes policies into the evaluator is `_load_policy_dicts`
(via `PolicyAdapter.adapt_batch` → `self._evaluator.load_policies`), reached from `_load_policies`. But
`_load_policies` returns early when `self._evaluator._index.all()` is non-empty ("Evaluator already has %d
policies loaded externally; skipping on-startup storage load to prevent duplicates."). Since `PDP.authorize`
consults only the evaluator (FW-001), classic policies registered with `add_policy` are invisible to
authorization. The guard is covered by `tests/test_yaml_storage_double_load.py::TestPDPDoubleLoadPrevention`.

## Citations

- path: `navigator_auth/abac/pdp.py`
  lines: 104-106
  symbol: `PDP.add_policy`
  excerpt: |
    def add_policy(self, policy: Policy):
        self._policies.append(policy)
        self.sorted_policies()

- path: `navigator_auth/abac/pdp.py`
  lines: 111-141
  symbol: `PDP._load_policies`
  excerpt: |
    if self._evaluator._index.all():
        self.logger.info(
            "Evaluator already has %d policies loaded externally; "
            "skipping on-startup storage load to prevent duplicates.", ...)
        return
    policies = await self.storage.load_policies()
    self._load_policy_dicts(policies)

- path: `navigator_auth/abac/pdp.py`
  symbol: `PDP._load_policy_dicts`
  excerpt: |
    resource_policies, warnings = PolicyAdapter.adapt_batch(policies)
    # Also keep them in self._policies for backward compatibility
    self._policies.extend(resource_policies)
    self._evaluator.load_policies(resource_policies)

- path: `tests/test_yaml_storage_double_load.py`
  symbol: `TestPDPDoubleLoadPrevention`
  excerpt: |
    class TestPDPDoubleLoadPrevention: PDP._load_policies must not re-load when evaluator is pre-populated.
        def test_load_policies_skips_when_evaluator_has_policies(...)
        def test_reload_policies_always_works(...)

## Notes

Wiki pages: `sym:navigator_auth/abac/pdp.py#PDP.add_policy`, `sym:navigator_auth/abac/pdp.py#PDP._load_policies`,
`file:navigator_auth/abac/pdp.py` (outline), `file:tests/test_yaml_storage_double_load.py` (score 0.08 on Q001).
Neither `_load_policies` nor `_load_policy_dicts` reads the classic objects already in `self._policies` —
so even WITHOUT the guard, add_policy() objects would not be adapted into the evaluator; the guard additionally
skips DB (pgStorage) and YAMLStorage policies. Whether this ever worked depends on history.
[cross-lane: type=git_log, intent=date the double-load guard in PDP._load_policies and any change to add_policy/authorize (switch from self._policies iteration to evaluator-only) — "was working before"]
[cross-lane: type=grep, intent=confirm no other caller (setup/on_startup/sorted_policies) adapts self._policies into the evaluator]
