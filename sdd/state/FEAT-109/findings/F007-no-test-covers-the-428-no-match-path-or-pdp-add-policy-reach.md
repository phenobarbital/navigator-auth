---
id: F007
query_id: "Q016"
type: "grep"
intent: "Existing tests covering no-match / default-deny behaviour"
executed_at: 2026-11-11T14:50:00Z
parent_id: null
depth: 0
merged_from: [FC-007]
---

# F007 — No test covers the 428 no-match path or PDP.add_policy reaching the evaluator; the pre-load guard IS tested

## Summary

No file under `tests/` references "No Matching Policies" or `PreconditionFailed`, and no test calls
`PDP.add_policy(`. The startup double-load guard (FC-004) has explicit coverage in
`tests/test_yaml_storage_double_load.py`, which asserts the pre-loaded evaluator count does not change —
i.e. the "skip storage when pre-loaded" behaviour is intentional and pinned by tests; a fix must keep it.

## Citations

- path: `tests/test_yaml_storage_double_load.py`
  lines: 236-269
  symbol: `pre_loaded_evaluator`
  excerpt: |
    236  initial_count = len(pre_loaded_evaluator._index.all())
    242  final_count = len(pre_loaded_evaluator._index.all())
    255  assert len(ev._index.all()) == 0
    258  assert len(ev._index.all()) > 0, (

## Notes

- Vault error classes are tested (`tests/unit/vault/test_vault_view.py:114`), see FC-001.
