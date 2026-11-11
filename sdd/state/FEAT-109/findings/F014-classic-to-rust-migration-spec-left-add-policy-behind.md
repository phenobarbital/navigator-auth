---
id: F014
query_id: "Q009-followup"
type: "read"
intent: "Follow-up from F004: which feature made PDP.authorize evaluator-only, and did it account for PDP.add_policy?"
executed_at: 2026-11-11T14:58:00Z
parent_id: F004
depth: 1
merged_from: []
---

# F014 — The classic→Rust migration spec made authorize() evaluator-only and never mentions add_policy

## Summary

`sdd/specs/migrate-classic-policies-abac-rust.spec.md` (brainstorm dated 2026-04-03) is the change that
made `PDP.authorize()` delegate to `PolicyEvaluator` and routed only `_load_policy_dicts()` through
`PolicyAdapter`. Its stated goal is to keep the PDP public interface unchanged, but a grep of the spec for
`add_policy` returns nothing: the public `add_policy()` kept its signature and silently lost its effect on
authorization. This dates the 428 gap to that migration (≈April 2026), well before the 45-day git window
the git lane searched (F008), which is consistent with "no recent commit explains it".

## Citations

- path: `sdd/specs/migrate-classic-policies-abac-rust.spec.md`
  lines: 37
  symbol: `goal: keep PDP public interface`
  excerpt: |
    37  - Keep `PDP` public interface (`authorize()`, `is_allowed()`, `filter_files()`) unchanged.

- path: `sdd/specs/migrate-classic-policies-abac-rust.spec.md`
  lines: 92
  symbol: `PDP module change`
  excerpt: |
    92  | `PDP` (`pdp.py`) | modifies | `authorize()` delegates to PolicyEvaluator; `_load_policy_dicts()` uses PolicyAdapter |

- path: `sdd/specs/migrate-classic-policies-abac-rust.spec.md`
  lines: 412
  symbol: `acceptance: authorize delegates`
  excerpt: |
    412 - [ ] `PDP.authorize()` delegates to `PolicyEvaluator.check_access()` successfully.

- path: `sdd/proposals/migrate-classic-policies-abac-rust.brainstorm.md`
  lines: 3, 25
  symbol: `brainstorm date / why now`
  excerpt: |
    3   **Date**: 2026-04-03
    25  **Why now:** There are no classic policies in production yet, making this the ideal time

## Notes

- `grep -n add_policy` over the spec: no match (absence evidence → the omission is inferred, medium).
- The example's last edits (ea8c599 2026-04-16 "add default value for pep evaluator", 1e3ebbc 2026-06-30, see F002)
  came after the migration, so whether the example ever worked post-migration is not established.
