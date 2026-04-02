# TASK-006: Cython Fast Resource Evaluator

**Feature**: FEAT-001 — policy-based-access-control
**Module**: Module 6 — Cython Fast Resource Evaluator
**Status**: in-progress

## Description

Create a Cython-accelerated resource pattern matching and condition evaluation module. Used by `PolicyEvaluator` when available, with pure-Python fallback.

## Files

- **CREATE**: `navigator_auth/libs/policy_eval.pyx`
- **MODIFY**: `setup.py` (add new extension)

## Classes/Functions

- `match_pattern(pattern: str, resource: str) -> bool` — fast glob matching
- `evaluate_conditions(env_dict: dict, conditions: dict) -> bool` — fast condition eval
- `filter_resources_batch(policies: list, resources: list, user: dict, env: dict) -> dict`

## Acceptance Criteria

- [ ] Cython module compiles
- [ ] Pattern matching equivalent to Python version
- [ ] Condition evaluation correct
- [ ] Added to setup.py ext_modules
- [ ] Pure-Python fallback when Cython not available

## Completion Note

_To be filled on completion._
