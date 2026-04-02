# TASK-001: Environment Migration to Pydantic

**Feature**: FEAT-001 — policy-based-access-control
**Module**: Module 1 — Environment Migration
**Status**: in-progress

## Description

Migrate `Environment` from `datamodel.Model` to Pydantic `BaseModel`. Add `DaySegment` enum, `is_business_hours`, `is_weekend`, `minute`, `timezone` fields. Read business-hours config from `navigator_auth.conf` via `navconfig`.

## Files

- **MODIFY**: `navigator_auth/abac/policies/environment.py`
- **MODIFY**: `navigator_auth/conf.py` (add BUSINESS_HOURS config keys)

## Classes/Functions

- `DaySegment(str, Enum)` — morning, afternoon, evening, night
- `Environment(BaseModel)` — Pydantic v2 model with `model_post_init`
- Config keys: `BUSINESS_HOURS_START`, `BUSINESS_HOURS_END`, `BUSINESS_DAYS`, `DAY_SEGMENT_*`

## Acceptance Criteria

- [ ] `Environment` uses Pydantic `BaseModel`
- [ ] Has `day_segment`, `is_business_hours`, `is_weekend`, `minute`, `timezone` fields
- [ ] Business hours configurable via navconfig
- [ ] `DaySegment` enum with four values
- [ ] Backward-compatible with existing dict-like access patterns used by `evaluate_environment` in `abstract.py`
- [ ] No breaking changes to callers that use `Environment()` constructor

## Completion Note

_To be filled on completion._
