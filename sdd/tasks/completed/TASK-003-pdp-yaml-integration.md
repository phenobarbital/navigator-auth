# TASK-003: PDP YAML Integration

**Feature**: FEAT-001 — policy-based-access-control
**Module**: Module 3 — PDP YAML Integration
**Status**: in-progress

## Description

Extend PDP startup to optionally load from `YAMLStorage` in addition to DB storage. Support mixed sources (DB + YAML).

## Files

- **MODIFY**: `navigator_auth/abac/pdp.py`

## Classes/Functions

- `PDP.__init__` — accept optional `yaml_storage` parameter
- `PDP._load_policies` — load from both DB and YAML storage
- `PDP.reload_policies` — reload from both sources

## Acceptance Criteria

- [ ] PDP accepts optional `yaml_storage` parameter
- [ ] Loads from both DB and YAML on startup
- [ ] `reload_policies()` reloads both sources
- [ ] Works with YAML-only, DB-only, or mixed
- [ ] No breaking changes to existing PDP interface

## Completion Note

_To be filled on completion._
