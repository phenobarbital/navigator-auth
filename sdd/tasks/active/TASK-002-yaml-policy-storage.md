# TASK-002: YAML Policy Storage

**Feature**: FEAT-001 — policy-based-access-control
**Module**: Module 2 — YAML Policy Storage
**Status**: in-progress

## Description

Implement `YAMLStorage(AbstractStorage)` that scans `POLICY_STORAGE_DIR` for `.yaml`/`.yml` files, parses them into policy dicts compatible with PDP loading. Support hot-reload.

## Files

- **CREATE**: `navigator_auth/abac/storages/yaml_storage.py`
- **MODIFY**: `navigator_auth/abac/storages/__init__.py` (export YAMLStorage)
- **MODIFY**: `navigator_auth/conf.py` (add POLICY_STORAGE_DIR)

## Classes/Functions

- `YAMLStorage(AbstractStorage)` with methods:
  - `async load_policies() -> list[dict]`
  - `async save_policy(policy: dict) -> None`
  - `async reload() -> list[dict]`
  - `async close()` (no-op for file-based)

## Acceptance Criteria

- [ ] `YAMLStorage` extends `AbstractStorage`
- [ ] Scans directory for `.yaml` and `.yml` files
- [ ] Returns policy dicts compatible with PDP's `_load_policies`
- [ ] Supports hot-reload
- [ ] Handles malformed YAML gracefully (logs error, skips)
- [ ] `POLICY_STORAGE_DIR` config key added

## Completion Note

_To be filled on completion._
