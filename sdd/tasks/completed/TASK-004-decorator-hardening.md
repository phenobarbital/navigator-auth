# TASK-004: Decorator Hardening for CBV

**Feature**: FEAT-001 — policy-based-access-control
**Module**: Module 4 — Decorator Hardening
**Status**: in-progress

## Description

Verify and harden `groups_protected` and `requires_permission` decorators for class-based views (aiohttp `web.View`). Use `_apply_decorator` pattern for CBV support.

## Files

- **MODIFY**: `navigator_auth/abac/decorators.py`

## Classes/Functions

- `groups_protected()` — use `_apply_decorator` for CBV support
- `requires_permission()` — already uses `_apply_decorator`, verify and fix edge cases

## Acceptance Criteria

- [ ] `groups_protected` works with both function handlers and `web.View` class-based views
- [ ] `requires_permission` works with CBV
- [ ] Uses `_apply_decorator` pattern consistently
- [ ] Edge cases handled (missing session, missing userinfo)

## Completion Note

_To be filled on completion._
