# TASK-197: APIKeyAuth declines a bearer that is not an API key

**Feature**: FEAT-108 — OAuth2 3LO examples work end-to-end — auth paths fail closed on misconfiguration and unknown users
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Spec §1 S1 / G3, §3 Module 3, AC5. A valid 3LO bearer sent to `GET /api/v1/me` answered **500**
`TypeError: 'bool' object is not subscriptable` (`api.py:154`): `@is_authenticated()` tries every
backend, and `APIKeyAuth.authenticate` indexes the `False` that `check_token_info` returns for a
JWT without `device_id`. `check_credentials` already has the `if not data` guard (`api.py:217-219`);
`authenticate` does not. `check_token_info(request, None)` also raises `TypeError` today.

---

## Scope

- In `APIKeyAuth.authenticate`, return `None` right after `data = await self.get_token_info(...)`
  when `data` is falsy (`False`, `None`, `{}`), mirroring `check_credentials`.
- In `APIKeyAuth.check_token_info`, return `False` for an empty payload (`None`, `{}`) before indexing it.
- Keep `InvalidAuth` for a **truthy** dict missing `device_id` / `user_id` (unchanged behaviour).
- Create `tests/test_apikey_authenticate_bearer.py`.

**NOT in scope**: the `@is_authenticated` loop (TASK-198); `check_credentials`; the SQL lookup.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/api.py` | MODIFY | Two guards |
| `tests/test_apikey_authenticate_bearer.py` | CREATE | AC5 tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `61d424b` (2026-11-11). FEAT-106 does not touch `api.py` (identical on its branch).

### Verified Imports
```python
from navigator_auth.backends.api import APIKeyAuth      # verified: navigator_auth/backends/api.py:38
from navigator_auth.exceptions import InvalidAuth       # verified: navigator_auth/exceptions.py:42 (imported in api.py:13)
from unittest.mock import AsyncMock, MagicMock          # stdlib
```

### Existing Signatures to Use
```python
# navigator_auth/backends/api.py
class APIKeyAuth(BaseAuthBackend):                                          # :38 (no own __init__)
    async def get_payload(self, request):                                   # :54 → (mech, token)
    async def get_token_info(self, request: web.Request, mech: str, token: str) -> dict:  # :95; ends `return await self.check_token_info(request, payload)` :141
    async def authenticate(self, request):                                  # :143
        #   :152  data = await self.get_token_info(request, mech, token)   (same line also at :217)
        #   :153  try:
        #   :154      device_id = str(data["device_id"])
        #   :156  except KeyError as err: raise InvalidAuth(f"Missing attributes for API Key: {err!s}", status=401)
    async def check_token_info(self, request, payload):                     # :185
        #   :186-190 try: user_id = payload["user_id"]; device_id = payload["device_id"] except KeyError: return False
    async def check_credentials(self, request: web.Request):                # :211 (guard `if not data: return False` :218-219)
```

### Does NOT Exist
- No test calls `APIKeyAuth.authenticate()` today.
- ~~`APIKeyAuth.is_api_key()`~~ / ~~`_looks_like_api_key`~~ — do not add a token-shape detector; the guard is on the decoded data.
- `tests/unit/identity/conftest.py:make_backend` is NOT importable from `tests/` root files (conftest scope) — replicate the `object.__new__` pattern locally.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/backends/api.py", "action": "MODIFY"},
    {"path": "tests/test_apikey_authenticate_bearer.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/api.py#APIKeyAuth",
    "sym:navigator_auth/backends/api.py#APIKeyAuth.authenticate",
    "sym:navigator_auth/backends/api.py#APIKeyAuth.check_token_info"
  ]
}
```

---

## Implementation Notes

- Returning `None` (not raising) is what lets the `@is_authenticated` loop move to the next backend.
- Do not catch `TypeError` broadly — the guard is a precondition, not an exception filter.

---

## Implementation Blueprint

### Steps (in order)
1. Add the `if not data: return None` guard in `authenticate` — *why*: AC5, S1 root cause.
2. Add the `if not payload: return False` guard at the top of `check_token_info` — *why*: AC5 (`None` payload).
3. Write the tests; run them.

### `navigator_auth/backends/api.py` (MODIFY) — `authenticate`
```python
# occurrences: 1 (verified: grep -c 'device_id = str(data\["device_id"\])' navigator_auth/backends/api.py)
# The preceding anchor `data = await self.get_token_info(request, mech, token)` occurs 2× (:152, :217);
# insert BETWEEN :152 and the `try:` at :153 (the occurrence directly above `device_id = str(data["device_id"])`):
            data = await self.get_token_info(request, mech, token)
            if not data:
                # Not an API key (e.g. an OAuth2 JWT without device_id): decline so the
                # next backend can try it, exactly as check_credentials does.
                return None
            try:
                device_id = str(data["device_id"])
```

### `navigator_auth/backends/api.py` (MODIFY) — `check_token_info`
```python
# occurrences: 1 (verified: grep -c 'async def check_token_info(self, request, payload):' navigator_auth/backends/api.py)
# AFTER — insert below `async def check_token_info(self, request, payload):` (verified: navigator_auth/backends/api.py:185)
        if not payload:
            # An empty/absent payload is "no API key", not a malformed one.
            return False
```

### `tests/test_apikey_authenticate_bearer.py` (CREATE)
```python
"""FEAT-108 M3 — APIKeyAuth declines bearers that are not API keys (S1)."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from navigator_auth.backends.api import APIKeyAuth
from navigator_auth.exceptions import InvalidAuth


def _backend() -> APIKeyAuth:
    """APIKeyAuth without app wiring (same pattern as tests/unit/identity/conftest.py:40)."""
    backend = object.__new__(APIKeyAuth)
    backend.logger = MagicMock()
    backend.get_payload = AsyncMock(return_value=("bearer", "jwt"))
    return backend


@pytest.mark.asyncio
@pytest.mark.parametrize("info", [False, None, {}])
async def test_authenticate_declines_non_apikey_bearer(info):
    backend = _backend()
    backend.get_token_info = AsyncMock(return_value=info)
    assert await backend.authenticate(MagicMock()) is None


@pytest.mark.asyncio
async def test_authenticate_missing_attributes_still_invalid():
    backend = _backend()
    backend.get_token_info = AsyncMock(return_value={"user_id": 7})
    with pytest.raises(InvalidAuth):
        await backend.authenticate(MagicMock())


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [None, {}])
async def test_check_token_info_empty_payload(payload):
    backend = _backend()
    assert await backend.check_token_info(MagicMock(), payload) is False
```

### FILL IN checklist
- [ ] none — the blueprint is complete; run the tests and `ruff check`.

---

## Acceptance Criteria

- [ ] AC5: `authenticate` returns `None` for token info `False` / `None` / `{}`; `check_token_info(request, None)` returns `False`; a dict missing `device_id` still raises `InvalidAuth`.
- [ ] `ruff check navigator_auth/backends/api.py tests/test_apikey_authenticate_bearer.py` is clean.

---

## Validation Commands

- `pytest tests/test_apikey_authenticate_bearer.py -q`

---

## Test Specification

See the CREATE block (spec §4, M3): `test_authenticate_declines_non_apikey_bearer`,
`test_authenticate_missing_attributes_still_invalid`, `test_check_token_info_empty_payload`.

---

## Agent Instructions

When you pick up this task:

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug oauth2-3lo-issues --feature-id FEAT-108`).
   The spec requires the worktree to be created from `origin/dev` **after FEAT-106 (PR #633) merges**.
2. **Read the spec** at the path listed above for full context.
3. **Check dependencies** — every `Depends-on` task must be `"done"` in `sdd/tasks/index/oauth2-3lo-issues.json`.
4. **Verify the Codebase Contract** — re-run each `grep -c` in the blueprint before editing; a changed
   count means the anchor moved (re-locate it), a `0` means drift (stop and report).
5. **Update status** in the index → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** from the Implementation Blueprint; never change a fixed signature or path.
7. **Verify** — run the Validation Commands.
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`).
9. **Close the task** with `parrot sdd task close TASK-197 oauth2-3lo-issues verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none
