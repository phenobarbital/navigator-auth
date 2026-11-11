# TASK-199: `_auth_middleware` exempt branch publishes `request["userdata"]`

**Feature**: FEAT-108 — OAuth2 3LO examples work end-to-end — auth paths fail closed on misconfiguration and unknown users
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Spec §1 S3 / G5, §3 Module 5, AC10. When `verify_exceptions` exempts a request (`allow_hosts`,
`allowed_ips`, exclude list), `AuthHandler._auth_middleware` still resolves a bearer "best-effort"
so downstream middlewares see `authenticated=True` — but it sets only `request.user`,
`request["authenticated"]` and the mechanism. Handlers that read the token claims
(`request["userdata"]`, e.g. "List my grants") then answer 401 "Not authenticated." The main path
publishes `userdata` (`auth.py:1140`, `:1172`).

---

## Scope

- In the exempt branch, set `request["userdata"] = payload` next to `request.user = user`.
- Create `tests/test_auth_middleware_exempt_userdata.py` (mock-based; no Redis).

**NOT in scope**: the main (non-exempt) path; `verify_exceptions`; the TrocToken/TokenAuth
middlewares (spec Non-Goals).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/auth.py` | MODIFY | One line in the exempt branch |
| `tests/test_auth_middleware_exempt_userdata.py` | CREATE | AC10 tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `61d424b` AND `feat-FEAT-106-basicauth-otp-2fa` @ `0b80d88` (2026-11-11).
> FEAT-106 rewrites parts of `auth.py`; the anchors below are textual and survive it (lines: dev / FEAT-106).

### Verified Imports
```python
from navigator_auth.auth import AuthHandler                     # verified: navigator_auth/auth.py (class AuthHandler)
from navigator_auth.conf import AUTH_MECHANISM_KEY, AUTH_MECHANISM_BEARER   # used at auth.py:1074 (dev)
from unittest.mock import AsyncMock, MagicMock, patch           # stdlib
```

### Existing Signatures to Use
```python
# navigator_auth/auth.py
async def verify_exceptions(self, request: web.Request) -> bool:              # dev :951 / 106 :989
async def _auth_middleware(self, request, handler) -> web.StreamResponse:     # dev :1051 / 106 :1089
#   exempt branch (dev :1060-1077 / 106 :1098-1115):
#       if hdrs.AUTHORIZATION in request.headers:
#           try:
#               token = await self._idp.get_payload(request)
#               _, payload = self._idp.decode_token(code=token)
#               if payload and not await self._token_is_revoked(payload):
#                   session = await get_session(request, payload, new=False)   # navigator_session.get_session, imported in auth.py
#                   if session:
#                       user = await self.get_session_user(session)
#                       if user:
#                           request.user = user                                # dev :1072 / 106 :1110
#                           request["authenticated"] = True
#                           request[AUTH_MECHANISM_KEY] = AUTH_MECHANISM_BEARER
#           except Exception:
#               pass  # Best-effort: if token is invalid, proceed unauthenticated   # dev :1076 / 106 :1114
#       return await handler(request)
async def get_session_user(self, session, name: str = "user"):               # dev :748
```

### Does NOT Exist
- No test for the exempt branch today (`tests/test_auth_middleware_mechanism.py` covers the main path with Redis).
- ~~`request["token_claims"]`~~ — the claims key is `"userdata"`, as on the main path.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/auth.py", "action": "MODIFY"},
    {"path": "tests/test_auth_middleware_exempt_userdata.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/auth.py#AuthHandler",
    "sym:navigator_auth/auth.py#AuthHandler._auth_middleware",
    "sym:navigator_auth/auth.py#AuthHandler.verify_exceptions",
    "sym:navigator_auth/auth.py#AuthHandler.get_session_user"
  ]
}
```

---

## Implementation Notes

- Mirror the main path exactly: `request["userdata"] = payload` (the decoded claims).
- Build the `AuthHandler` under test without `__init__` (`object.__new__(AuthHandler)`) and set
  `_idp`, `logger`, `verify_exceptions`, `_token_is_revoked`, `get_session_user` as mocks; patch
  `navigator_auth.auth.get_session` with an `AsyncMock`. Do not start Redis.

---

## Implementation Blueprint

### Steps (in order)
1. Insert the line — *why*: AC10, S3.
2. Write the two tests; run them.

### `navigator_auth/auth.py` (MODIFY)
```python
# Anchor `request.user = user` occurs 4× (dev :1072,:1139,:1171,:1191) — use the unique anchor instead:
# occurrences: 1 (verified: grep -c 'pass  # Best-effort: if token is invalid, proceed unauthenticated' navigator_auth/auth.py)
# Inside the `try:` that ends at that `except Exception: pass  # Best-effort…` (dev :1076 / 106 :1114),
# insert directly below its `request.user = user` (dev :1072 / 106 :1110):
                                request.user = user
                                request["userdata"] = payload   # FEAT-108 G5 — mirrors the main path (:1140)
                                request["authenticated"] = True
                                request[AUTH_MECHANISM_KEY] = AUTH_MECHANISM_BEARER
```
**Why**: the exempt branch must publish the same request contract as the main path once it accepted a bearer.

### `tests/test_auth_middleware_exempt_userdata.py` (CREATE)
```python
"""FEAT-108 M5 — the allow_hosts / exclude-list branch publishes the bearer claims."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import hdrs

from navigator_auth.auth import AuthHandler
from navigator_auth.conf import AUTH_MECHANISM_BEARER, AUTH_MECHANISM_KEY

PAYLOAD = {"user_id": 1, "username": "demo", "client_id": "nav_example_spa", "jti": "j-1", "scope": "default"}


def _handler_under_test(user) -> AuthHandler:
    auth = object.__new__(AuthHandler)
    auth.logger = MagicMock()
    auth.verify_exceptions = AsyncMock(return_value=True)
    auth._token_is_revoked = AsyncMock(return_value=False)
    auth.get_session_user = AsyncMock(return_value=user)
    auth._idp = MagicMock()
    auth._idp.get_payload = AsyncMock(return_value="tok")
    auth._idp.decode_token = MagicMock(return_value=("Bearer", PAYLOAD))
    return auth


def _request() -> dict:
    # FILL IN: a request double that supports `in request.headers`, item assignment and
    #          attribute `user` — e.g. a dict subclass with `.headers = {hdrs.AUTHORIZATION: "Bearer tok"}`.
    raise NotImplementedError


@pytest.mark.asyncio
async def test_exempt_branch_publishes_userdata():
    user = MagicMock()
    auth = _handler_under_test(user)
    request = _request()
    handler = AsyncMock(return_value="ok")
    with patch("navigator_auth.auth.get_session", AsyncMock(return_value=MagicMock())):
        await auth._auth_middleware(request, handler)
    assert request["userdata"] == PAYLOAD
    assert request.user is user
    assert request["authenticated"] is True
    assert request[AUTH_MECHANISM_KEY] == AUTH_MECHANISM_BEARER


@pytest.mark.asyncio
async def test_exempt_branch_invalid_token_unchanged():
    auth = _handler_under_test(MagicMock())
    auth._idp.decode_token = MagicMock(side_effect=ValueError("bad token"))
    request = _request()
    handler = AsyncMock(return_value="ok")
    assert await auth._auth_middleware(request, handler) == "ok"
    # FILL IN: assert "userdata" and "authenticated" are absent — bounded by spec §4 M5.
```

### FILL IN checklist
- [ ] `_request()` double; spec §4 M5.
- [ ] Absence assertions in the invalid-token test.

---

## Acceptance Criteria

- [ ] AC10: in the exempt branch a bearer that resolves a session user sets `request["userdata"]` to the decoded payload, besides `request.user`, `request["authenticated"]` and the bearer mechanism.
- [ ] An invalid bearer still lets the handler run unauthenticated, with no `userdata`.
- [ ] `ruff check navigator_auth/auth.py tests/test_auth_middleware_exempt_userdata.py` clean.

---

## Validation Commands

- `pytest tests/test_auth_middleware_exempt_userdata.py -q`

---

## Test Specification

Spec §4, M5: `test_exempt_branch_publishes_userdata`, `test_exempt_branch_invalid_token_unchanged`.
`tests/test_auth_middleware_mechanism.py` (Redis) stays in the feature Validation Contract.

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
6. **Implement** from the Implementation Blueprint; complete every `# FILL IN:`; never change a fixed signature or path.
7. **Verify** — run the Validation Commands.
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`).
9. **Close the task** with `parrot sdd task close TASK-199 oauth2-3lo-issues verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none

## Completion Note

Delivered by the coder pool (execution 8700c4ca), merged into the feature branch; merge-tier validation green (only baseline reds: short AUTH_SECRET_KEY JWT warnings). Closed by sdd-worker; semantic review is the feature-wide code review.
