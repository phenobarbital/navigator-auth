# TASK-201: `/oauth2/userinfo` omits the profile claims it cannot supply

**Feature**: FEAT-108 — OAuth2 3LO examples work end-to-end — auth paths fail closed on misconfiguration and unknown users
**Spec**: `sdd/specs/oauth2-3lo-issues.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Spec §1 S4 / G7, §3 Module 7, AC17. When `user_from_id` fails, every scope-gated claim defaults
to `""`, so the 3LO example showed `{"sub":"35","username":"",…}`. The claims must be set only when
a non-empty value exists (token payload first, then the IdP user). Scope gating is unchanged, and so
is FEAT-106's `amr` echo (FEAT-106 TASK-186 adds it to this method before FEAT-108 starts).

This is the first FEAT-108 task that edits `oauth2/backend.py`; TASK-203 → 204 → 205 follow it on
the same file (serialized by the graph).

---

## Scope

- In `Oauth2Provider.userinfo`, set `username`, `given_name`, `family_name` and `email` only when the
  resolved value is not `None`/`""`.
- Create `tests/test_oauth2_userinfo_claims.py` (handler-level tests).
- Update `tests/test_oauth2_userinfo_logout.py::TestUserinfoClaims._build_claims` (a mirror of the old
  logic) to the new rule, keeping its existing tests green.

**NOT in scope**: the user lookup itself (still best-effort here — userinfo is not an owner check);
scope gating; `amr` (FEAT-106); introspection's username claim (`backend.py:2484-2492`).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `userinfo` sets non-empty claims only |
| `tests/test_oauth2_userinfo_claims.py` | CREATE | AC17 handler tests |
| `tests/test_oauth2_userinfo_logout.py` | MODIFY | `_build_claims` mirror follows the new rule |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `61d424b` AND `feat-FEAT-106-basicauth-otp-2fa` @ `0b80d88` (2026-11-11).
> FEAT-106's pending review-fix TASK-186 adds an `amr` echo near `claims = {"sub": …}`; keep it.

### Verified Imports
```python
from navigator_auth.backends.oauth2.backend import Oauth2Provider   # verified: tests/test_oauth2_3lo_session_binding.py:25
from navigator_auth.exceptions import UserNotFound                  # verified: exceptions.py:32
import json                                                         # tests read JSONResponse via json.loads(resp.body) (tests/test_oauth2_introspection.py:193)
```

### Existing Signatures to Use
```python
# navigator_auth/backends/oauth2/backend.py
from typing import Optional, Any                                    # :29
class Oauth2Provider(BaseAuthBackend):                              # :258
    async def userinfo(self, request):                              # :2194
        #  Bearer from request.headers["Authorization"]; payload = self._idp.decode_token(token)[1]  (:2200-2210)
        #  jti revocation via self.access_token_storage.is_revoked(jti) when storage set (:2214-2218)
        #  claims = {"sub": str(user_id)}                            (:2222)
        #  user = await self._idp.user_from_id(user_id) when profile/email in scopes; errors only logged (:2228-2232)
        def _claim(name: str, default: str = "") -> str:            # :2234 (payload first, then getattr(user, name))
        #  if "profile" in scopes:                                   (:2245)
        #      claims["username"] = str(_claim("username"))          (:2246)
        #      claims["given_name"] = str(_claim("given_name") or _claim("first_name"))    (:2247)
        #      claims["family_name"] = str(_claim("family_name") or _claim("last_name"))   (:2248)
        #  if "email" in scopes:
        #      claims["email"] = str(_claim("email"))                (:2250)
        #  return JSONResponse(claims, status=200)                   (:2252)

# tests/test_oauth2_3lo_session_binding.py
@pytest.fixture
def provider():                                                     # :81-85
    prov = Oauth2Provider(user_model=MagicMock(), identity=MagicMock()); prov.logger = MagicMock()

# tests/test_oauth2_userinfo_logout.py
class TestUserinfoClaims:                                           # :50
    def _build_claims(self, payload: dict) -> dict:                 # :53 (mirror of the OLD logic: payload.get(..., ""))
```

### Does NOT Exist
- ~~`Oauth2Provider._userinfo_claims`~~ — the logic is inline in `userinfo`; do not extract a new public helper.
- No handler-level userinfo test exists today (only the logic mirror in `test_oauth2_userinfo_logout.py`).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/backends/oauth2/backend.py", "action": "MODIFY"},
    {"path": "tests/test_oauth2_userinfo_claims.py", "action": "CREATE"},
    {"path": "tests/test_oauth2_userinfo_logout.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider",
    "sym:navigator_auth/backends/oauth2/backend.py#Oauth2Provider.userinfo"
  ]
}
```

---

## Implementation Blueprint

### Steps (in order)
1. Replace the four claim assignments with a local `_set` that skips empty values — *why*: AC17.
2. Update the `_build_claims` mirror — *why*: it asserts the old logic and would drift otherwise.
3. Create the handler tests; run both files.

### `navigator_auth/backends/oauth2/backend.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'claims\["username"\] = str(_claim("username"))' navigator_auth/backends/oauth2/backend.py)
# occurrences: 1 (verified: grep -c 'claims\["email"\] = str(_claim("email"))' navigator_auth/backends/oauth2/backend.py)
# REPLACE the block from `# Scope-gated claims.` through `claims["email"] = str(_claim("email"))`
# (verified: :2244-2250) WITH:
        def _set(name: str, value: Any) -> None:
            # FEAT-108 G7: never answer an empty-string claim — omit what we cannot supply.
            if value not in (None, ""):
                claims[name] = str(value)

        # Scope-gated claims.
        if "profile" in scopes:
            _set("username", _claim("username"))
            _set("given_name", _claim("given_name") or _claim("first_name"))
            _set("family_name", _claim("family_name") or _claim("last_name"))
        if "email" in scopes:
            _set("email", _claim("email"))
```
**Why**: `_claim` already prefers the payload then the user record; only the "always set" changes.
Any FEAT-106 `amr` lines around this block stay as they are.

### `tests/test_oauth2_userinfo_logout.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'def _build_claims(self, payload: dict) -> dict:' tests/test_oauth2_userinfo_logout.py)
# REPLACE the method body at :53-65 so each claim is set only when payload.get(name) not in (None, "").
# FILL IN: keep the method name and signature; keep every existing TestUserinfoClaims test passing
#          unchanged — bounded by AC17 (they assert presence for non-empty payload values and absence
#          when the scope is missing, both still true).
```

### `tests/test_oauth2_userinfo_claims.py` (CREATE)
```python
"""FEAT-108 M7 — /oauth2/userinfo omits the claims it cannot supply (S4)."""
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from navigator_auth.backends.oauth2.backend import Oauth2Provider
from navigator_auth.exceptions import UserNotFound

PAYLOAD = {"user_id": 35, "scope": "default profile email", "jti": "j-1"}


@pytest.fixture
def provider():
    prov = Oauth2Provider(user_model=MagicMock(), identity=MagicMock())
    prov.logger = MagicMock()
    prov.access_token_storage = None
    prov._idp.decode_token = MagicMock(return_value=("Bearer", dict(PAYLOAD)))
    return prov


def _request():
    request = MagicMock()
    request.headers = {"Authorization": "Bearer tok"}
    return request


@pytest.mark.asyncio
async def test_userinfo_omits_unknown_claims(provider):
    provider._idp.user_from_id = AsyncMock(side_effect=UserNotFound("gone"))
    body = json.loads((await provider.userinfo(_request())).body)
    # FILL IN: assert body == {"sub": "35"} — plus "amr" only if FEAT-106 echoes it and the payload
    #          carries it (it does not here) — bounded by AC17.


@pytest.mark.asyncio
async def test_userinfo_full_profile(provider):
    user = SimpleNamespace(username="demo", first_name="Demo", last_name="User", email="demo@example.com")
    provider._idp.user_from_id = AsyncMock(return_value=user)
    body = json.loads((await provider.userinfo(_request())).body)
    assert body["username"] == "demo"
    assert body["given_name"] == "Demo"
    assert body["family_name"] == "User"
    assert body["email"] == "demo@example.com"
```

### FILL IN checklist
- [ ] `_build_claims` mirror; AC17.
- [ ] `test_userinfo_omits_unknown_claims` assertion; AC17.

---

## Acceptance Criteria

- [ ] AC17: `/oauth2/userinfo` never returns an empty-string claim; with an unloadable user the body is `{"sub": …}` (plus FEAT-106's `amr` only when the token carries it); with a resolvable user the profile and email claims are present as today.
- [ ] `tests/test_oauth2_userinfo_logout.py` passes.
- [ ] `ruff check` clean on the three files.

---

## Validation Commands

- `pytest tests/test_oauth2_userinfo_claims.py -q`
- `pytest tests/test_oauth2_userinfo_logout.py -q`

---

## Test Specification

Spec §4, M7: `test_userinfo_omits_unknown_claims`, `test_userinfo_full_profile`.

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
9. **Close the task** with `parrot sdd task close TASK-201 oauth2-3lo-issues verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none
