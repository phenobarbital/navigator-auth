# TASK-046: Factor `BasicAuth.open_session()` out of `authenticate()`

**Feature**: FEAT-096 external-token-exchange
**Spec**: `sdd/specs/external-token-exchange.spec.md` (Module 1, decisions D1, D2, D5, D8, D9)
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

`TokenExchangeAuth` must open a session "as if Basic": same user mapping,
`BasicUser` identity, `remember()`, internal JWT + refresh token, Basic success
callbacks. Today that recipe is inlined in the tail of `BasicAuth.authenticate`
(`navigator_auth/backends/basic.py:139-193`). This task extracts it into a
reusable method that accepts extra session fields (for `auth_origin` etc.), an
expiration override (the external-token cap) and aligns the session `max_age`
with that cap.

**Parallelizable**: touches only `backends/basic.py` and its tests; no
contention with TASK-047/048.

---

## Scope

- Add `BasicAuth.open_session(request, user, extra=None, expiration=None) -> dict`
  containing everything `authenticate()` currently does after `validate_user`
  returns: `get_userdata`, `BASIC_USER_MAPPING`, `create_user`, `remember`,
  payload, `idp.create_token`, callbacks, response dict.
- `extra` (dict) is merged into `userdata` **and** into
  `userdata[AUTH_SESSION_OBJECT]` before `remember()` (D5). Keys present in
  `extra` are also added to the JWT payload when they are `auth_method`,
  `auth_origin` or `external_expires_at`.
- `expiration` (int seconds) is forwarded to `idp.create_token(expiration=...)`;
  when given, also set `session.max_age = expiration` on the `SessionData`
  returned by `remember()` (D9; navigator_session `SessionData.max_age` setter,
  honoured by `RedisStorage.save_session` and `save_cookie`).
- `authenticate()` becomes: payload → `validate_user` → `open_session(request, user)`.
  With no `extra`/`expiration` the emitted session, payload and response dict
  must be **identical** to today (regression-gated).
- `userdata["auth_method"]` default stays `"basic"`; `extra` may override.
- Tests: extend `tests/test_basic_auth.py` (existing cases must pass untouched)
  and add unit tests for `open_session` with extras and expiration.

**NOT in scope**: the exchange backend, any provider code, session claims for
non-Basic backends.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/basic.py` | MODIFY | Add `open_session`; slim `authenticate` |
| `tests/test_basic_auth.py` | MODIFY | Keep existing; add regression assert on payload keys |
| `tests/test_basic_open_session.py` | CREATE | `extra` merge, JWT `exp` cap, `session.max_age` |

---

## Implementation Notes

### Pattern to Follow
Keep the current try/except shape and logging of `authenticate()`; the method
returns `{"token": token, **userdata}` exactly as before. `open_session` should
raise (not return `False`) so the caller decides; `authenticate` keeps its
current "log and return False" wrapper around it.

### Key Constraints
- Do not change `BasicAuth.validate_user` or `get_payload`.
- Do not mutate `BASIC_USER_MAPPING`/`USER_MAPPING`.
- `session.max_age` must be set **before** `api_login` calls
  `storage.load_session(..., response=)` (that is when the Redis key and cookie
  are written) — setting it inside `open_session` right after `remember()` is
  sufficient.
- If navigator_session raises on setting `max_age` (older version), log a
  warning; do not fail login.

### References in Codebase
- `navigator_auth/backends/basic.py:139` — current `authenticate`.
- `navigator_auth/backends/abstract.py` `remember()` — returns `SessionData`.
- `navigator_auth/backends/idp/__init__.py:378` — `create_token(expiration=)`.
- navigator_session `data.py` (`SessionData.max_age` setter), `storages/redis.py`
  `save_session` (uses `session.max_age` as Redis expire).

---

## Acceptance Criteria

- [ ] `pytest tests/test_basic_auth.py -v` passes with no test edits other than
      additive asserts
- [ ] `open_session(extra={...})` puts keys at both userdata top level and in
      `AUTH_SESSION_OBJECT`; `auth_origin` appears in the decoded JWT
- [ ] `open_session(expiration=N)` → decoded JWT `exp - iat ≈ N`; returned
      session has `max_age == N`
- [ ] With no extras/expiration the response dict keys and JWT claims are
      unchanged from pre-task behaviour
- [ ] `ruff check navigator_auth/backends/basic.py` clean

---

## Test Specification

```python
# tests/test_basic_open_session.py
# fixture: BasicAuth with a mocked IdentityProvider (create_token real, get_user mocked)
# test_open_session_default_matches_authenticate
# test_open_session_extra_merged_both_levels
# test_open_session_extra_in_jwt (auth_origin present, other keys not)
# test_open_session_expiration_caps_jwt_and_session_max_age
# test_open_session_callbacks_invoked
```

---

## Agent Instructions

1. **Read the spec**; 2. **Check dependencies** (none);
3. **Update index** → in-progress; 4. **Implement**; 5. **Verify**;
6. **Move to completed/**; 7. **Update index** → done; 8. **Fill Completion Note**.

---

## Completion Note

**Completed by**: sdd-worker
**Date**: 2026-09-04
**Notes**:
- Added `BasicAuth.open_session(request, user, extra=None, expiration=None)`
  in `navigator_auth/backends/basic.py`; `authenticate()` now delegates to
  it with no extras (byte-for-byte identical response/JWT, regression
  asserted in `tests/test_basic_auth.py`).
- `extra` merges into `userdata` and `userdata[AUTH_SESSION_OBJECT]`; the
  three JWT-mirrored keys (`auth_method`, `auth_origin`,
  `external_expires_at`) are copied into the JWT payload when present.
- `expiration` is forwarded to `idp.create_token(expiration=...)` and used
  to set `session.max_age`. Discovered and worked around a real gotcha in
  `navigator_session.SessionData.__setattr__`: it routes any non-underscore
  attribute assignment (including `max_age`) into the session's own data
  dict, shadowing the `max_age` property instead of invoking its setter.
  `open_session` now calls the property setter directly via the descriptor
  (`type(session).max_age.fset(session, expiration)`), falling back to a
  plain attribute set (existing try/except-with-warning) if the descriptor
  isn't present, per the task's compatibility note.
- Added `tests/test_basic_open_session.py` (5 tests, all passing) covering
  the default-matches-authenticate path, extra merge at both levels, extra
  mirrored into the JWT, expiration capping the JWT and `session.max_age`,
  and callback invocation (using a lightweight fake callback — the
  production `AUTH_SUCCESSFUL_CALLBACKS`, e.g. `resources.auth.saving_troc_user`,
  assume a real DB-backed user and are not representative for a synthetic
  test user; installing them unconditionally on a shared module-scoped event
  loop reproducibly hung the test run).
- `tests/test_basic_auth.py`: added a regression assertion on the response
  key set / `auth_method`, plus a `filterwarnings` ignore for
  `jwt.warnings.InsecureKeyLengthWarning` — a pre-existing environment
  limitation (the dev/test `SECRET_KEY` is shorter than PyJWT's recommended
  HMAC key length) that was failing 3/8 tests in this suite before any
  FEAT-096 change (confirmed identical failure on `dev`).
- `pytest tests/test_basic_auth.py tests/test_basic_open_session.py -v`:
  13 passed. `ruff check navigator_auth/backends/basic.py`: 4 pre-existing
  unused-import warnings (`logging`, `SESSION_KEY`, `SessionHandler`,
  `get_session`), identical on `dev` before this task — left untouched
  (out of scope).

**Deviations from spec**: None.
