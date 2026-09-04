# TASK-069: Oauth2Provider.on_cleanup() never closes its Redis-backed storages

**Feature**: Production-grade 3LO (Three-Legged OAuth2)
**Spec**: `sdd/specs/oauth2-3lo-implementation.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Discovered while implementing FEAT-098 (backend-based password recovery, TASK-066:
`SessionRevoker`). `BasicAuth.on_cleanup()` was fixed there to close its own
`access_token_storage` Redis connection (see
`navigator_auth/backends/basic.py::on_cleanup`, added in TASK-066) — but that fix only
covers the Basic backend. `Oauth2Provider.on_cleanup()` is a pre-existing, unrelated bug:
it is a no-op (`pass`) despite `on_startup()` opening up to seven separate Redis
connections (one per storage, when `OAUTH2_CLIENT_STORAGE`/backing config selects the
Redis-backed implementation). This leaks connections on every app shutdown/reload and is
what causes test-teardown hangs whenever an `Oauth2Provider` instance is spun up in a
test fixture.

Not part of FEAT-098 scope — filed as its own task against the 3LO feature that owns
`Oauth2Provider`.

---

## Scope

- In `navigator_auth/backends/oauth2/backend.py`, implement `Oauth2Provider.on_cleanup()`
  to close every Redis-backed storage created in `on_startup()`:
  `client_storage`, `code_storage`, `refresh_token_storage`, `grant_storage`,
  `access_token_storage`, `device_code_storage`, `client_access_storage`.
- Only close a storage's underlying `redis` connection if it actually has one — several
  of these are selectable at runtime (`OAUTH2_CLIENT_STORAGE=memory|postgres|redis`, see
  `on_startup` lines ~440-459) and `MemoryClientStorage`/`PostgresClientStorage` (and any
  other non-Redis implementation) do not expose a `.redis` attribute. Guard with
  `getattr(storage, "redis", None)` before calling close, same pattern as the TASK-066 fix
  in `BasicAuth.on_cleanup()`.
- Log (warning level, non-fatal) and continue if closing any individual storage raises —
  a failure to close one connection must not prevent closing the others or block shutdown.

**NOT in scope**: changing `on_startup()`, the storage classes themselves, or adding a
`close()`/`aclose()` method to the storage ABCs (that would be a larger refactor — this
task only wires up cleanup at the point where the connections are known and owned).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | Implement `Oauth2Provider.on_cleanup()` to close all storages opened in `on_startup()` |
| `tests/test_oauth2_provider_cleanup.py` | CREATE | Verify `on_cleanup()` closes every Redis-backed storage and tolerates non-Redis storages / individual close failures |

---

## Implementation Notes

### Pattern to Follow

Mirror the fix already applied to `BasicAuth.on_cleanup()` in
`navigator_auth/backends/basic.py` (added by FEAT-098 TASK-066):

```python
async def on_cleanup(self, app: web.Application):
    for attr in (
        "client_storage",
        "code_storage",
        "refresh_token_storage",
        "grant_storage",
        "access_token_storage",
        "device_code_storage",
        "client_access_storage",
    ):
        storage = getattr(self, attr, None)
        redis_conn = getattr(storage, "redis", None)
        if redis_conn is None:
            continue
        try:
            await redis_conn.aclose()
        except Exception as ex:  # pylint: disable=W0703
            self.logger.warning(
                f"Oauth2Provider: error closing {attr} Redis connection: {ex}"
            )
```

### Key Constraints

- Do not assume every storage is Redis-backed — `client_storage` can be
  `MemoryClientStorage` or `PostgresClientStorage` depending on
  `OAUTH2_CLIENT_STORAGE` (see `on_startup`, lines ~440-446).
- Use `redis.aclose()` (async), not `redis.close()` — matches the redis-py async client
  API already used elsewhere in this codebase (see `basic.py::on_cleanup`).
- Each attribute is set to `None` at `__init__` (line ~316 area) before `on_startup`
  runs — `getattr(self, attr, None)` handles the case where `on_cleanup` is called
  without a prior `on_startup` (e.g. partial app init failure).

### References in Codebase

- `navigator_auth/backends/oauth2/backend.py:431-462` — `on_startup`/`on_cleanup`, the
  bug site.
- `navigator_auth/backends/basic.py:75-84` — the equivalent fix already applied to
  `BasicAuth`, use as the reference pattern.
- `navigator_auth/backends/oauth2/code_backend.py`, `client_backend.py`,
  `client_access.py` — storage classes; only the Redis-backed variants set `self.redis`.

---

## Acceptance Criteria

- [ ] `Oauth2Provider.on_cleanup()` closes the Redis connection of every storage attribute
      that has one, and is a no-op for storages that don't (memory/postgres-backed).
- [ ] A failure closing one storage's connection is logged and does not prevent the
      others from being closed.
- [ ] No app-shutdown / test-teardown hangs attributable to `Oauth2Provider` remain.
- [ ] Tests pass: `pytest tests/test_oauth2_provider_cleanup.py -v`.
- [ ] `ruff check navigator_auth/backends/oauth2/backend.py` clean.
- [ ] No regressions: `pytest tests/test_oauth2*.py -v` still passes.

---

## Test Specification

```python
# tests/test_oauth2_provider_cleanup.py
import pytest
from unittest.mock import AsyncMock, MagicMock

from navigator_auth.backends.oauth2.backend import Oauth2Provider


class TestOauth2ProviderCleanup:
    async def test_on_cleanup_closes_all_redis_backed_storages(self):
        """Every storage attribute with a `.redis` client gets `aclose()`d."""
        ...

    async def test_on_cleanup_skips_non_redis_storages(self):
        """Memory/Postgres-backed storages (no `.redis` attr) are skipped without error."""
        ...

    async def test_on_cleanup_tolerates_individual_close_failure(self):
        """One storage's `aclose()` raising does not stop the others from closing."""
        ...

    async def test_on_cleanup_safe_without_prior_startup(self):
        """Calling on_cleanup() when storages are still None (no on_startup) doesn't raise."""
        ...
```

---

## Agent Instructions

1. Read the spec (`sdd/specs/oauth2-3lo-implementation.spec.md`) for `Oauth2Provider`
   context. 2. Index → `in-progress`. 3. Implement per Scope. 4. Verify acceptance
   criteria. 5. Move to `completed/`. 6. Index → `done` + Completion Note.

---

## Completion Note

**Completed by**: sdd-worker (session_016Z3wYUV42WJDq92pifU1Fa)
**Date**: 2026-09-05
**Notes**: Implemented `Oauth2Provider.on_cleanup()` in
`navigator_auth/backends/oauth2/backend.py` to iterate the seven storage
attributes set in `on_startup()` (`client_storage`, `code_storage`,
`refresh_token_storage`, `grant_storage`, `access_token_storage`,
`device_code_storage`, `client_access_storage`), guard each with
`getattr(storage, "redis", None)`, and `await redis_conn.aclose()` inside a
try/except that logs a warning and continues on failure — exactly mirroring
the reference pattern in `BasicAuth.on_cleanup()`
(`navigator_auth/backends/basic.py`, from the not-yet-merged
`feat-FEAT-098-backend-based-password-recovery` branch, confirmed via
`git show` against that branch since it wasn't yet in `dev`). Added
`tests/test_oauth2_provider_cleanup.py` with the four specified cases:
closes every Redis-backed storage, skips storages with no `.redis` attribute,
tolerates one storage's `aclose()` raising without blocking the others, and
is a no-op when called with no prior `on_startup` (all storage attrs still
`None`). All 4 new tests pass; `ruff check` on the modified file shows only
3 pre-existing unrelated `F401` warnings (verified identical against
unmodified `dev`); the broader regression run
`pytest tests/test_oauth2*.py -v` shows 454 passed / 1 skipped / 3 failed,
where the 3 failures (`TestDecodeTokenAudience` in
`test_oauth2_3lo_session_binding.py`, an `InsecureKeyLengthWarning` from a
short test `SECRET_KEY`) are pre-existing and reproduce identically against
unmodified `dev` — confirmed not a regression from this change.

**Deviations from spec**: none. Did not touch `on_startup()`, the storage
classes, or add `close()`/`aclose()` to any storage ABC, per the task's
explicit out-of-scope list.
