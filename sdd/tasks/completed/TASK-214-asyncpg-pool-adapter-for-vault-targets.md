# TASK-214: asyncpg pool adapter for vault targets on the asyncdb authdb pool

**Feature**: FEAT-115 — Vault targets on the asyncdb `authdb` pool — native asyncpg connections for rotation
**Spec**: `sdd/specs/tests-test-mfa-review-fixes-vault-fixes.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned
**Discovered-from**: `issue:82ec902fa145`

---

## Context

Ledger `issue:82ec902fa145` (bug, major): navigator-session's `PostgresTarget` uses the asyncpg
connection API (`conn.transaction()` then `await tx.start()`; `execute()` that raises and returns
`"UPDATE n"`). The application's `authdb` pool is an asyncdb pool. Its `pg` driver's `transaction()` is a
coroutine that has already started the transaction, and its `execute()` never raises and returns
`[result, error]`. On `dev` @ `d226b03`, with the live `mfa_db` asyncdb pool:

- `IdentityTarget(pool)` / `UserVaultTarget(pool)`: `transaction()` raises
  `AttributeError: 'coroutine' object has no attribute 'start'`.
- `MfaSecretTarget(pool)`: the FEAT-106 override (`a065202`) makes `transaction()` work, but `write()` to a
  missing row and a `write()` Postgres rejects both return **without error**. Rotation then counts an
  unwritten seed as rotated (fail-open).

The FEAT-106 rotation test hides this by rotating through `mfa_db._pool` (the private asyncpg pool).
This task implements spec §3 Module 1: a pool adapter that yields the native asyncpg connection under the
asyncdb driver, wired into both navigator-auth targets. The fail-open override is removed.

---

## Scope

- Create `navigator_auth/vault/pool.py` with `AsyncpgPoolAdapter`, `native_connection()` and
  `asyncpg_pool()` exactly as spec §2/§3 define them.
- Export `asyncpg_pool` and `AsyncpgPoolAdapter` from `navigator_auth.vault`.
- `MfaSecretTarget.__init__` and `IdentityTarget.__init__`: pass `asyncpg_pool(db_pool)` to `super().__init__`.
- Delete `MfaSecretTarget.transaction()` and the now-unused imports (`inspect`, `asynccontextmanager`,
  `AsyncIterator`, `acquire_connection`).
- Tests: new unit tests for the adapter; replace the fake-driver test in `tests/test_mfa_review_followups.py`;
  drop the `_pool` workaround in the rotation test and add two live-DB tests (spec §4).
- Add a short "In-process rotation" note to `docs/vault.rst` and a CHANGELOG "Unreleased" bullet.

**NOT in scope**: changing navigator-session; `SessionVault` / `ReservedPrefixSessionVault`; any new
rotation entry point.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/vault/pool.py` | CREATE | adapter + `native_connection` + `asyncpg_pool` |
| `navigator_auth/vault/__init__.py` | MODIFY | export `asyncpg_pool`, `AsyncpgPoolAdapter` |
| `navigator_auth/mfa/targets.py` | MODIFY | wrap pool; delete `transaction()` override |
| `navigator_auth/identity/targets.py` | MODIFY | wrap pool |
| `tests/unit/vault/test_asyncpg_pool.py` | CREATE | adapter unit tests |
| `tests/test_mfa_review_followups.py` | MODIFY | replace fake-driver transaction test |
| `tests/test_mfa_review_fixes_vault.py` | MODIFY | rotate on asyncdb pool; live-DB fail-closed tests |
| `docs/vault.rst` | MODIFY | in-process rotation note |
| `CHANGELOG.md` | MODIFY | Unreleased bullet |

---

## Codebase Contract (Anti-Hallucination)

### Verified Imports
```python
from navigator_session.vault.targets.postgres import PostgresTarget, acquire_connection  # postgres.py:54, :89 (navigator-session 1.1.1)
from navigator_session.vault.targets import UserVaultTarget  # targets/user_vault.py:33 (inherits PostgresTarget.__init__)
from navigator_session.vault import KeyRing, rotate_master_key  # key_rotation.py:40
from navigator_session.vault.registry import VaultRow
from navigator_auth.mfa.targets import MfaSecretTarget, factory  # mfa/targets.py:16, :85
from navigator_auth.identity.targets import IdentityTarget, factory  # identity/targets.py:21, :60
from tests.fixtures.mfa import mfa_db  # tests/fixtures/mfa.py:61 (asyncdb pool; skips when Postgres is down)
```

### Existing Signatures to Use
```python
# navigator_session/vault/targets/postgres.py (1.1.1)
@asynccontextmanager
async def acquire_connection(pool: Any) -> AsyncIterator[Any]  # :53-77; `async with` if acquire() has __aenter__, else await + release
class PostgresTarget:
    def __init__(self, db_pool: Any) -> None  # :116; self._pool = db_pool
    async def transaction(self) -> AsyncIterator[Any]  # :218; tx = conn.transaction(); await tx.start() (:228-229)
    async def write(self, row, blobs, key_version) -> None  # conn.execute(...) then _check_updated
    @staticmethod
    def _check_updated(status: Any, ref: str) -> None  # LookupError only when status is str ending " 0"

# asyncdb/interfaces/abstract.py (2.16.3)
def get_connection(self): return self._connection  # :66
engine = get_connection  # :69  -> asyncpg PoolConnectionProxy for the pg driver

# navigator_auth/mfa/targets.py
class MfaSecretTarget(PostgresTarget):
    def __init__(self, db_pool: Any, schema: str = AUTH_DB_SCHEMA) -> None  # :31; super().__init__(db_pool) at :35
    async def transaction(self) -> AsyncIterator[Any]  # :37-66 (decorator at :37) — DELETE

# navigator_auth/identity/targets.py
class IdentityTarget(PostgresTarget):
    def __init__(self, db_pool: Any, schema: str = AUTH_DB_SCHEMA) -> None  # :36; super().__init__(db_pool) at :41
```

### Does NOT Exist
- ~~public raw-pool accessor on asyncdb `pgPool`~~ — only private `_pool`; never use it.
- ~~`navigator_auth.vault.pool`~~ — this task creates it.
- ~~in-process rotation entry point in `navigator_auth`~~ — `rotate_master_key` is called only from tests.
- ~~`[tool.ruff]` in `pyproject.toml`~~ — ruff is not configured; lint with flake8 (`pyproject.toml:107` dev dep).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/vault/pool.py", "action": "CREATE"},
    {"path": "navigator_auth/vault/__init__.py", "action": "MODIFY"},
    {"path": "navigator_auth/mfa/targets.py", "action": "MODIFY"},
    {"path": "navigator_auth/identity/targets.py", "action": "MODIFY"},
    {"path": "tests/unit/vault/test_asyncpg_pool.py", "action": "CREATE"},
    {"path": "tests/test_mfa_review_followups.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_review_fixes_vault.py", "action": "MODIFY"},
    {"path": "docs/vault.rst", "action": "MODIFY"},
    {"path": "CHANGELOG.md", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/mfa/targets.py#MfaSecretTarget",
    "sym:navigator_auth/mfa/targets.py#MfaSecretTarget.transaction",
    "sym:navigator_auth/identity/targets.py#IdentityTarget",
    "sym:tests/test_mfa_review_fixes_vault.py#test_rotate_master_key_rotates_mfa_seeds",
    "sym:tests/test_mfa_review_followups.py#test_mfa_target_transaction_supports_asyncdb_style_connections"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- Fail closed: an asyncdb-style connection (`fetch_all`) with no native connection raises `TypeError`;
  never fall back to driving the asyncdb driver (its `execute()` swallows errors).
- `asyncpg_pool` is idempotent — never double-wrap.
- `MfaSecretTarget(object())`, `IdentityTarget(db_pool=object())` and `factory({"db_pool": object()})` must
  keep constructing (existing context/factory tests).
- Asyncpg-style fakes (`RecordingPool` in `tests/unit/identity/test_identity_vault_v2.py`) must pass through.

---

## Implementation Blueprint

### Steps (in order)
1. Create `navigator_auth/vault/pool.py` — *why*: one adapter serves every `PostgresTarget`, including
   navigator-session's `UserVaultTarget`, which navigator-auth cannot subclass at its factory.
2. Export it from `navigator_auth/vault/__init__.py` — *why*: in-process callers wrap `UserVaultTarget`'s pool.
3. Wrap the pool in both target `__init__`s and delete the `MfaSecretTarget.transaction()` override — *why*:
   the library `transaction()` is correct on a native connection; the override is the fail-open path.
4. Update the tests, then docs/CHANGELOG — *why*: AC1–AC6.

### `navigator_auth/vault/pool.py` (CREATE)
```python
"""asyncpg view of an application database pool, for vault protected targets.

``PostgresTarget`` (navigator-session) drives its connection with the asyncpg API, while the application's
``authdb`` pool is an asyncdb pool whose ``pg`` driver has a started-on-await ``transaction()`` and an
``execute()`` that never raises. ``asyncpg_pool()`` borrows from the application pool and hands targets
the native asyncpg connection under the driver, so writes fail closed.
"""
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any, AsyncIterator

from navigator_session.vault.targets.postgres import acquire_connection


def native_connection(conn: Any) -> Any:
    """Return the asyncpg connection behind ``conn``.

    Raises:
        TypeError: ``conn`` is asyncdb-style but exposes no native connection.
    """
    # FILL IN: callable `engine` -> raw = engine(); raw None or without callable `transaction` -> TypeError;
    #          else `fetch_all` present -> TypeError; else return conn unchanged — bounded by spec §2 Overview
    raise NotImplementedError


class AsyncpgPoolAdapter:
    """Pool whose ``acquire()`` yields native asyncpg connections from the wrapped pool."""

    def __init__(self, pool: Any) -> None:
        """Wrap an asyncpg pool or an asyncdb pool."""
        self.pool = pool

    def acquire(self) -> AbstractAsyncContextManager[Any]:
        """Borrow a connection; it goes back to the wrapped pool when the context exits."""
        return self._acquire()

    @asynccontextmanager
    async def _acquire(self) -> AsyncIterator[Any]:
        async with acquire_connection(self.pool) as conn:
            yield native_connection(conn)


def asyncpg_pool(pool: Any) -> AsyncpgPoolAdapter:
    """Wrap ``pool`` for vault targets; an ``AsyncpgPoolAdapter`` is returned unchanged."""
    # FILL IN: idempotent wrap — bounded by AC3
    raise NotImplementedError
```
**Why this shape**: `acquire_connection` already handles both acquire styles and releases on exit; the
adapter only changes what is yielded. `acquire()` returns an async context manager, so `PostgresTarget`'s
own `acquire_connection` takes its `async with` branch.

### `navigator_auth/vault/__init__.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'from .migrations import ensure_vault_tables' navigator_auth/vault/__init__.py)
# AFTER — insert below `from .migrations import ensure_vault_tables` (verified: navigator_auth/vault/__init__.py:10)
from .pool import AsyncpgPoolAdapter, asyncpg_pool
# and add "AsyncpgPoolAdapter", "asyncpg_pool" to __all__
```

### `navigator_auth/mfa/targets.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '        super().__init__(db_pool)' navigator_auth/mfa/targets.py) — :35
        super().__init__(asyncpg_pool(db_pool))
# occurrences: 1 (verified: grep -c 'async def transaction(self) -> AsyncIterator\[Any\]:' navigator_auth/mfa/targets.py) — :38
# DELETE the whole override (decorator :37 through :66) and the imports it alone used:
#   `import inspect`, `from contextlib import asynccontextmanager`, `AsyncIterator`, `acquire_connection`
# ADD: from ..vault.pool import asyncpg_pool
```
**Why**: the override accepted the asyncdb awaitable but left `write()` on asyncdb's `execute()`.

### `navigator_auth/identity/targets.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '        super().__init__(db_pool)' navigator_auth/identity/targets.py) — :41
        super().__init__(asyncpg_pool(db_pool))
# ADD: from ..vault.pool import asyncpg_pool
```

### Tests (CREATE / MODIFY)
```python
# tests/test_mfa_review_fixes_vault.py — occurrences: 1 (verified: grep -c 'raw_pool = getattr(mfa_db, "_pool", mfa_db)') — :186
# FILL IN: delete the workaround comment + raw_pool; rotate with
#   [UserVaultTarget(asyncpg_pool(mfa_db)), MfaSecretTarget(mfa_db)]; add test_targets_transaction_on_asyncdb_pool
#   and test_mfa_target_write_fails_closed_on_asyncdb_pool (spec §4) — bounded by AC1, AC2
# tests/test_mfa_review_followups.py — occurrences: 1 — :107
# FILL IN: replace with a fake asyncdb driver exposing engine() -> raw conn whose transaction() returns
#   a start/commit/rollback object; assert start, commit / start, rollback recorded on the raw tx — bounded by AC1
# tests/unit/vault/test_asyncpg_pool.py — FILL IN: the 7 unit tests listed in spec §4
```

### FILL IN checklist
- [ ] `pool.py::native_connection` — detection order and `TypeError`s; bounded by spec §2
- [ ] `pool.py::asyncpg_pool` — idempotent; bounded by AC3
- [ ] tests per spec §4; bounded by AC1–AC3
- [ ] `docs/vault.rst` (insert before `Schema migrations`, :42) + CHANGELOG bullet; bounded by AC6

---

## Acceptance Criteria

- [ ] AC1: `MfaSecretTarget` / `IdentityTarget` on the asyncdb pool run transactions, raise `LookupError` on
      a row-less write and propagate Postgres errors.
- [ ] AC2: `rotate_master_key` rotates MFA seeds on the asyncdb pool with no private-attribute access.
- [ ] AC3: `asyncpg_pool` / `AsyncpgPoolAdapter` exported from `navigator_auth.vault`; idempotent;
      asyncdb-style connection without a native connection raises `TypeError`.
- [ ] AC4: `MfaSecretTarget.transaction()` override and its imports removed.
- [ ] AC5: factories unchanged; `factory({"db_pool": object()})` still returns the target.
- [ ] AC6: `docs/vault.rst` note + CHANGELOG bullet.
- [ ] flake8 clean on changed Python files.

---

## Validation Commands

- `pytest tests/unit/vault/test_asyncpg_pool.py -q`
- `pytest tests/test_mfa_review_fixes_vault.py -q`
- `pytest tests/test_mfa_review_followups.py -q`
- `pytest tests/unit/identity/test_identity_vault_v2.py -q`
- `pytest tests/test_mfa_review_fixes_docs.py -q`

---

## Test Specification

```python
# tests/unit/vault/test_asyncpg_pool.py
import pytest
from navigator_auth.vault import AsyncpgPoolAdapter, asyncpg_pool
from navigator_auth.vault.pool import native_connection


def test_asyncpg_pool_is_idempotent():
    adapter = asyncpg_pool(object())
    assert asyncpg_pool(adapter) is adapter


def test_native_connection_rejects_asyncdb_style_without_engine():
    class _Conn:
        async def fetch_all(self, *a): ...
    with pytest.raises(TypeError):
        native_connection(_Conn())
```

---

## Agent Instructions

1. Work in the feature worktree (`parrot sdd worktree ensure --slug tests-test-mfa-review-fixes-vault-fixes --feature-id FEAT-115`).
2. Read the spec; verify the Codebase Contract; set status `in-progress` in the per-spec index.
3. Implement from the blueprint; run the Validation Commands; commit only the listed files.
4. `parrot sdd task close TASK-214 tests-test-mfa-review-fixes-vault-fixes verified`; fill the Completion Note.

---

## Completion Note

**Completed by**: agent:sdd-fix:e9a076bc (Claude Code, /sdd-fix issue:82ec902fa145)
**Date**: 2026-11-11
**Notes**: Implemented in `df73ea6`. `navigator_auth/vault/pool.py` adds `AsyncpgPoolAdapter`,
`native_connection()` and `asyncpg_pool()` (exported from `navigator_auth.vault`). `MfaSecretTarget` and
`IdentityTarget` wrap their pool; the fail-open `MfaSecretTarget.transaction()` override is deleted.
Validation Commands: all five pass in the worktree against live Postgres (37 tests, no skips), plus
`tests/unit/vault`, `tests/unit/identity` and `tests/test_mfa_trusted_devices.py` (366 passed). Live-DB
tests now prove that, on the asyncdb pool, `IdentityTarget`/`MfaSecretTarget` transactions run, a row-less
write raises `LookupError`, a rejected write raises, and rotation works without `mfa_db._pool`. flake8: no
new findings (F811 warnings are the file's existing fixture-import pattern); pylint 10/10 on `pool.py`.
Adversarial review: `codex exec review --base 060e3f4`, no actionable findings; its test claims were
spot-checked (logs `artifacts/logs/review_*.log`: 32 passed, 5 DB tests skipped in its sandbox).

**Deviations from spec**: one extra unit test
(`test_adapter_supports_context_acquire_and_releases_on_refusal`): a refused driver is still returned to a
context-manager pool. Upstream navigator-session (`PostgresTarget.transaction()` / `execute`) is unchanged,
per the spec's non-goals.
