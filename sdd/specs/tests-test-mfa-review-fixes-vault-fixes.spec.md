---
# SDD flow type and base branch (FEAT-145).
type: feature
base_branch: dev
projects: [vault, mfa, identity]
tags: [vault, key-rotation, asyncdb, asyncpg, fail-closed, ledger-fix]
docs:
  policy: none
  pages: []
  api_modules: [navigator_auth.vault.pool, navigator_auth.mfa.targets, navigator_auth.identity.targets]
---

# Feature Specification: Vault targets on the asyncdb `authdb` pool — native asyncpg connections for rotation

**Feature ID**: FEAT-115
**Date**: 2026-11-11
**Author**: Jesus Lara (spec scaffolded by Claude Code via /sdd-fix)
**Status**: approved
**Target version**: unreleased
**Parent**: FEAT-106 — BasicAuth OTP 2FA review fixes (`sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`, completed)
**Ledger group**: `fixgroup:7ada78ad3fbe` — `issue:82ec902fa145` (bug, major)

---

## 1. Motivation & Business Requirements

### Problem Statement

`issue:82ec902fa145`: navigator-session's `PostgresTarget` (the base of every vault protected target) drives
its connection with the asyncpg API. The application's `authdb` pool is an **asyncdb** pool, whose
connections are asyncdb `pg` drivers with different semantics:

| Call in `PostgresTarget` | asyncpg connection | asyncdb `pg` driver |
|---|---|---|
| `tx = conn.transaction(); await tx.start()` (`postgres.py:228-229`) | transaction object | coroutine that already started it → `AttributeError: 'coroutine' object has no attribute 'start'` |
| `await conn.execute(sql, *args)` in `write`/`quarantine`/`restore_raw` | raises on error, returns `"UPDATE n"` | **never raises**, returns `[result, error]` (asyncdb 2.16.3 `pg.execute` returns from `finally`) |
| `_check_updated(status, ref)` (`postgres.py:356`) | `"UPDATE 0"` → `LookupError` | a list → check skipped, missing row unnoticed |

Verified on `dev` @ `d226b03` against a live Postgres (`mfa_db` asyncdb pool fixture):

| Target built on the asyncdb pool | Today |
|---|---|
| `IdentityTarget(pool)` — `transaction()` | `AttributeError: 'coroutine' object has no attribute 'start'` |
| `UserVaultTarget(pool)` (navigator-session) — `transaction()` | same `AttributeError` |
| `MfaSecretTarget(pool)` — `transaction()` | works: FEAT-106 follow-up `a065202` overrode it to accept the asyncdb awaitable |
| `MfaSecretTarget(pool)` — `write()` of a row that does not exist | **no error** (`LookupError` expected) |
| `MfaSecretTarget(pool)` — `write()` that fails in Postgres (bad UUID) | **no error, nothing written** |

So in-process rotation with the app pool either crashes, or, for MFA seeds, **fails open**:
`rotate_master_key` counts the row as rotated though the seed is still sealed under the old key. Once the
operator retires that key, the seed cannot be opened and the user is locked out of TOTP. The FEAT-106 test
works around this by rotating through the asyncdb pool's private asyncpg pool (`mfa_db._pool`,
`tests/test_mfa_review_fixes_vault.py:186`).

The `navigator-vault` CLI is not affected: it builds its own asyncpg pool
(`navigator_session/vault/migrate/cli.py:177`).

### Goals
- Every vault target navigator-auth ships (`MfaSecretTarget`, `IdentityTarget`) works on the asyncdb
  `authdb` pool with asyncpg semantics: transactions start/commit/roll back, a failed write raises, a
  row-less UPDATE raises `LookupError`.
- A public helper lets in-process callers run navigator-session's own targets (`UserVaultTarget`) on the
  app pool the same way.
- The FEAT-106 rotation test runs on the asyncdb pool with no private-attribute workaround.
- The fail-open `MfaSecretTarget.transaction()` override is removed.

### Non-Goals (explicitly out of scope)
- Changing navigator-session (`PostgresTarget.transaction()` / `execute` handling). That is the upstream
  fix, `../navigator-session` (same code at `c80bdbc`), and is recommended as follow-up work.
- Changing `SessionVault` / `ReservedPrefixSessionVault` connection handling.
- Adding an in-process rotation entry point or HTTP endpoint.

---

## Governing Decisions

decision audit not configured in this repository

---

## 2. Architectural Design

### Overview

Add a pool adapter, `navigator_auth.vault.pool.AsyncpgPoolAdapter`, built with `asyncpg_pool(pool)`. Its
`acquire()` borrows a connection from the wrapped pool, using navigator-session's `acquire_connection`
(asyncpg- or asyncdb-style), and yields the **native asyncpg connection**:

- asyncdb `pg` driver: has a callable `engine()` (alias of `get_connection`, `asyncdb/interfaces/abstract.py:66-69`),
  which returns the asyncpg connection the driver wraps (a `PoolConnectionProxy` from asyncdb's inner
  asyncpg pool). That connection is yielded. A driver whose `engine()` returns `None` or something without
  `transaction` raises `TypeError` (fail closed).
- Any other connection with `fetch_all` but no `engine()` is asyncdb-style with no native connection to
  hand over: `TypeError`.
- Anything else (asyncpg connections, test fakes) is yielded unchanged, so on an asyncpg pool the adapter
  passes everything through.

The connection goes back to the asyncdb pool through its own context manager. `asyncpg_pool()` is
idempotent: an adapter comes back unchanged, never double-wrapped.

`MfaSecretTarget.__init__` and `IdentityTarget.__init__` wrap their pool with `asyncpg_pool()`, so the entry
point factories and in-process callers both get native semantics. The `MfaSecretTarget.transaction()`
override is deleted; the library implementation is now correct for every pool.

### Component Diagram
```
authdb asyncdb pool ──acquire()──▶ pg driver ──engine()──▶ asyncpg PoolConnectionProxy
        ▲                                                        │
AsyncpgPoolAdapter.acquire() ◀───────────────────────────────────┘ yields native conn
        ▲
PostgresTarget (MfaSecretTarget / IdentityTarget / UserVaultTarget) ── rotate_master_key
```

### Integration Points

| Existing Component | Integration Type | Notes |
|---|---|---|
| `navigator_session.vault.targets.postgres.acquire_connection` | uses | borrows from asyncpg- or asyncdb-style pools |
| `navigator_session.vault.targets.postgres.PostgresTarget` | receives adapter as `db_pool` | unchanged library code |
| `MfaSecretTarget` / `IdentityTarget` | modify `__init__` | wrap pool |
| `navigator_auth.vault` package | export | `asyncpg_pool`, `AsyncpgPoolAdapter` |

### Data Models
None.

### New Public Interfaces
```python
# navigator_auth/vault/pool.py
class AsyncpgPoolAdapter:
    pool: Any
    def acquire(self) -> AbstractAsyncContextManager[Any]: ...

def native_connection(conn: Any) -> Any: ...
def asyncpg_pool(pool: Any) -> AsyncpgPoolAdapter: ...
```

---

## 3. Module Breakdown

#### Delegation-eligible modules

| Module | Eligible? | Decided patterns / exact contracts | Why not (if no) |
|---|---|---|---|
| M1: asyncpg pool adapter + target wiring | yes | §2 Overview fixes detection order, errors, idempotence, file layout | — |

### Module 1: asyncpg pool adapter and target wiring (`issue:82ec902fa145`)
- **Path**: `navigator_auth/vault/pool.py` (new); modifies `navigator_auth/vault/__init__.py`,
  `navigator_auth/mfa/targets.py`, `navigator_auth/identity/targets.py`, `docs/vault.rst`, `CHANGELOG.md`
- **Responsibility**: give vault targets native asyncpg connections from any pool; wire both navigator-auth
  targets; drop the fail-open override; document in-process use.
- **Depends on**: navigator-session >= 1.1.1 (`acquire_connection`)
- **Interface Skeleton**:
  ```python
  # navigator_auth/vault/pool.py  (new)
  class AsyncpgPoolAdapter:
      """Pool whose ``acquire()`` yields the native asyncpg connection of any wrapped pool."""
      def __init__(self, pool: Any) -> None:
          """Wrap an asyncpg pool or an asyncdb pool."""
      def acquire(self) -> AbstractAsyncContextManager[Any]:
          """Borrow a connection; yields native_connection(conn); returns it to the wrapped pool on exit."""

  def native_connection(conn: Any) -> Any:
      """asyncdb driver → its engine(); other asyncdb-style (fetch_all, no engine) → TypeError; else conn."""

  def asyncpg_pool(pool: Any) -> AsyncpgPoolAdapter:
      """Wrap ``pool``; an AsyncpgPoolAdapter is returned unchanged."""

  # navigator_auth/mfa/targets.py  (modifies __init__ at :31; deletes transaction() at :37-66)
  class MfaSecretTarget(PostgresTarget):
      def __init__(self, db_pool: Any, schema: str = AUTH_DB_SCHEMA) -> None:
          """... super().__init__(asyncpg_pool(db_pool))."""

  # navigator_auth/identity/targets.py  (modifies __init__ at :36)
  class IdentityTarget(PostgresTarget):
      def __init__(self, db_pool: Any, schema: str = AUTH_DB_SCHEMA) -> None:
          """... super().__init__(asyncpg_pool(db_pool))."""
  ```

---

## 4. Test Specification

### Unit Tests (`tests/unit/vault/test_asyncpg_pool.py`, new)
| Test | Description |
|---|---|
| `test_native_connection_unwraps_asyncdb_driver` | a fake driver with `engine()` yields the raw connection |
| `test_native_connection_passes_asyncpg_through` | a connection without `engine`/`fetch_all` is returned unchanged |
| `test_native_connection_rejects_driver_without_raw` | `engine()` → `None` raises `TypeError` |
| `test_native_connection_rejects_asyncdb_style_without_engine` | `fetch_all` and no `engine` raises `TypeError` |
| `test_asyncpg_pool_is_idempotent` | `asyncpg_pool(asyncpg_pool(p))` is the same adapter |
| `test_adapter_supports_awaitable_acquire_and_releases` | awaitable-style pool: connection unwrapped and released |
| `test_targets_wrap_their_pool` | `MfaSecretTarget(p)._pool` / `IdentityTarget(p)._pool` are adapters around `p`; factories too |

### Changed tests
| Test | Change |
|---|---|
| `tests/test_mfa_review_followups.py::test_mfa_target_transaction_supports_asyncdb_style_connections` | replaced: the fake asyncdb driver exposes `engine()`; the transaction starts/commits/rolls back on the **raw** connection's transaction object |
| `tests/test_mfa_review_fixes_vault.py::test_rotate_master_key_rotates_mfa_seeds` | rotates on the asyncdb `mfa_db` pool: `MfaSecretTarget(mfa_db)`, `UserVaultTarget(asyncpg_pool(mfa_db))`; the `_pool` workaround and its comment are removed |

### Integration Tests (live Postgres, `tests/test_mfa_review_fixes_vault.py`, skip when unavailable)
| Test | Description |
|---|---|
| `test_targets_transaction_on_asyncdb_pool` | `MfaSecretTarget(mfa_db)` and `IdentityTarget(mfa_db)` open/commit a transaction |
| `test_mfa_target_write_fails_closed_on_asyncdb_pool` | `write()` of a missing row raises `LookupError`; a write Postgres rejects raises; the pool still serves `SELECT 1` |

### Validation Contract

tests:
- tests/unit/vault/test_asyncpg_pool.py
- tests/test_mfa_review_fixes_vault.py
- tests/test_mfa_review_followups.py
- tests/unit/identity/test_identity_vault_v2.py
- tests/test_mfa_review_fixes_docs.py
markers: none

### Test Data / Fixtures
`mfa_db` (asyncdb pool on the test DSN, skips when Postgres is down) from `tests/fixtures/mfa.py:60`.

---

## 5. Acceptance Criteria

- [ ] `MfaSecretTarget` and `IdentityTarget` built on the asyncdb `authdb` pool run transactions, raise
      `LookupError` on a row-less write and propagate Postgres errors (live-DB tests above).
- [ ] `rotate_master_key` rotates MFA seeds on the asyncdb pool with no private-attribute access.
- [ ] `asyncpg_pool` / `AsyncpgPoolAdapter` exported from `navigator_auth.vault`; adapter idempotent; an
      asyncdb-style connection with no native connection raises `TypeError`.
- [ ] `MfaSecretTarget.transaction()` override removed; `inspect` / `acquire_connection` imports dropped.
- [ ] Entry-point factories unchanged in signature and still return the target (`factory({"db_pool": object()})`).
- [ ] `docs/vault.rst` documents in-process rotation on the app pool; CHANGELOG "Unreleased" has a bullet.
- [ ] All Validation Contract tests pass; `ruff check` clean on changed files.

---

## 6. Codebase Contract

### Verified Imports
```python
from navigator_session.vault.targets.postgres import PostgresTarget, acquire_connection  # postgres.py:54, :89 (navigator-session 1.1.1)
from navigator_session.vault.targets import UserVaultTarget  # targets/user_vault.py:33, no own __init__
from navigator_session.vault import KeyRing, rotate_master_key  # key_rotation.py:40
from navigator_session.vault.registry import VaultRow
from navigator_auth.mfa.targets import MfaSecretTarget, factory  # mfa/targets.py:16
from navigator_auth.identity.targets import IdentityTarget, factory  # identity/targets.py:21
from tests.fixtures.mfa import mfa_db  # tests/fixtures/mfa.py:61
```

### Existing Class Signatures
```python
# navigator_session/vault/targets/postgres.py (1.1.1)
async def acquire_connection(pool: Any) -> AsyncIterator[Any]  # :53-77 asynccontextmanager; CM or awaitable acquire
class PostgresTarget:
    def __init__(self, db_pool: Any) -> None  # :116, stores self._pool
    async def transaction(self) -> AsyncIterator[Any]  # :218, tx = conn.transaction(); await tx.start() at :228-229
    async def write(self, row, blobs, key_version) -> None  # conn.execute + _check_updated
    @staticmethod
    def _check_updated(status: Any, ref: str) -> None  # LookupError only for str "... 0"

# asyncdb/interfaces/abstract.py (2.16.3)
def get_connection(self): return self._connection  # :66
engine = get_connection  # :69

# navigator_auth/mfa/targets.py
class MfaSecretTarget(PostgresTarget):
    def __init__(self, db_pool: Any, schema: str = AUTH_DB_SCHEMA) -> None  # :31, super().__init__(db_pool) at :35
    async def transaction(self) -> AsyncIterator[Any]  # :37-66 override (to delete)

# navigator_auth/identity/targets.py
class IdentityTarget(PostgresTarget):
    def __init__(self, db_pool: Any, schema: str = AUTH_DB_SCHEMA) -> None  # :36, super().__init__(db_pool) at :41
```

### Does NOT Exist (Anti-Hallucination)
- ~~`asyncdb pgPool.get_pool()` / public raw-pool accessor~~ — only the private `_pool`; do not use it.
- ~~`navigator_auth.vault.pool`~~ — created by this feature.
- ~~an in-process rotation entry point in navigator_auth~~ — `rotate_master_key` is only called from tests.

### Edit Sites (Blueprint Anchors)

Verified against: `d226b03`

| File | Action | Verbatim anchor line | Verified at | Occurrences |
|---|---|---|---|---|
| `navigator_auth/vault/pool.py` | CREATE | — | — | — |
| `navigator_auth/vault/__init__.py` | MODIFY | `from .migrations import ensure_vault_tables` | `__init__.py:10` | 1 |
| `navigator_auth/mfa/targets.py` | MODIFY | `    async def transaction(self) -> AsyncIterator[Any]:` | `targets.py:38` | 1 |
| `navigator_auth/mfa/targets.py` | MODIFY | `        super().__init__(db_pool)` | `targets.py:35` | 1 |
| `navigator_auth/identity/targets.py` | MODIFY | `        super().__init__(db_pool)` | `targets.py:41` | 1 |
| `tests/test_mfa_review_fixes_vault.py` | MODIFY | `    raw_pool = getattr(mfa_db, "_pool", mfa_db)` | `:186` | 1 |
| `tests/test_mfa_review_followups.py` | MODIFY | `async def test_mfa_target_transaction_supports_asyncdb_style_connections():` | `:107` | 1 |
| `tests/unit/vault/test_asyncpg_pool.py` | CREATE | — | — | — |
| `docs/vault.rst` | MODIFY | `Schema migrations` | `vault.rst:42` | 1 |
| `CHANGELOG.md` | MODIFY | `# Unreleased` | `CHANGELOG.md:1` | 1 |

---

## 7. Implementation Notes & Constraints

### Known Risks / Gotchas
- asyncdb `pg.execute()` swallows every error; never let a target write through an asyncdb driver.
  `native_connection` refuses rather than falls back.
- The adapter returns the native connection to asyncdb's acquire context, which releases it to asyncdb's
  inner asyncpg pool; asyncpg's release resets connection state, so an aborted transaction never leaks.
- `MfaSecretTarget(object())` / `IdentityTarget(db_pool=object())` must keep constructing (context tests):
  the adapter only stores the pool.
- Test fakes such as `RecordingPool` (`tests/unit/identity/test_identity_vault_v2.py`) expose asyncpg-style
  connections with no `engine`/`fetch_all`; they must pass through unchanged.

### External Dependencies
None new.

---

## 8. Open Questions

- [x] Fix in navigator-session or in navigator-auth? — navigator-auth adapter now (ledger scope); upstream
      `PostgresTarget` fix recommended as follow-up. *Owner: Jesus Lara*

---

## 9. Design Research Cross-Check

> Status: skipped (/sdd-fix ledger lane — no accepted exploration document).

---

## 10. Documentation

- **Policy**: `none`
- **Pages**: none (the `docs/vault.rst` paragraph ships with Module 1)
- **API modules**: `navigator_auth.vault.pool`

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-11-11 | Claude Code (/sdd-fix) | Initial spec from ledger group `fixgroup:7ada78ad3fbe` |
