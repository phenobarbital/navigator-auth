---
id: F010
query_id: Q020
type: read
intent: "Read existing migration tests to learn what is asserted and how the DB is faked."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 0
merged_from: [FC-010]
---

# F010 — Migration tests: mocked pool + SQL-text assertions, no live DB

## Summary

`tests/unit/identity/test_identity_migrations.py` fakes the pool with `MagicMock`/`AsyncMock` (`_make_pool_async_cm`, `_make_failing_pool`) and asserts (a) SQL file text is additive/guarded (`TestSQLFile`), (b) runner behaviour: one execute per file, release on awaitable acquire, one failure does not block later files, every failing file reported (`TestEnsureIdentityColumns`), (c) wrapper swallows errors (`TestSetupIdentityColumns`). Sibling tests exist at `tests/unit/vault/test_migrations.py` and `tests/test_passkey_migrations.py`.

## Citations

- path: `tests/unit/identity/test_identity_migrations.py`
  lines: 13-37
  symbol: `_make_failing_pool`
  excerpt: |
    def _make_pool_async_cm():
        """Pool whose acquire() returns an async context manager."""
        conn = AsyncMock()
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=conn)
- path: `tests/unit/identity/test_identity_migrations.py`
  lines: 40-121
  symbol: `TestSQLFile`
- path: `tests/unit/identity/test_identity_migrations.py`
  lines: 156-217
  symbol: `TestEnsureIdentityColumns`
- path: `tests/unit/identity/test_identity_migrations.py`
  lines: 232-247
  symbol: `TestSetupIdentityColumns`
- path: `tests/unit/vault/test_migrations.py`
- path: `tests/test_passkey_migrations.py`

## Notes

Tests import `SQL_DIR` from the runner module; moving SQL files to `docs/migrations/` breaks these imports/paths unless the constants are kept or tests updated.
