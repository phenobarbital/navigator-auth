---
id: FC-004
query_id: Q013
type: read
intent: "Read the vault migration runner for the same contract."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 0
---

# FC-004 — Vault runner: same shape, fail-fast, public MIGRATION_FILES

## Summary

`ensure_vault_tables` iterates a public tuple `MIGRATION_FILES` (2 files) in order, with an identical copy of `_run_sql`. No per-file error collection: the first failure propagates. No schema templating.

## Citations

- path: `navigator_auth/vault/migrations.py`
  lines: 18-24
  symbol: `MIGRATION_FILES`
  excerpt: |
    SQL_DIR = Path(__file__).parent / "sql"
    # Applied in order, at every startup. Each file is idempotent.
    MIGRATION_FILES = (
        "001_create_vault_tables.sql",
        "002_vault_crypto_hardening.sql",
    )
- path: `navigator_auth/vault/migrations.py`
  lines: 27-42
  symbol: `_run_sql`
- path: `navigator_auth/vault/migrations.py`
  lines: 45-57
  symbol: `ensure_vault_tables`
  excerpt: |
    for filename in MIGRATION_FILES:
        await _run_sql(db_pool, (SQL_DIR / filename).read_text())
    logger.info("Vault tables ensured.")

## Notes

`_run_sql` is duplicated verbatim in all three runners (identity, vault, passkey) — a shared runner is an obvious consolidation point.
