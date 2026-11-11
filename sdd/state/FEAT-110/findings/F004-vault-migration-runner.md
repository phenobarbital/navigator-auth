---
id: F004
query_id: Q013
type: read
intent: "Read the vault migration runner for the same contract."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 0
merged_from: [FC-004, FW-005]
---

# F004 — Vault runner: same shape, fail-fast, public MIGRATION_FILES

## Summary

[FC-004] `ensure_vault_tables` iterates a public tuple `MIGRATION_FILES` (2 files) in order, with an identical copy of `_run_sql`. No per-file error collection: the first failure propagates. No schema templating.

[FW-005] `navigator_auth/vault/migrations.py` has a public tuple `MIGRATION_FILES` (two files) and `ensure_vault_tables(db_pool)`, which runs them in order with no per-file error handling. It carries its own copy of `_run_sql`, identical to the identity one. The page exposes no `setup_vault_tables` in this module, although `AuthHandler.auth_startup` calls a function of that name (FW-007).

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

- path: `navigator_auth/vault/migrations.py`
  symbol: `MIGRATION_FILES`
  wiki_page_id: `file:navigator_auth/vault/migrations.py`
  excerpt: |
    MIGRATION_FILES = (
        "001_create_vault_tables.sql",
        "002_vault_crypto_hardening.sql",
    )
- path: `navigator_auth/vault/migrations.py`
  symbol: `ensure_vault_tables`
  excerpt: |
    for filename in MIGRATION_FILES:
        await _run_sql(db_pool, (SQL_DIR / filename).read_text())
    logger.info("Vault tables ensured.")
- path: `navigator_auth/vault/migrations.py`
  symbol: `_run_sql`
- path: `navigator_auth/vault/sql/001_create_vault_tables.sql`
  wiki_page_id: same (score 0.14 in follow-up query)

## Notes

[FC-004] `_run_sql` is duplicated verbatim in all three runners (identity, vault, passkey) — a shared runner is an obvious consolidation point.

[FW-005] [cross-lane: type=grep, intent=locate the definition of `setup_vault_tables` (called in auth.py, not defined in vault/migrations.py per its wiki outline)]
