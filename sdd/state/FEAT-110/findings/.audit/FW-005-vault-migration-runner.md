---
id: FW-005
query_id: Q005
type: wiki_page
intent: "API outline of the vault migration runner."
executed_at: 2026-11-11T13:50:00Z
duration_ms: 0
parent_id: null
depth: 0
---

# FW-005 — Vault runner: same shape, two files, stops at first failure

## Summary

`navigator_auth/vault/migrations.py` has a public tuple `MIGRATION_FILES` (two files) and `ensure_vault_tables(db_pool)`, which runs them in order with no per-file error handling. It carries its own copy of `_run_sql`, identical to the identity one. The page exposes no `setup_vault_tables` in this module, although `AuthHandler.auth_startup` calls a function of that name (FW-007).

## Citations

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

[cross-lane: type=grep, intent=locate the definition of `setup_vault_tables` (called in auth.py, not defined in vault/migrations.py per its wiki outline)]
