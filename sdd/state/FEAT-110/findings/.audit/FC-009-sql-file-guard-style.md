---
id: FC-009
query_id: Q019
type: read
intent: "Read the newest identity migrations to capture the guard/idempotency style SQL files use."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 0
---

# FC-009 — SQL files are idempotent by construction (IF NOT EXISTS + catalog-guarded DO blocks)

## Summary

`004_identity_base_columns.sql` shows the house style: a header comment with the FEAT id and rationale, `ALTER TABLE IF EXISTS … ADD COLUMN IF NOT EXISTS`, an idempotent backfill `UPDATE`, and a `DO $$ … $$` block guarded on `to_regclass(...)` and `pg_constraint` lookups. Files are designed to be re-run on every startup and to no-op on an up-to-date DB. Schema name `auth.` is hard-coded.

## Citations

- path: `navigator_auth/identity/sql/004_identity_base_columns.sql`
  lines: 15-23
  symbol: (ADD COLUMN block)
  excerpt: |
    ALTER TABLE IF EXISTS auth.user_identities
        ADD COLUMN IF NOT EXISTS identity_id  UUID DEFAULT gen_random_uuid(),
        ADD COLUMN IF NOT EXISTS display_name VARCHAR(254),
        ...
        ADD COLUMN IF NOT EXISTS avatar       TEXT;
- path: `navigator_auth/identity/sql/004_identity_base_columns.sql`
  lines: 37-57
  symbol: (guarded DO block)
  excerpt: |
    DO $$
    BEGIN
        IF to_regclass('auth.user_identities') IS NULL THEN
            RETURN;
        END IF;
        ...
        IF current_pk IS DISTINCT FROM 'identity_id' THEN
            CREATE UNIQUE INDEX IF NOT EXISTS uq_user_identities_identity_id
                ON auth.user_identities (identity_id);

## Notes

Because every file is idempotent, a "compare with existing tables" step can be as simple as re-running all files; a ledger table would add reporting ("what was applied when"), not correctness. Header comment at lines 3-7 documents the exact failure a stale DB shows: `column "identity_id" does not exist`.
