---
id: F008
query_id: Q018
type: grep
intent: "Find DDL that lives outside the migration sql/ folders."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 1
merged_from: [FC-008, FW-010]
---

# F008 — DDL that no runner applies (manual patches today)

## Summary

[FC-008] `CREATE TABLE|ALTER TABLE` appears outside the three runner folders in: `navigator_auth/backends/oauth2/ddl.sql` (≈20 `ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS …`), its markdown twin `documentation/client_changes.md`, `documentation/audit-log.md` (`CREATE TABLE audit_log`), and `examples/sql/identity_vault_schema.sql` (canonical identity DDL referenced by migration 004). `ddl.sql` is referenced by no Python file — it is a manual patch, exactly the workflow the source wants to replace. `docs/`, `resources/`, `etc/` contain no DDL.

[FW-010] A follow-up query for base-table DDL finds `auth.clients` OAuth2 column changes in two duplicate places, `navigator_auth/backends/oauth2/ddl.sql` and `documentation/client_changes.md`, neither referenced by any runner found in this lane. This is a concrete instance of the manual-patch problem in the source. `examples/sql/identity_vault_schema.sql` is an example bootstrap of a minimal `auth` schema, applied with `psql`.

## Citations

- path: `navigator_auth/backends/oauth2/ddl.sql`
  lines: 7-33
  symbol: (auth.clients patch)
  excerpt: |
    ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client          VARCHAR(255);
    ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client_name     VARCHAR(255) NOT NULL;
    ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client_type     VARCHAR(50)  NOT NULL DEFAULT 'public';
- path: `documentation/client_changes.md`
  lines: 1-26
  symbol: (ALTER TABLE para auth.clients)
- path: `documentation/audit-log.md`
  lines: 149-170
  symbol: (CREATE TABLE audit_log)
- path: `examples/sql/identity_vault_schema.sql`
  symbol: (canonical identity DDL)

- path: `navigator_auth/backends/oauth2/ddl.sql`
  wiki_page_id: same (score 0.57)
  excerpt: |
    ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client          VARCHAR(255);
    ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client_name     VARCHAR(255) NOT NULL;
    ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS client_secret   VARCHAR(255);
- path: `documentation/client_changes.md`
  wiki_page_id: same (score 0.16)
  excerpt: |
    # ALTER TABLE para auth.clients (OAuth2 public clients)
- path: `examples/sql/identity_vault_schema.sql`
  wiki_page_id: same (score 0.11)
  excerpt: |
    -- Apply with:
    --   psql "$DSN" -f examples/sql/identity_vault_schema.sql

## Notes

[FC-008] No CREATE TABLE for `auth.users` / `auth.groups` / `auth.clients` base tables was found anywhere in the searched paths — base-table creation is out of this repo's migrations today.

[FW-010] The wiki returned no migration for `auth.users` columns; whether `users` has pending manual patches is not answerable from this lane.
[cross-lane: type=grep, intent=confirm navigator_auth/backends/oauth2/ddl.sql is not loaded by any Python code, and list other loose CREATE/ALTER TABLE files (plan Q018)]
