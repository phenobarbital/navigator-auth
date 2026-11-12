---
id: FC-008
query_id: Q018
type: grep
intent: "Find DDL that lives outside the migration sql/ folders."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 0
---

# FC-008 — DDL that no runner applies (manual patches today)

## Summary

`CREATE TABLE|ALTER TABLE` appears outside the three runner folders in: `navigator_auth/backends/oauth2/ddl.sql` (≈20 `ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS …`), its markdown twin `documentation/client_changes.md`, `documentation/audit-log.md` (`CREATE TABLE audit_log`), and `examples/sql/identity_vault_schema.sql` (canonical identity DDL referenced by migration 004). `ddl.sql` is referenced by no Python file — it is a manual patch, exactly the workflow the source wants to replace. `docs/`, `resources/`, `etc/` contain no DDL.

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

## Notes

No CREATE TABLE for `auth.users` / `auth.groups` / `auth.clients` base tables was found anywhere in the searched paths — base-table creation is out of this repo's migrations today.
