---
id: FW-010
query_id: Q001
type: wiki_query
intent: "Follow-up: DDL for auth tables that lives outside any migration runner."
executed_at: 2026-11-11T13:50:00Z
duration_ms: 0
parent_id: FW-001
depth: 1
---

# FW-010 — Unmanaged DDL: auth.clients changes exist only as loose SQL / docs, applied by hand

## Summary

A follow-up query for base-table DDL finds `auth.clients` OAuth2 column changes in two duplicate places, `navigator_auth/backends/oauth2/ddl.sql` and `documentation/client_changes.md`, neither referenced by any runner found in this lane. This is a concrete instance of the manual-patch problem in the source. `examples/sql/identity_vault_schema.sql` is an example bootstrap of a minimal `auth` schema, applied with `psql`.

## Citations

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

The wiki returned no migration for `auth.users` columns; whether `users` has pending manual patches is not answerable from this lane.
[cross-lane: type=grep, intent=confirm navigator_auth/backends/oauth2/ddl.sql is not loaded by any Python code, and list other loose CREATE/ALTER TABLE files (plan Q018)]
