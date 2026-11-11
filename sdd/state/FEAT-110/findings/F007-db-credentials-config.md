---
id: F007
query_id: Q017
type: grep
intent: "Find how DB credentials / DSN / AUTH_DB_SCHEMA are configured, to see where admin credentials would plug in."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 0
merged_from: [FC-007]
---

# F007 — One runtime DB credential set; no admin/migration credentials

## Summary

`navigator_auth/conf.py` reads a single credential set (`DBUSER`, `DBPWD`, `DBHOST`, `DBPORT`, `DBNAME`) via navconfig and builds `default_dsn`. Schema/table names come from `AUTH_DB_SCHEMA` (default `auth`), `AUTH_USERS_TABLE`, `AUTH_USERS_VIEW`, `AUTH_GROUPS_TABLE`. There is no separate admin/owner credential setting for DDL.

## Citations

- path: `navigator_auth/conf.py`
  lines: 33-36
  symbol: `AUTH_DB_SCHEMA`
  excerpt: |
    AUTH_DB_SCHEMA = config.get("AUTH_DB_SCHEMA", fallback="auth")
    AUTH_USERS_TABLE = config.get("AUTH_USERS_TABLE", fallback="users")
    AUTH_USERS_VIEW = config.get("AUTH_USERS_VIEW", fallback="vw_users")
    AUTH_GROUPS_TABLE = config.get("AUTH_GROUPS_TABLE", fallback="groups")
- path: `navigator_auth/conf.py`
  lines: 39-45
  symbol: `default_dsn`
  excerpt: |
    DBUSER = config.get("DBUSER")
    DBHOST = config.get("DBHOST", fallback="localhost")
    DBPWD = config.get("DBPWD")
    DBNAME = config.get("DBNAME", fallback="navigator")
    DBPORT = config.get("DBPORT", fallback=5432)
    default_dsn = f"postgres://{DBUSER}:{DBPWD}@{DBHOST}:{DBPORT}/{DBNAME}"

## Notes

"New admin-based credentials" from the source has no existing hook: new settings (e.g. an admin DSN / user+password) or CLI flags would have to be introduced.
