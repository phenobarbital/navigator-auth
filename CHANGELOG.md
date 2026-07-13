# Unreleased

- **Audit log — tenant scoping & query API.** `AuditLog.log()` now accepts an
  optional keyword-only `tenant`, threaded to every backend (SQL column,
  document field, influx tag, logger message). New `AuditLog.query(*, tenant, ...)`
  reads entries back, always constrained to one tenant (SQL backends; other
  families degrade to `[]` with a warning). Added the pure `build_select()`
  helper and a `tenant` column/index on the audit table. Backwards-compatible —
  existing PDP callers are unaffected. See `documentation/audit-log.md`.

# v0.0.6

- NoAuth, Basic Authentication
- DjangoAuth (getting user info using Django SessionID)
# v0.0.1

- First Version
- Work with Basic Authentication
