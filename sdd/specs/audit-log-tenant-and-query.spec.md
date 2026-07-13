---
type: feature
base_branch: dev
---

<!-- LANGUAGE: English only. -->

# Feature Specification: Audit Log — Tenant Scoping & Query API

**Feature**: audit-log-tenant-and-query
**Branch**: `feat-audit-tenant-and-query` (off `dev`)
**Date**: 2026-07-13
**Author**: FieldSync team (with Jesús Lara's "reuse nav-auth audit log" direction)
**Status**: implemented (pending PR to `phenobarbital/navigator-auth` `dev` + Jesús's review)

> **Resume anchor.** This spec exists so the work survives a context compaction.
> It captures the verified current state of `navigator_auth/abac/audit.py`, the
> planned change, and how the downstream consumer (FieldSync FEAT-314) uses it.

---

## 1. Motivation

FieldSync **FEAT-314 (Audit Trail & Compliance Log)** must reuse navigator-auth's
audit log instead of building its own store (decision: Jesús Lara). A code review
of the FieldSync implementation found two blockers that trace back to gaps in
`navigator_auth.abac.audit.AuditLog`:

1. **No tenant scoping.** `AuditLog` records have no `tenant`, and the `audit_log`
   table has no tenant column — so a `GET /api/v1/audit` read cannot be constrained
   to one tenant → cross-tenant audit/PII leak. (nav-auth already scopes *policies*
   per tenant — see `sdd/specs/per-tenant-policy-scoping.spec.md`; audit should too.)
2. **No read/query API.** `AuditLog` only writes (`log()`); it has no `query()`, so
   consumers hand-roll raw reads. A tenant-scoped `query()` belongs in nav-auth.

Adding both makes the audit log **multi-tenant and queryable** for every consumer,
and lets FieldSync FEAT-314 drop its interim `compliance.audit_log` table and reuse
nav-auth fully.

---

## 2. Current State (verified 2026-07-13, `navigator_auth/abac/audit.py` on `dev`)

- Backend **families** (via `AUDIT_BACKEND`): `log` (logger), `timeseries`
  (`influx`), `document` (`mongo`/`documentdb`), `sql` (any asyncdb driver +
  `AUDIT_DSN`). Classified by `AuditLog._resolve_family()`.
- Pure helpers: `resolve_paramstyle()`, `build_placeholders()`, `build_insert()`
  (paramstyle-aware, unit-tested independently). `SQL_PARAMSTYLES` maps drivers →
  dialect; `_PARAMSTYLE_RENDERERS` renders the n-th placeholder.
- `_build_record(answer, status, user, host) -> dict` → columns: `timestamp,
  environment, domain, host, status, message (=answer.response), rule, username,
  user_id`. **No `tenant`.**
- `async log(answer, status, user)` dispatches to `_log_to_logger` / `_log_to_influx`
  / `_log_to_document` / `_log_to_db`. Writes are **best-effort** (driver errors are
  caught + logged, never raised).
- **No `query()` method exists.**
- Settings (`navigator_auth/conf.py`): `ENABLE_AUDIT_LOG` (491), `AUDIT_BACKEND`
  (498, default `influx`), `AUDIT_DSN` (510), `AUDIT_TABLE` (512, default `audit_log`),
  `AUDIT_PARAMSTYLE` (519, default `format`), `AUDIT_CREDENTIALS` (522, = INFLUX creds).

---

## 3. Design / Changes (backwards-compatible)

### 3.1 Tenant on writes
- `_build_record(answer, status, user, host, *, tenant=None)` adds a `tenant` key.
- `AuditLog.log(answer, status, user, *, tenant=None)` threads `tenant` to every
  write path: logger (include in message), influx (tag), document (field), sql
  (column). `tenant` is **optional** → existing PDP callers (`log(answer, status, user)`)
  are unaffected.

### 3.2 `tenant` column on the SQL audit table
- The `AUDIT_TABLE` gains a `tenant` column. nav-auth does not own DDL/migrations;
  document the required column + a suggested migration. Consumers (FieldSync) run it.
  Index suggestion: `(tenant, timestamp DESC)`.

### 3.3 New `query()` read API
- `async AuditLog.query(*, tenant, user_id=None, username=None, status=None,
  rule=None, since=None, until=None, limit=100, offset=0) -> list[dict]`.
- **`tenant` is required** and always constrains the read.
- Backend-aware:
  - `sql`: parameterised `SELECT ... WHERE tenant = ? [AND ...] ORDER BY timestamp DESC
    LIMIT/OFFSET` — via a pure `build_select(table, conditions, paramstyle, ...)` helper
    (unit-testable like `build_insert`; conditions are `(column, operator, value)` triples).
  - `document` / `timeseries` (influx) / `log`: **write-only through this API** — `query()`
    logs a warning and returns `[]`. **Decision (impl):** structured reads are SQL-only for
    now; the real consumer (FieldSync) uses Postgres, and shipping untested influx/mongo read
    queries would violate the "backend-safe, degrade cleanly" requirement from the FEAT-314
    review (Major 3). Query those stores directly if needed. The **write** path still supports
    all four families (tenant as column/field/tag/message).
- Read errors are best-effort (catch driver errors, log, return `[]`) — consistent
  with the write side.
- `tenant=None` raises `ValueError` (a query can never span tenants).

### 3.4 Tests
- Extend the existing pure-helper tests: `build_select` + `build_placeholders` for all
  paramstyles.
- `_build_record` includes `tenant` when provided; `log(..., tenant=...)` round-trips.
- `query()` filters by tenant (a fake driver asserts tenant is always in the WHERE),
  pagination, unsupported backend (`log`) → `[]`.

---

## 4. Module Breakdown (candidate tasks)
- **T1** — tenant on writes: `_build_record` + `log(*, tenant=None)` + 4 write paths + tests.
- **T2** — `query()` + `build_select` helper + backend reads + tests.
- **T3** — docs (`config.rst`, `changelog.rst`) + audit-table `tenant` DDL/migration note.

---

## 5. Downstream Consumption (FieldSync FEAT-314)
- FieldSync uses nav-auth via editable source: uncomment
  `navigator-auth = { path = "../navigator-auth", editable = true }` in fieldsync
  `pyproject.toml [tool.uv.sources]` (do NOT commit) + `uv sync` in fieldsync's venv.
- `apps/compliance/audit_log.py::AuditLogAdapter` then calls `log(..., tenant=...)`
  and `query(tenant=...)`, and the interim `compliance.audit_log` own-table plan
  (FieldSync `TASK-314-5`) is **dropped** in favour of nav-auth.
- `GET /api/v1/audit` resolves tenant server-side (like `apps/claims _get_tenant`) and
  passes it to `AuditLog.query(tenant=...)`.

---

## 6. Codebase Contract (anti-hallucination)
```python
# navigator_auth/abac/audit.py (dev):
def _build_record(answer, status, user, host) -> dict          # add *, tenant=None
def build_insert(table, record, paramstyle) -> tuple[str,list] # pattern for build_select
def resolve_paramstyle(backend, default="format") -> str
def build_placeholders(paramstyle, count) -> list[str]
class AuditLog:
    def __init__(self)                        # _backend/_family/_driver/_paramstyle
    async def log(self, answer, status, user) # add *, tenant=None
    # NO query() yet — this feature adds it
# conf.py: AUDIT_BACKEND, AUDIT_DSN, AUDIT_TABLE, AUDIT_PARAMSTYLE, AUDIT_CREDENTIALS, ENABLE_AUDIT_LOG
```
### Does NOT exist
- ~~`AuditLog.query()`~~ — added by this feature.
- ~~`tenant` in `_build_record` / the audit table~~ — added by this feature.

---

## 7. Open / Coordination
- **PR to `phenobarbital/navigator-auth` `dev`** — this is Jesús's platform library; needs his buy-in.
- **Release + version bump** for non-editable consumers (FieldSync dev uses editable path meanwhile).
- **Audit-table `tenant` migration** is ops-owned (nav-auth doesn't manage DDL).
- Cross-ref: FieldSync `sdd/specs/audit-trail-compliance.spec.md` (FEAT-314) + its `TASK-314-5`
  (review remediation) — the tenant fix there defers to THIS spec once landed.

## Revision History
| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-07-13 | FieldSync team | Initial spec (resume anchor): tenant scoping + `query()` on `AuditLog`, driven by FieldSync FEAT-314 review. |
| 0.2 | 2026-07-13 | FieldSync team | **Implemented.** `tenant` on `_build_record`/`log()` across all 4 write families; `build_select()` helper; `AuditLog.query(*, tenant, ...)` SQL-only (other families degrade to `[]`+warning); docs (`documentation/audit-log.md`, `CHANGELOG.md`) + `tenant` DDL/migration + index. 34 unit tests pass (`tests/test_audit_backends.py`, incl. 18 new). Pending PR to Jesús's `dev`. |
