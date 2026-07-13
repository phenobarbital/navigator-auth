# PBAC Audit Log Backends

The ABAC/PBAC **Policy Decision Point** (`navigator_auth/abac/pdp.py`) records
every access decision through the pluggable `AuditLog`
(`navigator_auth/abac/audit.py`). Each `allow`/`deny` outcome is written to the
configured backend.

## Configuration

All settings live in `navigator_auth/conf.py` and are read from the environment.

| Setting             | Default          | Purpose                                                              |
|---------------------|------------------|----------------------------------------------------------------------|
| `ENABLE_AUDIT_LOG`  | `true`           | Master switch. When `false`, everything falls back to the logger.    |
| `AUDIT_BACKEND`     | `influx`         | Which backend to use (see below).                                    |
| `AUDIT_DSN`         | `None`           | Connection DSN for SQL/document drivers. **Required** for those.     |
| `AUDIT_TABLE`       | `audit_log`      | Destination table (SQL) or collection (document/Mongo).              |
| `AUDIT_PARAMSTYLE`  | `format`         | SQL placeholder dialect for drivers not auto-detected.               |
| `INFLUX_*`          | see below        | InfluxDB credentials (host/port/database/org/token).                 |

### InfluxDB credentials (`AUDIT_BACKEND=influx`)

| Setting          | Default            |
|------------------|--------------------|
| `INFLUX_HOST`    | `localhost`        |
| `INFLUX_PORT`    | `8086`             |
| `INFLUX_DATABASE`| `navigator_audit`  |
| `INFLUX_ORG`     | `navigator`        |
| `INFLUX_TOKEN`   | *(unset)*          |

## Supported backends

The backend is selected by name and classified into one of four **families**,
each with its own write mechanism:

| `AUDIT_BACKEND`            | Family       | Write mechanism                          | Extra config    |
|---------------------------|--------------|------------------------------------------|-----------------|
| `log`                     | logger       | `logger.info(...)`                       | none            |
| `influx`                  | time-series  | asyncdb point `write()` to `audit`       | `INFLUX_*`      |
| `mongo` / `documentdb`    | document     | asyncdb `insert(collection, record)`     | `AUDIT_DSN`     |
| `pg`, `postgres`          | SQL          | `INSERT ... VALUES ($1, $2, ...)`        | `AUDIT_DSN`     |
| `mysql`, `mysqlclient`, `mariadb` | SQL  | `INSERT ... VALUES (%s, %s, ...)`        | `AUDIT_DSN`     |
| `mssql`, `sqlite`, `duckdb` | SQL        | `INSERT ... VALUES (?, ?, ...)`          | `AUDIT_DSN`     |
| `oracle`                  | SQL          | `INSERT ... VALUES (:1, :2, ...)`        | `AUDIT_DSN`     |
| *any other asyncdb driver*| SQL          | uses `AUDIT_PARAMSTYLE` placeholders      | `AUDIT_DSN`     |

### Development / testing fallback

When `ENVIRONMENT` is `development` or `testing` **and** `AUDIT_BACKEND=influx`,
the audit log is silently downgraded to the `log` backend to avoid needing a
live InfluxDB. All other backends are honoured in every environment.

## SQL placeholder dialects

SQL drivers accept a uniform `execute(sentence, *values)` call but differ in the
bind-parameter placeholder they expect. `AuditLog` resolves this automatically
from `SQL_PARAMSTYLES`:

| Dialect     | Placeholder | Drivers                              |
|-------------|-------------|--------------------------------------|
| `numeric`   | `$1, $2`    | `pg`, `postgres` (asyncpg)           |
| `format`    | `%s`        | `mysql`, `mysqlclient`, `mariadb`    |
| `qmark`     | `?`         | `mssql`, `sqlite`, `duckdb`          |
| `named`     | `:1, :2`    | `oracle`                             |

Any SQL driver **not** in that table falls back to `AUDIT_PARAMSTYLE`
(default `format`). Set `AUDIT_PARAMSTYLE` explicitly if you point
`AUDIT_BACKEND` at a driver whose dialect differs from the default.

> **Note on Oracle / DuckDB:** these drivers have driver-specific bind
> behaviours in `asyncdb` and may require additional tuning of
> `AUDIT_PARAMSTYLE` or the target schema. `pg`/`postgres`, `mysql`, `mssql`
> and `sqlite` are the exercised SQL paths.

## Audit record schema

SQL and document backends store a flat record with these columns/fields:

| Field         | Type              | Description                                  |
|---------------|-------------------|----------------------------------------------|
| `timestamp`   | UTC datetime      | When the decision was made.                  |
| `environment` | string            | `ENVIRONMENT` (e.g. `production`).           |
| `domain`      | string            | `DOMAIN`.                                     |
| `host`        | string            | Resolved host IP of the auth service.        |
| `status`      | string            | `ALLOW` / `DENY` (the `PolicyEffect` name).  |
| `message`     | string            | The policy answer `response`.                |
| `rule`        | string \| null    | Matched policy rule, if any.                 |
| `username`    | string            | Subject username.                            |
| `user_id`     | int \| null       | Subject id.                                  |
| `tenant`      | string \| null    | Owning tenant (see *Tenant scoping* below).  |

The InfluxDB backend stores the same information as a point in the `audit`
measurement: `status` as a field, and host/region/message/answer/username/user/tenant
as tags.

## Tenant scoping & querying

Audit entries carry an optional **`tenant`** so a multi-tenant deployment can
attribute — and, crucially, read back — decisions per tenant (mirroring the
per-tenant policy scoping in `sdd/specs/per-tenant-policy-scoping.spec.md`).

### Writing with a tenant

`AuditLog.log()` accepts a keyword-only `tenant`; it is threaded to every write
family (SQL column, document field, influx tag, logger message). It is optional,
so existing PDP callers (`log(answer, status, user)`) are unaffected.

```python
await audit.log(answer, status, user, tenant="acme")
```

### Reading back — `AuditLog.query()`

```python
rows = await audit.query(
    tenant="acme",                 # REQUIRED — always constrains the read
    status="DENY",                 # optional equality filters
    user_id=42, username="alice", rule="rule-1",
    since=start, until=end,        # optional inclusive timestamp range
    limit=100, offset=0,           # pagination (newest first)
)
```

- **`tenant` is mandatory** and is always the first `WHERE` predicate — a query
  can never span tenants (passing `tenant=None` raises `ValueError`).
- Structured `query()` is implemented for **SQL backends only**. For the
  `influx`, `mongo`/`documentdb` and `log` families it logs a warning and returns
  `[]` (those stores remain write-only through this API — query them directly).
- Reads are **best-effort**: driver errors are caught, logged, and surface as `[]`,
  consistent with the write side.

## Examples

### Log only (no external dependency)

```bash
AUDIT_BACKEND=log
```

### PostgreSQL

```bash
AUDIT_BACKEND=pg
AUDIT_DSN=postgres://user:pass@localhost:5432/navigator
AUDIT_TABLE=audit_log
```

```sql
CREATE TABLE audit_log (
    timestamp   timestamptz NOT NULL,
    environment text,
    domain      text,
    host        text,
    status      text,
    message     text,
    rule        text,
    username    text,
    user_id     integer,
    tenant      text
);

-- Speeds up the tenant-scoped, newest-first reads issued by AuditLog.query().
CREATE INDEX idx_audit_log_tenant_ts ON audit_log (tenant, timestamp DESC);
```

> **Migration (existing deployments).** The `tenant` column is additive and
> nullable, so adding it is non-breaking:
>
> ```sql
> ALTER TABLE audit_log ADD COLUMN tenant text;
> CREATE INDEX idx_audit_log_tenant_ts ON audit_log (tenant, timestamp DESC);
> ```
>
> DDL/migrations are owned by the consuming service — `navigator-auth` does not
> manage them.

### MySQL / MariaDB

```bash
AUDIT_BACKEND=mysql
AUDIT_DSN=mysql://user:pass@localhost:3306/navigator
```

### MongoDB

```bash
AUDIT_BACKEND=mongo
AUDIT_DSN=mongodb://user:pass@localhost:27017/navigator
AUDIT_TABLE=audit_log            # used as the collection name
```

### InfluxDB (production default)

```bash
AUDIT_BACKEND=influx
INFLUX_HOST=influx.internal
INFLUX_PORT=8086
INFLUX_DATABASE=navigator_audit
INFLUX_ORG=navigator
INFLUX_TOKEN=***
```

### Unlisted SQL driver

```bash
AUDIT_BACKEND=some_new_sql_driver
AUDIT_DSN=...
AUDIT_PARAMSTYLE=qmark           # tell AuditLog which placeholder to emit
```

## Implementation notes

- `resolve_paramstyle(backend, default)` — maps a driver name to its dialect.
- `build_placeholders(paramstyle, count)` — renders the bind placeholders.
- `build_insert(table, record, paramstyle)` — assembles the `INSERT` `(sql, values)`
  pair.
- `build_select(table, conditions, paramstyle, *, order_by, descending, limit,
  offset)` — assembles the `SELECT` `(sql, values)` pair for `query()`; each
  condition is a `(column, operator, value)` triple with the value bound as a
  placeholder, `LIMIT`/`OFFSET` inlined as coerced ints.

These helpers are pure and unit-tested in
`tests/test_audit_backends.py` (no live database required). Driver I/O is
exercised in integration tests.
