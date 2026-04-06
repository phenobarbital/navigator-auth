# Database Agent (`parrot/bots/database`) — Comprehensive Guide

## 1) Purpose and Scope

The **Database Agent** is intended to answer operational and development questions about data backends used by this project, including:

- application primary storage,
- cache/session storage,
- audit/event storage,
- and driver-specific configuration concerns.

In this repository, database access is built around `asyncdb` abstractions (`AsyncDB` and `AsyncPool`) and concrete storage wrappers for PostgreSQL and Redis, plus an audit backend that supports InfluxDB and any asyncdb-compatible driver.

---

## 2) User Roles

The Database Agent should support multiple personas with different goals.

### A. Application Developer
**Primary intent:** ship features safely.

Typical asks:
- "How do I configure the Postgres DSN for auth?"
- "Which backend should I use for OAuth2 client storage in development vs production?"
- "Show me a valid insert pattern for audit rows."

Expected depth:
- concise but actionable,
- includes concrete config keys and code-level integration points.

### B. Platform/SRE Engineer
**Primary intent:** reliability and operability.

Typical asks:
- "Which backends are initialized on app startup?"
- "What happens if a DB driver fails to initialize?"
- "What timeout/pool defaults are used?"

Expected depth:
- startup/shutdown lifecycle,
- failure modes,
- environment-specific behavior.

### C. Security / Compliance / Audit Owner
**Primary intent:** traceability and policy evidence.

Typical asks:
- "Where are audit records written?"
- "Which fields are captured in audit rows?"
- "How can we switch audit backend without code changes?"

Expected depth:
- explicit audit fields,
- backend selection logic,
- configuration requirements (`AUDIT_DSN`, Influx credentials).

### D. QA / Support Engineer
**Primary intent:** rapid diagnosis and reproducibility.

Typical asks:
- "Why is auth storage not connected?"
- "How do I verify Redis-based OAuth2 storage is active?"
- "What config mismatch causes startup runtime errors?"

Expected depth:
- likely root-cause list,
- quick validation steps,
- targeted remediation.

---

## 3) Output Contract (How the Agent Should Respond)

When answering, the Database Agent should produce outputs in a deterministic structure:

1. **Short Answer** — one-paragraph direct response.
2. **Evidence** — exact config keys and code paths.
3. **Working Example** — runnable config/code snippet.
4. **Validation Steps** — how to confirm correctness.
5. **Risks / Caveats** — environment or compatibility gotchas.

Recommended response styles:

- **Configuration output**: key/value blocks for `.env` or settings modules.
- **Driver guidance**: selected driver, prerequisites, fallback behavior.
- **Troubleshooting output**: symptom → probable cause → fix.
- **Comparison output**: backend trade-offs table.

---

## 4) Types of Questions the Agent Can Answer

### A. Capability & Selection Questions
- Which storage backends are supported for OAuth2 client storage?
- Which audit backends are available?
- When should I use Postgres vs Redis vs Memory?

### B. Configuration Questions
- Which environment variables/settings are required per driver?
- What does `AUDIT_BACKEND` accept?
- What DSN format is expected for a given backend?

### C. Lifecycle & Runtime Questions
- How are connections initialized at startup?
- Are drivers pool-based or single connection?
- What shutdown/cleanup behavior is implemented?

### D. Data Model & Persistence Questions
- Which fields are recorded in audit logs?
- How are audit inserts executed?
- Where are session and token artifacts stored?

### E. Error & Troubleshooting Questions
- Why did storage init fail with provider/driver errors?
- Why is audit backend failing in non-production?
- Why are OAuth2 clients not persisted across restarts?

---

## 5) Supported Drivers in This Codebase

> **Important:** The list below is constrained to drivers/backends explicitly referenced in this repository (code/docs), not every driver `asyncdb` might support globally.

| Driver / Backend | Context in this repo | Type | Notes |
|---|---|---|---|
| `pg` / `postgres` | Primary auth storage + OAuth2 option | Relational | Pool-based in `PostgresStorage`; OAuth2 docs use `postgres` naming. |
| `redis` | Auth/session/caching + OAuth2 option | Key-value | Non-pool storage wrapper; widely used for session/token workflows. |
| `memory` | OAuth2 client storage option | In-memory backend | Good for tests/dev; not durable. |
| `influx` | Audit backend | Time-series | Uses dedicated credentials block and asyncdb influx driver. |
| `mongo` (example) | Audit backend as asyncdb-compatible driver example | Document DB | Supported as an example via generic asyncdb backend path. |
| `<any asyncdb driver>` | Audit backend generic path | Generic | Requires `AUDIT_DSN`; exact compatibility depends on asyncdb driver availability. |

---

## 6) Provisioned Example Set (All Supported Drivers/Backends)

The following examples are provisioned so each supported driver/backend category is represented.

### 6.1 PostgreSQL (`pg` / `postgres`)

**Use case:** primary persistent auth storage.

```python
# settings.py / env-backed config
DBHOST = "127.0.0.1"
DBPORT = 5432
DBUSER = "navigator"
DBPWD = "secret"
DBNAME = "authdb"

# Default DSN shape used in conf
# postgres://<DBUSER>:<DBPWD>@<DBHOST>:<DBPORT>/<DBNAME>
```

**Driver behavior:** pool-based connection via `AsyncPool("pg", ...)`.

---

### 6.2 Redis (`redis`)

**Use case:** session/token/cache fast-path and OAuth2 client storage option.

```python
REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
REDIS_DB = 0
# Effective URL shape: redis://<host>:<port>/<db>

# OAuth2 option
OAUTH2_CLIENT_STORAGE = "redis"
```

**Driver behavior:** direct async DB connection path (non-pool wrapper in `RedisStorage`).

---

### 6.3 Memory (`memory`) backend

**Use case:** development/testing with zero external dependencies.

```python
OAUTH2_CLIENT_STORAGE = "memory"
```

**Caveat:** data does not survive process restart.

---

### 6.4 InfluxDB (`influx`)

**Use case:** audit/event logging in time-series form.

```python
AUDIT_BACKEND = "influx"
INFLUX_HOST = "localhost"
INFLUX_PORT = 8086
INFLUX_DATABASE = "navigator_audit"
INFLUX_ORG = "navigator"
INFLUX_TOKEN = "<token>"
```

**Driver behavior:** `AsyncDB("influx", params=AUDIT_CREDENTIALS)`.

---

### 6.5 MongoDB (`mongo`) via generic asyncdb backend

**Use case:** audit storage in document DB format.

```python
AUDIT_BACKEND = "mongo"
AUDIT_DSN = "mongodb://user:pass@localhost:27017/audit"
AUDIT_TABLE = "audit_log"
```

**Driver behavior:** generic path `AsyncDB(AUDIT_BACKEND, dsn=AUDIT_DSN)`.

---

### 6.6 Generic asyncdb driver template

**Use case:** extending audit backend to another asyncdb-compatible provider.

```python
AUDIT_BACKEND = "<driver_name>"
AUDIT_DSN = "<driver_specific_dsn>"
AUDIT_TABLE = "audit_log"
```

**Rule:** if backend is neither `log` nor `influx`, `AUDIT_DSN` must be set.

---

## 7) Practical Q&A Examples (By Role)

### Developer Example
**Q:** "How do I move OAuth2 storage from memory to durable backend?"

**A:** Set `OAUTH2_CLIENT_STORAGE = "postgres"` (or `"redis"`), ensure its corresponding connection settings are defined, and restart the service.

### SRE Example
**Q:** "What proves database startup is wired into app lifecycle?"

**A:** Storage objects register startup/shutdown/cleanup hooks via `configure(app)`, then initialize connections during startup.

### Audit Owner Example
**Q:** "What fields are captured for audit records?"

**A:** Timestamp, environment, domain, host, status, message/rule, and user identity fields (`username`, `user_id`).

### QA Example
**Q:** "Why does custom audit backend fail even though `AUDIT_BACKEND` is set?"

**A:** If backend is not `log`/`influx`, missing `AUDIT_DSN` raises configuration error at initialization.

---

## 8) Guardrails and Non-Goals

The Database Agent should:
- avoid inventing unsupported drivers,
- clearly separate **repo-supported** vs **potential asyncdb-compatible** drivers,
- prefer code-evidenced statements over assumptions,
- include caveats when behavior is environment-dependent.

The Database Agent should not:
- assume schema/table existence for external databases,
- emit destructive migration commands without explicit user confirmation,
- claim universal compatibility for all asyncdb drivers without environment verification.

---

## 9) Quick Reference

- **Primary storage abstraction:** `AuthStorage` with `AsyncPool`/`AsyncDB`.
- **Auth DB concrete drivers:** `pg` and `redis`.
- **OAuth2 storage options:** `memory`, `redis`, `postgres`.
- **Audit backends:** `log`, `influx`, or any asyncdb-compatible driver (with DSN).

