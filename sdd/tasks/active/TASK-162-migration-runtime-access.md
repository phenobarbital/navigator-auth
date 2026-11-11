# TASK-162: Runtime-role grants and access verification

**Feature**: FEAT-110 — navauth self upgrade database migration command
**Spec**: `sdd/specs/new-command-migration.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-160
**Assigned-to**: unassigned

---

## Context

Implements spec §3 **"Runtime access contract (Modules 2, 5 and 7)"**. Migrations
run as an admin role (spec G5); the application keeps connecting as `DBUSER`. With
no default privileges configured, tables an admin creates are unusable by the
runtime role unless the runner grants access explicitly.

This task adds `navigator_auth/migrations/access.py`: the exact grant scope per
set, role validation, `GRANT` execution, and read-only privilege checks. `upgrade()`
(TASK-163) grants + verifies inside each file's transaction and reconciles
already-applied sets; `navauth self upgrade --check` (TASK-165) reports missing
access without writing.

Runs in parallel with TASK-161 (checks) — separate module, no shared files.

---

## Scope

- Create `navigator_auth/migrations/access.py` with `RUNTIME_TABLES`,
  `TABLE_PRIVILEGES`, `SEQUENCE_PRIVILEGES`, `scope_for`, `validate_runtime_role`,
  `existing_tables`, `owned_sequences`, `grant_runtime_access`,
  `missing_runtime_access`, `verify_runtime_access`.
- Grant scope (spec, verbatim): vault `user_vault_secrets`, `user_vault_audit`,
  `vault_key_registry`; identity `user_identities`; passkey `user_credentials`,
  `user_passkey_handles`; OAuth2 `clients`, `policies`, `oauth_refresh_tokens`,
  `oauth_grants`, `oauth_access_tokens`, `oauth_device_codes`, `client_access`.
  `mfa` has an empty scope here (TASK-170 extends it).
- `USAGE` on each schema used; `SELECT, INSERT, UPDATE, DELETE` on each existing
  scoped table; `USAGE, SELECT` on sequences owned by their columns
  (discovered through `pg_depend`).
- Create `tests/unit/migrations/test_access.py`.

**NOT in scope**: calling this from `upgrade()` or the CLI (TASK-163 / TASK-165);
the live distinct-roles test (TASK-168); MFA tables (TASK-170). Never transfer
ownership, grant DDL rights, `ALTER DEFAULT PRIVILEGES`, or grant anything to
`PUBLIC` (spec).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/migrations/access.py` | CREATE | Grant scope, role validation, grants, privilege checks |
| `tests/unit/migrations/test_access.py` | CREATE | Unit tests against `FakeConnection` |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `87c9b9c` (2026-11-11).

### Verified Imports
```python
from navigator_auth.conf import AUTH_DB_SCHEMA                                   # verified: navigator_auth/conf.py:33
from navigator_auth.migrations.runner import MigrationError, execute_checked, quote_ident  # created by TASK-160
import logging                                                                   # stdlib
from typing import Any                                                           # stdlib
```

### Existing Signatures to Use
```python
# navigator_auth/migrations/runner.py (TASK-160)
class MigrationError(Exception)
def quote_ident(name: str) -> str
async def execute_checked(conn: Any, sql: str, *args: Any) -> Any   # raises MigrationError on asyncdb error pairs;
                                                                    # a raw asyncpg conn raises asyncpg.PostgresError itself

# tests/unit/migrations/conftest.py (TASK-160)
class FakeConnection:   # respond(marker, value|callable(sql, args)); fail_on(marker, exc); relations: set[str]
```

Where the scoped tables live (verified in the released SQL):
- vault: `auth.user_vault_secrets` (vault/001:11), `auth.user_vault_audit` (vault/001:40, `id BIGSERIAL`
  → owned sequence), `auth.vault_key_registry` (vault/001:57) — schema `auth` hard-coded.
- identity: `auth.user_identities` — schema `auth` hard-coded (base table from the platform).
- passkey: `{schema}.user_credentials`, `{schema}.user_passkey_handles` — `AUTH_DB_SCHEMA`.
- oauth2: `{schema}.clients`, `{schema}.policies` (base) and the five `oauth_*`/`client_access`
  tables from TASK-167 — `AUTH_DB_SCHEMA`. `oauth_refresh_tokens`, `oauth_access_tokens`,
  `oauth_device_codes` have `BIGSERIAL` ids → owned sequences.

PostgreSQL facts the blueprint relies on:
- `has_table_privilege(role text, table text, priv text)` and `has_sequence_privilege(...)`
  parse the table argument as a (possibly quoted, qualified) identifier → pass
  `"schema"."table"`. `has_schema_privilege(role text, schema text, priv text)` takes the
  schema **name** → pass it unquoted. The role is passed as a plain name, as a `$n` parameter.
- `PUBLIC` is not a row of `pg_roles`; the existence check rejects it naturally.
- Serial/identity sequences depend on their table through `pg_depend` with
  `classid = refclassid = 'pg_class'::regclass`, `deptype IN ('a', 'i')`, `relkind = 'S'`.

### Does NOT Exist
- ~~`ALTER DEFAULT PRIVILEGES` anywhere in this repo~~ — spec: "Never assume default privileges have been configured" — and do not add one.
- ~~A runtime-role setting other than `DBUSER`~~ — `--runtime-role` / `DBUSER` resolution is the CLI's (TASK-165); library callers pass `runtime_role` explicitly.
- ~~`navigator_auth/migrations/checks.py` symbols~~ — TASK-161 runs in parallel; do not import from it.
- ~~`asyncpg.utils._quote_ident`~~ — private; use `runner.quote_ident`.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/migrations/access.py", "action": "CREATE"},
    {"path": "tests/unit/migrations/test_access.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/migrations/runner.py#MigrationError",
    "sym:navigator_auth/migrations/runner.py#execute_checked",
    "sym:navigator_auth/migrations/runner.py#quote_ident"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- Identifiers (schema, table, sequence, **role**) are always `quote_ident`-ed in `GRANT`
  text; values in queries are `$n` parameters — spec: "never interpolate an unquoted role".
- Grant only to **existing** objects in the selected set's scope — spec: "objects introduced
  only by later files are not required prematurely". Absence of a required object is a
  postcondition failure (TASK-161), not this module's.
- `grant_runtime_access` re-raises any failure as `MigrationError("could not grant …: <err>")`
  naming the object and role — because grant failures are "actionable errors and never success".
- `missing_runtime_access` is read-only (no `execute`) — `--check` must not write.

---

## Implementation Blueprint

### Steps (in order)
1. Write `access.py` from the two blocks; fill the `FILL IN`s — *why*: TASK-163/165 call it.
2. Write `test_access.py`; drive `FakeConnection` with `relations` (existing tables),
   `respond("pg_roles", …)`, `respond("pg_depend", …)`, `respond("has_table_privilege", …)`.
3. Run the Validation Commands.

### `navigator_auth/migrations/access.py` (CREATE) — block 1: scope and discovery
```python
"""Runtime-role grants and access checks (FEAT-110, spec "Runtime access contract").

Migrations run as an admin role; the application connects as the runtime role
(``--runtime-role`` or ``DBUSER``). This module grants that role exactly the access the
application needs on the tables each migration set owns, and verifies it.
"""
from __future__ import annotations

import logging
from typing import Any

from ..conf import AUTH_DB_SCHEMA
from .runner import MigrationError, execute_checked, quote_ident

logger = logging.getLogger("navigator.migrations")

RELEASED_SCHEMA = "auth"  # vault and identity tables stay in `auth`
TABLE_PRIVILEGES: tuple[str, ...] = ("SELECT", "INSERT", "UPDATE", "DELETE")
SEQUENCE_PRIVILEGES: tuple[str, ...] = ("USAGE", "SELECT")

# (schema, table); a schema of None means AUTH_DB_SCHEMA (templated migrations).
RUNTIME_TABLES: dict[str, tuple[tuple[str | None, str], ...]] = {
    "vault": ((RELEASED_SCHEMA, "user_vault_secrets"), (RELEASED_SCHEMA, "user_vault_audit"),
              (RELEASED_SCHEMA, "vault_key_registry")),
    "identity": ((RELEASED_SCHEMA, "user_identities"),),
    "passkey": ((None, "user_credentials"), (None, "user_passkey_handles")),
    "mfa": (),  # TASK-170 adds the MFA tables
    "oauth2": ((None, "clients"), (None, "policies"), (None, "oauth_refresh_tokens"), (None, "oauth_grants"),
               (None, "oauth_access_tokens"), (None, "oauth_device_codes"), (None, "client_access")),
}

_SEQUENCES_SQL = (
    "SELECT n.nspname AS schema, s.relname AS name FROM pg_depend d "
    "JOIN pg_class s ON s.oid = d.objid JOIN pg_namespace n ON n.oid = s.relnamespace "
    "WHERE d.classid = 'pg_class'::regclass AND d.refclassid = 'pg_class'::regclass "
    "AND d.refobjid = to_regclass($1) AND d.deptype IN ('a', 'i') AND s.relkind = 'S'"
)


def _qualified(schema: str, name: str) -> str:
    return f"{quote_ident(schema)}.{quote_ident(name)}"


def scope_for(migration_set: str) -> list[tuple[str, str]]:
    """Resolved ``(schema, table)`` grant scope of a set; empty for an unknown set."""
    return [(schema or AUTH_DB_SCHEMA, table) for schema, table in RUNTIME_TABLES.get(migration_set, ())]


async def validate_runtime_role(conn: Any, role: str | None) -> str:
    """Return ``role`` when it is non-empty and exists in ``pg_roles``.

    Raises:
        MigrationError: empty/blank role, or no such role.
    """
    # FILL IN: blank → MigrationError("runtime role is empty; pass --runtime-role or set DBUSER");
    #   `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)` false → MigrationError naming it.
    raise NotImplementedError


async def existing_tables(conn: Any, migration_set: str) -> list[tuple[str, str]]:
    """The set's scoped tables that currently exist (``to_regclass``)."""
    return [
        (schema, table)
        for schema, table in scope_for(migration_set)
        if await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", _qualified(schema, table))
    ]


async def owned_sequences(conn: Any, schema: str, table: str) -> list[tuple[str, str]]:
    """``(schema, sequence)`` owned by columns of ``schema.table`` (serial / identity)."""
    rows = await conn.fetch(_SEQUENCES_SQL, _qualified(schema, table))
    return [(row["schema"], row["name"]) for row in rows or ()]
```
**Why this shape**: the scope dict is the spec's grant scope verbatim; `None` →
`AUTH_DB_SCHEMA` keeps released tables in `auth` while templated sets follow config.

### `navigator_auth/migrations/access.py` (CREATE) — block 2: grant and check
```python
async def grant_runtime_access(conn: Any, migration_set: str, role: str) -> None:
    """Grant ``role`` the set's runtime access on existing objects. Idempotent.

    ``USAGE`` on each schema used, ``SELECT, INSERT, UPDATE, DELETE`` on each existing
    scoped table, ``USAGE, SELECT`` on sequences owned by their columns.

    Raises:
        MigrationError: naming the object and role, when any GRANT fails.
    """
    tables = await existing_tables(conn, migration_set)
    role_q = quote_ident(role)
    # FILL IN: distinct schemas of `tables` (keep order) → GRANT USAGE ON SCHEMA <q> TO <role_q>;
    #   each table → GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE <q.q> TO <role_q>;
    #   each owned sequence → GRANT USAGE, SELECT ON SEQUENCE <q.q> TO <role_q>.
    #   All via execute_checked; wrap any exception in MigrationError(f"could not grant … on … to {role}: {err}")
    #   chained `from err` — bounded by spec "Grant failures are actionable errors and never success".
    logger.debug("Granted runtime access for set %s to %s", migration_set, role)


async def missing_runtime_access(conn: Any, migration_set: str, role: str) -> list[str]:
    """Read-only: one message per missing privilege of ``role`` on the set's existing objects."""
    # FILL IN: has_schema_privilege($1, $2, 'USAGE') with the UNQUOTED schema name;
    #   has_table_privilege($1, $2, $3) per TABLE_PRIVILEGES with the quoted qualified table;
    #   has_sequence_privilege($1, $2, $3) per SEQUENCE_PRIVILEGES for owned sequences.
    #   Message shape: f"{role} lacks {priv} on {schema}.{name}". Never call execute().
    raise NotImplementedError


async def verify_runtime_access(conn: Any, migration_set: str, role: str) -> None:
    """Raise ``MigrationError`` listing every missing privilege; return when complete."""
    missing = await missing_runtime_access(conn, migration_set, role)
    if missing:
        raise MigrationError("; ".join(missing))
```

### FILL IN checklist
- [ ] `validate_runtime_role` — blank and missing-role errors
- [ ] `grant_runtime_access` — schema/table/sequence grants, quoted, wrapped errors
- [ ] `missing_runtime_access` — the three `has_*_privilege` probes, read-only
- [ ] `test_access.py` — tests below

---

## Acceptance Criteria

- [ ] Grants touch only the scoped tables that exist, their schemas and owned sequences; nothing to `PUBLIC`, no ownership/DDL/default-privilege statements.
- [ ] Every identifier in a `GRANT` is quoted — a role named `app"role` produces `"app""role"`.
- [ ] A failing `GRANT` raises `MigrationError` naming the object and role.
- [ ] `missing_runtime_access` reports missing schema/table/sequence privileges and issues no `execute()`.
- [ ] `validate_runtime_role` rejects a blank role and a role absent from `pg_roles`.

---

## Validation Commands

- `pytest tests/unit/migrations/test_access.py -q`

> Task tier only: `test_access.py` is not in the spec's Validation Contract (access code was split out of
> `runner.py` so TASK-161/162 run in parallel). At merge tier the behaviour is exercised by TASK-163's
> `test_runtime_grants_and_reconciliation` (`test_runner.py`) and TASK-165's
> `test_check_reports_missing_runtime_access_without_writes` (`test_cli.py`).

---

## Test Specification

```python
# tests/unit/migrations/test_access.py
import pytest

from navigator_auth.migrations.access import (
    grant_runtime_access, missing_runtime_access, scope_for, validate_runtime_role,
)
from navigator_auth.migrations.runner import MigrationError


def test_scope_matches_spec_and_excludes_unrelated_tables():
    """vault/identity in `auth`; passkey/oauth2 in AUTH_DB_SCHEMA; no `users`, no `schema_migrations`; mfa empty."""


@pytest.mark.asyncio
async def test_validate_runtime_role(fake_conn):
    """'' and '  ' raise; respond('pg_roles', False) raises naming the role; True returns it."""


@pytest.mark.asyncio
async def test_grants_are_scoped_quoted_and_include_owned_sequences(fake_conn):
    """vault with all three tables + one owned sequence → USAGE on "auth", DML on three tables,
    USAGE, SELECT on the sequence; role 'app"role' appears as "app""role"."""


@pytest.mark.asyncio
async def test_absent_tables_are_not_granted(fake_conn):
    """oauth2 with only clients/policies present → no GRANT on oauth_* tables."""


@pytest.mark.asyncio
async def test_grant_failure_raises_migration_error(fake_conn):
    """fail_on('GRANT', RuntimeError('permission denied')) → MigrationError naming role and object."""


@pytest.mark.asyncio
async def test_missing_runtime_access_reports_without_writes(fake_conn):
    """respond('has_table_privilege', False) → messages per privilege; no execute() recorded."""
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug new-command-migration --feature-id FEAT-110`)
2. **Read the spec** at the path listed above for full context
3. **Check dependencies** — every `Depends-on` task must be `"done"` in the
   per-spec index `sdd/tasks/index/new-command-migration.json`
4. **Verify the Codebase Contract** — before writing ANY code:
   - Confirm every import in "Verified Imports" still exists (`grep` or `read` the source)
   - Confirm every class/method in "Existing Signatures" still has the listed attributes
   - If anything has changed, update the contract FIRST, then implement
   - **NEVER** reference an import, attribute, or method not in the contract without verifying it exists
5. **Update status** in `sdd/tasks/index/new-command-migration.json` → `"in-progress"`
   (set `started_at`) and commit only that index file
6. **Implement** — start from the Implementation Blueprint blocks, complete every
   `# FILL IN:` marker, and never change a signature or path the blueprint fixes
7. **Verify** all acceptance criteria are met — run the Validation Commands
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`)
9. **Close the task** with `parrot sdd task close TASK-162 new-command-migration verified`
   — it moves this file to `sdd/tasks/completed/` and marks it `"done"` in the
   index; never move or copy the file by hand
10. **Fill in the Completion Note** below, then commit the staged SDD state

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any
