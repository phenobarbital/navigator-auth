# TASK-161: Prerequisite and completion checks for migration files

**Feature**: FEAT-110 — navauth self upgrade database migration command
**Spec**: `sdd/specs/new-command-migration.spec.md`
**Status**: done
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-160
**Assigned-to**: unassigned

---

## Context

Implements spec §3 **"Completion and retry contract (Module 2)"**. A successful
`execute()` is not enough to record a file as applied: several released files
guard their effect and return normally when they skip (identity `006` is the
documented case), and the OAuth2 conversion (TASK-167) guards every statement.

This task adds a read-only module, `navigator_auth/migrations/checks.py`, that
answers two questions for one `MigrationFile`:

1. **Prerequisites** — do the base tables the set needs exist? (Base tables are
   created by the Navigator platform; a missing one fails the file without a
   ledger row.)
2. **Postconditions** — after the SQL ran, is the intended schema really there?

`upgrade()` (TASK-163) calls both inside the per-file transaction. Keeping them in
their own module lets this task run in parallel with TASK-162 (grants).

---

## Scope

- Create `navigator_auth/migrations/checks.py` with the probes, the OAuth2
  completion constants, `prerequisite_tables`, `check_prerequisites` and
  `check_postconditions` (signatures below).
- Postcondition rules, keyed by `(migration_set, filename)`:
  - `vault/001_create_vault_tables.sql` → `auth.user_vault_secrets`,
    `auth.user_vault_audit`, `auth.vault_key_registry` exist.
  - `passkey/001_passkey_credentials.sql` → `{schema}.user_passkey_handles`,
    `{schema}.user_credentials` exist.
  - `identity/006_identity_drop_legacy_uid.sql` → `auth.user_identities` has no
    `uid` column.
  - `oauth2/001_oauth2_schema.sql` → full OAuth2 completion (constants below).
  - Every other file: no postcondition (its DDL raises on failure).
- Create `tests/unit/migrations/test_checks.py`.

**NOT in scope**: calling these from `upgrade()` (TASK-163); the OAuth2 SQL file
itself (TASK-167); MFA prerequisites/postconditions (TASK-170); runtime grants
(TASK-162). Never execute DDL or DML here — read-only catalog queries only.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/migrations/checks.py` | CREATE | Prerequisite + postcondition probes |
| `tests/unit/migrations/test_checks.py` | CREATE | Unit tests against `FakeConnection` |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `87c9b9c` (2026-11-11).

### Verified Imports
```python
from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE        # verified: navigator_auth/conf.py:33-34
from navigator_auth.migrations.catalog import MigrationFile             # created by TASK-159
from navigator_auth.migrations.runner import MigrationError, quote_ident  # created by TASK-160
import logging                                                          # stdlib
from typing import Any                                                  # stdlib
```

### Existing Signatures to Use
```python
# navigator_auth/migrations/runner.py (TASK-160)
class MigrationError(Exception)
def quote_ident(name: str) -> str          # '"' + name.replace('"', '""') + '"'

# tests/unit/migrations/conftest.py (TASK-160)
class FakeConnection:                      # respond(marker, value|callable(sql, args)); relations: set[str]
                                           # (unquoted "schema.table"); to_regclass answered from relations
```

Objects the released SQL creates (verified):
- `navigator_auth/migrations/sql/vault/001_create_vault_tables.sql` (moved by TASK-159):
  `auth.user_vault_secrets` (line 11, FK `user_id → auth.users`), `auth.user_vault_audit`
  (line 40, `BIGSERIAL`), `auth.vault_key_registry` (line 57).
- `…/sql/passkey/001_passkey_credentials.sql`: `{schema}.user_passkey_handles` (line 6),
  `{schema}.user_credentials` (line 14); both FK `user_id → {schema}.{users_table}`.
- `…/sql/identity/006_identity_drop_legacy_uid.sql`: guarded drop of `auth.user_identities.uid`;
  returns normally (with `RAISE WARNING`) when `identity_id` is missing, a dependent object
  exists, or identifiers are duplicated.

OAuth2 completion objects — from `navigator_auth/backends/oauth2/ddl.sql` (284 lines) and
spec §7 rule 7. All tables live in `AUTH_DB_SCHEMA`; the users table is `AUTH_USERS_TABLE`:

| Kind | Objects |
|---|---|
| Base tables (prerequisites) | `{users_table}`, `clients`, `policies` |
| New tables | `oauth_refresh_tokens`, `oauth_grants`, `oauth_access_tokens`, `oauth_device_codes`, `client_access` |
| `clients` columns | `client`, `client_name`, `client_type`, `client_secret`, `redirect_uris`, `policy_uri`, `client_logo_uri`, `user_id`, `default_scopes`, `allowed_grant_types`, `is_active`, `expiration_date`, `created_at`, `updated_at`, `client_uid`, `token_endpoint_auth_method`, `registration_source`, `enforce_access_gate` |
| `policies` columns | `scopes` |
| NOT NULL | `clients.client_name`, `clients.client_uid` |
| Nullable | `clients.client_secret` (ddl.sql:13), `clients.user_id` (ddl.sql:239) |
| Unique (single column) | `clients.client_uid` |
| Foreign keys (table.column → table) | `clients.user_id → {users_table}`; `oauth_refresh_tokens.client_id → clients`, `.user_id → {users_table}`; `oauth_grants.user_id → {users_table}`; `oauth_access_tokens.user_id → {users_table}`, `.client_id → clients`; `oauth_device_codes.client_id → clients`, `.user_id → {users_table}`; `client_access.user_id → {users_table}`, `.client_id → clients`, `.granted_by → {users_table}` |
| Indexes | `idx_oauth_refresh_tokens_user`, `idx_oauth_refresh_tokens_client`, `idx_oauth_refresh_tokens_parent`, `idx_oauth_grants_user`, `idx_oauth_access_tokens_jti`, `idx_oauth_access_tokens_user`, `idx_oauth_device_codes_device_code`, `idx_oauth_device_codes_user_code`, `idx_oauth_device_codes_client`, `idx_oauth_device_codes_status_expires`, `idx_clients_registration_source`, `uq_client_access_user_client`, `uq_client_access_user_client_uid`, `idx_client_access_client_uid`, `idx_client_access_client_status` |

The OAuth2 SQL file name is `001_oauth2_schema.sql` in set `oauth2` (spec M4; created by TASK-167).
TASK-167 writes its SQL against this same table — keep the constants in sync with it.

### Does NOT Exist
- ~~`navigator_auth/migrations/checks.py`~~ — this task creates it (the spec keeps the rules
  "in `runner.py`"; they are split into this module so TASK-161 and TASK-162 can run in
  parallel — `runner.upgrade()` imports them, the behaviour is the spec's).
- ~~A NOTICE/WARNING parser~~ — spec M2: "do not interpret arbitrary NOTICE/WARNING text as a completion signal".
- ~~`CREATE TABLE` for `auth.users` / `auth.clients` / `auth.user_identities` / `auth.policies` in this repo~~ — base tables come from the Navigator platform.
- ~~A hand-written list of migration files to execute~~ — postcondition rules supplement discovery; they never decide what runs.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/migrations/checks.py", "action": "CREATE"},
    {"path": "tests/unit/migrations/test_checks.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/migrations/runner.py#MigrationError",
    "sym:navigator_auth/migrations/runner.py#quote_ident",
    "sym:navigator_auth/migrations/catalog.py#MigrationFile"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- Parameterised catalog lookups only (`$n`), identifiers through `quote_ident` — spec M2.
- Released vault/identity objects are in schema `auth` regardless of `AUTH_DB_SCHEMA`;
  passkey/OAuth2 objects use `AUTH_DB_SCHEMA` (spec runtime access contract: "configured
  schema names apply only to templated migrations").
- `check_postconditions` collects **every** unmet condition and raises once, naming them
  all — because the operator repairs them in one pass (spec: "Missing data is reported
  for operator repair").
- A file with no rule passes; an unknown set in `prerequisite_tables` returns `()`.

---

## Implementation Blueprint

### Steps (in order)
1. Write `checks.py` blocks 1 and 2; fill the probe bodies and the OAuth2 rule —
   *why*: TASK-163 calls `check_prerequisites` / `check_postconditions` per file.
2. Write `test_checks.py` against `FakeConnection` (configure with `relations` and
   `respond`) — *why*: no live database in the unit suite (spec §7 Patterns).
3. Run the Validation Commands.

### `navigator_auth/migrations/checks.py` (CREATE) — block 1: probes and constants
```python
"""Prerequisite and completion checks for migration files (FEAT-110, spec M2 completion contract).

Read-only: every function here runs catalog queries only. ``runner.upgrade()`` calls
``check_prerequisites`` before a file's SQL and ``check_postconditions`` after it, inside
the file's transaction, so an unmet condition rolls the file back and leaves it pending.
"""
from __future__ import annotations

import logging
from typing import Any

from ..conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE
from .catalog import MigrationFile
from .runner import MigrationError, quote_ident

logger = logging.getLogger("navigator.migrations")

RELEASED_SCHEMA = "auth"  # vault and identity SQL hard-code `auth.`

OAUTH2_FILE = ("oauth2", "001_oauth2_schema.sql")
OAUTH2_TABLES: tuple[str, ...] = (
    "oauth_refresh_tokens", "oauth_grants", "oauth_access_tokens", "oauth_device_codes", "client_access",
)
OAUTH2_CLIENT_COLUMNS: tuple[str, ...] = (
    "client", "client_name", "client_type", "client_secret", "redirect_uris", "policy_uri",
    "client_logo_uri", "user_id", "default_scopes", "allowed_grant_types", "is_active",
    "expiration_date", "created_at", "updated_at", "client_uid", "token_endpoint_auth_method",
    "registration_source", "enforce_access_gate",
)
OAUTH2_NOT_NULL: tuple[tuple[str, str], ...] = (("clients", "client_name"), ("clients", "client_uid"))
OAUTH2_NULLABLE: tuple[tuple[str, str], ...] = (("clients", "client_secret"), ("clients", "user_id"))
OAUTH2_UNIQUE: tuple[tuple[str, str], ...] = (("clients", "client_uid"),)
OAUTH2_FOREIGN_KEYS: tuple[tuple[str, str, str], ...] = (
    ("clients", "user_id", AUTH_USERS_TABLE),
    ("oauth_refresh_tokens", "client_id", "clients"),
    ("oauth_refresh_tokens", "user_id", AUTH_USERS_TABLE),
    ("oauth_grants", "user_id", AUTH_USERS_TABLE),
    ("oauth_access_tokens", "user_id", AUTH_USERS_TABLE),
    ("oauth_access_tokens", "client_id", "clients"),
    ("oauth_device_codes", "client_id", "clients"),
    ("oauth_device_codes", "user_id", AUTH_USERS_TABLE),
    ("client_access", "user_id", AUTH_USERS_TABLE),
    ("client_access", "client_id", "clients"),
    ("client_access", "granted_by", AUTH_USERS_TABLE),
)
# FILL IN: OAUTH2_INDEXES — the 15 index names from the contract table, as a tuple[str, ...].

_COLUMN_SQL = (
    "SELECT a.attnotnull FROM pg_attribute a "
    "WHERE a.attrelid = to_regclass($1) AND a.attname = $2 AND a.attnum > 0 AND NOT a.attisdropped"
)
_UNIQUE_SQL = (
    "SELECT EXISTS (SELECT 1 FROM pg_index i "
    "JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0] "
    "WHERE i.indrelid = to_regclass($1) AND i.indisunique AND i.indnkeyatts = 1 "
    "AND i.indpred IS NULL AND a.attname = $2)"
)
_FK_SQL = (
    "SELECT EXISTS (SELECT 1 FROM pg_constraint c "
    "JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey) "
    "WHERE c.contype = 'f' AND c.conrelid = to_regclass($1) AND c.confrelid = to_regclass($2) "
    "AND a.attname = $3)"
)


def qualified(schema: str, name: str) -> str:
    """``"schema"."name"`` with both parts quoted."""
    return f"{quote_ident(schema)}.{quote_ident(name)}"


async def relation_exists(conn: Any, schema: str, name: str) -> bool:
    """True when ``schema.name`` resolves with ``to_regclass`` (tables and indexes)."""
    return bool(await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", qualified(schema, name)))


async def column_not_null(conn: Any, schema: str, table: str, column: str) -> bool | None:
    """``attnotnull`` of a column; ``None`` when the table or column is absent."""
    row = await conn.fetchrow(_COLUMN_SQL, qualified(schema, table), column)
    # FILL IN: None when row is None, else bool(row["attnotnull"]).
    raise NotImplementedError


async def has_unique_on(conn: Any, schema: str, table: str, column: str) -> bool:
    """A non-partial unique index (or unique/PK constraint) whose only key is ``column``."""
    return bool(await conn.fetchval(_UNIQUE_SQL, qualified(schema, table), column))


async def has_foreign_key(conn: Any, schema: str, table: str, column: str, ref_table: str) -> bool:
    """A foreign key on ``schema.table(column)`` referencing ``schema.ref_table``."""
    return bool(await conn.fetchval(_FK_SQL, qualified(schema, table), qualified(schema, ref_table), column))
```
**Why this shape**: the SQL constants are the decided probes; `qualified()` keeps
every identifier quoted. The 15 index names are listed in the contract table.

### `navigator_auth/migrations/checks.py` (CREATE) — block 2: rules
```python
def prerequisite_tables(migration_set: str) -> tuple[tuple[str, str], ...]:
    """``(schema, table)`` base tables a set needs before any of its files runs."""
    if migration_set == "vault":
        return ((RELEASED_SCHEMA, "users"),)
    if migration_set == "identity":
        return ((RELEASED_SCHEMA, "user_identities"),)
    if migration_set == "passkey":
        return ((AUTH_DB_SCHEMA, AUTH_USERS_TABLE),)
    if migration_set == "oauth2":
        return ((AUTH_DB_SCHEMA, AUTH_USERS_TABLE), (AUTH_DB_SCHEMA, "clients"), (AUTH_DB_SCHEMA, "policies"))
    return ()  # "mfa" is added by TASK-170


async def check_prerequisites(conn: Any, file: MigrationFile) -> None:
    """Raise ``MigrationError`` naming every missing base table of ``file``'s set."""
    missing = [
        f"{schema}.{table}"
        for schema, table in prerequisite_tables(file.migration_set)
        if not await relation_exists(conn, schema, table)
    ]
    if missing:
        raise MigrationError(
            f"{file.migration_set}/{file.filename}: missing base table(s) {', '.join(missing)}; "
            "base tables are provisioned by the Navigator platform"
        )


async def _oauth2_unmet(conn: Any) -> list[str]:
    """Every unmet OAuth2 completion condition, as human-readable strings."""
    # FILL IN: check, in AUTH_DB_SCHEMA: OAUTH2_TABLES exist; OAUTH2_CLIENT_COLUMNS exist on
    #   `clients` and `scopes` on `policies` (column_not_null(...) is not None); OAUTH2_NOT_NULL are
    #   True; OAUTH2_NULLABLE are False; OAUTH2_UNIQUE hold; OAUTH2_FOREIGN_KEYS hold; OAUTH2_INDEXES
    #   exist — bounded by spec M2 "OAuth2 completion" and §7 rule 7. One string per failure,
    #   e.g. "clients.client_name is nullable (backfill client_name, then re-run)".
    raise NotImplementedError


async def _identity_006_unmet(conn: Any) -> list[str]:
    """``auth.user_identities.uid`` must be gone."""
    # FILL IN: column_not_null(conn, RELEASED_SCHEMA, "user_identities", "uid") is not None → one
    #   message naming the column and the documented blockers (missing identity_id, dependent
    #   objects, duplicate identifiers) — bounded by spec M2 "Identity 006 is complete only when…".
    raise NotImplementedError


async def _tables_unmet(conn: Any, schema: str, tables: tuple[str, ...]) -> list[str]:
    """Names of ``tables`` that do not exist in ``schema``."""
    return [f"{schema}.{t} is missing" for t in tables if not await relation_exists(conn, schema, t)]


async def check_postconditions(conn: Any, file: MigrationFile) -> None:
    """Raise ``MigrationError`` naming every unmet completion condition of ``file``.

    Files without a rule pass. Rules are keyed by ``(migration_set, filename)``.
    """
    key = (file.migration_set, file.filename)
    unmet: list[str] = []
    # FILL IN: dispatch — ("vault", "001_create_vault_tables.sql") → _tables_unmet(RELEASED_SCHEMA,
    #   user_vault_secrets/user_vault_audit/vault_key_registry); ("passkey", "001_passkey_credentials.sql")
    #   → _tables_unmet(AUTH_DB_SCHEMA, user_passkey_handles/user_credentials);
    #   ("identity", "006_identity_drop_legacy_uid.sql") → _identity_006_unmet; OAUTH2_FILE → _oauth2_unmet.
    if unmet:
        raise MigrationError(f"{file.migration_set}/{file.filename} incomplete: {'; '.join(unmet)}")
```

### FILL IN checklist
- [ ] `OAUTH2_INDEXES` — 15 names from the contract table
- [ ] `column_not_null` — `None` / bool mapping
- [ ] `_oauth2_unmet` — every condition, one message each; bounded by spec M2 + §7 rule 7
- [ ] `_identity_006_unmet` — `uid` present → message
- [ ] `check_postconditions` — dispatch table
- [ ] `test_checks.py` — tests below

---

## Acceptance Criteria

- [ ] A missing base table makes `check_prerequisites` raise `MigrationError` naming it (vault, identity, passkey, oauth2).
- [ ] `check_postconditions` for identity `006` raises while `uid` exists and passes once it is gone.
- [ ] OAuth2 postconditions fail for: a missing table, a nullable `client_name`, a non-unique `client_uid`, a missing FK, a missing index — and pass when all hold.
- [ ] Files without a rule pass; no function issues `execute()`.
- [ ] `ruff check` reports nothing new on touched files.

---

## Validation Commands

- `pytest tests/unit/migrations/test_checks.py -q`

> Task tier only: `test_checks.py` is not in the spec's Validation Contract (the spec kept these rules
> inside `runner.py`; they were split out so TASK-161/162 run in parallel). At merge tier the same
> behaviour is exercised through `upgrade()` by TASK-163's `test_guarded_skip_stays_pending_and_retries`
> and `test_missing_prerequisites_and_oauth2_postconditions_fail` in `test_runner.py`.

---

## Test Specification

```python
# tests/unit/migrations/test_checks.py
import pytest

from navigator_auth.migrations.catalog import MigrationFile
from navigator_auth.migrations.checks import check_postconditions, check_prerequisites
from navigator_auth.migrations.runner import MigrationError


def _file(migration_set: str, filename: str) -> MigrationFile:
    """A MigrationFile that need not exist on disk."""


@pytest.mark.asyncio
async def test_missing_prerequisite_fails_each_set(fake_conn):
    """vault without auth.users, identity without auth.user_identities, oauth2 without clients → MigrationError naming it."""


@pytest.mark.asyncio
async def test_identity_006_incomplete_while_uid_exists(fake_conn):
    """respond('pg_attribute', row for uid) → raises naming uid; respond None → passes."""


@pytest.mark.asyncio
async def test_oauth2_complete_passes(fake_conn):
    """All tables/columns/constraints/indexes present → no raise."""


@pytest.mark.asyncio
@pytest.mark.parametrize("broken", ["missing_table", "nullable_client_name", "client_uid_not_unique", "missing_fk", "missing_index"])
async def test_oauth2_each_unmet_condition_fails(fake_conn, broken):
    """Each single defect → MigrationError naming it."""


@pytest.mark.asyncio
async def test_file_without_rule_passes_and_checks_never_execute(fake_conn):
    """identity/001 passes; fake_conn recorded no execute()."""
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
9. **Close the task** with `parrot sdd task close TASK-161 new-command-migration verified`
   — it moves this file to `sdd/tasks/completed/` and marks it `"done"` in the
   index; never move or copy the file by hand
10. **Fill in the Completion Note** below, then commit the staged SDD state

---

## Completion Note

**Completed by**: sdd-worker (see index/execution seats; native sonnet for TASK-164, codex for 161/162)
**Date**: 2026-11-11
**Notes**: Delivered and merged; wave merge-tier validation 64 passed; orchestrator review found no defects, 0 fix commits (review recorded). Closed via `parrot sdd task close` (durable evidence root read-only in sandbox).

**Deviations from spec**: none
