# TASK-167: OAuth2 schema becomes a managed, guarded migration

**Feature**: FEAT-110 — navauth self upgrade database migration command
**Spec**: `sdd/specs/new-command-migration.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-159
**Assigned-to**: unassigned

---

## Context

Implements spec §3 **Module 4** (goal G7) under the rules of spec §7 **"OAuth2
conversion rules (Module 4)"**. `navigator_auth/backends/oauth2/ddl.sql` is a
284-line hand-applied patch that no code loads; the inspected database is missing
five of its tables for that reason. It also cannot be copied as is: it writes a
known test secret into every public client, adds a `NOT NULL` column to a populated
table, and rebuilds a unique constraint on every run.

The spec marks this module **not delegation-eligible**: each statement needs
judgement (NOT NULL on populated tables, constraint guards). Implement it with the
thinking model and review the SQL statement by statement.

---

## Scope

- Create `navigator_auth/migrations/sql/oauth2/001_oauth2_schema.sql` — idempotent,
  guarded, using `{schema}` / `{users_table}` placeholders, following the seven rules below.
- Delete `navigator_auth/backends/oauth2/ddl.sql` (`git rm`).
- Prepend a note to `documentation/client_changes.md` pointing to the new file and
  to `navauth self upgrade`.
- Create `tests/unit/migrations/test_oauth2_sql.py` with the two static tests.

**NOT in scope**: the OAuth2 postcondition probes (TASK-161 — your SQL must satisfy
them); the live completion test (TASK-168 appends it to this test file); prose docs
that mention `ddl.sql` (`documentation/mcp-connector.md`, `documentation/oauth.md`,
`examples/…` — TASK-169).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/migrations/sql/oauth2/001_oauth2_schema.sql` | CREATE | Converted, guarded OAuth2 migration |
| `navigator_auth/backends/oauth2/ddl.sql` | DELETE | Replaced by the migration (`git rm`) |
| `documentation/client_changes.md` | MODIFY | First-line pointer to the managed migration |
| `tests/unit/migrations/test_oauth2_sql.py` | CREATE | Static guard / coverage tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `87c9b9c` (2026-11-11).

### Verified Imports
```python
from navigator_auth.migrations.catalog import discover, render_sql, set_dir   # TASK-159
import re                                                                     # stdlib
```

### Existing Signatures to Use
`navigator_auth/backends/oauth2/ddl.sql` — read it in full before writing (284 lines). Map:

| ddl.sql lines | Content | Conversion |
|---|---|---|
| 7-33 | `ALTER TABLE auth.clients ADD COLUMN IF NOT EXISTS …` (15 columns); line 8 `client_name … NOT NULL`; line 13 `ALTER COLUMN client_secret DROP NOT NULL`; line 23 `user_id INTEGER REFERENCES auth.users(user_id) ON DELETE CASCADE` | keep, `ALTER TABLE IF EXISTS {schema}.clients`; `client_name` added **nullable** (rule 2); `user_id` FK added by a guarded block when missing (inline `REFERENCES` is skipped when the column already exists) |
| 40-41 | `client_name` ↔ `client` backfills | keep once (rule 4), inside a `to_regclass` guard |
| 44-51, 86-93 | `UPDATE … SET client_secret = 'test_client_secret', redirect_uris = …localhost…` | **drop entirely** (rule 1) |
| 58-64 | `client_uid` add + opaque backfill | keep (rule 4) |
| 67-68 | `ALTER COLUMN client_uid SET NOT NULL` | guarded by "no NULLs remain" |
| 70-74 | `DROP CONSTRAINT IF EXISTS clients_client_uid_key` + `ADD CONSTRAINT … UNIQUE (client_uid)` | replace with a `pg_constraint`-guarded add (rule 3) |
| 76-93 | duplicate of 39-51 | appears once (rule 5) |
| 100-120 | `oauth_refresh_tokens` + 3 indexes | keep, `{schema}` / `{users_table}` |
| 127-139 | `oauth_grants` + 1 index | keep |
| 148-162 | `oauth_access_tokens` + 2 indexes | keep |
| 168-169 | `policies.scopes` | keep, `ALTER TABLE IF EXISTS {schema}.policies` |
| 186-214 | `oauth_device_codes` + 4 indexes | keep |
| 223-247 | DCR columns `token_endpoint_auth_method`, `registration_source NOT NULL DEFAULT 'static'`, `enforce_access_gate NOT NULL DEFAULT FALSE`; `ALTER COLUMN user_id DROP NOT NULL`; `registration_source` backfill; `idx_clients_registration_source` | keep (`NOT NULL DEFAULT` adds are safe as written) |
| 255-284 | `client_access` + 2 unique + 2 plain indexes | keep |

Completion conditions the runner verifies after this file (TASK-161 `checks.py`, spec M2) — the SQL
must leave all of them true on a database whose data allows it:
- tables `oauth_refresh_tokens`, `oauth_grants`, `oauth_access_tokens`, `oauth_device_codes`, `client_access`;
- all 18 `clients` columns of spec §7 rule 7 and `policies.scopes`;
- `clients.client_name` and `clients.client_uid` NOT NULL; `clients.client_secret` and `clients.user_id` nullable;
- a single-column unique constraint on `clients.client_uid` (name `clients_client_uid_key`);
- FKs: `clients.user_id`, `oauth_refresh_tokens.{client_id,user_id}`, `oauth_grants.user_id`,
  `oauth_access_tokens.{user_id,client_id}`, `oauth_device_codes.{client_id,user_id}`,
  `client_access.{user_id,client_id,granted_by}` — to `{users_table}` / `clients`;
- the 15 indexes: `idx_oauth_refresh_tokens_user`, `idx_oauth_refresh_tokens_client`,
  `idx_oauth_refresh_tokens_parent`, `idx_oauth_grants_user`, `idx_oauth_access_tokens_jti`,
  `idx_oauth_access_tokens_user`, `idx_oauth_device_codes_device_code`, `idx_oauth_device_codes_user_code`,
  `idx_oauth_device_codes_client`, `idx_oauth_device_codes_status_expires`, `idx_clients_registration_source`,
  `uq_client_access_user_client`, `uq_client_access_user_client_uid`, `idx_client_access_client_uid`,
  `idx_client_access_client_status`.

Style model for guarded SQL: `navigator_auth/migrations/sql/identity/004_identity_base_columns.sql`
(after TASK-159; header comment with FEAT id + rationale, `DO $$ … $$` blocks guarded on
`to_regclass(...)` / catalog lookups).

`documentation/client_changes.md` line 1: `  # ALTER TABLE para auth.clients (OAuth2 public clients)`
(occurrences: 1).

### Does NOT Exist
- ~~Any Python loader of `ddl.sql`~~ — no code reads it (spec §1); deleting it breaks no import.
- ~~`CREATE TABLE` for `{schema}.clients` / `{schema}.policies` / `{schema}.{users_table}`~~ — base tables
  come from the Navigator platform; do not create them (spec Non-Goals).
- ~~`BEGIN` / `COMMIT` / `CONCURRENTLY`~~ — the runner wraps the file in its own transaction (spec §7).
- ~~Seed rows / test clients~~ — rule 1; the tests reject `test_client_secret` and `localhost`.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/migrations/sql/oauth2/001_oauth2_schema.sql", "action": "CREATE"},
    {"path": "documentation/client_changes.md", "action": "MODIFY"},
    {"path": "tests/unit/migrations/test_oauth2_sql.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/migrations/catalog.py#render_sql",
    "sym:navigator_auth/migrations/catalog.py#set_dir"
  ]
}
```

---

## Implementation Notes

### OAuth2 conversion rules (spec §7, verbatim intent)
1. **Drop all seed/test data** — none of the `client_secret = 'test_client_secret'` `UPDATE`s is carried over.
2. **`client_name`**: add nullable → backfill `client_name = client` → `SET NOT NULL` inside a guarded
   block that only runs when no NULLs remain; otherwise `RAISE WARNING` and let the runner's
   postcondition fail the file (rolled back, not recorded). Same treatment for `client_uid`.
3. **Constraint**: `pg_constraint`-guarded `ADD CONSTRAINT clients_client_uid_key UNIQUE (client_uid)`;
   never `DROP CONSTRAINT`.
4. **Keep** the idempotent backfills that only fill NULLs: `client` ↔ `client_name`, `client_uid`,
   `registration_source`.
5. **Duplicated blocks** appear once.
6. **Every statement is guarded** on its table's existence (`ALTER TABLE IF EXISTS`, or a `DO` block on
   `to_regclass('{schema}.clients')`, …). `UPDATE`s and `CREATE TABLE`s that reference `clients` /
   `{users_table}` go inside such `DO` blocks.
7. **Coverage** — every object in the contract table above.

### Key Constraints
- New SQL uses `{schema}` / `{users_table}` only — no hard-coded `auth.` (spec §7 Patterns).
- Running the file twice on a populated `{schema}.clients` must not error (AC).
- Missing data is reported for operator repair (via the runner's postconditions), never fabricated.

---

## Implementation Blueprint

### Steps (in order)
1. Read `ddl.sql` lines 1-284 and `004_identity_base_columns.sql` — *why*: exact table bodies and house style.
2. Write the SQL file section by section from the skeleton below — *why*: one section per rule keeps review tractable.
3. `git rm navigator_auth/backends/oauth2/ddl.sql`; prepend the note to `client_changes.md`.
4. Write `test_oauth2_sql.py`; run the Validation Commands. If a disposable PostgreSQL is at hand,
   run the file twice through `render_sql` on a populated `clients` table (TASK-168 automates this).

### `navigator_auth/migrations/sql/oauth2/001_oauth2_schema.sql` (CREATE)
```sql
-- FEAT-110 — OAuth2 schema (FEAT-093/094/095), converted from the hand-applied
-- navigator_auth/backends/oauth2/ddl.sql into a managed migration.
-- Applied by `navauth self upgrade`; {schema} / {users_table} are rendered by
-- navigator_auth/migrations/catalog.py::render_sql. Idempotent and guarded.
-- No seed or test data: the old patch set client_secret = 'test_client_secret'
-- on every client without a secret, i.e. on every legitimate public client.
-- Completion (NOT NULL, unique client_uid, foreign keys, indexes) is verified by the
-- runner after this file; unmet conditions roll the file back for operator repair.

-- 1. {schema}.clients columns (ddl.sql 7-33, 223-239)
-- FILL IN: ALTER TABLE IF EXISTS {schema}.clients ADD COLUMN IF NOT EXISTS … for all 18 columns
--   (client_name WITHOUT NOT NULL; user_id INTEGER without inline REFERENCES);
--   ALTER COLUMN client_secret DROP NOT NULL; ALTER COLUMN user_id DROP NOT NULL.

-- 2. Backfills that only fill NULLs (rule 4)
DO $$
BEGIN
    IF to_regclass('{schema}.clients') IS NULL THEN
        RETURN;
    END IF;
    -- FILL IN: client_name = client / client = client_name (WHERE … IS NULL);
    --   client_uid = 'client_' || client_id::text || '_' || substr(md5(random()::text), 1, 12) WHERE client_uid IS NULL;
    --   registration_source = 'static' WHERE registration_source IS NULL.
END
$$;

-- 3. NOT NULL and unique client_uid, guarded (rules 2-3)
-- FILL IN: one DO block — SET NOT NULL on client_name / client_uid only when no NULL rows remain
--   (else RAISE WARNING naming the column); ADD CONSTRAINT clients_client_uid_key UNIQUE (client_uid)
--   only when absent in pg_constraint for conrelid = to_regclass('{schema}.clients');
--   FK on clients.user_id → {schema}.{users_table}(user_id) ON DELETE CASCADE only when no FK exists on that column.

-- 4. policies.scopes (ddl.sql 168-169)
ALTER TABLE IF EXISTS {schema}.policies
    ADD COLUMN IF NOT EXISTS scopes JSONB DEFAULT '[]'::jsonb;

-- 5. New tables + their indexes (ddl.sql 100-162, 186-214, 255-284), guarded on clients/{users_table}
-- FILL IN: DO block (or blocks) guarded on to_regclass('{schema}.clients') and
--   to_regclass('{schema}.{users_table}'): CREATE TABLE IF NOT EXISTS for oauth_refresh_tokens,
--   oauth_grants, oauth_access_tokens, oauth_device_codes, client_access with the exact column bodies
--   of ddl.sql (auth.clients → {schema}.clients, auth.users → {schema}.{users_table}); then every
--   CREATE [UNIQUE] INDEX IF NOT EXISTS of the old file, including idx_clients_registration_source.
```
**Why this shape**: sections mirror the seven rules so a reviewer can tick them off.
Guards make the file a no-op on a database without the base tables; the runner's
prerequisite check fails such a database before the file runs (spec rule 6).

### `documentation/client_changes.md` (MODIFY)
```markdown
<!-- occurrences: 1 (verified: grep -c '# ALTER TABLE para auth.clients (OAuth2 public clients)' documentation/client_changes.md) -->
<!-- BEFORE — insert above line 1 `  # ALTER TABLE para auth.clients (OAuth2 public clients)` (verified: documentation/client_changes.md:1) -->
> **Superseded (FEAT-110).** This patch is now the managed migration
> `navigator_auth/migrations/sql/oauth2/001_oauth2_schema.sql`, applied by
> `navauth self upgrade`. Do not run the SQL below by hand.

```

### FILL IN checklist
- [ ] Section 1 — 18 column adds, two `DROP NOT NULL`s
- [ ] Section 2 — four NULL-only backfills
- [ ] Section 3 — guarded `SET NOT NULL` ×2, guarded unique constraint, guarded `clients.user_id` FK
- [ ] Section 5 — five tables, 15 indexes
- [ ] `test_oauth2_sql.py` — the two tests below

---

## Acceptance Criteria

- [ ] The file contains no seed or test data (`test_client_secret`, `localhost`) and no `DROP CONSTRAINT`.
- [ ] Every `ADD COLUMN` has `IF NOT EXISTS`; every `ADD CONSTRAINT` sits in a `pg_constraint`-guarded block; `SET NOT NULL` appears only for `client_name` and `client_uid`, after their backfills.
- [ ] Every table, column and index listed in the contract appears in the file; no hard-coded `auth.`.
- [ ] `navigator_auth/backends/oauth2/ddl.sql` no longer exists; `discover(["oauth2"])` returns the new file.
- [ ] `documentation/client_changes.md` starts with the pointer note.

---

## Validation Commands

- `pytest tests/unit/migrations/test_oauth2_sql.py -q`

> `tests/unit/migrations/test_catalog.py` (TASK-159) must keep passing with the new `oauth2/` directory;
> it is in the spec's Validation Contract, so the merge tier runs it.

---

## Test Specification

```python
# tests/unit/migrations/test_oauth2_sql.py
from navigator_auth.migrations.catalog import set_dir

SQL_PATH = set_dir("oauth2") / "001_oauth2_schema.sql"
TABLES = ("oauth_refresh_tokens", "oauth_grants", "oauth_access_tokens", "oauth_device_codes", "client_access")
# FILL IN: CLIENT_COLUMNS (18), INDEXES (15) — from the contract.


def test_oauth2_sql_is_guarded_and_has_no_seed_data():
    """No test_client_secret / localhost / DROP CONSTRAINT / hard-coded schema (regex r"\bauth\." matches
    nothing — comments included); every ADD COLUMN has
    IF NOT EXISTS; every ADD CONSTRAINT is preceded in its DO block by a pg_constraint lookup;
    SET NOT NULL only for client_name and client_uid."""


def test_oauth2_sql_covers_every_object_of_old_ddl():
    """Every name in TABLES, CLIENT_COLUMNS, INDEXES and `scopes` appears; `ddl.sql` is gone."""
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
9. **Close the task** with `parrot sdd task close TASK-167 new-command-migration verified`
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
