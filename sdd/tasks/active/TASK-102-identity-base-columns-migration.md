# TASK-102: Reconcile the `auth.user_identities` base schema (migration 004)

**Feature**: FEAT-103 — Capture, vault and refresh the external provider credential
**Spec**: `sdd/specs/external-provider-token-capture.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Spec §3 Module 0 (prerequisite) + §1 (e) + §6 "Identity-table drift evidence".

The `auth.user_identities` table on the `navigator` dev database predates the
`UserIdentity` model (`navigator_auth/models.py:77`). Migrations `001`-`003`
added every *credential* column, but the **base** columns — `identity_id`
(the model's primary key) and the seven profile columns — exist only in
`examples/sql/identity_vault_schema.sql:58-72` and were never applied to
databases created before it. A real token exchange proved the consequence:

```
TokenExchange: vault write failed provider=azure user_id=35:
  Error on get user_identities: column "identity_id" does not exist
```

So **G2 is unreachable until this lands**: every write through
`IdentityStore.save_linked_identity` dies on the `UserIdentity.get()` lookup.
This task is the prerequisite for TASK-104 (vaulting) and TASK-106 (refresh).

---

## Scope

- Create `navigator_auth/identity/sql/004_identity_base_columns.sql`: additive,
  idempotent DDL that adds `identity_id UUID DEFAULT gen_random_uuid()` plus
  `display_name`, `title`, `nickname`, `email`, `phone`, `short_bio`, `avatar`,
  backfills `identity_id` on existing rows, and promotes `identity_id` to
  PRIMARY KEY **only when** the current primary key is not already
  `identity_id`.
- Register `"004_identity_base_columns.sql"` in `_MIGRATION_FILES`
  (`navigator_auth/identity/migrations.py:18-22`).
- Update the three existing assertions in
  `tests/unit/identity/test_identity_migrations.py` that hardcode
  `conn.execute.await_count == 3` → `4`, and add the `004` file assertions
  next to the existing per-file ones.
- Add `examples/sql/identity_vault_schema.sql` coverage only if the canonical
  DDL has drifted — verify first; per spec §6 it already has all 8 columns, so
  the expected outcome is **no change to that file**.

**NOT in scope**: dropping the legacy `(user_id, uid)` primary key or the
`uid` column (spec Module 0: the model ignores `uid`, and dropping a column in
a migration that also runs against healthy databases is the riskier choice);
adding a unique index on `(user_id, auth_provider)` (spec Module 0 "Note on
`ON CONFLICT`" — that would forbid a user holding two accounts on one
provider, and the 42P10 caller is `ai-parrot`'s, see spec §8 Q5); confirming
the **production** table shape (spec §8 Q5, still open — owner: Jesus Lara).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/identity/sql/004_identity_base_columns.sql` | CREATE | Additive base-column DDL + conditional PK promotion |
| `navigator_auth/identity/migrations.py` | MODIFY | Register `004` in `_MIGRATION_FILES` |
| `tests/unit/identity/test_identity_migrations.py` | MODIFY | `await_count` 3 → 4, assertions for `004` |

---

## Codebase Contract

### Verified Imports
```python
from navigator_auth.identity.migrations import (
    SQL_DIR, ensure_identity_columns, setup_identity_columns,
)                                   # verified: tests/unit/identity/test_identity_migrations.py:7-11
from pathlib import Path            # verified: navigator_auth/identity/migrations.py:8
from unittest.mock import AsyncMock, MagicMock   # verified: test_identity_migrations.py:3
```

### Verified Signatures
```python
# navigator_auth/identity/migrations.py
SQL_DIR = Path(__file__).parent / "sql"                     # verified: :13
_MIGRATION_FILES = (                                        # verified: :18-22
    "001_identity_credentials.sql",
    "002_identity_id_token.sql",
    "003_identity_key_version_integer.sql",
)
async def _run_sql(db_pool: Any, sql: str) -> None:         # verified: :25
async def ensure_identity_columns(db_pool: Any) -> None:    # verified: :42 — loops _MIGRATION_FILES in order
async def setup_identity_columns(db_pool: Any) -> None:     # verified: :59 — logs, never raises

# navigator_auth/models.py — the shape 004 must satisfy
class UserIdentity(Model):                                  # verified: :77
    identity_id: UUID = Column(required=False, primary_key=True, db_default="auto", repr=False)   # :78
    display_name: str; title: str; nickname: str; email: str; phone: str      # :81-85
    short_bio: Text; avatar: Text                                             # :86-87
    user_id: User = Column(required=True, fk="user_id|username", ...)         # :88
    class Meta: name = "user_identities"; schema = AUTH_DB_SCHEMA             # :111-113

# navigator_auth/identity/sql/003_identity_key_version_integer.sql
# the conditional-DDL pattern to copy: DO $$ BEGIN IF EXISTS (SELECT 1 FROM
# information_schema.columns WHERE table_schema='auth' ...) THEN ALTER ... END IF; END $$;
```

### Verified live-database shape (spec §6, `navigator` dev DB, 2026-10-22)
```
present  user_id, uid, auth_provider, auth_data, attributes, created_at,
         provider_user_id, scopes, access_token, refresh_token, token_type,
         expires_at, refreshed_at, enabled, key_version, id_token
pk       pk_auth_user_identities_pkey PRIMARY KEY (user_id, uid)
missing  identity_id, display_name, email, title, nickname, phone, short_bio, avatar
```

### Does NOT Exist (do not reference)
- **No** `004_*.sql` file today — `ls navigator_auth/identity/sql/` returns
  exactly `001`, `002`, `003`.
- **No** migration framework, version table or down-migration: every file is
  re-run on **every** startup (`ensure_identity_columns` docstring, `:44-46`),
  so `004` must be idempotent, not "run once".
- **No** `alembic`, `yoyo` or `asyncpg`-native migration helper in this repo.
- **No** unique index on `(user_id, auth_provider)` — only the non-unique
  `idx_user_identities_user` and the *partial* `uq_user_identities_provider_account`
  on `(user_id, auth_provider, provider_user_id) WHERE provider_user_id IS NOT NULL`
  (`navigator_auth/identity/sql/001_identity_credentials.sql:17-19`).
- **No** `gen_random_uuid()` guarantee — it is built in from PostgreSQL 13;
  `examples/sql/identity_vault_schema.sql:58` already relies on it, so no
  `pgcrypto` extension statement is needed.

---

## Implementation Blueprint

### Steps (in order)
1. Block A: write `004_identity_base_columns.sql`. Three statements in order —
   `ADD COLUMN IF NOT EXISTS` for all 8 columns, then a backfill `UPDATE` for
   rows that predate the default, then a guarded PK promotion. The order
   matters: the PK promotion must not run before every row has a non-null
   `identity_id`, or `ALTER TABLE ... ADD PRIMARY KEY` fails.
2. Block B: register the file in `_MIGRATION_FILES` — because
   `ensure_identity_columns` iterates that tuple and nothing else discovers
   files on disk.
3. Block C: update the existing `await_count == 3` assertions to `4` —
   because they would otherwise fail the moment Block B lands, and a red test
   here looks like a defect in this task rather than an arithmetic update.
4. Block D: add `004` file-content assertions mirroring the existing
   `test_id_token_sql_file_exists_and_additive` shape.
5. Verify the no-op guarantee by reading the SQL, then run
   `pytest tests/unit/identity/test_identity_migrations.py -v`.

### Block A — `navigator_auth/identity/sql/004_identity_base_columns.sql` (CREATE)
```sql
-- Identity Vault: base columns on auth.user_identities (FEAT-103 Module 0)
--
-- Migrations 001-003 added the credential columns, but the BASE columns the
-- `UserIdentity` model requires (models.py:77) were only ever written into
-- examples/sql/identity_vault_schema.sql. A database created before that file
-- therefore has no `identity_id`, and every IdentityStore write fails with
-- `column "identity_id" does not exist`.
--
-- Additive and idempotent — re-run on every startup, and a no-op against a
-- database already built from the canonical DDL. The legacy (user_id, uid)
-- primary key and the `uid` column are deliberately LEFT IN PLACE: the model
-- ignores `uid`, and dropping a column in a migration that also runs against
-- healthy databases is the riskier choice.

ALTER TABLE IF EXISTS auth.user_identities
    ADD COLUMN IF NOT EXISTS identity_id  UUID DEFAULT gen_random_uuid(),
    ADD COLUMN IF NOT EXISTS display_name VARCHAR(254),
    ADD COLUMN IF NOT EXISTS title        VARCHAR(120),
    ADD COLUMN IF NOT EXISTS nickname     VARCHAR(120),
    ADD COLUMN IF NOT EXISTS email        VARCHAR(254),
    ADD COLUMN IF NOT EXISTS phone        VARCHAR(50),
    ADD COLUMN IF NOT EXISTS short_bio    TEXT,
    ADD COLUMN IF NOT EXISTS avatar       TEXT;

-- Backfill: ADD COLUMN ... DEFAULT fills existing rows on PG 11+, but a column
-- added by an older server (or added without the default) can still hold NULLs.
-- FILL IN: confirm whether a NOT NULL constraint should be asserted after the
-- backfill — bounded by Module 0's guardrail "must be a no-op on a canonical
-- database" (the canonical DDL declares identity_id as PRIMARY KEY, hence
-- already NOT NULL, so asserting it is redundant there but harmless).
UPDATE auth.user_identities
   SET identity_id = gen_random_uuid()
 WHERE identity_id IS NULL;

-- Promote identity_id to PRIMARY KEY only when it is not already the PK.
-- Guarded, because a canonical database already has
-- `identity_id UUID PRIMARY KEY` and a second ADD PRIMARY KEY would raise
-- 42P16 ("multiple primary keys for table are not allowed").
DO $$
DECLARE
    current_pk text;
BEGIN
    SELECT string_agg(a.attname, ',' ORDER BY k.ord)
      INTO current_pk
      FROM pg_constraint c
      JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON TRUE
      JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
     WHERE c.conrelid = 'auth.user_identities'::regclass
       AND c.contype = 'p';

    IF current_pk IS DISTINCT FROM 'identity_id' THEN
        -- FILL IN: decide whether to DROP the legacy constraint named in
        -- `current_pk` before adding the new one, or to add a UNIQUE index on
        -- identity_id and leave the legacy PK untouched — bounded by Module 0
        -- ("the legacy (user_id, uid) primary key ... left in place") and by
        -- the acceptance criterion that save_linked_identity must SUCCEED.
        -- Note: the model declares identity_id as primary_key, and asyncdb's
        -- UserIdentity.get(identity_id=...) only needs a unique lookup, not a
        -- declared PK. Prefer the least destructive option that satisfies it.
        RAISE NOTICE 'auth.user_identities primary key is %, not identity_id', current_pk;
    END IF;
END $$;
```
**Why**: `ADD COLUMN IF NOT EXISTS` is the pattern every sibling migration uses
(`001_identity_credentials.sql:6-15`), and the `DO $$ ... IF ... END IF` guard is
copied from `003_identity_key_version_integer.sql:5-14`, which is this repo's
only precedent for conditional DDL. `'auth.user_identities'::regclass` raises if
the table is absent — the `ALTER TABLE IF EXISTS` above tolerates absence, so
**FILL IN: wrap the DO block in a `to_regclass('auth.user_identities') IS NOT NULL`
guard** — bounded by the guardrail that the whole file must be safe on a database
where the table does not exist yet (`001` uses `ALTER TABLE IF EXISTS` for exactly
that reason).

### Block B — `navigator_auth/identity/migrations.py`
```python
# REPLACE — the `_MIGRATION_FILES` tuple
# occurrences: 1 (verified: grep -c '_MIGRATION_FILES = (' navigator_auth/identity/migrations.py)
_MIGRATION_FILES = (
    "001_identity_credentials.sql",
    "002_identity_id_token.sql",
    "003_identity_key_version_integer.sql",
    "004_identity_base_columns.sql",
)
```
**Why**: `ensure_identity_columns` (`:53`) iterates this tuple and reads each
file from `SQL_DIR`; nothing globs the directory, so an unregistered file is
silently never executed — which is exactly how the base columns went missing.

### Block C — `tests/unit/identity/test_identity_migrations.py` (count updates)
```python
# REPLACE — all three occurrences of the execute-count assertion
# occurrences: 3 (verified: grep -c 'conn.execute.await_count == 3' tests/unit/identity/test_identity_migrations.py
#                 -> lines 67, 84, 101: test_executes_ddl, test_awaitable_acquire_releases,
#                    TestSetupIdentityColumns.test_calls_through)
        assert conn.execute.await_count == 4
```
```python
# REPLACE — the release-count assertion in test_awaitable_acquire_releases
# occurrences: 1 (verified: grep -c 'pool.release.await_count == 3' tests/unit/identity/test_identity_migrations.py -> line 85)
        assert pool.release.await_count == 4
```
```python
# REPLACE — the tuple unpack in test_executes_ddl
# occurrences: 1 (verified: grep -c 'first, second, third = ' tests/unit/identity/test_identity_migrations.py)
        # FEAT-096 TASK-047: 001 then 002; FEAT-099: 003 (INTEGER key_version);
        # FEAT-103 TASK-102: 004 (base columns).
        first, second, third, fourth = (
            c.args[0] for c in conn.execute.await_args_list
        )
        assert "auth.user_identities" in first
        assert "id_token" in second
        assert "key_version TYPE INTEGER" in third
        assert "identity_id" in fourth
```
**Why**: `test_awaitable_acquire_releases` (line 84-86) asserts **both**
`conn.execute.await_count` and `pool.release.await_count` — one release per
migration file — so both move to 4 for the same reason. Leaving either at 3
makes this task land red.

### Block D — `tests/unit/identity/test_identity_migrations.py` (new assertions)
```python
# AFTER — insert below the body of `test_key_version_integer_sql_is_conditional`
# occurrences: 1 (verified: grep -c 'def test_key_version_integer_sql_is_conditional' tests/unit/identity/test_identity_migrations.py)
    def test_base_columns_sql_is_additive_and_guarded(self):
        """FEAT-103 Module 0: 004 adds the model's base columns, never drops."""
        sql = (SQL_DIR / "004_identity_base_columns.sql").read_text()
        assert "ADD COLUMN IF NOT EXISTS" in sql
        for column in (
            "identity_id",
            "display_name",
            "title",
            "nickname",
            "email",
            "phone",
            "short_bio",
            "avatar",
        ):
            assert column in sql
        # The legacy (user_id, uid) PK and the uid column stay put.
        assert "DROP COLUMN" not in sql.upper()
        # FILL IN: assert the primary-key promotion is guarded — bounded by
        # Module 0's "promote identity_id to primary key ONLY WHEN the existing
        # primary key is not already identity_id", i.e. assert on whichever
        # guard Block A actually emitted (contype = 'p' / to_regclass).
```
**Why**: the existing per-file tests are static SQL-text assertions, not DB
round-trips — this repo has no live-Postgres fixture in `tests/unit/identity/`.
The real two-shape / twice-run proof required by the Module 0 guardrail and by
spec §5's first acceptance criterion is therefore a **manual verification step**
(see Acceptance Criteria below), not something this test file can assert.

### FILL IN checklist
- [ ] Block A: the `to_regclass` guard around the `DO $$` block.
- [ ] Block A: whether a legacy PK is dropped, or `identity_id` gets a UNIQUE
      index instead (least-destructive option that makes
      `UserIdentity.get(identity_id=...)` work).
- [ ] Block A: whether to assert `NOT NULL` on `identity_id` after the backfill.
- [ ] Block D: the guard assertion matching Block A's final form.

---

## Implementation Notes

### Key Constraints
- Every migration file re-runs on **every** application startup
  (`ensure_identity_columns`, `migrations.py:42-57`). Idempotence is not a
  nicety, it is the contract.
- `setup_identity_columns` swallows exceptions (`:59-65`), so a broken `004`
  fails **silently** at startup and only surfaces later as the same
  `column ... does not exist` error this task exists to remove. Verify by
  running the SQL, not by watching the log.
- Never `DROP` anything in this file (`test_sql_is_idempotent_and_additive`
  asserts `"DROP" not in sql.upper()` for `001`; keep the same discipline).

### References in Codebase
- `navigator_auth/identity/sql/003_identity_key_version_integer.sql` — the
  conditional-DDL pattern.
- `navigator_auth/identity/sql/001_identity_credentials.sql` — the additive
  `ALTER TABLE IF EXISTS` pattern and the partial unique index.
- `examples/sql/identity_vault_schema.sql:57-75` — the canonical target shape.

---

## Acceptance Criteria

- [ ] `pytest tests/unit/identity/test_identity_migrations.py -v` passes with
      the counts at 4
- [ ] `004_identity_base_columns.sql` contains no `DROP COLUMN` and no
      unconditional `ADD PRIMARY KEY`
- [ ] **Manual, against a real database** (spec §5 criterion 1): on a legacy
      `(user_id, uid)` table, `ensure_identity_columns` makes
      `IdentityStore.save_linked_identity` succeed; running it a **second**
      time is a no-op; running it against a database built from
      `examples/sql/identity_vault_schema.sql` is a no-op. Record the three
      outcomes in the Completion Note — do not claim them untested.
- [ ] `ruff check navigator_auth/identity/` clean

---

## Test Specification

See Block C/D above. The static-SQL tests go in the existing
`tests/unit/identity/test_identity_migrations.py`; no new test module.

---

## Agent Instructions

1. **Read the spec** §3 Module 0, §1 (e) and §6 "Identity-table drift evidence".
2. **Check dependencies** — none.
3. **Update status** in `sdd/tasks/index/external-provider-token-capture.json` → `in-progress`.
4. **Implement** per the blueprint; resolve every `FILL IN`.
5. **Verify** all acceptance criteria, including the manual database proof.
6. **Move this file** to `sdd/tasks/completed/TASK-102-identity-base-columns-migration.md`.
7. **Update index** → `done`.
8. **Fill in the Completion Note**.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
