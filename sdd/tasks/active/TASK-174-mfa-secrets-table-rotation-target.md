# TASK-174: user_mfa_secrets table, 002 migration and MfaSecretTarget (M7)

**Feature**: FEAT-106 — Review fixes: OAuth2 second factor, MFA key rotation, atomic and deadlock-free security transitions
**Spec**: `sdd/specs/basicauth-otp-2fa-review-fixes.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-172
**Assigned-to**: unassigned

---

## Context

Review finding **#2** (spec §1, Module 7, AC7–AC9). TOTP seeds are sealed into
`auth.user_vault_secrets` with the AAD context `mfa/db (user_id, provider, key)`
(`mfa_seed_context`, `navigator_auth/mfa/totp.py:36`). That table's rotation target,
`navigator_session.vault.targets.UserVaultTarget`, rebuilds every row's context as
`user-vault/db (user_id, key)`, so `navigator-vault rotate` cannot re-seal MFA seeds: once the
old master key is retired, every TOTP login answers 503.

`PostgresTarget` has no row filter (it scans the whole table, soft-deleted rows included), and
`UserVaultTarget` lives in an external package — so the only fix is to move the seeds into their own
table whose identity columns are exactly the AAD fields (decision D3). Moved ciphertext stays valid
without re-sealing because the AAD carries no table name. A new `MfaSecretTarget` registered under the
`navigator_session.vault_targets` entry point lets rotation and v1→v2 migration cover them.

This task is **exclusive** (`parallel: false`): the new migration runs from `ensure_mfa_tables`, which
every live-DB MFA test applies through the `mfa_db` fixture, and it edits `pyproject.toml`.

---

## Scope

- Create `navigator_auth/mfa/sql/002_mfa_secrets.sql`: the `{schema}.user_mfa_secrets` table, its partial
  unique index, and an idempotent, atomic move of every `mfa:%` row out of `auth.user_vault_secrets`
  (hard delete from the vault table — `UserVaultTarget` scans soft-deleted rows too).
- Register it: `_MIGRATION_FILES = ("001_mfa_tables.sql", "002_mfa_secrets.sql")`; `MFA_TABLES` gains
  `"user_mfa_secrets"`; fix the `ensure_mfa_tables` docstring ("six" is no longer true).
- Update the `001_mfa_tables.sql` header comment (lines 4–5) to point at the new table.
- `navigator_auth/mfa/totp.py`: replace `VAULT_SECRETS_TABLE` with
  `MFA_SECRETS_TABLE = f"{AUTH_DB_SCHEMA}.user_mfa_secrets"`; every seed read/write/soft-delete filters or
  inserts `provider = PROVIDER_TOTP`; the upsert conflicts on `(user_id, provider, key) WHERE deleted_at IS NULL`.
- Create `navigator_auth/mfa/targets.py` with `MfaSecretTarget(PostgresTarget)` and `factory(resources)`,
  mirroring `navigator_auth/identity/targets.py`.
- `pyproject.toml`: add `mfa = "navigator_auth.mfa.targets:factory"` to
  `[project.entry-points."navigator_session.vault_targets"]`.
- Update the existing tests that read/write seeds through the old table name (intended behaviour change —
  say so in a docstring/comment, AC21).
- Write `tests/test_mfa_review_fixes_vault.py` (AC7, AC8, AC9).

**NOT in scope**:
- The `navigator_auth/vault/reserved.py` `mfa:` prefix guard — keep it unchanged; it still stops users
  from writing `mfa:*` keys through the vault API.
- Any `conn=` parameter on `_load_seed` / `verify` (TASK-172 adds them — this task only swaps the table).
- Reinstalling the package (`uv pip install -e .`) — never in a worktree; tests construct the target directly.
- Documentation (`docs/two_factor_auth.rst`, CHANGELOG) — TASK-188.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/mfa/sql/002_mfa_secrets.sql` | CREATE | Table, partial unique index, guarded atomic move of `mfa:%` rows |
| `navigator_auth/mfa/sql/001_mfa_tables.sql` | MODIFY | Header comment (lines 4–5) points at `user_mfa_secrets` |
| `navigator_auth/mfa/migrations.py` | MODIFY | Register `002_mfa_secrets.sql`; `MFA_TABLES` gains `user_mfa_secrets`; docstring |
| `navigator_auth/mfa/totp.py` | MODIFY | `MFA_SECRETS_TABLE` replaces `VAULT_SECRETS_TABLE`; provider column in all seed SQL |
| `navigator_auth/mfa/targets.py` | CREATE | `MfaSecretTarget` + entry-point `factory` |
| `pyproject.toml` | MODIFY | `mfa` vault-target entry point |
| `tests/test_mfa_review_fixes_vault.py` | CREATE | AC7, AC8, AC9 tests |
| `tests/test_mfa_vault_isolation.py` | MODIFY | Add: seeds never live in the user vault table |
| `tests/test_mfa_enrollment_security.py` | MODIFY | `VAULT` constant → new table |
| `tests/test_mfa_admin_disenroll.py` | MODIFY | `VAULT` constant → new table; INSERT carries `provider` |
| `tests/test_mfa_e2e.py` | MODIFY | `VAULT` constant → new table; seed-copy INSERT carries `provider` |
| `tests/test_mfa_migrations.py` | MODIFY | Table-declaration test spans every migration file |

---

## Codebase Contract (Anti-Hallucination)

> **CRITICAL**: This section contains VERIFIED code references from the actual codebase.
> The implementing agent MUST use these exact imports, class names, and method signatures.
> **DO NOT** invent, guess, or assume any import, attribute, or method not listed here.
> If you need something not listed, VERIFY it exists first with `grep` or `read`.
>
> Verified against `0b80d88` (branch `feat-FEAT-106-basicauth-otp-2fa`). TASK-172 lands first and edits
> `_load_seed`/`verify` in `totp.py` (adds `conn=`); line numbers there may shift — re-run the `grep -c`
> commands in the blueprint before editing.

### Verified Imports
```python
from navigator_session.vault.targets.postgres import PostgresTarget   # verified: site-packages navigator_session 1.1.1, vault/targets/postgres.py:89
from navigator_session.vault.context import ContextValue              # verified: vault/context.py:32 (also re-exported by navigator_session.vault, __init__.py:30)
from navigator_session.vault.targets import UserVaultTarget           # verified: vault/targets/__init__.py:3
from navigator_session.vault.registry import VaultRow                 # verified: vault/registry.py:36 (dataclass: ref, pk, identity, values, key_version, state)
from navigator_session.vault import KeyRing, VaultContext, rotate_master_key, seal_value, open_value  # verified: vault/__init__.py:28,30,43 (seal/open used by totp.py:15)
from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE      # verified: navigator_auth/conf.py:33,34
from navigator_auth.mfa.totp import MFA_SEED_PURPOSE, TOTP_VAULT_KEY, mfa_seed_context, TOTPProvider  # verified: totp.py:29,26,36,70
from navigator_auth.mfa.types import PROVIDER_TOTP                    # verified: mfa/types.py:10
from navigator_auth.mfa.exceptions import MfaStorageError             # verified: mfa/exceptions.py:8
from navigator_auth.mfa.migrations import MFA_TABLES, SQL_DIR, _MIGRATION_FILES, ensure_mfa_tables, render_sql, setup_mfa_tables  # verified: migrations.py:14,12,13,77,24,117
from navigator_auth.vault.integration import setup_vault_tables, VAULT_KEYRING_APP_KEY  # verified: vault/integration.py:103,29
from tests.fixtures.mfa import mfa_db, mfa_user_factory, frozen_totp_clock  # verified: tests/fixtures/mfa.py:59,76,151
```

### Existing Signatures to Use
```python
# navigator_auth/mfa/totp.py
TOTP_VAULT_KEY = "mfa:totp"                                            # line 26
MFA_SEED_PURPOSE, MFA_PENDING_PURPOSE = "mfa", "mfa-pending"           # line 29
VAULT_SECRETS_TABLE = "auth.user_vault_secrets"                        # line 31  (REPLACED by this task)
def mfa_seed_context(user_id: int, provider: str = PROVIDER_TOTP, key: str = TOTP_VAULT_KEY) -> VaultContext  # line 36
    # VaultContext(purpose=MFA_SEED_PURPOSE, layer="db", fields=(("user_id", int), ("provider", str), ("key", str)))
class TOTPProvider(AbstractOTPProvider):                               # line 70
    def __init__(self, *, app, db_pool, store, issuer=AUTH_TOTP_ISSUER, clock=time.time)  # line 76
    def _keyring(self) -> KeyRing                                       # line 88 — app[VAULT_KEYRING_APP_KEY] or MfaStorageError
    async def _load_seed(self, user_id: int) -> Optional[bytes]         # line 113; SQL at line 117 (TASK-172 adds `*, conn=None`)
    async def is_enrolled(self, user: Mapping) -> bool                  # line 136; EXISTS sub-select at line 142
    async def verify(self, request, user, code, challenge=None) -> bool # line 210
    async def _disenroll_on(self, conn: Any, user_id: int) -> None      # line 241; UPDATE at line 243
    async def _install_seed(self, conn: Any, user_id: int, seed: bytes) -> None  # line 268; INSERT at line 272

# navigator_auth/mfa/migrations.py
SQL_DIR = Path(__file__).parent / "sql"                                 # line 12
_MIGRATION_FILES = ("001_mfa_tables.sql",)                              # line 13
MFA_TABLES = ("tenant_mfa_policy", "user_mfa", "user_mfa_backup_codes", "user_trusted_devices", "user_mfa_audit", "user_mfa_security")  # lines 14-21
def render_sql(sql: str) -> str                                         # line 24 — {schema}/{users_table} via str.replace
async def ensure_mfa_tables(db_pool: Any) -> None                       # line 77 — runs each file; _raise_on_execute_error on (result, err) tuples
async def mfa_tables_present(db_pool: Any) -> bool                      # line 96 — to_regclass probe over MFA_TABLES
async def setup_mfa_tables(db_pool: Any) -> bool                        # line 117 — never raises

# navigator_auth/identity/targets.py — the pattern to mirror
class IdentityTarget(PostgresTarget):                                   # line 21; __init__ sets instance table/name then super().__init__(db_pool)
def factory(resources: Mapping[str, Any]) -> Optional[IdentityTarget]  # line 60 — resources.get("db_pool") or None

# navigator_session (site-packages 1.1.1)
class PostgresTarget:                                                    # vault/targets/postgres.py:89
    name/table/purpose/pk_column/identity_columns/encrypted_fields/include_field_in_context/
    key_version_column/touch_column/state_columns/quarantine_assignments  # ClassVars, lines 102-116
    def __init__(self, db_pool) -> None                                  # line 118 — validates columns; quote_ident(self.table) handles "schema.table"
    def context_value(self, column, value) -> ContextValue               # line 152 (hook)
    def pk_from_json(self, value) -> Any                                 # hook
    def state_from_json(self, column, value) -> Any                      # hook
    def context_for(self, row, field) -> VaultContext                    # line 177 — fields from identity_columns via context_value
    async def iter_batches(self, batch_size)                             # line 194 — scans EVERY row, soft-deleted included
class UserVaultTarget(PostgresTarget): purpose="user-vault"; identity_columns=("user_id","key")  # vault/targets/user_vault.py:33
async def rotate_master_key(targets, old_key_id, new_key_id, keyring, batch_size=100) -> dict[str, dict]  # vault/key_rotation.py:40
    # per target stats: total, rotated, skipped, errors, failed_refs; rows whose blob key_id != old_key_id are skipped;
    # unreadable headers count as errors.
class KeyRing: def __init__(self, master_keys: Mapping[int, bytes], active_key_id: int, *, cipher_backend="aesgcm", naming_key_id=None)  # keyring.py:137; MAX_KEY_ID = 0xFFFF (line 44)

# auth.user_vault_secrets (navigator_auth/vault/sql/001_create_vault_tables.sql:11-20)
#   id UUID PK DEFAULT gen_random_uuid(), user_id INTEGER, key VARCHAR(255), ciphertext_db BYTEA,
#   key_version SMALLINT → widened to INTEGER by vault/sql/002_vault_crypto_hardening.sql:49-68 (FEAT-099),
#   created_at, updated_at, deleted_at TIMESTAMPTZ.

# pyproject.toml
[project.entry-points."navigator_session.vault_targets"]                 # line 76
identity = "navigator_auth.identity.targets:factory"                     # line 77
```

### Does NOT Exist
- ~~`{schema}.user_mfa_secrets`~~, ~~`navigator_auth/mfa/targets.py`~~, ~~`MfaSecretTarget`~~,
  ~~`navigator_auth.mfa.totp.MFA_SECRETS_TABLE`~~, ~~`002_mfa_secrets.sql`~~ — created by this task.
- ~~a row filter / `WHERE` hook on `PostgresTarget`~~ — none; a shared table cannot be partitioned between targets (D3).
- ~~`navigator_session.vault.migrate.runner.rotate_master_key`~~ — rotation is `navigator_session.vault.key_rotation`
  (exported from `navigator_session.vault`).
- ~~`navigator_session.vault.discover_targets`~~ — `discover_targets` lives in `navigator_session.vault.registry`
  and reads INSTALLED entry-point metadata (stale until reinstall); do not use it in tests.
- ~~`TargetRow` as a constructible class~~ — `registry.TargetRow` is a `Protocol`; build rows with `VaultRow(...)`.
- ~~`BackupCodeStore` / `user_mfa_backup_codes` in the vault~~ — backup codes are keyed hashes, not sealed; untouched.
- ~~`IdentityTarget`-style `audit_quarantine` for MFA~~ — the default no-op is used.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/mfa/sql/002_mfa_secrets.sql", "action": "CREATE"},
    {"path": "navigator_auth/mfa/sql/001_mfa_tables.sql", "action": "MODIFY"},
    {"path": "navigator_auth/mfa/migrations.py", "action": "MODIFY"},
    {"path": "navigator_auth/mfa/totp.py", "action": "MODIFY"},
    {"path": "navigator_auth/mfa/targets.py", "action": "CREATE"},
    {"path": "pyproject.toml", "action": "MODIFY"},
    {"path": "tests/test_mfa_review_fixes_vault.py", "action": "CREATE"},
    {"path": "tests/test_mfa_vault_isolation.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_enrollment_security.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_admin_disenroll.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_e2e.py", "action": "MODIFY"},
    {"path": "tests/test_mfa_migrations.py", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/mfa/totp.py#mfa_seed_context",
    "sym:navigator_auth/mfa/totp.py#TOTPProvider",
    "sym:navigator_auth/mfa/totp.py#TOTPProvider._load_seed",
    "sym:navigator_auth/mfa/totp.py#TOTPProvider.is_enrolled",
    "sym:navigator_auth/mfa/totp.py#TOTPProvider.verify",
    "sym:navigator_auth/mfa/totp.py#TOTPProvider._disenroll_on",
    "sym:navigator_auth/mfa/totp.py#TOTPProvider._install_seed",
    "sym:navigator_auth/mfa/migrations.py#render_sql",
    "sym:navigator_auth/mfa/migrations.py#ensure_mfa_tables",
    "sym:navigator_auth/mfa/migrations.py#mfa_tables_present",
    "sym:navigator_auth/mfa/migrations.py#setup_mfa_tables",
    "sym:navigator_auth/identity/targets.py#IdentityTarget",
    "sym:navigator_auth/identity/targets.py#factory",
    "sym:navigator_auth/vault/integration.py#setup_vault_tables"
  ]
}
```

---

## Implementation Notes

### Pattern to Follow
```python
# navigator_auth/identity/targets.py:21-57 — instance table/name override, then super().__init__
class IdentityTarget(PostgresTarget):
    def __init__(self, db_pool: Any, schema: str = AUTH_DB_SCHEMA) -> None:
        self.table = f"{schema}.user_identities"
        self.name = self.table
        super().__init__(db_pool)
```

### Key Constraints
- **DDL deviation from spec §2 (decided here):** `key_version` is `INTEGER`, not `SMALLINT`. FEAT-099
  (`vault/sql/002_vault_crypto_hardening.sql:49-68`) widened `auth.user_vault_secrets.key_version` to
  INTEGER because `KeyRing` accepts key ids up to `0xFFFF` (`keyring.py:44`); a SMALLINT column would make
  the move fail (or overflow on a later rotation) for key ids > 32767. Everything else in the DDL is spec §2 verbatim.
- **Move conflict target (decided here):** use `ON CONFLICT DO NOTHING` (no target), not `ON CONFLICT (id)`.
  `ON CONFLICT (id)` does not catch a violation of the partial unique index `(user_id, provider, key)`; with a
  pre-existing active row the whole startup migration would fail and MFA would be unavailable. The vault copy
  of such a row is stale (new code writes only the new table) and is deleted with the rest.
- The INSERT … SELECT and the DELETE live in **one** `DO $$ … $$` block, guarded by
  `to_regclass('auth.user_vault_secrets') IS NOT NULL` — a DO block is one statement, so the move is atomic
  regardless of how asyncdb sends the file (spec "Known Risks: multi-statement migration atomicity").
- The vault table is always `auth.user_vault_secrets` (hard-coded schema in the vault DDL and in
  `UserVaultTarget`); the new table uses `{schema}` like every MFA table.
- Every `mfa:%` row is a TOTP seed today (`TOTP_VAULT_KEY = "mfa:totp"` is the only writer), so the moved rows get
  `provider = 'totp'`, which equals `mfa_seed_context`'s default provider — the AAD still matches.
- asyncdb `conn.execute` swallows DB errors; seed writes keep using `fetchval … RETURNING` (project memory
  `asyncdb-execute-never-raises`). Never log seed bytes, ciphertext or key material.
- Google-style docstrings + type hints on every new function/class; module logger, never `print`.
- Entry points are read from installed metadata — the `mfa` target is invisible to `discover_targets()` until the
  package is reinstalled by the operator. Tests assert the `pyproject.toml` declaration and build the target directly.

### References in Codebase
- `navigator_auth/identity/targets.py` — target + factory pattern
- `navigator_auth/vault/sql/001_create_vault_tables.sql:11-35` — source table layout
- `navigator_auth/identity/sql/003_identity_key_version_integer.sql` — INTEGER key_version precedent
- site-packages `navigator_session/vault/targets/user_vault.py:33-62` — hooks for a UUID pk + TIMESTAMPTZ state

---

## Implementation Blueprint

> **CRITICAL — Executor-ready starting point.** Write each block below to its declared
> path nearly verbatim, then complete every `# FILL IN:` marker. Blocks were derived
> from the spec's Interface Skeletons and re-verified against the Codebase Contract
> above when this task was written. This is NOT the full implementation:
> business-logic branches, edge cases and test bodies are `FILL IN` stubs by design.
> Never change a signature, class name, or file path the blueprint fixes.

### Steps (in order)
1. Create `002_mfa_secrets.sql` — *why*: the table must exist before `totp.py` reads it, and the move must run on every startup until no `mfa:%` row is left in the vault table.
2. Register it in `migrations.py` and add `user_mfa_secrets` to `MFA_TABLES` — *why*: `mfa_tables_present` then reports MFA unavailable (fail closed) when the new table is missing (AC9).
3. Update the `001_mfa_tables.sql` header comment — *why*: it currently tells readers the seed lives in the vault table.
4. Swap the table in `totp.py` and add the `provider` column to its four seed statements — *why*: the identity columns must equal the AAD fields for rotation to rebuild the right context (G2).
5. Create `targets.py` — *why*: `rotate_master_key` needs a target whose `context_for` equals `mfa_seed_context` (AC7).
6. Add the entry point to `pyproject.toml` — *why*: `navigator-vault` discovers targets only through `navigator_session.vault_targets` (AC9).
7. Update the four existing test files, then write `tests/test_mfa_review_fixes_vault.py` — *why*: AC21 keeps every existing MFA suite green; the new file proves AC7–AC9.
8. Run the Validation Commands — *why*: every live suite re-applies the migration through `mfa_db`.

### `navigator_auth/mfa/sql/002_mfa_secrets.sql` (CREATE)
```sql
-- FEAT-106 review fix #2 (spec M7): TOTP seeds get their own table.
-- {schema} / {users_table} are substituted by mfa/migrations.py.
-- Identity columns (user_id, provider, key) == the AAD fields of mfa_seed_context, so the
-- MfaSecretTarget (navigator_auth/mfa/targets.py) rebuilds the right context on rotation and moved
-- ciphertext stays valid without re-sealing (the AAD carries no table name).
-- key_version is INTEGER (not SMALLINT) to match auth.user_vault_secrets after FEAT-099.
-- Additive and idempotent: safe to run on every startup.
CREATE TABLE IF NOT EXISTS {schema}.user_mfa_secrets (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       bigint       NOT NULL REFERENCES {schema}.{users_table}(user_id) ON DELETE CASCADE,
    provider      VARCHAR(32)  NOT NULL,
    key           VARCHAR(255) NOT NULL,
    ciphertext_db BYTEA        NOT NULL,
    key_version   INTEGER      NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at    TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS user_mfa_secrets_active_unique
    ON {schema}.user_mfa_secrets (user_id, provider, key) WHERE deleted_at IS NULL;

-- Move every MFA seed out of the user vault (UserVaultTarget scans soft-deleted rows too, so the
-- vault rows are HARD-deleted). One DO block = one statement = atomic. No-op once moved, and a
-- no-op when the vault table does not exist.
DO $$
BEGIN
    IF to_regclass('auth.user_vault_secrets') IS NOT NULL THEN
        INSERT INTO {schema}.user_mfa_secrets
            (id, user_id, provider, key, ciphertext_db, key_version, created_at, updated_at, deleted_at)
        SELECT id, user_id, 'totp', key, ciphertext_db, key_version, created_at, updated_at, deleted_at
          FROM auth.user_vault_secrets
         WHERE key LIKE 'mfa:%'
        ON CONFLICT DO NOTHING;
        DELETE FROM auth.user_vault_secrets WHERE key LIKE 'mfa:%';
    END IF;
END $$;
```
**Why this shape**: spec §2 DDL with two decided deviations (INTEGER `key_version`; target-less `ON CONFLICT`,
see Key Constraints). Do not add a vault-side soft delete: a soft-deleted `mfa:` row would still be scanned and
fail rotation under the `user-vault` context.

### `navigator_auth/mfa/sql/001_mfa_tables.sql` (MODIFY)
```sql
-- occurrences: 1 (verified: grep -c "under the reserved 'mfa:' namespace (TASK-136 / TASK-143)." navigator_auth/mfa/sql/001_mfa_tables.sql)
-- REPLACE — lines 4-5 (verified: navigator_auth/mfa/sql/001_mfa_tables.sql:4-5):
--   -- The TOTP seed is NOT here: it lives sealed in {schema}.user_vault_secrets
--   -- under the reserved 'mfa:' namespace (TASK-136 / TASK-143).
-- WITH:
-- The TOTP seed is NOT here: it lives sealed in {schema}.user_mfa_secrets
-- (002_mfa_secrets.sql; rotated by navigator_auth.mfa.targets.MfaSecretTarget).
```
**Why**: comment only — DDL in 001 is unchanged so existing databases are not touched by it.

### `navigator_auth/mfa/migrations.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '_MIGRATION_FILES = ("001_mfa_tables.sql",)' navigator_auth/mfa/migrations.py)
# REPLACE — `_MIGRATION_FILES = ("001_mfa_tables.sql",)` (verified: navigator_auth/mfa/migrations.py:13)
_MIGRATION_FILES = ("001_mfa_tables.sql", "002_mfa_secrets.sql")

# occurrences: 1 (verified: grep -c 'MFA_TABLES = (' navigator_auth/mfa/migrations.py)
# REPLACE — the `MFA_TABLES = (` tuple (verified: navigator_auth/mfa/migrations.py:14-21); append the last entry:
MFA_TABLES = (
    "tenant_mfa_policy",
    "user_mfa",
    "user_mfa_backup_codes",
    "user_trusted_devices",
    "user_mfa_audit",
    "user_mfa_security",
    "user_mfa_secrets",
)

# occurrences: 1 (verified: grep -c 'Create the six MFA tables if missing.' navigator_auth/mfa/migrations.py)
# REPLACE — docstring first line in ensure_mfa_tables (verified: navigator_auth/mfa/migrations.py:78)
    """Create the MFA tables if missing and move MFA seeds out of the user vault.
```
**Why**: `mfa_tables_present` probes `MFA_TABLES`, so a missing `user_mfa_secrets` makes `setup_mfa_tables`
return False → MFA unavailable → logins refused (fail closed), never a seed lookup against a missing table.

### `navigator_auth/mfa/totp.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'VAULT_SECRETS_TABLE = "auth.user_vault_secrets"' navigator_auth/mfa/totp.py)
# REPLACE — line 31 (verified: navigator_auth/mfa/totp.py:31)
MFA_SECRETS_TABLE = f"{AUTH_DB_SCHEMA}.user_mfa_secrets"

# occurrences: 1 (verified: grep -cF 'f"SELECT ciphertext_db FROM {VAULT_SECRETS_TABLE} WHERE user_id = $1 AND key = $2 AND deleted_at IS NULL",' navigator_auth/mfa/totp.py)
# REPLACE — _load_seed SQL (verified: navigator_auth/mfa/totp.py:117-119); keep TASK-172's connection handling as-is
                    f"SELECT ciphertext_db FROM {MFA_SECRETS_TABLE} WHERE user_id = $1 AND provider = $2 AND key = $3 AND deleted_at IS NULL",
                    user_id,
                    PROVIDER_TOTP,
                    TOTP_VAULT_KEY,

# occurrences: 1 (verified: grep -cF 'EXISTS (SELECT 1 FROM {VAULT_SECRETS_TABLE} v WHERE v.user_id=$1 AND v.key=$3 AND v.deleted_at IS NULL)' navigator_auth/mfa/totp.py)
# REPLACE — is_enrolled sub-select (verified: navigator_auth/mfa/totp.py:142); $2 is already PROVIDER_TOTP (line 144)
                    f"SELECT m.enabled, m.confirmed_at FROM {USER_MFA_TABLE} m WHERE m.user_id=$1 AND m.provider=$2 AND EXISTS (SELECT 1 FROM {MFA_SECRETS_TABLE} v WHERE v.user_id=$1 AND v.provider=$2 AND v.key=$3 AND v.deleted_at IS NULL)",

# occurrences: 1 (verified: grep -cF 'f"UPDATE {VAULT_SECRETS_TABLE} SET deleted_at = now() WHERE user_id=$1 AND key=$2 AND deleted_at IS NULL RETURNING 1",' navigator_auth/mfa/totp.py)
# REPLACE — _disenroll_on first statement (verified: navigator_auth/mfa/totp.py:242-246)
        await conn.fetchval(
            f"UPDATE {MFA_SECRETS_TABLE} SET deleted_at = now() WHERE user_id=$1 AND provider=$2 AND key=$3 AND deleted_at IS NULL RETURNING 1",
            user_id,
            PROVIDER_TOTP,
            TOTP_VAULT_KEY,
        )

# occurrences: 1 (verified: grep -cF 'f"INSERT INTO {VAULT_SECRETS_TABLE} (user_id,key,ciphertext_db,key_version) VALUES ($1,$2,$3,$4)' navigator_auth/mfa/totp.py)
# REPLACE — _install_seed first statement (verified: navigator_auth/mfa/totp.py:271-277)
        await conn.fetchval(
            f"INSERT INTO {MFA_SECRETS_TABLE} (user_id,provider,key,ciphertext_db,key_version) VALUES ($1,$2,$3,$4,$5) "
            "ON CONFLICT (user_id,provider,key) WHERE deleted_at IS NULL DO UPDATE SET "
            "ciphertext_db=EXCLUDED.ciphertext_db,key_version=EXCLUDED.key_version,updated_at=NOW() RETURNING 1",
            user_id,
            PROVIDER_TOTP,
            TOTP_VAULT_KEY,
            ciphertext,
            keyring.active_key_id,
        )
```
**Why**: the `provider` value written is exactly the one `mfa_seed_context(user_id)` seals with, so the target's
`context_for` reproduces the AAD. After editing, `grep -c VAULT_SECRETS_TABLE navigator_auth/mfa/totp.py` must be 0
and nothing else in the repo may import it (`grep -rn VAULT_SECRETS_TABLE navigator_auth tests` → empty).

### `navigator_auth/mfa/targets.py` (CREATE)
```python
"""Vault protected target for MFA seeds (``<AUTH_DB_SCHEMA>.user_mfa_secrets``) — FEAT-106 spec M7.

Registered under the ``navigator_session.vault_targets`` entry-point group so ``navigator-vault``
rotation and v1 -> v2 migration re-seal TOTP seeds with their own context:
``mfa/db (user_id, provider, key)`` — the same values ``mfa_seed_context`` seals with.
Quarantine soft-deletes the row (the user must re-enrol TOTP); the blob is kept for a restore.
"""

from datetime import datetime
from typing import Any, Mapping, Optional
from uuid import UUID

from navigator_session.vault.context import ContextValue
from navigator_session.vault.targets.postgres import PostgresTarget

from ..conf import AUTH_DB_SCHEMA
from .totp import MFA_SEED_PURPOSE


class MfaSecretTarget(PostgresTarget):
    """Sealed TOTP seeds in ``<AUTH_DB_SCHEMA>.user_mfa_secrets``."""

    name = "auth.user_mfa_secrets"
    table = "auth.user_mfa_secrets"
    purpose = MFA_SEED_PURPOSE
    pk_column = "id"
    identity_columns = ("user_id", "provider", "key")
    encrypted_fields = ("ciphertext_db",)
    include_field_in_context = False
    key_version_column = "key_version"
    touch_column = "updated_at"
    state_columns = ("deleted_at", "updated_at")
    quarantine_assignments = "deleted_at = COALESCE(deleted_at, NOW())"

    def __init__(self, db_pool: Any, schema: str = AUTH_DB_SCHEMA) -> None:
        """Bind the target to the auth schema's table (instance attributes shadow the class defaults)."""
        self.table = f"{schema}.user_mfa_secrets"
        self.name = self.table
        super().__init__(db_pool)

    def context_value(self, column: str, value: Any) -> ContextValue:
        """Match ``mfa_seed_context``: ``user_id`` as int, ``provider``/``key`` as str."""
        if column == "user_id":
            return int(value)
        return str(value)

    def pk_from_json(self, value: Any) -> Any:
        """``id`` is a UUID."""
        return value if isinstance(value, UUID) else UUID(str(value))

    def state_from_json(self, column: str, value: Any) -> Any:
        """Lifecycle columns are TIMESTAMPTZ."""
        if value is None or isinstance(value, datetime):
            return value
        return datetime.fromisoformat(value)


def factory(resources: Mapping[str, Any]) -> Optional[MfaSecretTarget]:
    """Entry-point factory: requires ``db_pool`` (the ``authdb`` pool).

    Returns:
        Target, or ``None`` when no database pool is configured.
    """
    pool = resources.get("db_pool")
    if pool is None:
        return None
    return MfaSecretTarget(pool)
```
**Why this shape**: spec §3 M7 skeleton verbatim, with `IdentityTarget`'s instance override so a non-`auth`
`AUTH_DB_SCHEMA` works. `context_value` must return exactly the types `mfa_seed_context` uses (int user_id,
str provider/key) — a `str` user_id would produce a different AAD and every rotation would error.

### `pyproject.toml` (MODIFY)
```toml
# occurrences: 1 (verified: grep -c 'identity = "navigator_auth.identity.targets:factory"' pyproject.toml)
# AFTER — insert below `identity = "navigator_auth.identity.targets:factory"` (verified: pyproject.toml:77)
mfa = "navigator_auth.mfa.targets:factory"
```
**Why**: entry point name `mfa` is fixed by spec M7/AC9. No dependency change (AC22).

### `tests/test_mfa_enrollment_security.py`, `tests/test_mfa_admin_disenroll.py`, `tests/test_mfa_e2e.py` (MODIFY)
```python
# occurrences: 1 per file (verified: grep -c 'VAULT = "auth.user_vault_secrets"' <file>;
#   test_mfa_enrollment_security.py:63, test_mfa_admin_disenroll.py:40, test_mfa_e2e.py:91)
# REPLACE in each file — `VAULT = "auth.user_vault_secrets"`
VAULT = f"{AUTH_DB_SCHEMA}.user_mfa_secrets"  # FEAT-106 review fix #2: seeds moved out of the user vault (spec M7)
#   AUTH_DB_SCHEMA is already imported in all three files (enrollment_security:32, admin_disenroll:15, e2e:46).

# tests/test_mfa_admin_disenroll.py — occurrences: 1 (verified: grep -cF "(user_id, key, ciphertext_db) VALUES" tests/test_mfa_admin_disenroll.py; line 125)
# REPLACE the INSERT string:
                f"INSERT INTO {VAULT} (user_id, provider, key, ciphertext_db) VALUES ($1, 'totp', 'mfa:totp', $2) RETURNING 1",

# tests/test_mfa_e2e.py — occurrences: 1 each (verified: grep -cF on lines 718 and 719)
# REPLACE lines 718-719 (the AAD-binding seed copy):
        f"INSERT INTO {VAULT} (user_id, provider, key, ciphertext_db, key_version) "
        f"SELECT $2, provider, key, ciphertext_db, key_version FROM {VAULT} "
```
**Why**: every other statement in these files already filters `key = 'mfa:totp'`, which stays correct on the new
table; only the INSERTs need the new NOT NULL `provider` column. Keep the `to_regclass($1)` guards as they are.

### `tests/test_mfa_migrations.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '^def test_migration_declares_six_tables' tests/test_mfa_migrations.py; line 74)
# REPLACE the first two body lines of test_migration_declares_six_tables (lines 75-78) so the table loop spans every file:
    """DDL contains required MFA tables (across every migration file) and security-specific columns.

    Updated for FEAT-106 review fix #2: ``user_mfa_secrets`` is declared in 002_mfa_secrets.sql.
    """
    sql = (SQL_DIR / _MIGRATION_FILES[0]).read_text()
    all_sql = "\n".join((SQL_DIR / name).read_text() for name in _MIGRATION_FILES)
    for table in MFA_TABLES:
        assert f"CREATE TABLE IF NOT EXISTS {{schema}}.{table}" in all_sql
# (the trusted_devices / audit assertions below keep using `sql`, i.e. 001)
```

### `tests/test_mfa_vault_isolation.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'class TestValidateKey:' tests/test_mfa_vault_isolation.py; line 85)
# AFTER — append at the end of the file (after the last test):
def test_mfa_seeds_never_live_in_the_user_vault():
    """FEAT-106 review fix #2: TOTP seeds are stored outside auth.user_vault_secrets (spec M7)."""
    from navigator_auth.mfa import totp

    assert totp.MFA_SECRETS_TABLE.endswith(".user_mfa_secrets")
    assert not hasattr(totp, "VAULT_SECRETS_TABLE")
```

### `tests/test_mfa_review_fixes_vault.py` (CREATE)
```python
"""FEAT-106 review fixes — MFA secrets table and rotation target (spec M7, AC7-AC9)."""

import os
import secrets
import tomllib
from pathlib import Path

import pytest

from navigator_session.vault import KeyRing, rotate_master_key
from navigator_session.vault.registry import VaultRow
from navigator_session.vault.targets import UserVaultTarget

from navigator_auth.conf import AUTH_DB_SCHEMA
from navigator_auth.mfa.exceptions import MfaStorageError
from navigator_auth.mfa.migrations import MFA_TABLES, ensure_mfa_tables
from navigator_auth.mfa.targets import MfaSecretTarget, factory
from navigator_auth.mfa.totp import TOTP_VAULT_KEY, TOTPProvider, mfa_seed_context
from navigator_auth.mfa.types import PROVIDER_TOTP
from navigator_auth.vault.integration import VAULT_KEYRING_APP_KEY, setup_vault_tables
from tests.fixtures.mfa import frozen_totp_clock, mfa_db, mfa_user_factory  # noqa: F401

SECRETS = f"{AUTH_DB_SCHEMA}.user_mfa_secrets"
ROOT = Path(__file__).resolve().parents[1]


def test_mfa_secret_target_context_matches_seed():
    """context_for(row, "ciphertext_db") == mfa_seed_context(user_id)."""
    target = MfaSecretTarget(object())
    row = VaultRow(ref="r", pk=None, identity={"user_id": "42", "provider": PROVIDER_TOTP, "key": TOTP_VAULT_KEY}, values={})
    assert target.context_for(row, "ciphertext_db") == mfa_seed_context(42)


def test_mfa_target_factory_requires_pool():
    """factory({}) is None (AC9)."""
    assert factory({}) is None
    assert isinstance(factory({"db_pool": object()}), MfaSecretTarget)


def test_vault_target_entry_point_declared():
    """pyproject.toml declares mfa = "navigator_auth.mfa.targets:factory"; MFA_TABLES has the table (AC9)."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert data["project"]["entry-points"]["navigator_session.vault_targets"]["mfa"] == "navigator_auth.mfa.targets:factory"
    assert "user_mfa_secrets" in MFA_TABLES


@pytest.mark.asyncio
async def test_mfa_secrets_migration_moves_rows(mfa_db, mfa_user_factory):
    """AC8: mfa:% rows move byte-identical, vault keeps none, re-run is a no-op, failure loses nothing."""
    await setup_vault_tables(mfa_db)
    # FILL IN: insert 1 active + 1 soft-deleted 'mfa:totp' row (fixed id, ciphertext, key_version, timestamps)
    #          into auth.user_vault_secrets for a factory user, plus one ordinary vault row ('jira:token');
    #          run ensure_mfa_tables(mfa_db); assert the two rows exist in SECRETS with provider='totp' and
    #          id/ciphertext_db/key_version/created_at/updated_at/deleted_at identical, zero 'mfa:%' rows remain in
    #          the vault, the 'jira:token' row is untouched; run ensure_mfa_tables again → same state — bounded by AC8.
    # FILL IN: failure injection — re-insert an 'mfa:%' row, create a BEFORE DELETE trigger on auth.user_vault_secrets
    #          that RAISEs for key LIKE 'mfa:%', assert ensure_mfa_tables raises MfaStorageError and the row is still in
    #          the vault and NOT in SECRETS (the DO block rolled back); drop the trigger and function in `finally`
    #          — bounded by spec Known Risks "multi-statement migration atomicity".
    raise NotImplementedError


@pytest.mark.asyncio
async def test_rotate_master_key_rotates_mfa_seeds(mfa_db, mfa_user_factory, frozen_totp_clock):
    """AC7: rotation over [UserVaultTarget, MfaSecretTarget] re-seals seeds; TOTP verifies with key 2 only."""
    await setup_vault_tables(mfa_db)
    old_id, new_id = 40000 + secrets.randbelow(10000), 50000 + secrets.randbelow(10000)
    k1, k2 = os.urandom(32), os.urandom(32)
    # FILL IN: enrol TOTP for a factory user by sealing a 20-byte seed with KeyRing({old_id: k1}, old_id)
    #          through TOTPProvider._install_seed on an acquired conn (app = {VAULT_KEYRING_APP_KEY: ring});
    #          rotate with rotate_master_key([UserVaultTarget(mfa_db), MfaSecretTarget(mfa_db)], old_id, new_id,
    #          KeyRing({old_id: k1, new_id: k2}, new_id)); assert errors == 0 for both targets and the seed row's
    #          key_version == new_id; then verify a current code with a provider whose keyring is
    #          KeyRing({new_id: k2}, new_id) — bounded by AC7. The random key ids keep other rows "skipped".
    # FILL IN: if the shared DB holds unreadable leftovers from other runs (errors > 0 not caused by this test),
    #          assert instead that no failed_refs entry references this test's row ids — and say so in a comment.
    raise NotImplementedError
```
**Why this shape**: the three pure tests need no database (`PostgresTarget.__init__` only stores the pool), so AC9
and the context equality are proven even where Postgres is absent; the two live tests follow the `mfa_db` skip
pattern. Random high key ids keep rows sealed by other tests out of the rotation (they are "skipped", not errors).

### FILL IN checklist
- [ ] `test_mfa_review_fixes_vault.py::test_mfa_secrets_migration_moves_rows` — move, byte identity, idempotency, failure rollback; bounded by AC8
- [ ] `test_mfa_review_fixes_vault.py::test_rotate_master_key_rotates_mfa_seeds` — rotation stats + key-2-only verify; bounded by AC7
- [ ] Re-run every `grep -cF` above after TASK-172 merges; a count of 0 means the SQL line moved — re-locate it, never invent a new attachment point

---

## Acceptance Criteria

- [ ] AC7 — With a TOTP-enrolled user, `rotate_master_key([UserVaultTarget(pool), MfaSecretTarget(pool)], 1, 2, keyring)` reports `errors == 0` for both targets, every MFA seed is at the new `key_version`, and TOTP verify then succeeds with a keyring holding only the new key.
- [ ] AC8 — `002_mfa_secrets.sql` moves `mfa:%` rows byte-identical (ciphertext, key_version, timestamps), leaves zero `mfa:%` rows in `auth.user_vault_secrets`, is a no-op on re-run, succeeds when the vault table does not exist, and an injected failure between INSERT and DELETE loses no row.
- [ ] AC9 — `pyproject.toml` declares the `mfa` vault-target entry point; `factory()` without `db_pool` returns `None`; `MFA_TABLES` includes `user_mfa_secrets`.
- [ ] AC21 — every listed existing MFA suite passes; changed tests say why in a docstring/comment.
- [ ] `grep -rn VAULT_SECRETS_TABLE navigator_auth tests` returns nothing.
- [ ] No linting errors (`ruff check navigator_auth/mfa/targets.py navigator_auth/mfa/totp.py navigator_auth/mfa/migrations.py` if ruff is configured).
- [ ] Imports work: `from navigator_auth.mfa.targets import MfaSecretTarget, factory`.

---

## Validation Commands

- `pytest tests/test_mfa_review_fixes_vault.py -q`
- `pytest tests/test_mfa_vault_isolation.py -q`
- `pytest tests/test_mfa_migrations.py -q`
- `pytest tests/test_mfa_enrollment_security.py -q`
- `pytest tests/test_mfa_admin_disenroll.py -q`
- `pytest tests/test_mfa_e2e.py -q`

---

## Test Specification

```python
# tests/test_mfa_review_fixes_vault.py — see the Implementation Blueprint for the scaffold.
# Required tests (spec §4):
#   test_mfa_secret_target_context_matches_seed   (unit, M7)
#   test_mfa_target_factory_requires_pool         (unit, AC9)
#   test_vault_target_entry_point_declared        (unit, AC9)
#   test_mfa_secrets_migration_moves_rows         (live, AC8 incl. failure injection)
#   test_rotate_master_key_rotates_mfa_seeds      (live, AC7)
```

---

## Agent Instructions

When you pick up this task:

1. **Work in the existing feature worktree `.claude/worktrees/feat-FEAT-106-basicauth-otp-2fa`** (branch
   `feat-FEAT-106-basicauth-otp-2fa`, PR #633) — never on `dev`.
2. **Read the spec** at the path listed above for full context (§2 Data Models, §3 Module 7, §7 D3).
3. **Check dependencies** — TASK-172 must be `"done"` in `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json`.
4. **Verify the Codebase Contract** — re-run every `grep -c` in the blueprint; if anything changed, update the contract FIRST.
5. **Update status** in `sdd/tasks/index/basicauth-otp-2fa-review-fixes.json` → `"in-progress"` (set `started_at`) and commit only that index file.
6. **Implement** — start from the Implementation Blueprint blocks, complete every `# FILL IN:` marker, and never change a signature or path the blueprint fixes.
7. **Verify** all acceptance criteria — run the Validation Commands (this task is exclusive: nothing else runs DDL meanwhile).
8. **Commit the code** — stage only the files this task lists (never `git add .` / `-A`).
9. **Close the task** with `parrot sdd task close TASK-174 basicauth-otp-2fa-review-fixes verified`.
10. **Fill in the Completion Note** below, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: `key_version INTEGER` (spec §2 says SMALLINT) and target-less `ON CONFLICT DO NOTHING` in the move — both decided at task time, see Key Constraints.
