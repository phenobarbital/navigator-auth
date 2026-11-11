# TASK-169: Migration docs, CHANGELOG, moved-path references and the identity example

**Feature**: FEAT-110 — navauth self upgrade database migration command
**Spec**: `sdd/specs/new-command-migration.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-165, TASK-167
**Assigned-to**: unassigned

---

## Context

Implements spec §3 **Module 7** (goal G8) and spec §10: the documented view of the
migrations, plus the release note for the operator-visible behaviour change
("startup no longer migrates"). It also updates the prose and examples that still
name the moved SQL paths or rely on boot-time migration (spec §7 "Docs and SQL
comments mention old paths … prose docs are updated in M7").

One code change belongs here because it is the example's documentation contract:
`examples/identity_vault_server.py` relied on startup migrations to add the identity
credential columns and the vault tables. Since TASK-166 startup only warns, the
example's bootstrap must apply them itself through `navigator_auth.migrations.upgrade`.

---

## Scope

- Create `docs/migrations/README.md` with four sections — *Running*, *Index*,
  *Adding a migration*, *Upgrading from ≤ 0.29* (contents below).
- Create `docs/migrations.rst` (includes the README with myst) and add `migrations` to
  the `docs/index.rst` toctree.
- Add a `# Unreleased` entry to `CHANGELOG.md`.
- Update path / behaviour mentions: `documentation/identity-vault.md:36`,
  `docs/vault.rst:45-48`, `documentation/mcp-connector.md:46-50`,
  `documentation/oauth.md:583,642`, `examples/README.md:69,121`,
  `examples/oauth2_mcp_server.py:43`, `examples/identity_vault_server.py:72,216` (docstrings).
- `examples/identity_vault_server.py::bootstrap_database`: after the example schema, run
  `upgrade(raw_conn, ["vault", "identity"], runtime_role=DBUSER)`.
- Create `tests/unit/migrations/test_docs_index.py` (`test_readme_index_lists_every_sql_file`).

**NOT in scope**: version bump (the release workflow does it — spec M7); `documentation/client_changes.md`
(TASK-167); MFA rows in the index (TASK-170 adds them with the MFA files); SQL file content (frozen).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `docs/migrations/README.md` | CREATE | Running / Index / Adding / Upgrading |
| `docs/migrations.rst` | CREATE | Sphinx page including the README |
| `docs/index.rst` | MODIFY | Toctree entry |
| `CHANGELOG.md` | MODIFY | `# Unreleased` entry |
| `documentation/identity-vault.md` | MODIFY | Moved path + "applied by navauth self upgrade" |
| `docs/vault.rst` | MODIFY | Moved paths + behaviour |
| `documentation/mcp-connector.md` | MODIFY | Replace `psql -f ddl.sql` with `navauth self upgrade --set oauth2` |
| `documentation/oauth.md` | MODIFY | Two `backends/oauth2/ddl.sql` mentions |
| `examples/README.md` | MODIFY | `ddl.sql` mention; startup-migration sentence |
| `examples/oauth2_mcp_server.py` | MODIFY | Docstring `ddl.sql` mention |
| `examples/identity_vault_server.py` | MODIFY | Bootstrap runs `upgrade()`; docstrings |
| `examples/sql/identity_vault_schema.sql` | MODIFY | Comment-only: drop the moved `identity/sql/` path (acceptance grep covers `examples/`) |
| `tests/unit/migrations/test_docs_index.py` | CREATE | README index test |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `87c9b9c` (2026-11-11).

### Verified Imports
```python
from navigator_auth.migrations.catalog import discover          # TASK-159
from navigator_auth.migrations.runner import upgrade             # TASK-163 (example only)
from navigator_auth.conf import DBUSER                           # navigator_auth/conf.py:39 (example only)
from pathlib import Path                                         # stdlib (test)
```

### Existing Signatures to Use
```text
docs/index.rst:40            "   token_exchange"       (occurrences: 1) — toctree; add "   migrations" below it
docs/index.rst:30-31         ".. include:: ../README.md" + "   :parser: myst_parser.sphinx_"  ← include style to copy
CHANGELOG.md:1               "# Unreleased"            (occurrences: 1) — entries are "- **Title (FEAT-NNN…).** text" bullets
documentation/identity-vault.md:35-36  "…by an idempotent\nstartup migration (`navigator_auth/identity/sql/001_identity_credentials.sql`):"
docs/vault.rst:42-48         "Schema migrations" section listing vault/sql/002 and identity/sql/003; "Both are applied automatically at startup and are safe to re-run."
documentation/mcp-connector.md:46-50  "Apply the DDL once:" + ```bash psql "$AUTH_DB_DSN" -f navigator_auth/backends/oauth2/ddl.sql```
documentation/oauth.md:583, :642      "Run `backends/oauth2/ddl.sql`." / "— see `backends/oauth2/ddl.sql`."  (occurrences: 2)
examples/README.md:69        "production default is `postgres` (see `navigator_auth/backends/oauth2/ddl.sql`)."
examples/README.md:120-121   "The credential columns and the Session Vault\n  tables are added by the library's own idempotent startup migrations."
examples/oauth2_mcp_server.py:42-43   "A real deployment drops this and\n  applies ``navigator_auth/backends/oauth2/ddl.sql``."
examples/identity_vault_server.py:71-72  "…The credential\n  columns and the Session Vault tables are added by the library's own\n  startup migrations."
examples/identity_vault_server.py:144-151  from navigator_auth.conf import (... default_dsn,)  — add DBUSER here
examples/identity_vault_server.py:212-245  async def bootstrap_database() — `db = AsyncDB("pg", dsn=default_dsn)`;
                                           `async with await db.connection() as conn:` (line 223, occurrences: 1);
                                           conn is an asyncdb `pg` connection → `conn.get_connection()` is the raw asyncpg one
```

CLI facts to document (TASK-165): flags `--check`, `--dsn`, `--user`, `--set NAME` (repeatable),
`--runtime-role` (default `DBUSER`), `--reapply-changed`, `--fail-fast`, `-v`; exit codes
`0/1/2/3`; DSN precedence `--dsn` → `AUTH_ADMIN_DSN` → `--user`/`AUTH_ADMIN_USER` + `AUTH_ADMIN_PWD`
(or prompt) → `default_dsn` with a notice. Grant scope (TASK-162): see spec "Runtime access contract".
Ledger: `<AUTH_DB_SCHEMA>.schema_migrations`, `GRANT SELECT … TO PUBLIC`.

Catalog files to index (after TASK-159/167): vault `001_create_vault_tables.sql`,
`002_vault_crypto_hardening.sql`; identity `001_identity_credentials.sql`, `002_identity_id_token.sql`,
`003_identity_key_version_integer.sql`, `004_identity_base_columns.sql`,
`005_identity_legacy_uid_default.sql`, `006_identity_drop_legacy_uid.sql`; passkey
`001_passkey_credentials.sql`; oauth2 `001_oauth2_schema.sql`. Take each row's feature id from the
file's header comment or `git log --follow -- <file>`; never guess one (write "—" when neither names it).

### Does NOT Exist
- ~~`docs/migrations/`~~ — this task creates it; `docs/` is a Sphinx tree (myst_parser for Markdown).
- ~~`wiki/`~~ — no techwiki in this repo (`sdd/config.json` `techwiki: null`).
- ~~A version bump in `navigator_auth/version.py`~~ — not this feature (spec M7).

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "docs/migrations/README.md", "action": "CREATE"},
    {"path": "docs/migrations.rst", "action": "CREATE"},
    {"path": "docs/index.rst", "action": "MODIFY"},
    {"path": "CHANGELOG.md", "action": "MODIFY"},
    {"path": "documentation/identity-vault.md", "action": "MODIFY"},
    {"path": "docs/vault.rst", "action": "MODIFY"},
    {"path": "documentation/mcp-connector.md", "action": "MODIFY"},
    {"path": "documentation/oauth.md", "action": "MODIFY"},
    {"path": "examples/README.md", "action": "MODIFY"},
    {"path": "examples/oauth2_mcp_server.py", "action": "MODIFY"},
    {"path": "examples/identity_vault_server.py", "action": "MODIFY"},
    {"path": "examples/sql/identity_vault_schema.sql", "action": "MODIFY"},
    {"path": "tests/unit/migrations/test_docs_index.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/migrations/catalog.py#discover",
    "sym:navigator_auth/migrations/runner.py#upgrade"
  ]
}
```

---

## Implementation Notes

### README structure (spec M7)
1. **Running** — `navauth self upgrade`, `--check` (CI: exit 1 means pending/changed/missing access),
   credentials and their precedence (never put the password on the command line; DSN/password are never
   printed), runtime role and the exact grant scope, the requirement that the admin principal can grant
   those privileges (no default privileges assumed), exit codes, repairing blocked postconditions
   (identity `006` blockers: missing `identity_id`, dependent views, duplicates; OAuth2: NULL
   `client`/`client_name`) and that an ordinary re-run retries.
2. **Index** — one table row per SQL file: set, file, feature, what it changes.
3. **Adding a migration** — `NNN_description.sql` in the set directory (no registration), idempotent
   rules (`IF NOT EXISTS`, `DO` blocks guarded on `to_regclass`/catalog lookups — model
   `identity/004_identity_base_columns.sql`), `{schema}`/`{users_table}` placeholders, a conditional
   early return must come with a postcondition in `navigator_auth/migrations/checks.py`, new application
   tables must extend `navigator_auth/migrations/access.py::RUNTIME_TABLES`, no `BEGIN/COMMIT`, no
   `CREATE INDEX CONCURRENTLY` (each file runs in one transaction), add the index row.
4. **Upgrading from ≤ 0.29** — startup no longer migrates (one warning until you run the command);
   the first run on an existing database re-runs the idempotent files and records them; the OAuth2
   patch is now managed (no seed data; NULL names must be repaired).

### CHANGELOG entry (spec M7)
A `- **Behaviour change — …(FEAT-110).**` bullet at the top of `# Unreleased`: the `navauth self upgrade`
command, startup no longer applies DDL (warns instead; PasskeyAuth refuses to start without its tables),
`AUTH_ADMIN_DSN`/`AUTH_ADMIN_USER`/`AUTH_ADMIN_PWD`, OAuth2 `ddl.sql` replaced by a managed migration
without seed data, and a link to `docs/migrations/README.md`.

---

## Implementation Blueprint

### Steps (in order)
1. Write `docs/migrations/README.md`, reading each SQL header for the Index — *why*: the test enforces the index.
2. `docs/migrations.rst` + toctree line — *why*: Sphinx only builds pages in a toctree.
3. CHANGELOG entry.
4. The path/behaviour edits listed in Scope.
5. The example bootstrap change.
6. `test_docs_index.py`; run the Validation Commands.

### `docs/migrations.rst` (CREATE)
```rst
Database migrations
===================

.. include:: migrations/README.md
   :parser: myst_parser.sphinx_
```

### `docs/index.rst` (MODIFY)
```rst
.. occurrences: 1 (verified: grep -c '   token_exchange' docs/index.rst)
.. AFTER — insert below `   token_exchange` (verified: docs/index.rst:40)
   migrations
```

### `examples/identity_vault_server.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'from navigator_auth.conf import (  # noqa: E402' examples/identity_vault_server.py)
# MODIFY the import block at lines 144-151: add `DBUSER,` (alphabetical: before `default_dsn`).
# AFTER the conf import block add:
from navigator_auth.migrations import upgrade  # noqa: E402

# occurrences: 1 (verified: grep -c 'async with await db.connection() as conn:' examples/identity_vault_server.py)
# INSIDE `async with await db.connection() as conn:` (verified: examples/identity_vault_server.py:223),
# right after `await conn.execute(SCHEMA_FILE.read_text())` (line 224), add:
        # Startup no longer migrates (FEAT-110): apply the identity and vault sets here, on the raw
        # asyncpg connection, exactly as `navauth self upgrade --set vault --set identity` would.
        report = await upgrade(conn.get_connection(), ["vault", "identity"], runtime_role=DBUSER)
        # FILL IN: when report.failed or report.access_errors, raise RuntimeError naming the failed files
        #   (the example must not start half-migrated).
```
Update the two docstrings (lines 71-72 and 215-217) to say the example applies the library
migrations itself through `navigator_auth.migrations.upgrade`.

### `tests/unit/migrations/test_docs_index.py` (CREATE)
```python
"""The migrations README indexes every catalog file (FEAT-110, spec M7)."""
from pathlib import Path

from navigator_auth.migrations.catalog import discover

README = Path(__file__).resolve().parents[3] / "docs" / "migrations" / "README.md"


def test_readme_index_lists_every_sql_file():
    """Every discover() filename appears in docs/migrations/README.md."""
    text = README.read_text(encoding="utf-8")
    missing = [f"{f.migration_set}/{f.filename}" for f in discover() if f.filename not in text]
    assert not missing, f"docs/migrations/README.md does not index: {missing}"


def test_docs_wire_the_page_and_changelog():
    """docs/index.rst toctree lists `migrations`; CHANGELOG `# Unreleased` mentions `navauth self upgrade`."""
    # FILL IN
```

### FILL IN checklist
- [ ] README — four sections, index row per file
- [ ] CHANGELOG bullet
- [ ] eight path/behaviour edits
- [ ] example bootstrap failure handling
- [ ] `test_docs_wire_the_page_and_changelog`

---

## Acceptance Criteria

- [ ] `docs/migrations/README.md` lists every SQL file; `test_readme_index_lists_every_sql_file` enforces it.
- [ ] `docs/migrations.rst` is in the `docs/index.rst` toctree.
- [ ] `CHANGELOG.md` documents the command and the startup behaviour change under `# Unreleased`.
- [ ] `grep -rn "backends/oauth2/ddl.sql\|identity/sql/\|vault/sql/\|passkey/sql/" docs documentation examples README.md` finds nothing.
- [ ] The identity example applies the vault and identity sets itself before the app starts.

---

## Validation Commands

- `pytest tests/unit/migrations/test_docs_index.py -q`

---

## Test Specification

See the blueprint's `test_docs_index.py`.

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
9. **Close the task** with `parrot sdd task close TASK-169 new-command-migration verified`
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
