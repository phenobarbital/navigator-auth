---
id: FEAT-110
title: "`navauth self upgrade` — CLI command that applies navigator-auth SQL migrations"
slug: new-command-migration
type: feature
mode: enrichment
status: review
source:
  kind: inline
  jira_key: null
  jira_url: null
  fetched_at: 2026-11-11
  summary_oneline: "New 'navauth self upgrade' CLI command that applies SQL migrations from docs/migrations/ to navigator-auth tables"
overall_confidence: medium
base_branch: dev
projects: []
tags: [migrations, cli, database-schema, navauth, identity]
research_state: sdd/state/FEAT-110/
created: 2026-11-11
updated: 2026-11-11
---

# FEAT-110 — `navauth self upgrade`: CLI command for database migrations

> **Mode**: enrichment
> **Confidence**: medium
> **Source**: `inline`
> **Audit**: [`sdd/state/FEAT-110/`](../state/FEAT-110/)

---

## 0. Origin

The original request, preserved verbatim. The full source is at
`sdd/state/FEAT-110/source.md`.

> **New command for database migrations**
>
> Any time a new column need to be added into navigator-auth tables (users,
> identities, etc) a migration SQL patch need to be created and executed
> manually, instead, using a new admin-based credentials, a CLI command can be
> used for running migrations, a simple "navauth self upgrade", will be used to
> check the existing migrations and compare with existing tables and applying
> the required changes, for example current auth.user_identities table is lack
> some new changes on my local, instead trying to find which changes I need to
> apply, create a docs/migrations/ folder with SQL-based changes, and run the
> changes over the tables using "navauth self upgrade" command.

**Initial signals** (extracted, not interpreted):
- Verbs: "create", "run", "check", "compare", "apply" → additive, feature-shaped
- Named entities: `navauth self upgrade`, `docs/migrations/`, `auth.user_identities`, users, identities, "admin-based credentials"
- Components / labels: none (inline source)
- Acceptance criteria provided: no

---

## 1. Synthesis Summary

The request is for a `navauth self upgrade` command that brings a database's
navigator-auth tables up to date using admin credentials, with the SQL changes
kept in a documented migrations folder. Research shows the premise is only
partly true: vault and identity migrations already run automatically on every
app boot from `auth_startup` in `navigator_auth/auth.py`, but they use the
runtime DB user and only log failures, so a database can fall behind silently;
only the `auth.clients` patch in `navigator_auth/backends/oauth2/ddl.sql` is
applied by hand. The package has three copy-pasted runners
(`navigator_auth/identity/migrations.py`, `navigator_auth/vault/migrations.py`,
`navigator_auth/passkey/migrations.py`), no CLI, no admin credential setting in
`navigator_auth/conf.py`, and no record of what was applied. The proposal is
one central runner with a ledger table, exposed through a new `navauth` console
script, with the existing `ensure_*` functions kept as shims and startup reduced
to a check-and-warn. The four design forks were answered by the user (§5), so
the next step is `/sdd-spec`.

---

## 2. Codebase Findings

> All entries in this section are grounded in the research findings persisted
> at `sdd/state/FEAT-110/findings/`. Each cites the finding ID(s) that justify
> its inclusion. **No fabricated paths or symbols.**

### 2.1 Localization

| # | Path | Symbol | Lines | Role | Evidence |
|---|------|--------|-------|------|----------|
| 1 | `navigator_auth/identity/migrations.py` | `ensure_identity_columns` | 52-94 | identity runner: applies 001–006 to `auth.user_identities`, collects failures, raises once | F003, F013 |
| 2 | `navigator_auth/identity/migrations.py` | `_MIGRATION_FILES` | 18-31 | hand-maintained ordered registry; a file not listed is inert | F003, F013 |
| 3 | `navigator_auth/identity/migrations.py` | `_run_sql` | 34-49 | per-file executor, duplicated verbatim in all three runners; ignores the result of `conn.execute()` | F003, F004, F019 |
| 4 | `navigator_auth/identity/migrations.py` | `setup_identity_columns` | 97-107 | log-only startup wrapper | F003, F013 |
| 5 | `navigator_auth/vault/migrations.py` | `ensure_vault_tables` | 45-57 | vault runner: 2 files, stops at first failure, no schema templating | F004, F014 |
| 6 | `navigator_auth/passkey/migrations.py` | `render_sql` | 11-22 | only runner that substitutes `{schema}` / `{users_table}` | F005 |
| 7 | `navigator_auth/passkey/migrations.py` | `ensure_passkey_tables` | 43-52 | passkey runner, executed only when the backend is enabled | F005, F014 |
| 8 | `navigator_auth/auth.py` | `auth_startup` | 178-192 | startup hook that runs vault + identity migrations on `app["authdb"]` | F002 |
| 9 | `navigator_auth/vault/integration.py` | `setup_vault_tables` | 102-113 | log-only startup wrapper for the vault runner | F002 |
| 10 | `navigator_auth/backends/passkey.py` | `on_startup` | 103-106 | passkey startup hook; raises `ConfigError` on failure | F002, F005 |
| 11 | `navigator_auth/conf.py` | `default_dsn` | 39-45 | the single runtime credential set (`DBUSER`/`DBPWD`/…) | F007 |
| 12 | `navigator_auth/conf.py` | `AUTH_DB_SCHEMA` | 33-36 | configurable schema / table names | F007, F005 |
| 13 | `navigator_auth/backends/oauth2/ddl.sql` | (auth.clients patch) | 7-33 | hand-applied patch that no code loads | F008, F001 |
| 14 | `pyproject.toml` | `[tool.setuptools.packages.find]` | 79-89 | packaging scope; where the first `[project.scripts]` entry goes | F012, F015, F006 |
| 15 | `tests/unit/identity/test_identity_migrations.py` | `TestEnsureIdentityColumns` | 156-217 | existing runner tests (mocked pool, SQL-text assertions) | F010 |
| 16 | `sdd/tasks/active/TASK-130-mfa-migrations.md` | — | — | pending FEAT-106 task adding a fourth (MFA) runner | F019, F016 |

SQL inventory (F001): identity `001`–`006` under `navigator_auth/identity/sql/`,
vault `001`–`002` under `navigator_auth/vault/sql/`, passkey `001` under
`navigator_auth/passkey/sql/`. `docs/migrations/` does not exist; `docs/` is a
Sphinx tree (F011).

### 2.2 Constraints Discovered

- **`execute()` never raises.** asyncdb's `conn.execute()` returns
  `[None, <error>]` instead of raising, and every `_run_sql` copy ignores that
  value.
  *Implication*: the command must execute fail-closed (inspect the result or
  use a raising call) and confirm the outcome with a catalog probe; otherwise
  "applied" is unreliable.
  *Evidence*: F019, F003

- **Idempotent SQL is the house style.** Every existing file uses
  `IF NOT EXISTS` and `DO` blocks guarded on `to_regclass` / catalog lookups,
  and is designed to be re-run.
  *Implication*: new files keep that style; the ledger adds reporting, not
  correctness.
  *Evidence*: F009, F003

- **Only `navigator_auth*` is packaged.** A repo-root `docs/` folder is outside
  the wheel.
  *Implication*: SQL must live inside the package for an installed `navauth`
  to find it.
  *Evidence*: F012, F011

- **Two SQL conventions coexist.** Identity and vault hard-code `auth.`;
  passkey (and the planned MFA file) use `{schema}` / `{users_table}` rendered
  by `render_sql`.
  *Implication*: the central runner needs one rendering rule that leaves
  hard-coded files untouched.
  *Evidence*: F005, F009, F019

- **Tests depend on the current module layout.** Existing tests import
  `SQL_DIR` and the file tuples from the three runner modules.
  *Implication*: moving SQL or removing `ensure_identity_columns` /
  `ensure_vault_tables` / `ensure_passkey_tables` breaks tests unless shims
  (or updated tests) come with it.
  *Evidence*: F010, F012

- **One credential set.** `navigator_auth/conf.py` exposes only `default_dsn`.
  *Implication*: admin credentials need a new input; the DSN must never be
  printed.
  *Evidence*: F007

- **Base tables are not ours.** The base `auth` schema is created by the
  Navigator platform, not by this library.
  *Implication*: the command applies additive changes to an existing schema; it
  does not bootstrap a database.
  *Evidence*: F002, F008

- **FEAT-106 overlap.** TASK-130 (pending) will add an MFA runner in the
  per-subsystem style.
  *Implication*: the two features must agree on where MFA SQL lives and who
  runs it.
  *Evidence*: F019

- **First CLI.** No console script, argparse, click or typer usage exists in
  the package or its git history.
  *Implication*: the `navigator-vault` design in TASK-076 (another repository)
  is the only precedent.
  *Evidence*: F006, F015, F017

### 2.3 Recent History (Relevant)

| Commit | When | Author | Message | Touched files |
|--------|------|--------|---------|---------------|
| `569383d` | 2026-10-23 | Jesus Lara | fix(identity): isolate migration failures so later files still run | `navigator_auth/identity/migrations.py`, `tests/unit/identity/test_identity_migrations.py` |
| `95d98e0` | 2026-10-23 | Jesus Lara | fix(identity): run 006 at startup so legacy uid is actually dropped | `navigator_auth/identity/migrations.py` |
| `64d18bd` | 2026-10-23 | Jesus Lara | fix(identity): drop the legacy uid column from auth.user_identities | `navigator_auth/identity/sql/005_…`, `006_…` |
| `ccce461` | 2026-10-23 | Jesus Lara | fix(identity): migration 005 so the legacy uid column cannot block the vault write | `navigator_auth/identity/migrations.py`, `005_…` |
| `81b6663` | 2026-10-23 | Jesus Lara | feat(external-provider-token-capture): TASK-102 — identity base columns migration 004 | `navigator_auth/identity/migrations.py`, `004_…` |
| `75b4475` | 2026-10-02 | Jesus Lara | feat(passkey-support-backend): TASK-87 — Passkey types and migration | `navigator_auth/passkey/migrations.py`, `001_passkey_credentials.sql` |
| `d9906ac` | 2026-09-16 | Jesus Lara | feat(vault-crypto-hardening): TASK-078 — … audit migration | vault `002_…`, identity `003_…`, both runners |
| `b2c7c32` | 2026-09-04 | Jesus Lara | feat(external-token-exchange): TASK-047 — Vault id_token column | `navigator_auth/identity/migrations.py`, `002_…` |

Identity migrations grew from 002 to 006 in under two months, and each new file
needed a manual edit of `_MIGRATION_FILES`; `95d98e0` exists because 006 was
added but not registered (F013). No commit ever added `[project.scripts]` or
`console_scripts` (F015).

---

## 3. Probable Scope

### What's New

- **`navauth` console script** — first `[project.scripts]` entry, with a
  `self upgrade` subcommand; `main(argv) -> int`, `asyncio.run()` entry,
  explicit exit codes.
- **`self upgrade --check`** (dry run) — lists applied and pending migrations
  without changing the database.
- **Central migration runner** — discovers ordered SQL files, renders
  `{schema}` / `{users_table}`, executes fail-closed, reports per-file status.
- **In-package migrations folder** (e.g. `navigator_auth/migrations/`) holding
  the SQL so it ships with the wheel. *(U1)*
- **`docs/migrations/`** — README and index of changes: what each migration
  does and how to add one. *(U1)*
- **Ledger table** recording each applied file with checksum and timestamp;
  files stay idempotent as a safety net. *(U2)*
- **Admin-credential input** for DDL, separate from the runtime `DBUSER`;
  default assumption is `--dsn` → environment variable → navconfig, following
  the `navigator-vault` precedent (F018). Exact names are left to the spec.
- **Migration for the `auth.clients` patch**, converting the manual file into a
  managed one. *(U4)*

### What Changes

- **`pyproject.toml`** — add `[project.scripts] navauth = …`; make sure SQL
  files ship as package data.  *Evidence*: F012, F015
- **`navigator_auth/identity/migrations.py`::`ensure_identity_columns`** —
  delegates to the central runner; `_MIGRATION_FILES` replaced by discovery.
  *Evidence*: F003, F013
- **`navigator_auth/vault/migrations.py`::`ensure_vault_tables`** — delegates
  to the central runner.  *Evidence*: F004
- **`navigator_auth/passkey/migrations.py`::`ensure_passkey_tables`** —
  delegates; `render_sql` becomes the shared rendering rule.  *Evidence*: F005
- **`navigator_auth/auth.py`::`auth_startup`** — stops running DDL; detects
  pending migrations and logs a warning pointing to `navauth self upgrade`.
  *(U3)*  *Evidence*: F002
- **`navigator_auth/backends/passkey.py`::`on_startup`** — same check-and-warn
  treatment for the passkey set (to be confirmed in the spec, since today it
  raises `ConfigError`).  *Evidence*: F002, F005
- **`navigator_auth/backends/oauth2/ddl.sql`** — retired as a loose patch once
  its content is a numbered migration.  *Evidence*: F008
- **`navigator_auth/conf.py`** — optional admin DSN / credential settings.
  *Evidence*: F007

### What's Untouched (Non-Goals)

- Creating the base `auth` schema and tables (owned by the Navigator platform).
- Data migrations and vault key rotation (the `navigator-vault` CLI in
  navigator-session).
- Down / rollback migrations.
- The content of already-released SQL files (identity 001–006, vault 001–002,
  passkey 001).
- Databases other than PostgreSQL.

### Patterns to Follow

- Idempotent SQL: header comment with the FEAT id, `ADD COLUMN IF NOT EXISTS`,
  `DO` blocks guarded on `to_regclass` / catalog lookups.  *Evidence*: F009
- Collect failures, keep running later files, raise once naming every failed
  file.  *Evidence*: F003, F013
- CLI shape from `navigator-vault`: DSN precedence, injectable factories for
  tests, explicit exit codes, DSN never printed.  *Evidence*: F018
- Fail-closed execution confirmed with a `to_regclass` / `fetchval` probe, as
  TASK-130 specifies for MFA.  *Evidence*: F019
- Runner tests with a mocked pool plus SQL-text assertions.  *Evidence*: F010

### Integration Risks

- **Silent success**: `execute()` swallows errors, so the command could report
  "upgraded" on a failed file. Mitigation: inspect the result or use a raising
  call, and verify with catalog probes.  *Evidence*: F019, F003
- **Startup no longer migrates**: deployments that rely on boot-time migration
  will stay behind until someone runs the command. Mitigation: loud warning at
  startup, release note, and `--check` usable in CI/deploy scripts.
  *Evidence*: F002, F013
- **Ledger bootstrap on existing databases**: databases already migrated by
  startup have no ledger rows. Mitigation: first run re-applies the idempotent
  files and records them (the reason files stay idempotent).  *Evidence*: F009
- **Collision with FEAT-106 TASK-130**, which adds a fourth per-subsystem
  runner. Mitigation: sequence the features, or have TASK-130 target the
  central runner.  *Evidence*: F019
- **Optional-feature tables**: applying passkey (and later MFA) tables to
  databases that do not use those backends. Accepted by U4; the spec should
  state it explicitly.  *Evidence*: F005
- **`006` removes a legacy column**: with elevated credentials on an unexpected
  schema this is destructive. Mitigation: keep its catalog guards untouched;
  `--check` first.  *Evidence*: F003, F013
- **`auth.clients` patch adds `NOT NULL` columns**: converting it to a managed
  migration may fail on tables with existing rows. Mitigation: review the patch
  content during the spec.  *Evidence*: F008

---

## 4. Confidence Map

| ID | Claim | Evidence | Confidence | Reasoning |
|----|-------|----------|------------|-----------|
| C1 | Three independent runners exist (identity 6 files, vault 2, passkey 1), each with its own `sql/` folder and a duplicated `_run_sql` | F001, F003, F004, F005 | high | Files read directly; citations probe-verified |
| C2 | Vault and identity migrations already run at every app startup through `auth_startup`, on the runtime pool, and failures are only logged | F002, F003 | high | Direct read of `navigator_auth/auth.py:178-192` and the wrappers. Contradicts the source's premise that every change is manual |
| C3 | The local `auth.user_identities` lag is most likely a startup migration that failed silently | F002, F013, F019 | low | Inferred from several findings; the local database was not inspected |
| C4 | No applied-migrations ledger table exists; correctness rests on idempotent SQL | F003, F009 | high | Negative grep plus runner comments |
| C5 | navigator-auth has no CLI and never had a console script | F006, F015, F017 | high | Negative grep plus pickaxe over full git history |
| C6 | There is no admin/DDL credential setting; only `DBUSER`/`DBPWD` via `default_dsn` | F007 | high | Direct read of `navigator_auth/conf.py:39-45` |
| C7 | `navigator_auth/backends/oauth2/ddl.sql` is a hand-applied patch referenced by no Python code | F008 | medium | Grep found no loader; a loader outside the searched paths is not fully excluded |
| C8 | A repo-root `docs/migrations/` would be missing from a pip-installed package | F012, F011 | medium | `packages.find` includes only `navigator_auth*`; no wheel was built to check package data |
| C9 | asyncdb `conn.execute()` never raises, so current runners can report success without applying anything | F019 | medium | Recorded as verified in TASK-130; not re-run in this research |
| C10 | A hand-maintained file registry already caused an inert migration (006) | F013 | high | Stated in commit `95d98e0` |
| C11 | The `navigator-vault` CLI (TASK-076) is a usable precedent for DSN resolution and exit codes | F018 | medium | Task document only; the sibling repository was not read |
| C12 | FEAT-106 TASK-130 will add a fourth runner in the per-subsystem style | F019, F016 | high | Active task document |
| C13 | A central runner plus thin `ensure_*` shims satisfies the request without rewriting released SQL | F003, F004, F005, F010 | medium | Design inference from the identical runner shapes; fixed by the answers in §5 |

Distribution: **7** high, **5** medium, **1** low.

> C3 is low but not load-bearing: the feature is justified by C2, C4, C5 and
> C10 regardless of why the local database lags.

---

## 5. Open Questions

### Resolved (during proposal phase)

- [x] **U1 — Where should the SQL files physically live, given that `docs/` is not packaged?** — *Resolved*: In package + docs index: SQL lives inside the package (e.g. `navigator_auth/migrations/`) so an installed `navauth` always finds it; `docs/migrations/` holds the README and index of changes.
  *Resolves claims*: C8, C13
- [x] **U2 — How should `self upgrade` decide what is pending?** — *Resolved*: Ledger + idempotent SQL: a small table records each applied file with checksum and timestamp; files stay idempotent as a safety net.
  *Resolves claims*: C4, C13
- [x] **U3 — What should app startup do once the command exists?** — *Resolved*: Check and warn only: startup no longer runs DDL; it detects pending migrations and logs a warning telling the operator to run `navauth self upgrade`.
  *Resolves claims*: C2, C13
- [x] **U4 — Which change sets does the first version cover?** — *Resolved*: Everything incl. `auth.clients`: identity, vault, passkey and the manual `auth.clients` patch converted to a migration; MFA joins when FEAT-106 lands.
  *Resolves claims*: C7, C12, C13

### Unresolved (defer to spec / implementation)

None blocking. Items for the spec to settle, none of which change the next
command:

- Exact names for the admin-credential inputs (flag, environment variable,
  optional settings).
- Ledger table name and schema, and how the runtime user reads it for the
  startup check.
- Whether in-package `*.sql` files currently ship as package data (build a
  wheel and look).
- Whether one folder with a single global numbering replaces the three
  per-subsystem numberings, or the folder keeps per-area subfolders.
- Ordering with FEAT-106 TASK-130.

---

## 6. Recommended Next Step

**`/sdd-spec FEAT-110`** — *Rationale*: localization is verified and the four
design forks were decided by the user, so there is a single architecture
(central runner + ledger + `navauth` CLI + startup check) to specify.

### Alternatives

- **`/sdd-brainstorm FEAT-110`** — if you want to compare against adopting an
  off-the-shelf migration tool instead of a home-grown runner.
- **`/sdd-task FEAT-110`** — not recommended; the change spans packaging, three
  runners, startup and a new CLI.
- **Manual review** — not needed; research was not truncated.

---

## 7. Research Audit

| Artifact | Path |
|----------|------|
| State checkpoints | `sdd/state/FEAT-110/state.json` |
| Source (raw) | `sdd/state/FEAT-110/source.md` |
| Research plan | `sdd/state/FEAT-110/research_plan.json` |
| Findings (digests) | `sdd/state/FEAT-110/findings/F001-*.md` … `F019-*.md` |
| Lane originals + merge/probe records | `sdd/state/FEAT-110/findings/.audit/` |
| Synthesis (JSON) | `sdd/state/FEAT-110/synthesis.json` |
| Synthesis reasoning | not persisted |

**Budget consumed** (profile `default`, three parallel lanes):
- Files read: 10 / 40
- Grep calls: 14 / 25
- Git calls: 7 / 10
- Wall time: 182s / 300s (slowest lane)
- Truncated: **no** (1 planned query skipped: no CLI module exists to read)

**Merge**: 26 lane findings → 19 canonical (7 merged).
**Citation probe**: 73 checks, all verified. Seven module-level names and one
import were reported `missing` by the probe's def/class pattern and confirmed
by a direct check.

**Mode determination**: `auto` → resolved to `enrichment` (additive verbs:
"new command", "create a docs/migrations/ folder").

---

## 8. Provenance

| Field | Value |
|-------|-------|
| Generated by | `/sdd-proposal v1.0` |
| Synthesis prompt | `sdd/templates/synthesis.prompt.md v1.0` |
| Plan prompt | `sdd/templates/research_plan.prompt.md v1.0` |
| Schema versions | state=1.0, synthesis=1.0, research_plan=1.0 |
| Operator | Jesus Lara / Claude Code |
