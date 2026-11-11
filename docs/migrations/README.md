# Database migrations

navigator-auth ships its PostgreSQL DDL as an ordered catalog of idempotent SQL
files under `navigator_auth/migrations/sql/<set>/NNN_description.sql`. They are
applied by an explicit, operator-run command, never at application startup:

```bash
navauth self upgrade
```

## Running

```bash
navauth self upgrade                      # apply every pending file of every set
navauth self upgrade --set vault --set identity   # only some sets (repeatable)
navauth self upgrade --check              # change nothing; report applied/pending/changed
```

Flags: `--check`, `--dsn`, `--user`, `--set NAME` (repeatable), `--runtime-role`
(default `DBUSER`), `--reapply-changed`, `--fail-fast`, `-v`.

**Credentials.** The command needs an *admin* principal able to create tables and
to grant privileges. The DSN is resolved in this order:

1. `--dsn`
2. `AUTH_ADMIN_DSN`
3. `--user` / `AUTH_ADMIN_USER` plus `AUTH_ADMIN_PWD` (or an interactive prompt)
4. the application's `default_dsn`, with a notice

Never put the password on the command line. The DSN and password are never printed.

**Runtime role and grants.** After the files are applied the command grants the
application role (`--runtime-role`, default `DBUSER`) `SELECT, INSERT, UPDATE,
DELETE` on the tables each set owns and `USAGE, SELECT` on their sequences. No
default privileges are assumed, so the admin principal must itself be able to
grant these. The applied-migration ledger is `<AUTH_DB_SCHEMA>.schema_migrations`
(`GRANT SELECT ... TO PUBLIC`).

**`--check` in CI.** Exit code `1` means something is pending, changed, or the
runtime role lacks access.

**Exit codes.**

| Code | Meaning |
|---|---|
| `0` | everything applied / nothing pending |
| `1` | `--check` found pending, changed or missing-access items |
| `2` | at least one file failed, or a grant could not be applied |
| `3` | configuration or connection error (DSN, unknown role, bad set) |

**Repairing blocked postconditions.** Some files refuse to be recorded until the
data is in a state they can handle; fix the data and simply re-run (an ordinary
re-run retries failed files):

- identity `006`: rows missing `identity_id`, views that depend on the legacy
  `uid` column, or duplicate rows.
- OAuth2 `001`: rows with a NULL `client` or `client_name`.

A file whose checksum changed after being applied is skipped and reported; use
`--reapply-changed` to run it again.

## Index

| Set | File | Feature | What it changes |
|---|---|---|---|
| vault | `001_create_vault_tables.sql` | FEAT-001 | Session Vault tables (`user_vault_secrets`, `user_vault_audit`, `vault_key_registry`) |
| vault | `002_vault_crypto_hardening.sql` | FEAT-099 | Schema changes for the v2 envelope format |
| identity | `001_identity_credentials.sql` | — | Credential columns on `auth.user_identities` |
| identity | `002_identity_id_token.sql` | FEAT-096 | `id_token` column |
| identity | `003_identity_key_version_integer.sql` | FEAT-099 | `key_version` widened to `INTEGER` |
| identity | `004_identity_base_columns.sql` | FEAT-103 | Base columns required by the `UserIdentity` model |
| identity | `005_identity_legacy_uid_default.sql` | FEAT-103 | Legacy `uid` column made self-filling |
| identity | `006_identity_drop_legacy_uid.sql` | — | Drops the legacy `uid` column (guarded by postconditions) |
| passkey | `001_passkey_credentials.sql` | FEAT-101 | WebAuthn credential and handle tables |
| oauth2 | `001_oauth2_schema.sql` | FEAT-110 | OAuth2 clients, policies, tokens, grants, device codes, client access (FEAT-093/094/095), no seed data |

## Adding a migration

1. Create `NNN_description.sql` in the set directory under
   `navigator_auth/migrations/sql/<set>/`. The catalog discovers it; there is no
   registration step.
2. Make it idempotent: `IF NOT EXISTS`, and `DO` blocks guarded on `to_regclass`
   or catalog lookups. Model it on `identity/004_identity_base_columns.sql`.
3. Use the `{schema}` / `{users_table}` placeholders for templated objects.
4. Do not write `BEGIN` / `COMMIT`, and do not use `CREATE INDEX CONCURRENTLY`:
   each file runs in a single transaction.
5. A conditional early return must come with a postcondition in
   `navigator_auth/migrations/checks.py`, so a skipped file is never recorded as
   done.
6. New application tables must extend
   `navigator_auth/migrations/access.py::RUNTIME_TABLES` so the runtime role is
   granted access.
7. Add the row to the Index above (a test enforces it).

## Upgrading from <= 0.29

- Application startup no longer migrates. Until you run `navauth self upgrade`
  you get one warning at boot (and `PasskeyAuth` refuses to start without its
  tables).
- The first run on an existing database re-runs the idempotent files and
  records them in the ledger.
- The OAuth2 patch is now a managed migration with no seed data; rows with NULL
  `client` / `client_name` must be repaired before it can be recorded.
