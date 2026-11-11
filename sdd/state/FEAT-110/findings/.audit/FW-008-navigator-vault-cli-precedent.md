---
id: FW-008
query_id: Q007
type: wiki_page
intent: "Learn how the existing navigator-vault CLI was specified (precedent for a new command)."
executed_at: 2026-11-11T13:50:00Z
duration_ms: 0
parent_id: null
depth: 0
---

# FW-008 — navigator-vault CLI precedent lives in navigator-session, not in this repo

## Summary

TASK-076 specified and delivered the `navigator-vault` CLI, but in the sibling repository `../navigator-session` (`navigator_session/vault/migrate/cli.py`, console script in that repo's `pyproject.toml`). It is a design precedent only: argparse-style subcommands, `main(argv, ...) -> int` with injectable factories for tests, `asyncio.run()` entry, explicit exit codes, DSN resolved from `--dsn` then an env var then navconfig `DBUSER/DBPWD/DBHOST/DBPORT/DBNAME`, and DSN never printed.

## Citations

- path: `sdd/tasks/completed/TASK-076-navigator-vault-cli.md`
  wiki_page_id: same
  excerpt: |
    **Repository**: `../navigator-session`
    - `navigator_session/vault/migrate/cli.py` + console script `navigator-vault` in `pyproject.toml`.
- path: `sdd/tasks/completed/TASK-076-navigator-vault-cli.md`
  excerpt: |
    - Resources: DSN from `--dsn` → `VAULT_DB_DSN` → navconfig `DBUSER/DBPWD/DBHOST/DBPORT/DBNAME`
      (asyncpg imported lazily, not a navigator-session dependency)
    - `pyproject.toml`: `[project.scripts] navigator-vault = "navigator_session.vault.migrate.cli:console_entry"`.
    - Exit codes: 0 ok, 1 restore aborted, 2 failed rows / verification failed / rotation errors,
      3 usage ... or configuration ..., 4 backup errors.

## Notes

The paths under `navigator_session/` are in another repository and must not be cited as files of navigator-auth. The `--dsn` → env → navconfig precedence is a ready-made pattern for supplying admin credentials to `navauth self upgrade`.
