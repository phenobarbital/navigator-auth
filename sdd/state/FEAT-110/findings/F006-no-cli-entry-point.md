---
id: F006
query_id: Q015
type: grep
intent: "Locate existing CLI entry points and the arg-parsing library in use."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 0
merged_from: [FC-006]
---

# F006 — navigator-auth ships no CLI of its own

## Summary

No matches for `argparse|import click|typer|console_scripts|[project.scripts]|__main__` in `navigator_auth/`, `pyproject.toml` or `setup.py`. A follow-up grep for `navauth|navigator-vault|def main(|sys.argv` found only comments: the `navigator-vault` CLI belongs to the external `navigator_session` package, to which navigator-auth merely contributes an entry point. `navauth` would be the package's first console script and no arg-parsing library precedent exists in-repo.

## Citations

- path: `pyproject.toml`
  lines: 74-77
  symbol: `[project.entry-points."navigator_session.vault_targets"]`
  excerpt: |
    # Protected stores for navigator-session vault rotation / migration
    # (navigator-vault CLI). See navigator_session/vault/registry.py.
    [project.entry-points."navigator_session.vault_targets"]
    identity = "navigator_auth.identity.targets:factory"
- path: `navigator_auth/identity/targets.py`
  lines: 4
  symbol: (module docstring)
  excerpt: |
    ``navigator-vault`` rotation and v1 → v2 migration cover linked-identity tokens.

## Notes

Q016 (read the CLI module found by Q015) is therefore not executable — no such module exists. Skipped.
[cross-lane: type=wiki_page, intent=TASK-076 navigator-vault CLI — confirm it was implemented in navigator_session, not here, and which arg-parsing library it used]
