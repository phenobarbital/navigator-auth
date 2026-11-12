---
id: F017
query_id: Q002
type: wiki_query
intent: "Orient: find any existing CLI / console-script entry point."
executed_at: 2026-11-11T13:42:30Z
duration_ms: 0
parent_id: null
depth: 0
merged_from: [FW-002]
---

# F017 — No CLI in navigator-auth surfaced by the wiki; only precedent is navigator-vault (other repo)

## Summary

The CLI query returns no navigator-auth module that is a command-line entry point. The only relevant hit is the task document for the `navigator-vault` CLI; the remaining hits are unrelated skill scripts and templates. The wiki therefore gives no evidence of an existing `navauth` command or console script in this package.

## Citations

- path: `sdd/tasks/completed/TASK-076-navigator-vault-cli.md`
  wiki_page_id: same (score 1.00)
- path: `.agent/workflows/run-python-command.md`
  wiki_page_id: same (score 0.14)
- path: `tests/unit/identity/test_identity_vault_v2.py`
  symbol: `TestIdentityTarget.test_entry_point_declared`
  wiki_page_id: `sym:tests/unit/identity/test_identity_vault_v2.py#TestIdentityTarget.test_entry_point_declared` (score 0.00)

## Notes

Absence in a lexical wiki query is weak evidence.
[cross-lane: type=grep, intent=confirm no `[project.scripts]` / console_scripts / argparse / click entry point exists in pyproject.toml, setup.py or navigator_auth/ (plan Q015)]
