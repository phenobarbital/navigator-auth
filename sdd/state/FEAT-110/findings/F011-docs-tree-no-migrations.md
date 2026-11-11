---
id: F011
query_id: Q022
type: tree
intent: "Confirm docs/migrations/ does not exist yet and see what docs/ and documentation/ hold."
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: null
depth: 0
merged_from: [FC-012]
---

# F011 — docs/ is a Sphinx tree; docs/migrations/ does not exist

## Summary

`docs/` holds Sphinx sources (`conf.py`, `index.rst`, `vault.rst`, `passkey.rst`, `settings.rst`, …, plus `docs/sdd/CODEX.md`); `documentation/` holds markdown guides (`identity-vault.md`, `client_changes.md`, `audit-log.md`, `oauth.md`, …). There is no `docs/migrations/` folder.

## Citations

- path: `docs/conf.py`
- path: `docs/index.rst`
- path: `docs/settings.rst`
- path: `docs/vault.rst`
- path: `docs/sdd/CODEX.md`
- path: `documentation/identity-vault.md`
- path: `documentation/client_changes.md`

## Notes

See FC-013: `docs/` is outside the packaged tree, which matters for an installed `navauth` command.
