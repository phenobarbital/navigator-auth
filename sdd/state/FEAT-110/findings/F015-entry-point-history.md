---
id: F015
query_id: Q025
type: git_log
intent: "History of pyproject.toml / setup.py entry points (when/if a CLI script was added)."
executed_at: 2026-11-11T13:45:10Z
duration_ms: 500
parent_id: null
depth: 0
merged_from: [FG-003]
---

# F015 — pyproject.toml / setup.py history: no CLI entry point was ever added

## Summary

15 commits (cap reached) touched `pyproject.toml` in the last 180 days; `setup.py` changed once (423da76, wheel builds). Themes are dependencies, version bumps, build/wheels and SDD tooling — none mention a console script. Pickaxe searches over full history, `git log -S'[project.scripts]' -- pyproject.toml` and `git log -S'console_scripts' -- setup.py pyproject.toml`, returned no commits: neither string has ever been added or removed. A `navauth` console script would be the first `[project.scripts]` entry in the package.

## Citations

- path: `pyproject.toml`
  commit: `46d9a58` — 2026-11-11 — Jesus Lara — "pyproject"
  files: `pyproject.toml`
- path: `pyproject.toml`
  commit: `7e72b96` — 2026-11-11 — Jesus Lara — "fixing sdd flow"
  files: `pyproject.toml` (plus sdd/ files, not listed)
- path: `setup.py`
  commit: `423da76` — 2026-11-05 — Jesus Lara — "build: produce Windows and macOS (Apple Silicon) wheels"
  files: `pyproject.toml`, `setup.py`
- path: `pyproject.toml`
  commit: `ecfebe0` — 2026-10-23 — Jesus Lara — "feat(external-provider-token-capture): TASK-110 — raise navigator-session floor to >=1.1.1"
- path: `pyproject.toml`
  commit: `1d6d5ed` — 2026-10-02 — Jesus Lara — "feat(passkey-support-backend): TASK-86 — Passkey settings and extra"
- path: `pyproject.toml`
  commit: `44f1de2` — 2026-09-16 — Jesus Lara — "feat(vault-crypto-hardening): TASK-085 — version 0.28.0, docs and verification evidence"
- path: `pyproject.toml`
  commit: `d7dbc8f` — 2026-09-16 — Jesus Lara — "feat(vault-crypto-hardening): TASK-077 — Identity Vault — context-bound IdentityCipher, store re-seal, identity target"
- path: `pyproject.toml`
  commits (deps/python-version only): `5df3e94` (2026-09-25), `7cd81e5`, `9f07c92`, `84faaf2`, `924a0e4`, `b5693c4` (2026-09-05), `411916c` (2026-06-26)
- path: `pyproject.toml`
  absent: `[project.scripts]` — pickaxe over full history returned 0 commits
- path: `setup.py`
  absent: `console_scripts` — pickaxe over full history returned 0 commits

## Notes

- Touched-file lists for these commits were filtered to drop sdd/, tests/, docs/ paths; only pyproject.toml / setup.py membership is asserted.
- The wiki surfaced a completed TASK-076 "`navigator-vault` CLI"; git shows it was not wired as a console script in pyproject.toml/setup.py.
- [cross-lane: type=grep, intent=find how the navigator-vault CLI from TASK-076 is actually invoked (python -m module, __main__.py, or a script file), since no [project.scripts]/console_scripts entry ever existed]
- pyproject.toml also has uncommitted local changes ([tool.parrot.worktree] block), unrelated to entry points.
