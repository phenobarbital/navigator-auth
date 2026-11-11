---
id: F012
query_id: Q015
type: read
intent: "Follow-up: is docs/ shipped in the wheel? (where can an installed CLI find SQL files)"
executed_at: 2026-11-11T13:46:09Z
duration_ms: 0
parent_id: FC-006
depth: 1
merged_from: [FC-013]
---

# F012 — Only navigator_auth* is packaged; docs/ would not ship with the wheel

## Summary

`pyproject.toml` packages only `navigator_auth*` (`[tool.setuptools.packages.find] include`), and `MANIFEST.in` lists top-level files plus `navigator_auth/rs_pep`. The existing runners locate SQL via `Path(__file__).parent / "sql"`, i.e. inside the package. A `docs/migrations/` folder at repo root would be absent from a pip-installed navigator-auth, so `navauth self upgrade` could only find it when run from a source checkout.

## Citations

- path: `pyproject.toml`
  lines: 79-89
  symbol: `[tool.setuptools.packages.find]`
  excerpt: |
    [tool.setuptools.packages.find]
    where = ["."]
    include = ["navigator_auth*"]
    [tool.setuptools.exclude-package-data]
- path: `MANIFEST.in`
  lines: 2-11
  symbol: (include rules)
  excerpt: |
    include LICENSE
    ...
    recursive-include navigator_auth/rs_pep *
- path: `navigator_auth/identity/migrations.py`
  lines: 18
  symbol: `SQL_DIR`
  excerpt: |
    SQL_DIR = Path(__file__).parent / "sql"

## Notes

Design fork for the proposal: SQL lives in `docs/migrations/` (as the source asks; needs packaging or checkout-only use) vs inside the package (e.g. `navigator_auth/migrations/`) with `docs/migrations/` as documentation/mirror. User-answerable unknown.
