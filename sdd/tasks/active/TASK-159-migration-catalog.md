# TASK-159: Migration catalog and relocation of the released SQL files

**Feature**: FEAT-110 — navauth self upgrade database migration command
**Spec**: `sdd/specs/new-command-migration.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Implements spec §3 **Module 1** (Catalog + SQL relocation). This is the root of
the FEAT-110 task graph: every later task reads the new
`navigator_auth/migrations/` package or the relocated SQL files.

Today the nine released SQL files live in three per-subsystem `sql/`
directories and each runner keeps a hand-written file list. This task creates
the single catalog (`navigator_auth/migrations/sql/<set>/NNN_*.sql`, discovered
from the filesystem) and moves the files there with `git mv`, byte-identical.

To keep the tree green after the move, this task also repoints the `SQL_DIR`
constant of the three legacy modules at the new directories (one line each).
Everything else about those modules (file discovery, removing `_run_sql`,
fail-closed execution) is TASK-164.

The MFA set (`navigator_auth/mfa/sql/`) is **not** moved here: FEAT-106 is not
on `dev` yet, so that move is TASK-170. `"mfa"` is still listed in
`MIGRATION_SETS`; a missing set directory simply has no files.

---

## Scope

- Create the package `navigator_auth/migrations/` (`__init__.py`, `catalog.py`)
  with `SQL_ROOT`, `MIGRATION_SETS`, `FILENAME_PATTERN`, `MigrationCatalogError`,
  `MigrationFile`, `set_dir`, `set_filenames`, `discover`, `render_sql`.
- Move the nine released SQL files with `git mv` (content untouched):
  - `navigator_auth/vault/sql/*.sql` → `navigator_auth/migrations/sql/vault/`
  - `navigator_auth/identity/sql/*.sql` → `navigator_auth/migrations/sql/identity/`
  - `navigator_auth/passkey/sql/*.sql` → `navigator_auth/migrations/sql/passkey/`
- Repoint `SQL_DIR` in `navigator_auth/{identity,vault,passkey}/migrations.py`
  to `set_dir("<set>")` and drop their now-unused `from pathlib import Path`.
- Create `tests/unit/migrations/` (`__init__.py`, `conftest.py` with the
  `tmp_catalog` fixture, `test_catalog.py`).

**NOT in scope**: the runner and ledger (TASK-160/163), `_MIGRATION_FILES`
discovery and `_run_sql` removal in the legacy modules (TASK-164), the `oauth2`
set (TASK-167), the `mfa` set (TASK-170), docs (TASK-169). Do **not** edit the
content of any SQL file — the checksums below must still match after the move.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/migrations/__init__.py` | CREATE | Package; re-exports the catalog names |
| `navigator_auth/migrations/catalog.py` | CREATE | Catalog: discovery, ordering, rendering |
| `navigator_auth/migrations/sql/vault/001_create_vault_tables.sql` | CREATE | `git mv` from `navigator_auth/vault/sql/` |
| `navigator_auth/migrations/sql/vault/002_vault_crypto_hardening.sql` | CREATE | `git mv` from `navigator_auth/vault/sql/` |
| `navigator_auth/migrations/sql/identity/001_identity_credentials.sql` | CREATE | `git mv` from `navigator_auth/identity/sql/` |
| `navigator_auth/migrations/sql/identity/002_identity_id_token.sql` | CREATE | `git mv` from `navigator_auth/identity/sql/` |
| `navigator_auth/migrations/sql/identity/003_identity_key_version_integer.sql` | CREATE | `git mv` from `navigator_auth/identity/sql/` |
| `navigator_auth/migrations/sql/identity/004_identity_base_columns.sql` | CREATE | `git mv` from `navigator_auth/identity/sql/` |
| `navigator_auth/migrations/sql/identity/005_identity_legacy_uid_default.sql` | CREATE | `git mv` from `navigator_auth/identity/sql/` |
| `navigator_auth/migrations/sql/identity/006_identity_drop_legacy_uid.sql` | CREATE | `git mv` from `navigator_auth/identity/sql/` |
| `navigator_auth/migrations/sql/passkey/001_passkey_credentials.sql` | CREATE | `git mv` from `navigator_auth/passkey/sql/` |
| `navigator_auth/vault/sql/001_create_vault_tables.sql` | DELETE | source of the `git mv` |
| `navigator_auth/vault/sql/002_vault_crypto_hardening.sql` | DELETE | source of the `git mv` |
| `navigator_auth/identity/sql/001_identity_credentials.sql` | DELETE | source of the `git mv` |
| `navigator_auth/identity/sql/002_identity_id_token.sql` | DELETE | source of the `git mv` |
| `navigator_auth/identity/sql/003_identity_key_version_integer.sql` | DELETE | source of the `git mv` |
| `navigator_auth/identity/sql/004_identity_base_columns.sql` | DELETE | source of the `git mv` |
| `navigator_auth/identity/sql/005_identity_legacy_uid_default.sql` | DELETE | source of the `git mv` |
| `navigator_auth/identity/sql/006_identity_drop_legacy_uid.sql` | DELETE | source of the `git mv` |
| `navigator_auth/passkey/sql/001_passkey_credentials.sql` | DELETE | source of the `git mv` |
| `navigator_auth/identity/migrations.py` | MODIFY | `SQL_DIR = set_dir("identity")`; drop `Path` import |
| `navigator_auth/vault/migrations.py` | MODIFY | `SQL_DIR = set_dir("vault")`; drop `Path` import |
| `navigator_auth/passkey/migrations.py` | MODIFY | `SQL_DIR = set_dir("passkey")`; drop `Path` import |
| `tests/unit/migrations/__init__.py` | CREATE | Empty test package marker |
| `tests/unit/migrations/conftest.py` | CREATE | `tmp_catalog` fixture |
| `tests/unit/migrations/test_catalog.py` | CREATE | Catalog unit tests |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` @ `87c9b9c` (2026-11-11).

### Verified Imports
```python
from navigator_auth.conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE   # verified: navigator_auth/conf.py:33-34 (defaults "auth", "users")
from pydantic import BaseModel, ConfigDict                         # pydantic>=2.12.5 declared in pyproject.toml; 2.13.4 installed
import hashlib, re                                                 # stdlib
from pathlib import Path                                           # stdlib
from collections.abc import Iterable                               # stdlib
```

### Existing Signatures to Use
```python
# navigator_auth/identity/migrations.py
from pathlib import Path                                   # line 13 — only used by SQL_DIR
SQL_DIR = Path(__file__).parent / "sql"                    # line 18
_MIGRATION_FILES = (...)                                   # lines 24-31 — left alone here (TASK-164)

# navigator_auth/vault/migrations.py
from pathlib import Path                                   # line 13 — only used by SQL_DIR
SQL_DIR = Path(__file__).parent / "sql"                    # line 18
MIGRATION_FILES = (...)                                    # lines 21-24 — left alone here (TASK-164)

# navigator_auth/passkey/migrations.py
from pathlib import Path                                   # line 8 — only used by SQL_DIR
from ..conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE        # line 11 — still used by render_sql (keep)
SQL_DIR = Path(__file__).parent / "sql"                    # line 15
def render_sql(sql: str) -> str:                           # line 20 — same body as catalog.render_sql
```

Released files and their sha256 (raw bytes, `git show 87c9b9c:<path> | sha256sum`).
`test_released_files_are_byte_identical` hard-codes these values:

| Set | File | sha256 |
|---|---|---|
| vault | `001_create_vault_tables.sql` | `def230b640fbd385c7fadd42586bc0db9ba2f7e8256d22132b9baf7b4edb7c38` |
| vault | `002_vault_crypto_hardening.sql` | `7e0482573142e4fc9249079306bdecc29d2eff6f8ae2b61addaeee16a6002b18` |
| identity | `001_identity_credentials.sql` | `8f94156c97e195fb592c398f773f60764e1d9fd6dff2f645bbf4f383415d8dce` |
| identity | `002_identity_id_token.sql` | `12a6359ed7e518511c7071e289f73a4e54ac412cb02f3e48157771d76dea847c` |
| identity | `003_identity_key_version_integer.sql` | `4207ee7f2d25c61d71525664fb172a947d2d41a010fe6ee84ad21c2395a8bc0c` |
| identity | `004_identity_base_columns.sql` | `d83d2f0501c61fc48b31d98e87a0b6ccd2ffca0e1eefbfc2166f99c9499ec44b` |
| identity | `005_identity_legacy_uid_default.sql` | `e77db04d4756984f092f3438d7ceacc515cc5769744c2f7ad747cd36c9d29d25` |
| identity | `006_identity_drop_legacy_uid.sql` | `77d5293158802e84de00a854cc744eca30b503747dfd14b9cf9e46af0eb22a1f` |
| passkey | `001_passkey_credentials.sql` | `56ec735aed75c85101da1ef9e60ca3f227ce8a1a135f0c9a0a4e0ae8eef3c710` |

SQL conventions: identity and vault files hard-code `auth.` and contain no
placeholders; passkey uses `{schema}` / `{users_table}`. No file contains
`BEGIN`/`COMMIT`/`ROLLBACK` or `CONCURRENTLY`. The three old `sql/` directories
contain only these `.sql` files (no `__init__.py`, nothing else tracked).

Packaging: `[tool.setuptools.packages.find] include = ["navigator_auth*"]`
(`pyproject.toml:79-81`) and `graft navigator_auth` in `MANIFEST.in` ship data
files under a package directory, so `migrations/` needs an `__init__.py`; the
`sql/<set>/` directories must **not** get one.

Tests: `tests/unit/__init__.py` exists (test dirs are packages); async tests use
`@pytest.mark.asyncio` (no `asyncio_mode = auto`); `pyproject.toml:121`
`filterwarnings = ["error", …]`.

Existing tests that read `SQL_DIR` (must keep passing unchanged):
`tests/unit/identity/test_identity_migrations.py` (lines 42-132),
`tests/unit/vault/test_migrations.py` (lines 22-42, 149-154),
`tests/test_passkey_migrations.py` (lines 42-53).

### Does NOT Exist
- ~~`navigator_auth/migrations/`~~ — this task creates it.
- ~~`navigator_auth/mfa/`~~ — not on `dev` (FEAT-106 unmerged); do not create `sql/mfa/` here.
- ~~`navigator_auth/migrations/sql/oauth2/`~~ — TASK-167 creates it.
- ~~`schema_migrations`, `MigrationStatus`, `get_status`, `upgrade`~~ — TASK-160/163.
- ~~`tests/unit/migrations/`~~ — this task creates it; there is no `tests/unit/conftest.py`.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/migrations/__init__.py", "action": "CREATE"},
    {"path": "navigator_auth/migrations/catalog.py", "action": "CREATE"},
    {"path": "navigator_auth/migrations/sql/vault/001_create_vault_tables.sql", "action": "CREATE"},
    {"path": "navigator_auth/migrations/sql/vault/002_vault_crypto_hardening.sql", "action": "CREATE"},
    {"path": "navigator_auth/migrations/sql/identity/001_identity_credentials.sql", "action": "CREATE"},
    {"path": "navigator_auth/migrations/sql/identity/002_identity_id_token.sql", "action": "CREATE"},
    {"path": "navigator_auth/migrations/sql/identity/003_identity_key_version_integer.sql", "action": "CREATE"},
    {"path": "navigator_auth/migrations/sql/identity/004_identity_base_columns.sql", "action": "CREATE"},
    {"path": "navigator_auth/migrations/sql/identity/005_identity_legacy_uid_default.sql", "action": "CREATE"},
    {"path": "navigator_auth/migrations/sql/identity/006_identity_drop_legacy_uid.sql", "action": "CREATE"},
    {"path": "navigator_auth/migrations/sql/passkey/001_passkey_credentials.sql", "action": "CREATE"},
    {"path": "navigator_auth/identity/migrations.py", "action": "MODIFY"},
    {"path": "navigator_auth/vault/migrations.py", "action": "MODIFY"},
    {"path": "navigator_auth/passkey/migrations.py", "action": "MODIFY"},
    {"path": "tests/unit/migrations/__init__.py", "action": "CREATE"},
    {"path": "tests/unit/migrations/conftest.py", "action": "CREATE"},
    {"path": "tests/unit/migrations/test_catalog.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/passkey/migrations.py#render_sql"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- `set_dir()` must read the module-level `SQL_ROOT` **at call time** (no default
  argument binding) — because `tmp_catalog` monkeypatches `catalog.SQL_ROOT`.
- Checksums are over raw bytes (`path.read_bytes()`), never over decoded text —
  because the ledger compares them across machines (spec §7 "Line-ending /
  checksum stability").
- Module logger is not needed here; the catalog only raises.
- Google-style docstrings and full type hints (project rule).

### References in Codebase
- `navigator_auth/passkey/migrations.py:20-22` — `render_sql` body to copy.

---

## Implementation Blueprint

### Steps (in order)
1. Create `navigator_auth/migrations/sql/{vault,identity,passkey}/` and run
   `git mv` for each of the nine files — *why*: history follows the file and the
   content stays byte-identical.
2. Write `catalog.py` and `__init__.py` from the blocks below; fill `discover` —
   *why*: everything else in FEAT-110 reads files through it.
3. Repoint `SQL_DIR` in the three legacy modules and drop `from pathlib import Path`
   — *why*: their existing tests read `SQL_DIR / "<file>"` and must keep passing;
   the unused import would be a new ruff finding.
4. Write the test package, `conftest.py` and `test_catalog.py`; run the
   Validation Commands — *why*: the legacy tests prove the move broke nothing.
5. Confirm `git status` shows the nine files as renames (`R`), not delete+add
   with edits — *why*: AC "byte-identical".

### `navigator_auth/migrations/catalog.py` (CREATE)
```python
"""Migration catalog — which SQL files navigator-auth applies, and in what order (FEAT-110).

Every schema change lives in ``navigator_auth/migrations/sql/<set>/NNN_description.sql``.
Files are discovered from the filesystem: a correctly named file dropped into a set
directory is registered by being there.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from ..conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE

SQL_ROOT: Path = Path(__file__).parent / "sql"
MIGRATION_SETS: tuple[str, ...] = ("vault", "identity", "passkey", "mfa", "oauth2")
FILENAME_PATTERN: re.Pattern[str] = re.compile(r"^\d{3}_[a-z0-9_]+\.sql$")


class MigrationCatalogError(Exception):
    """The files on disk do not form a valid catalog."""


class MigrationFile(BaseModel):
    """One SQL migration file.

    Attributes:
        migration_set: Set name, one of ``MIGRATION_SETS``.
        filename: File name, e.g. ``004_identity_base_columns.sql``.
        path: Absolute path of the file.
        checksum: sha256 hex digest of the raw file bytes.
    """

    model_config = ConfigDict(frozen=True)

    migration_set: str
    filename: str
    path: Path
    checksum: str


def set_dir(migration_set: str) -> Path:
    """Return the directory of a migration set.

    Raises:
        MigrationCatalogError: when ``migration_set`` is not in ``MIGRATION_SETS``.
    """
    if migration_set not in MIGRATION_SETS:
        raise MigrationCatalogError(f"Unknown migration set: {migration_set!r}")
    return SQL_ROOT / migration_set


def set_filenames(migration_set: str) -> tuple[str, ...]:
    """Sorted filenames of one set; an empty tuple when the set directory does not exist."""
    return tuple(f.filename for f in discover([migration_set]))


def discover(sets: Iterable[str] | None = None) -> tuple[MigrationFile, ...]:
    """Return every migration file, ordered by ``MIGRATION_SETS`` then filename.

    Args:
        sets: Restrict to these set names; ``None`` means all sets.

    Raises:
        MigrationCatalogError: a requested set is unknown; a directory under
            ``SQL_ROOT`` is not in ``MIGRATION_SETS``; a ``.sql`` file does not
            match ``FILENAME_PATTERN``; two files in one set share the numeric prefix.
    """
    # FILL IN: validate `sets` (unknown name → MigrationCatalogError); keep MIGRATION_SETS order,
    #   not the caller's order — bounded by spec §2 "Sets are applied in a fixed order".
    # FILL IN: when SQL_ROOT exists, reject any sub-directory not in MIGRATION_SETS — ignore names
    #   starting with "." or "__" (e.g. __pycache__) — bounded by test_every_sql_dir_is_registered.
    # FILL IN: per selected set: skip a missing directory; list "*.sql" files sorted by name; reject a
    #   name not matching FILENAME_PATTERN and a repeated 3-digit prefix; ignore non-.sql files.
    # FILL IN: build MigrationFile(checksum=hashlib.sha256(path.read_bytes()).hexdigest()) — raw bytes.
    raise NotImplementedError


def render_sql(sql: str) -> str:
    """Replace ``{schema}`` and ``{users_table}``; other text is returned unchanged."""
    return sql.replace("{schema}", AUTH_DB_SCHEMA).replace("{users_table}", AUTH_USERS_TABLE)
```
**Why this shape**: signatures, constants and model fields are fixed by the spec's
M1 Interface Skeleton. `set_filenames` delegates to `discover` so the legacy shims
(TASK-164) get the same validation and ordering as the runner. `render_sql` is a
copy of the passkey one so TASK-164 can re-export it from there.

### `navigator_auth/migrations/__init__.py` (CREATE)
```python
"""navigator-auth database migrations (FEAT-110): catalog, runner and the ``navauth`` CLI."""
from .catalog import (
    MIGRATION_SETS,
    MigrationCatalogError,
    MigrationFile,
    discover,
    render_sql,
)

__all__ = [
    "MIGRATION_SETS",
    "MigrationCatalogError",
    "MigrationFile",
    "discover",
    "render_sql",
]
```
**Why**: TASK-160 and TASK-163 append `get_status` / `upgrade` and the status
models. Never import `cli` here — importing the package must stay cheap.

### `navigator_auth/identity/migrations.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'from pathlib import Path' navigator_auth/identity/migrations.py)
# REPLACE line 13 `from pathlib import Path` (verified: navigator_auth/identity/migrations.py:13) — delete it
# occurrences: 1 (verified: grep -c 'SQL_DIR = Path(__file__).parent / "sql"' navigator_auth/identity/migrations.py)
# REPLACE `SQL_DIR = Path(__file__).parent / "sql"` (verified: navigator_auth/identity/migrations.py:18) with:
from ..migrations.catalog import set_dir

SQL_DIR = set_dir("identity")
```
**Why**: put the import with the other imports (after `from typing import Any`,
line 14) and keep `SQL_DIR` as a module attribute — tests import it.

### `navigator_auth/vault/migrations.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'from pathlib import Path' navigator_auth/vault/migrations.py)
# REPLACE line 13 `from pathlib import Path` (verified: navigator_auth/vault/migrations.py:13) — delete it
# occurrences: 1 (verified: grep -c 'SQL_DIR = Path(__file__).parent / "sql"' navigator_auth/vault/migrations.py)
# REPLACE `SQL_DIR = Path(__file__).parent / "sql"` (verified: navigator_auth/vault/migrations.py:18) with:
from ..migrations.catalog import set_dir

SQL_DIR = set_dir("vault")
```
**Why**: same as identity; the import goes after `from typing import Any` (line 14).

### `navigator_auth/passkey/migrations.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c 'from pathlib import Path' navigator_auth/passkey/migrations.py)
# REPLACE line 8 `from pathlib import Path` (verified: navigator_auth/passkey/migrations.py:8) — delete it
# occurrences: 1 (verified: grep -c 'SQL_DIR = Path(__file__).parent / "sql"' navigator_auth/passkey/migrations.py)
# REPLACE `SQL_DIR = Path(__file__).parent / "sql"` (verified: navigator_auth/passkey/migrations.py:15) with:
from ..migrations.catalog import set_dir

SQL_DIR = set_dir("passkey")
```
**Why**: the import goes next to `from ..conf import AUTH_DB_SCHEMA, AUTH_USERS_TABLE`
(line 11), which stays — `render_sql` there still uses it until TASK-164.

### `tests/unit/migrations/conftest.py` (CREATE)
```python
"""Shared fixtures for the FEAT-110 migration tests."""
from pathlib import Path

import pytest

from navigator_auth.migrations import catalog


@pytest.fixture
def tmp_catalog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point ``catalog.SQL_ROOT`` at a temporary tree with two sets and three files.

    Layout: ``vault/001_first.sql``, ``vault/002_second.sql``, ``identity/001_third.sql``.
    """
    # FILL IN: create the three files with distinct small SQL bodies (one using {schema});
    #   monkeypatch.setattr(catalog, "SQL_ROOT", tmp_path); return tmp_path.
    raise NotImplementedError
```
**Why**: TASK-160 extends this file with `FakeConnection`; keep it to fixtures only.

### `tests/unit/migrations/__init__.py` (CREATE)
Empty file.

### FILL IN checklist
- [ ] `catalog.py::discover` — set validation, order, directory check, filename/prefix checks, checksum; bounded by spec M1 docstring and the five catalog tests
- [ ] `conftest.py::tmp_catalog` — three files under two registered sets
- [ ] `test_catalog.py` — the tests listed in Test Specification, with the nine hashes above

---

## Acceptance Criteria

- [ ] `navigator_auth/migrations/sql/{vault,identity,passkey}/` hold the nine files; `navigator_auth/identity/sql/`, `navigator_auth/vault/sql/` and `navigator_auth/passkey/sql/` no longer exist.
- [ ] The moved files are byte-identical (checksums above); `git log --follow` works on them.
- [ ] `discover()` returns vault 001-002, identity 001-006, passkey 001, in that order.
- [ ] A new `NNN_new.sql` in a set directory appears in `discover()` with no code change.
- [ ] `SQL_DIR` is still importable from the three legacy modules and the existing migration tests pass unchanged.
- [ ] `ruff check` reports nothing new on touched files.

---

## Validation Commands

- `pytest tests/unit/migrations/test_catalog.py -q`
- `pytest tests/unit/identity/test_identity_migrations.py -q`
- `pytest tests/unit/vault/test_migrations.py -q`
- `pytest tests/test_passkey_migrations.py -q`
- `pytest tests/test_identity_id_token.py -q`

---

## Test Specification

```python
# tests/unit/migrations/test_catalog.py
import pytest

from navigator_auth.migrations import catalog
from navigator_auth.migrations.catalog import (
    MIGRATION_SETS,
    MigrationCatalogError,
    discover,
    render_sql,
    set_dir,
    set_filenames,
)

RELEASED = {
    ("vault", "001_create_vault_tables.sql"): "def230b640fbd385c7fadd42586bc0db9ba2f7e8256d22132b9baf7b4edb7c38",
    # FILL IN: the other eight rows from the Codebase Contract table
}


def test_discover_orders_sets_then_files():
    """Real catalog: vault → identity → passkey (→ mfa → oauth2 when present), names ascending."""


def test_discover_orders_tmp_catalog(tmp_catalog):
    """vault/001, vault/002, identity/001 — set order wins over filesystem order."""


def test_every_sql_dir_is_registered():
    """Every directory under SQL_ROOT is in MIGRATION_SETS."""


def test_discover_rejects_bad_filename_and_duplicate_prefix(tmp_catalog):
    """MigrationCatalogError for `1_bad.sql`, for `001_x.sql` + `001_y.sql`, and for an unknown directory."""


def test_released_files_are_byte_identical():
    """discover() checksums equal RELEASED for all nine files."""


def test_render_sql_leaves_hardcoded_schema_untouched():
    """Every identity and vault file renders to itself."""


def test_new_file_is_discovered_without_code_change(tmp_catalog):
    """Writing identity/002_new.sql makes it appear in discover() and set_filenames()."""


def test_set_dir_rejects_unknown_set_and_missing_dir_is_empty(tmp_catalog):
    """set_dir('nope') raises; set_filenames('passkey') on the tmp tree is ()."""


def test_old_sql_dirs_are_gone():
    """navigator_auth/{identity,vault,passkey}/sql do not exist."""
```

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
9. **Close the task** with `parrot sdd task close TASK-159 new-command-migration verified`
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
