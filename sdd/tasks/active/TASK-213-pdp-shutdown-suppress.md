# TASK-213: Replace nonexistent `asyncio.suppress` in `PDP.on_shutdown`

**Feature**: FEAT-113 — PDP shutdown — replace nonexistent `asyncio.suppress`
**Spec**: `sdd/specs/abac-pdp-fixes.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned
**Discovered-from**: `issue:7bd9bfe643b2`

---

## Context

Spec §1 and §3 Module 1. `PDP.on_shutdown` (pdp.py:382-389) runs
`with asyncio.suppress(asyncio.CancelledError):`, but `asyncio` has no `suppress` (it is
`contextlib.suppress`). With `ABAC_RELOAD_INTERVAL > 0` a reload task exists, so every shutdown raises
`AttributeError` after `cancel()` and neither storage is closed.

---

## Scope

- Add `import contextlib` to `navigator_auth/abac/pdp.py`.
- Replace `asyncio.suppress(` with `contextlib.suppress(` in `on_shutdown`.
- Create `tests/test_pdp_shutdown.py` with the two spec §4 tests.
- Add one CHANGELOG "Unreleased" bullet.

**NOT in scope**: closing the YAML storage when `storage.close()` raises; `AbstractStorage.close`;
other Pyright findings in `pdp.py`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/abac/pdp.py` | MODIFY | `import contextlib`; `contextlib.suppress` in `on_shutdown` |
| `tests/test_pdp_shutdown.py` | CREATE | shutdown tests |
| `CHANGELOG.md` | MODIFY | one bullet under "# Unreleased" |

---

## Codebase Contract (Anti-Hallucination)

### Verified Imports
```python
import asyncio                                   # verified: pdp.py:4
import contextlib                                # stdlib; NEW in pdp.py
from navigator_auth.abac.pdp import PDP          # verified: pdp.py:71 (class PDP)
```

### Existing Signatures to Use
```python
# navigator_auth/abac/pdp.py (dev @ 64bf627)
ABAC_RELOAD_INTERVAL                                    # imported at :10 from navigator_auth.conf (module global)
class PDP:
    self._reload_task: Optional[asyncio.Task] = None    # :105
    self.storage                                        # constructor arg `storage`
    self.yaml_storage                                   # constructor arg `yaml_storage`, may be None
    async def on_startup(self, app: web.Application)    # :372
    async def on_shutdown(self, app: web.Application)   # :382-389
    async def _periodic_reload(self)                    # :445 — returns at once if ABAC_RELOAD_INTERVAL <= 0
# navigator_auth/abac/storages/db.py:78           async def close(self)
# navigator_auth/abac/storages/yaml_storage.py:96 async def close(self) -> None
```

### Does NOT Exist
- ~~`asyncio.suppress`~~ — the bug.
- ~~`AbstractStorage.close`~~ — not declared on the abstract class; tests use `AsyncMock` storages.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/abac/pdp.py", "action": "MODIFY"},
    {"path": "tests/test_pdp_shutdown.py", "action": "CREATE"},
    {"path": "CHANGELOG.md", "action": "MODIFY"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/abac/pdp.py#PDP.on_shutdown",
    "sym:navigator_auth/abac/pdp.py#PDP._periodic_reload"
  ]
}
```

---

## Implementation Blueprint

### Steps (in order)
1. Add `import contextlib` below `import asyncio` — *why*: `suppress` lives in `contextlib`.
2. Replace the `with` line in `on_shutdown` — *why*: the fix itself.
3. Write the tests — *why*: the reload task path has no coverage today, which is how the bug survived.
4. Add the CHANGELOG bullet; run the Validation Commands.

### `navigator_auth/abac/pdp.py` (MODIFY)
```python
# occurrences: 1 (verified: grep -c '^import asyncio' navigator_auth/abac/pdp.py)
# AFTER — insert below `import asyncio` (verified: pdp.py:4)
import contextlib

# occurrences: 1 (verified: grep -c '^            with asyncio.suppress(asyncio.CancelledError):' pdp.py)
# REPLACE `            with asyncio.suppress(asyncio.CancelledError):` (verified: pdp.py:385) with:
            with contextlib.suppress(asyncio.CancelledError):
```
**Why**: keep `asyncio.CancelledError` — only the context manager's module changes.

### `tests/test_pdp_shutdown.py` (CREATE)
```python
"""PDP.on_shutdown cancels the reload task and closes storages (FEAT-113)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from navigator_auth.abac.pdp import PDP


@pytest.fixture(autouse=True)
def _stub_audit_log(monkeypatch):
    """Keep PDP tests local; audit-log construction otherwise resolves host DNS."""
    monkeypatch.setattr("navigator_auth.abac.pdp.AuditLog", lambda: MagicMock(log=AsyncMock()))


def _pdp() -> PDP:
    storage = AsyncMock()
    storage.load_policies = AsyncMock(return_value=[])
    return PDP(storage=storage, yaml_storage=AsyncMock())


@pytest.mark.asyncio
async def test_on_shutdown_cancels_reload_task_and_closes_storages(monkeypatch):
    # FILL IN: monkeypatch navigator_auth.abac.pdp.ABAC_RELOAD_INTERVAL to 3600;
    # pdp._reload_task = asyncio.ensure_future(pdp._periodic_reload()); await asyncio.sleep(0) so it
    # starts; await pdp.on_shutdown(MagicMock()) raises nothing; task.cancelled() or task.done();
    # storage.close and yaml_storage.close awaited once — bounded by AC 1
    ...


@pytest.mark.asyncio
async def test_on_shutdown_without_reload_task_closes_storages():
    # FILL IN: _reload_task is None; await on_shutdown; both closes awaited once — bounded by AC 2
    ...
```
**Why**: patch the name in `navigator_auth.abac.pdp` — `_periodic_reload` reads the module global.

### `CHANGELOG.md` (MODIFY)
```markdown
# occurrences: 1 (verified: grep -c '^- \*\*PDP policy registry hardening (FEAT-112).\*\*' CHANGELOG.md)
# AFTER the FEAT-112 bullet (ends with "instead of silently ignoring a tuple."), add:
- **`PDP.on_shutdown` no longer crashes with periodic reload on (FEAT-113).** It called the
  nonexistent `asyncio.suppress`, so with `ABAC_RELOAD_INTERVAL > 0` shutdown raised
  `AttributeError` and the policy storages were never closed. It now uses `contextlib.suppress`.
```

### FILL IN checklist
- [ ] `test_on_shutdown_cancels_reload_task_and_closes_storages` — bounded by AC 1
- [ ] `test_on_shutdown_without_reload_task_closes_storages` — bounded by AC 2

---

## Acceptance Criteria

- [ ] With a running reload task, `on_shutdown` returns normally and closes both storages.
- [ ] Without a reload task, `on_shutdown` closes both storages.
- [ ] Validation Commands pass; black (`-l 120`) and flake8 clean on changed files.

---

## Validation Commands
- `pytest tests/test_pdp_shutdown.py -q`
- `pytest tests/test_pdp_add_policy.py -q`

---

## Test Specification

See the CREATE block above; spec §4.

---

## Agent Instructions

When you pick up this task:
1. **Work in the feature worktree** (`parrot sdd worktree ensure --slug abac-pdp-fixes --feature-id FEAT-113`)
2. **Read the spec** at the path listed above
3. **Check dependencies** — none
4. **Verify the Codebase Contract** before writing any code
5. **Update status** in `sdd/tasks/index/abac-pdp-fixes.json` → `"in-progress"` (set `started_at`)
6. **Implement** from the blueprint; complete every `# FILL IN:`
7. **Verify** — run the Validation Commands
8. **Commit the code** — stage only the files this task lists
9. **Close the task** with `parrot sdd task close TASK-213 abac-pdp-fixes verified`
10. **Fill in the Completion Note**, then commit the SDD state

---

## Completion Note
*(Agent fills this in when done)*

**Completed by**:
**Date**:
**Notes**:
**Deviations from spec**: none
