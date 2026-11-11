---
# SDD flow type and base branch (FEAT-145).
type: feature
base_branch: dev
projects: [abac]
tags: [pdp, shutdown, ledger-fix]
docs:
  policy: none
  pages: []
  api_modules: [navigator_auth.abac.pdp]
---

# Feature Specification: PDP shutdown — replace nonexistent `asyncio.suppress`

**Feature ID**: FEAT-113
**Date**: 2026-11-11
**Author**: Jesus Lara (spec scaffolded by Claude Code via /sdd-fix)
**Status**: approved
**Target version**: unreleased
**Parent**: FEAT-112 — PDP policy registry hardening (`sdd/specs/abac-pdp-tech-debt.spec.md`, completed; PR #636 merged at `761aaa0`)
**Ledger group**: `fixgroup:226fe3e0417f` — `issue:7bd9bfe643b2` (bug, minor)

---

## 1. Motivation & Business Requirements

### Problem Statement

`PDP.on_shutdown` (pdp.py:382-389 on `dev` @ `12cc71f`) cancels the periodic reload task and then runs
`with asyncio.suppress(asyncio.CancelledError):`. The `asyncio` module has no `suppress`
(`hasattr(asyncio, "suppress")` is `False` on Python 3.11; the helper is `contextlib.suppress`).

`on_startup` creates `self._reload_task` only when `ABAC_RELOAD_INTERVAL > 0`. With periodic reload
enabled, every application shutdown raises `AttributeError` right after `cancel()`, so
`self.storage.close()` and `self.yaml_storage.close()` never run (the DB pool is not released) and
aiohttp logs a failed shutdown handler. With reload disabled the bug is dormant.

Found by Pyright (`reportAttributeAccessIssue`) while implementing FEAT-112; filed as `issue:7bd9bfe643b2`.

### Goals
- `on_shutdown` cancels and awaits the reload task without raising, then closes both storages.

### Non-Goals (explicitly out of scope)
- Closing the YAML storage when `storage.close()` itself raises.
- `AbstractStorage` lacking a declared `close()` (type-checker only; both concrete storages define it).
- Any other Pyright finding in `pdp.py`.

---

## Governing Decisions

decision audit not configured in this repository

---

## 2. Architectural Design

### Overview
Import `contextlib` and use `contextlib.suppress(asyncio.CancelledError)`. No behaviour change when no
reload task exists.

### Integration Points
- `PDP.on_startup` (pdp.py:372-380) creates `_reload_task` via `asyncio.ensure_future(self._periodic_reload())`.
- `PDP._periodic_reload` (pdp.py:445) exits its loop on `asyncio.CancelledError`.
- `PDP.setup` registers `on_shutdown` in `app.on_shutdown` (pdp.py:474).

### Data Models
None.

### New Public Interfaces
None.

---

## 3. Module Breakdown

### Module 1: shutdown fix (`issue:7bd9bfe643b2`)
- `pdp.py`: `import contextlib`; replace `asyncio.suppress` with `contextlib.suppress` in `on_shutdown`.
- New `tests/test_pdp_shutdown.py`.

---

## 4. Test Specification

### Unit Tests (all in `tests/test_pdp_shutdown.py`)
| Test | Module | Description |
|---|---|---|
| `test_on_shutdown_cancels_reload_task_and_closes_storages` | M1 | `ABAC_RELOAD_INTERVAL` patched > 0, `_reload_task = ensure_future(_periodic_reload())`; `await on_shutdown(app)` raises nothing; task cancelled; `storage.close` and `yaml_storage.close` awaited once |
| `test_on_shutdown_without_reload_task_closes_storages` | M1 | no reload task → both storages closed |

### Validation Contract

tests:
- tests/test_pdp_shutdown.py
- tests/test_pdp_add_policy.py
- tests/test_pdp_registry_hardening.py
markers: none

### Test Data / Fixtures
Copy the `_stub_audit_log` fixture pattern from `tests/test_pdp_registry_hardening.py`.

---

## 5. Acceptance Criteria

- [ ] With a running reload task, `on_shutdown` returns normally and closes both storages.
- [ ] Without a reload task, `on_shutdown` closes both storages (unchanged).
- [ ] All Validation Contract tests pass; black (`-l 120`) and flake8 clean on changed files.

---

## 6. Codebase Contract

### Verified Imports
```python
import asyncio                                   # pdp.py:4
from navigator_auth.abac.pdp import PDP          # pdp.py:71
import contextlib                                # stdlib; NEW in pdp.py
```

### Existing Class Signatures
```python
# navigator_auth/abac/pdp.py
class PDP:
    self._reload_task: Optional[asyncio.Task]           # set in __init__
    async def on_startup(self, app: web.Application)    # :372
    async def on_shutdown(self, app: web.Application)   # :382
    async def _periodic_reload(self)                    # reads module-level ABAC_RELOAD_INTERVAL
# navigator_auth/abac/storages/db.py:78          async def close(self)
# navigator_auth/abac/storages/yaml_storage.py:96 async def close(self) -> None
```

### Does NOT Exist (Anti-Hallucination)
- `asyncio.suppress` — the bug itself.
- `AbstractStorage.close` — not declared on the abstract class.

### Edit Sites (Blueprint Anchors)
| Module | File | Anchor |
|---|---|---|
| M1 | `navigator_auth/abac/pdp.py` | `import asyncio` (line 4, occurrences 1) |
| M1 | `navigator_auth/abac/pdp.py` | `            with asyncio.suppress(asyncio.CancelledError):` (line 385, occurrences 1) |

---

## 7. Implementation Notes & Constraints

### Known Risks / Gotchas
- `_periodic_reload` reads `ABAC_RELOAD_INTERVAL` from the `navigator_auth.abac.pdp` module namespace:
  patch `navigator_auth.abac.pdp.ABAC_RELOAD_INTERVAL`, not `navigator_auth.conf`.

### External Dependencies
None.

---

## 8. Open Questions

None.

---

## 9. Design Research Cross-Check

Status: skipped (one-line ledger fix).

---

## 10. Documentation

- **Policy**: `none` — CHANGELOG line only.
- **API modules**: `navigator_auth.abac.pdp`

---

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-11-11 | Claude Code (/sdd-fix) | Initial spec from ledger group fixgroup:226fe3e0417f |
