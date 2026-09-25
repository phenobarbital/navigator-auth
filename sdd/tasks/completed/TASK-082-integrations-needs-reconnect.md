# TASK-082: Integrations `needs_reconnect` status and `VaultTokenSync` F4 regression

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 10, §2 HTTP contract ai-parrot)
**Repository**: `../ai-parrot` — packages `ai-parrot` (service/models) and `ai-parrot-server` (handler, `VaultTokenSync`)
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-073, TASK-080
**Assigned-to**: unassigned

---

## Context

Integration metadata lives in DocumentDB `users_integrations`; the tokens themselves are stored
in the Session Vault through `VaultTokenSync` (`{provider}:{field}` keys, deterministic
`telegram-persistent:` / `cli-persistent:` session schemes). Today:

- `IntegrationsService.list_for_user` reports `connected = integration_row is not None`, even
  when the tokens are missing or unreadable.
- F4: `SessionVault` rejected `:` keys, so `VaultTokenSync.store_tokens` silently stored nothing
  (fixed in TASK-073 — this task proves it end to end).

---

## Scope

- `packages/ai-parrot/src/parrot/auth/oauth2/models.py`: add
  `status: Literal["connected","disconnected","needs_reconnect"]` to `IntegrationDescriptor`;
  keep `connected: bool` (true only when `status == "connected"`).
- `packages/ai-parrot/src/parrot/auth/oauth2/service.py` (`list_for_user`, `confirm_enable`):
  when a `users_integrations` row exists, probe token readability via the provider's token
  source (`VaultTokenSync.read_tokens` or equivalent); `VaultIntegrityError` /
  `UnknownKeyVersionError` / required token missing → `needs_reconnect`; no row →
  `disconnected`. Probing must not refresh tokens or call the provider.
- `packages/ai-parrot-server/src/parrot/services/vault_token_sync.py`: surface integrity errors
  from `read_tokens` as a typed result (not a silent empty dict) so the service can
  distinguish "missing" from "tampered"; keep write-first-field ordering from FEAT-267.
- `packages/ai-parrot-server/src/parrot/handlers/integrations.py`: serialize `status`.
- Tests:
  - `packages/ai-parrot-server/tests/unit/test_vault_token_sync_atomic_persist.py` and
    `packages/ai-parrot/tests/unit/test_vault_token_sync.py`: add a round-trip test with real
    `SessionVault` v2 (fake pool/redis) for `jira:access_token` (F4 regression).
  - New `packages/ai-parrot/tests/auth/test_integrations_status.py`.
  - Check `tests/integration/test_a2a_fireflies_vertical.py` / `test_a2a_workiq_vertical.py`
    still pass or adjust fixtures.

**NOT in scope**: frontend rendering (TASK-084); reconnect flow changes (existing connect flow is
reused).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `packages/ai-parrot/src/parrot/auth/oauth2/models.py` | MODIFY | `status` field |
| `packages/ai-parrot/src/parrot/auth/oauth2/service.py` | MODIFY | Status computation |
| `packages/ai-parrot-server/src/parrot/services/vault_token_sync.py` | MODIFY | Typed read result |
| `packages/ai-parrot-server/src/parrot/handlers/integrations.py` | MODIFY | Serialize `status` |
| `packages/ai-parrot/tests/auth/test_integrations_status.py` | CREATE | Status tests |
| `packages/ai-parrot/tests/unit/test_vault_token_sync.py` | MODIFY | F4 regression |
| `packages/ai-parrot-server/tests/unit/test_vault_token_sync_atomic_persist.py` | MODIFY | Typed read result |

---

## Implementation Notes

### Key Constraints
- `list_for_user` is called per page load: probe cost must be one vault read per connected
  provider; reuse a single `SessionVault` load per user per request.
- Do not change the O365 device-code resolver behaviour beyond the typed read result.
- Never log tokens.

### References in Codebase
- `packages/ai-parrot/src/parrot/auth/oauth2/service.py` (`list_for_user` ~74–135)
- `packages/ai-parrot/src/parrot/auth/oauth2/persistence.py` (`users_integrations`)
- `packages/ai-parrot-server/src/parrot/services/vault_token_sync.py`
- `packages/ai-parrot/src/parrot/auth/oauth2/o365_devicecode_provider.py` (`read_tokens` usage)

---

## Acceptance Criteria

- [ ] Row + readable tokens → `connected`; row + tampered/missing tokens → `needs_reconnect`; no row → `disconnected`
- [ ] `connected` boolean consistent with `status`
- [ ] `VaultTokenSync` stores and reads `{provider}:{field}` with deterministic session scheme (F4)
- [ ] Touched test suites pass

---

## Test Specification

```python
# packages/ai-parrot/tests/auth/test_integrations_status.py
import pytest


@pytest.mark.asyncio
async def test_tampered_tokens_need_reconnect(service_with_row, vault_with_swapped_tokens):
    items = await service_with_row.list_for_user(user_id="1", agent_id="a")
    jira = next(i for i in items if i.provider == "jira")
    assert jira.status == "needs_reconnect" and jira.connected is False
```

---

## Agent Instructions

1. **Read the spec** (Module 10)
2. **Check dependencies** — TASK-073, TASK-080 completed
3. **Update status** → `"in-progress"`
4. **Implement** in the ai-parrot feature worktree
5. **Verify** acceptance criteria
6. **Move file** to `sdd/tasks/completed/`, index → `"done"`
7. **Completion Note**

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: claude-session (Claude Opus 5)
**Date**: 2026-09-16
**Notes**:
- ai-parrot worktree `.claude/worktrees/feat-FEAT-099-vault-crypto-hardening`, commit `ea23a57`.
- `services/vault_token_sync.py`: new `VaultTokenRead` dataclass + `read_tokens_result()` with
  status `ok` / `missing` / `unreadable` (VaultCryptoError, logged by class only) / `unavailable`;
  `read_tokens()` keeps its old signature by delegating (`.tokens`), so the O365 device-code
  provider, jira/fireflies/workiq callers are untouched. The loaded `SessionVault` is cached per
  instance (one load per user per request) and invalidated after `store_tokens`/`delete_tokens`.
  FEAT-267 write-first ordering and the partial-write warning are unchanged.
- `auth/oauth2/models.py`: `IntegrationStatus = Literal["connected","disconnected",
  "needs_reconnect"]`, new `status` field and a `model_validator` keeping `connected` in sync
  (explicit `status` wins, otherwise it is derived from `connected`).
- `auth/oauth2/service.py`: `IntegrationsService(vault_token_sync=None)` memoizes one
  `VaultTokenSync` per instance; `list_for_user` probes the stored tokens of providers that have a
  `users_integrations` row → `needs_reconnect` when they are missing/unreadable, `connected`
  otherwise. Probe failures or a missing app/pool fall back to `connected`, so a vault outage never
  hides working integrations. The handler already serializes with `model_dump(mode="json")`.
- Tests: `packages/ai-parrot/tests/auth/test_integrations_status.py` (status matrix, no probe
  without a row, outage/probe-failure fallbacks, descriptor contract) and
  `packages/ai-parrot-server/tests/unit/test_vault_token_sync_f4_regression.py` (real
  `SessionVault` over in-memory DB/Redis doubles: `{provider}:{field}` keys really persist and read
  back, deterministic scheme across instances, delete, missing vs tampered, partial-write warning
  without leaking tokens).
- Results vs dev baseline — ai-parrot `tests/{unit/test_vault_token_sync,auth,handlers,security}`:
  570 → 607 passed with the **same** 42 pre-existing failures (dataset/planogram/etc.);
  ai-parrot-server `tests/{unit,integration}`: 205 → 227 passed with the same 3 pre-existing
  failures (a2a vertical broker registration). `ruff`: only the pre-existing `F401` in
  `service.py` (also present on `dev`).

**Deviations from spec**:
- `read_tokens()` was kept as the compatibility wrapper and the typed result exposed through a new
  `read_tokens_result()`, instead of changing the existing method's return type (5 callers).
- `missing` tokens also map to `needs_reconnect` (a credential row without usable tokens is not a
  working integration).
- The status probe needs `request.app` for the pools; without it the service reports `connected`
  rather than guessing.
