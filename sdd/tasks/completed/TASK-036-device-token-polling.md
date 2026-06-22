# TASK-036: Device token polling branch (RFC 8628 §3.4–§3.5)

**Feature**: oauth2-introspection-device-grant (FEAT-094)
**Spec**: `sdd/specs/oauth2-introspection-device-grant.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-032, TASK-034, TASK-035
**Assigned-to**: unassigned

---

## Context

Implements spec §3 Module 5 — the `device_code` grant branch on `/oauth2/token`, the polling half
of the device flow. Reuses the existing `authorization_code` exchange (brainstorm shortcut D-2) so
device-issued tokens inherit owner-binding, single-use, refresh rotation, and refresh-iff-
`offline_access` for free. Final device task; shares `backend.py` with TASK-033/034/035.

---

## Scope

- Add the `grant_type=urn:ietf:params:oauth:grant-type:device_code` branch to `token_request`.
- Resolve `device_code` via `DeviceCodeStorage`; enforce client match.
- Run the TASK-032 `poll_decision` state machine:
  - too soon ⇒ `slow_down` (bump `interval` by `OAUTH_DEVICE_SLOW_DOWN_INCREMENT`, update
    `last_polled_at`);
  - `pending` ⇒ `authorization_pending`;
  - `denied` ⇒ `access_denied`;
  - expired/unknown ⇒ `expired_token`.
- On `approved`: **verify PKCE (D4)** — `code_verifier` against stored `code_challenge`
  (FEAT-093 helper, `hmac.compare_digest`; `invalid_grant` on mismatch) — then **delegate to the
  existing `authorization_code` exchange** via the stored `auth_code` carrier (owner-bound access
  token + refresh **iff** `offline_access`). Mark the device_code `consumed` (single-use; second
  poll rejected).
- Use standard OAuth error envelopes throughout.
- Write unit tests.

**NOT in scope**: device_authorization issuance (TASK-034), verification page (TASK-035),
introspection (TASK-033).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | `device_code` branch in `token_request` |
| `tests/test_device_token_polling.py` | CREATE | Unit tests |

---

## Implementation Notes

### Key Constraints
- Reuse the auth-code exchange path verbatim (D-2) — do NOT duplicate token-minting logic.
- Guard the exchange so the device-origin carrier auth-code (no `redirect_uri`) is accepted.
- `slow_down` must increase the required interval server-side (enforced via `last_polled_at`).
- Single-use: after success, `status=consumed`; a replayed `device_code` is rejected.
- `offline_access` gating consistent with FEAT-093 D5.

### References in Codebase
- `navigator_auth/backends/oauth2/backend.py` — `token_request` (`authorization_code` branch).
- `navigator_auth/backends/oauth2/pkce.py` — FEAT-093 PKCE verify helper.
- `navigator_auth/backends/oauth2/code_backend.py` — `DeviceCodeStorage`,
  `AuthorizationCodeStorage`.

---

## Acceptance Criteria

- [ ] Polling faster than `interval` ⇒ `slow_down` (+ interval bump).
- [ ] `pending`/`denied`/expired map to `authorization_pending`/`access_denied`/`expired_token`.
- [ ] `approved` + valid `code_verifier` ⇒ owner-bound token (refresh iff `offline_access`);
      mismatch ⇒ `invalid_grant`.
- [ ] Second poll after success ⇒ rejected (consumed/single-use).
- [ ] Tests pass: `pytest tests/test_device_token_polling.py -v`.

---

## Test Specification

```python
# tests/test_device_token_polling.py — maps to spec §4:
#   test_device_poll_slow_down, test_device_poll_pending_denied_expired,
#   test_device_poll_success_single_use, test_device_no_offline_access_no_refresh, test_device_pkce_verify
```

---

## Agent Instructions

When you pick up this task:
1. **Read the spec** at the path above.
2. **Check dependencies** — TASK-032/034/035 in `tasks/completed/`.
3. **Update status** in `tasks/.index.json` → `"in-progress"`.
4. **Implement** per scope.
5. **Verify** acceptance criteria.
6. **Move** this file to `tasks/completed/TASK-036-device-token-polling.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

**Completed by**: claude-sonnet-4-6 / SDD Worker
**Date**: 2026-06-22
**Notes**: All 9 unit tests pass. `_handle_device_code` handler was already implemented in backend.py
during TASK-033. Tests cover: slow_down + interval bump, authorization_pending, access_denied,
expired_token, approved + PKCE → access token + refresh (offline_access), no offline_access → no
refresh, bad code_verifier → invalid_grant, missing device_code, unknown device_code. Also fixed a
bug in poll_decision() where CONSUMED/DENIED terminal states were evaluated AFTER the rate-limit
check — now CONSUMED/DENIED are checked before the rate-limit (slow_down) check, so second polls
after exchange correctly return expired_token rather than slow_down.
**Deviations from spec**: none
