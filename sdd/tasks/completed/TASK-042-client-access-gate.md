# TASK-042: Per-client access gate + approval queue

**Feature**: FEAT-095 oauth2-for-mcp-agents
**Spec**: `sdd/specs/oauth2-for-mcp-agents.spec.md` (Module 5, decisions D3 + D7)
**Status**: done
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-041
**Assigned-to**: unassigned

---

## Context

Nothing in the login path gates who may receive tokens — `AUTH_MISSING_ACCOUNT="create"`
auto-provisions any Google login. For MCP exposure, token issuance must require explicit
per-user activation per client (D3), with an approval queue so admins can see and approve
who tried (D7, ships in v1).

---

## Scope

- Create `navigator_auth/backends/oauth2/client_access.py`: `ClientAccessStorage` ABC +
  memory/redis/postgres tiers, registered in the FEAT-093 storage factory
  (`get_token_storages`). Interface per spec §2: `check`, `grant`, `revoke`,
  `list_for_client` (+ `list_pending`, `approve`, `reject` for the queue).
- `ClientAccess` model (`models.py`) + `auth.client_access` DDL (unique
  `(user_id, client_id)`, indexed `client_uid`; `status`: `active|revoked|pending`).
- Gate check in `authorize` (after login, **before consent**) and in FEAT-094 device
  verification (`/oauth2/device`): enforced when `OAUTH_ACCESS_GATE_ENABLED` (global) or
  the client's `enforce_access_gate` flag; failure ⇒ standard `access_denied` error
  redirect (with `state`) — never reaches consent, never gets a code.
- **Approval queue (D7)**: denied gated attempt upserts one `status='pending'` row per
  (user, client) when `OAUTH_ACCESS_GATE_QUEUE=True` (default).
- Deactivation cascade: revoke `OauthGrant`s + `revoke_chain` on refresh tokens + revoke
  live `jti`s for that (user, client); effect ≤ access-token TTL.
- Management API `handlers/client_access.py`:
  `GET/POST/DELETE /api/v1/oauth2/clients/{client_uid}/access` (admin/superuser only,
  behind auth middleware + ABAC); list includes pending rows; approve (`pending→active`)
  and reject.
- Unit tests per spec §4 (five `test_gate_*` rows).

**NOT in scope**: any UI beyond the JSON API; shadow/dry-run PBAC mode (explicit non-goal).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/oauth2/client_access.py` | CREATE | Storage ABC + 3 tiers |
| `navigator_auth/models.py` | MODIFY | `ClientAccess` model |
| `navigator_auth/backends/oauth2/ddl.sql` | MODIFY | `auth.client_access` table |
| `navigator_auth/backends/oauth2/backend.py` | MODIFY | Gate check in `authorize` + device verification |
| `navigator_auth/handlers/client_access.py` | CREATE | Management API |
| `navigator_auth/handlers/__init__.py` | MODIFY | Mount routes |
| `navigator_auth/conf.py` | MODIFY | (keys exist from TASK-038 — wire only) |
| `tests/test_oauth2_access_gate.py` | CREATE | Gate matrix + cascade + queue |

---

## Implementation Notes

### Key Constraints
- **Device-flow parity is a security requirement**: the gate must cover
  `/oauth2/device` verification or it is bypassable via the device grant (spec §6 risk).
- Cascade uses only FEAT-093/094 primitives (`GrantStorage`, `RefreshTokenStorage.
  revoke_chain`, `AccessTokenStorage`); no new revocation machinery.
- Table carries both int FK (`client_id`) and denormalized `client_uid` (three-meanings
  discipline).
- `access_denied` must include the original `state` and use the standard OAuth error
  redirect (FEAT-093 `auth_error` helper).

### References in Codebase
- `navigator_auth/backends/oauth2/client_backend.py` — storage ABC + trio template.
- `navigator_auth/backends/oauth2/backend.py:476` `authorize`, FEAT-094 device
  verification — insertion points.
- `navigator_auth/handlers/user_identities.py` — handler + mounting pattern.

---

## Acceptance Criteria

- [ ] Non-activated user on a gated client ⇒ `access_denied` (with `state`), no code, no
      token; pending row recorded
- [ ] Gate off globally + client flag off ⇒ FEAT-093 behavior unchanged
- [ ] Approve ⇒ next authorize succeeds; reject ⇒ still denied; no duplicate pending rows
- [ ] Deactivate ⇒ grants + refresh chain + jtis revoked; refresh ⇒ `invalid_grant`;
      introspect ⇒ inactive; new authorize ⇒ `access_denied`
- [ ] Gate enforced at FEAT-094 device verification too
- [ ] Tests pass: `pytest tests/test_oauth2_access_gate.py -v`

---

## Test Specification

```python
# tests/test_oauth2_access_gate.py — per spec §4:
# test_gate_blocks_before_consent, test_gate_disabled_by_default,
# test_gate_revoke_cascade, test_gate_device_flow, test_gate_pending_queue
# + integration test_gate_lifecycle (activate → works → deactivate → revoked everywhere)
```

---

## Agent Instructions

1. **Read the spec**; 2. **Check dependencies** (TASK-041 completed);
3. **Update index** → in-progress; 4. **Implement**; 5. **Verify**;
6. **Move to completed/**; 7. **Update index** → done; 8. **Fill Completion Note**.

---

## Completion Note

**Completed by**: sdd-worker (Claude Opus 5)
**Date**: 2026-08-31
**Notes**: `oauth2/client_access.py` ships `ClientAccessStorage` (ABC) + memory/redis/postgres tiers and `get_client_access_storage`, wired into `on_startup` alongside the FEAT-093 storages and published as `app["oauth2_client_access_storage"]`. Records are the asyncdb `ClientAccess` model (`auth.client_access`), so all three tiers speak the table's shape; `check` returns True only for `status='active'`, so every other state fails closed. `_enforce_access_gate` runs in `authorize` immediately after the session check and **before** both the consent-skip and the consent hand-off (asserted by a source-order test), and again in `device_verification` right after the client lookup — device parity is a security requirement, not a nicety. Enforced when `OAUTH_ACCESS_GATE_ENABLED` **or** the client's `enforce_access_gate` flag; with both off the gate is completely inert (no check, no queue row). Denial returns the standard `access_denied` redirect carrying the original `state`, and falls back to a rendered 403 when there is no validated `redirect_uri` (the device flow) — never a bare unvalidated redirect. The gate fails closed if storage is missing or throws. D7 queue: a denied attempt upserts exactly one `pending` row per (user, client); repeated attempts do not duplicate, and `request_access` never downgrades an `active` row nor reopens a `revoked` one. `cascade_access_revocation` uses only existing primitives — `GrantStorage.revoke_grant`, `RefreshTokenStorage.revoke_chain` filtered to the client's live tokens, and jti revocation — and tolerates partial failures. Management API `ClientAccessHandler` at `GET/POST/DELETE /api/v1/oauth2/clients/{client_uid}/access`, superuser-only, mounted in `handlers/__init__.py`; POST takes `action: grant|approve|reject`, DELETE revokes and cascades. 32 new tests; 308 pass across the non-DB OAuth2 suites.

**Deviations from spec**: none functionally. Two implementation notes. (1) `AccessTokenStorage` has no (user, client) index — it is keyed by jti only — so `_revoke_client_jtis` sweeps live records over that storage's own Redis handle, skipping the `revoked:` markers that share its prefix. This adds no new revocation machinery (it calls the existing `AccessTokenStorage.revoke`) and runs only on an administrative deactivation, never on the request path. (2) The DDL carries the spec'd `UNIQUE (user_id, client_id)` **and** an additional `UNIQUE (user_id, client_uid)`; `client_id` is nullable because clients held in the memory/redis tiers have no integer PK, so the uid pair is what actually guarantees "no duplicate pending rows". `conf.py` needed no edit — TASK-038 already added `OAUTH_ACCESS_GATE_ENABLED` / `OAUTH_ACCESS_GATE_QUEUE`; this task only wires them.
