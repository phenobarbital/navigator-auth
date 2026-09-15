# TASK-084: Frontend — forced re-login notice and integration `needs_reconnect`

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 13)
**Repository**: `../navigator/navigator-frontend-next`
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: none (contract-first; backend lands in TASK-082)
**Assigned-to**: unassigned

---

## Context

At deploy all sessions are purged. Every open tab will receive a burst of `401`s. Today
`src/lib/api/http.ts` (~lines 126–143) sets `window.location.href = "/login"` for non-policy
401s — potentially many times concurrently and with no explanation. Separately, integrations
whose stored tokens became unreadable must show a Reconnect action instead of looking connected.

---

## Scope

- `src/lib/api/http.ts`: single-flight guard for the 401 redirect (both client variants at
  ~126 and ~223); redirect to `/login?reason=session_expired`; do not redirect when already on
  `/login`; preserve the existing policy-denial branch (401 with a server message stays an
  `ApiError`).
- `src/routes/login/`: when `reason=session_expired`, show once:
  *"Your session has ended because of a security update. Please sign in again."*; remove the
  query param from the URL after display (`history.replaceState`) so refresh does not repeat it.
- `src/lib/api/integrations.ts`: `export type IntegrationStatus = "connected" | "disconnected" |
  "needs_reconnect"`; add `status?: IntegrationStatus` to `IntegrationDescriptor` (fallback
  derived from `connected` when absent, for older backends).
- Integrations panel component(s) that render `IntegrationDescriptor` (locate via usages of
  `listIntegrations` / `IntegrationDescriptor`): render a warning badge and a "Reconnect" button
  for `needs_reconnect` that starts the existing connect flow.
- Tests: extend `src/lib/api/http.test.ts`; add login notice test and integrations status test.

**NOT in scope**: Secrets page (TASK-083); backend.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `src/lib/api/http.ts` | MODIFY | Single-flight redirect with reason |
| `src/lib/api/http.test.ts` | MODIFY | Burst-of-401 test |
| `src/routes/login/+page.svelte` | MODIFY | Notice |
| `src/lib/api/integrations.ts` | MODIFY | `status` type |
| Integrations panel component(s) | MODIFY | Reconnect UI |
| `src/routes/login/login-notice.test.ts` | CREATE | Notice shown once |
| Integrations component test | CREATE | `needs_reconnect` rendering |

---

## Implementation Notes

### Key Constraints
- The notice text must match the spec exactly (tests assert it).
- Guard must be module-level (shared by both client factories) and reset only on full page load.
- Keep backward compatibility when `status` is missing.

### References in Codebase
- `src/lib/api/http.ts` — 401 handling (~126–143, ~223–233)
- `src/lib/api/integrations.ts` — `IntegrationDescriptor`, `connect` flow
- `src/routes/login/` — login page

---

## Acceptance Criteria

- [ ] N concurrent 401s → exactly one navigation to `/login?reason=session_expired`
- [ ] Policy-denial 401s still surface as `ApiError` without redirect
- [ ] Login shows the security-update notice once; param removed after display
- [ ] `needs_reconnect` integrations show badge + Reconnect action; `status` absent → derived from `connected`
- [ ] `pnpm test` passes; `pnpm check` has no new errors

---

## Test Specification

```typescript
// src/lib/api/http.test.ts (addition)
it("redirects once on a burst of 401s", async () => {
  const assign = vi.spyOn(window.location, "href", "set");
  await Promise.allSettled([call401(), call401(), call401()]);
  expect(assign).toHaveBeenCalledTimes(1);
  expect(assign).toHaveBeenCalledWith("/login?reason=session_expired");
});
```

---

## Agent Instructions

1. **Read the spec** (Module 13)
2. **Check dependencies** — none
3. **Update status** → `"in-progress"`
4. **Implement** in the navigator-frontend-next feature worktree
5. **Verify** acceptance criteria
6. **Move file** to `sdd/tasks/completed/`, index → `"done"`
7. **Completion Note**

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
