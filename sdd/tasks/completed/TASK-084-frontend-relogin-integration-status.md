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

### Worktree setup (done in TASK-083)
- Worktree: `navigator/navigator-frontend-next/.claude/worktrees/feat-FEAT-099-vault-crypto-hardening`
  (branch from `dev`), with `pnpm install --frozen-lockfile --prefer-offline --ignore-scripts`
  (~2 s, hardlinks from the pnpm store) and `npx svelte-kit sync`. Do **not** symlink
  `node_modules` from the main checkout: vite blocks files outside the project root and
  `@testing-library/svelte/vitest` fails to load.
- Baseline (both on `dev` and in the worktree): 3 test files / 9 tests fail before any change;
  `svelte-check` reports 0 errors and 168 pre-existing warnings.
- `vi.mock` factories are hoisted: declare mock classes inside the factory and read them back
  with `await import(...)`.

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

**Completed by**: claude-session (Claude Opus 5)
**Date**: 2026-09-16
**Notes**:
- navigator-frontend-next worktree `.claude/worktrees/feat-FEAT-099-vault-crypto-hardening`,
  commit `dd97b4c`.
- `src/lib/api/http.ts`: `SESSION_EXPIRED_REASON`, `SESSION_EXPIRED_MESSAGE`,
  `redirectToLogin()` (module-level single-flight guard, clears the stored token inside
  try/catch, skips navigation when already on `/login`, sends
  `/login?reason=session_expired`) and `takeSessionExpiredNotice()` (returns the message once and
  removes only the `reason` param via `history.replaceState`). The 401 branch now calls
  `redirectToLogin()`; the policy-denial branch is untouched, and the token client
  (`createApiClientWithToken`) still never redirects.
- `src/routes/login/+page.svelte`: `takeSessionExpiredNotice()` in `onMount` renders a
  `role="status"` notice above the error slot.
- `src/lib/api/integrations.ts`: `IntegrationStatus` union, optional `status` on
  `IntegrationDescriptor`, and `integrationStatus()` deriving it from `connected` for backends
  that predate FEAT-099.
- `IntegrationItem.svelte`: three states — Connected/Disconnect, "Needs reconnect" badge +
  Reconnect (re-runs the existing connect flow), Not connected/Connect; the account name stays
  visible while a reconnect is pending.
- Tests: `src/lib/api/http.session.test.ts` (6: burst of 401s → one navigation, no redirect on
  `/login`, token cleared, notice consumed once, other query params kept, no reason → null) and
  `IntegrationItem.test.ts` (7: the three states, account visible, legacy fallback,
  `integrationStatus` helper).
- Results: full suite dev 694 passed / 9 failed (3 files) → worktree 723 passed with the **same**
  9 pre-existing failures and no new failing files. `svelte-check`: 0 errors, the same 168
  pre-existing warnings.

**Deviations from spec**:
- The notice logic lives in `http.ts` as `takeSessionExpiredNotice()` (next to the redirect that
  produces the query param) instead of inside the login page, so it is unit-testable without
  rendering the whole login route.
- Tests stub `window.location`/`history` rather than driving jsdom navigation: axios reads
  `location.href` at import time and needs an absolute URL.
- No dedicated login-route render test (the page pulls in auth, provider buttons and carousel
  assets); the consumed-once behaviour is covered at the helper level.
