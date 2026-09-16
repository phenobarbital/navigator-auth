# TASK-083: Frontend — vault API client and `/profile/secrets` page

**Feature**: FEAT-099 vault-crypto-hardening
**Spec**: `sdd/specs/vault-crypto-hardening.spec.md` (Module 12, §2 HTTP contract navigator-auth)
**Repository**: `../navigator/navigator-frontend-next` (branch from `dev`)
**Status**: pending
**Priority**: medium
**Estimated effort**: L (4-8h)
**Depends-on**: none (contract-first; backend lands in TASK-078)
**Assigned-to**: unassigned

---

## Context

G7. Users need to see and manage their vault secrets without ever receiving values in the
browser. The page is a dedicated route `/profile/secrets` (not a tab), reachable from a
"Manage secrets" link on `/profile` and by direct URL. It is built against the HTTP contract
in the spec and can be developed with a mocked client before TASK-078 is merged.

---

## Scope

- `src/lib/api/vault.ts`: typed client using `createApiClient()` from `$lib/api/http`:
  - `listSecrets(): Promise<VaultSecretMetadata[]>` → `GET /api/v1/user/vault` (`secrets`)
  - `getSecret(key)` → `GET /api/v1/user/vault/{key}` (metadata)
  - `saveSecret(key, value)` → `POST /api/v1/user/vault` → `{key, updated_at, key_version, message}`
  - `deleteSecret(key)` → `DELETE /api/v1/user/vault/{key}`
  - `encodeURIComponent` for keys (keys may contain `:`)
  - Map `409 vault_integrity_error` and `503 vault_unavailable` to typed errors.
- `src/routes/profile/secrets/+page.svelte` under the same `AuthGuard` pattern as
  `src/routes/profile/+page.svelte`.
- Components in `src/lib/components/profile/`:
  - `UserSecrets.svelte` — table (name, last updated, key version), empty state, banners.
  - `UserSecretForm.svelte` — name + masked write-only value (never pre-filled; on edit only
    the name is shown and a new value is required); client validation mirroring backend
    (non-empty, ≤ 255 chars, no control chars; `:` allowed); updates the row from the POST
    response.
  - Delete confirmation dialog (reuse existing UI dialog components from `$lib/ui/components`).
- `src/routes/profile/+page.svelte`: add a "Manage secrets" link/button next to the tabs.
- Tests (vitest): `src/lib/api/vault.test.ts`, component tests for form/table, route guard test.

**NOT in scope**: forced re-login notice and integrations status (TASK-084); backend.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `src/lib/api/vault.ts` | CREATE | Typed client |
| `src/lib/api/vault.test.ts` | CREATE | Client tests |
| `src/routes/profile/secrets/+page.svelte` | CREATE | Secrets page |
| `src/lib/components/profile/UserSecrets.svelte` | CREATE | List + banners |
| `src/lib/components/profile/UserSecretForm.svelte` | CREATE | Create/update form |
| `src/lib/components/profile/UserSecrets.test.ts` | CREATE | Component tests |
| `src/routes/profile/+page.svelte` | MODIFY | "Manage secrets" link |

---

## Implementation Notes

### Pattern to Follow
- API client style: `src/lib/api/integrations.ts` (typed interfaces + `createApiClient()`).
- Page/guard style: `src/routes/profile/+page.svelte` (Svelte 5 runes, `AuthGuard`, `$page.data.client`).
- Component style: `src/lib/components/profile/UserIdentities.svelte`.

### Key Constraints
- The value input must use `type="password"` (with optional reveal of **what the user is
  typing** only), `autocomplete="off"`, and be cleared after submit; never stored in stores or
  `localStorage`.
- Never call an endpoint expecting `value` in a response.
- Package manager `pnpm`; tests `pnpm test`.

### References in Codebase
- `src/lib/api/http.ts` — client, error handling (`ApiError`)
- `src/lib/api/integrations.ts` — typed client pattern
- `src/lib/components/profile/*` — profile components

---

## Acceptance Criteria

- [ ] `/profile/secrets` lists metadata, creates/updates (write-only value), deletes with confirmation
- [ ] Unauthenticated access redirects to `/login` via `AuthGuard`
- [ ] "Manage secrets" link on `/profile` navigates to the page
- [ ] `vault_unavailable` / `vault_integrity_error` render banners, page does not crash
- [ ] Keys with `:` work (URL-encoded)
- [ ] `pnpm test` passes for new tests; `pnpm check` has no new errors

---

## Test Specification

```typescript
// src/lib/api/vault.test.ts
import { describe, it, expect, vi } from "vitest";
import { listSecrets, saveSecret } from "$lib/api/vault";

describe("vault api", () => {
  it("never exposes value from list", async () => {
    // mock GET /api/v1/user/vault -> { secrets: [{ key, updated_at, key_version }] }
    const items = await listSecrets();
    expect(Object.keys(items[0])).not.toContain("value");
  });

  it("encodes keys with colon", async () => {
    // expect DELETE /api/v1/user/vault/jira%3Atoken
  });
});
```

---

## Agent Instructions

1. **Read the spec** (Module 12, HTTP contract)
2. **Check dependencies** — none (mock the API until TASK-078 lands)
3. **Update status** in navigator-auth `sdd/tasks/.index.json` → `"in-progress"`
4. **Implement** in a navigator-frontend-next worktree
   (`.claude/worktrees/feat-FEAT-099-vault-crypto-hardening` from `dev`)
5. **Verify** acceptance criteria
6. **Move file** to `sdd/tasks/completed/` (navigator-auth), index → `"done"`
7. **Completion Note**

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
