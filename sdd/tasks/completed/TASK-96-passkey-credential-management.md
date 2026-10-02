# TASK-96: Passkey credential management — list, rename, delete (E13)

**Feature**: FEAT-101 — Passkey (WebAuthn) Authentication Backend
**Spec**: `sdd/specs/passkey-support-backend.spec.md` (Module 7, §2 Overview item 9, §2 New Public Interfaces, AC12)
**Status**: done
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-95
**Assigned-to**: unassigned

---

## Context

This is P2. It lets a signed-in user see, rename and remove their passkeys.

Removing the last passkey is refused with 409 (E13) when it would lock the user out. That is
the case when the user has no password set **and** no linked external identity
(`IdentityStore.list_for_user`).

This task edits the same file as TASK-95, so it runs after it.

---

## Scope

- Add these routes in `PasskeyAuth.configure`, all session-gated:
  - `GET {PASSKEY_PREFIX}/credentials`;
  - `PATCH {PASSKEY_PREFIX}/credentials/{id}`;
  - `DELETE {PASSKEY_PREFIX}/credentials/{id}`.
  
  None of them is added to the exclude list. PATCH and DELETE are CSRF-protected automatically
  (cookie-only sessions).
- `list_credentials`: returns `[{id (b64url), label, created_at, last_used_at, device_type, backed_up, rp_id}]`
  for **all** of the user's RPs. It never returns `public_key`, `sign_count` or the user handle.
- `rename_credential`:
  - body `{label}`, 1 to 128 characters after strip, else 400;
  - 404 when the credential is not the caller's;
  - 200 `{"status": "renamed"}`.
- `delete_credential`:
  - 404 when not the caller's;
  - if it is the user's last credential (`count_credentials == 1`) and
    `not await self._has_other_login_method(user_id)`, return 409 (E13);
  - else 204.
- `_has_other_login_method(user_id)`: the user has a non-empty password (load it with
  `self._idp.user_from_id`), or `IdentityStore(app["authdb"]).list_for_user(user_id)` is non-empty.
- Write `tests/test_passkey_management.py` (`test_manage_list_rename_delete`, live).

**NOT in scope**: disabling credentials or notifying users (Non-Goal, Q4).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/passkey.py` | MODIFY | Routes and four methods |
| `tests/test_passkey_management.py` | CREATE | Live management test |

---

## Codebase Contract (Anti-Hallucination)

> Verified 2026-10-02 against `dev` @ `564c440`, plus the files created by TASKS 87 to 95.

### Verified Imports
```python
from ..identity.store import IdentityStore               # identity/store.py:49 (exchange.py:15 imports it the same way)
from ..responses import JSONResponse                     # responses.py:75
```

### Existing Signatures to Use
```python
class IdentityStore:
    def __init__(self, db_pool, cipher=None)              # identity/store.py:52 — cipher defaults to IdentityCipher()
    async def list_for_user(self, user_id) -> list[dict]  # :199 — masked rows, [] when none
# Precedent for building it per request — exchange.py:55-56:
def _identity_store(self, request): return IdentityStore(request.app["authdb"])
# BasicAuth password attribute name: pwd_atrribute = "password" (basic.py:47 — note the typo, use it as is)
# TASK-88 PasskeyStore: list_credentials(user_id, rp_id=None), rename_credential(user_id, id, label) -> bool,
#   delete_credential(user_id, id) -> bool, count_credentials(user_id) -> int
# TASK-93: _session_user(request), PASSKEY_PREFIX, configure(app)
```
- `IdentityCipher()` may raise `ConfigError` when vault keys are not configured. Treat that as
  "no linked identity can be checked": log it, and count only the password.

### Does NOT Exist
- `PasskeyStore.has_other_login_method`. The rule lives in the backend (this task).
- A `{id}` that is anything but base64url. Decode it with `base64url_to_bytes`; a bad value returns 404.

---

## Implementation Blueprint

### Steps (in order)
1. Add the three `router.add_route` calls in `configure`, next to the ceremony routes.
2. Implement the methods. Check ownership in SQL (TASK-88's methods filter by `user_id`), so a
   foreign id is indistinguishable from a missing one: 404 in both cases.
3. Write the live test, covering every branch including 409.

### `navigator_auth/backends/passkey.py` — MODIFY
```python
# In configure(), AFTER the `passkey_login_options` add_route (created by TASK-93; occurrences: 1):
        router.add_route("GET", f"{PASSKEY_PREFIX}/credentials", self.list_credentials,
                         name="passkey_credentials")
        router.add_route("PATCH", f"{PASSKEY_PREFIX}/credentials/{{id}}", self.rename_credential,
                         name="passkey_credential_rename")
        router.add_route("DELETE", f"{PASSKEY_PREFIX}/credentials/{{id}}", self.delete_credential,
                         name="passkey_credential_delete")

# New methods on PasskeyAuth:
    async def list_credentials(self, request: web.Request) -> web.Response:
        """The caller's passkeys across all RPs (no key material)."""
        user = self._session_user(request)
        creds = await self._store.list_credentials(user.user_id)
        # FILL IN: JSONResponse([{id: b64url, label, created_at, last_used_at, device_type,
        #          backed_up, rp_id} for c in creds]) — never public_key/sign_count.

    async def rename_credential(self, request: web.Request) -> web.Response:
        """Rename one of the caller's passkeys."""
        user = self._session_user(request)
        # FILL IN: decode request.match_info["id"] (bad ⇒ 404); body label 1..128 (else 400);
        #          store.rename_credential False ⇒ 404; JSONResponse({"status": "renamed"}).

    async def delete_credential(self, request: web.Request) -> web.Response:
        """Delete one of the caller's passkeys; 409 when it would lock the user out (E13)."""
        user = self._session_user(request)
        # FILL IN: decode id (bad ⇒ 404); ownership: id must be among list_credentials(user_id) ⇒ else 404;
        #          if count_credentials == 1 and not await self._has_other_login_method(user.user_id):
        #              raise web.HTTPConflict(reason="Passkey: cannot delete the last login method")
        #          store.delete_credential; web.HTTPNoContent semantics (return web.Response(status=204)).

    async def _has_other_login_method(self, user_id: int) -> bool:
        """True when the user has a password or at least one linked external identity."""
        # FILL IN: user = await self._idp.user_from_id(user_id); password via Mapping.get/getattr
        #          (self.pwd_atrribute) non-empty ⇒ True; else IdentityStore(self._app["authdb"])
        #          .list_for_user(user_id) non-empty ⇒ True (ConfigError ⇒ log, treat as none).
```
**Why**: The 409 rule protects the user from self-lockout. It only applies when the passkey is
truly their last way in, so a user with a password can always remove all their passkeys.

### `tests/test_passkey_management.py` — CREATE
```python
"""FEAT-101 TASK-96 — passkey credential management, live (Postgres + Redis)."""
import pytest

from tests.fixtures.passkey import passkey_app, passkey_rp_config, soft_authenticator  # noqa: F401

pytestmark = pytest.mark.asyncio(loop_scope="module")


async def test_manage_list_rename_delete(passkey_app, soft_authenticator):
    """List (no key material), rename (400/404/200), delete (404, 204, and 409 for the last
    credential of a user with no password and no identity — E13)."""
    # FILL IN: seed a second user with password NULL and no user_identities rows for the 409 case.
```

### FILL IN checklist
- [ ] List serialisation.
- [ ] Rename validation and the 404 mapping.
- [ ] Delete with the E13 rule.
- [ ] `_has_other_login_method`.
- [ ] Live test covering every branch.

---

## Acceptance Criteria

- [ ] AC12: list, rename and delete work, and E13 returns 409.
- [ ] Without a session, all three endpoints return 401. Cookie-only PATCH or DELETE without `X-CSRF-Token` returns 403.
- [ ] `pytest tests/test_passkey_management.py -v` passes.
- [ ] `ruff check navigator_auth/backends/passkey.py tests/test_passkey_management.py` shows no new findings.

---

## Test Specification

See the blueprint above (spec §4: `test_manage_list_rename_delete`).

---

## Agent Instructions

1. Read the spec (Module 7, §2.9).
2. Confirm TASK-95 is in `sdd/tasks/completed/`.
3. Set this task to `"in-progress"` in `sdd/tasks/index/passkey-support-backend.json`.
4. Implement inside `.worktrees/feat-FEAT-101-passkey-support-backend`.
5. Verify the acceptance criteria.
6. Move this file to `sdd/tasks/completed/`, set the index entry to `"done"`, and fill in the Completion Note.

---

## Completion Note

**Completed by**: sdd-worker (Sonnet 5.5, sequential fallback)
**Date**: 2026-10-02
**Notes**: list/rename/delete routes and _has_other_login_method (E13). 3 live tests pass; foreign credential returns 404; last-credential no-password returns 409.
**Deviations from spec**: none
