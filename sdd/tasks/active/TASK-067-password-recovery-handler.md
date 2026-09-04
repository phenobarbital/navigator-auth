# TASK-067: `PasswordRecoveryHandler` — the three endpoints and routing

**Feature**: FEAT-098 backend-based-password-recovery
**Spec**: `sdd/specs/backend-based-password-recovery.spec.md` (Module 6)
**Status**: pending
**Priority**: high
**Estimated effort**: L (4-8h)
**Depends-on**: TASK-062, TASK-063, TASK-064, TASK-065, TASK-066
**Assigned-to**: unassigned

---

## Context

The integration task: assembles the store, policy, limiter and revoker into the
three-step HTTP flow, and finally deletes the broken
`navigator_auth/handlers/recovery.py`.

Everything security-relevant that is *not* in the other modules lives here — the
uniform response, the latency padding, and keeping the token out of responses
and logs.

---

## Scope

- Implement `PasswordRecoveryHandler(BaseView)` in
  `navigator_auth/handlers/recovery/handler.py` with the three endpoints.
- E-mail lookup (`email` and `alt_email`).
- Callback invocation with `NotificationPayload`.
- Register routes; repoint the two legacy routes as aliases.
- **Delete** the old `ForgotPasswordHandler`, `ResetPasswordHandler` and
  `RecoveryTokenStorage`.

**NOT in scope**: end-to-end tests and docs (TASK-068). Write enough tests to
prove each endpoint; the enumeration/timing suite belongs to TASK-068.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/recovery/handler.py` | CREATE | `PasswordRecoveryHandler` |
| `navigator_auth/handlers/recovery.py` | DELETE | Replaced by the package |
| `navigator_auth/handlers/__init__.py` | MODIFY | Routes; update the import at line 14 |
| `tests/test_password_recovery.py` | MODIFY | Add `TestRecoveryEndpoints` |

---

## Implementation Notes

### Routes

| Verb | Path | Step |
|---|---|---|
| POST | `/api/v1/password-recovery` | 1 — request |
| GET | `/api/v1/password-recovery/{token}` | 2 — validate, mint confirmation |
| POST | `/api/v1/password-recovery/confirm` | 3 — set password |

Register the literal `confirm` route **before** the `{token}` route, or
`confirm` will be captured as a token. `handlers/__init__.py:64` already has this
exact ordering problem solved for the identity routes — follow that comment.

Legacy aliases: `/api/v1/forgot-password` → step 1,
`/api/v1/reset-password` → step 3.

### Step 1 — the delicate one

```
1. rate-limit check (email, then IP)  -> over limit: generic 200/429
2. look up the user by email/alt_email
3. on hit:  store.issue_recovery(user)  -> callback(found=True, token, url)
   on miss: no token, no Redis write    -> callback(found=False)
4. pad elapsed time to the floor, then return the SAME generic body
```

- **The response never contains the token.** Same body, same status, for hit and
  miss (D1, D9).
- **Latency padding**: a hit queries Postgres, a miss may not — the delta alone
  leaks whether an account exists. Measure elapsed time and sleep to a fixed
  floor (~250 ms) on **both** paths before responding.
- `AUTH_RECOVERY_URL_TEMPLATE.format(token=token)` builds the link. If the
  template is unset, log an error and still return the generic body — a
  misconfiguration must not reveal anything to the caller.
- Callback failures are caught, logged, and **do not** change the response.
- Rate-limit rejection should also return the generic body (a distinct 429 tells
  an attacker the address is being tracked; prefer the generic 200 unless you
  have a reason otherwise — note your choice in the Completion Note).

### Step 2

- `store.validate_recovery(token)` → miss/expired/bad signature = **400**, with a
  message that does not distinguish those cases.
- On success, `store.issue_confirmation(token)` and return
  `{"token": ..., "expires_in": 900, "username": ...}`.
- The stage-1 token is **not** consumed (D4) — refresh and back-button must work.

### Step 3

```
1. password == confirm_password                  -> 400
2. store.consume_confirmation(token)             -> 400 if absent (GETDEL, single use)
3. policy.validate(password, current_hash)       -> 422 {violations}
4. user.password = set_basic_password(password); user.is_new = False; update()
5. store.drop_pair(recovery_key, confirm_key)
6. revoker.revoke_user(request, user)
7. 202 {"action": "Password was changed successfully", "status": "OK"}
```

**Ordering trap**: step 2 consumes the confirmation token before the policy check
at step 3, so a weak password would burn the token and force the user back to
step 2. The spec requires a policy failure to leave the tokens **intact**
(`test_step3_policy_violation`). Therefore: **validate the policy before
consuming**, or re-issue on failure. Validating first is simpler — do that.

- **No auto-login** (D15): return no `token` / `refresh_token`.
- `is_new = False` (D17). Note the superuser `password_reset`
  (`handlers/users/session.py:170`) deliberately sets it `True`; do not
  "harmonise" them.

### E-mail lookup

`idp.get_user()` searches `username_attribute` only (`idp/__init__.py:145`) and
**cannot** be reused. Query `User` by `email`, falling back to `alt_email`.

`User.email` has no unique constraint: if the query returns more than one row,
**refuse to guess** — log a warning and take the generic not-found path.

Federated users with no local password must be allowed through (D10) — a `None`
password is not an error, and `PasswordPolicy` already tolerates
`current_hash=None`.

### Key Constraints

- `BaseView` response helpers (`self.json_response`, `self.error`,
  `self.critical`) — not raw `web.HTTP*`. Match `UserSession`.
- **Never log the raw token**, at any level, including the step-2 request path.
- One shared `ConnectionPool`, created at startup — never `redis.from_url()` per
  request (the mistake in the module being deleted).

### References in Codebase
- `navigator_auth/handlers/users/session.py:17` — `UserSession(BaseHandler)`, the response-helper style
- `navigator_auth/handlers/__init__.py:64` — literal-before-parameter route ordering
- `navigator_auth/handlers/users/passwd.py:12` — `set_basic_password`

---

## Acceptance Criteria

- [ ] Three routes resolve; `confirm` is not captured by `{token}`
- [ ] Legacy `/api/v1/forgot-password` and `/api/v1/reset-password` reach the new handler
- [ ] Step 1 returns an identical body and status for known and unknown addresses
- [ ] Step 1 never returns the token, for any input
- [ ] Step 2 can be called repeatedly; the newest confirmation wins, stage-1 survives
- [ ] Step 3 with a weak password returns 422 and leaves **both** tokens usable
- [ ] Step 3 success: password changed, `is_new` False, both records gone, sessions revoked
- [ ] Replaying step 3 returns 400
- [ ] No response contains `token`/`refresh_token` (no auto-login)
- [ ] A duplicate e-mail takes the generic not-found path and logs a warning
- [ ] `caplog` contains no raw token after a full flow
- [ ] Old `recovery.py` is deleted; nothing imports it
- [ ] `pytest tests/ -v` passes

---

## Test Specification

```python
class TestRecoveryEndpoints:
    async def test_step1_never_returns_token(self, client): ...
    async def test_step1_unknown_email_same_body(self, client): ...
    async def test_step1_invokes_callback_with_url(self, client, captured_callback): ...
    async def test_callback_failure_does_not_leak(self, client, raising_callback): ...
    async def test_step2_refresh_is_safe(self, client): ...
    async def test_step3_password_mismatch(self, client): ...
    async def test_step3_policy_violation_keeps_tokens(self, client):
        """422, and the user can retry with the SAME confirmation token."""
    async def test_step3_success(self, client): ...
    async def test_step3_replay_rejected(self, client): ...
    async def test_no_autologin(self, client): ...
    async def test_duplicate_email_takes_generic_path(self, client, caplog): ...
    async def test_legacy_routes_aliased(self, client): ...
    async def test_token_never_logged(self, client, caplog): ...
```

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify TASK-062…066 are all in `sdd/tasks/completed/`
3. **Update status** in `sdd/tasks/.index.json` → `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `sdd/tasks/completed/TASK-067-password-recovery-handler.md`
7. **Update index** → `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
