# TASK-068: End-to-end tests, documentation, and version bump

**Feature**: FEAT-098 backend-based-password-recovery
**Spec**: `sdd/specs/backend-based-password-recovery.spec.md` (Module 7)
**Status**: pending
**Priority**: medium
**Estimated effort**: M (2-4h)
**Depends-on**: TASK-067
**Assigned-to**: unassigned

---

## Context

Closes the feature. The security properties the earlier tasks *claim* are only
actually guaranteed once tested end to end — particularly the two that no single
module owns: **non-enumerability** (identical body, status and latency) and
**token secrecy** (never in a response, never in Redis, never in a log).

---

## Scope

- Full-flow integration tests (steps 1→2→3, then log in with the new password).
- The enumeration/timing test.
- The token-secrecy sweep.
- Document the callback contract and every `AUTH_RECOVERY_*` key.
- Bump the version to `0.27.0`.

**NOT in scope**: new behaviour. If a test reveals a defect, fix it here and note
it in the Completion Note.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `tests/test_password_recovery.py` | MODIFY | `TestRecoveryEndToEnd` |
| `docs/` | CREATE/MODIFY | Recovery flow + callback contract |
| `navigator_auth/version.py` | MODIFY | `0.25.0` → `0.27.0` |
| `CHANGELOG.md` | MODIFY | Feature entry |

---

## Implementation Notes

### The timing test needs care to not be flaky

Assert the *difference* between known and unknown is small relative to the
padding floor, rather than asserting absolute latency. Take the median of
several runs; a single sample will flake in CI.

```python
async def test_step1_unknown_email_identical(self, client):
    known   = median(await timed_post(client, KNOWN_EMAIL)   for _ in range(5))
    unknown = median(await timed_post(client, UNKNOWN_EMAIL) for _ in range(5))
    assert abs(known - unknown) < 0.05          # 50 ms of a ~250 ms floor
```

### Version

`0.25.0` is current (FEAT-096 bumped it). FEAT-097 takes `0.26.0`. This feature
is **`0.27.0`**. If FEAT-097 has not landed when you get here, still use
`0.27.0` — do not renumber.

### Docs to write

- The three endpoints with request/response examples.
- **The callback contract** — the `NotificationPayload` fields, that `found=False`
  means no account existed, and that a raising callback is swallowed.
- Every `AUTH_RECOVERY_*` key with its default.
- A migration note: `FORGOT_PASSWORD_CALLBACK` is deprecated in favour of
  `AUTH_RECOVERY_CALLBACK`, whose payload is richer.
- The security properties an operator relies on: no enumeration, single-use
  confirmation, both records dropped, sessions revoked.

### References in Codebase
- `docs/` — existing docs layout
- FEAT-096's TASK-053 (`sdd/tasks/completed/`) — the analogous docs+version task

---

## Acceptance Criteria

- [ ] Full flow passes: request → validate → confirm → log in with the new password
- [ ] Known vs unknown e-mail: identical status, identical body, median latency
      delta under 50 ms
- [ ] The raw token appears in **no** response body and **no** log record
- [ ] Scanning all Redis keys and values after a flow finds no raw token
- [ ] A pre-reset JWT is rejected after the reset
- [ ] `test_federated_user_can_recover` passes (D10)
- [ ] `test_step3_sets_is_new_false` passes (D17)
- [ ] Rate limit: 4th request for one address within the hour is refused
- [ ] `pytest tests/ -v` fully green, including `test_basic_auth.py` and
      `test_login.py` **unmodified**
- [ ] Docs cover the callback contract and all eleven config keys
- [ ] Version is `0.27.0`; CHANGELOG updated

---

## Test Specification

```python
class TestRecoveryEndToEnd:
    async def test_full_recovery_flow(self, client, captured_callback):
        """1 -> 2 -> 3, then the user logs in with the new password."""

    async def test_step1_unknown_email_identical(self, client):
        """D9 — body, status and median latency indistinguishable."""

    async def test_token_never_leaks(self, client, caplog, redis):
        """Not in any response, log record, or Redis key/value."""

    async def test_step3_revokes_sessions(self, client):
        """A JWT and session issued before the reset are dead after it."""

    async def test_federated_user_can_recover(self, client):
        """D10 — a user with no local password completes the flow."""

    async def test_step3_sets_is_new_false(self, client): ...
    async def test_rate_limit_per_email(self, client): ...
    async def test_step3_recovery_token_dead_after_success(self, client): ...
```

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify TASK-067 is in `sdd/tasks/completed/`
3. **Update status** in `sdd/tasks/.index.json` → `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `sdd/tasks/completed/TASK-068-recovery-e2e-docs-version.md`
7. **Update index** → `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
