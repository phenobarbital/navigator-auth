# TASK-063: `PasswordPolicy` validator

**Feature**: FEAT-098 backend-based-password-recovery
**Spec**: `sdd/specs/backend-based-password-recovery.spec.md` (Module 2)
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-062
**Assigned-to**: unassigned

---

## Context

Nothing in navigator-auth validates password strength today. Step 3 of the
recovery flow (TASK-067) needs it, and so will any future "change password"
screen, so it is built as a standalone, dependency-free validator rather than
inline in the handler.

Pure function, no I/O — the easiest task in the feature to verify and the safest
to run in parallel.

---

## Scope

- Implement `PasswordPolicy` in `navigator_auth/handlers/recovery/policy.py`.
- `validate()` returns **every** violation, not just the first, so a front-end
  can render the full checklist at once.
- Defaults come from the `AUTH_RECOVERY_PWD_*` keys added in TASK-062.

**NOT in scope**: HTTP status codes or error payload shaping (TASK-067), the
token store, the rate limiter, any Redis or database access. This module must
import nothing from `redis`, `aiohttp` or `navigator`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/handlers/recovery/policy.py` | CREATE | `PasswordPolicy` |
| `tests/test_password_recovery.py` | MODIFY | Add `TestPasswordPolicy` |

---

## Implementation Notes

### Interface (from the spec)

```python
class PasswordPolicy:
    def __init__(self, min_length: int = 8, require_letter: bool = True,
                 require_digit: bool = True, reject_current: bool = True): ...

    def validate(self, password: str, current_hash: str = None) -> list[PolicyViolation]:
        """Empty list == valid."""
```

### Rules and their `rule` slugs

| Slug | Condition |
|---|---|
| `min_length` | `len(password) < min_length` |
| `needs_letter` | no `[A-Za-z]` present (when `require_letter`) |
| `needs_digit` | no `[0-9]` present (when `require_digit`) |
| `same_as_current` | `check_password(current_hash, password)` is `True` (when `reject_current` and a hash was supplied) |

### Key Constraints

- **Return all violations.** `"abc"` must yield both `min_length` and
  `needs_digit`. Do not short-circuit on the first failure.
- Use `check_password` from `navigator_auth.handlers.users.passwd` for the
  `same_as_current` check — it already does the constant-time comparison. Never
  re-implement hash comparison here.
- Handle `current_hash=None` (a federated user with no local password, D10) by
  skipping the `same_as_current` rule rather than raising.
- `check_password` raises `AuthException` on a malformed stored hash
  (`passwd.py:33`). Catch it and treat the rule as *not violated* — a corrupt
  existing hash must not block a user from setting a new password.
- Messages are human-readable and safe to show a user; they must not echo the
  password back.

### References in Codebase
- `navigator_auth/handlers/users/passwd.py:29` — `check_password`
- `navigator_auth/handlers/recovery/types.py` — `PolicyViolation` (TASK-062)

---

## Acceptance Criteria

- [ ] `from navigator_auth.handlers.recovery.policy import PasswordPolicy` works
- [ ] Module imports nothing from `redis`, `aiohttp` or `navigator`
- [ ] `validate()` returns every applicable violation, not just the first
- [ ] `current_hash=None` skips `same_as_current` without raising
- [ ] A malformed `current_hash` does not propagate `AuthException`
- [ ] Violation messages never contain the candidate password
- [ ] `pytest tests/test_password_recovery.py -k Policy -v` passes

---

## Test Specification

```python
class TestPasswordPolicy:
    def test_policy_accepts_valid(self):
        assert PasswordPolicy().validate("abc12345") == []

    def test_policy_min_length(self):
        v = PasswordPolicy().validate("abc1234")      # 7 chars
        assert [x.rule for x in v] == ["min_length"]

    def test_policy_requires_letter_and_digit(self):
        assert "needs_letter" in [x.rule for x in PasswordPolicy().validate("12345678")]
        assert "needs_digit" in [x.rule for x in PasswordPolicy().validate("abcdefgh")]

    def test_policy_returns_all_violations(self):
        rules = {x.rule for x in PasswordPolicy().validate("abc")}
        assert rules == {"min_length", "needs_digit"}

    def test_policy_rejects_current_password(self):
        from navigator_auth.handlers.users.passwd import set_basic_password
        h = set_basic_password("abc12345")
        v = PasswordPolicy().validate("abc12345", current_hash=h)
        assert [x.rule for x in v] == ["same_as_current"]

    def test_policy_no_current_hash_is_fine(self):
        assert PasswordPolicy().validate("abc12345", current_hash=None) == []

    def test_policy_malformed_current_hash_does_not_raise(self):
        assert PasswordPolicy().validate("abc12345", current_hash="garbage") == []

    def test_policy_message_never_echoes_password(self):
        for v in PasswordPolicy().validate("a"):
            assert "a" not in v.message.replace("at least", "")  # no echo of the input
```

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — verify TASK-062 is in `sdd/tasks/completed/`
3. **Update status** in `sdd/tasks/.index.json` → `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `sdd/tasks/completed/TASK-063-password-policy-validator.md`
7. **Update index** → `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
