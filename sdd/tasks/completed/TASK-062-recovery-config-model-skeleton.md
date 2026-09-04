# TASK-062: Recovery config keys, package skeleton, and `User.password` width fix

**Feature**: FEAT-098 backend-based-password-recovery
**Spec**: `sdd/specs/backend-based-password-recovery.spec.md` (Module 1)
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Foundation task. Every other FEAT-098 task imports the `AUTH_RECOVERY_*` config
keys and the `types.py` dataclasses created here. Front-loading **all** config
into this one task is deliberate: it is what makes TASK-063/064/065/066 safe to
run in four parallel worktrees, because no later task then needs to touch
`conf.py`.

This task also carries a small, unrelated fix the spec surfaced: `User.password`
is declared `max=16` while a real PBKDF2 hash is 77 characters.

---

## Scope

- Add the eleven `AUTH_RECOVERY_*` settings to `navigator_auth/conf.py`.
- Create the `navigator_auth/handlers/recovery/` package with `__init__.py` and
  `types.py` (the four frozen dataclasses from the spec's Data Models section).
- Add the `FORGOT_PASSWORD_CALLBACK` deprecation shim.
- Fix `User.password` `max=16` → `max=255`.

**NOT in scope**: the token store (TASK-064), the policy validator (TASK-063),
the rate limiter (TASK-065), any `jti` work (TASK-066), the handler or routes
(TASK-067). Do **not** delete the existing `handlers/recovery.py` yet —
TASK-067 replaces it. The new package is `handlers/recovery/`, which will
shadow the module; create the package and leave the old `recovery.py` in place
until TASK-067 removes it, or move it aside as `recovery_legacy.py` if the
import collision blocks you (note whichever you chose in the Completion Note).

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/conf.py` | MODIFY | Add the `AUTH_RECOVERY_*` block after the `TOKEN_EXCHANGE_*` block (~line 578) |
| `navigator_auth/handlers/recovery/__init__.py` | CREATE | Package exports |
| `navigator_auth/handlers/recovery/types.py` | CREATE | `RecoveryPayload`, `ConfirmationPayload`, `NotificationPayload`, `PolicyViolation` |
| `navigator_auth/models.py` | MODIFY | Line 51: `max=16` → `max=255` |
| `tests/test_password_recovery.py` | CREATE | Config-defaults and password-width tests |

---

## Implementation Notes

### Config keys (all new)

Add after the `TOKEN_EXCHANGE_PROVIDERS` block in `conf.py` (~line 578), so this
task owns a single contiguous hunk and does not conflict with FEAT-097, which
also adds keys to this file.

| Key | Default | Purpose |
|---|---|---|
| `AUTH_RECOVERY_SECRET` | falls back to `SECRET_KEY` | HMAC key for both stages |
| `AUTH_RECOVERY_TTL` | `3600` | stage-1 lifetime (seconds) |
| `AUTH_RECOVERY_CONFIRM_TTL` | `900` | stage-2 lifetime (seconds) |
| `AUTH_RECOVERY_CALLBACK` | `None` | dotted path to the notification callable |
| `AUTH_RECOVERY_URL_TEMPLATE` | `None` | e.g. `https://app/reset?token={token}` |
| `AUTH_RECOVERY_RATE_EMAIL` | `"3/hour"` | per-address limit |
| `AUTH_RECOVERY_RATE_IP` | `"10/hour"` | per-IP limit |
| `AUTH_RECOVERY_PWD_MIN_LENGTH` | `8` | policy |
| `AUTH_RECOVERY_PWD_REQUIRE_LETTER` | `True` | policy |
| `AUTH_RECOVERY_PWD_REQUIRE_DIGIT` | `True` | policy |

Use `config.get` / `config.getint` / `config.getboolean` exactly as the
surrounding code does. `AUTH_RECOVERY_SECRET` must fall back to `SECRET_KEY`
when unset, and must end up as `bytes` for `hmac.new()`.

### Deprecation shim

`FORGOT_PASSWORD_CALLBACK` is the old name read by the current
`handlers/recovery.py:80`. When it is set and `AUTH_RECOVERY_CALLBACK` is not,
use it and emit a `DeprecationWarning` naming the replacement.

### `User.password` fix

`navigator_auth/models.py:51`:

```python
# before
password: str = Column(required=False, max=16, secret=True, repr=False)
# after
password: str = Column(required=False, max=255, secret=True, repr=False)
```

Why 255, verified 2026-09-04:
- `set_basic_password()` at current defaults yields exactly **77** chars:
  `pbkdf2_sha256$80000$<12-hex-salt>$<44-char-b64>` = 13+1+5+1+12+1+44.
- `max=` is **not enforced** today (a 77-char value constructs and `is_valid()`
  returns `True`), so this changes no behaviour now — but the day it *is*
  enforced, every password write in the project breaks.
- The reference DDL already declares `password VARCHAR(255)`
  (`examples/sql/identity_vault_schema.sql:37`), so **no migration is needed**;
  this only aligns the model with the column, matching how `email`/`username`
  pair `max=254` with `VARCHAR(254)`.
- 255 leaves headroom: even sha512 with `AUTH_PWD_LENGTH=64` (88-char hash), a
  32-char salt and 7-digit iterations reaches only ~123.

### References in Codebase
- `navigator_auth/conf.py:565-578` — `TOKEN_EXCHANGE_*` block, the insertion point and style to copy
- `navigator_auth/handlers/users/passwd.py:12` — `set_basic_password`, the hash format
- `examples/sql/identity_vault_schema.sql:37` — the `VARCHAR(255)` column

---

## Acceptance Criteria

- [ ] All eleven keys importable from `navigator_auth.conf` with the documented defaults
- [ ] `AUTH_RECOVERY_SECRET` falls back to `SECRET_KEY` when unset, and is `bytes`
- [ ] Setting only `FORGOT_PASSWORD_CALLBACK` still works and emits a `DeprecationWarning`
- [ ] The four dataclasses import from `navigator_auth.handlers.recovery.types` and are frozen
- [ ] `NotificationPayload.__repr__` does **not** include the `token` field
- [ ] `User.password` declares `max=255`; a real 77-char hash round-trips through the model
- [ ] `pytest tests/test_password_recovery.py -v` passes
- [ ] `tests/test_basic_auth.py` and `tests/test_login.py` pass unmodified

---

## Test Specification

```python
# tests/test_password_recovery.py
import pytest
from navigator_auth.handlers.users.passwd import set_basic_password
from navigator_auth.models import User


class TestRecoveryConfig:
    def test_defaults(self):
        from navigator_auth import conf
        assert conf.AUTH_RECOVERY_TTL == 3600
        assert conf.AUTH_RECOVERY_CONFIRM_TTL == 900
        assert conf.AUTH_RECOVERY_RATE_EMAIL == "3/hour"
        assert conf.AUTH_RECOVERY_RATE_IP == "10/hour"
        assert conf.AUTH_RECOVERY_PWD_MIN_LENGTH == 8

    def test_secret_falls_back_to_secret_key(self):
        from navigator_auth import conf
        assert conf.AUTH_RECOVERY_SECRET
        assert isinstance(conf.AUTH_RECOVERY_SECRET, bytes)


class TestUserPasswordWidth:
    def test_user_password_column_fits_hash(self):
        """A real PBKDF2 hash (77 chars) must fit the declared max."""
        h = set_basic_password("correct horse battery staple")
        assert len(h) == 77
        col = User.get_columns()["password"]
        assert col.metadata.get("max", 0) >= len(h)

    def test_hash_roundtrips_through_model(self):
        h = set_basic_password("correct horse battery staple")
        u = User(user_id=1, username="t", password=h)
        assert u.password == h
        assert u.is_valid()


class TestNotificationPayloadSecrecy:
    def test_repr_hides_token(self):
        from navigator_auth.handlers.recovery.types import NotificationPayload
        import datetime
        p = NotificationPayload(
            email="a@b.c", display_name="A", username="a",
            token="SUPERSECRETTOKEN", url="https://x/?token=SUPERSECRETTOKEN",
            expires_at=datetime.datetime.now(), found=True,
        )
        assert "SUPERSECRETTOKEN" not in repr(p)
```

---

## Agent Instructions

When you pick up this task:

1. **Read the spec** at the path listed above for full context
2. **Check dependencies** — none; this task runs first
3. **Update status** in `sdd/tasks/.index.json` → `"in-progress"` with your session ID
4. **Implement** following the scope and notes above
5. **Verify** all acceptance criteria are met
6. **Move this file** to `sdd/tasks/completed/TASK-062-recovery-config-model-skeleton.md`
7. **Update index** → `"done"`
8. **Fill in the Completion Note** below

---

## Completion Note

**Completed by**: sdd-worker (session_016Z3wYUV42WJDq92pifU1Fa)
**Date**: 2026-09-04
**Notes**: Added the eleven AUTH_RECOVERY_*/FORGOT_PASSWORD_CALLBACK keys to
`conf.py` right after `TOKEN_EXCHANGE_PROVIDERS`. `AUTH_RECOVERY_SECRET`
falls back to `SECRET_KEY` and is always coerced to `bytes`.
`FORGOT_PASSWORD_CALLBACK` emits a `DeprecationWarning` and feeds
`AUTH_RECOVERY_CALLBACK` when the latter is unset. Created
`navigator_auth/handlers/recovery/{__init__,types}.py` with the four
frozen dataclasses; `NotificationPayload` has a custom `__repr__` that
redacts `token`/`url`. Fixed `User.password` `max=16` -> `max=255` in
`models.py`. All 5 tests in `tests/test_password_recovery.py` pass.
`tests/test_basic_auth.py`/`tests/test_login.py` show the same
pre-existing connection-refused failures (no live server/DB in this
sandbox) both before and after this change — confirmed identical on
unmodified `dev`, so no regression was introduced.

**Deviations from spec**: The task anticipated that the new
`handlers/recovery/` package would collide with the existing
`handlers/recovery.py` module, and explicitly authorized renaming the
legacy module to `recovery_legacy.py` if that blocked implementation.
It did block implementation (Python's package-over-module import
precedence makes the new package shadow `recovery.py`, breaking
`handlers/__init__.py`'s `from .recovery import ForgotPasswordHandler,
ResetPasswordHandler`). Renamed `navigator_auth/handlers/recovery.py`
-> `navigator_auth/handlers/recovery_legacy.py` and updated the one
import line in `navigator_auth/handlers/__init__.py` accordingly. Both
files are outside the task's Files table but the rename path was
explicitly sanctioned by the task text; TASK-067 will delete
`recovery_legacy.py` once the new handler replaces it.
