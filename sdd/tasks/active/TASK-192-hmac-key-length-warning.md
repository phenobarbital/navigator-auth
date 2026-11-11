# TASK-192: HMAC key-length startup warning

**Feature**: FEAT-109 — PBAC example policy issues
**Spec**: `sdd/specs/policy-issues.spec.md`
**Status**: pending
**Priority**: medium
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

PyJWT emits `InsecureKeyLengthWarning: The HMAC key is 6 bytes long` on every token because
`AUTH_SECRET_KEY` is 6 characters in the operator's `env/.env`, and `PARTNER_KEY` (the
`AUTH_TOKEN_SECRET` fallback) is 16 bytes (spec §1 problem 3). Nothing checks key length at
startup. This task implements spec §3 **Module 4**: a new `navigator_auth/libs/hmac_keys.py` that
measures the configured HMAC keys and logs one WARNING per key under 32 bytes on the
`navigator_auth.security` logger; `AuthHandler.setup` calls it once; `docs/settings.rst` documents
the minimum. Rotating the real secrets is an operator step (`env/` is git-ignored) — not this task.

---

## Scope

- Create `navigator_auth/libs/hmac_keys.py` with `MIN_HMAC_KEY_BYTES`, `SECURITY_LOGGER`,
  `configured_hmac_keys()`, `short_hmac_keys()`, `warn_short_hmac_keys()`.
- Call `warn_short_hmac_keys()` once in `AuthHandler.setup`, right after the exclude-list seed (auth.py:670).
- Add a "Signing keys" section to `docs/settings.rst` before "Backend-Based Password Recovery (FEAT-098)".
- Write `tests/test_hmac_key_strength.py`.

**NOT in scope**: raising or refusing to start on short keys; `warnings.warn` (pytest runs with
`filterwarnings = ["error"]`); changing `conf.py` key loading; rotating `env/.env` values;
PyJWT's own `InsecureKeyLengthWarning`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/libs/hmac_keys.py` | CREATE | key collection, measurement and WARNING logging |
| `navigator_auth/auth.py` | MODIFY | import + one `warn_short_hmac_keys()` call in `AuthHandler.setup` |
| `docs/settings.rst` | MODIFY | "Signing keys" section (32-byte minimum + generation command) |
| `tests/test_hmac_key_strength.py` | CREATE | unit tests for the three functions + the setup call |

---

## Codebase Contract (Anti-Hallucination)

> Verified against `dev` HEAD `c5403d4` on 2026-11-11.

### Verified Imports
```python
# hmac_keys.py
import logging
from collections.abc import Mapping
from .. import conf                     # style verified: navigator_auth/middlewares/protected_paths.py:27
# conf attributes read at CALL time (so tests can monkeypatch them):
#   conf.SECRET_KEY            conf.py:328 (str from AUTH_SECRET_KEY, or random 32 bytes fallback 329-331)
#   conf.PARTNER_KEY           conf.py:367 (str or None)
#   conf.AUTH_TOKEN_SECRET     conf.py:372 (fallback=PARTNER_KEY)
#   conf.AUTH_RECOVERY_SECRET  conf.py:646-650 (falls back to SECRET_KEY; always coerced to bytes)
# auth.py
from .libs.hmac_keys import warn_short_hmac_keys   # new; place after auth.py:40 `from .libs.expiry import expiry_fields`
# tests
from aiohttp import web
from navigator_auth import conf
from navigator_auth.libs.hmac_keys import (
    MIN_HMAC_KEY_BYTES, SECURITY_LOGGER, configured_hmac_keys, short_hmac_keys, warn_short_hmac_keys,
)
import navigator_auth.auth as auth_mod          # AuthHandler lives here (auth.py)
```

### Existing Signatures to Use
```python
# navigator_auth/middlewares/probes.py:31
SECURITY_LOGGER = "navigator_auth.security"   # reuse the NAME (define the same constant in hmac_keys.py;
                                              # do not import probes, it pulls in unrelated machinery)
# navigator_auth/auth.py
class AuthHandler:
    def setup(self, app: web.Application) -> web.Application: ...   # line 641
        # line 670: self.app[AUTH_EXCLUDE_LIST_KEY] = list(exclude_list)   <- insert the call right after
# Test construction pattern (tests/test_protected_paths.py:250-253):
#   with warnings.catch_warnings(): warnings.simplefilter("ignore")
#       AuthHandler(secure_cookies=False, enable_authdb=False)  ; then .setup(web.Application())
```

### Does NOT Exist
- ~~`navigator_auth.libs.hmac_keys`~~ — created by this task; no key-length check exists anywhere today.
- ~~`conf.MIN_HMAC_KEY_BYTES` / an `AUTH_MIN_KEY_BYTES` setting~~ — the threshold is the module constant.
- ~~`conf.AUTH_RECOVERY_SECRET` as `str`~~ — it is always `bytes` after conf.py:649-650.

---

## Complexity Contract

```json
{
  "schema_version": 1,
  "targets": [
    {"path": "navigator_auth/libs/hmac_keys.py", "action": "CREATE"},
    {"path": "navigator_auth/auth.py", "action": "MODIFY"},
    {"path": "docs/settings.rst", "action": "MODIFY"},
    {"path": "tests/test_hmac_key_strength.py", "action": "CREATE"}
  ],
  "contract_symbols": [
    "sym:navigator_auth/auth.py#AuthHandler",
    "sym:navigator_auth/auth.py#AuthHandler.setup"
  ]
}
```

---

## Implementation Notes

### Key Constraints
- **Log, never warn, never raise.** `warn_short_hmac_keys` must not call `warnings.warn` and must
  swallow its own errors (startup must not fail on a diagnostic).
- **Never log the key value** — label and byte length only; on an internal error log the
  exception **type** only.
- `str` keys are measured as UTF-8 bytes.
- New test fixtures must use keys ≥ 32 bytes so PyJWT's own `InsecureKeyLengthWarning` cannot
  trip `filterwarnings = ["error"]`.
- The operator's test env may have a short `AUTH_SECRET_KEY`, so other tests that call
  `AuthHandler.setup` will now see one WARNING on `navigator_auth.security`; check that
  `tests/test_protected_paths.py` and `tests/test_probes.py` (which count records on that logger)
  stay green.

---

## Implementation Blueprint

### Steps (in order)
1. Create `navigator_auth/libs/hmac_keys.py` — *why*: spec §3 M4 skeleton fixes the module path and three functions.
2. Import and call it in `AuthHandler.setup` — *why*: one check per app setup, after the exclude list is seeded.
3. Add the docs section — *why*: AC "docs/settings.rst documents the 32-byte minimum and a generation command".
4. Write the tests; run the Validation Commands.

### `navigator_auth/libs/hmac_keys.py` (CREATE)
```python
"""Startup check for short HMAC signing keys (FEAT-109).

PyJWT warns on every token signed with an HMAC key shorter than the hash
output (RFC 7518 §3.2). ``warn_short_hmac_keys`` checks the configured keys
once at setup and logs one WARNING per short key on the security logger,
naming the setting and its byte length — never the value.
"""
from __future__ import annotations

import logging
from collections.abc import Mapping

from .. import conf

MIN_HMAC_KEY_BYTES: int = 32
SECURITY_LOGGER = "navigator_auth.security"  # same name as middlewares/probes.py:31


def configured_hmac_keys() -> dict[str, str | bytes | None]:
    """Return the configured HMAC keys, read from ``navigator_auth.conf`` at call time.

    Returns:
        ``{setting label: value}``: "AUTH_SECRET_KEY" -> ``conf.SECRET_KEY``;
        "AUTH_TOKEN_SECRET" -> ``conf.AUTH_TOKEN_SECRET`` (labelled
        "AUTH_TOKEN_SECRET (PARTNER_KEY)" when it is the ``PARTNER_KEY`` fallback);
        "AUTH_RECOVERY_SECRET" only when it differs from the encoded
        ``SECRET_KEY`` fallback.
    """
    keys: dict[str, str | bytes | None] = {"AUTH_SECRET_KEY": conf.SECRET_KEY}
    # FILL IN: token_label = "AUTH_TOKEN_SECRET (PARTNER_KEY)" when conf.AUTH_TOKEN_SECRET is not
    #   None and equals conf.PARTNER_KEY, else "AUTH_TOKEN_SECRET" — bounded by spec §3 M4 (conf.py:367,372)
    token_label = "AUTH_TOKEN_SECRET"
    keys[token_label] = conf.AUTH_TOKEN_SECRET
    secret = conf.SECRET_KEY
    fallback = secret.encode("utf-8") if isinstance(secret, str) else secret
    if conf.AUTH_RECOVERY_SECRET != fallback:
        keys["AUTH_RECOVERY_SECRET"] = conf.AUTH_RECOVERY_SECRET
    return keys


def short_hmac_keys(keys: Mapping[str, str | bytes | None]) -> list[tuple[str, int]]:
    """Measure keys against ``MIN_HMAC_KEY_BYTES``.

    Args:
        keys: ``{label: value}``; ``str`` values are measured as UTF-8 bytes.

    Returns:
        ``(label, byte length)`` for every non-empty key shorter than the
        minimum, in input order. None/empty keys are ignored.
    """
    short: list[tuple[str, int]] = []
    for label, value in keys.items():
        if not value:
            continue
        size = len(value.encode("utf-8")) if isinstance(value, str) else len(value)
        if size < MIN_HMAC_KEY_BYTES:
            short.append((label, size))
    return short


def warn_short_hmac_keys(logger: logging.Logger | None = None) -> list[str]:
    """Log one WARNING per configured HMAC key shorter than 32 bytes.

    Args:
        logger: Target logger; defaults to ``logging.getLogger(SECURITY_LOGGER)``.

    Returns:
        The labels of the short keys. Never raises, never calls ``warnings.warn``,
        never logs a key value.
    """
    log = logger or logging.getLogger(SECURITY_LOGGER)
    try:
        short = short_hmac_keys(configured_hmac_keys())
    except Exception as exc:  # pylint: disable=W0703
        log.debug("HMAC key-length check skipped: %s", type(exc).__name__)
        return []
    for label, size in short:
        log.warning(
            "%s is %d bytes; HMAC keys should be at least %d bytes (RFC 7518 §3.2).",
            label, size, MIN_HMAC_KEY_BYTES,
        )
    return [label for label, _ in short]
```
**Why this shape**: spec §3 M4 skeleton (names, signatures, message text, logger name). The
message renders as `'<label> is <n> bytes; HMAC keys should be at least 32 bytes (RFC 7518 §3.2).'`.

### `navigator_auth/auth.py` (MODIFY — import)
```python
# occurrences: 1 (verified: grep -c 'from .libs.expiry import expiry_fields' navigator_auth/auth.py)
# AFTER — insert below `from .libs.expiry import expiry_fields` (verified: auth.py:40)
from .libs.hmac_keys import warn_short_hmac_keys
```

### `navigator_auth/auth.py` (MODIFY — call)
```python
# occurrences: 1 (verified: grep -cF '        self.app[AUTH_EXCLUDE_LIST_KEY] = list(exclude_list)' navigator_auth/auth.py)
# AFTER — insert below `        self.app[AUTH_EXCLUDE_LIST_KEY] = list(exclude_list)` (verified: auth.py:670)
        # FEAT-109: one security WARNING per configured HMAC key under 32 bytes.
        warn_short_hmac_keys()
```

### `docs/settings.rst` (MODIFY)
```rst
.. occurrences: 1 (verified: grep -c 'Backend-Based Password Recovery (FEAT-098)' docs/settings.rst)
.. BEFORE — insert above the heading `Backend-Based Password Recovery (FEAT-098)` (verified: settings.rst:105),
.. keeping one blank line before it:
Signing keys
------------

HMAC signing keys must be at least **32 bytes** (RFC 7518 §3.2). At startup
``AuthHandler.setup`` logs one WARNING on the ``navigator_auth.security`` logger
for each configured key that is shorter, naming the setting and its length in
bytes (never the value).

``AUTH_SECRET_KEY``
   Session/token signing key (``SECRET_KEY``). Minimum 32 bytes.

``AUTH_TOKEN_SECRET`` / ``PARTNER_KEY``
   OAuth2 token signing key; falls back to ``PARTNER_KEY`` when unset.
   Minimum 32 bytes.

Generate a key with::

   python -c "import secrets; print(secrets.token_urlsafe(48))"

```
**Why**: spec §3 M4 — section placement, both settings, and the exact generation command.
Do not paste the `..` instruction lines into the file.

### `tests/test_hmac_key_strength.py` (CREATE)
See **Test Specification** below.

### FILL IN checklist
- [ ] `hmac_keys.py::configured_hmac_keys` — `PARTNER_KEY` label; bounded by spec §3 M4
- [ ] `tests/test_hmac_key_strength.py` — remaining test bodies; bounded by spec §4 M4 rows + AC

---

## Acceptance Criteria

- [ ] `AuthHandler.setup` calls `warn_short_hmac_keys()` exactly once.
- [ ] One WARNING on `navigator_auth.security` per HMAC key under 32 bytes, naming setting and byte length, never the value; no WARNING when all keys are ≥ 32 bytes.
- [ ] No `warnings.warn` call in `navigator_auth/libs/hmac_keys.py` (`grep -c "warnings.warn" navigator_auth/libs/hmac_keys.py` → 0).
- [ ] `docs/settings.rst` documents the 32-byte minimum and `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
- [ ] All Validation Commands pass.

---

## Validation Commands
- `pytest tests/test_hmac_key_strength.py -q`
- `pytest tests/test_protected_paths.py -q`
- `pytest tests/test_probes.py -q`

---

## Test Specification

```python
# tests/test_hmac_key_strength.py
"""HMAC key-length startup warning (FEAT-109 M4)."""
import logging
import warnings
from unittest.mock import MagicMock

import pytest
from aiohttp import web

import navigator_auth.auth as auth_mod
from navigator_auth import conf
from navigator_auth.libs.hmac_keys import (
    SECURITY_LOGGER, configured_hmac_keys, short_hmac_keys, warn_short_hmac_keys,
)

LONG = "k" * 48


@pytest.fixture
def long_keys(monkeypatch):
    """All configured keys >= 32 bytes."""
    monkeypatch.setattr(conf, "SECRET_KEY", LONG)
    monkeypatch.setattr(conf, "PARTNER_KEY", None)
    monkeypatch.setattr(conf, "AUTH_TOKEN_SECRET", LONG + "t")
    monkeypatch.setattr(conf, "AUTH_RECOVERY_SECRET", LONG.encode("utf-8"))


def test_short_hmac_keys_reports_lengths():
    keys = {"A": "abcdef", "B": b"x" * 16, "C": "y" * 32, "D": None}
    assert short_hmac_keys(keys) == [("A", 6), ("B", 16)]


def test_warn_short_hmac_keys_never_logs_value(long_keys, monkeypatch, caplog):
    monkeypatch.setattr(conf, "SECRET_KEY", "s3cr3t")
    caplog.set_level(logging.WARNING, logger=SECURITY_LOGGER)
    assert warn_short_hmac_keys() == ["AUTH_SECRET_KEY"]
    messages = [r.getMessage() for r in caplog.records if r.name == SECURITY_LOGGER]
    assert len(messages) == 1 and "AUTH_SECRET_KEY" in messages[0] and "6 bytes" in messages[0]
    assert "s3cr3t" not in messages[0]


def test_auth_setup_calls_warn_once(monkeypatch):
    spy = MagicMock(return_value=[])
    monkeypatch.setattr(auth_mod, "warn_short_hmac_keys", spy)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        handler = auth_mod.AuthHandler(secure_cookies=False, enable_authdb=False)
    handler.setup(web.Application())
    spy.assert_called_once_with()


# FILL IN: test_configured_hmac_keys_recovery_fallback_skipped (AUTH_RECOVERY_SECRET ==
#   SECRET_KEY.encode() -> no "AUTH_RECOVERY_SECRET" key; a different value -> listed),
#   test_partner_key_fallback_label, test_no_warning_when_all_keys_long (long_keys -> [] and no
#   record), test_no_warnings_warn (warnings.catch_warnings(record=True) + simplefilter("always")
#   around warn_short_hmac_keys() -> recorded list empty)
```

---

## Agent Instructions

1. **Work in the feature worktree** — never on `dev`
   (`parrot sdd worktree ensure --slug policy-issues --feature-id FEAT-109`).
2. **Read the spec** (§1 problem 3, §3 Module 4, §7 Known Risks — pytest warnings-as-errors).
3. **Check dependencies** — none.
4. **Verify the Codebase Contract** before writing code.
5. **Update status** in `sdd/tasks/index/policy-issues.json` → `"in-progress"` (set `started_at`).
6. **Implement** from the blueprint; complete every `# FILL IN:`.
7. **Verify** — run the Validation Commands.
8. **Commit the code** — stage only the files listed above.
9. **Close the task** with `parrot sdd task close TASK-192 policy-issues verified`.
10. **Fill in the Completion Note**, then commit the staged SDD state.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**: What was implemented, any deviations from scope, issues encountered.

**Deviations from spec**: none | describe if any
