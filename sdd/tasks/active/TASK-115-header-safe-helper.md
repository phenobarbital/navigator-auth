# TASK-115: Add a `header_safe()` sanitizer to `navigator_auth/libs/sanitize.py`

**Feature**: FEAT-104 — Identity-Link Failure: Non-Nullable Token Columns and Unsafe Error Headers
**Spec**: `sdd/specs/bug-identity.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: none
**Assigned-to**: unassigned

---

## Context

Implements the first half of **spec §3 Module 2**. This task adds the helper
only; wiring it into `failed_redirect` is TASK-116.

`ExternalAuth.failed_redirect` writes caller-supplied text straight into
response headers (`external.py:349`). Two consequences, both visible in the
FEAT-104 traceback:

- A multi-line value — e.g. a `datamodel` `ValidationError` — trips aiohttp's
  `_write_str_raise_on_nlcr` and the whole response dies with
  `ValueError: Forbidden control character detected in headers`. A handled,
  redirectable failure becomes an unhandled 500 with no body.
- At `external.py:799-801` the value is built from `?error` /
  `?error_description`, which are **attacker-controlled**. That is a live CRLF
  header-injection vector: send a victim to
  `/auth/<provider>/callback/?error=x&error_description=<CRLF payload>`.

`failed_redirect` is the single chokepoint for all 22 call sites across
`external.py`, `azure.py`, `adfs.py` and `saml/sp.py`, so one sanitizer at
that boundary covers every backend.

This task is deliberately separated from TASK-116 so the helper can be
written and tested against the injection payloads on its own, without an
aiohttp request in the picture.

---

## Scope

- Add `HEADER_FORBIDDEN` and `header_safe()` to the existing
  `navigator_auth/libs/sanitize.py`.
- Add unit tests covering CRLF, the full control range, truncation and
  non-`str` coercion.

**NOT in scope**:
- Calling `header_safe()` from anywhere. TASK-116 does the wiring; this task
  must not touch `navigator_auth/backends/`.
- Changing or re-testing the existing `sanitize_request()` /
  `AUTH_QUERY_PARAMS` in the same module.
- Changing the *content* of any message passed to `failed_redirect` — that is
  TASK-117.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/libs/sanitize.py` | MODIFY | Add `re` import, `HEADER_FORBIDDEN`, `header_safe()` |
| `tests/unit/identity/test_header_safe.py` | CREATE | Unit tests for the helper |

---

## Codebase Contract

> Verified on `dev` @ `b222064` (2026-10-23).

### `navigator_auth/libs/sanitize.py` — the complete current file (30 lines)

```python
"""Sanitize auth-related query parameters from request URLs."""
from aiohttp import web

AUTH_QUERY_PARAMS = frozenset({
    "apikey",
    "api_key",
    "auth",
    "access_token",
})


def sanitize_request(
    request: web.Request,
    params: frozenset[str] = AUTH_QUERY_PARAMS,
) -> web.Request:
    """Strip auth-related query parameters from the request URL.
    ...
    """
    query = request.rel_url.query
    if not any(p in query for p in params):
        return request
    clean_query = {k: v for k, v in query.items() if k not in params}
    clean_url = request.rel_url.with_query(clean_query)
    new_request = request.clone(rel_url=clean_url)
    if hasattr(request, "user"):
        new_request.user = request.user
    return new_request
```

`re` is **not** imported in this module today — this task adds it.
`typing.Any` is **not** imported either — this task adds it.

### The interface fixed by spec §2 (not renegotiable)

```python
def header_safe(value: Any, max_length: int = 256) -> str
```

### The tripwire this defends against

`aiohttp/http_writer.py:222 _serialize_headers` →
`aiohttp/_http_writer.pyx:117 _write_str_raise_on_nlcr` →
`ValueError: Forbidden control character detected in headers.`

### Does NOT Exist (do not reference)

- There is **no** existing header-sanitizing helper anywhere in
  `navigator_auth/`. `libs/sanitize.py` sanitizes *query parameters*, not
  headers. Do not import a `sanitize_header`, `clean_header` or `header_safe`
  that already exists — it must be written here.
- `navigator_auth/libs/` has **no** `headers.py`, `http.py` or `strings.py`.
  Do not create one; the helper belongs in the existing `sanitize.py`.
- aiohttp exposes **no** public header-sanitizing helper to delegate to.
  `aiohttp.helpers` has nothing for this, and
  `aiohttp._http_writer._write_str_raise_on_nlcr` is a private Cython symbol
  that *raises* rather than sanitizes — do not import it.
- `navigator_auth/libs/` contains compiled Cython modules (`cipher`, `json`,
  `parser`, `policy_eval`). `sanitize.py` is **plain Python** — no `.pyx`, no
  rebuild needed.

---

## Implementation Blueprint

### `navigator_auth/libs/sanitize.py` — MODIFY

```python
# AFTER — replace the module header (verified: navigator_auth/libs/sanitize.py:1-2)
# occurrences: 1 (verified: grep -cF 'from aiohttp import web' navigator_auth/libs/sanitize.py)
"""Sanitize auth-related query parameters from request URLs, and
arbitrary values destined for HTTP response headers."""
import re
from typing import Any

from aiohttp import web
```

```python
# AFTER — append at end of file (verified anchor: the final `return new_request`)
# occurrences: 1 (verified: grep -cF 'def sanitize_request(' navigator_auth/libs/sanitize.py)

#: Characters forbidden in an HTTP header value (RFC 9110 section 5.5):
#: CR, LF, NUL and the remaining C0 and C1 control ranges.
HEADER_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def header_safe(value: Any, max_length: int = 256) -> str:
    """Make an arbitrary value safe to use as an HTTP header value.

    Collapses CR/LF/NUL and every other C0/C1 control character to a single
    space, collapses runs of whitespace, strips the result, and truncates it
    to ``max_length`` characters. Always returns a ``str``; ``None`` and
    non-string values are coerced via ``str()`` first (``None`` -> ``""``).

    This is the last line of defence against header injection — it must be
    applied to every header value derived from a request, a provider
    response, or an exception message.

    Args:
        value: The untrusted value destined for a header.
        max_length: Maximum length of the returned string.

    Returns:
        A single-line, control-character-free string.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    # FILL IN: substitute HEADER_FORBIDDEN -> " ", collapse whitespace runs,
    # strip, THEN truncate to max_length — in that order, bounded by AC-4.
```

**Why — order matters.** Sanitize *before* truncating. Truncating first can
leave a payload split so the surviving prefix ends mid-sequence, and it also
wastes the budget on characters that were about to be removed. Strip
controls, collapse, strip, then slice.

**Why the C1 range (`\x7f-\x9f`), not just `\r\n\0`.** aiohttp's
`_write_str_raise_on_nlcr` is today's tripwire and only checks CR/LF, but
header values are latin-1 encoded on the wire, so a raw C1 byte travels
intact and is interpreted inconsistently by proxies and clients. Stripping
the whole control space costs nothing and removes a class of problem rather
than one instance.

**Why replace with a space rather than delete.** `"a\r\nb"` must not become
`"ab"` — silently welding two lines together changes the text's meaning.
Mapping each control to a space and then collapsing runs preserves the word
boundary while guaranteeing a single line.

**Why coerce instead of raising on a non-`str`.** Callers pass exception
instances and provider objects. This helper sits on an error path, so it must
never be the thing that raises — a sanitizer that throws inside an exception
handler turns a handled failure into an unhandled one, which is precisely the
bug being fixed.

### `tests/unit/identity/test_header_safe.py` — CREATE

```python
"""Unit tests for `header_safe` (FEAT-104, TASK-115)."""
import pytest

from navigator_auth.libs.sanitize import HEADER_FORBIDDEN, header_safe


class TestHeaderSafe:
    def test_strips_crlf(self):
        """A CRLF payload cannot survive as a second header line."""
        # FILL IN: assert "\r" not in out and "\n" not in out for an input
        # like "boom\r\nSet-Cookie: evil=1" — bounded by AC-1.

    def test_strips_control_characters(self):
        """NUL, ESC, DEL and the C1 range are all removed."""
        # FILL IN: cover "\x00", "\x1b", "\x7f", "\x9f" — bounded by AC-2.

    def test_truncates(self):
        """A long input is capped at max_length."""
        # FILL IN: 10_000-char input, assert len(out) <= default max_length,
        # and that an explicit max_length is honoured — bounded by AC-3.

    def test_sanitizes_before_truncating(self):
        """Control stripping happens first, so the cap is spent on real text."""
        # FILL IN: an input whose leading chars are controls must not consume
        # the length budget — bounded by AC-4.

    def test_coerces_non_str(self):
        """None -> ""; an Exception -> its str(), sanitized."""
        # FILL IN: header_safe(None) == ""; header_safe(ValueError("a\nb"))
        # contains no newline — bounded by AC-5.

    def test_result_is_header_encodable(self):
        """The output always survives latin-1 header encoding."""
        # FILL IN: for each payload above, out.encode("latin-1") must not
        # raise and HEADER_FORBIDDEN.search(out) must be None — bounded by AC-6.
```

**Why `test_result_is_header_encodable`**: the other tests check properties
we thought of. This one checks the property that actually matters — the value
can be written as a header — so it still fails if someone later weakens the
regex. Keep it.

### Steps (in order)

1. Add the `re` / `typing.Any` imports and the new module docstring line.
   Leave `AUTH_QUERY_PARAMS` and `sanitize_request` untouched.
2. Append `HEADER_FORBIDDEN` and `header_safe`, then fill the one body stub.
3. Create the test module and fill all six bodies.
4. Run the tests, then `ruff check navigator_auth/libs/sanitize.py tests/unit/identity/test_header_safe.py`.
5. Confirm you touched nothing under `navigator_auth/backends/` —
   `git diff --name-only` must list exactly the two files above.

### FILL IN checklist

- [ ] `header_safe` body: substitute → collapse → strip → truncate — AC-4
- [ ] `test_strips_crlf` body — AC-1
- [ ] `test_strips_control_characters` body — AC-2
- [ ] `test_truncates` body — AC-3
- [ ] `test_sanitizes_before_truncating` body — AC-4
- [ ] `test_coerces_non_str` body — AC-5
- [ ] `test_result_is_header_encodable` body — AC-6

---

## Acceptance Criteria

- [ ] **AC-1** `header_safe()` removes CR and LF; `"a\r\nX-Evil: 1"` yields a value containing neither.
- [ ] **AC-2** NUL, `\x1b`, `\x7f` and the C1 range (`\x80-\x9f`) are all removed.
- [ ] **AC-3** A 10 000-character input returns at most `max_length` characters; an explicit `max_length` is honoured.
- [ ] **AC-4** Sanitization happens **before** truncation.
- [ ] **AC-5** `header_safe(None) == ""`; a non-`str` is coerced via `str()` and then sanitized.
- [ ] **AC-6** For every tested payload, `HEADER_FORBIDDEN.search(result) is None` and `result.encode("latin-1")` does not raise.
- [ ] **AC-7** `sanitize_request()` and `AUTH_QUERY_PARAMS` are unchanged.
- [ ] **AC-8** Nothing under `navigator_auth/backends/` is modified.
- [ ] **AC-9** `pytest tests/unit/identity/test_header_safe.py -v` passes and `ruff check` is clean on both files.

---

## Test Specification

```bash
pytest tests/unit/identity/test_header_safe.py -v
ruff check navigator_auth/libs/sanitize.py tests/unit/identity/test_header_safe.py
```

```python
from navigator_auth.libs.sanitize import HEADER_FORBIDDEN, header_safe
```

---

## Agent Instructions

1. **Read the spec** at `sdd/specs/bug-identity.spec.md` — §1 Defect B, §2
   New Public Interfaces, §3 Module 2.
2. **Check dependencies** — none.
3. **Update status** in `sdd/tasks/index/bug-identity.json` → `"in-progress"`.
4. **Implement** per the blueprint.
5. **Verify** every acceptance criterion, including AC-8 (backends untouched).
6. **Move this file** to `sdd/tasks/completed/TASK-115-header-safe-helper.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
