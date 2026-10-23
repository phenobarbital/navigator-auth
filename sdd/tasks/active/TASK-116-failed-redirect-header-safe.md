# TASK-116: Route `failed_redirect` header values through `header_safe()`

**Feature**: FEAT-104 — Identity-Link Failure: Non-Nullable Token Columns and Unsafe Error Headers
**Spec**: `sdd/specs/bug-identity.spec.md`
**Status**: pending
**Priority**: high
**Estimated effort**: S (< 2h)
**Depends-on**: TASK-115
**Assigned-to**: unassigned

---

## Context

Implements the second half of **spec §3 Module 2** — the wiring that makes
TASK-115's helper actually protect anything.

`ExternalAuth.failed_redirect` (`external.py:347-352`) writes `message` and
`error` verbatim into the `x-message` / `x-error` response headers. This is
the single chokepoint for all 22 `self.failed_redirect(...)` call sites
across `external.py`, `azure.py`, `adfs.py` and `saml/sp.py`, so sanitizing
here fixes every backend at once — including the ~16 call sites that pass a
static literal today and would otherwise be one careless edit away from the
same exposure.

Closing it here is what turns the FEAT-104 500 back into the intended
redirect, and what shuts the CRLF-injection vector reachable from
`?error_description=` at `external.py:799-801`.

**Note on existing coverage**: `tests/unit/identity/test_link_flow.py:109
TestFinishIdentityLink` replaces `backend.failed_redirect` with a `MagicMock`
(lines 154, 171). Those tests pass today *because* the real method never
runs. Do not extend them for this task — mocking the method under test
proves nothing. Write tests that call the real `failed_redirect`.

---

## Scope

- Import `header_safe` into `navigator_auth/backends/external.py`.
- Pass both `error` and `message` through it in `failed_redirect` before they
  reach either the headers or the query parameters.
- Add tests that call the **real** `failed_redirect` and assert on the
  resulting `HTTPFound`.

**NOT in scope**:
- Changing the *content* of any message passed to `failed_redirect`. The six
  call sites that interpolate exception text are TASK-117.
- Renaming the `x-message` / `x-error` headers or the `?error=` / `?message=`
  query parameters — they are the contract a frontend may rely on
  (spec §1 Non-Goals).
- Touching `home_redirect` / `finish_redirect` (`external.py:300-331`). Its
  only header is the constant `x-authenticated: "true"` plus a token type;
  neither is caller-controlled free text.
- `get_failed_redirect_url` (`external.py:338-345`) — the URL itself is built
  from config, not from `message`.

---

## Files to Create / Modify

| File | Action | Description |
|---|---|---|
| `navigator_auth/backends/external.py` | MODIFY | Import `header_safe`; sanitize in `failed_redirect` |
| `tests/unit/identity/test_failed_redirect.py` | CREATE | Tests against the real `failed_redirect` |

---

## Codebase Contract

> Verified on `dev` @ `b222064` (2026-10-23).

### `navigator_auth/backends/external.py`

```python
class ExternalAuth(BaseAuthBackend):                        # line 85

    def get_domain(self, request: web.Request) -> str       # 238
    def prepare_url(self, url: str, params: dict = None)    # 281  (URL-encodes params)
    def get_failed_redirect_url(self, request: web.Request) -> str   # 338

    def failed_redirect(self, request: web.Request,         # 347  <-- CHANGE
                        error: str = "ERROR_UNKNOWN",
                        message: str = "ERROR_UNKNOWN"):
        url = self.get_failed_redirect_url(request)         # 348
        headers = {"x-message": message, "x-error": str(error)}   # 349  <-- unsanitized
        params = {"error": error, "message": message}       # 350
        url = self.prepare_url(url, params)                 # 351
        return web.HTTPFound(url, headers=headers)          # 352
```

Existing imports at the top of the module (lines 6-39) already include:

```python
from aiohttp import web, hdrs                       # line 16
from ..libs.json import json_decoder                # line 23
from ..libs.redirect import safe_redirect_url       # line 24
from ..exceptions import UserNotFound, AuthException, InvalidAuth   # line 25
```

### From TASK-115 (must be complete first)

```python
# navigator_auth/libs/sanitize.py
HEADER_FORBIDDEN: re.Pattern
def header_safe(value: Any, max_length: int = 256) -> str
```

### Test helpers (`tests/unit/identity/conftest.py`)

```python
def make_backend(cls, flow_store=None, **attrs)   # line 39
# builds a backend via object.__new__ (no app wiring), sets:
#   backend.logger = MagicMock()
#   backend._flow_store, backend.scheme, backend.session_key_property,
#   backend.session_id_property, backend.user_property
# extra attributes are set from **attrs
@pytest.fixture
def flow_store()                                   # line 35 -> FakeFlowStore()
```

Idiom used by the sibling tests (`test_link_flow.py:1-20`):

```python
from aiohttp.test_utils import make_mocked_request
from .conftest import make_backend
from navigator_auth.backends.github import GithubAuth
```

### Does NOT Exist (do not reference)

- `prepare_url` is **not** the vulnerability. It calls
  `requests.models.PreparedRequest.prepare_url` (`external.py:293-295`),
  which URL-encodes the query string — a CRLF in `?message=` was already
  percent-encoded. The header is the hole. Sanitize both anyway so the
  header and the URL carry the same text.
- There is **no** `ExternalAuth.error_redirect`, `auth_failed` or
  `redirect_error` method. The only failure redirect is `failed_redirect`.
- `BaseAuthBackend` does **not** define `failed_redirect`; it is defined on
  `ExternalAuth` only (`external.py:347`) — verified with
  `grep -n "def failed_redirect" navigator_auth/backends/*.py`.
- `web.HTTPFound` performs no sanitization of its own; the `ValueError` is
  raised later, at write time, by `aiohttp._http_writer`. A unit test that
  only constructs the response will **not** reproduce the crash — assert on
  `response.headers` content instead of expecting an exception.

---

## Implementation Blueprint

### `navigator_auth/backends/external.py` — MODIFY (import)

```python
# AFTER — insert below `from ..libs.redirect import safe_redirect_url` (verified: navigator_auth/backends/external.py:24)
# occurrences: 1 (verified: grep -cF 'from ..libs.redirect import safe_redirect_url' navigator_auth/backends/external.py)
from ..libs.sanitize import header_safe
```

### `navigator_auth/backends/external.py` — MODIFY (`failed_redirect`)

```python
# AFTER — replace the body of failed_redirect (verified: navigator_auth/backends/external.py:347-352)
# anchor occurrences: 1 (verified: grep -cF 'headers = {"x-message": message, "x-error": str(error)}' navigator_auth/backends/external.py)
    def failed_redirect(self, request: web.Request, error: str = "ERROR_UNKNOWN", message: str = "ERROR_UNKNOWN"):
        """Redirect the browser to the failed-redirect URL.

        Both ``error`` and ``message`` may originate from a provider
        response, a query parameter or an exception string, so both are
        passed through :func:`header_safe` before reaching a header.
        """
        url = self.get_failed_redirect_url(request)
        safe_error = header_safe(error)
        safe_message = header_safe(message)
        headers = {"x-message": safe_message, "x-error": safe_error}
        params = {"error": safe_error, "message": safe_message}
        url = self.prepare_url(url, params)
        return web.HTTPFound(url, headers=headers)
```

**Why sanitize `error` too, when every call site passes a constant.** The
default is `"ERROR_UNKNOWN"` and all 22 call sites pass an uppercase literal
today, so `error` looks safe. It is a public method parameter with no
enforcement behind it; the next caller — or a subclass in a downstream
Navigator app — can pass anything. Sanitizing both costs one line and makes
the guarantee a property of the method rather than of its current callers.

**Why the same sanitized values go into `params`.** `prepare_url` already
percent-encodes, so the query string was never the vector. But if the header
and the URL carried different text, an operator comparing the two during an
incident would be chasing a discrepancy that means nothing. Keep them equal.

**Why keep `str(error)` semantics.** The old code applied `str()` to `error`
but not to `message`. `header_safe` coerces internally, so the explicit
`str()` is redundant — drop it rather than nesting the two.

### `tests/unit/identity/test_failed_redirect.py` — CREATE

```python
"""Tests for the real `ExternalAuth.failed_redirect` (FEAT-104, TASK-116).

Deliberately calls the real method. `test_link_flow.py:TestFinishIdentityLink`
replaces it with a MagicMock, so those tests pass today while the method is
still unsafe.
"""
import pytest
from aiohttp.test_utils import make_mocked_request

from navigator_auth.libs.sanitize import HEADER_FORBIDDEN
from .conftest import make_backend


def _backend():
    from navigator_auth.backends.github import GithubAuth

    backend = make_backend(GithubAuth)
    # FILL IN: set whatever get_failed_redirect_url needs so the real method
    # runs without app wiring — stub get_failed_redirect_url to a fixed URL
    # rather than patching conf — bounded by AC-1.
    return backend


class TestFailedRedirectHeaderSafety:
    def test_multiline_message_yields_single_line_header(self):
        """The FEAT-104 crash: a ValidationError's text has newlines."""
        # FILL IN: message="UserIdentity: errors\nHint: check payload"
        # assert no "\n"/"\r" in response.headers["x-message"] — bounded by AC-2.

    def test_crlf_payload_injects_no_header(self):
        """A CRLF payload must not become a second header."""
        # FILL IN: message="boom\r\nSet-Cookie: evil=1"
        # assert "Set-Cookie" not in response.headers — bounded by AC-3.

    def test_error_code_is_sanitized_too(self):
        """`error` is a public parameter with no enforcement behind it."""
        # FILL IN: error="E\r\nX-Injected: 1" — bounded by AC-4.

    def test_headers_and_query_agree(self):
        """The sanitized value appears in both the header and the URL."""
        # FILL IN: assert the x-message value also appears (percent-encoded)
        # in response.location — bounded by AC-5.

    def test_clean_message_passes_through(self):
        """No regression: an ordinary message is unchanged."""
        # FILL IN: message="Access denied" round-trips verbatim — bounded by AC-6.
```

**Why assert on `response.headers` rather than `pytest.raises(ValueError)`.**
`web.HTTPFound` does not validate; the `ValueError` is raised much later, by
`aiohttp._http_writer` at socket-write time. A unit test cannot reach that
without a real server, so assert the property that prevents it — the header
value is single-line and control-free — which is both stronger and faster.

### Steps (in order)

1. Confirm TASK-115 is in `sdd/tasks/completed/` and
   `from navigator_auth.libs.sanitize import header_safe` resolves. If it
   does not, stop — this task cannot be completed first.
2. Add the import below `safe_redirect_url` (`external.py:24`), keeping the
   relative-import grouping the module already uses.
3. Replace the `failed_redirect` body exactly as blueprinted. Do not change
   the signature, the header names or the parameter names.
4. Create the test module, fill `_backend()` first (everything else depends
   on it), then the five test bodies.
5. Run the new tests, then the whole identity suite — `failed_redirect` is
   inherited by every external backend, so regressions would surface in the
   SAML and Azure tests, not here.
6. `ruff check navigator_auth/backends/external.py tests/unit/identity/test_failed_redirect.py`.

### FILL IN checklist

- [ ] `_backend()` helper: stub `get_failed_redirect_url` — AC-1
- [ ] `test_multiline_message_yields_single_line_header` — AC-2
- [ ] `test_crlf_payload_injects_no_header` — AC-3
- [ ] `test_error_code_is_sanitized_too` — AC-4
- [ ] `test_headers_and_query_agree` — AC-5
- [ ] `test_clean_message_passes_through` — AC-6

---

## Acceptance Criteria

- [ ] **AC-1** The tests call the real `ExternalAuth.failed_redirect`; it is not replaced by a mock in this module.
- [ ] **AC-2** A multi-line `message` produces an `HTTPFound` whose `x-message` header contains no `\r` and no `\n`.
- [ ] **AC-3** A `message` containing `\r\nSet-Cookie: evil=1` produces no `Set-Cookie` header on the response.
- [ ] **AC-4** `error` is sanitized as well as `message`.
- [ ] **AC-5** The same sanitized text appears in both the header and the redirect URL's query string.
- [ ] **AC-6** An ordinary single-line message round-trips unchanged.
- [ ] **AC-7** The header names (`x-message`, `x-error`) and query parameter names (`error`, `message`) are unchanged.
- [ ] **AC-8** No `failed_redirect` **call site** is edited in this task (that is TASK-117): `git diff navigator_auth/backends/external.py` shows changes only in the import block and in `failed_redirect`; `azure.py`, `adfs.py` and `saml/sp.py` are untouched.
- [ ] **AC-9** `pytest tests/unit/identity/ -q` passes with no new failures.
- [ ] **AC-10** `ruff check` clean on both files.

---

## Test Specification

```bash
pytest tests/unit/identity/test_failed_redirect.py -v
pytest tests/unit/identity/ -q
```

---

## Agent Instructions

1. **Read the spec** at `sdd/specs/bug-identity.spec.md` — §1 Defect B, §3 Module 2.
2. **Check dependencies** — TASK-115 must be in `sdd/tasks/completed/`.
3. **Update status** in `sdd/tasks/index/bug-identity.json` → `"in-progress"`.
4. **Implement** per the blueprint.
5. **Verify** every acceptance criterion, including AC-8.
6. **Move this file** to `sdd/tasks/completed/TASK-116-failed-redirect-header-safe.md`.
7. **Update index** → `"done"`.
8. **Fill in the Completion Note** below.

---

## Completion Note

*(Agent fills this in when done)*

**Completed by**: <session or agent ID>
**Date**: YYYY-MM-DD
**Notes**:

**Deviations from spec**: none | describe if any
